"""
risk_calculator.py
--------------------
The core of the SBOM Risk Analyzer. Combines the dependency data,
the vulnerability database, the license rules, and the dependency
graph to produce a list of risk "findings" -- one row per issue
detected, each with a computed risk_score.

Risk score formula (as specified for the project):

    risk_score = (CVSS score x 10)
               + license_penalty
               + maintenance_penalty
               + dependency_depth_weight

Penalties:
    GPL license                -> +30
    AGPL license                -> +40
    Unknown license             -> +20
    Not updated in 2+ years     -> +20
    Transitive vulnerability    -> +15

Dependency depth weight: depth of the library below the application
in the dependency graph (1 = direct, 2 = one hop transitive, etc.),
multiplied by 5, so deeper/more-hidden risks score a bit higher.
"""

from datetime import datetime, timedelta

from graph_builder import build_graph, get_dependency_depth

# How old counts as "unmaintained" for this project.
UNMAINTAINED_THRESHOLD_YEARS = 2

# Flat penalty points added to risk_score, per the project spec.
LICENSE_PENALTIES = {
    "GPL": 30,          # matches GPL-2.0, GPL-3.0, etc. (substring match)
    "AGPL": 40,
    "UNKNOWN": 20,
}
MAINTENANCE_PENALTY = 20
TRANSITIVE_PENALTY = 15
DEPTH_WEIGHT_MULTIPLIER = 5


# ---------------------------------------------------------------------
# Version matching helpers
# ---------------------------------------------------------------------

def _clean_version(version):
    """
    Turn a version string like '1.1.1k' or '5.3.9' into a comparable
    tuple of integers, e.g. (1, 1, 1) or (5, 3, 9).
    Any trailing letters (like the 'k' in openssl's '1.1.1k') are dropped
    since they don't affect basic numeric comparison for this project.
    """
    parts = []
    for chunk in str(version).strip().split("."):
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break  # stop at the first non-digit character
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_matches(version, rule):
    """
    Check whether a dependency's version falls inside a CVE's
    affected_version rule. Supports the simple formats used in our
    vulnerability_db.json:
        "<=2.14.1"            -> less than or equal to
        "<2.20.0"             -> strictly less than
        ">=5.3.0 <5.3.18"     -> range (both bounds)
        "1.0.1-1.0.2"         -> inclusive range with a dash
        "1.0.2"               -> exact match
    This is intentionally simple (no full semver spec) to stay
    beginner-friendly and easy to explain to judges.
    """
    rule = rule.strip()
    v = _clean_version(version)

    # Range with both a lower and upper bound, e.g. ">=5.3.0 <5.3.18"
    if ">=" in rule and "<" in rule:
        lower_part, upper_part = rule.split("<", 1)
        lower = _clean_version(lower_part.replace(">=", "").strip())
        upper_inclusive = upper_part.startswith("=")
        upper = _clean_version(upper_part.lstrip("=").strip())
        if upper_inclusive:
            return lower <= v <= upper
        return lower <= v < upper

    # Dash range, e.g. "1.0.1-1.0.2"
    if "-" in rule and not rule.startswith("-"):
        low_str, high_str = rule.split("-", 1)
        low, high = _clean_version(low_str), _clean_version(high_str)
        return low <= v <= high

    # Less-than-or-equal, e.g. "<=2.14.1"
    if rule.startswith("<="):
        return v <= _clean_version(rule[2:])

    # Strictly less-than, e.g. "<2.20.0"
    if rule.startswith("<"):
        return v < _clean_version(rule[1:])

    # Greater-than-or-equal only, e.g. ">=5.3.0"
    if rule.startswith(">="):
        return v >= _clean_version(rule[2:])

    # Fallback: exact version match, e.g. "1.0.2"
    return v == _clean_version(rule)


def find_vulnerabilities_for(library, version, vulnerabilities):
    """
    Return every CVE from the vulnerability database that applies to
    this library + version combination.
    """
    matches = []
    for cve in vulnerabilities:
        if cve["library"].lower() != library.lower():
            continue
        try:
            if _version_matches(version, cve["affected_version"]):
                matches.append(cve)
        except (ValueError, IndexError):
            # A malformed affected_version string shouldn't crash the scan.
            continue
    return matches


# ---------------------------------------------------------------------
# License helpers
# ---------------------------------------------------------------------

def _license_penalty(license_name):
    """Return the flat penalty points for a given license string."""
    name = (license_name or "").upper()
    if "AGPL" in name:
        return LICENSE_PENALTIES["AGPL"]
    if "GPL" in name:  # catches GPL-2.0, GPL-3.0 (checked after AGPL)
        return LICENSE_PENALTIES["GPL"]
    if "UNKNOWN" in name or name == "":
        return LICENSE_PENALTIES["UNKNOWN"]
    return 0


def get_license_risk(license_name, license_rules):
    """
    Look up a license's compatibility/risk info from license_rules.json.
    Falls back to a generic "Unknown" entry if the license isn't listed.
    """
    for rule in license_rules:
        if rule["license"].lower() == (license_name or "").lower():
            return rule
    return {
        "license": license_name or "Unknown",
        "compatibility": "Unverified",
        "risk_level": "High",
        "explanation": "License not found in license_rules.json; treat as high risk until confirmed.",
    }


# ---------------------------------------------------------------------
# Maintenance helpers
# ---------------------------------------------------------------------

def is_unmaintained(last_updated, reference_date=None):
    """
    Return True if last_updated is more than UNMAINTAINED_THRESHOLD_YEARS
    years before the reference date (defaults to today).
    """
    if last_updated is None or (hasattr(last_updated, "isna") and last_updated.isna()):
        return False
    reference_date = reference_date or datetime.now()
    cutoff = reference_date - timedelta(days=365 * UNMAINTAINED_THRESHOLD_YEARS)
    return last_updated < cutoff


# ---------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------

def _recommendation_for(issue_type, cve=None, license_name=None):
    if issue_type == "Vulnerable Library":
        return f"Upgrade past {cve['affected_version']} to remediate {cve['cve_id']} ({cve['severity']})."
    if issue_type == "Transitive Vulnerability":
        return f"Upgrade the parent dependency that pulls this library in to remediate {cve['cve_id']}."
    if issue_type == "License Conflict":
        return f"Review legal implications of {license_name} before shipping; consider an alternative library."
    if issue_type == "Unmaintained Library":
        return "Library has not been updated in 2+ years; evaluate for replacement or active fork."
    return "Review this finding."


# ---------------------------------------------------------------------
# Main scoring engine
# ---------------------------------------------------------------------

def calculate_risk(dependencies_df, vulnerabilities, license_rules, graph=None, reference_date=None):
    """
    Walk every dependency row and produce a list of risk findings.

    Args:
        dependencies_df (pandas.DataFrame): from parser.load_dependencies()
        vulnerabilities (list[dict]): from parser.load_vulnerabilities()
        license_rules (list[dict]): from parser.load_license_rules()
        graph (networkx.DiGraph, optional): from graph_builder.build_graph().
            Built automatically from dependencies_df if not provided.
        reference_date (datetime, optional): "today", for testing.

    Returns:
        list[dict]: each finding has keys:
            application, library, issue_type, severity, risk_score,
            recommendation
    """
    if graph is None:
        graph = build_graph(dependencies_df)

    findings = []

    for _, row in dependencies_df.iterrows():
        application = row["application"]
        library = row["library"]
        version = row["version"]
        license_name = row["license"]
        direct = bool(row["direct"])
        last_updated = row["last_updated"]

        depth = get_dependency_depth(graph, application, library, version) or 1
        depth_weight = depth * DEPTH_WEIGHT_MULTIPLIER

        license_penalty = _license_penalty(license_name)
        license_info = get_license_risk(license_name, license_rules)

        maintenance_flag = is_unmaintained(last_updated, reference_date)
        maintenance_penalty = MAINTENANCE_PENALTY if maintenance_flag else 0

        # --- 1 & 2: Vulnerable / transitive-vulnerable libraries ---
        matching_cves = find_vulnerabilities_for(library, version, vulnerabilities)
        for cve in matching_cves:
            is_transitive = not direct
            transitive_penalty = TRANSITIVE_PENALTY if is_transitive else 0

            risk_score = (
                cve["cvss_score"] * 10
                + license_penalty
                + maintenance_penalty
                + depth_weight
                + transitive_penalty
            )

            issue_type = "Transitive Vulnerability" if is_transitive else "Vulnerable Library"
            findings.append({
                "application": application,
                "library": f"{library}@{version}",
                "issue_type": issue_type,
                "severity": cve["severity"],
                "risk_score": round(risk_score, 2),
                "recommendation": _recommendation_for(issue_type, cve=cve),
            })

        # --- 3: License conflicts (Critical/High risk licenses only) ---
        if license_info["risk_level"] in ("Critical", "High"):
            risk_score = license_penalty + maintenance_penalty + depth_weight
            findings.append({
                "application": application,
                "library": f"{library}@{version}",
                "issue_type": "License Conflict",
                "severity": license_info["risk_level"],
                "risk_score": round(risk_score, 2),
                "recommendation": _recommendation_for("License Conflict", license_name=license_name),
            })

        # --- 4: Unmaintained libraries ---
        if maintenance_flag:
            risk_score = maintenance_penalty + depth_weight + license_penalty
            findings.append({
                "application": application,
                "library": f"{library}@{version}",
                "issue_type": "Unmaintained Library",
                "severity": "Medium",
                "risk_score": round(risk_score, 2),
                "recommendation": _recommendation_for("Unmaintained Library"),
            })

    # Highest risk first -- most useful order for a dashboard table.
    findings.sort(key=lambda f: f["risk_score"], reverse=True)
    return findings


# ---------------------------------------------------------------------
# Manual run / sample output
# ---------------------------------------------------------------------

if __name__ == "__main__":
    from parser import load_all

    data = load_all("data")
    graph = build_graph(data["dependencies"])

    results = calculate_risk(
        data["dependencies"],
        data["vulnerabilities"],
        data["license_rules"],
        graph=graph,
    )

    print(f"Total findings: {len(results)}\n")
    print("Top 5 highest-risk findings:")
    for finding in results[:5]:
        print(
            f"  [{finding['risk_score']:>6}] {finding['application']:<20} "
            f"{finding['library']:<25} {finding['issue_type']:<24} ({finding['severity']})"
        )