"""
license_checker.py
--------------------
A standalone License Compliance Checker for the SBOM Risk Analyzer.

This module focuses on ONE job: given the SBOM dependency table and the
license rules table, figure out which dependencies carry legal/licensing
risk, why, and what to do about it. It doesn't know about CVEs or
maintenance dates -- risk_calculator.py already folds a version of this
logic into the overall risk score. This module exists so license
compliance can be explained, demoed, and tested completely on its own
(useful if a judge asks "just show me the license problem").

Core ideas:
    - Every dependency's license is looked up in license_rules.json.
    - "Conflict" = risk_level is Critical or High (matches the same
      definition risk_calculator.py uses, so the two stay consistent).
    - A flat penalty score reuses the same point values as the overall
      risk formula (GPL +30, AGPL +40, Unknown +20) so this module's
      numbers line up with the dashboard's numbers.
"""

import os
from collections import Counter

# Same flat penalty points used in risk_calculator.py, duplicated here
# on purpose so this module has zero dependency on risk_calculator and
# can be demoed / tested completely standalone.
LICENSE_PENALTIES = {
    "GPL": 30,      # matches GPL-2.0, GPL-3.0, etc.
    "AGPL": 40,
    "UNKNOWN": 20,
}

# Which risk levels count as an actual "conflict" worth flagging.
CONFLICT_RISK_LEVELS = {"Critical", "High"}


# ---------------------------------------------------------------------
# License lookup
# ---------------------------------------------------------------------

def get_license_info(license_name, license_rules):
    """
    Look up a license's compatibility/risk info from license_rules.json.

    Args:
        license_name (str): e.g. "GPL-3.0", "MIT"
        license_rules (list[dict]): from parser.load_license_rules()

    Returns:
        dict: the matching rule, or a synthetic "Unknown" rule if the
        license isn't listed at all (e.g. a typo or a license we've
        never seen before -- treated as high risk until a human checks it).
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


def license_penalty(license_name):
    """
    Return the flat penalty points for a license string, using
    substring matching so "GPL-2.0", "GPL-3.0", "LGPL-2.1" etc. all
    resolve correctly. Checked in order: AGPL before GPL, since
    "AGPL" also contains the substring "GPL".
    """
    name = (license_name or "").upper()
    if "AGPL" in name:
        return LICENSE_PENALTIES["AGPL"]
    if "GPL" in name:
        return LICENSE_PENALTIES["GPL"]
    if "UNKNOWN" in name or name == "":
        return LICENSE_PENALTIES["UNKNOWN"]
    return 0


def is_conflict(license_name, license_rules):
    """True if this license's risk_level counts as a compliance conflict."""
    info = get_license_info(license_name, license_rules)
    return info["risk_level"] in CONFLICT_RISK_LEVELS


# ---------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------

def _recommendation_for(license_name, risk_level):
    if risk_level == "Critical":
        return f"Do not ship with {license_name}; replace with a permissively-licensed alternative before release."
    if risk_level == "High":
        return f"Escalate {license_name} to legal/compliance review before this dependency ships."
    return "No action needed."


# ---------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------

def check_licenses(dependencies_df, license_rules):
    """
    Scan every dependency row and flag license conflicts.

    Args:
        dependencies_df (pandas.DataFrame): from parser.load_dependencies()
        license_rules (list[dict]): from parser.load_license_rules()

    Returns:
        list[dict]: one entry per dependency that has a Critical/High
        risk license, each with keys:
            application, library, version, license, compatibility,
            risk_level, penalty_score, recommendation
    """
    findings = []

    for _, row in dependencies_df.iterrows():
        license_name = row["license"]
        info = get_license_info(license_name, license_rules)

        if info["risk_level"] not in CONFLICT_RISK_LEVELS:
            continue  # clean license, nothing to report

        findings.append({
            "application": row["application"],
            "library": row["library"],
            "version": row["version"],
            "license": license_name,
            "compatibility": info["compatibility"],
            "risk_level": info["risk_level"],
            "penalty_score": license_penalty(license_name),
            "recommendation": _recommendation_for(license_name, info["risk_level"]),
        })

    # Worst offenders first: Critical before High, then by penalty score.
    severity_order = {"Critical": 0, "High": 1}
    findings.sort(key=lambda f: (severity_order.get(f["risk_level"], 2), -f["penalty_score"]))
    return findings


# ---------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------

def summarize_by_license(findings):
    """
    Count how many conflicting dependencies use each license.

    Returns:
        list[dict]: [{"license": "GPL-3.0", "count": 2, "risk_level": "Critical"}, ...]
        sorted by count, highest first.
    """
    counts = Counter(f["license"] for f in findings)
    risk_by_license = {f["license"]: f["risk_level"] for f in findings}

    summary = [
        {"license": lic, "count": count, "risk_level": risk_by_license[lic]}
        for lic, count in counts.items()
    ]
    return sorted(summary, key=lambda s: s["count"], reverse=True)


def summarize_by_application(findings):
    """
    Count license conflicts and total penalty score per application --
    "which app has the messiest license situation" view.

    Returns:
        list[dict]: [{"application": "...", "conflict_count": 3, "total_penalty": 90}, ...]
        sorted by total_penalty, highest first.
    """
    apps = {}
    for f in findings:
        app = f["application"]
        if app not in apps:
            apps[app] = {"application": app, "conflict_count": 0, "total_penalty": 0}
        apps[app]["conflict_count"] += 1
        apps[app]["total_penalty"] += f["penalty_score"]

    return sorted(apps.values(), key=lambda a: a["total_penalty"], reverse=True)


def get_clean_dependencies(dependencies_df, license_rules):
    """
    The flip side of check_licenses(): every dependency whose license
    is fine (Low/Medium risk). Useful for showing "here's what's NOT
    a problem" alongside the conflict list.

    Returns:
        list[dict]: application, library, version, license
    """
    clean = []
    for _, row in dependencies_df.iterrows():
        info = get_license_info(row["license"], license_rules)
        if info["risk_level"] not in CONFLICT_RISK_LEVELS:
            clean.append({
                "application": row["application"],
                "library": row["library"],
                "version": row["version"],
                "license": row["license"],
            })
    return clean


# ---------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------

def export_license_report(findings, output_dir="reports"):
    """
    Write the license conflict findings and both summaries to
    reports/ as CSV and JSON.

    Returns:
        dict: {"conflicts": [...], "by_license": [...], "by_application": [...]}
    """
    import pandas as pd

    os.makedirs(output_dir, exist_ok=True)

    by_license = summarize_by_license(findings)
    by_application = summarize_by_application(findings)

    exports = {
        "license_conflicts": findings,
        "license_summary_by_license": by_license,
        "license_summary_by_application": by_application,
    }

    for name, records in exports.items():
        df = pd.DataFrame(records)
        df.to_csv(os.path.join(output_dir, f"{name}.csv"), index=False)
        df.to_json(os.path.join(output_dir, f"{name}.json"), orient="records", indent=2)

    return {
        "conflicts": findings,
        "by_license": by_license,
        "by_application": by_application,
    }


# ---------------------------------------------------------------------
# Manual run / sample output
# ---------------------------------------------------------------------

if __name__ == "__main__":
    from parser import load_dependencies, load_license_rules

    deps = load_dependencies("data/sbom_dependencies.csv")
    rules = load_license_rules("data/license_rules.json")

    findings = check_licenses(deps, rules)
    report = export_license_report(findings, output_dir="reports")

    print(f"Total license conflicts found: {len(findings)}\n")

    print("Conflicts (worst first):")
    for f in findings:
        print(f"  [{f['risk_level']:<8}] {f['application']:<22} {f['library']:<15} {f['license']:<12} "
              f"penalty={f['penalty_score']}")

    print("\nBy license:")
    for s in report["by_license"]:
        print(f"  {s['license']:<15} count={s['count']:<3} risk={s['risk_level']}")

    print("\nBy application:")
    for a in report["by_application"]:
        print(f"  {a['application']:<22} conflicts={a['conflict_count']:<3} total_penalty={a['total_penalty']}")