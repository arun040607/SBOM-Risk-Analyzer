"""
parser.py
----------
Loads all raw project data (applications, SBOM dependencies,
vulnerability database, license rules) and returns clean Python
objects that the rest of the pipeline (graph_builder, risk_calculator,
report_generator) can work with.

Design choice for the hackathon:
- applications.json, vulnerability_db.json, license_rules.json are
  small lookup tables -> loaded as plain Python lists of dicts.
- sbom_dependencies.csv is the big relational table -> loaded as a
  pandas DataFrame, since risk_calculator needs to filter/group it.
"""

import json
import os
import pandas as pd


# ---------------------------------------------------------------------
# Individual loaders
# ---------------------------------------------------------------------

def load_applications(filepath="data/applications.json"):
    """
    Load the list of applications.

    Returns:
        list[dict]: one dict per application, e.g.
        {"app_id": "APP01", "application_name": "Employee Portal",
         "owner": "Arun", "business_criticality": "Critical"}
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("applications.json must contain a JSON array.")
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"[parser] Could not find applications file at: {filepath}")
    except json.JSONDecodeError as e:
        raise ValueError(f"[parser] applications.json is not valid JSON: {e}")


def load_dependencies(filepath="data/sbom_dependencies.csv"):
    """
    Load the SBOM dependency table.

    Returns:
        pandas.DataFrame with columns:
        application, library, version, license, direct,
        last_updated, depends_on
    """
    try:
        df = pd.read_csv(filepath)
    except FileNotFoundError:
        raise FileNotFoundError(f"[parser] Could not find dependencies file at: {filepath}")
    except pd.errors.EmptyDataError:
        raise ValueError(f"[parser] Dependencies file is empty: {filepath}")
    except pd.errors.ParserError as e:
        raise ValueError(f"[parser] Could not parse dependencies CSV: {e}")

    required_columns = {
        "application", "library", "version", "license",
        "direct", "last_updated", "depends_on"
    }
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"[parser] sbom_dependencies.csv is missing columns: {missing}")

    # Normalize types so downstream code doesn't have to guess.
    # "direct" comes in as the strings "True"/"False" -> real booleans.
    df["direct"] = df["direct"].astype(str).str.strip().str.lower() == "true"

    # depends_on is often blank for leaf libraries -> use empty string, not NaN.
    df["depends_on"] = df["depends_on"].fillna("").astype(str).str.strip()

    # last_updated -> real datetime so risk_calculator can do date math.
    df["last_updated"] = pd.to_datetime(df["last_updated"], errors="coerce")

    # Strip whitespace on text columns to avoid silent join failures later.
    for col in ["application", "library", "version", "license"]:
        df[col] = df[col].astype(str).str.strip()

    return df


def load_vulnerabilities(filepath="data/vulnerability_db.json"):
    """
    Load the vulnerability (CVE) database.

    Returns:
        list[dict]: one dict per CVE, e.g.
        {"cve_id": "CVE-2021-44228", "library": "log4j",
         "affected_version": "<=2.14.1", "cvss_score": 10.0,
         "severity": "Critical", "patch_available": true,
         "exploit_available": true, "description": "..."}
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("vulnerability_db.json must contain a JSON array.")
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"[parser] Could not find vulnerability file at: {filepath}")
    except json.JSONDecodeError as e:
        raise ValueError(f"[parser] vulnerability_db.json is not valid JSON: {e}")


def load_license_rules(filepath="data/license_rules.json"):
    """
    Load the license risk rules.

    Returns:
        list[dict]: one dict per license, e.g.
        {"license": "GPL-3.0", "compatibility": "Incompatible",
         "risk_level": "Critical", "explanation": "..."}
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("license_rules.json must contain a JSON array.")
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"[parser] Could not find license rules file at: {filepath}")
    except json.JSONDecodeError as e:
        raise ValueError(f"[parser] license_rules.json is not valid JSON: {e}")


# ---------------------------------------------------------------------
# Convenience: load everything in one call
# ---------------------------------------------------------------------

def load_all(data_dir="data"):
    """
    Load all four data sources at once.

    Args:
        data_dir (str): folder containing the four data files.

    Returns:
        dict with keys: "applications", "dependencies",
        "vulnerabilities", "license_rules"
    """
    return {
        "applications": load_applications(os.path.join(data_dir, "applications.json")),
        "dependencies": load_dependencies(os.path.join(data_dir, "sbom_dependencies.csv")),
        "vulnerabilities": load_vulnerabilities(os.path.join(data_dir, "vulnerability_db.json")),
        "license_rules": load_license_rules(os.path.join(data_dir, "license_rules.json")),
    }


# ---------------------------------------------------------------------
# Manual run / sample output (useful for a live demo)
# ---------------------------------------------------------------------

if __name__ == "__main__":
    data = load_all("data")

    print(f"Applications loaded: {len(data['applications'])}")
    print(f"Dependency records loaded: {len(data['dependencies'])}")
    print(f"Vulnerabilities loaded: {len(data['vulnerabilities'])}")
    print(f"License rules loaded: {len(data['license_rules'])}")

    print("\nSample application:", data["applications"][0])
    print("\nSample dependency row:\n", data["dependencies"].iloc[0])
    print("\nSample vulnerability:", data["vulnerabilities"][0])
    print("\nSample license rule:", data["license_rules"][0])