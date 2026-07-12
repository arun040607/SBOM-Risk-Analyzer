"""
test_license.py
------------------
Simple debug script for license_checker.py. Loads dependencies and
license rules, runs the license checker, and prints out what it found.

Run with:
    python src/test_license.py
(run from the project root, so the "data/" folder is found)
"""

from parser import load_dependencies, load_license_rules
from license_checker import check_licenses


def test_license_checker():
    """Load data, run check_licenses(), and print the results."""
    print("\n--- Testing license_checker.py ---")
    try:
        dependencies = load_dependencies("data/sbom_dependencies.csv")
        license_rules = load_license_rules("data/license_rules.json")
    except Exception as e:
        print("ERROR while loading data:", e)
        return

    try:
        findings = check_licenses(dependencies, license_rules)
    except Exception as e:
        print("ERROR while running check_licenses():", e)
        return

    # --- Total license conflicts ---
    print(f"Total license conflicts: {len(findings)}")

    # --- Libraries with GPL licenses ---
    # (matches GPL-2.0, GPL-3.0, etc. but not AGPL, checked separately below)
    print("\nLibraries with GPL licenses:")
    gpl_findings = [f for f in findings if "GPL" in f["license"].upper() and "AGPL" not in f["license"].upper()]
    if gpl_findings:
        for f in gpl_findings:
            print(f"  {f['application']} -> {f['library']} ({f['license']})")
    else:
        print("  None found.")

    # --- Libraries with Unknown licenses ---
    print("\nLibraries with Unknown licenses:")
    unknown_findings = [f for f in findings if f["license"].upper() == "UNKNOWN"]
    if unknown_findings:
        for f in unknown_findings:
            print(f"  {f['application']} -> {f['library']} ({f['license']})")
    else:
        print("  None found.")

    # --- Recommendations ---
    print("\nRecommendations:")
    if findings:
        for f in findings:
            print(f"  [{f['risk_level']}] {f['application']} -> {f['library']}: {f['recommendation']}")
    else:
        print("  No license conflicts to recommend on.")


if __name__ == "__main__":
    print("Running license_checker.py tests...")
    test_license_checker()
    print("\nDone.")