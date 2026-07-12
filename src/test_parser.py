"""
test_parser.py
----------------
Simple debug script for parser.py. Not a pytest suite -- just runs each
loader function and prints what came back, so you can quickly see
whether the data files are loading correctly.

Run with:
    python src/test_parser.py
(run from the project root, so the "data/" folder is found)
"""
from parser import (
    load_applications,
    load_dependencies,
    load_vulnerabilities,
    load_license_rules,
)


def test_load_applications():
    """Load applications.json and print how many apps we got."""
    print("\n--- Testing load_applications() ---")
    try:
        applications = load_applications("data/applications.json")
        print(f"Number of applications: {len(applications)}")
        print("First application:", applications[0])
    except Exception as e:
        # Catching a broad Exception here is fine for a debug script --
        # we just want to see the problem, not stop the whole run.
        print("ERROR while loading applications:", e)


def test_load_dependencies():
    """Load sbom_dependencies.csv and print the first few rows."""
    print("\n--- Testing load_dependencies() ---")
    try:
        dependencies = load_dependencies("data/sbom_dependencies.csv")
        print(f"Number of dependency rows: {len(dependencies)}")
        print("First 5 dependencies:")
        print(dependencies.head(5))
    except Exception as e:
        print("ERROR while loading dependencies:", e)


def test_load_vulnerabilities():
    """Load vulnerability_db.json and print how many CVEs we got."""
    print("\n--- Testing load_vulnerabilities() ---")
    try:
        vulnerabilities = load_vulnerabilities("data/vulnerability_db.json")
        print(f"Number of vulnerabilities: {len(vulnerabilities)}")
        print("First vulnerability:", vulnerabilities[0])
    except Exception as e:
        print("ERROR while loading vulnerabilities:", e)


def test_load_license_rules():
    """Load license_rules.json and print how many rules we got."""
    print("\n--- Testing load_license_rules() ---")
    try:
        license_rules = load_license_rules("data/license_rules.json")
        print(f"Number of license rules: {len(license_rules)}")
        print("First license rule:", license_rules[0])
    except Exception as e:
        print("ERROR while loading license rules:", e)


if __name__ == "__main__":
    print("Running parser.py tests...")
    test_load_applications()
    test_load_dependencies()
    test_load_vulnerabilities()
    test_load_license_rules()
    print("\nDone.")