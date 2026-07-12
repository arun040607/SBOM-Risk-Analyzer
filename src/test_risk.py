"""
test_risk.py
--------------
Simple debug script for risk_calculator.py. Loads all four data
sources, runs the full risk calculation, and prints the highest-risk
findings so you can sanity-check the scoring without starting Flask.

Run with:
    python src/test_risk.py
(run from the project root, so the "data/" folder is found)
"""

from parser import load_applications, load_dependencies, load_vulnerabilities, load_license_rules
from graph_builder import build_graph
from risk_calculator import calculate_risk


def load_all_data():
    """Load applications, dependencies, vulnerabilities, and license rules."""
    print("\n--- Loading data ---")
    try:
        applications = load_applications("data/applications.json")
        dependencies = load_dependencies("data/sbom_dependencies.csv")
        vulnerabilities = load_vulnerabilities("data/vulnerability_db.json")
        license_rules = load_license_rules("data/license_rules.json")
        print(f"Loaded {len(applications)} applications, {len(dependencies)} dependencies, "
              f"{len(vulnerabilities)} vulnerabilities, {len(license_rules)} license rules.")
        return applications, dependencies, vulnerabilities, license_rules
    except Exception as e:
        print("ERROR while loading data:", e)
        return None, None, None, None


def run_risk_calculation(applications, dependencies, vulnerabilities, license_rules):
    """Build the graph and run calculate_risk(). Returns the findings list, or None on failure."""
    print("\n--- Running risk_calculator.calculate_risk() ---")
    try:
        graph = build_graph(dependencies)
        findings = calculate_risk(dependencies, vulnerabilities, license_rules, graph=graph)
        print(f"Total findings: {len(findings)}")
        return findings
    except Exception as e:
        print("ERROR while calculating risk:", e)
        return None


def print_top_risky_libraries(findings, top_n=10):
    """Print the top N highest-risk findings (application + library + issue)."""
    print(f"\n--- Top {top_n} risky libraries ---")
    if not findings:
        print("No findings to show.")
        return

    for f in findings[:top_n]:
        print(f"  [{f['risk_score']:>6}] {f['application']} -> {f['library']} "
              f"({f['issue_type']}, {f['severity']})")


def print_top_risky_applications(findings, top_n=5):
    """Aggregate risk_score per application and print the top N riskiest apps."""
    print(f"\n--- Top {top_n} risky applications ---")
    if not findings:
        print("No findings to show.")
        return

    try:
        # Add up the risk_score for every finding that belongs to each application.
        totals = {}
        for f in findings:
            app = f["application"]
            totals[app] = totals.get(app, 0) + f["risk_score"]

        # Sort applications by total risk score, highest first.
        ranked = sorted(totals.items(), key=lambda item: item[1], reverse=True)

        for app_name, total_score in ranked[:top_n]:
            print(f"  {app_name}: total risk score = {round(total_score, 2)}")
    except Exception as e:
        print("ERROR while ranking applications:", e)


def print_recommendations(findings, top_n=10):
    """Print the recommendation text for the top N findings."""
    print(f"\n--- Recommendations for top {top_n} findings ---")
    if not findings:
        print("No findings to show.")
        return

    for f in findings[:top_n]:
        print(f"  {f['application']} -> {f['library']}: {f['recommendation']}")


if __name__ == "__main__":
    print("Running risk_calculator.py tests...")

    applications, dependencies, vulnerabilities, license_rules = load_all_data()

    if dependencies is not None:
        findings = run_risk_calculation(applications, dependencies, vulnerabilities, license_rules)
        print_top_risky_libraries(findings, top_n=10)
        print_top_risky_applications(findings, top_n=5)
        print_recommendations(findings, top_n=10)

    print("\nDone.")