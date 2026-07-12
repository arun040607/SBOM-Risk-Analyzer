"""
app.py

Main Flask application for the SBOM Risk Analyzer.
Wires together parser.py, graph_builder.py, risk_calculator.py,
license_checker.py, and report_generator.py. Contains no analysis
logic itself.
"""

from flask import Flask, render_template

from parser import load_all
from graph_builder import build_graph, save_dependency_graph

from risk_calculator import calculate_risk
from license_checker import check_licenses, summarize_by_license, summarize_by_application
from report_generator import generate_application_report, generate_summary

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FOLDER = os.path.join(BASE_DIR, "data")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)



@app.route("/")
def home():
    """Homepage route."""
    return render_template("index.html")


@app.route("/analyze")
def analyze():
    """
    Load data, build the graph, score risk, check licenses,
    build per-application reports + a fleet summary, render report.html.
    """

    # STEP 1: Load all raw data (keys: applications, dependencies,
    # vulnerabilities, license_rules -- matches parser.load_all()).
    data = load_all(DATA_FOLDER)
    applications = data["applications"]
    dependencies_df = data["dependencies"]
    vulnerabilities = data["vulnerabilities"]
    license_rules = data["license_rules"]
    # STEP 2: Build the dependency graph once, reuse everywhere.
    graph = build_graph(dependencies_df)
    save_dependency_graph(graph)

    # STEP 3-4: calculate_risk() already covers vulnerable + transitive
    # + license + unmaintained findings in one pass (risk_calculator.py).
    all_findings = calculate_risk(
        dependencies_df, vulnerabilities, license_rules, graph=graph
    )

    # STEP 5: License-specific view (for the license section of the report).
    license_findings = check_licenses(dependencies_df, license_rules)

    # STEP 6-7: Build one report per application.
    application_reports = []
    for application in applications:
        app_name = application["application_name"]

        app_findings = [f for f in all_findings if f["application"] == app_name]
        total_risk_score = sum(f["risk_score"] for f in app_findings)

        if total_risk_score >= 600:
            risk_level = "Critical"
            priority= "P1 - replace within 24 hours"
        elif total_risk_score >= 350:
            risk_level = "High"
            priority= "P2 - Replace within 7 days"
        elif total_risk_score >= 200:
            risk_level = "Medium"
            priority="P3 - Replace within 30 days"
        else:
            risk_level = "Low"
            priority="P4 - Monitor"

        # report_generator expects dependency dicts with boolean flags;
        # derive them from each finding's issue_type here so
        # report_generator.py needs no knowledge of risk_calculator's
        # issue_type strings.
        dependency_results = []
        for f in app_findings:
            dependency_results.append({
    "library_name": f["library"],
    "issue_type": f["issue_type"],
    "severity": f["severity"],
    "risk_score": f["risk_score"],
    "recommendation": f.get("recommendation", ""),

    "cve_id": f.get("cve_id", ""),
    "description": f.get("description", ""),
    "remediation_steps": f.get("remediation_steps", ""),
    "prevention_steps": f.get("prevention_steps", ""),
    "patched_version": f.get("patched_version", ""),

    "is_vulnerable": f["issue_type"] == "Vulnerable Library",
    "is_license_conflict": f["issue_type"] == "License Conflict",
    "is_unmaintained": f["issue_type"] == "Unmaintained Library",
})

        app_report = generate_application_report(
            application_name=app_name,
            dependency_results=dependency_results,
            total_risk_score=round(total_risk_score, 2),
            risk_level=risk_level,
            priority=priority
        )
        app_report["business_criticality"] = application["business_criticality"]
        app_report["owner"] = application["owner"]
        application_reports.append(app_report)
        application_reports.sort(key=lambda r: r["risk_score"], reverse=True)
        top_priority_apps = application_reports[:5]

    # STEP 8: Fleet-wide summary.
    summary = generate_summary(application_reports)

    # STEP 9: Render.
    return render_template(
        "report.html",
        summary=summary,
        application_reports=application_reports,
        top_priority_apps=top_priority_apps,
        license_by_license=summarize_by_license(license_findings),
        license_by_application=summarize_by_application(license_findings),
        
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)