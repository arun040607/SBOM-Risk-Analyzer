"""
app.py

Main Flask application for the SBOM Risk Analyzer.
"""

import os
from flask import Flask, render_template

from parser import load_all
from graph_builder import build_graph
from risk_calculator import calculate_risk
from license_checker import (
    check_licenses,
    summarize_by_license,
    summarize_by_application,
)
from report_generator import (
    generate_application_report,
    generate_summary,
    save_json_report,
    save_csv_report,
)

# -----------------------------
# Flask Configuration
# -----------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates")
)

DATA_FOLDER = os.path.join(BASE_DIR, "data")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")


# -----------------------------
# Home Page
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------
# Analyze Applications
# -----------------------------
@app.route("/analyze")
def analyze():

    # Load data
    data = load_all(DATA_FOLDER)

    applications = data["applications"]
    dependencies_df = data["dependencies"]
    vulnerabilities = data["vulnerabilities"]
    license_rules = data["license_rules"]

    # Build dependency graph
    graph = build_graph(dependencies_df)

    # Calculate risks
    all_findings = calculate_risk(
        dependencies_df,
        vulnerabilities,
        license_rules,
        graph=graph,
    )

    # License analysis
    license_findings = check_licenses(
        dependencies_df,
        license_rules,
    )

    application_reports = []

    # Build report for every application
    for application in applications:

        app_name = application["application_name"]

        app_findings = [
            finding
            for finding in all_findings
            if finding["application"] == app_name
        ]

        total_risk_score = sum(
            finding["risk_score"] for finding in app_findings
        )

        if total_risk_score >= 600:
            risk_level = "Critical"
        elif total_risk_score >= 350:
            risk_level = "High"
        elif total_risk_score >= 200
            risk_level = "Medium"
        else:
            risk_level = "Low"

        dependency_results = []

        for finding in app_findings:

            dependency_results.append(
                {
                    "library_name": finding["library"],
                    "issue_type": finding["issue_type"],
                    "severity": finding["severity"],
                    "risk_score": finding["risk_score"],
                    "recommendation": finding["recommendation"],

                    "is_vulnerable":
                        finding["issue_type"] == "Vulnerable Library",

                    "is_license_conflict":
                        finding["issue_type"] == "License Conflict",

                    "is_unmaintained":
                        finding["issue_type"] == "Unmaintained Library",
                }
            )

        report = generate_application_report(
            application_name=app_name,
            dependency_results=dependency_results,
            total_risk_score=round(total_risk_score, 2),
            risk_level=risk_level,
        )

        # Add extra fields for HTML
        report["business_criticality"] = application.get(
            "business_criticality",
            "-"
        )

        report["owner"] = application.get(
            "owner",
            "-"
        )

        application_reports.append(report)

    # Fleet summary
    summary = generate_summary(application_reports)

    # Save reports
    save_json_report(
        os.path.join(OUTPUT_FOLDER, "report.json"),
        application_reports,
        summary,
    )

    save_csv_report(
        os.path.join(OUTPUT_FOLDER, "findings.csv"),
        application_reports,
    )

    # Render HTML
    return render_template(
        "report.html",
        summary=summary,
        application_reports=application_reports,
        license_by_license=summarize_by_license(
            license_findings
        ),
        license_by_application=summarize_by_application(
            license_findings
        ),
    )


# -----------------------------
# Run Application
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)