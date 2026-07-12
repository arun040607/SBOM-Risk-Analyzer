"""
report_generator.py

Report generation module for the SBOM Risk Analyzer.

This module takes the already-computed results from graph_builder.py,
risk_calculator.py, and license_checker.py, and turns them into:
    1. A per-application report (dictionary)
    2. A fleet-wide summary (dictionary)
    3. A saved JSON report (file)
    4. A saved CSV report of findings (file)

No graph logic, no risk-scoring logic, and no license-checking logic
lives here -- this file only shapes and saves results that were already
calculated elsewhere.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

import pandas as pd


def generate_application_report(
    application_name: str,
    dependency_results: List[Dict[str, Any]],
    total_risk_score: float,
    risk_level: str,
    priority: str
) -> Dict[str, Any]:
    """
    Build a single application's risk report.

    Args:
        application_name: Name of the application (e.g. "Employee Portal").
        dependency_results: A list of dictionaries, one per dependency,
            each describing that dependency's findings. Each dictionary
            is expected to look something like:
                {
                    "library_name": "log-forge",
                    "version": "1.2.3",
                    "is_vulnerable": True,
                    "is_license_conflict": False,
                    "is_unmaintained": False,
                    "details": "CVE-2024-1234 (CVSS 7.5)"
                }
            (Missing keys are treated as False / empty, so this function
            still works even with slightly different dependency dicts.)
        total_risk_score: The application's overall risk score (e.g. 82).
        risk_level: The application's risk level label
            (e.g. "Critical", "High", "Medium", "Low").

    Returns:
        A dictionary summarizing the application's risk report:
            {
                "application": "Employee Portal",
                "risk_score": 82,
                "risk_level": "High",
                "total_dependencies": 15,
                "vulnerable_dependencies": 5,
                "license_conflicts": 2,
                "unmaintained": 3,
                "findings": [...]
            }
    """
    total_dependencies = len(dependency_results)

    # Count how many dependencies fall into each issue category.
    vulnerable_count = 0
    license_conflict_count = 0
    unmaintained_count = 0

    for dependency in dependency_results:
        if dependency.get("is_vulnerable"):
            vulnerable_count += 1
        if dependency.get("is_license_conflict"):
            license_conflict_count += 1
        if dependency.get("is_unmaintained"):
            unmaintained_count += 1

    application_report = {
        "application": application_name,
        "risk_score": total_risk_score,
        "risk_level": risk_level,
        "priority": priority,
        "total_dependencies": total_dependencies,
        "vulnerable_dependencies": vulnerable_count,
        "license_conflicts": license_conflict_count,
        "unmaintained": unmaintained_count,
        "findings": dependency_results,
    }

    return application_report


def generate_summary(application_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a fleet-wide summary across every application's report.

    Args:
        application_reports: A list of dictionaries, where each
            dictionary is the output of generate_application_report()
            for one application.

    Returns:
        A dictionary counting how many applications fall into each
        risk level:
            {
                "applications": 10,
                "critical": 2,
                "high": 3,
                "medium": 4,
                "low": 1
            }
    """
    summary = {
        "applications": len(application_reports),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for report in application_reports:
        # Normalize so "High", "high", " High " all match correctly.
        risk_level = str(report.get("risk_level", "")).strip().lower()

        if risk_level == "critical":
            summary["critical"] += 1
        elif risk_level == "high":
            summary["high"] += 1
        elif risk_level == "medium":
            summary["medium"] += 1
        elif risk_level == "low":
            summary["low"] += 1
        # Unrecognized risk levels are simply not counted in any bucket.

    return summary


def save_json_report(
    filename: Union[str, Path],
    application_reports: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> None:
    """
    Save the complete report (all application reports + the summary)
    to a JSON file.

    Args:
        filename: Path to the JSON file to write (e.g. "report.json").
        application_reports: A list of per-application report
            dictionaries, each from generate_application_report().
        summary: The fleet-wide summary dictionary from generate_summary().

    Returns:
        None. Writes the JSON file to disk.
    """
    output_path = Path(filename)

    # Make sure the parent folder exists before writing the file.
    output_path.parent.mkdir(parents=True, exist_ok=True)

    full_report = {
        "summary": summary,
        "applications": application_reports,
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"JSON report saved to: {output_path}")


def save_csv_report(
    filename: Union[str, Path],
    application_reports: List[Dict[str, Any]],
) -> None:
    """
    Export every finding (across all applications) to a single CSV file.

    Each row in the CSV represents one dependency finding, tagged with
    the application it belongs to.

    Args:
        filename: Path to the CSV file to write (e.g. "findings.csv").
        application_reports: A list of per-application report
            dictionaries, each from generate_application_report().

    Returns:
        None. Writes the CSV file to disk.
    """
    output_path = Path(filename)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Flatten every application's findings into one big list of rows,
    # adding the application name onto each finding so we don't lose
    # track of where it came from.
    all_findings_rows = []

    for report in application_reports:
        application_name = report.get("application", "")
        findings = report.get("findings", [])

        for finding in findings:
            row = {"application": application_name}
            row.update(finding)
            all_findings_rows.append(row)

    if not all_findings_rows:
        # Still create an (empty) CSV so downstream steps don't break
        # if an application somehow has zero findings.
        pd.DataFrame().to_csv(output_path, index=False)
        print(f"No findings to export. Empty CSV saved to: {output_path}")
        return

    findings_df = pd.DataFrame(all_findings_rows)
    findings_df.to_csv(output_path, index=False)

    print(f"CSV report saved to: {output_path}")


if __name__ == "__main__":
    # Small demo showing how these functions fit together.
    # Replace this with real dependency_results from graph_builder.py,
    # risk_calculator.py, and license_checker.py in the actual app.

    sample_dependency_results_1 = [
        {"library_name": "log-forge", "version": "1.2.3",
         "is_vulnerable": True, "is_license_conflict": False,
         "is_unmaintained": False, "details": "CVE-2024-1234 (CVSS 7.5)"},
        {"library_name": "json-lite", "version": "2.0.0",
         "is_vulnerable": False, "is_license_conflict": True,
         "is_unmaintained": False, "details": "GPL-3.0 in distributed app"},
    ]

    sample_dependency_results_2 = [
        {"library_name": "http-toolkit", "version": "4.3.4",
         "is_vulnerable": False, "is_license_conflict": False,
         "is_unmaintained": True, "details": "No updates in 3.2 years"},
    ]

    report_1 = generate_application_report(
        "Employee Portal", sample_dependency_results_1, 82, "High"
    )
    report_2 = generate_application_report(
        "Internal Admin", sample_dependency_results_2, 40, "Medium"
    )

    all_reports = [report_1, report_2]
    summary_report = generate_summary(all_reports)

    print("Summary:", summary_report)

    save_json_report("../output/report.json", all_reports, summary_report)
    save_csv_report("../output/findings.csv", all_reports)