"""Rendering: text for humans, json for pipelines, markdown for pull requests."""

from __future__ import annotations

import json
from typing import Any

from .model import CRITICAL, OK, WARN, dimension_string

_MARK = {CRITICAL: "CRIT", WARN: "WARN", OK: " ok "}


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False, default=str)


def _header(report: dict[str, Any]) -> str:
    summary = report["summary"]
    region = report.get("region") or "(region unknown)"
    return (
        f"CloudWatch alarm coverage — {region}\n"
        f"{summary['resources']} resources, {summary['metric_alarms']} metric alarms "
        f"+ {summary['composite_alarms']} composite, {summary['findings']} findings"
    )


def render_text(report: dict[str, Any], show_ok: bool = False) -> str:
    lines: list[str] = [_header(report), ""]

    rows = [r for r in report["resources"] if show_ok or r["severity"] != OK]
    if rows:
        lines.append("Resources")
        for row in rows:
            lines.append(
                f"  [{_MARK[row['severity']]}] {row['label']} {row['id']}"
                f"  ({dimension_string(row['dimensions'])})"
            )
            for finding in row["findings"]:
                lines.append(f"         {finding['severity']}: {finding['message']}")
                if finding.get("fix"):
                    lines.append(f"           fix: {finding['fix']}")
            if row["severity"] == OK and row["alarms"]:
                lines.append(f"           alarms: {', '.join(row['alarms'])}")
        lines.append("")

    if report["alarms"]:
        lines.append("Alarms")
        for row in report["alarms"]:
            lines.append(f"  [{_MARK[row['severity']]}] {row['name']}  ({row['state']})")
            for finding in row["findings"]:
                lines.append(f"         {finding['severity']}: {finding['message']}")
                if finding.get("fix"):
                    lines.append(f"           fix: {finding['fix']}")
        lines.append("")

    if not rows and not report["alarms"]:
        lines.append("No findings: every inventoried resource has actionable coverage.")
        lines.append("")

    summary = report["summary"]
    lines.append(
        f"Result: {report['severity']} "
        f"({summary['resources_critical']} critical resources, {summary['resources_warn']} warn, "
        f"{summary['alarms_with_findings']} alarms with problems)"
    )
    return "\n".join(lines)


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    region = report.get("region") or "unknown region"
    lines: list[str] = [
        f"## CloudWatch alarm coverage — {region}",
        "",
        f"- Resources inventoried: **{summary['resources']}** "
        f"({summary['resources_critical']} critical, {summary['resources_warn']} warn, "
        f"{summary['resources_ok']} ok)",
        f"- Alarms indexed: **{summary['metric_alarms']}** metric, "
        f"{summary['composite_alarms']} composite",
        f"- Findings: **{summary['findings']}**",
        f"- Result: **{report['severity']}**",
        "",
    ]

    rows = [r for r in report["resources"] if r["severity"] != OK]
    if rows:
        lines += [
            "### Resources missing coverage",
            "",
            "| Severity | Resource | Finding | Fix |",
            "| --- | --- | --- | --- |",
        ]
        for row in rows:
            for finding in row["findings"]:
                lines.append(
                    f"| {finding['severity']} | `{row['id']}` ({row['label']}) "
                    f"| {finding['message']} | {finding.get('fix', '')} |"
                )
        lines.append("")

    if report["alarms"]:
        lines += [
            "### Alarms that are not what they look like",
            "",
            "| Severity | Alarm | Finding |",
            "| --- | --- | --- |",
        ]
        for row in report["alarms"]:
            for finding in row["findings"]:
                lines.append(f"| {finding['severity']} | `{row['name']}` | {finding['message']} |")
        lines.append("")

    if not rows and not report["alarms"]:
        lines += ["Every inventoried resource has actionable coverage.", ""]

    return "\n".join(lines)


def render(report: dict[str, Any], fmt: str, show_ok: bool = False) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    return render_text(report, show_ok=show_ok)
