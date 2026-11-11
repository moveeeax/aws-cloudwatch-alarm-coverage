from __future__ import annotations

import datetime as dt
import json

from aws_cloudwatch_alarm_coverage.engine import evaluate
from aws_cloudwatch_alarm_coverage.report import render, render_json, render_markdown, render_text

NOW = dt.datetime(2026, 11, 11, 9, 0, tzinfo=dt.timezone.utc)


def test_text_report_shows_the_fix_next_to_the_finding(account):
    report = evaluate(account, now=NOW)
    out = render_text(report)

    assert "CloudWatch alarm coverage — eu-central-1" in out
    assert "no alarm on required metric FreeStorageSpace" in out
    assert "fix: alarm on AWS/RDS FreeStorageSpace with dimension DBInstanceIdentifier=prod-db" in out
    assert out.rstrip().splitlines()[-1].startswith("Result: critical")


def test_text_report_hides_ok_resources_by_default(account):
    report = evaluate(account, now=NOW)

    assert "target group web-tg" not in render_text(report)
    assert "target group web-tg" in render_text(report, show_ok=True)


def test_clean_report_says_so():
    report = evaluate({"region": "eu-west-1", "alarms": [], "resources": []}, now=NOW)

    assert "No findings" in render_text(report)
    assert "Every inventoried resource has actionable coverage." in render_markdown(report)


def test_json_report_is_valid_json_with_datetimes_stringified(account):
    for entry in account["alarms"]:
        if entry["AlarmName"] == "orders-age":
            entry["StateUpdatedTimestamp"] = dt.datetime(2026, 1, 9, tzinfo=dt.timezone.utc)
    report = evaluate(account, now=NOW)

    parsed = json.loads(render_json(report))
    assert parsed["severity"] == "critical"
    stale = next(a for a in parsed["alarms"] if a["name"] == "orders-age")
    finding = next(f for f in stale["findings"] if f["code"] == "insufficient_data")
    assert finding["details"]["state_updated"] == "2026-01-09 00:00:00+00:00"


def test_render_dispatches_on_format(account):
    report = evaluate(account, now=NOW)

    assert render(report, "json").startswith("{")
    assert render(report, "markdown").startswith("## CloudWatch")
    assert render(report, "text").startswith("CloudWatch")
