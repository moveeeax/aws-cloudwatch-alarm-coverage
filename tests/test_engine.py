"""The acceptance criteria, as tests."""

from __future__ import annotations

import datetime as dt

import pytest

from aws_cloudwatch_alarm_coverage.engine import evaluate
from aws_cloudwatch_alarm_coverage.model import CRITICAL, OK, WARN, InputError
from aws_cloudwatch_alarm_coverage.rules import RuleTable, load_rules

NOW = dt.datetime(2026, 11, 11, 9, 0, tzinfo=dt.timezone.utc)


def report_for(payload, **kwargs):
    kwargs.setdefault("now", NOW)
    return evaluate(payload, **kwargs)


def resource(report, identifier):
    for row in report["resources"]:
        if row["id"] == identifier:
            return row
    raise AssertionError(f"{identifier} not in report")


def alarm(report, name):
    for row in report["alarms"]:
        if row["name"] == name:
            return row
    return None


def codes(row):
    return {finding["code"] for finding in row["findings"]}


def test_missing_required_metric_is_critical_and_names_the_dimension(account):
    report = report_for(account)
    row = resource(report, "prod-db")

    assert row["severity"] == CRITICAL
    missing = [f for f in row["findings"] if f["code"] == "missing_required_alarm"]
    assert [f["details"]["metric"] for f in missing] == ["FreeStorageSpace"]
    fix = missing[0]["fix"]
    assert "AWS/RDS" in fix
    assert "FreeStorageSpace" in fix
    assert "DBInstanceIdentifier=prod-db" in fix


def test_present_required_alarm_is_not_reported(account):
    """The same instance with the alarm present stops being flagged for it."""
    account["alarms"].append(
        {
            "AlarmName": "prod-db-storage",
            "Namespace": "AWS/RDS",
            "MetricName": "FreeStorageSpace",
            "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "prod-db"}],
            "StateValue": "OK",
            "AlarmActions": ["arn:aws:sns:eu-central-1:111122223333:platform-alerts"],
            "ActionsEnabled": True,
            "ComparisonOperator": "LessThanThreshold",
            "Threshold": 10737418240.0,
        }
    )
    row = resource(report_for(account), "prod-db")

    assert "missing_required_alarm" not in codes(row)
    assert row["severity"] == WARN  # only the recommended DatabaseConnections metric is left


def test_resource_with_no_alarms_at_all_is_critical(account):
    row = resource(report_for(account), "reporting-db")

    assert row["severity"] == CRITICAL
    assert codes(row) == {"no_alarms"}
    finding = row["findings"][0]
    assert finding["details"]["required_metrics"] == ["CPUUtilization", "FreeStorageSpace"]
    assert row["alarms"] == []


def test_empty_alarm_actions_is_not_coverage_and_the_alarm_is_critical(account):
    report = report_for(account)

    worker = resource(report, "invoice-worker")
    not_actionable = [f for f in worker["findings"] if f["code"] == "coverage_not_actionable"]
    assert [f["details"]["metric"] for f in not_actionable] == ["Errors"]
    assert worker["severity"] == CRITICAL

    decorative = alarm(report, "invoice-worker-errors")
    assert decorative is not None
    assert decorative["severity"] == CRITICAL
    assert "decorative_alarm" in codes(decorative)


def test_actions_disabled_is_critical_and_voids_coverage(account):
    report = report_for(account)

    row = alarm(report, "web-lb-5xx")
    assert "actions_disabled" in codes(row)
    assert row["severity"] == CRITICAL

    lb = resource(report, "web")
    assert "coverage_not_actionable" in codes(lb)


def test_alarm_without_actions_counts_when_a_composite_pages(account):
    """invoice-worker-throttles has no actions but platform-pager references it."""
    report = report_for(account)

    assert alarm(report, "invoice-worker-throttles") is None
    worker = resource(report, "invoice-worker")
    covered = [f for f in worker["findings"] if f["details"].get("metric") == "Throttles"]
    assert covered == []


def test_orphaned_alarm_is_warn_and_names_the_dimension_value(account):
    row = alarm(report_for(account), "legacy-db-cpu")

    assert row["severity"] == WARN
    finding = next(f for f in row["findings"] if f["code"] == "orphaned_alarm")
    assert finding["details"] == {"dimension": "DBInstanceIdentifier", "value": "legacy-db"}
    assert "legacy-db" in finding["message"]


def test_insufficient_data_is_warn_with_the_age(account):
    row = alarm(report_for(account), "orders-age")

    finding = next(f for f in row["findings"] if f["code"] == "insufficient_data")
    assert finding["severity"] == WARN
    assert "150 days" in finding["message"]


def test_insufficient_data_without_a_stale_timestamp_omits_the_age(account):
    for entry in account["alarms"]:
        if entry["AlarmName"] == "orders-age":
            entry["StateUpdatedTimestamp"] = "2026-11-11T08:00:00+00:00"
    row = alarm(report_for(account), "orders-age")

    finding = next(f for f in row["findings"] if f["code"] == "insufficient_data")
    assert "days" not in finding["message"]


def test_zero_threshold_is_a_placeholder_except_for_greater_than(account):
    report = report_for(account)

    sessions = alarm(report, "sessions-throttles")
    assert "placeholder_threshold" in codes(sessions)
    # bastion-status is threshold 0 with GreaterThanThreshold, the idiomatic form
    assert alarm(report, "bastion-status") is None


def test_dimension_containment_covers_a_target_group_alarm(account):
    """The alarm carries TargetGroup plus LoadBalancer; both resources are covered."""
    report = report_for(account)

    assert resource(report, "web-tg")["severity"] == OK
    assert sorted(resource(report, "web-tg")["alarms"]) == ["web-tg-latency", "web-tg-unhealthy"]
    lb = resource(report, "web")
    assert "missing_recommended_alarm" not in codes(lb)


def test_services_filter_narrows_both_inventory_and_orphan_checks(account):
    report = report_for(account, services=["lambda"])

    assert {row["type"] for row in report["resources"]} == {"lambda_function"}
    assert report["services"] == ["lambda"]
    # the RDS alarm is no longer checked for orphanhood, only for being decorative
    assert alarm(report, "legacy-db-cpu") is None


def test_rules_override_can_silence_and_promote_metrics(account, tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rds_instance:\n"
        "  FreeStorageSpace: off\n"
        "  DatabaseConnections: required\n",
        encoding="utf-8",
    )
    row = resource(report_for(account, table=load_rules(str(path))), "prod-db")

    missing = {f["details"]["metric"]: f["severity"] for f in row["findings"]}
    assert "FreeStorageSpace" not in missing
    assert missing["DatabaseConnections"] == CRITICAL


def test_summary_and_overall_severity(account):
    report = report_for(account)

    assert report["severity"] == CRITICAL
    assert report["region"] == "eu-central-1"
    summary = report["summary"]
    assert summary["resources"] == 8
    assert summary["metric_alarms"] == 10
    assert summary["composite_alarms"] == 1
    assert summary["resources_ok"] == 1
    assert summary["findings"] > 0


def test_clean_account_has_no_findings():
    report = report_for({"region": "eu-west-1", "alarms": [], "resources": []})

    assert report["severity"] == OK
    assert report["summary"]["findings"] == 0


def test_metric_math_alarm_resolves_its_inner_metric():
    payload = {
        "region": "eu-west-1",
        "alarms": [
            {
                "AlarmName": "math",
                "AlarmActions": ["arn:aws:sns:eu-west-1:1:x"],
                "StateValue": "OK",
                "Metrics": [
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": "AWS/Lambda",
                                "MetricName": "Errors",
                                "Dimensions": [{"Name": "FunctionName", "Value": "fn"}],
                            },
                            "Period": 300,
                            "Stat": "Sum",
                        },
                    }
                ],
            }
        ],
        "resources": [
            {"type": "lambda_function", "id": "fn", "dimensions": {"FunctionName": "fn"}}
        ],
    }
    row = resource(report_for(payload, services=["lambda"]), "fn")

    assert "missing_required_alarm" in codes(row)
    assert [f["details"]["metric"] for f in row["findings"] if f["code"] == "missing_required_alarm"] == [
        "Throttles"
    ]


@pytest.mark.parametrize(
    "payload,message",
    [
        ([], "must be a JSON object"),
        ({"resources": {}}, "must be a list"),
        ({"resources": [{"type": "nope", "id": "x"}]}, "unknown type"),
        ({"resources": [{"type": "rds_instance"}]}, "missing 'id'"),
        ({"composite_alarms": "x"}, "must be a list"),
    ],
)
def test_malformed_payload_raises_input_error(payload, message):
    with pytest.raises(InputError) as excinfo:
        evaluate(payload, table=RuleTable(), now=NOW)
    assert message in str(excinfo.value)
