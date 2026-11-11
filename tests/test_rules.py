from __future__ import annotations

import pytest

from aws_cloudwatch_alarm_coverage.model import InputError
from aws_cloudwatch_alarm_coverage.rules import (
    DEFAULT_RULES,
    RESOURCE_TYPES,
    SERVICES,
    is_count_metric,
    load_rules,
    parse_services,
    types_for_services,
)


def test_every_rule_targets_a_known_resource_type():
    assert set(DEFAULT_RULES) <= set(RESOURCE_TYPES)
    for spec in RESOURCE_TYPES.values():
        assert spec["namespace"].startswith("AWS/")
        assert spec["dimensions"]


def test_default_rules_are_unchanged_by_an_override(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("ec2_instance:\n  StatusCheckFailed: off\n", encoding="utf-8")

    load_rules(str(path))

    assert DEFAULT_RULES["ec2_instance"]["StatusCheckFailed"] == "required"


def test_load_rules_without_a_path_returns_the_defaults():
    table = load_rules(None)

    assert table.required_metrics("lambda_function") == ["Errors", "Throttles"]
    assert "Duration" in table.metrics_for("lambda_function")


def test_load_rules_promotes_demotes_and_removes(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "lambda_function:\n"
        "  Duration: required\n"
        "  Throttles: off\n"
        "sqs_queue:\n"
        "  ApproximateAgeOfOldestMessage: recommended\n",
        encoding="utf-8",
    )
    table = load_rules(str(path))

    assert table.required_metrics("lambda_function") == ["Errors", "Duration"]
    assert table.metrics_for("sqs_queue")["ApproximateAgeOfOldestMessage"] == "recommended"


def test_empty_rules_file_is_accepted(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("", encoding="utf-8")

    assert load_rules(str(path)).to_dict() == DEFAULT_RULES


@pytest.mark.parametrize(
    "content,message",
    [
        ("not_a_type:\n  Foo: required\n", "unknown resource type"),
        ("rds_instance: 7\n", "must map metric names to levels"),
        ("rds_instance:\n  CPUUtilization: urgent\n", "expected required, recommended or off"),
        ("- a\n- b\n", "must be a mapping"),
        ("rds_instance:\n  - [\n", "not valid YAML"),
    ],
)
def test_bad_rules_file_raises_input_error(tmp_path, content, message):
    path = tmp_path / "rules.yaml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(InputError) as excinfo:
        load_rules(str(path))
    assert message in str(excinfo.value)


def test_missing_rules_file_raises_input_error():
    with pytest.raises(InputError) as excinfo:
        load_rules("/nonexistent/rules.yaml")
    assert "cannot read rules file" in str(excinfo.value)


def test_parse_services_defaults_to_everything():
    assert parse_services(None) == SERVICES
    assert parse_services("") == SERVICES


def test_parse_services_accepts_a_subset_and_rejects_junk():
    assert parse_services("rds, lambda") == ["rds", "lambda"]

    with pytest.raises(InputError) as excinfo:
        parse_services("rds,eks")
    assert "eks" in str(excinfo.value)


def test_types_for_services_expands_one_service_into_several_types():
    assert sorted(types_for_services(["rds"])) == ["rds_cluster", "rds_instance"]
    assert sorted(types_for_services(["elbv2"])) == ["load_balancer", "target_group"]


@pytest.mark.parametrize(
    "metric,expected",
    [
        ("Errors", True),
        ("HTTPCode_ELB_5XX_Count", True),
        ("SomethingCount", True),
        ("CPUUtilization", False),
        ("FreeStorageSpace", False),
    ],
)
def test_is_count_metric(metric, expected):
    assert is_count_metric(metric) is expected
