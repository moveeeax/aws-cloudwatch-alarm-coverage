from __future__ import annotations

from aws_cloudwatch_alarm_coverage.alarms import AlarmIndex, normalize_alarm, normalize_composite


def test_normalize_alarm_flattens_dimensions_and_defaults():
    alarm = normalize_alarm(
        {
            "AlarmName": "db-cpu",
            "Namespace": "AWS/RDS",
            "MetricName": "CPUUtilization",
            "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": "prod-db"}],
        }
    )

    assert alarm["dimensions"] == {"DBInstanceIdentifier": "prod-db"}
    assert alarm["state"] == "INSUFFICIENT_DATA"
    assert alarm["actions"] == []
    assert alarm["actions_enabled"] is True
    assert alarm["composite"] is False


def test_normalize_composite_extracts_child_names_from_the_rule():
    composite = normalize_composite(
        {
            "AlarmName": "pager",
            "AlarmRule": (
                'ALARM("a-errors") OR (ALARM("b-errors") '
                "AND ALARM(arn:aws:cloudwatch:eu-west-1:1:alarm:c-errors))"
            ),
            "AlarmActions": ["arn:aws:sns:eu-west-1:1:pager"],
        }
    )

    assert composite["children"] == ["a-errors", "b-errors", "c-errors"]
    assert composite["composite"] is True


def test_index_matches_by_dimension_containment_not_equality():
    index = AlarmIndex(
        [
            {
                "AlarmName": "tg-unhealthy",
                "Namespace": "AWS/ApplicationELB",
                "MetricName": "UnHealthyHostCount",
                "Dimensions": [
                    {"Name": "TargetGroup", "Value": "targetgroup/web/abc"},
                    {"Name": "LoadBalancer", "Value": "app/web/def"},
                ],
                "AlarmActions": ["arn:aws:sns:eu-west-1:1:x"],
            }
        ],
        [],
    )

    matched = index.for_resource(
        "AWS/ApplicationELB", "UnHealthyHostCount", {"TargetGroup": "targetgroup/web/abc"}
    )
    assert [a["name"] for a in matched] == ["tg-unhealthy"]

    assert index.for_resource("AWS/ApplicationELB", "UnHealthyHostCount", {"TargetGroup": "other"}) == []
    assert (
        index.for_resource(
            "AWS/ApplicationELB", "TargetResponseTime", {"TargetGroup": "targetgroup/web/abc"}
        )
        == []
    )


def test_any_for_resource_ignores_the_metric_name():
    index = AlarmIndex(
        [
            {
                "AlarmName": "a",
                "Namespace": "AWS/SQS",
                "MetricName": "ApproximateAgeOfOldestMessage",
                "Dimensions": [{"Name": "QueueName", "Value": "orders"}],
            }
        ],
        [],
    )

    assert len(index.any_for_resource("AWS/SQS", {"QueueName": "orders"})) == 1
    assert index.any_for_resource("AWS/SQS", {"QueueName": "invoices"}) == []


def test_actionable_follows_composite_parents():
    metric_alarms = [
        {"AlarmName": "child", "Namespace": "AWS/Lambda", "MetricName": "Errors", "AlarmActions": []},
        {"AlarmName": "lonely", "Namespace": "AWS/Lambda", "MetricName": "Throttles", "AlarmActions": []},
    ]
    composites = [
        {
            "AlarmName": "pager",
            "AlarmRule": 'ALARM("child")',
            "AlarmActions": ["arn:aws:sns:eu-west-1:1:pager"],
        },
        {"AlarmName": "silent", "AlarmRule": 'ALARM("lonely")', "AlarmActions": []},
    ]
    index = AlarmIndex(metric_alarms, composites)
    by_name = {alarm["name"]: alarm for alarm in index.alarms}

    assert by_name["child"]["actionable"] is True
    assert by_name["lonely"]["actionable"] is False
    assert len(index) == 4
