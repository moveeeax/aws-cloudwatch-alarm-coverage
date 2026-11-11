"""The declarative table of what must be alarmed, plus the YAML override loader."""

from __future__ import annotations

from typing import Any

from .model import InputError

# Resource types we can inventory, and the dimension shape CloudWatch uses for each.
# `service` is what --services accepts, so one service can own several resource types.
RESOURCE_TYPES: dict[str, dict[str, Any]] = {
    "rds_instance": {
        "service": "rds",
        "label": "RDS instance",
        "namespace": "AWS/RDS",
        "dimensions": ["DBInstanceIdentifier"],
    },
    "rds_cluster": {
        "service": "rds",
        "label": "RDS cluster",
        "namespace": "AWS/RDS",
        "dimensions": ["DBClusterIdentifier"],
    },
    "load_balancer": {
        "service": "elbv2",
        "label": "load balancer",
        "namespace": "AWS/ApplicationELB",
        "dimensions": ["LoadBalancer"],
    },
    "target_group": {
        "service": "elbv2",
        "label": "target group",
        "namespace": "AWS/ApplicationELB",
        "dimensions": ["TargetGroup"],
    },
    "sqs_queue": {
        "service": "sqs",
        "label": "SQS queue",
        "namespace": "AWS/SQS",
        "dimensions": ["QueueName"],
    },
    "lambda_function": {
        "service": "lambda",
        "label": "Lambda function",
        "namespace": "AWS/Lambda",
        "dimensions": ["FunctionName"],
    },
    "ecs_service": {
        "service": "ecs",
        "label": "ECS service",
        "namespace": "AWS/ECS",
        "dimensions": ["ClusterName", "ServiceName"],
    },
    "dynamodb_table": {
        "service": "dynamodb",
        "label": "DynamoDB table",
        "namespace": "AWS/DynamoDB",
        "dimensions": ["TableName"],
    },
    "ec2_instance": {
        "service": "ec2",
        "label": "EC2 instance",
        "namespace": "AWS/EC2",
        "dimensions": ["InstanceId"],
    },
}

SERVICES: list[str] = sorted({spec["service"] for spec in RESOURCE_TYPES.values()})

REQUIRED = "required"
RECOMMENDED = "recommended"

# metric -> required|recommended, per resource type. Overridable with --rules.
DEFAULT_RULES: dict[str, dict[str, str]] = {
    "rds_instance": {
        "CPUUtilization": REQUIRED,
        "FreeStorageSpace": REQUIRED,
        "DatabaseConnections": RECOMMENDED,
    },
    "rds_cluster": {
        "CPUUtilization": REQUIRED,
        "DatabaseConnections": RECOMMENDED,
    },
    "load_balancer": {
        "HTTPCode_ELB_5XX_Count": REQUIRED,
        "TargetResponseTime": RECOMMENDED,
    },
    "target_group": {
        "UnHealthyHostCount": REQUIRED,
        "TargetResponseTime": REQUIRED,
    },
    "sqs_queue": {
        "ApproximateAgeOfOldestMessage": REQUIRED,
        "ApproximateNumberOfMessagesVisible": RECOMMENDED,
    },
    "lambda_function": {
        "Errors": REQUIRED,
        "Throttles": REQUIRED,
        "Duration": RECOMMENDED,
    },
    "ecs_service": {
        "CPUUtilization": REQUIRED,
        "MemoryUtilization": REQUIRED,
    },
    "dynamodb_table": {
        "ThrottledRequests": REQUIRED,
        "SystemErrors": RECOMMENDED,
    },
    "ec2_instance": {
        "StatusCheckFailed": REQUIRED,
        "CPUUtilization": RECOMMENDED,
    },
}

# Metrics that count events. A threshold of 0 on these is usually a placeholder,
# except with GreaterThanThreshold, which is the idiomatic "any occurrence at all".
COUNT_METRICS = {
    "Errors",
    "Throttles",
    "ThrottledRequests",
    "SystemErrors",
    "StatusCheckFailed",
    "StatusCheckFailed_Instance",
    "StatusCheckFailed_System",
    "UnHealthyHostCount",
    "HTTPCode_ELB_5XX_Count",
    "HTTPCode_Target_5XX_Count",
    "ApproximateNumberOfMessagesVisible",
    "DeadLetterQueueMessagesVisible",
}


def is_count_metric(metric_name: str) -> bool:
    return metric_name in COUNT_METRICS or metric_name.endswith("Count")


class RuleTable:
    """Metric expectations per resource type, after any override is merged in."""

    def __init__(self, table: dict[str, dict[str, str]] | None = None) -> None:
        self.table = table if table is not None else {k: dict(v) for k, v in DEFAULT_RULES.items()}

    def metrics_for(self, resource_type: str) -> dict[str, str]:
        return self.table.get(resource_type, {})

    def required_metrics(self, resource_type: str) -> list[str]:
        return [m for m, level in self.metrics_for(resource_type).items() if level == REQUIRED]

    def known_metrics(self) -> list[str]:
        seen = set()
        for metrics in self.table.values():
            seen.update(metrics)
        return sorted(seen)

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {k: dict(v) for k, v in self.table.items()}


def load_rules(path: str | None) -> RuleTable:
    """Merge a YAML override on top of DEFAULT_RULES.

    The file maps resource type -> metric -> required|recommended|off. `off`
    deletes an expectation, which is how you silence a metric you do not want.
    """
    table = {k: dict(v) for k, v in DEFAULT_RULES.items()}
    if not path:
        return RuleTable(table)

    import yaml  # imported lazily so --help works without PyYAML installed

    try:
        with open(path, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
    except OSError as exc:
        raise InputError(f"cannot read rules file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise InputError(f"rules file {path} is not valid YAML: {exc}") from exc

    if raw is None:
        return RuleTable(table)
    if not isinstance(raw, dict):
        raise InputError(f"rules file {path} must be a mapping of resource type to metrics")

    for resource_type, metrics in raw.items():
        if resource_type not in RESOURCE_TYPES:
            raise InputError(
                f"rules file {path}: unknown resource type {resource_type!r}; "
                f"known types are {', '.join(sorted(RESOURCE_TYPES))}"
            )
        if not isinstance(metrics, dict):
            raise InputError(f"rules file {path}: {resource_type} must map metric names to levels")
        bucket = table.setdefault(resource_type, {})
        for metric, level in metrics.items():
            if level in (None, "off", False):
                bucket.pop(metric, None)
                continue
            if level not in (REQUIRED, RECOMMENDED):
                raise InputError(
                    f"rules file {path}: {resource_type}.{metric} is {level!r}, "
                    "expected required, recommended or off"
                )
            bucket[metric] = level

    return RuleTable(table)


def parse_services(value: str | None) -> list[str]:
    """Validate a --services list, defaulting to everything we support."""
    if not value:
        return list(SERVICES)
    wanted = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in wanted if item not in SERVICES]
    if unknown:
        raise InputError(
            f"unknown service(s): {', '.join(unknown)}; supported: {', '.join(SERVICES)}"
        )
    return wanted


def types_for_services(services: list[str]) -> list[str]:
    return [name for name, spec in RESOURCE_TYPES.items() if spec["service"] in services]
