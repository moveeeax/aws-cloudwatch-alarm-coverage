"""The rule engine: turns a payload plus a rule table into a report."""

from __future__ import annotations

import datetime as dt
from typing import Any

from .alarms import AlarmIndex
from .model import CRITICAL, OK, WARN, Finding, InputError, dimension_string, worst
from .rules import RECOMMENDED, RESOURCE_TYPES, RuleTable, is_count_metric, types_for_services

# A threshold of 0 with this operator is the idiomatic "alert on any occurrence".
_ANY_OCCURRENCE = "GreaterThanThreshold"


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def validate_payload(payload: Any) -> dict[str, Any]:
    """Reject a payload that would otherwise blow up deep inside a rule."""
    if not isinstance(payload, dict):
        raise InputError("payload must be a JSON object")
    for key in ("alarms", "resources"):
        if key in payload and not isinstance(payload[key], list):
            raise InputError(f"payload key {key!r} must be a list")
    if "composite_alarms" in payload and not isinstance(payload["composite_alarms"], list):
        raise InputError("payload key 'composite_alarms' must be a list")
    for index, resource in enumerate(payload.get("resources") or []):
        if not isinstance(resource, dict):
            raise InputError(f"payload resources[{index}] must be an object")
        rtype = resource.get("type")
        if rtype not in RESOURCE_TYPES:
            raise InputError(
                f"payload resources[{index}] has unknown type {rtype!r}; "
                f"known types are {', '.join(sorted(RESOURCE_TYPES))}"
            )
        if not resource.get("id"):
            raise InputError(f"payload resources[{index}] is missing 'id'")
    return payload


def _inventory_index(resources: list[dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
    """(namespace, dimension name) -> every value we actually saw running."""
    index: dict[tuple[str, str], set[str]] = {}
    for resource in resources:
        spec = RESOURCE_TYPES[resource["type"]]
        for name, value in (resource.get("dimensions") or {}).items():
            index.setdefault((spec["namespace"], name), set()).add(value)
    return index


def _resource_dimensions(resource: dict[str, Any]) -> dict[str, str]:
    spec = RESOURCE_TYPES[resource["type"]]
    dims = resource.get("dimensions") or {}
    return {name: dims[name] for name in spec["dimensions"] if name in dims}


def _coverage_findings(
    resource: dict[str, Any], index: AlarmIndex, table: RuleTable
) -> tuple[list[Finding], list[str]]:
    spec = RESOURCE_TYPES[resource["type"]]
    namespace = spec["namespace"]
    dims = _resource_dimensions(resource)
    expectations = table.metrics_for(resource["type"])

    attached = index.any_for_resource(namespace, dims)
    attached_names = sorted(alarm["name"] for alarm in attached)

    if not attached:
        required = table.required_metrics(resource["type"])
        wanted = ", ".join(required) if required else "any metric that matters"
        return (
            [
                Finding(
                    severity=CRITICAL,
                    code="no_alarms",
                    subject=resource["id"],
                    message=f"no CloudWatch alarm references this {spec['label']} on any metric",
                    fix=f"alarm on {namespace} {wanted} with dimension {dimension_string(dims)}",
                    details={"required_metrics": required},
                )
            ],
            attached_names,
        )

    findings: list[Finding] = []
    for metric, level in sorted(expectations.items()):
        severity = WARN if level == RECOMMENDED else CRITICAL
        matched = index.for_resource(namespace, metric, dims)
        if not matched:
            findings.append(
                Finding(
                    severity=severity,
                    code=f"missing_{level}_alarm",
                    subject=resource["id"],
                    message=f"no alarm on {level} metric {metric}",
                    fix=f"alarm on {namespace} {metric} with dimension {dimension_string(dims)}",
                    details={"metric": metric, "namespace": namespace, "level": level},
                )
            )
            continue
        if not any(alarm["actionable"] for alarm in matched):
            names = ", ".join(sorted(alarm["name"] for alarm in matched))
            findings.append(
                Finding(
                    severity=severity,
                    code="coverage_not_actionable",
                    subject=resource["id"],
                    message=f"{metric} is only covered by alarms that notify nobody: {names}",
                    fix=f"add an SNS action to {names}, or reference it from a composite alarm that has one",
                    details={"metric": metric, "alarms": sorted(a["name"] for a in matched)},
                )
            )
    return findings, attached_names


def _alarm_findings(
    alarm: dict[str, Any],
    inventory: dict[tuple[str, str], set[str]],
    checked_dimensions: set[tuple[str, str]],
    lookback_days: int,
    now: dt.datetime,
) -> list[Finding]:
    findings: list[Finding] = []
    name = alarm["name"]

    if not alarm.get("composite_parent"):
        if not alarm["actions"]:
            findings.append(
                Finding(
                    severity=CRITICAL,
                    code="decorative_alarm",
                    subject=name,
                    message="AlarmActions is empty, so breaching this alarm notifies nobody",
                    fix="attach an SNS topic (or any action) to the alarm, or delete it",
                )
            )
        elif not alarm["actions_enabled"]:
            findings.append(
                Finding(
                    severity=CRITICAL,
                    code="actions_disabled",
                    subject=name,
                    message="ActionsEnabled is false, so the configured actions never fire",
                    fix="re-enable actions with enable-alarm-actions",
                )
            )

    if alarm["state"] == "INSUFFICIENT_DATA":
        updated = _parse_timestamp(alarm.get("state_updated"))
        age = ""
        if updated:
            days = (now - updated).days
            if days >= lookback_days:
                age = f" for {days} days"
        findings.append(
            Finding(
                severity=WARN,
                code="insufficient_data",
                subject=name,
                message=f"alarm has been in INSUFFICIENT_DATA{age}; it has never evaluated anything",
                fix="check the metric name, dimensions and period; the metric is probably not being emitted",
                details={"state_updated": alarm.get("state_updated")},
            )
        )

    for dim_name, dim_value in sorted(alarm["dimensions"].items()):
        key = (alarm["namespace"], dim_name)
        if key not in checked_dimensions:
            continue
        if dim_value not in inventory.get(key, set()):
            findings.append(
                Finding(
                    severity=WARN,
                    code="orphaned_alarm",
                    subject=name,
                    message=f"dimension {dim_name}={dim_value} matches no live resource",
                    fix="delete the alarm; the resource it watched is gone and it will report OK forever",
                    details={"dimension": dim_name, "value": dim_value},
                )
            )

    threshold = alarm.get("threshold")
    metric = alarm.get("metric_name") or ""
    if threshold == 0 and is_count_metric(metric) and alarm.get("comparison") != _ANY_OCCURRENCE:
        findings.append(
            Finding(
                severity=WARN,
                code="placeholder_threshold",
                subject=name,
                message=(
                    f"threshold 0 with {alarm.get('comparison')} on count metric {metric} "
                    "is trivially true or trivially false"
                ),
                fix=f"use {_ANY_OCCURRENCE} with threshold 0, or set a real threshold",
                details={"metric": metric, "comparison": alarm.get("comparison")},
            )
        )

    return findings


def evaluate(
    payload: dict[str, Any],
    table: RuleTable | None = None,
    services: list[str] | None = None,
    lookback_days: int = 14,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Join alarms to resources and return the full report document."""
    validate_payload(payload)
    table = table or RuleTable()
    now = now or dt.datetime.now(dt.timezone.utc)

    selected = services or payload.get("services") or sorted({s["service"] for s in RESOURCE_TYPES.values()})
    wanted_types = set(types_for_services(list(selected)))

    resources = [r for r in (payload.get("resources") or []) if r["type"] in wanted_types]
    index = AlarmIndex(payload.get("alarms") or [], payload.get("composite_alarms") or [])
    inventory = _inventory_index(resources)
    checked_dimensions = {
        (RESOURCE_TYPES[rtype]["namespace"], dim)
        for rtype in wanted_types
        for dim in RESOURCE_TYPES[rtype]["dimensions"]
    }

    resource_rows: list[dict[str, Any]] = []
    for resource in sorted(resources, key=lambda r: (r["type"], r["id"])):
        findings, attached = _coverage_findings(resource, index, table)
        severity = worst(*[f.severity for f in findings]) if findings else OK
        resource_rows.append(
            {
                "type": resource["type"],
                "label": RESOURCE_TYPES[resource["type"]]["label"],
                "id": resource["id"],
                "dimensions": _resource_dimensions(resource),
                "severity": severity,
                "alarms": attached,
                "findings": [f.to_dict() for f in findings],
            }
        )

    alarm_rows: list[dict[str, Any]] = []
    for alarm in sorted(index.alarms, key=lambda a: a["name"]):
        findings = _alarm_findings(alarm, inventory, checked_dimensions, lookback_days, now)
        if not findings:
            continue
        alarm_rows.append(
            {
                "name": alarm["name"],
                "namespace": alarm["namespace"],
                "metric": alarm["metric_name"],
                "dimensions": alarm["dimensions"],
                "state": alarm["state"],
                "severity": worst(*[f.severity for f in findings]),
                "findings": [f.to_dict() for f in findings],
            }
        )

    all_severities = [row["severity"] for row in resource_rows] + [row["severity"] for row in alarm_rows]
    overall = worst(*all_severities) if all_severities else OK

    return {
        "region": payload.get("region"),
        "collected_at": payload.get("collected_at"),
        "services": sorted(selected),
        "severity": overall,
        "summary": {
            "resources": len(resource_rows),
            "resources_critical": sum(1 for r in resource_rows if r["severity"] == CRITICAL),
            "resources_warn": sum(1 for r in resource_rows if r["severity"] == WARN),
            "resources_ok": sum(1 for r in resource_rows if r["severity"] == OK),
            "metric_alarms": len(index.alarms),
            "composite_alarms": len(index.composites),
            "alarms_with_findings": len(alarm_rows),
            "findings": sum(len(r["findings"]) for r in resource_rows)
            + sum(len(a["findings"]) for a in alarm_rows),
        },
        "resources": resource_rows,
        "alarms": alarm_rows,
    }
