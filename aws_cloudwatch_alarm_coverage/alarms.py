"""The alarm index: the join between describe_alarms and everything else."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

# ALARM("name") or ALARM(arn:aws:cloudwatch:...:alarm:name) inside a composite AlarmRule.
_ALARM_REF = re.compile(r"ALARM\s*\(\s*\"?([^\")]+)\"?\s*\)", re.IGNORECASE)


def normalize_alarm(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten one describe_alarms MetricAlarms entry into what the rules need."""
    dimensions = {d.get("Name"): d.get("Value") for d in raw.get("Dimensions") or []}
    metric_name = raw.get("MetricName")
    namespace = raw.get("Namespace")

    # Metric-math and multi-stat alarms carry their real metric inside Metrics[].
    if not metric_name and raw.get("Metrics"):
        for entry in raw["Metrics"]:
            stat = entry.get("MetricStat") or {}
            metric = stat.get("Metric") or {}
            if metric.get("MetricName"):
                metric_name = metric["MetricName"]
                namespace = namespace or metric.get("Namespace")
                if not dimensions:
                    dimensions = {d.get("Name"): d.get("Value") for d in metric.get("Dimensions") or []}
                break

    return {
        "name": raw.get("AlarmName", ""),
        "arn": raw.get("AlarmArn", ""),
        "namespace": namespace,
        "metric_name": metric_name,
        "dimensions": dimensions,
        "state": raw.get("StateValue", "INSUFFICIENT_DATA"),
        "state_updated": raw.get("StateUpdatedTimestamp"),
        "actions": list(raw.get("AlarmActions") or []),
        "ok_actions": list(raw.get("OKActions") or []),
        "actions_enabled": bool(raw.get("ActionsEnabled", True)),
        "threshold": raw.get("Threshold"),
        "comparison": raw.get("ComparisonOperator"),
        "period": raw.get("Period"),
        "composite": False,
    }


def normalize_composite(raw: dict[str, Any]) -> dict[str, Any]:
    """Flatten one describe_alarms CompositeAlarms entry."""
    rule = raw.get("AlarmRule", "") or ""
    return {
        "name": raw.get("AlarmName", ""),
        "arn": raw.get("AlarmArn", ""),
        "rule": rule,
        "children": sorted({ref.strip().split(":")[-1] for ref in _ALARM_REF.findall(rule)}),
        "state": raw.get("StateValue", "INSUFFICIENT_DATA"),
        "state_updated": raw.get("StateUpdatedTimestamp"),
        "actions": list(raw.get("AlarmActions") or []),
        "actions_enabled": bool(raw.get("ActionsEnabled", True)),
        "composite": True,
    }


def alarm_is_actionable(alarm: dict[str, Any]) -> bool:
    """True when breaching this alarm would actually tell somebody."""
    return bool(alarm.get("actions")) and bool(alarm.get("actions_enabled", True))


class AlarmIndex:
    """Alarms indexed once, queried by every rule.

    Two indexes, because there are two questions. Coverage asks "is there an
    alarm on this namespace/metric whose dimensions cover this resource", and
    orphan detection asks "does this alarm's dimension value exist at all".
    """

    def __init__(self, metric_alarms: Iterable[dict[str, Any]], composites: Iterable[dict[str, Any]]) -> None:
        self.alarms: list[dict[str, Any]] = [normalize_alarm(a) for a in metric_alarms]
        self.composites: list[dict[str, Any]] = [normalize_composite(a) for a in composites]

        self._by_metric: dict[tuple[str | None, str | None], list[dict[str, Any]]] = {}
        self._by_namespace: dict[str | None, list[dict[str, Any]]] = {}
        for alarm in self.alarms:
            self._by_metric.setdefault((alarm["namespace"], alarm["metric_name"]), []).append(alarm)
            self._by_namespace.setdefault(alarm["namespace"], []).append(alarm)

        # A metric alarm with no actions is still real coverage if a composite
        # alarm that does have actions references it. This is the common pattern
        # for teams that page on an OR of a dozen child alarms.
        covered_by_composite = set()
        for composite in self.composites:
            if not alarm_is_actionable(composite):
                continue
            covered_by_composite.update(composite["children"])
        for alarm in self.alarms:
            alarm["composite_parent"] = alarm["name"] in covered_by_composite
            alarm["actionable"] = alarm_is_actionable(alarm) or alarm["composite_parent"]

    def __len__(self) -> int:
        return len(self.alarms) + len(self.composites)

    def for_resource(
        self, namespace: str, metric_name: str, dimensions: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Alarms on this metric whose dimension map contains the resource's dimensions.

        Containment, not equality: an alarm on a target group legitimately carries
        both TargetGroup and LoadBalancer dimensions, and it still covers the
        target group. Equality would report that as missing coverage.
        """
        candidates = self._by_metric.get((namespace, metric_name), [])
        matched = []
        for alarm in candidates:
            alarm_dims = alarm["dimensions"]
            if all(alarm_dims.get(name) == value for name, value in dimensions.items()):
                matched.append(alarm)
        return matched

    def any_for_resource(self, namespace: str, dimensions: dict[str, str]) -> list[dict[str, Any]]:
        """Every alarm in the namespace pointing at this resource, whatever the metric."""
        matched = []
        for alarm in self._by_namespace.get(namespace, []):
            alarm_dims = alarm["dimensions"]
            if all(alarm_dims.get(name) == value for name, value in dimensions.items()):
                matched.append(alarm)
        return matched
