"""boto3 collectors. Each one returns plain dicts so the rules stay testable."""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable

from .rules import RESOURCE_TYPES


def _lb_dimension(arn: str) -> str | None:
    """arn:...:loadbalancer/app/name/id -> app/name/id, the value CloudWatch uses."""
    marker = ":loadbalancer/"
    if marker in arn:
        return arn.split(marker, 1)[1]
    return None


def _tg_dimension(arn: str) -> str | None:
    """arn:...:targetgroup/name/id -> targetgroup/name/id."""
    if ":targetgroup/" in arn:
        return "targetgroup/" + arn.split(":targetgroup/", 1)[1]
    return None


def _resource(rtype: str, identifier: str, dimensions: dict[str, str], **extra: Any) -> dict[str, Any]:
    assert rtype in RESOURCE_TYPES
    row: dict[str, Any] = {"type": rtype, "id": identifier, "dimensions": dimensions}
    if extra:
        row["extra"] = extra
    return row


def collect_alarms(session: Any, region: str) -> dict[str, list[dict[str, Any]]]:
    client = session.client("cloudwatch", region_name=region)
    metric_alarms: list[dict[str, Any]] = []
    composites: list[dict[str, Any]] = []
    paginator = client.get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmTypes=["CompositeAlarm", "MetricAlarm"]):
        metric_alarms.extend(page.get("MetricAlarms") or [])
        composites.extend(page.get("CompositeAlarms") or [])
    return {"alarms": metric_alarms, "composite_alarms": composites}


def collect_rds(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("rds", region_name=region)
    out: list[dict[str, Any]] = []
    for page in client.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances") or []:
            ident = db.get("DBInstanceIdentifier")
            if not ident:
                continue
            out.append(
                _resource(
                    "rds_instance",
                    ident,
                    {"DBInstanceIdentifier": ident},
                    engine=db.get("Engine"),
                    instance_class=db.get("DBInstanceClass"),
                    multi_az=db.get("MultiAZ"),
                )
            )
    for page in client.get_paginator("describe_db_clusters").paginate():
        for cluster in page.get("DBClusters") or []:
            ident = cluster.get("DBClusterIdentifier")
            if not ident:
                continue
            out.append(
                _resource("rds_cluster", ident, {"DBClusterIdentifier": ident}, engine=cluster.get("Engine"))
            )
    return out


def collect_elbv2(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("elbv2", region_name=region)
    out: list[dict[str, Any]] = []
    for page in client.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancers") or []:
            dimension = _lb_dimension(lb.get("LoadBalancerArn", ""))
            if not dimension:
                continue
            out.append(
                _resource(
                    "load_balancer",
                    lb.get("LoadBalancerName") or dimension,
                    {"LoadBalancer": dimension},
                    scheme=lb.get("Scheme"),
                    lb_type=lb.get("Type"),
                )
            )
    for page in client.get_paginator("describe_target_groups").paginate():
        for tg in page.get("TargetGroups") or []:
            dimension = _tg_dimension(tg.get("TargetGroupArn", ""))
            if not dimension:
                continue
            out.append(
                _resource(
                    "target_group",
                    tg.get("TargetGroupName") or dimension,
                    {"TargetGroup": dimension},
                    protocol=tg.get("Protocol"),
                    target_type=tg.get("TargetType"),
                )
            )
    return out


def collect_sqs(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("sqs", region_name=region)
    out: list[dict[str, Any]] = []
    for page in client.get_paginator("list_queues").paginate():
        for url in page.get("QueueUrls") or []:
            name = url.rsplit("/", 1)[-1]
            out.append(_resource("sqs_queue", name, {"QueueName": name}, url=url))
    return out


def collect_lambda(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("lambda", region_name=region)
    out: list[dict[str, Any]] = []
    for page in client.get_paginator("list_functions").paginate():
        for fn in page.get("Functions") or []:
            name = fn.get("FunctionName")
            if not name:
                continue
            out.append(
                _resource("lambda_function", name, {"FunctionName": name}, runtime=fn.get("Runtime"))
            )
    return out


def collect_ecs(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("ecs", region_name=region)
    out: list[dict[str, Any]] = []
    for cluster_page in client.get_paginator("list_clusters").paginate():
        for cluster_arn in cluster_page.get("clusterArns") or []:
            cluster_name = cluster_arn.rsplit("/", 1)[-1]
            for svc_page in client.get_paginator("list_services").paginate(cluster=cluster_arn):
                for service_arn in svc_page.get("serviceArns") or []:
                    service_name = service_arn.rsplit("/", 1)[-1]
                    out.append(
                        _resource(
                            "ecs_service",
                            f"{cluster_name}/{service_name}",
                            {"ClusterName": cluster_name, "ServiceName": service_name},
                        )
                    )
    return out


def collect_dynamodb(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("dynamodb", region_name=region)
    out: list[dict[str, Any]] = []
    for page in client.get_paginator("list_tables").paginate():
        for name in page.get("TableNames") or []:
            out.append(_resource("dynamodb_table", name, {"TableName": name}))
    return out


def collect_ec2(session: Any, region: str) -> list[dict[str, Any]]:
    client = session.client("ec2", region_name=region)
    out: list[dict[str, Any]] = []
    pages = client.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    )
    for page in pages:
        for reservation in page.get("Reservations") or []:
            for instance in reservation.get("Instances") or []:
                ident = instance.get("InstanceId")
                if not ident:
                    continue
                out.append(
                    _resource(
                        "ec2_instance",
                        ident,
                        {"InstanceId": ident},
                        instance_type=instance.get("InstanceType"),
                        state=(instance.get("State") or {}).get("Name"),
                    )
                )
    return out


COLLECTORS: dict[str, Callable[[Any, str], list[dict[str, Any]]]] = {
    "rds": collect_rds,
    "elbv2": collect_elbv2,
    "sqs": collect_sqs,
    "lambda": collect_lambda,
    "ecs": collect_ecs,
    "dynamodb": collect_dynamodb,
    "ec2": collect_ec2,
}


def collect(region: str, services: list[str], profile: str | None = None) -> dict[str, Any]:
    """Build the payload the rule engine consumes. The only place that calls AWS."""
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    region = region or session.region_name
    if not region:
        from .model import InputError

        raise InputError("no region: pass --region or set AWS_REGION")

    payload: dict[str, Any] = {
        "region": region,
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "services": sorted(services),
        "resources": [],
        "errors": [],
    }
    payload.update(collect_alarms(session, region))

    for service in sorted(services):
        collector = COLLECTORS[service]
        try:
            payload["resources"].extend(collector(session, region))
        except Exception as exc:  # a denied service should not kill the whole audit
            payload["errors"].append({"service": service, "error": str(exc)})
    return payload
