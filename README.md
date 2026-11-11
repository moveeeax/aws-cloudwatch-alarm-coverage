# aws-cloudwatch-alarm-coverage

[![ci](https://github.com/moveeeax/aws-cloudwatch-alarm-coverage/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-cloudwatch-alarm-coverage/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Find the AWS resources nobody would hear fail, and the alarms that only look like coverage.

CloudWatch alarm coverage is not a property you can read anywhere. The alarms live in
`describe_alarms`, the resources live in a dozen other APIs, and the only thing joining them is a
dimension value buried inside each alarm definition. So "which RDS instance has no free-storage
alarm" has no console answer — you read 300 alarms and 40 instances and do the join by hand.

Worse, an alarm existing proves nothing. An alarm with an empty `AlarmActions` fires into the void.
An alarm stuck in `INSUFFICIENT_DATA` has been lying since the day it was created. An alarm on a
deleted resource's dimension reports `OK` forever. This tool does the join and applies both sets of
rules.

## What it checks

**Coverage** — a declarative table of the metrics that must be alarmed per resource type:

| Resource type | Required | Recommended |
| --- | --- | --- |
| `rds_instance` | `CPUUtilization`, `FreeStorageSpace` | `DatabaseConnections` |
| `rds_cluster` | `CPUUtilization` | `DatabaseConnections` |
| `load_balancer` | `HTTPCode_ELB_5XX_Count` | `TargetResponseTime` |
| `target_group` | `UnHealthyHostCount`, `TargetResponseTime` | — |
| `sqs_queue` | `ApproximateAgeOfOldestMessage` | `ApproximateNumberOfMessagesVisible` |
| `lambda_function` | `Errors`, `Throttles` | `Duration` |
| `ecs_service` | `CPUUtilization`, `MemoryUtilization` | — |
| `dynamodb_table` | `ThrottledRequests` | `SystemErrors` |
| `ec2_instance` | `StatusCheckFailed` | `CPUUtilization` |

A missing required metric is `critical`, a missing recommended one is `warn`, and a resource with no
alarm at all on any metric is `critical` regardless of the table. Override any of it with
`--rules` (see [`examples/rules.yaml`](examples/rules.yaml)).

**Alarm quality** — because the alarm existing is not the same as the alarm working:

- `AlarmActions` empty, or `ActionsEnabled: false` → `critical`. The alarm is decorative, and it
  does not count as coverage either.
- `INSUFFICIENT_DATA` → `warn`, with the age when it has been stuck longer than `--lookback-days`.
- A dimension value matching no inventoried resource → `warn`, orphaned.
- Threshold `0` on a count metric with any operator other than `GreaterThanThreshold` → `warn`,
  because it is trivially true or trivially false.

## Install

```console
pip install git+https://github.com/moveeeax/aws-cloudwatch-alarm-coverage
```

Needs read-only access: `cloudwatch:DescribeAlarms` plus the `Describe*`/`List*` call for each
service you inventory.

## Usage

```console
$ aws-cloudwatch-alarm-coverage --from-json tests/fixtures/account.json
CloudWatch alarm coverage — eu-central-1
8 resources, 10 metric alarms + 1 composite, 14 findings

Resources
  [CRIT] Lambda function invoice-worker  (FunctionName=invoice-worker)
         warn: no alarm on recommended metric Duration
           fix: alarm on AWS/Lambda Duration with dimension FunctionName=invoice-worker
         critical: Errors is only covered by alarms that notify nobody: invoice-worker-errors
           fix: add an SNS action to invoice-worker-errors, or reference it from a composite alarm that has one
  [CRIT] RDS instance prod-db  (DBInstanceIdentifier=prod-db)
         warn: no alarm on recommended metric DatabaseConnections
           fix: alarm on AWS/RDS DatabaseConnections with dimension DBInstanceIdentifier=prod-db
         critical: no alarm on required metric FreeStorageSpace
           fix: alarm on AWS/RDS FreeStorageSpace with dimension DBInstanceIdentifier=prod-db
  [CRIT] RDS instance reporting-db  (DBInstanceIdentifier=reporting-db)
         critical: no CloudWatch alarm references this RDS instance on any metric
           fix: alarm on AWS/RDS CPUUtilization, FreeStorageSpace with dimension DBInstanceIdentifier=reporting-db

Alarms
  [CRIT] invoice-worker-errors  (OK)
         critical: AlarmActions is empty, so breaching this alarm notifies nobody
           fix: attach an SNS topic (or any action) to the alarm, or delete it
  [WARN] legacy-db-cpu  (OK)
         warn: dimension DBInstanceIdentifier=legacy-db matches no live resource
           fix: delete the alarm; the resource it watched is gone and it will report OK forever

Result: critical (4 critical resources, 3 warn, 5 alarms with problems)
```

(trimmed — the full fixture run also reports the SQS queue, the DynamoDB table, the EC2 instance,
the stale `INSUFFICIENT_DATA` alarm and a placeholder threshold)

Real runs and the other formats:

```console
aws-cloudwatch-alarm-coverage --region eu-central-1
aws-cloudwatch-alarm-coverage --services rds,lambda --fail-on critical
aws-cloudwatch-alarm-coverage --format json | jq '.resources[] | select(.severity=="critical")'
aws-cloudwatch-alarm-coverage --region eu-central-1 --dump-json prod.json
aws-cloudwatch-alarm-coverage --from-json prod.json --format markdown
```

| Flag | What it does |
| --- | --- |
| `--region`, `--profile` | which account and region to inventory |
| `--services` | narrow the inventory: `rds,elbv2,sqs,lambda,ecs,dynamodb,ec2` |
| `--rules FILE` | YAML override of the metric table (`required`, `recommended`, `off`) |
| `--format` | `text` (default), `json`, `markdown` |
| `--fail-on` | `critical` (default), `warn`, `none` |
| `--show-ok` | also list resources that are fully covered |
| `--dump-json FILE` | save the collected payload |
| `--from-json FILE` | replay a saved payload, making zero AWS calls |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` bad input (unreadable payload,
broken rules file, unknown service) — never a traceback.

## In CI

```yaml
- name: CloudWatch alarm coverage
  run: |
    aws-cloudwatch-alarm-coverage --region eu-central-1 --fail-on critical \
      --format markdown >> "$GITHUB_STEP_SUMMARY"
```

## How the join works

Dimensions are matched by **containment, not equality**. An alarm on a target group legitimately
carries both `TargetGroup` and `LoadBalancer` dimensions, so requiring an exact dimension match
would report that target group as uncovered. A resource is covered when some alarm's dimension map
contains all of the resource's dimensions.

A metric alarm with no actions still counts as coverage when a **composite alarm that does have
actions** references it — that is the normal shape for teams who page on an `OR` of a dozen child
alarms, and flagging those children would be the tool's loudest false positive.

Collectors return plain dicts and the rule engine consumes them, so every rule is tested against
JSON fixtures under `tests/fixtures/` with no AWS credentials and no `moto`.

## Development

```console
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest ruff
ruff check . && pytest -q
```

## License

MIT
