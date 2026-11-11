"""Command line entry point. Exit 0 clean, 1 findings at --fail-on, 2 bad input."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__
from .engine import evaluate
from .model import InputError, at_least
from .report import render
from .rules import SERVICES, load_rules, parse_services

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-cloudwatch-alarm-coverage",
        description=(
            "Report the AWS resources nobody would hear fail: resources with no CloudWatch "
            "alarm on the metric that matters, and alarms that only look like coverage."
        ),
    )
    parser.add_argument("--region", help="AWS region to audit (default: the session region)")
    parser.add_argument("--profile", help="AWS profile to use")
    parser.add_argument(
        "--services",
        help=f"comma-separated subset to inventory (default: all of {','.join(SERVICES)})",
    )
    parser.add_argument("--rules", help="YAML file overriding the metric expectations")
    parser.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text", help="output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=("warn", "critical", "none"),
        default="critical",
        help="lowest severity that exits 1 (default: critical)",
    )
    parser.add_argument(
        "--lookback-days",
        type=int,
        default=14,
        help="how long an INSUFFICIENT_DATA alarm must be stale before the age is reported",
    )
    parser.add_argument("--show-ok", action="store_true", help="also list resources with no findings")
    parser.add_argument("--from-json", metavar="FILE", help="replay a saved payload, making no AWS calls")
    parser.add_argument("--dump-json", metavar="FILE", help="write the collected payload for later replay")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def load_payload(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise InputError(f"cannot read payload {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"payload {path} is not valid JSON: {exc}") from exc


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        services = parse_services(args.services)
        table = load_rules(args.rules)

        if args.from_json:
            payload = load_payload(args.from_json)
            if args.services:
                selected: list[str] | None = services
            else:
                selected = None
        else:
            from .collect import collect

            payload = collect(args.region or "", services, profile=args.profile)
            selected = services

        if args.dump_json:
            try:
                with open(args.dump_json, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, default=str)
            except OSError as exc:
                raise InputError(f"cannot write {args.dump_json}: {exc}") from exc

        report = evaluate(payload, table=table, services=selected, lookback_days=args.lookback_days)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(render(report, args.format, show_ok=args.show_ok))

    for error in payload.get("errors") or []:
        print(
            f"warning: {error.get('service')} could not be inventoried: {error.get('error')}",
            file=sys.stderr,
        )

    if args.fail_on != "none" and at_least(report["severity"], args.fail_on):
        return EXIT_FINDINGS
    return EXIT_OK


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
