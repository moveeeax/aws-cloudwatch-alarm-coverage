from __future__ import annotations

import json

import pytest

from aws_cloudwatch_alarm_coverage.cli import run


def fixture_path(fixtures_dir):
    return str(fixtures_dir / "account.json")


def test_fail_on_critical_exits_one(fixtures_dir, capsys):
    code = run(["--from-json", fixture_path(fixtures_dir), "--fail-on", "critical"])

    assert code == 1
    assert "reporting-db" in capsys.readouterr().out


def test_fail_on_critical_exits_zero_when_nothing_is_critical(fixtures_dir, tmp_path, capsys):
    with open(fixtures_dir / "account.json", encoding="utf-8") as handle:
        payload = json.load(handle)
    # keep only the queue, whose single problem is a missing recommended metric
    payload["resources"] = [r for r in payload["resources"] if r["id"] == "orders"]
    payload["alarms"] = [a for a in payload["alarms"] if a["AlarmName"] == "orders-age"]
    payload["composite_alarms"] = []
    path = tmp_path / "queue.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert run(["--from-json", str(path), "--fail-on", "critical"]) == 0
    assert run(["--from-json", str(path), "--fail-on", "warn"]) == 1
    assert run(["--from-json", str(path), "--fail-on", "none"]) == 0
    capsys.readouterr()


def test_json_output_is_machine_readable(fixtures_dir, capsys):
    run(["--from-json", fixture_path(fixtures_dir), "--format", "json", "--fail-on", "none"])

    report = json.loads(capsys.readouterr().out)
    critical = [r["id"] for r in report["resources"] if r["severity"] == "critical"]
    assert "reporting-db" in critical
    assert report["summary"]["resources"] == 8


def test_markdown_output_has_tables(fixtures_dir, capsys):
    run(["--from-json", fixture_path(fixtures_dir), "--format", "markdown", "--fail-on", "none"])

    out = capsys.readouterr().out
    assert "## CloudWatch alarm coverage — eu-central-1" in out
    assert "| Severity | Resource | Finding | Fix |" in out
    assert "`legacy-db-cpu`" in out


def test_show_ok_lists_covered_resources(fixtures_dir, capsys):
    run(["--from-json", fixture_path(fixtures_dir), "--show-ok", "--fail-on", "none"])
    with_ok = capsys.readouterr().out

    run(["--from-json", fixture_path(fixtures_dir), "--fail-on", "none"])
    without_ok = capsys.readouterr().out

    assert "web-tg" in with_ok
    assert "web-tg-unhealthy" in with_ok
    assert "target group web-tg" not in without_ok


def test_services_filter_reaches_the_engine(fixtures_dir, capsys):
    run(
        [
            "--from-json",
            fixture_path(fixtures_dir),
            "--services",
            "rds",
            "--format",
            "json",
            "--fail-on",
            "none",
        ]
    )

    report = json.loads(capsys.readouterr().out)
    assert {r["type"] for r in report["resources"]} == {"rds_instance"}


def test_dump_json_round_trips(fixtures_dir, tmp_path, capsys):
    out = tmp_path / "dump.json"
    run(["--from-json", fixture_path(fixtures_dir), "--dump-json", str(out), "--fail-on", "none"])
    capsys.readouterr()

    assert run(["--from-json", str(out), "--fail-on", "none"]) == 0
    assert "eu-central-1" in capsys.readouterr().out


def test_collector_errors_are_surfaced_as_warnings(fixtures_dir, tmp_path, capsys):
    with open(fixtures_dir / "account.json", encoding="utf-8") as handle:
        payload = json.load(handle)
    payload["errors"] = [{"service": "ecs", "error": "AccessDenied"}]
    path = tmp_path / "denied.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    run(["--from-json", str(path), "--fail-on", "none"])

    assert "ecs could not be inventoried: AccessDenied" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv,message",
    [
        (["--from-json", "/nonexistent.json"], "cannot read payload"),
        (["--from-json", "BROKEN"], "not valid JSON"),
        (["--from-json", "FIXTURE", "--services", "eks"], "unknown service"),
        (["--from-json", "FIXTURE", "--rules", "/nonexistent.yaml"], "cannot read rules file"),
    ],
)
def test_bad_input_exits_two_without_a_traceback(fixtures_dir, tmp_path, capsys, argv, message):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    argv = [broken.as_posix() if a == "BROKEN" else a for a in argv]
    argv = [fixture_path(fixtures_dir) if a == "FIXTURE" else a for a in argv]

    assert run(argv) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert message in captured.err


def test_no_aws_call_is_made_when_replaying(fixtures_dir, monkeypatch, capsys):
    def explode(*args, **kwargs):
        raise AssertionError("--from-json must not touch AWS")

    monkeypatch.setattr("aws_cloudwatch_alarm_coverage.collect.collect", explode)
    run(["--from-json", fixture_path(fixtures_dir), "--fail-on", "none"])

    assert "CloudWatch alarm coverage" in capsys.readouterr().out
