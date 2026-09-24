"""CLI smoke tests via Typer's runner."""

from __future__ import annotations

from typer.testing import CliRunner

from sentinel.cli import app
from sentinel.sandbox.ledger import AuditLedger

runner = CliRunner()


def test_inspect_renders_decision():
    res = runner.invoke(app, ["inspect", "--tool", "calculator", "--args", '{"expression": "1+1"}'])
    assert res.exit_code == 0
    assert "ALLOW" in res.output


def test_test_attack_runs_known_scenario_and_rejects_unknown():
    assert runner.invoke(app, ["test-attack", "--type", "shell_catastrophic"]).exit_code == 0
    assert runner.invoke(app, ["test-attack", "--type", "nope"]).exit_code == 1


def test_verify_ledger_detects_tamper(tmp_path):
    path = tmp_path / "a.jsonl"
    AuditLedger(path).append("E", {"n": 1})
    assert runner.invoke(app, ["verify-ledger", "--path", str(path)]).exit_code == 0
    path.write_text(path.read_text().replace('"n":1', '"n":2'))
    assert runner.invoke(app, ["verify-ledger", "--path", str(path)]).exit_code == 1


def test_benchmark_command():
    res = runner.invoke(app, ["benchmark", "-n", "5"])
    assert res.exit_code == 0 and "p95" in res.output
