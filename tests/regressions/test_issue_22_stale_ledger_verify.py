"""Issue 22: a long-lived ledger verified stale records against the on-disk head: false tamper alarm."""

from __future__ import annotations

from sentinel.sandbox.ledger import AuditLedger


def test_verify_sees_records_appended_by_another_writer(tmp_path):
    path = tmp_path / "a.jsonl"
    api = AuditLedger(path)
    api.append("E", {"n": 1})
    AuditLedger(path).append("E", {"n": 2})  # e.g. the CLI, same SENTINEL_HOME
    assert api.verify_integrity() == (True, None)
    assert len(api.get_recent(10)) == 2


def test_partial_trailing_line_is_not_consumed(tmp_path):
    path = tmp_path / "a.jsonl"
    AuditLedger(path).append("E", {"n": 1})
    reader = AuditLedger(path)
    with open(path, "a") as f:
        f.write('{"record_id": "half-written')  # a concurrent append in progress
    reader.get_recent(10)  # must not raise or skip past the partial line
    assert len(reader.records) == 1
