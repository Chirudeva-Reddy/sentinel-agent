"""Unit tests for AuditLedger cryptographic hash-chaining."""

from __future__ import annotations

import json

from sentinel.sandbox.ledger import GENESIS_HASH, AuditLedger


def test_audit_ledger_chain_and_verify(tmp_path):
    log_path = tmp_path / "audit.jsonl"
    ledger = AuditLedger(log_path)

    # Initial state
    assert ledger.latest_hash == GENESIS_HASH

    # Append 3 events
    rec1 = ledger.append("TOOL_ALLOW", {"tool": "read_file", "path": "a.txt"})
    assert rec1.previous_hash == GENESIS_HASH

    rec2 = ledger.append("TOOL_WARN", {"tool": "cat", "path": ".env"})
    assert rec2.previous_hash == rec1.current_hash

    rec3 = ledger.append("TOOL_BLOCK", {"tool": "rm", "path": "/"})
    assert rec3.previous_hash == rec2.current_hash

    # Verify integrity
    valid, err = ledger.verify_integrity()
    assert valid is True
    assert err is None


def test_audit_ledger_detects_tampering(tmp_path):
    log_path = tmp_path / "tampered_audit.jsonl"
    ledger = AuditLedger(log_path)

    ledger.append("TOOL_ALLOW", {"id": 1})
    ledger.append("TOOL_ALLOW", {"id": 2})

    # Manually tamper with the file content
    with open(log_path) as f:
        lines = f.readlines()

    # Modify payload of second record
    rec2_data = json.loads(lines[1])
    rec2_data["payload"]["id"] = 9999
    lines[1] = json.dumps(rec2_data) + "\n"

    with open(log_path, "w") as f:
        f.writelines(lines)

    # Reload ledger and verify
    tampered_ledger = AuditLedger(log_path)
    valid, err = tampered_ledger.verify_integrity()
    assert valid is False
    assert "payload tampered" in err
