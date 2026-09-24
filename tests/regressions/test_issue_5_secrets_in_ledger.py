"""Issue 5: secret values were written verbatim to the audit ledger."""

from __future__ import annotations

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import ToolCallRequest
from sentinel.sandbox.ledger import AuditLedger

SECRETS = {
    "api_key": "not-a-pattern-but-named-secret-123",
    "db_password": "hunter2hunter2",
    "Authorization": "Bearer abcdefabcdef",
    "note": "use sk-live-51HqLyjWDarjtT1zdp7dcXYZ for billing",
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "gh": "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "nested": {"items": [{"client_secret": "zzz-very-secret-zzz"}]},
}
LEAKS = [
    "not-a-pattern-but-named-secret-123",
    "hunter2hunter2",
    "abcdefabcdef",
    "sk-live-51HqLyjWDarjtT1zdp7dcXYZ",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "zzz-very-secret-zzz",
]


def test_no_secret_reaches_ledger_bytes(tmp_path):
    ledger = AuditLedger(tmp_path / "a.jsonl")
    SentinelGateway(ledger=ledger).inspect(ToolCallRequest(tool_name="call_api", arguments=SECRETS))
    raw = (tmp_path / "a.jsonl").read_text()
    for leak in LEAKS:
        assert leak not in raw, leak
    assert "sha256:" in raw
    assert "use " in raw and " for billing" in raw  # surrounding text kept
    assert ledger.verify_integrity()[0]
