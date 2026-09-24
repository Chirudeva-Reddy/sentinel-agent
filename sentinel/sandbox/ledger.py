"""Cryptographically chained tamper-evident audit ledger for AI Agent actions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.types import AuditRecord

GENESIS_HASH = "0" * 64


class AuditLedger:
    """Tamper-evident audit log where each entry cryptographically commits to the entire history."""

    def __init__(self, log_path: Path | None = None):
        self.log_path = log_path or Path("audit.jsonl")
        self.records: list[AuditRecord] = []
        self._load_records()

    def _load_records(self) -> None:
        if not self.log_path.exists():
            return
        self.records.clear()
        with open(self.log_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                self.records.append(AuditRecord(**data))

    @property
    def latest_hash(self) -> str:
        if not self.records:
            return GENESIS_HASH
        return self.records[-1].current_hash

    @staticmethod
    def compute_hash(prev_hash: str, timestamp: str, event_type: str, payload: dict[str, Any]) -> str:
        serialized_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        raw = f"{prev_hash}|{timestamp}|{event_type}|{serialized_payload}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditRecord:
        """Appends a new event and cryptographically chains it to previous state."""
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self.latest_hash
        current_hash = self.compute_hash(prev_hash, timestamp, event_type, payload)

        record = AuditRecord(
            timestamp=timestamp,
            previous_hash=prev_hash,
            current_hash=current_hash,
            event_type=event_type,
            payload=payload,
        )

        self.records.append(record)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")

        return record

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Verifies that all entries in the ledger form an unbroken, untampered cryptographic chain."""
        expected_prev = GENESIS_HASH
        for idx, rec in enumerate(self.records):
            if rec.previous_hash != expected_prev:
                return (
                    False,
                    f"Integrity broken at index {idx}: expected prev_hash {expected_prev}, found {rec.previous_hash}",
                )

            recomputed = self.compute_hash(rec.previous_hash, rec.timestamp, rec.event_type, rec.payload)
            if recomputed != rec.current_hash:
                return (
                    False,
                    f"Integrity broken at index {idx}: payload tampered (expected {recomputed}, recorded {rec.current_hash})",
                )

            expected_prev = rec.current_hash

        return True, None

    def get_recent(self, limit: int = 50) -> list[AuditRecord]:
        return self.records[-limit:]
