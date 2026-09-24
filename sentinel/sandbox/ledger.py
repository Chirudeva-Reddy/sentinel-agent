"""Tamper-evident audit ledger: HMAC-chained, sequenced, head-anchored, file-locked, secrets redacted.

Threat model: detects edits, deletions, reordering, truncation and re-hashed rewrites by anyone who
does not hold the ledger key. ponytail: the key defaults to $SENTINEL_HOME/ledger.key, next to the
log; in production set SENTINEL_LEDGER_KEY from a secret store so log writers can't read it, and ship
head checkpoints off-host if deleting the whole ledger (log + head) must also be detectable.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.core.types import AuditRecord
from sentinel.settings import sentinel_home

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]  # ponytail: no cross-process lock on Windows; use portalocker if needed

GENESIS_HASH = "0" * 64

# --- redaction -----------------------------------------------------------------------------------

_SECRET_KEY = re.compile(
    r"pass(word|wd)?|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie", re.I
)
_SECRET_VALUE = re.compile(
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]*PRIVATE KEY-----"
)


def _fingerprint(value: str) -> str:
    return f"[REDACTED sha256:{hashlib.sha256(value.encode()).hexdigest()[:12]}]"


def redact(obj: Any, key: str = "") -> Any:
    """Replace secret-named fields and secret-shaped substrings with a short hash (still correlatable)."""
    if isinstance(obj, dict):
        return {k: redact(v, str(k)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, key) for v in obj]
    if isinstance(obj, str):
        if _SECRET_KEY.search(key):
            return _fingerprint(obj)
        return _SECRET_VALUE.sub(lambda m: _fingerprint(m.group(0)), obj)
    if _SECRET_KEY.search(key) and obj is not None and not isinstance(obj, bool):
        return _fingerprint(str(obj))
    return obj


# --- key -----------------------------------------------------------------------------------------


def ledger_key() -> bytes:
    env = os.environ.get("SENTINEL_LEDGER_KEY")
    if env:
        return env.encode()
    path = sentinel_home() / "ledger.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes()
    with os.fdopen(fd, "wb") as f:
        key = secrets.token_hex(32).encode()
        f.write(key)
    return key


# --- ledger --------------------------------------------------------------------------------------


class AuditLedger:
    """Append-only JSONL where record n commits (via HMAC) to record n-1 and to its own sequence number."""

    def __init__(self, log_path: Path | None = None):
        self.log_path = Path(log_path) if log_path else sentinel_home() / "audit.jsonl"
        self.head_path = self.log_path.with_name(self.log_path.name + ".head")
        self._key = ledger_key()
        self.records: list[AuditRecord] = []
        self._offset = 0
        self._load_new()

    def _load_new(self) -> None:
        """Read records appended since our last read (possibly by another process)."""
        if not self.log_path.exists():
            return
        with open(self.log_path, "rb") as f:
            f.seek(self._offset)
            for raw in f:
                if raw.strip():
                    self.records.append(AuditRecord(**json.loads(raw)))
            self._offset = f.tell()

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path.with_name(self.log_path.name + ".lock"), "a") as lock:
            if fcntl:
                fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl:
                    fcntl.flock(lock, fcntl.LOCK_UN)

    @property
    def latest_hash(self) -> str:
        return self.records[-1].current_hash if self.records else GENESIS_HASH

    def _mac(self, *parts: object) -> str:
        return hmac.new(self._key, "|".join(map(str, parts)).encode(), hashlib.sha256).hexdigest()

    def compute_hash(self, rec: AuditRecord) -> str:
        """MAC over every field except the MAC itself."""
        body = rec.model_dump(exclude={"current_hash"})
        return self._mac(json.dumps(body, sort_keys=True, separators=(",", ":")))

    def append(self, event_type: str, payload: dict[str, Any]) -> AuditRecord:
        """Redacts secrets, then appends a record chained to the current on-disk head."""
        payload = redact(payload)
        with self._locked():
            self._load_new()
            seq = len(self.records)
            timestamp = datetime.now(timezone.utc).isoformat()
            prev = self.latest_hash
            record = AuditRecord(
                seq=seq,
                timestamp=timestamp,
                previous_hash=prev,
                current_hash="",
                event_type=event_type,
                payload=payload,
            )
            record.current_hash = self.compute_hash(record)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(record.model_dump_json() + "\n")
            tmp = self.head_path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(
                    {"seq": seq, "hash": record.current_hash, "mac": self._mac("head", seq, record.current_hash)}
                )
            )
            tmp.replace(self.head_path)
            self._load_new()
        return record

    def verify_integrity(self) -> tuple[bool, str | None]:
        """Checks the chain, sequence and MACs, then that the last record matches the signed head."""
        expected_prev = GENESIS_HASH
        for idx, rec in enumerate(self.records):
            if rec.seq != idx:
                return False, f"Integrity broken at index {idx}: sequence {rec.seq} out of order"
            if rec.previous_hash != expected_prev:
                return (
                    False,
                    f"Integrity broken at index {idx}: expected prev_hash {expected_prev}, found {rec.previous_hash}",
                )
            recomputed = self.compute_hash(rec)
            if not hmac.compare_digest(recomputed, rec.current_hash):
                return False, f"Integrity broken at index {idx}: payload tampered or wrong ledger key"
            expected_prev = rec.current_hash

        if not self.head_path.exists():
            return (True, None) if not self.records else (False, "Head checkpoint missing")
        try:
            head = json.loads(self.head_path.read_text())
        except ValueError:
            return False, "Head checkpoint unreadable"
        if not hmac.compare_digest(head.get("mac", ""), self._mac("head", head.get("seq"), head.get("hash"))):
            return False, "Head checkpoint signature invalid"
        if head["seq"] != len(self.records) - 1 or head["hash"] != self.latest_hash:
            return (
                False,
                f"Ledger truncated or rolled back: head is seq {head['seq']}, log ends at {len(self.records) - 1}",
            )
        return True, None

    def get_recent(self, limit: int = 50) -> list[AuditRecord]:
        self._load_new()
        return self.records[-limit:]
