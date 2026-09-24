"""Issue 6: truncation and re-hashed rewrites verified as valid; concurrent writers forked the chain."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp

from hypothesis import given, settings
from hypothesis import strategies as st

from sentinel.sandbox.ledger import AuditLedger


def _ledger(tmp_path, n=5):
    path = tmp_path / "a.jsonl"
    led = AuditLedger(path)
    for i in range(n):
        led.append("E", {"i": i})
    return path


def _lines(path):
    return path.read_text().splitlines()


def test_tail_truncation_detected(tmp_path):
    path = _ledger(tmp_path)
    path.write_text("\n".join(_lines(path)[:-2]) + "\n")
    assert AuditLedger(path).verify_integrity()[0] is False


def test_unkeyed_rehash_rewrite_detected(tmp_path):
    """Attacker edits a record and recomputes plain SHA-256 hashes down the chain."""
    path = _ledger(tmp_path)
    recs = [json.loads(line) for line in _lines(path)]
    recs[1]["payload"]["i"] = 999
    prev = recs[0]["current_hash"]
    for r in recs[1:]:
        r["previous_hash"] = prev
        body = f"{prev}|{r['timestamp']}|{r['event_type']}|{json.dumps(r['payload'], sort_keys=True, separators=(',', ':'))}"
        r["current_hash"] = prev = hashlib.sha256(body.encode()).hexdigest()
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    assert AuditLedger(path).verify_integrity()[0] is False


def test_different_key_fails_verification(tmp_path, monkeypatch):
    path = _ledger(tmp_path)
    monkeypatch.setenv("SENTINEL_LEDGER_KEY", "another-key")
    assert AuditLedger(path).verify_integrity()[0] is False


@settings(max_examples=40, deadline=None)
@given(op=st.sampled_from(["edit", "delete", "swap", "truncate", "byte"]), idx=st.integers(0, 4), pos=st.integers(0))
def test_any_single_tamper_detected(tmp_path_factory, op, idx, pos):
    path = _ledger(tmp_path_factory.mktemp("l"))
    lines = _lines(path)
    if op == "edit":
        r = json.loads(lines[idx])
        r["event_type"] += "X"
        lines[idx] = json.dumps(r)
    elif op == "delete":
        del lines[idx]
    elif op == "swap":
        j = (idx + 1) % len(lines)
        lines[idx], lines[j] = lines[j], lines[idx]
    elif op == "truncate":
        lines = lines[:idx]
    else:
        s = lines[idx]
        p = pos % len(s)
        lines[idx] = s[:p] + ("0" if s[p] != "0" else "1") + s[p + 1 :]
    path.write_text("".join(line + "\n" for line in lines))
    try:
        ok = AuditLedger(path).verify_integrity()[0]
    except Exception:
        ok = False  # unparsable is also "detected"
    assert ok is False


def _writer(path, n):
    led = AuditLedger(path)
    for i in range(n):
        led.append("E", {"i": i})


def test_two_processes_do_not_fork_the_chain(tmp_path):
    path = tmp_path / "shared.jsonl"
    AuditLedger(path)  # create key before forking
    procs = [mp.get_context("spawn").Process(target=_writer, args=(path, 30)) for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    led = AuditLedger(path)
    assert len(led.records) == 60
    assert led.verify_integrity() == (True, None)
