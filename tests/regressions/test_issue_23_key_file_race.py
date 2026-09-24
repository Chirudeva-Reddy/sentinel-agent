"""Issue 23: a process could read the key file between creation and write and sign with an empty key."""

from __future__ import annotations

import multiprocessing as mp

import pytest

from sentinel.settings import secret_key, sentinel_home


def _read(q):
    q.put(secret_key("race"))


def test_concurrent_first_use_yields_one_nonempty_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    procs = [ctx.Process(target=_read, args=(q,)) for _ in range(8)]
    for p in procs:
        p.start()
    keys = {q.get(timeout=30) for _ in procs}
    for p in procs:
        p.join()
    assert len(keys) == 1 and len(keys.pop()) >= 32


def test_empty_key_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    (sentinel_home() / "broken.key").write_bytes(b"")
    with pytest.raises(RuntimeError, match="broken.key"):
        secret_key("broken")
