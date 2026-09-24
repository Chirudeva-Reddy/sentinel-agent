"""Issue 26: secret_key crashes on Pyodide/WebAssembly when os has no attribute 'link'."""

from __future__ import annotations

import os

from sentinel.settings import secret_key


def test_secret_key_succeeds_without_os_link(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))
    monkeypatch.delattr(os, "link", raising=False)

    key = secret_key("wasm")
    assert isinstance(key, bytes)
    assert len(key) >= 32

    # Second invocation reads existing key
    key2 = secret_key("wasm")
    assert key2 == key


def test_secret_key_succeeds_when_os_link_raises_attribute_error(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path))

    def _broken_link(src, dst):
        raise AttributeError("module 'os' has no attribute 'link'. Did you mean: 'unlink'?")

    monkeypatch.setattr(os, "link", _broken_link, raising=False)

    key = secret_key("wasm_attr")
    assert isinstance(key, bytes)
    assert len(key) >= 32
