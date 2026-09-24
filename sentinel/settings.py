"""Runtime locations. All mutable state lives under SENTINEL_HOME (default ~/.sentinel), never the CWD."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def sentinel_home() -> Path:
    home = Path(os.environ.get("SENTINEL_HOME", Path.home() / ".sentinel")).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    return home


def secret_key(name: str) -> bytes:
    """HMAC key `name`: $SENTINEL_<NAME>_KEY if set, else a random key persisted (0600) under SENTINEL_HOME.

    ponytail: the file fallback keeps local use zero-config; in production inject the env var from a
    secret store so processes that write logs/approvals can't read the key.
    """
    env = os.environ.get(f"SENTINEL_{name.upper()}_KEY")
    if env:
        return env.encode()
    path = sentinel_home() / f"{name}.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_bytes()
    key = secrets.token_hex(32).encode()
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key
