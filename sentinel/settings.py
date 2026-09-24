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
    if not path.exists():
        # Write the whole key to a private temp file, then link it into place: link() is atomic and never
        # overwrites, so a concurrent first run either wins or reads the winner's complete key.
        tmp = path.with_name(f".{name}.key.{os.getpid()}.{secrets.token_hex(4)}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_hex(32).encode())
        try:
            if hasattr(os, "link"):
                try:
                    os.link(tmp, path)
                except FileExistsError:
                    pass
                except (AttributeError, OSError, NotImplementedError):
                    if not path.exists():
                        os.replace(tmp, path)
            else:
                if not path.exists():
                    os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
    key = path.read_bytes()
    if len(key) < 32:
        raise RuntimeError(f"{path} is empty or truncated; delete it (or set SENTINEL_{name.upper()}_KEY) and retry")
    return key
