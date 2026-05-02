from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def load_env(path: Path | None = None, *, override: bool = False) -> None:
    """Load simple KEY=VALUE lines from .env without adding a runtime dependency."""
    global _LOADED
    if _LOADED and not override:
        return
    env_path = path or Path.cwd() / ".env"
    if not env_path.exists():
        _LOADED = True
        return
    for raw in env_path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if override or key not in os.environ:
            os.environ[key] = value
    _LOADED = True
