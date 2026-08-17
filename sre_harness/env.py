"""Minimal `.env` loading, stdlib only.

The harness declares no runtime dependencies, so this is ~40 lines rather than
a python-dotenv import. It implements the part of the format that matters and
nothing else.

One rule worth stating because it is load-bearing: **the real environment
wins**. A value already present in `os.environ` is never overwritten unless the
caller passes `override=True`. That means `DEEPSEEK_API_KEY=... python -m ...`
and CI secrets behave the way you expect, and a stale key left in a local
`.env` cannot silently shadow the one you just exported.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_NAME = ".env"


def find_dotenv(start: str | os.PathLike[str] | None = None, name: str = DEFAULT_NAME) -> Path | None:
    """Walk up from `start` (default: cwd) looking for a `.env`.

    Walking up means `pytest` from a subdirectory, or `python -m sre_harness.cli`
    from anywhere inside the repo, both find the same file.
    """
    here = Path(start) if start is not None else Path.cwd()
    here = here if here.is_dir() else here.parent
    for directory in [here, *here.parents]:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def parse_dotenv(text: str) -> dict[str, str]:
    """Parse `.env` text into a dict.

    Supports `KEY=value`, `export KEY=value`, `#` comments, blank lines, and
    single/double quoted values. An unquoted value has a trailing ` #comment`
    stripped; a quoted one does not, because `#` is legal inside a real secret.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            # Unquoted: an inline comment must be preceded by whitespace, so a
            # key that legitimately contains '#' survives.
            hash_at = value.find(" #")
            if hash_at != -1:
                value = value[:hash_at].rstrip()
        out[key] = value
    return out


def load_dotenv(
    path: str | os.PathLike[str] | None = None,
    *,
    override: bool = False,
) -> dict[str, str]:
    """Load a `.env` into `os.environ` and return what it applied.

    Missing file is not an error — the environment may already be populated.
    Empty values are skipped so a placeholder `DEEPSEEK_API_KEY=` in the
    template cannot mask a key that is genuinely exported.
    """
    found = Path(path) if path is not None else find_dotenv()
    if found is None or not found.is_file():
        return {}
    applied: dict[str, str] = {}
    for key, value in parse_dotenv(found.read_text(encoding="utf-8")).items():
        if not value:
            continue
        if not override and os.environ.get(key):
            continue
        os.environ[key] = value
        applied[key] = value
    return applied


def redact(secret: str | None, *, keep: int = 4) -> str:
    """Render a key for logs: `sk-…a1b2` or `<unset>`. Never print the raw value."""
    if not secret:
        return "<unset>"
    if len(secret) <= keep:
        return "*" * len(secret)
    prefix = secret[:3] if secret.startswith("sk-") else ""
    return f"{prefix}…{secret[-keep:]}"


__all__ = ["load_dotenv", "find_dotenv", "parse_dotenv", "redact", "DEFAULT_NAME"]
