"""Agent credential persistence at /data/agent.json.

Single source of identity once the agent is registered. Read on startup;
absent file means first-run (do registration). Written atomically with
mode 0600 because agent_secret is a long-lived credential equivalent to
the agent's identity — leaking it would let anyone impersonate the agent
to the dashboard.

Atomic-write contract: never observable in a half-written state. Even on
crash mid-write, the previous file (or no file) remains intact, so the
next startup will either pick up the old credentials or re-register —
never load a corrupted file silently.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


class CredentialsCorruptError(Exception):
    """Raised when /data/agent.json exists but cannot be parsed.

    The operator must investigate before the agent re-registers — a fresh
    registration would create a new identity and orphan the dashboard's
    record of this agent (the old `agent_id` would still exist, with no
    one ever heartbeating against it again)."""


def save_credentials(
    path: str | Path,
    agent_id: str,
    agent_secret: str,
    dashboard_url: str,
    registered_at: str,
) -> None:
    """Atomically persist agent credentials.

    Strategy: write to a sibling `<path>.tmp` first, fsync it, then
    `os.replace()` it into place. POSIX `rename()` within a single
    filesystem is atomic — readers see either the previous file or the
    new one, never a half-written hybrid. File mode is set to 0600 both
    at create-time and after rename (in case umask masked the create
    mode bits).

    Creates parent directories if missing so callers don't need to set
    up `/data` themselves.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "agent_id": agent_id,
        "agent_secret": agent_secret,
        "dashboard_url": dashboard_url,
        "registered_at": registered_at,
    }

    tmp = path.parent / (path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Clean up partial tmp on failure so it doesn't linger. The
        # rename hasn't happened, so the original (if any) is intact.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise

    os.replace(tmp, path)
    # Belt-and-braces: ensure mode is exactly 0600 even if umask masked
    # the create-time bits.
    os.chmod(path, 0o600)


def load_credentials(path: str | Path) -> Optional[dict]:
    """Return the parsed credentials dict if the file exists, else None.

    None means "first run, do registration". A corrupted file (invalid
    JSON, or root that isn't an object) raises CredentialsCorruptError —
    do NOT silently return None and re-register, which would create a new
    identity and abandon the existing dashboard record.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        with open(p, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise CredentialsCorruptError(
            f"credentials file at {p} is not valid JSON: {e}"
        ) from e
    except OSError as e:
        raise CredentialsCorruptError(
            f"could not read credentials file at {p}: {e}"
        ) from e
    if not isinstance(data, dict):
        raise CredentialsCorruptError(
            f"credentials file at {p} root is {type(data).__name__}, expected object"
        )
    return data
