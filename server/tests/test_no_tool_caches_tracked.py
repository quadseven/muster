"""No local tool cache may be tracked in this repository.

WHY THIS EXISTS. `.wrangler/cache/pages.json` was committed once. It is the
Cloudflare Pages CLI's local cache, not source, and it held a hosting account
identifier, in a public repo. `.gitignore` now names `.wrangler/`, but an
ignore line only stops `git add .`; `git add -f` or a rename still lands the
file. This test reads what git actually tracks, so the path coming back is a
red `server tests` job rather than a later scrub.

The check is a prefix list, so the next tool cache that leaks is one line here.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

# Directories that only ever hold a local tool's cache or state.
CACHE_PREFIXES = (".wrangler/",)


def _tracked_files() -> list[str]:
    root = Path(__file__).resolve().parents[2]
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode()
    return [rel for rel in out.split("\0") if rel]


def test_the_scan_sees_tracked_files() -> None:
    """Guards the guard: an empty listing would make the real check pass."""
    assert "server/pyproject.toml" in _tracked_files()


def test_no_tool_cache_is_tracked() -> None:
    offenders = [
        rel for rel in _tracked_files() if rel.startswith(CACHE_PREFIXES)
    ]
    assert not offenders, (
        f"local tool cache tracked by git: {offenders}; "
        "run `git rm --cached` on it and keep its directory in .gitignore"
    )
