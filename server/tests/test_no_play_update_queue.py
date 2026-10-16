"""Nothing in muster reaches for Play's update queue (muster#162).

muster can bring an app up to date only if it OWNS it: an `install-apps` line
names the asset, the digest and the versionCode, and the agent installs it
silently as Device Owner. An app Play installed is outside that. Play keeps its
own queue, and a Device Owner can neither read it nor drive it, so code that
claimed to would report updates that never happen. Drift for such an app shows
as `unmanaged` (muster/drift.py), which is the honest answer.

This pins that by name, so a later edit that pulls in an in-app-updates library
or deep-links into the store has to delete this test and say why.
"""
from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The agent's shipped sources and its dependency list, and the server. Agent
# TESTS are excluded: AppVisibilityPolicyTest names the store's package because
# hiding it is the point of that policy, which is visibility and not updates.
SCANNED = (
    ROOT / "agent/android/app/src/main",
    ROOT / "agent/android/app/build.gradle.kts",
    ROOT / "server/muster",
)

# Each is a way in to Play's update machinery, not merely a mention of Play.
FORBIDDEN = (
    # Play Core / Play In-App Updates, the only API that touches the queue.
    "com.google.android.play",
    "AppUpdateManager",
    # The store's internal package, which is what a queue hack would target.
    "finsky",
    # Deep links that hand an update to the store to perform.
    "market://",
    "play.google.com/store",
)


def _files():
    for target in SCANNED:
        if target.is_file():
            yield target
        else:
            yield from (
                p for p in target.rglob("*")
                if p.is_file() and p.suffix in {".kt", ".kts", ".xml", ".py", ".html"}
            )


def test_the_scanned_paths_exist():
    """A guard over a moved directory scans nothing and passes forever."""
    for target in SCANNED:
        assert target.exists(), target
    assert any(p.suffix == ".kt" for p in _files())


@pytest.mark.parametrize("marker", FORBIDDEN)
def test_nothing_drives_plays_update_queue(marker):
    hits = [
        str(path.relative_to(ROOT))
        for path in _files()
        if marker in path.read_text(encoding="utf-8")
    ]
    assert hits == [], f"{marker!r} found in {hits}"
