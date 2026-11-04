"""README.md follows the public README standard (#200).

The standard is templates/public-repo/README-STANDARD.md in the shared
infra-public repo. This pins the parts of its reviewer checklist a machine can
check: the opening, the seven required sections in order, one Mermaid diagram
(and no box-drawing art) under How it works, ASCII-only text, one live status
link in this repo, a Contributing section that points to AGENTS.md, and the
facts the README carried before it was rewritten, so a later edit cannot
quietly drop one.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

README = Path(__file__).resolve().parents[2] / "README.md"

REQUIRED = [
    "What it does",
    "Quick start",
    "How it works",
    "Run and test locally",
    "Configuration",
    "Status",
    "Contributing",
]

KEPT_FACTS = [
    "To muster is to assemble a company and take the roll.",
    "**vouches**",
    "Lapse and revoke are different acts",
    "provisioning QR",
    "CONTEXT.md",
    "ARCHITECTURE.md",
    "DECISIONS.md",
    "https://github.com/quadseven/zippie",
    "docs/android-constraints.md",
    "Android Management API",
    "six-tap QR flow provisioned a Pixel on 2026-08-19",
    "server/muster/enroll.py",
    "server/muster/kith.py",
    "server/muster/administrator.py",
    "server/muster/console.py",
    "docs/administrator-sign-in.md",
    "cd server && uv run --group dev --python 3.12 python -m pytest -q",
]


def _text() -> str:
    return README.read_text(encoding="utf-8")


def _sections(text: str) -> dict[str, str]:
    """Each `## ` heading mapped to its body, ignoring fenced code."""
    out: dict[str, str] = {}
    current = None
    fenced = False
    for line in text.splitlines():
        if line.startswith(("```", "~~~")):
            fenced = not fenced
        if not fenced and line.startswith("## "):
            current = line[3:].strip()
            out[current] = ""
            continue
        if current is not None:
            out[current] += line + "\n"
    return out


def test_opening_is_the_name_then_one_line():
    lines = _text().splitlines()
    assert lines[0] == "# muster"
    body = [ln for ln in lines[1:] if ln.strip()]
    assert not body[0].startswith(("#", "!", "[!")), "a one-line description follows"


def test_required_sections_in_order():
    headings = list(_sections(_text()))
    missing = [h for h in REQUIRED if h not in headings]
    assert missing == [], f"missing sections: {missing}"
    order = [headings.index(h) for h in REQUIRED]
    assert order == sorted(order), f"sections out of order: {headings}"


def test_how_it_works_has_one_mermaid_diagram():
    assert _sections(_text()).get("How it works", "").count("```mermaid") == 1


def test_ascii_only_and_no_box_art():
    text = _text()
    bad = sorted({c for c in text if ord(c) > 127})
    assert bad == [], f"non-ASCII characters: {bad!r}"
    assert re.search("[─-╿]", text) is None


def test_status_links_one_issue_in_this_repo():
    links = re.findall(
        r"https://github\.com/quadseven/muster/issues/\d+",
        _sections(_text()).get("Status", ""),
    )
    assert len(links) == 1, links


def test_contributing_says_pull_request_and_points_to_agents_md():
    body = _sections(_text()).get("Contributing", "")
    assert "pull request" in body
    assert "AGENTS.md" in body


@pytest.mark.parametrize("fact", KEPT_FACTS)
def test_kept_fact(fact):
    # Compare with line wrapping folded away, so rewrapping is not a loss.
    assert fact in " ".join(_text().split()), f"README dropped: {fact}"
