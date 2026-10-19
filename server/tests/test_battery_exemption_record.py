"""The battery exemption verification must stay recorded where people look.

Refs issue 114: the exemption is an enrolment precondition for a `wake`
directive, and whether a Device Owner can grant it was derived once on a real
handset. The one API that does grant it, `setApplicationExemptions`, is exactly
what the next reader finds and tries, so the record has to name it and say why
it does not apply to muster.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONSTRAINTS = ROOT / "docs/android-constraints.md"
POLICY = ROOT / "agent/android/app/src/main/java/app/muster/agent/AppConfigPolicy.kt"


def _section(text: str) -> str:
    start = text.index("**Battery optimization exemption for a wake target")
    return text[start:start + 3000]


def test_constraints_doc_names_the_role_gated_api():
    section = _section(CONSTRAINTS.read_text())
    assert "setApplicationExemptions" in section
    assert "DEVICE_POLICY_MANAGEMENT" in section
    assert "MANAGE_DEVICE_POLICY_APP_EXEMPTIONS" in section


def test_constraints_doc_records_the_operator_step():
    section = _section(CONSTRAINTS.read_text())
    assert "dumpsys deviceidle whitelist +<package>" in section
    assert "persists across reboot" in section


def test_policy_comment_does_not_claim_the_manager_has_no_such_method():
    text = POLICY.read_text()
    assert 'contains nothing matching "exempt"' not in text
    assert "setApplicationExemptions" in text
