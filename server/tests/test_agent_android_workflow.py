"""Guard the agent build against publishing a debug-signed APK unattended.

build.server-image.yml bakes the newest SUCCESSFUL run of check.agent-android.yml
on main, whatever event started it, and it also runs whenever that workflow
completes on main. So any trigger that runs on main without the signing secrets
produces a debug-signed APK that the next image publishes in place of the
release agent (muster#123: a weekly schedule did exactly that).

A person who presses workflow_dispatch chooses to; a schedule fires on its own.
This test refuses a `schedule` trigger unless every expression that hands the
build its signing secrets also admits scheduled runs.

Note: PyYAML parses the GitHub Actions `on:` key as boolean True.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github/workflows/check.agent-android.yml"
)

SIGNING_SECRETS = (
    "MUSTER_KEYSTORE_BASE64",
    "MUSTER_KEYSTORE_PASSWORD",
    "MUSTER_KEY_ALIAS",
    "MUSTER_KEY_PASSWORD",
)


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def _secret_gates(workflow: dict) -> dict[str, str]:
    """Every env expression, in any step, that reads a signing secret."""
    gates: dict[str, str] = {}
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            for name, value in (step.get("env") or {}).items():
                text = str(value)
                for secret in SIGNING_SECRETS:
                    if f"secrets.{secret}" in text:
                        gates[name] = text
    return gates


def test_every_signing_secret_is_gated() -> None:
    """The scan below is only meaningful if it finds all four secrets."""
    gates = _secret_gates(_workflow())
    found = {s for s in SIGNING_SECRETS for g in gates.values() if f"secrets.{s}" in g}
    assert found == set(SIGNING_SECRETS), f"signing secrets not found: {set(SIGNING_SECRETS) - found}"


def test_a_schedule_never_builds_an_unsigned_main_apk() -> None:
    """No unattended trigger may run on main without the signing secrets."""
    workflow = _workflow()
    on = workflow.get(True) or {}
    if "schedule" not in on:
        return
    gates = _secret_gates(workflow)
    unsigned = [
        name
        for name, expr in gates.items()
        if not re.search(r"github\.event_name\s*==\s*'schedule'", expr)
    ]
    assert not unsigned, (
        "check.agent-android.yml has a schedule trigger, but these signing "
        f"secrets are not handed to scheduled runs: {unsigned}. A scheduled "
        "build would succeed DEBUG-signed and build.server-image.yml would "
        "publish it in place of the release agent (muster#123)."
    )
