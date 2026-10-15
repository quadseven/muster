"""Validate the leak scan workflow configuration.

This test ensures the caller workflow runs the shared leak scan on every PR
(with the right triggers) and that it's properly configured.

Note: The GitHub Actions 'on:' keyword is parsed as boolean True by PyYAML
because 'on' is a YAML boolean keyword. Use workflow[True] or workflow.get(True)
to access the trigger configuration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

WORKFLOW_PATH = (
    Path(__file__).resolve().parents[2] / ".github/workflows/check.leak-scan.yml"
)


def test_leak_scan_workflow_exists() -> None:
    """The leak scan workflow must exist."""
    assert WORKFLOW_PATH.is_file(), f"Leak scan workflow not found at {WORKFLOW_PATH}"


def test_leak_scan_workflow_has_correct_triggers() -> None:
    """The workflow must run on PR opened, synchronize, reopened, and edited."""
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())

    # Note: 'on' is parsed as boolean True by PyYAML because it's a YAML keyword
    on = workflow.get(True, {})
    pull_request = on.get("pull_request", {})
    types = pull_request.get("types", [])

    required = ["opened", "synchronize", "reopened", "edited"]
    for trigger in required:
        assert trigger in types, (
            f"PR trigger '{trigger}' is missing from leak scan workflow"
        )


def test_leak_scan_workflow_calls_shared_reusable() -> None:
    """The workflow must call the shared leak scan reusable workflow."""
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())

    jobs = workflow.get("jobs", {})
    leak_scan = jobs.get("leak-scan", {})
    uses = leak_scan.get("uses", "")

    assert "_reusable.leak-scan.yml" in uses, (
        f"Leak scan workflow must call _reusable.leak-scan.yml, got: {uses}"
    )


def test_leak_scan_workflow_has_required_permissions() -> None:
    """The workflow must have contents: read and id-token: write permissions."""
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())

    jobs = workflow.get("jobs", {})
    leak_scan = jobs.get("leak-scan", {})
    permissions = leak_scan.get("permissions", {})

    assert permissions.get("contents") == "read", (
        "Leak scan workflow must have 'contents: read' permission"
    )
    assert permissions.get("id-token") == "write", (
        "Leak scan workflow must have 'id-token: write' permission"
    )


def test_leak_scan_workflow_passes_required_parameters() -> None:
    """The workflow must pass required parameters to the reusable workflow."""
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text())

    jobs = workflow.get("jobs", {})
    leak_scan = jobs.get("leak-scan", {})
    with_params = leak_scan.get("with", {})

    assert "allowed-repo-refs" in with_params, (
        "Leak scan workflow must have 'allowed-repo-refs' parameter"
    )
    assert "deny-list-ssm-param" in with_params, (
        "Leak scan workflow must have 'deny-list-ssm-param' parameter"
    )
