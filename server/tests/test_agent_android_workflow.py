"""Guard the agent build against publishing a debug-signed APK unattended.

build.server-image.yml bakes the newest SUCCESSFUL run of check.agent-android.yml
on main, whatever event started it, and it also runs whenever that workflow
completes on main. So any trigger that runs on main without the signing secrets
produces a debug-signed APK that the next image publishes in place of the
release agent (muster#123: a weekly schedule did exactly that).

A schedule fires on its own, so this test refuses a `schedule` trigger unless
every expression that hands the build its signing secrets also admits scheduled
runs. A manual dispatch on main is no safer: whoever dispatches it to test
something has not chosen to publish a debug agent fleet-wide. The image build
therefore bakes only runs started by a push (DECISIONS.md D33), and the tests
below hold that query, the image's start gate and the Dockerfile's ownership of
/app in place (muster#226).

Note: PyYAML parses the GitHub Actions `on:` key as boolean True.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

from muster.api import app_from_env

REPO = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github/workflows"
WORKFLOW_PATH = WORKFLOWS / "check.agent-android.yml"
IMAGE_WORKFLOW_PATH = WORKFLOWS / "build.server-image.yml"
DOCKERFILE_PATH = REPO / "server/Dockerfile"
START_GATE = "The image must refuse to start without administrator sign-in"

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


def _steps(path: Path) -> list[dict]:
    workflow = yaml.safe_load(path.read_text())
    return [step for job in workflow["jobs"].values() for step in job.get("steps", [])]


def _step(path: Path, name: str) -> dict:
    found = [step for step in _steps(path) if step.get("name") == name]
    assert len(found) == 1, f"{path.name}: expected one step named {name!r}"
    return found[0]


def test_no_github_context_is_spliced_into_run_text() -> None:
    """github.* reaches a script through env:, never as pasted text.

    A branch name may carry `$`, backticks or `;`, and an expression is
    substituted before the shell parses the script.
    """
    spliced = [
        f"{path.name}: {step.get('name', '<unnamed>')}"
        for path in sorted(WORKFLOWS.glob("*.yml"))
        for step in _steps(path)
        if re.search(r"\$\{\{[^}]*\bgithub\.", str(step.get("run", "")))
    ]
    assert not spliced, f"github.* spliced into run: text in {spliced}"


def test_every_job_runs_on_a_pinned_image() -> None:
    floating = [
        f"{path.name}: {name}"
        for path in sorted(WORKFLOWS.glob("*.yml"))
        for name, job in yaml.safe_load(path.read_text())["jobs"].items()
        if "latest" in str(job.get("runs-on", ""))
    ]
    assert not floating, f"jobs on a floating runner image: {floating}"


def test_only_a_push_build_can_become_the_served_agent() -> None:
    """A dispatch on main builds debug-signed; it must not be baked."""
    run = str(_step(IMAGE_WORKFLOW_PATH, "Find the newest agent APK the mini published")["run"])
    queries = re.findall(r'"\$runs\?([^"]*)"', run)
    assert queries, "the agent run lookup query was not found"
    for query in queries:
        params = dict(part.split("=", 1) for part in query.split("&"))
        assert params.get("event") == "push", f"agent run query without event=push: {query}"
        assert params.get("branch") == "main"
        assert params.get("status") == "success"


def test_the_start_gate_reads_the_refusal_not_just_the_exit_code() -> None:
    """Any crash exits non-zero, so the gate must find the refusal itself."""
    step = _step(IMAGE_WORKFLOW_PATH, START_GATE)
    run = str(step["run"])
    assert "/dev/null" not in run, "the start gate discards the container's output"
    expected = str((step.get("env") or {}).get("REFUSAL", ""))
    assert expected, "the start gate names no refusal text to look for"
    assert '"$REFUSAL"' in run, "the start gate does not search for the refusal"


def test_the_start_gate_text_is_what_app_from_env_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate's expected text must match the real refusal, or it never passes."""
    for name in list(os.environ):
        if name.startswith("MUSTER_"):
            monkeypatch.delenv(name)
    with pytest.raises(RuntimeError) as refused:
        app_from_env()
    line = f"{type(refused.value).__name__}: {refused.value}"
    env = _step(IMAGE_WORKFLOW_PATH, START_GATE).get("env") or {}
    expected = str(env.get("REFUSAL", ""))
    assert expected and expected in line, f"{expected!r} is not in {line!r}"


def test_the_runtime_user_does_not_own_its_code() -> None:
    """The process holds the CA key; it must not be able to rewrite /app."""
    text = DOCKERFILE_PATH.read_text()
    instructions = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    assert not [line for line in instructions if "chown" in line], (
        "server/Dockerfile hands ownership of files to the runtime user"
    )
    assert "MUSTER_ADMIN_TOKEN" not in text, (
        "server/Dockerfile cites a variable api.py no longer reads"
    )
