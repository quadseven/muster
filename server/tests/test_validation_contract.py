from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / ".loom" / "validation.conf"
WORKFLOW = ROOT / ".github" / "workflows" / "check.server.yml"
ANDROID_WORKFLOW = ROOT / ".github" / "workflows" / "check.agent-android.yml"

# The managed-file seam CI checks in `assemble the DPC`, only for these paths.
MANAGED_FILES_CHECK = (
    "cd server && set -euo pipefail"
    " && NAMES=../agent/android/app/build/cross-language/agent-managed-files.json"
    ' && [ -f "$NAMES" ] || { echo "::error::the JVM test did not write the managed-file names"; exit 1; }'
    ' && uv run --group dev --python 3.12 python tools/check_managed_files.py "$NAMES"'
)
AFFECTED = (
    "printf '%s\\n' \"$LOOM_CHANGED_FILES\""
    " | grep -qE '^(agent/android/|\\.github/workflows/check\\.agent-android\\.yml$)' || exit 0;"
    " (cd agent/android/app && bash ../../tools/jvm-tests.sh) || exit 1; "
    + MANAGED_FILES_CHECK
)


def test_validation_contract_matches_pull_request_check():
    """The lane runs the same repository test command as pull request CI."""
    assert CONTRACT.is_file()
    lines = CONTRACT.read_text().splitlines()
    assert lines[:3] == [
        "# lint: no pull-request run step",
        "# format: no pull-request run step",
        "# type: no pull-request run step",
    ]
    assert "# test: .github/workflows/check.server.yml :: pytest" in lines
    command = "cd server && uv run --group dev --python 3.12 python -m pytest -q"
    assert [line for line in lines if not line.startswith("#")] == [
        "interpreter: uv",
        "submodules: no",
        f"check: {command}",
        f"affected: {AFFECTED}",
    ]
    workflow = WORKFLOW.read_text()
    assert "  pull_request:" in workflow
    assert "      - name: pytest\n" in workflow
    assert f"        run: {command.removeprefix('cd server && ')}" in workflow


def test_affected_runs_the_managed_files_step_ci_runs():
    """The affected command runs the step CI runs, for CI's paths only."""
    workflow = ANDROID_WORKFLOW.read_text()
    assert "      - 'agent/android/**'\n" in workflow
    assert "      - '.github/workflows/check.agent-android.yml'\n" in workflow
    step = workflow.split("- name: The agent and the server must agree which files may travel\n", 1)[1]
    step = step.split("\n\n", 1)[0]
    assert "        working-directory: server\n" in step
    run = [line.strip() for line in step.split("run: |\n", 1)[1].splitlines()]
    assert " && ".join(["cd server", *run]) == MANAGED_FILES_CHECK
