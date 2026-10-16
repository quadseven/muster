from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / ".loom" / "validation.conf"
WORKFLOW = ROOT / ".github" / "workflows" / "check.server.yml"


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
    ]
    workflow = WORKFLOW.read_text()
    assert "  pull_request:" in workflow
    assert "      - name: pytest\n" in workflow
    assert f"        run: {command.removeprefix('cd server && ')}" in workflow
