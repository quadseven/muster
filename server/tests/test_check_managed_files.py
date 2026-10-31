"""The cross-language check on managed names, and its one named exception.

`assemble the DPC` runs this tool against a list the JVM test writes. It lives
in tools/ and is not a package, so it is loaded from its path here.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

from muster import policy

_TOOL = pathlib.Path(__file__).resolve().parent.parent / "tools" / "check_managed_files.py"
_spec = importlib.util.spec_from_file_location("check_managed_files", _TOOL)
assert _spec is not None and _spec.loader is not None
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)


def _run(tmp_path: pathlib.Path, agent: set[str]) -> int:
    names = tmp_path / "agent-managed-files.json"
    names.write_text(json.dumps(sorted(agent)))
    return tool.main(["check_managed_files.py", str(names)])


def _agent_today() -> set[str]:
    return set(policy.MANAGED_FILES) - {policy.WIFI_FILE}


def test_wifi_alone_may_be_served_ahead_of_the_agent(tmp_path, capsys):
    """docs/policy.md: the agent has no wifi steward, so it does not hold it."""
    assert _run(tmp_path, _agent_today()) == 0
    assert "wifi" in capsys.readouterr().out


def test_another_name_the_agent_lacks_still_fails(tmp_path, capsys):
    assert _run(tmp_path, _agent_today() - {"wallpaper"}) == 1
    err = capsys.readouterr().err
    assert "the server serves 'wallpaper'" in err


def test_a_name_the_server_does_not_serve_still_fails(tmp_path, capsys):
    assert _run(tmp_path, _agent_today() | {"ringtone"}) == 1
    assert "the agent expects 'ringtone'" in capsys.readouterr().err


def test_the_exception_dies_once_the_agent_holds_the_name(tmp_path, capsys):
    """The exception must not outlive the gap it describes."""
    assert _run(tmp_path, set(policy.MANAGED_FILES)) == 1
    err = capsys.readouterr().err
    assert "SERVER_AHEAD" in err and "'wifi'" in err


def test_the_agent_list_being_missing_is_still_a_failure(tmp_path):
    assert tool.main(["check_managed_files.py", str(tmp_path / "absent.json")]) == 1


@pytest.mark.parametrize("argv", [["tool"], ["tool", "a", "b"]])
def test_the_wrong_arguments_are_a_usage_error(argv):
    assert tool.main(argv) == 2
