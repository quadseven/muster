#!/usr/bin/env python3
"""Do the agent and the server agree what each HTTP status means?

THE SEAM. `muster.api._STATUS` maps an enrollment refusal to a status code; the
Android client maps that code back to a behaviour. They are two halves of one
contract written in different languages, and neither test suite can see the
other - so a code that quietly changes meaning on one side produces a device
that retries something which can never succeed, or gives up while an operator is
still walking to their laptop.

Both sides export their map as data. This compares them.

    uv run --group dev python tools/check_status_map.py agent-status-map.json
"""
from __future__ import annotations

import json
import pathlib
import sys

from muster.api import DEVICE_FACING, _STATUS


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <agent-status-map.json>", file=sys.stderr)
        return 2

    path = pathlib.Path(argv[1])
    if not path.is_file():
        print(f"::error::the JVM test did not write {path}", file=sys.stderr)
        return 1

    agent = {int(k): v for k, v in json.loads(path.read_text()).items()}

    # Only the DEVICE-FACING half. The server reuses 409 across two endpoints -
    # CODE_USED for a device, FINGERPRINT_MISMATCH for an administrator - so a
    # naive inversion of _STATUS silently keeps whichever came last and then
    # reports a disagreement that is not one. That is exactly what happened the
    # first time this ran.
    server = {
        _STATUS[outcome]: outcome.value
        for outcome in _STATUS
        if outcome in DEVICE_FACING
    }

    problems = []

    # Every code the SERVER can return for an enrollment refusal must be one the
    # agent understands. A code the agent does not know falls into its
    # `Unexpected` branch, where it has no idea whether to retry.
    for status, meaning in server.items():
        if status not in agent:
            problems.append(f"server returns {status} ({meaning}); agent does not know it")
        elif agent[status] != meaning:
            problems.append(
                f"{status}: server says {meaning!r}, agent says {agent[status]!r}"
            )

    # And the reverse: a code the agent handles which the server never sends is
    # dead branch, which is harmless but usually means one side was edited.
    for status, meaning in agent.items():
        if status not in server and meaning != "malformed-request":
            problems.append(
                f"agent handles {status} ({meaning}); server never returns it"
            )

    if problems:
        for problem in problems:
            print(f"::error::{problem}", file=sys.stderr)
        return 1

    shared = sorted(set(agent) & set(server))
    print(f"agent and server agree on {len(shared)} status codes: {shared}")
    print("::notice::the agent and the server agree on what each refusal means")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
