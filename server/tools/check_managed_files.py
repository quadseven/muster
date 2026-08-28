#!/usr/bin/env python3
"""Do the agent and the server agree which files may travel to a device?

THE SEAM. `muster.policy.MANAGED_FILES` decides what the server will serve;
`ConfigurationPolicy.MANAGED` in the Android agent decides what the device will
write. They are two halves of one contract in two languages, and neither test
suite can see the other.

THE DRIFT IS SILENT IN BOTH DIRECTIONS, which is why this is a CI step and not
a comment:

  - A name the SERVER serves and the AGENT does not hold is refused at the
    device and never written. The operator sees their file being served and the
    handset behaves as though nothing was configured.
  - A name the AGENT holds and the SERVER will not serve is a policy file an
    operator can write, save, and watch do nothing at all.

Neither produces an error anybody is looking at. `wallpaper` was added to the
server first and did exactly the first of these until this check was written.

    uv run --group dev python tools/check_managed_files.py agent-managed-files.json
"""
from __future__ import annotations

import json
import pathlib
import sys

from muster.policy import MANAGED_FILES


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <agent-managed-files.json>", file=sys.stderr)
        return 2

    path = pathlib.Path(argv[1])
    if not path.is_file():
        print(f"::error::{path} is not there; the JVM test did not write it", file=sys.stderr)
        return 1

    try:
        agent = set(json.loads(path.read_text()))
    except (OSError, ValueError) as exc:
        print(f"::error::{path} could not be read as JSON: {exc}", file=sys.stderr)
        return 1

    server = set(MANAGED_FILES)
    if agent == server:
        print(f"agent and server agree on {len(server)} managed files: {sorted(server)}")
        return 0

    # BOTH DIRECTIONS ARE REPORTED SEPARATELY, because the fix is in a
    # different language for each and "they differ" sends somebody to read two
    # files to work out which.
    for name in sorted(server - agent):
        print(
            f"::error::the server serves '{name}' and the agent refuses it - "
            "add it to ConfigurationPolicy.MANAGED",
            file=sys.stderr,
        )
    for name in sorted(agent - server):
        print(
            f"::error::the agent expects '{name}' and the server will not serve it - "
            "add it to policy.MANAGED_FILES",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
