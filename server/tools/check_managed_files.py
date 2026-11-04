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

ONE NAMED EXCEPTION, `SERVER_AHEAD`. A name goes there only when the server half
has shipped, docs/policy.md says the agent half has not, and holding the name
without a steward would be worse than refusing it. The check fails the moment
the agent holds such a name, so the exception cannot outlive the gap.

    uv run --group dev python tools/check_managed_files.py agent-managed-files.json
"""
from __future__ import annotations

import json
import pathlib
import sys

from muster.policy import MANAGED_FILES, WIFI_FILE

# Served, and refused by the agent on purpose. `wifi` carries a passphrase and
# the agent has no steward for it yet (muster#195), so adding it to
# ConfigurationPolicy.MANAGED would leave a credential on the device that
# nothing reads. The device reports the refusal, so this drift is not silent.
SERVER_AHEAD = frozenset({WIFI_FILE})


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

    server = set(MANAGED_FILES) - SERVER_AHEAD
    if agent == server:
        print(
            f"agent and server agree on {len(server)} managed files: {sorted(server)}; "
            f"served ahead of the agent: {sorted(SERVER_AHEAD)}"
        )
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
    for name in sorted(agent & SERVER_AHEAD):
        print(
            f"::error::the agent now holds '{name}' - remove it from SERVER_AHEAD",
            file=sys.stderr,
        )
    for name in sorted(agent - server - SERVER_AHEAD):
        print(
            f"::error::the agent expects '{name}' and the server will not serve it - "
            "add it to policy.MANAGED_FILES",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
