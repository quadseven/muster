"""What a device carries, held against what its policy tells it to (muster#162).

WHY THIS EXISTS. muster hid the Play Store and so took on keeping the device's
apps current (muster#67). The device already reports the versionCode of every
package `install-apps` names (muster#146), and `install-apps` already says
which version each one should be at. Until this, nothing put the two side by
side, so a phone stuck on an old build looked exactly like one that was fine
unless somebody read both and compared them by eye.

THE EXPECTED VERSION IS THE SERVED POLICY, not a second list. It is read from
the `install-apps` text `Policies.for_device` would hand this device - merged
across kith, role and device scope by package (muster#109) - so drift is judged
against what the device is actually told, and a role that pins a newer build
is not reported against the kith's older one.

WHAT CLOSES DRIFT, AND WHAT CANNOT. A `behind` or `missing` package is one
muster owns: its line names an asset and a digest, and the agent installs it
silently as Device Owner at its next check-in. Raising the line's `version` and
publishing the asset IS the push. A package no line names is `unmanaged` -
which includes everything Play installed. Play keeps its own update queue and
a Device Owner can neither read it nor drive it, so muster says the app is out
of reach rather than pretending to schedule an update that will never happen.

The agent stays the validator of the line's grammar (policy.py,
`_merge_install_apps`). This reads only the version, and a line it cannot read
one from is `unreadable`, because the agent refuses that line and nothing will
be installed for it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from muster.kith import PackageReport
from muster.policy import install_package

# At or past the version named. Past is what a hand-installed build looks like
# and the agent leaves it alone (AppInstallPolicy.plan), so it is not drift.
CURRENT = "current"
# Installed, below the version named. Drift, and muster's to close.
BEHIND = "behind"
# The device looked and the package is not there. Drift, and muster's to close.
MISSING = "missing"
# The policy names it and the report does not mention it: the report predates
# the line, or there is no report at all. Not "not installed" - nobody said so.
UNREPORTED = "unreported"
# Reported, and no line names it. muster cannot push it.
UNMANAGED = "unmanaged"
# A line names it and no version can be read off that line.
UNREADABLE = "unreadable"

DRIFT_STATES = frozenset({BEHIND, MISSING})

# `install <package> <asset> sha256 <hex> version <code>` - the positions
# AppInstallPolicy.read checks. Digits only: a sign is not a versionCode.
_VERSION_KEYWORD_AT = 5
_VERSION_AT = 6
_CODE = re.compile(r"[0-9]+")


@dataclass(frozen=True)
class Entry:
    package: str
    expected_version_code: int | None
    reported_version_code: int | None
    state: str


def _version_of(line: str) -> int | None:
    words = line.split()
    if len(words) <= _VERSION_AT or words[_VERSION_KEYWORD_AT] != "version":
        return None
    code = words[_VERSION_AT]
    return int(code) if _CODE.fullmatch(code) else None


def expected_versions(install_apps: str | None) -> dict[str, int | None]:
    """Each package the file names, in file order, to the versionCode it names.

    None for a line whose version cannot be read. The first line naming a
    package wins, as it would on a device that refuses the later duplicate.
    """
    expected: dict[str, int | None] = {}
    for line in (install_apps or "").splitlines():
        package = install_package(line)
        if package is not None and package not in expected:
            expected[package] = _version_of(line)
    return expected


def _state(expected: int | None, reported: PackageReport | None) -> str:
    if expected is None:
        return UNREADABLE
    if reported is None:
        return UNREPORTED
    if reported.version_code is None:
        return MISSING
    return CURRENT if reported.version_code >= expected else BEHIND


def compare(
    expected: dict[str, int | None],
    reported: tuple[PackageReport, ...] | None,
) -> list[Entry]:
    """Every package either side names, once: the policy's in its order, then
    the report's leftovers. `reported` is None when the device never reported."""
    by_package = {p.package: p for p in reported or ()}
    entries = [
        Entry(
            package=package,
            expected_version_code=code,
            reported_version_code=(
                by_package[package].version_code if package in by_package else None
            ),
            state=_state(code, by_package.get(package)),
        )
        for package, code in expected.items()
    ]
    entries.extend(
        Entry(
            package=p.package,
            expected_version_code=None,
            reported_version_code=p.version_code,
            state=UNMANAGED,
        )
        for p in by_package.values()
        if p.package not in expected
    )
    return entries


def drifted(entries: list[Entry]) -> int:
    """How many packages muster owns are below the version their policy names."""
    return sum(1 for entry in entries if entry.state in DRIFT_STATES)
