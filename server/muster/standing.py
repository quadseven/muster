"""A device's standing: what may happen to it, and what it is answered (D29, D30).

THE ONE PLACE THESE RULES ARE RULED. Standing is read from timestamps on
`Device`, and this module holds no store and no HTTP, so all of it is a table a
test can walk with no database: see `tests/test_standing.py`.

A REFUSAL HERE IS A READ. The guards that close a race live in the Records
adapters, as single conditional statements. A caller still has to treat the
write as the authority, because the row can move after this answer.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from muster.kith import Device


class Verb(enum.Enum):
    """What can be done to a device that this module has a rule about."""

    REBOOT = "reboot"
    ACKNOWLEDGE_WIPE = "acknowledge_wipe"
    ACKNOWLEDGE_REBOOT = "acknowledge_reboot"


@dataclass(frozen=True)
class Served:
    """What the device channel gives a device in this standing."""

    refused: bool = False
    wipe: bool = False
    reboot: bool = False


def served(device: Device) -> Served:
    """What this device is answered.

    REFUSED ONLY WHEN REVOKED, and that ordering is D29: a queued erase must
    still be answered, or the instruction could never arrive. A reboot waiting
    on a revoked device is inert, because the refusal comes first (D30).
    """
    return Served(
        refused=device.revoked_at is not None,
        wipe=device.wipe_pending_at is not None,
        reboot=device.reboot_requested_at is not None,
    )


def permits(device: Device | None, verb: Verb) -> bool:
    """Whether this verb applies to this device now.

    None is a key the kith has no row for. It may not acknowledge anything, and
    a reboot asked for it goes on to the write, which answers "no such device".

    ONE ANSWER FOR "NEVER ASKED" AND "CALLED OFF IN BETWEEN". A device cannot
    act differently on the two, and telling it which one it lost would say
    something it is not entitled to know.
    """
    if verb is Verb.REBOOT:
        return device is None or device.revoked_at is None
    if device is None:
        return False
    if verb is Verb.ACKNOWLEDGE_WIPE:
        return device.wipe_pending_at is not None
    return device.reboot_requested_at is not None
