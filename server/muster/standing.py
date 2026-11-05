"""A device's standing, and what each verb may do to it (muster#217).

ONE TABLE, NO HTTP AND NO DATABASE. A device holds three facts about its
standing: whether it is revoked, whether an erase is queued, and whether a
reboot is waiting. Eight verbs move it. Before this module the rules lived in
the route helpers, the two Records adapters, the `Device` field comments and
the console, and each new verb re-derived them. Here they are read once:

    permits(standing, verb)   the transition a verb makes, or the refusal
    served(standing)          what the device channel answers it with
    offered(standing)         which administrator verbs the console shows
    written(verb, stamps, at) the row a transition leaves, for MemoryRecords

THE ORDERINGS THIS TABLE CARRIES ARE D29 AND D30. An erase lifts a revocation
so the instruction can travel, and holds the lifted time until the erase is
acknowledged, called off, or overruled by a later revoke or readmit. A reboot
never lifts a revocation: arming one on a revoked device is refused.

WHERE EACH GUARD IS ENFORCED. `permits` is the whole answer a caller gets. Two
of its refusals are also guards the store holds itself, inside one conditional
UPDATE (an acknowledgement applies only to an instruction still waiting), so a
stale read here can never turn into a wrong write. The others (a revoked
device is refused on the device channel; arming a reboot on a revoked device
is refused) are answered from a read, which D30 accepts for reboot because the
race leaves an inert flag on a device that is refused everything anyway.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace

REVOKE = "revoke"
READMIT = "readmit"
WIPE = "wipe"
CALL_OFF_WIPE = "call_off_wipe"
REBOOT = "reboot"
CALL_OFF_REBOOT = "call_off_reboot"
ACK_WIPE = "ack_wipe"
ACK_REBOOT = "ack_reboot"

# What an administrator does from the console, in the order its buttons sit.
ADMINISTRATOR_VERBS = (REBOOT, CALL_OFF_REBOOT, WIPE, CALL_OFF_WIPE, REVOKE, READMIT)
# What a device says over its own proven channel.
DEVICE_VERBS = (ACK_WIPE, ACK_REBOOT)
VERBS = ADMINISTRATOR_VERBS + DEVICE_VERBS

REVOKED_DETAIL = "this device has been revoked"
NOT_WIPE_PENDING_DETAIL = "this device is not waiting to be wiped"
NOT_REBOOT_REQUESTED_DETAIL = "this device was not asked to reboot"
REBOOT_REVOKED_DETAIL = "this device is revoked; readmit it before asking it to reboot"


@dataclass(frozen=True)
class Standing:
    """What a caller can read of a device's standing.

    An erase queued over a lifted revocation reads the same as a plain one:
    no read returns the revocation set aside, and no rule here needs it.
    """

    revoked: bool = False
    wipe_pending: bool = False
    reboot_requested: bool = False

    @classmethod
    def of(cls, device) -> Standing:
        """The standing a `kith.Device` (or anything with its three stamps) holds."""
        return cls(
            revoked=device.revoked_at is not None,
            wipe_pending=device.wipe_pending_at is not None,
            reboot_requested=device.reboot_requested_at is not None,
        )


@dataclass(frozen=True)
class Transition:
    """A verb the table permits from this standing."""

    verb: str


@dataclass(frozen=True)
class Refusal:
    """A verb the table refuses from this standing, as the status a route answers."""

    verb: str
    status: int
    detail: str


@dataclass(frozen=True)
class Served:
    """What the device channel answers a device in this standing with.

    `refused` is the 403 on every route (D27). Otherwise `wipe` means the erase
    answers alone and needs no policy directory (D29), and `reboot` means the
    reboot instruction joins the ordinary answer (D30). The two are never both
    set: the erase is the whole answer.
    """

    refused: bool
    wipe: bool
    reboot: bool


def permits(standing: Standing, verb: str) -> Transition | Refusal:
    """The transition `verb` makes from `standing`, or the refusal it gets."""
    if verb not in VERBS:
        raise ValueError(f"no such verb: {verb!r}")
    if verb in DEVICE_VERBS and standing.revoked:
        # The device channel refuses a revoked key before any verb is read.
        return Refusal(verb, 403, REVOKED_DETAIL)
    if verb == ACK_WIPE and not standing.wipe_pending:
        return Refusal(verb, 409, NOT_WIPE_PENDING_DETAIL)
    if verb == ACK_REBOOT and not standing.reboot_requested:
        return Refusal(verb, 409, NOT_REBOOT_REQUESTED_DETAIL)
    if verb == REBOOT and standing.revoked:
        # D30: a reboot is weaker than a revocation and must not lift one.
        return Refusal(verb, 409, REBOOT_REVOKED_DETAIL)
    return Transition(verb)


def refusable(verb: str) -> bool:
    """Whether any standing refuses `verb`, so whether a route must read one first."""
    return any(
        isinstance(permits(Standing(r, w, b), verb), Refusal)
        for r in (False, True)
        for w in (False, True)
        for b in (False, True)
    )


def served(standing: Standing) -> Served:
    """What the device channel gives a device in `standing`."""
    if standing.revoked:
        return Served(refused=True, wipe=False, reboot=False)
    # AN ERASE ANSWERS ALONE: a waiting reboot is not served beside it, and
    # would be pointless after the erase anyway (D30's boot order).
    return Served(
        refused=False,
        wipe=standing.wipe_pending,
        reboot=standing.reboot_requested and not standing.wipe_pending,
    )


def offered(standing: Standing) -> tuple[str, ...]:
    """The administrator verbs the console shows for a device in `standing`.

    A subset of what `permits` allows, never more. A verb is left out when it
    would change nothing a person asked for (calling off an erase that is not
    queued), and in one case on purpose: revoking or readmitting while an erase
    is queued is permitted, but it overrules the erase and drops it, so the
    console waits for the erase to land or be called off first (D29).
    """
    meaningful = {
        REBOOT: not standing.reboot_requested,
        CALL_OFF_REBOOT: standing.reboot_requested,
        WIPE: not standing.wipe_pending,
        CALL_OFF_WIPE: standing.wipe_pending,
        REVOKE: not standing.revoked and not standing.wipe_pending,
        READMIT: standing.revoked and not standing.wipe_pending,
    }
    return tuple(
        verb
        for verb in ADMINISTRATOR_VERBS
        if meaningful[verb] and isinstance(permits(standing, verb), Transition)
    )


@dataclass(frozen=True)
class Stamps:
    """The four columns a standing is stored in.

    `revoked_before_wipe_at` is the revocation an erase lifted (#214). It is
    never read back by a caller; calling the erase off is what restores it.
    """

    revoked_at: dt.datetime | None = None
    wipe_pending_at: dt.datetime | None = None
    reboot_requested_at: dt.datetime | None = None
    revoked_before_wipe_at: dt.datetime | None = None


def written(verb: str, stamps: Stamps, at: dt.datetime | None) -> Stamps | None:
    """The row `verb` leaves, under only the guards the store holds itself.

    None means the store's own guard refused: an acknowledgement of an
    instruction that is not waiting. The route-level refusals in `permits`
    are not repeated here, because the store is below them; `PostgresRecords`
    writes the same rows, each verb in one conditional UPDATE. `at` is the
    time a verb stamps; the verbs that clear a column ignore it.
    """
    if verb == REVOKE:
        return replace(stamps, revoked_at=at, wipe_pending_at=None, revoked_before_wipe_at=None)
    if verb == READMIT:
        return replace(stamps, revoked_at=None, wipe_pending_at=None, revoked_before_wipe_at=None)
    if verb == WIPE:
        # THE LIFT BELONGS TO THE ERASE: set aside, not lost (D29, #214).
        return replace(
            stamps,
            revoked_before_wipe_at=stamps.revoked_at or stamps.revoked_before_wipe_at,
            revoked_at=None,
            wipe_pending_at=at,
        )
    if verb == CALL_OFF_WIPE:
        # Restores what the erase set aside; with nothing set aside a
        # revocation stands, so a stray call off cannot readmit anyone.
        return replace(
            stamps,
            revoked_at=stamps.revoked_before_wipe_at or stamps.revoked_at,
            revoked_before_wipe_at=None,
            wipe_pending_at=None,
        )
    if verb == REBOOT:
        # NO REVOCATION SIDE EFFECT, unlike wipe (D30).
        return replace(stamps, reboot_requested_at=at)
    if verb == CALL_OFF_REBOOT:
        return replace(stamps, reboot_requested_at=None)
    if verb == ACK_WIPE:
        if stamps.wipe_pending_at is None:
            return None
        return replace(stamps, revoked_at=at, wipe_pending_at=None, revoked_before_wipe_at=None)
    if verb == ACK_REBOOT:
        if stamps.reboot_requested_at is None:
            return None
        return replace(stamps, reboot_requested_at=None)
    raise ValueError(f"no such verb: {verb!r}")
