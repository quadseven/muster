"""The standing module answers the characterization table on its own (muster#217).

`test_standing.py` walks every verb from every state through the routes and
through `Kith`. This file walks the same `TRANSITIONS`, `PAST_THE_ROUTES` and
`SERVED` through `muster.standing` alone, with no HTTP and no database, so the
table and the module that owns it can be read side by side.
"""
from __future__ import annotations

import datetime as dt

import pytest

from muster import policy, standing
from muster.standing import Refusal, Stamps, Standing, Transition
from tests.test_standing import (
    ALL_PAIRS,
    PAST_THE_ROUTES,
    RECIPES,
    SERVED,
    START,
    TRANSITIONS,
    VERBS,
    Seen,
    _render,
)


def _standing(stamps: Stamps) -> Standing:
    return Standing(
        revoked=stamps.revoked_at is not None,
        wipe_pending=stamps.wipe_pending_at is not None,
        reboot_requested=stamps.reboot_requested_at is not None,
    )


class _Row:
    """One device row driven only through the module, with a ticking clock."""

    def __init__(self) -> None:
        self.stamps = Stamps()
        self.t = START

    def tick(self) -> dt.datetime:
        self.t += dt.timedelta(seconds=1)
        return self.t

    def through_the_store(self, verb: str) -> bool:
        after = standing.written(verb, self.stamps, self.tick())
        if after is None:
            return False
        self.stamps = after
        return True

    def through_the_routes(self, verb: str) -> Transition | Refusal:
        answer = standing.permits(_standing(self.stamps), verb)
        if isinstance(answer, Transition):
            assert self.through_the_store(verb)
        return answer

    def seen(self) -> Seen:
        restored = None
        if self.stamps.wipe_pending_at is not None:
            restored = standing.written(
                standing.CALL_OFF_WIPE, self.stamps, self.tick()
            ).revoked_at
        return Seen(
            self.stamps.revoked_at,
            self.stamps.wipe_pending_at,
            self.stamps.reboot_requested_at,
            restored,
        )


def _in_state(state: str) -> tuple[_Row, dt.datetime | None, dt.datetime]:
    row = _Row()
    original = None
    for step in RECIPES[state]:
        assert isinstance(row.through_the_routes(step), Transition)
        original = original or row.stamps.revoked_at
    return row, original, row.tick() + dt.timedelta(seconds=1)


def test_the_module_names_the_same_verbs_as_the_table():
    assert set(standing.VERBS) == set(VERBS)


@pytest.mark.parametrize("state,verb", ALL_PAIRS)
def test_permits_answers_every_cell_of_the_table(state, verb):
    row, original, since = _in_state(state)
    expected = TRANSITIONS[state, verb]

    answer = row.through_the_routes(verb)

    if isinstance(expected, int):
        assert isinstance(answer, Refusal)
        assert answer.status == expected
        ended = state
    else:
        assert answer == Transition(verb)
        ended = expected
    assert _render(row.seen(), original, since) == ended


@pytest.mark.parametrize("state,verb", ALL_PAIRS)
def test_written_holds_only_the_guards_the_store_holds(state, verb):
    """Below the routes the store refuses only an acknowledgement of nothing."""
    row, original, since = _in_state(state)
    expected = PAST_THE_ROUTES.get((state, verb), TRANSITIONS[state, verb])

    applied = row.through_the_store(verb)

    assert applied is not isinstance(expected, int)
    ended = state if isinstance(expected, int) else expected
    assert _render(row.seen(), original, since) == ended


@pytest.mark.parametrize("state", sorted(SERVED))
def test_served_answers_what_each_state_is_given(state):
    row, _original, _since = _in_state(state)
    status, files = SERVED[state]

    given = standing.served(_standing(row.stamps))

    assert given.refused is (status == 403)
    if files is not None:
        assert given.wipe is (files == {policy.WIPE_FILE})
        assert given.reboot is (policy.REBOOT_FILE in files)


def test_an_erase_answers_alone_even_with_a_reboot_waiting():
    given = standing.served(Standing(wipe_pending=True, reboot_requested=True))
    assert given == standing.Served(refused=False, wipe=True, reboot=False)


@pytest.mark.parametrize("state,verb", ALL_PAIRS)
def test_offered_never_shows_a_verb_permits_refuses(state, verb):
    row, _original, _since = _in_state(state)
    now = _standing(row.stamps)
    if verb in standing.offered(now):
        assert isinstance(standing.permits(now, verb), Transition)


@pytest.mark.parametrize(
    "now,shown",
    [
        (Standing(), ("reboot", "wipe", "revoke")),
        (Standing(revoked=True), ("wipe", "readmit")),
        (Standing(wipe_pending=True), ("reboot", "call_off_wipe")),
        (Standing(reboot_requested=True), ("call_off_reboot", "wipe", "revoke")),
        (
            Standing(revoked=True, reboot_requested=True),
            ("call_off_reboot", "wipe", "readmit"),
        ),
        (
            Standing(wipe_pending=True, reboot_requested=True),
            ("call_off_reboot", "call_off_wipe"),
        ),
    ],
)
def test_offered_is_what_the_console_draws(now, shown):
    """The console renders exactly this list (muster#217). An erase is offered on
    a revoked device, because the server lifts the revocation to deliver it and
    restores it if the erase is called off (D29, #214). Revoking is held back
    while an erase is queued, because a revocation overrules the erase."""
    assert standing.offered(now) == shown


def test_no_device_verb_is_ever_offered_to_an_administrator():
    for r in (False, True):
        for w in (False, True):
            for b in (False, True):
                assert not set(standing.offered(Standing(r, w, b))) & set(
                    standing.DEVICE_VERBS
                )


def test_only_the_verbs_with_a_refusal_need_a_read_first():
    refusable = {verb for verb in standing.VERBS if standing.refusable(verb)}
    assert refusable == {"reboot", "ack_wipe", "ack_reboot"}


def test_an_unknown_verb_is_an_error_not_a_permission():
    with pytest.raises(ValueError):
        standing.permits(Standing(), "unrevoke")
    with pytest.raises(ValueError):
        standing.written("unrevoke", Stamps(), START)
