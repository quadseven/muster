"""The one-shot store behind muster#22, without the HTTP around it.

The test to read first is
`test_a_cancel_during_a_failed_issuance_stays_cancelled`: a renewal takes the
armed request, an administrator cancels, then issuance fails. Putting the
request back there would undo the cancel, and the device's next renewal would
come back short after the operator said not to.
"""
from __future__ import annotations

import datetime as dt

from muster.short_renewal import Armed, ShortRenewals

_KEY = "key-a"


def _armed(hours: int = 36) -> Armed:
    return Armed(
        lifetime=dt.timedelta(hours=hours),
        armed_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
    )


def test_a_failed_issuance_puts_the_request_back():
    store = ShortRenewals()
    request = _armed()
    store.arm(_KEY, request)

    taken = store.take(_KEY)
    store.put_back(_KEY, taken)

    assert store.peek(_KEY) is request


def test_a_cancel_during_a_failed_issuance_stays_cancelled():
    store = ShortRenewals()
    store.arm(_KEY, _armed())

    taken = store.take(_KEY)
    dropped = store.disarm(_KEY)
    store.put_back(_KEY, taken)

    assert dropped is taken
    assert store.peek(_KEY) is None


def test_a_rearm_during_a_failed_issuance_keeps_the_new_request():
    store = ShortRenewals()
    store.arm(_KEY, _armed(36))
    newer = _armed(6)

    taken = store.take(_KEY)
    store.arm(_KEY, newer)
    store.put_back(_KEY, taken)

    assert store.peek(_KEY) is newer


def test_a_rearm_then_cancel_during_a_failed_issuance_stays_cancelled():
    store = ShortRenewals()
    store.arm(_KEY, _armed(36))

    taken = store.take(_KEY)
    store.arm(_KEY, _armed(6))
    store.disarm(_KEY)
    store.put_back(_KEY, taken)

    assert store.peek(_KEY) is None


def test_a_spent_request_is_not_reported_as_cancelled_later():
    store = ShortRenewals()
    store.arm(_KEY, _armed())

    taken = store.take(_KEY)
    store.spent(_KEY, taken)

    assert store.disarm(_KEY) is None


def test_put_back_says_whether_the_request_went_back():
    store = ShortRenewals()
    store.arm(_KEY, _armed())
    taken = store.take(_KEY)
    assert store.put_back(_KEY, taken) is True

    taken = store.take(_KEY)
    store.disarm(_KEY)
    assert store.put_back(_KEY, taken) is False
