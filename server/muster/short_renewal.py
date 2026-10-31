"""One short-lived renewal for one device, armed by an administrator (muster#22).

WHY THIS EXISTS. A device renews at a third of a 90-day life, so watching a real
handset's scheduled check-in cross `renew_after` unaided means waiting a month.
The operator chose to issue one enrolled handset a certificate measured in
hours instead, so the real clock reaches the threshold within the day, and then
let the device go back to the standard lifetime on its own.

THE SHAPE, and each part is a safety property rather than a convenience:

- ONE DEVICE. Armed per key_id, by an administrator, through the same sign-in
  as every other kith write. No device can arm itself and no setting reaches a
  second key.
- ONE ISSUANCE. `take` removes the entry in the same step that reads it, under
  a lock, so two renewals racing cannot both come back short. The renewal after
  the short one finds nothing armed and issues the standard lifetime.
- IN MEMORY, DELIBERATELY. muster runs one replica. A restart forgets an armed
  entry, which fails toward the ordinary 90-day certificate; nothing durable can
  be left behind to shorten a later renewal by surprise. The issuance itself IS
  durable: the short certificate lands in `kith_certificate` like any other.

THE ARITHMETIC THE OPERATOR NEEDS, because BACKDATE dominates at these sizes.
For a certificate issued at t with lifetime L (measured from t, as `ca.issue`
measures every lifetime), not_before = t - 12h, so

    renew_after = t - 12h + (L + 12h) / 3  =  t + (L - 24h) / 3

L = 36h (the default) puts renew_after 4h after issuance with 32h of runway
before expiry. Any L of 24h or less puts renew_after at or before issuance, so
the device renews again at its very next check-in and the short certificate
lives about fifteen minutes; that still ends on a standard certificate, but it
never shows the clock crossing the threshold.
"""
from __future__ import annotations

import datetime as dt
import threading
from dataclasses import dataclass

# Bounds on the lifetime an administrator may ask for. The floor keeps a real
# runway, because a lapsed owned handset needs a pairing code and a person: at
# 6h the device is due at once and has 6h to renew before it lapses. The
# ceiling keeps "short" honest: 72h puts renew_after 16h out with 56h of
# runway, nowhere near the 14-day floor this waives.
MIN_HOURS = 6
MAX_HOURS = 72
DEFAULT_HOURS = 36


@dataclass(frozen=True)
class Armed:
    """What the administrator asked for, and when."""

    lifetime: dt.timedelta
    armed_at: dt.datetime


class ShortRenewals:
    """Which devices get their next renewal short. At most one each."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._armed: dict[str, Armed] = {}

    def arm(self, key_id: str, armed: Armed) -> None:
        with self._lock:
            self._armed[key_id] = armed

    def disarm(self, key_id: str) -> Armed | None:
        with self._lock:
            return self._armed.pop(key_id, None)

    def peek(self, key_id: str) -> Armed | None:
        with self._lock:
            return self._armed.get(key_id)

    def take(self, key_id: str) -> Armed | None:
        """Read and clear in one step. The one-shot property lives here."""
        with self._lock:
            return self._armed.pop(key_id, None)

    def put_back(self, key_id: str, armed: Armed) -> None:
        """Undo a `take` whose issuance failed, unless it was re-armed since.

        A failed issuance leaves the device on the certificate it already holds,
        so the request has not been used up and the next attempt may have it.
        """
        with self._lock:
            self._armed.setdefault(key_id, armed)
