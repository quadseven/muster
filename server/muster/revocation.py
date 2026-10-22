"""Standard answers for relying parties outside muster.

`_proven_device` remains muster's authoritative revocation check. It knows the
stable key_id and can refuse the device directly, without waiting for a cached
artifact filed by certificate serial. This module answers the different
question a third-party PKI client can ask: whether one issued serial is revoked.

THE STORE MAY NOT DEGRADE TO AN EMPTY OR GOOD ANSWER. A missing CRL entry says
"not revoked" and an OCSP `good` says it explicitly, so either answer during a
kith outage would turn loss of the revocation database into permission. Reads
therefore raise through unchanged; the HTTP layer returns 503 for CRL and an
RFC 6960 `tryLater` response for OCSP.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import ocsp

from muster.ca import Authority, Untrusted
from muster.kith import Kith

# Five minutes is the maximum time a shared cache may continue saying `good`
# after an administrator revokes a device. It is short compared with a 90-day
# certificate, long compared with the store's 30-second breaker cooldown, and
# keeps ordinary CRL refreshes out of the database hot path. DECISIONS.md owns
# the full argument; this constant makes the wire contract and cache header use
# the same number.
FRESHNESS = dt.timedelta(minutes=5)


@dataclass(frozen=True)
class Artifact:
    content: bytes
    this_update: dt.datetime | None
    next_update: dt.datetime | None

    @property
    def cacheable(self) -> bool:
        return self.next_update is not None


class Responder:
    """Build signed artifacts from the authoritative kith read path."""

    def __init__(
        self,
        authority: Authority,
        kith: Kith,
        *,
        clock=None,
        freshness: dt.timedelta = FRESHNESS,
    ) -> None:
        self._authority = authority
        self._kith = kith
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        self._freshness = freshness

    def crl(self) -> Artifact:
        now = self._clock()
        next_update = now + self._freshness
        statuses = self._kith.unexpired_revocations(now)
        content = self._authority.crl(
            [
                (int(status.certificate.serial, 16), status.revoked_at)
                for status in statuses
                if status.revoked_at is not None
            ],
            this_update=now,
            next_update=next_update,
        )
        return Artifact(content=content, this_update=now, next_update=next_update)

    def ocsp(self, request_der: bytes) -> Artifact:
        try:
            request = self._authority.ocsp_request(request_der)
        except ValueError:
            return _unsuccessful(ocsp.OCSPResponseStatus.MALFORMED_REQUEST)
        except Untrusted:
            return _unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED)

        status = self._kith.certificate_status(f"{request.serial_number:X}")
        if status is None:
            verdict = ocsp.OCSPCertStatus.UNKNOWN
            revoked_at = None
        elif status.revoked_at is not None:
            verdict = ocsp.OCSPCertStatus.REVOKED
            revoked_at = status.revoked_at
        else:
            verdict = ocsp.OCSPCertStatus.GOOD
            revoked_at = None

        now = self._clock()
        next_update = now + self._freshness
        content = self._authority.ocsp_response(
            request,
            verdict,
            this_update=now,
            next_update=next_update,
            revoked_at=revoked_at,
        )
        return Artifact(content=content, this_update=now, next_update=next_update)


def try_later() -> Artifact:
    return _unsuccessful(ocsp.OCSPResponseStatus.TRY_LATER)


def _unsuccessful(status: ocsp.OCSPResponseStatus) -> Artifact:
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(status)
    return Artifact(
        content=response.public_bytes(serialization.Encoding.DER),
        this_update=None,
        next_update=None,
    )
