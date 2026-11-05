"""Enrollment: a device's way in, and the administrator's half of it.

Split out of api.py by audience (muster#218). `POST /v1/enroll/requests` and
`GET /v1/enroll/requests/{id}/identity` are open, because a device that has not
enrolled has no credential yet; minting codes, listing the queue and vouching
are administrator-only. Same path, different audience, which is why
authorization is a dependency on each route rather than a prefix rule.

Renewal is NOT here. `POST /v1/enroll/renew` is a proven device asking over the
identity it holds, so it lives in device_channel.py with every other route that
calls `_proven_device`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from fastapi import Body, FastAPI, HTTPException, Response

from muster import kith as kith_store
from muster import telemetry
from muster.ca import Identity, Untrusted
from muster.device_channel import _spki_der
from muster.enroll import (
    DEFAULT_CODE_TTL_S,
    Outcome,
    Refused,
    Shape,
    clean_device_name,
    key_id,
)

if TYPE_CHECKING:
    from muster.api import State


# Which refusal maps to which status. Written out rather than defaulted, because
# the difference matters to a device deciding whether to retry: 429 and 410 are
# both "no" and only one of them is worth trying again after.
_STATUS = {
    Outcome.NO_SUCH_CODE: 403,
    Outcome.CODE_EXPIRED: 410,
    Outcome.CODE_USED: 409,
    Outcome.TOO_MANY_ATTEMPTS: 429,
    Outcome.NOT_PENDING: 404,
    Outcome.FINGERPRINT_MISMATCH: 409,
}

# WHICH REFUSALS A DEVICE CAN EVER SEE. 409 is deliberately reused - CODE_USED
# on the device's present endpoint, FINGERPRINT_MISMATCH on the administrator's
# vouch endpoint - and that is fine because they are different endpoints with
# different audiences. It is NOT fine to leave that implicit: the agent maps
# status codes back to behavior, and a reader comparing the two maps sees one
# code claiming two meanings with nothing saying why.
#
# Named here rather than inferred, because the cross-language check
# (tools/check_status_map.py) has to know which half of this map the agent is
# supposed to implement. It found this ambiguity on its first run.
DEVICE_FACING = frozenset(
    {
        Outcome.NO_SUCH_CODE,
        Outcome.CODE_EXPIRED,
        Outcome.CODE_USED,
        Outcome.TOO_MANY_ATTEMPTS,
    }
)


@dataclass
class Issued:
    """A vouched device's identity, held until it collects."""

    certificate_pem: bytes
    ca_pem: bytes
    not_after: str
    renew_after: str


# THERE IS NO PAIRING QR ANY MORE, and its absence is deliberate rather than an
# omission to fix. api.py used to render the pairing code as a QR "so a
# freshly provisioned device needs neither typed at it", and nothing on a device
# could ever read it: the agent declares no CAMERA permission, contains no
# scanner, and EnrollActivity has only a MAIN/LAUNCHER intent-filter. A QR on a
# screen that nothing can scan is worse than no QR, because it teaches an
# operator to hold a phone up to a monitor and wait for something that will
# never happen (muster#47).
#
# The QR that IS real is the PROVISIONING one in routes_agent.py, which
# Android's setup wizard reads on a wiped device - and muster#48 put the pairing
# code into that payload's admin extras, which is where a scan can actually
# reach a device. So a typed code is now the path for a phone somebody is
# holding: one provisioned earlier, or re-enrolling after its identity lapsed.


# THE SHAPE OF A REQUEST ID, checked before one reaches the store. They are
# minted by `secrets.token_urlsafe`, so this alphabet is the whole of what one
# can contain, and anything else names no request and need not be asked after.
# Asking the store anyway is what let a NUL byte in this open route's path
# become a refused statement, which the breaker then counted as an outage.
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}\Z")


def _issue(state: "State", request_id: str, pending) -> dict:
    """Sign a vouched-for request and write the device into the kith.

    ONE COPY, CALLED FROM TWO PLACES, and that is the reason it exists. A typed
    request reaches here when an administrator clicks vouch; a scanned one
    reaches here the moment the device presents, because minting its code was
    the authorization (enroll.py's module docstring). Two copies of this would
    be two chances to forget the kith write, and the QR path - the one nobody
    watches - would be the copy that forgot.
    """
    try:
        with state.telemetry.timed("ca.issue.duration"):
            identity = state.authority.issue(pending.csr_der, pending.device_name)
    except Untrusted as bad:
        # The CSR was already in the queue when this failed, so the operator
        # vouched for something unsignable. Say so plainly rather than
        # returning a 500 that reads like the server broke.
        telemetry.event(
            "vouched for an unsignable CSR",
            device_name=pending.device_name, error=str(bad),
        )
        state.telemetry.count("ca.issue.refused", tags=["reason:untrusted-csr"])
        raise HTTPException(status_code=422, detail=str(bad)) from bad

    state.issued[request_id] = Issued(
        certificate_pem=identity.certificate_pem,
        ca_pem=state.authority.certificate_pem,
        not_after=identity.not_after.isoformat(),
        renew_after=identity.renew_after().isoformat(),
    )
    # WRITTEN DOWN AFTER THE CERTIFICATE EXISTS, AND IT CANNOT FAIL THIS
    # REQUEST. The device is in the kith because it holds a certificate, not
    # because a row was written (CONTEXT.md); the row is what muster
    # remembers. See kith.py: a store outage defers this and issuance
    # carries on, because the alternative is that devices lapse - and lapse
    # means a human, a pairing code and, on a Device Owner phone, a wipe.
    now = state.kith.now()
    state.kith.issued(
        kith_store.Device(
            key_id=key_id(pending.public_key_der),
            fingerprint=pending.fingerprint,
            name=pending.device_name,
            first_seen=now,
            last_seen=now,
            # From the pairing code this device enrolled with (muster#70). The
            # moment a role stops being an intention and becomes a fact about a
            # device.
            role=pending.role,
        ),
        kith_store.Certificate(
            # Uppercase hex, matching `openssl x509 -serial` and what
            # docs/state-of-play.md quotes off a handset.
            serial=f"{identity.serial:X}",
            request_id=request_id,
            not_before=identity.not_before,
            not_after=identity.not_after,
            issued_at=now,
            certificate_pem=identity.certificate_pem.decode(),
        ),
    )
    telemetry.event(
        "certificate issued",
        device_name=pending.device_name,
        serial=identity.serial,
        not_after=identity.not_after.isoformat(),
    )
    state.telemetry.count("ca.issued")
    return {"device_name": pending.device_name, "serial": identity.serial}


def register(app: FastAPI, state: State, admin) -> None:
    """The administrator's enrollment routes, then the device's."""

    @app.post("/v1/enroll/codes", status_code=201, dependencies=[admin])
    def mint_code(ttl_s: float = Body(default=DEFAULT_CODE_TTL_S, embed=True)):
        """A TYPED pairing code, for the path where somebody holds the phone.

        This endpoint mints only that shape and takes no parameter to change it.
        A scanned code has to travel inside a provisioning QR to be worth
        anything - the whole point is that nothing reads it aloud - so handing
        one back as JSON would produce a 192-character string for an operator to
        type, which is the exact opposite of both paths. /v1/provision/qr.svg is
        where the other shape is minted, and it never returns it as text either.
        """
        code = state.enrollment.mint(ttl_s=ttl_s, shape=Shape.TYPED)
        telemetry.event("pairing code minted", ttl_s=ttl_s, shape=Shape.TYPED.value)
        state.telemetry.count(
            "enroll.code.minted", tags=[f"shape:{Shape.TYPED.value}"]
        )
        return {"code": code, "ttl_s": ttl_s}

    @app.get("/v1/enroll/requests", dependencies=[admin])
    def list_pending():
        """What is waiting to be vouched for, and which kind of vouch each is.

        `shape` is here so a console can stop drawing the two the same way. On a
        TYPED request the fingerprint beside it is also on a screen in the
        operator's hand and the comparison is real. On a SCANNED one there is no
        second copy of it anywhere, and an operator reading the fingerprint off
        the page they are clicking has compared nothing - so a console that does
        not say which is which is teaching a check that is sometimes theatre.
        See enroll.py's module docstring for what holds a scanned request up
        instead.
        """
        return {
            "pending": [
                {
                    "request_id": p.request_id,
                    "device_name": p.device_name,
                    "fingerprint": p.fingerprint,
                    "presented_at": p.presented_at,
                    "shape": p.shape.value,
                }
                for p in state.enrollment.pending.values()
            ]
        }

    @app.post("/v1/enroll/requests/{request_id}/vouch", dependencies=[admin])
    def vouch(request_id: str, fingerprint: str = Body(..., embed=True)):
        """Approve one request, by the fingerprint on the device's own screen.

        `fingerprint` is required by the schema, so there is no route through
        this endpoint that approves without comparing. That is deliberate: a
        vouch on the id alone confirms only "an enrollment is pending", which is
        exactly what a racer who guessed the pairing code has arranged.
        """
        try:
            pending = state.enrollment.vouch(request_id, fingerprint)
        except Refused as refused:
            # THE tag that matters. A fingerprint mismatch here is somebody
            # enrolling against the operator's code while they watch, and it
            # must never be averaged into a total with "the code expired".
            telemetry.event(
                "vouch refused", reason=refused.outcome.value, request_id=request_id
            )
            state.telemetry.count(
                "enroll.vouch.refused", tags=[f"reason:{refused.outcome.value}"]
            )
            raise HTTPException(
                status_code=_STATUS[refused.outcome], detail=str(refused)
            ) from refused

        return _issue(state, request_id, pending)

    # ---- device ----------------------------------------------------------

    @app.post("/v1/enroll/requests", status_code=202)
    def present(
        code: str = Body(..., embed=True),
        csr_pem: str = Body(..., embed=True),
        device_name: str = Body(..., embed=True),
    ):
        """A device offers its CSR and a pairing code. Grants nothing."""
        from cryptography import x509

        # Checked BEFORE anything is parsed or queued. This name becomes a
        # certificate's Common Name and a row in the kith, and both have opinions
        # about what a string may contain - see enroll.clean_device_name.
        try:
            device_name = clean_device_name(device_name)
        except ValueError as unusable:
            raise HTTPException(status_code=400, detail=str(unusable)) from unusable

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"unreadable CSR: {exc}") from exc

        public_der = _spki_der(csr.public_key())
        try:
            pending = state.enrollment.present(
                code,
                csr.public_bytes(serialization.Encoding.DER),
                public_der,
                device_name,
            )
        except Refused as refused:
            # No code, not even truncated - see telemetry's module docstring.
            #
            # SHAPE ALONGSIDE REASON, NOT INSTEAD OF IT. "The QR path is
            # failing" and "somebody is guessing six digits" are different
            # incidents with different responses, and before this tag they were
            # one number: a QR whose code expired before a phone finished
            # installing looked exactly like an operator mistyping. `unknown` is
            # the honest answer for NO_SUCH_CODE - there is no minted record to
            # read a shape off, and classifying by the FORM of what was sent
            # would let an attacker choose which bucket they land in.
            shape = refused.shape.value if refused.shape else "unknown"
            telemetry.event(
                "presentation refused",
                reason=refused.outcome.value,
                shape=shape,
                device_name=device_name,
            )
            state.telemetry.count(
                "enroll.present.refused",
                tags=[f"reason:{refused.outcome.value}", f"shape:{shape}"],
            )
            raise HTTPException(
                status_code=_STATUS[refused.outcome], detail=str(refused)
            ) from refused

        # The fingerprint goes back to the DEVICE so it can show it on its own
        # screen. That display is half of the comparison the vouch depends on -
        # without it the administrator has nothing to check the console against.
        telemetry.event(
            "device presented",
            request_id=pending.request_id,
            device_name=device_name,
            fingerprint=pending.fingerprint,
            shape=pending.shape.value,
        )
        state.telemetry.count(
            "enroll.present.accepted", tags=[f"shape:{pending.shape.value}"]
        )

        # THE QR WAS THE VOUCH. A scanned code was minted by an authenticated
        # administrator asking for one device to be enrolled, so there is nobody
        # left to ask and nothing to wait for - see enroll.py's module
        # docstring for why the second click compared a value against itself.
        #
        # THE DEVICE NEEDS NO CHANGE FOR THIS. It already presents and then
        # polls /v1/enroll/requests/{id}/identity until a certificate appears;
        # issuing here just means the first poll is the one that succeeds. A
        # handset provisioned by QR now finishes enrolling inside its own setup
        # run, with nobody touching a console.
        if pending.self_vouched:
            try:
                _issue(state, pending.request_id, pending)
            except HTTPException:
                # An unsignable CSR. The code is spent and the request was never
                # queued, so there is nothing to approve later and the honest
                # answer is to say so now rather than leave a phone polling for
                # a certificate that is never coming.
                telemetry.event(
                    "self-vouched request could not be signed",
                    request_id=pending.request_id, device_name=device_name,
                )
                raise
            telemetry.event(
                "certificate issued without a second approval",
                request_id=pending.request_id,
                device_name=device_name,
                shape=pending.shape.value,
            )
            state.telemetry.count("enroll.issued.self_vouched")

        return {
            "request_id": pending.request_id,
            "fingerprint": pending.fingerprint,
        }

    @app.get("/v1/enroll/requests/{request_id}/identity")
    def collect(request_id: str, response: Response):
        issued = state.issued.get(request_id)
        if issued is not None:
            # Handed over once. A certificate left collectable forever is a
            # credential sitting on an endpoint whose only protection is a
            # request id that has, by this point, travelled.
            #
            # The store is marked collected on the same deferred path as every
            # other write, so a store outage plus a restart can leave a
            # certificate collectable a second time. That is deliberately
            # accepted rather than made transactional: a certificate is public
            # and its private key never left the device, so a second collection
            # hands over bytes and no capability. Making it exact would mean
            # blocking the handover on a database write, which is the one thing
            # this whole module refuses to do.
            del state.issued[request_id]
            state.kith.collected(request_id)
            return {
                "certificate_pem": issued.certificate_pem.decode(),
                "ca_pem": issued.ca_pem.decode(),
                "not_after": issued.not_after,
                "renew_after": issued.renew_after,
            }

        if request_id in state.enrollment.pending:
            response.status_code = 202
            return {"status": "waiting for an administrator to vouch"}

        # Not in THIS pod's memory. It may have been signed by a pod that has
        # since been replaced, which before the kith was written down meant the
        # device lost a certificate that already existed and had to enroll again
        # with a human present.
        if not _REQUEST_ID.match(request_id):
            raise HTTPException(status_code=404, detail="no such request")
        try:
            held = state.kith.awaiting_collection(request_id)
        except kith_store.Unreachable as unreachable:
            # 503 AND NOT 404, AND THE DIFFERENCE IS A RE-ENROLLMENT. The agent
            # reads 404 as Gone and stops polling for good (EnrollmentClient.kt);
            # it reads anything it does not recognize as retryable and backs off.
            # Answering 404 because the DATABASE is unreachable would tell a
            # device to abandon a certificate muster really did sign for it.
            state.telemetry.count("enroll.collect.unreachable")
            raise HTTPException(
                status_code=503,
                detail="the kith store is unreachable; this request may exist. "
                       "Retry - do not start a new enrollment.",
            ) from unreachable

        if held is None:
            raise HTTPException(status_code=404, detail="no such request")

        state.kith.collected(request_id)
        state.telemetry.count("enroll.collect.from_store")
        telemetry.event("collected a certificate from the kith store", request_id=request_id)
        # renew_after recomputed by ca.Identity rather than stored, so the value
        # a device gets after a restart is produced by the same code as the one
        # it would have got before. A second copy of that arithmetic here is a
        # second definition of when a device starts renewing.
        identity = Identity(
            certificate_pem=held.certificate_pem.encode(),
            not_before=held.not_before,
            not_after=held.not_after,
            serial=int(held.serial, 16),
        )
        return {
            "certificate_pem": held.certificate_pem,
            "ca_pem": state.authority.certificate_pem.decode(),
            "not_after": held.not_after.isoformat(),
            "renew_after": identity.renew_after().isoformat(),
        }
