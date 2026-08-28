"""The HTTP surface: three audiences, one of them the open internet.

WHO CAN REACH WHAT, because this is the part that gets it wrong:

    device, unauthenticated    POST /v1/enroll/requests
                               GET  /v1/enroll/requests/{id}/identity
                               POST /v1/auth/challenge
                               POST /v1/auth/verify
                               GET  /agent.apk, /agent.json
    device, proven             POST /v1/device/config
    administrator, signed in   POST /v1/enroll/codes
                               GET  /v1/enroll/requests
                               POST /v1/enroll/requests/{id}/vouch
                               GET  /v1/provision/qr.svg
                               POST /v1/provision/qr
                               GET  /v1/kith
                               GET  /v1/kith/{key_id}

THE MIDDLE AUDIENCE IS A DEVICE THAT HAS ENROLLED (muster#46), and it is the one
that has to be got right next, because everything a device will ever say to
muster goes through it: configuration down, diagnostics up (muster#27),
inventory up (muster#42). Authenticated by the CERTIFICATE and nothing else -
`_proven_device` below is the whole of it, shared with /v1/auth/verify so there
is one scheme rather than two. There is deliberately no device token: a bearer
credential is a thing that can be copied off a device, which is precisely what
the key in the Android Keystore cannot be. It is not behind the administrator
session either, because nothing about a phone in a cupboard involves a person.

Read the first line against the eighth. `POST /v1/enroll/requests` is a
device's way in; `GET /v1/enroll/requests` is the administrator's pending list.
Same path, different audience, so no rule that reads a path prefix can tell them
apart - which is why authorization is a dependency on each route and
`test_api.py` asserts that every route in the app is deliberately on one side of
this table or the other.

The device endpoints are unauthenticated **because a device that has not
enrolled has no credential yet** - that is the whole problem enrollment solves.
They are safe to expose only because presenting grants nothing: it buys a place
in a queue and a fingerprint for a human to look at. Nothing about administrator
sign-in may reach them: a device with no credential that is asked for one is a
device that can never enroll.

THE APP REFUSES TO START WITH NO WAY IN. Administrator sign-in
(muster/administrator.py) must be configured, and the allowlist of subjects
may not be empty. Not a warning, not a generated default. An admin surface
that comes up open because a variable was unset is the failure this whole
design exists to prevent, and it fails at the worst moment - when it is first
exposed and nobody is looking yet.

TWO ENDPOINTS MINT PAIRING CODES, AND THEY MINT DIFFERENT ONES.
`POST /v1/enroll/codes` returns six digits for a person to type;
`GET /v1/provision/qr.svg` puts 192 bits into a QR that a wiped phone reads off
a monitor, and never returns it as text. The shapes are not interchangeable and
the reason is a security one - see enroll.py's module docstring and CONTEXT.md.
The short version: with nobody holding the handset there is no second copy of
the fingerprint to compare, so the code has to be the thing that cannot be
guessed.

WHY `request_id` IS ENOUGH FOR THE DEVICE TO POLL WITH. It is 96 bits from
`secrets.token_urlsafe`, returned only to the presenter, and it identifies one
pending request. It is a bearer secret with a short life and no authority beyond
"tell me whether I have been vouched for yet". Guessing one gets an attacker a
certificate ONLY if an administrator has already vouched for that exact
fingerprint, which means they were looking at the attacker's device.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import os
import pathlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse

from muster.ca import Authority, Identity, Untrusted
from muster.proof import Proofs, Verdict
from muster import administrator, console, policy, provisioning
from muster import assets as asset_store
from muster import kith as kith_store
from muster.enroll import (
    DEFAULT_CODE_TTL_S,
    Enrollment,
    Outcome,
    Refused,
    Shape,
    clean_device_name,
    key_id,
)
from muster import telemetry

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
# omission to fix. This module used to render the pairing code as a QR "so a
# freshly provisioned device needs neither typed at it", and nothing on a device
# could ever read it: the agent declares no CAMERA permission, contains no
# scanner, and EnrollActivity has only a MAIN/LAUNCHER intent-filter. A QR on a
# screen that nothing can scan is worse than no QR, because it teaches an
# operator to hold a phone up to a monitor and wait for something that will
# never happen (muster#47).
#
# The QR that IS real is the PROVISIONING one below, which Android's setup
# wizard reads on a wiped device - and muster#48 put the pairing code into that
# payload's admin extras, which is where a scan can actually reach a device. So
# a typed code is now the path for a phone somebody is holding: one provisioned
# earlier, or re-enrolling after its identity lapsed.


def _spki_der(public_key) -> bytes:
    """A public key in the one encoding everything here fingerprints.

    ONE function, because the fingerprint the administrator vouches against and
    the key the kith is keyed on have to be digests of exactly the same bytes.
    Two call sites each spelling out their own encoding is two chances for a
    device to be recorded under an identity the console never shows.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _key_id_of(certificate_pem: bytes) -> str:
    """Which device in the kith a certificate belongs to.

    Re-parses a certificate that proof.verify has already parsed, which is a
    few microseconds spent to avoid widening `verify`'s return type from a
    verdict into a verdict-and-a-certificate. The verdict is the interesting
    thing about that function and it should stay the whole of it.
    """
    from cryptography import x509

    return key_id(_spki_der(x509.load_pem_x509_certificate(certificate_pem).public_key()))


@dataclass
class State:
    enrollment: Enrollment
    authority: Authority
    # How an administrator signs in. None means no provider is configured, and
    # the console says so plainly rather than showing a button that cannot work.
    sign_in: administrator.SignIn | None = None
    # Off only for a laptop on plain http. A session cookie without Secure is
    # one that travels on the first request that is not TLS.
    cookie_secure: bool = True
    proofs: Proofs | None = None
    base_url: str = ""
    # Where the agent APK sits on disk. Empty means none is published, and the
    # endpoints below say so plainly rather than 404ing like a typo.
    agent_apk: str = ""
    issued: dict = field(default_factory=dict)
    # The record of the kith. Defaults to an in-memory one for the same reason
    # telemetry defaults to a disabled emitter: every call site can then write
    # to it unconditionally, and there is no `if state.kith:` to forget on the
    # one path nobody exercises. See muster/kith.py for why writing to it can
    # never fail a request.
    kith: kith_store.Kith = field(default_factory=kith_store.Kith)
    # What a device is told to be, once it has proved who it is. Defaults to a
    # source that serves nothing, for the same reason the kith defaults to an
    # in-memory record: an unconditional call site cannot forget a guard. A
    # muster with no policy directory answers "nothing is configured", which
    # every steward on the device already knows how to act on.
    policies: policy.Policies = field(default_factory=policy.Policies)
    # Operator files a proven device may fetch: a wallpaper today, an APK when
    # muster#42 lands. Defaults to a store that holds nothing, for the same
    # reason `policies` defaults to one that serves nothing - an unconditional
    # call site cannot forget a guard.
    assets: asset_store.Assets = field(default_factory=asset_store.Assets)
    # Defaults to a DISABLED emitter rather than None, so every call site can
    # emit unconditionally. A `if state.telemetry:` guard on each of a dozen
    # sites is a dozen chances to forget one, and the one that gets forgotten
    # is always the failure path nobody exercises.
    telemetry: telemetry.Telemetry = field(default_factory=telemetry.Telemetry)



def _role_or_400(role: str) -> str:
    """A role, or a 400 saying what one may be.

    THE SAME PATTERN AS EVERY OTHER DOOR A ROLE COMES THROUGH. `enroll.mint`
    checks at the QR, `policy.for_device` checks before it becomes half a
    filename, and this checks before it becomes a row. Without it a typo is a
    500 with a traceback in the log of the process that holds the CA, for what
    is an operator mistyping into a text box.
    """
    if not role:
        return ""
    if not enroll_role_pattern().match(role):
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{role}' is not a role: lowercase letters, digits and dashes, "
                "starting with a letter, at most 31 characters. A role becomes "
                "half of a policy file name and a Kubernetes Secret key."
            ),
        )
    return role


def enroll_role_pattern():
    """The one pattern, imported rather than restated.

    `enroll` and `policy` each keep their own copy and a test pins them equal -
    that is the house convention for a boundary check. A THIRD copy here would
    be a third thing to keep in step, and this module is not a boundary of the
    same kind: it is the console's door, and the console is not a device.
    """
    from muster.enroll import _ROLE

    return _ROLE


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


def _require_admin(state: State):
    """The one place a route says "a person has to be behind this".

    Who the caller is was settled before this ran, by AdministratorMiddleware -
    a signed-in session, which stamps an actor on the request. This function
    only decides whether that is enough, which is why it can be four lines and
    why adding a second way to sign in does not touch any route.
    """

    # async, so it runs on the event loop rather than costing a worker-thread
    # hop on every administrator request to read one attribute. A sync
    # dependency is handed to a threadpool whether or not it does any I/O.
    async def dependency(request: Request) -> console.Actor:
        actor: console.Actor = getattr(request.state, "actor", console.ANONYMOUS)
        if not actor.signed_in:
            raise HTTPException(
                status_code=401, detail="administrator sign-in required"
            )
        return actor

    return dependency


# Refusals a device can act on. 401 for a certificate we did not issue is
# deliberate rather than 403: the device is not forbidden, it is unrecognised,
# and the fix is to enroll. 409 for expired says renew.
_PROOF_STATUS = {
    Verdict.NO_SUCH_NONCE: 400,
    Verdict.NONCE_EXPIRED: 408,
    Verdict.NONCE_USED: 409,
    Verdict.BAD_SIGNATURE: 401,
    Verdict.CERT_EXPIRED: 409,
    Verdict.CERT_NOT_OURS: 401,
}


def _proven_device(
    state: State, nonce: str, signature_b64: str, certificate_pem: str
) -> str:
    """Which device sent this, or an HTTPException saying why it is nobody.

    THE ONE PLACE A DEVICE IS AUTHENTICATED, and it stays the one place. Every
    route a device will ever reach with something to say - configuration down
    (muster#46), diagnostics up (muster#27), inventory up (muster#42) - calls
    this and gets back a key_id. A second scheme invented for the second of
    those would be a second chance to get it wrong, and the one that got it
    wrong would be the one nobody tested against a handset.

    Returns the key_id, which is the device's identity across renewals
    (enroll.key_id) and therefore the right thing to key policy and reports on.
    A certificate serial changes every ninety days; the key does not.
    """
    # NO-STORE ON THE REFUSALS TOO, not only on the answer. FastAPI merges an
    # injected Response's headers on a normal return and NOT when the endpoint
    # raises, so a route that sets the header in its body has set it on exactly
    # the path that did not need it most. A cached 401 is a device that cannot
    # be configured again until the entry expires, on a phone nobody is holding.
    uncached = {"Cache-Control": "no-store"}
    if state.proofs is None:
        raise HTTPException(
            status_code=503, detail="proofs are not configured", headers=uncached
        )
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"signature is not base64: {exc}", headers=uncached
        ) from exc

    verdict = state.proofs.verify(nonce, signature, certificate_pem.encode())
    if verdict is not Verdict.OK:
        # Every failing verdict is its own operational story: a replayed nonce
        # is an attack, an expired certificate is a device that stopped
        # renewing, and a total would hide both behind each other.
        telemetry.event("proof refused", verdict=verdict.value)
        state.telemetry.count("proof.refused", tags=[f"verdict:{verdict.value}"])
        raise HTTPException(
            status_code=_PROOF_STATUS[verdict], detail=verdict.value, headers=uncached
        )

    state.telemetry.count("proof.verified", tags=["verdict:ok"])
    # LAST SEEN, and this is the only place that can honestly set it. A proof is
    # the one moment muster knows a specific device was reachable and still
    # holds its key - an unauthenticated request proves only that somebody sent
    # bytes. Recording it anywhere else would make "last seen" a column that
    # means nothing.
    #
    # Only after Verdict.OK, so a failed proof cannot be used to keep a device
    # looking alive; and deferred like every other write, so a store outage
    # cannot turn a good proof into a 500.
    proven = _key_id_of(certificate_pem.encode())
    state.kith.seen(proven)
    return proven


def create_app(state: State) -> FastAPI:
    # NO INTERACTIVE API BROWSER, and this is a security decision rather than a
    # tidying one. FastAPI's /docs and /redoc pages load their JavaScript from a
    # public CDN - a third-party script, on the SAME ORIGIN as the console.
    # Same-origin is the whole problem: that script can call every administrator
    # endpoint with the operator's session cookie attached, so a substituted
    # bundle vouches for a device. The console's own policy header cannot help,
    # because a policy applies to the response it arrives on. /openapi.json
    # stays: it describes the API and runs nothing.
    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        """Start the thing that retries deferred kith writes, and stop it.

        WITHOUT THIS THE BACKLOG IS DECORATION. Deferred writes are otherwise
        replayed only by the next enrollment, proof or console load, and muster
        is quiet by design - devices renew every ninety days. A store that comes
        back an hour after it went away would keep the rows in memory until
        something happened to knock on it, and a pod restarted first loses them.
        """
        state.kith.start_flushing()
        try:
            yield
        finally:
            state.kith.stop_flushing()

    app = FastAPI(
        title="muster", version="0.1.0", lifespan=lifespan,
        docs_url=None, redoc_url=None,
    )
    # Before any route is registered, and in an order this asserts: who is
    # acting has to be established before anything writes down what they did.
    console.install_middleware(app, state)
    admin = Depends(_require_admin(state))

    # ---- administrator ---------------------------------------------------

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

    _register_proof_routes(app, state)
    _register_device_routes(app, state)
    _register_agent_routes(app, state, admin)
    _register_kith_routes(app, state, admin)
    console.register_console_routes(app, state)

    @app.get("/livez")
    def livez():
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz():
        """Ready means "can this pod do its job", and its job is issuing.

        THE KITH STORE BEING DOWN DOES NOT MAKE THIS POD UNREADY, and that is
        the single most important line in this file to get right. Reporting
        unready would have Kubernetes pull the pod out of the Service, which
        stops enrollment and renewal for every device - the exact outcome the
        whole deferred-write design in kith.py exists to prevent, arrived at
        through the health check instead of through the code path. So the store
        is REPORTED here and never gates the verdict, and `Kith.status()` does
        no I/O so a probe every ten seconds cannot become load on a sick
        database.
        """
        # The policy directory is REPORTED and never gates the verdict either,
        # and for a sharper reason than the kith: a volume that did not mount
        # looks exactly like a fleet nobody has configured yet, because both
        # answer every device "nothing is configured" - and the device acts on
        # that by leaving itself alone. This line is what tells them apart
        # without an exec into the pod that holds the CA.
        return {
            "status": "ok",
            "ca": state.authority.certificate_pem.decode()[:32],
            "kith": state.kith.status(),
            "policy": state.policies.status(),
            "assets": state.assets.status(),
        }

    return app



def _register_proof_routes(app: FastAPI, state: State) -> None:
    """Proof of possession.

    Split out of create_app because that function grew past the complexity cap
    as endpoints accumulated. Route registration is naturally additive, and one
    function that mounts everything gets steadily harder to read for no benefit
    - the groups here are the same audiences the module docstring already names.
    """
    # ---- proof of possession (muster#1) ----------------------------------

    @app.post("/v1/auth/challenge", status_code=201)
    def challenge():
        """A nonce for an enrolled device to sign. Open by necessity.

        Unauthenticated because the thing being authenticated is the ANSWER, not
        the request. Handing out a nonce grants nothing: it is single use, it
        expires, and it is worthless without a signature from a key muster
        issued a certificate for.
        """
        if state.proofs is None:
            raise HTTPException(status_code=503, detail="proofs are not configured")
        # SWEPT HERE, BECAUSE THERE IS NOWHERE ELSE. `Proofs.sweep` existed with
        # tests and no caller: an unanswered challenge stayed in memory forever,
        # so anyone who could reach this open endpoint could grow the process
        # that holds the CA without limit, one request at a time. That was
        # survivable while nothing on a device called it on a schedule; muster#46
        # makes it a per-boot fleet path, which is the point at which a written,
        # tested, unreachable mechanism has to be wired up.
        #
        # On the way IN rather than on a timer: no background task to start and
        # stop, and the work is proportional to the load that caused it. It is a
        # walk of a dict whose size is bounded by the number of challenges issued
        # in the last two minutes.
        state.proofs.sweep()
        issued = state.proofs.challenge()
        return {"nonce": issued.nonce, "ttl_s": issued.ttl_s}

    @app.post("/v1/auth/verify")
    def verify_proof(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
    ):
        """Check a signed nonce against the certificate muster issued.

        Every refusal is distinct, and that is deliberate: 'expired certificate'
        means renew, 'not ours' means enroll, and 'bad signature' means something
        is wrong in a way neither of those fixes. `_proven_device` raises them.

        Kept as its own endpoint now that the proof travels with real requests
        too: this is how a device asks "do you still know me?" without asking
        for anything, which is what a status screen and a health check want.
        """
        _proven_device(state, nonce, signature_b64, certificate_pem)
        return {"verdict": Verdict.OK.value}


def _register_device_routes(app: FastAPI, state: State) -> None:
    """What an enrolled device asks muster for, over the identity it holds.

    THE THIRD AUDIENCE in this module's docstring, and the one everything a
    device will ever do arrives through. Configuration comes down here today
    (muster#46); diagnostics (muster#27) and inventory (muster#42) go up the
    same way, as sibling POSTs that call `_proven_device` and then act on the
    key_id it returns. The shape is fixed here on purpose so those two are a
    route each rather than an authentication design each.
    """

    @app.post("/v1/device/config")
    def device_config(
        response: Response,
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
    ):
        """The configuration for the device that signed this nonce.

        A POST FOR SOMETHING THAT READS. The proof has to travel with the
        request, and in a GET it would travel in the query string - which is
        the one part of a request that lands in every access log, every proxy,
        and Cloudflare's own. A signature and a certificate are not secret, but
        a URL that carries them is a URL somebody will paste. The nonce is
        single use, so a cached GET would be worse than useless besides.

        WHAT THE DEVICE DOES WITH THIS is the other half of the design, and it
        lives in the agent (ConfigurationPolicy.kt): a file absent from a
        SUCCESSFUL answer is removed from the device, and a fetch that did not
        succeed changes nothing at all. That is why an unreadable file below is
        a 503 rather than a shorter list of files - a half-answer here is
        indistinguishable from an operator having deleted a policy, and the
        device would take a restriction back off because a byte went bad.
        """
        # NEVER CACHED, AND THIS ONE IS PER-DEVICE. /agent.apk carries the same
        # header because Cloudflare caches by extension and served a stale APK
        # to a handset; the failure available here is worse in kind, because
        # this response holds ONE device's write tokens and every device asks
        # the same URL. Nothing is supposed to cache a POST, which is exactly
        # the sort of thing that holds until an intermediary decides otherwise.
        response.headers["Cache-Control"] = "no-store"
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        # WHAT THIS DEVICE IS FOR, read from the kith and NEVER sent by the
        # device (muster#70). A role selects which policy scope is served -
        # including `app-config`, which carries write tokens - so a device that
        # could name its own role could ask for another role's credentials.
        #
        # A STORE THAT IS DOWN MEANS NO ROLE, NOT NO CONFIGURATION. `member`
        # answers None when the kith cannot be read, and falling back to the
        # kith scope keeps a device configured through a database outage rather
        # than stripping it - the same argument kith.py makes for why writing to
        # the store can never fail a request.
        member = state.kith.member(proven)
        role = member.device.role if member is not None else ""
        try:
            configuration = state.policies.for_device(proven, role=role)
        except (policy.Unreadable, policy.NoSource) as cannot_say:
            # 503 AND NOT AN EMPTY ANSWER, and the difference is every managed
            # file on every device in the estate. The agent removes a file that
            # a SUCCESSFUL fetch did not mention, so "here is nothing" is an
            # authoritative instruction to withdraw - and a deleted secret
            # volume, an unmountable path and a file with a bad byte in it would
            # all have produced exactly that. muster refuses to answer rather
            # than answering something it cannot support.
            reason = (
                "no-source" if isinstance(cannot_say, policy.NoSource) else "unreadable"
            )
            state.telemetry.count("device.config.refused", tags=[f"reason:{reason}"])
            telemetry.event(
                "muster cannot say what a device should be",
                key_id=proven, reason=reason, error=str(cannot_say),
            )
            raise HTTPException(
                status_code=503,
                detail=f"{cannot_say} Retry - this device's existing "
                       "configuration is unaffected and stays in force.",
                headers={"Cache-Control": "no-store"},
            ) from cannot_say

        state.telemetry.count("device.config.served")
        # NAMES AND THE REVISION, NEVER THE CONTENT. `app-config` carries write
        # tokens, and `telemetry.event` drops a field called `files` outright
        # for exactly that reason - which is why this passes `file_names`, a
        # field whose name says what is in it.
        telemetry.event(
            "device configuration served",
            key_id=proven,
            revision=configuration.revision,
            file_names=sorted(configuration.files),
        )
        return {
            "key_id": configuration.key_id,
            "revision": configuration.revision,
            "files": configuration.files,
        }


# What /agent.json has already worked out, keyed by the bytes it describes.
# Module level rather than per-app so a test that builds several apps over one
# APK does not re-hash it each time; the key includes the path, so two apps
# serving different files cannot read each other's answer.
_APK_DESCRIPTIONS: dict[tuple[str, int, int], dict] = {}


def _register_kith_routes(app: FastAPI, state: State, admin) -> None:
    """Who muster has issued to. The first endpoints that can answer at all.

    503 RATHER THAN AN EMPTY LIST when the store cannot be read. A console
    rendering "no devices" over an unreachable database is a lie that reads
    exactly like a fleet that has vanished, and the operator's next move is to
    go looking for devices rather than for a database.
    """

    def _unreachable(exc: kith_store.Unreachable) -> HTTPException:
        state.telemetry.count("kith.read.refused")
        return HTTPException(
            status_code=503,
            detail=f"{exc}. Devices already issued to are unaffected: a "
                   "certificate is what makes a device part of the kith.",
        )

    @app.post("/v1/device/asset")
    def device_asset(
        response: Response,
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
        # DEFAULTED RATHER THAN REQUIRED, so that PROOF IS ALWAYS CHECKED
        # FIRST. A required field makes FastAPI answer 422 before the endpoint
        # body runs, which means a caller with no identity at all gets a
        # different answer for a malformed body than for a bad certificate -
        # and every other device route answers such a caller identically.
        # Validation of an unrelated field must never short-circuit
        # authentication. An empty name is then just a name no asset has.
        name: str = Body("", embed=True),
    ):
        """One operator file, for the device that signed this nonce.

        WHY A DEVICE MAY FETCH BYTES AT ALL (muster#45). Everything muster could
        apply used to travel over a cable, and a phone provisioned by QR is on
        somebody else's network. The wallpaper is the first asset through here;
        an APK is the same route with a bigger file behind it (muster#42).

        A POST, AND A SIBLING OF /v1/device/config ON PURPOSE. The proof has to
        travel with the request, and in a GET it would travel in the query
        string - the one part of a request that lands in every access log and
        every proxy. `_proven_device` stays the one place a device is
        authenticated; this route adds a name to that exchange and nothing else.

        THE NAME IS THE ONLY CALLER-SUPPLIED INPUT, and it is turned into a
        path on a pod that holds the CA. Proving you are a device buys you an
        asset, not a file: `assets.Assets.fetch` refuses anything that is not a
        plain name before it joins anything, and this route does not widen that
        by reporting which kind of refusal it was.

        WHAT THE DEVICE DOES WITH IT is the other half. It was told the digest
        to expect by a policy file it fetched over this same identity, so it
        checks these bytes against that and applies them only if they match. The
        header below is a convenience for an operator with `curl`, NOT the
        device's source of truth - an attacker who could substitute the bytes
        could substitute a header beside them.
        """
        # NEVER CACHED, INCLUDING THE REFUSALS. A cached 404 is a device that
        # cannot fetch a wallpaper the operator has since uploaded, on a phone
        # nobody is holding; a cached 200 is the stale-APK failure again, and
        # this endpoint serves a file with an extension, which is exactly what
        # Cloudflare caches on.
        uncached = {"Cache-Control": "no-store"}
        response.headers["Cache-Control"] = "no-store"
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        try:
            asset = state.assets.fetch(name)
        except asset_store.NoSource as no_store:
            # 503 AND NOT 404, and the difference is where somebody goes to
            # look. "The operator has not uploaded it" is a policy edit; "the
            # secret did not mount" is a deployment. An optional secret volume
            # that is absent mounts as an empty directory, so these two are
            # indistinguishable from the filesystem and have to be told apart
            # here or not at all.
            state.telemetry.count("device.asset.refused", tags=["reason:no-source"])
            telemetry.event(
                "muster has no asset store", key_id=proven, error=str(no_store)
            )
            raise HTTPException(
                status_code=503, detail=str(no_store), headers=uncached
            ) from no_store
        except asset_store.Unknown as unknown:
            # THE SAME ANSWER FOR A MISSING FILE AND AN UNUSABLE NAME. The
            # difference is only ever useful to a caller probing for one - so
            # the cause is chained for the traceback and kept out of `detail`.
            state.telemetry.count("device.asset.refused", tags=["reason:unknown"])
            telemetry.event("device asked for an asset muster does not have",
                            key_id=proven, name=name)
            raise HTTPException(
                status_code=404, detail="no such asset", headers=uncached
            ) from unknown
        except asset_store.TooLarge as too_large:
            state.telemetry.count("device.asset.refused", tags=["reason:too-large"])
            telemetry.event("asset is larger than muster serves",
                            key_id=proven, name=name, error=str(too_large))
            raise HTTPException(
                status_code=413, detail=str(too_large), headers=uncached
            ) from too_large
        except asset_store.Unavailable as wedged:
            # 503, AND NOT A 404. The share stopped answering; the asset is
            # almost certainly still there. A 404 would tell the device its
            # wallpaper had been withdrawn, and the agent acts on that - see
            # ConfigurationPolicy: a file absent from a SUCCESSFUL answer is
            # removed from the handset. Retryable is the honest answer.
            state.telemetry.count("device.asset.refused", tags=["reason:unavailable"])
            telemetry.event("asset store did not answer",
                            key_id=proven, name=name, error=str(wedged))
            raise HTTPException(
                status_code=503, detail=str(wedged), headers=uncached
            ) from wedged
        except asset_store.Unreadable as unreadable:
            state.telemetry.count("device.asset.refused", tags=["reason:unreadable"])
            telemetry.event("asset could not be read",
                            key_id=proven, name=name, error=str(unreadable))
            raise HTTPException(
                status_code=503, detail=str(unreadable), headers=uncached
            ) from unreadable

        state.telemetry.count("device.asset.served")
        telemetry.event(
            "device asset served",
            key_id=proven,
            name=asset.name,
            bytes=len(asset.content),
            digest=asset.digest,
        )
        return Response(
            content=asset.content,
            media_type=asset.media_type,
            headers={
                "Cache-Control": "no-store",
                # Named `X-Muster-` rather than RFC 9530 `Digest`, because an
                # intermediary is permitted to rewrite a body it re-encodes and
                # recompute a standard digest header to match. A device that
                # checked such a header would be checking the proxy's arithmetic.
                "X-Muster-Digest": asset.digest,
            },
        )

    @app.get("/v1/kith", dependencies=[admin])
    def roll():
        try:
            members = state.kith.roll()
        except kith_store.Unreachable as exc:
            raise _unreachable(exc) from exc
        return {"store": state.kith.status(), "devices": [_member(m) for m in members]}

    @app.post("/v1/kith/{key_id}/role", dependencies=[admin])
    def set_device_role(key_id: str, role: str = Body(default="", embed=True)):
        """Change what a device is FOR, without re-enrolling it.

        WHY THIS EXISTS (muster#73). A role arrived on a pairing code and was
        written at issuance, so changing one meant wiping a handset and
        provisioning it again - for a text field. That was a limitation of how
        the role got there, not of what a role is: policy is resolved from the
        kith on every fetch, so the device picks up its new scope at its next
        check-in with nothing else to do.

        AN EMPTY ROLE IS A DELIBERATE CLEAR, not a no-op. `record_issuance`
        refuses to let an empty role overwrite a set one, because a re-enrolment
        against a plain QR must not silently strip a handset. Here an operator
        is saying "this is no longer a zippie android" in as many words, and
        refusing would leave no way back.

        ADMINISTRATOR-ONLY, and it belongs to that set rather than the device
        one for a reason worth stating: a role selects which policy scope is
        served, INCLUDING `app-config`, which carries write tokens. A device
        that could set its own role could ask for another role's credentials.
        """
        try:
            changed = state.kith.set_role(key_id, _role_or_400(role))
        except kith_store.Unreachable as exc:
            # NOT a silent success. The operator is about to go and look at a
            # handset expecting different policy.
            raise _unreachable(exc) from exc
        if not changed:
            raise HTTPException(status_code=404, detail="no such device")
        telemetry.event("device role changed", key_id=key_id, role=role or "(none)")
        state.telemetry.count("kith.role.changed")
        return {"key_id": key_id, "role": role}

    @app.get("/v1/kith/{key_id}", dependencies=[admin])
    def device(key_id: str):
        """One device and every certificate it has ever been issued.

        The certificate list is what makes renewal visible: a device that has
        renewed twice is ONE entry here with three certificates, not three
        devices. That is the property the whole table layout exists for, so it
        is worth being able to see it without a database client.
        """
        try:
            member = state.kith.member(key_id)
            if member is None:
                raise HTTPException(status_code=404, detail="no such device")
            history = state.kith.history(key_id)
        except kith_store.Unreachable as exc:
            raise _unreachable(exc) from exc
        return {
            "device": _member(member),
            "certificates": [
                {
                    "serial": c.serial,
                    "not_before": c.not_before.isoformat(),
                    "not_after": c.not_after.isoformat(),
                    "issued_at": c.issued_at.isoformat(),
                    "collected_at": c.collected_at.isoformat() if c.collected_at else None,
                    "certificate_pem": c.certificate_pem,
                }
                for c in history
            ],
        }


def _agent_version_code() -> int | None:
    """The versionCode of the APK this server serves, or None if unknown.

    Beside the APK rather than inside this process: the agent build reads it out
    of the APK with `aapt` and writes it in the SAME step that verifies it
    matches, so the file cannot describe different bytes. Re-deriving it here
    would be a second answer, and two answers about which agent is deployed is
    the failure this whole endpoint exists to prevent.
    """
    apk = os.environ.get("MUSTER_AGENT_APK", "").strip()
    if not apk:
        return None
    beside = pathlib.Path(apk).with_name("agent-version.txt")
    try:
        raw = beside.read_text().strip()
    except OSError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _member(member: kith_store.Member) -> dict:
    """One device on the roll, as JSON.

    `certificates` is a COUNT and not a list on this shape deliberately: the
    roll is what a console renders for the whole estate, and inlining every PEM
    would make listing ten devices a megabyte.
    """
    return {
        "key_id": member.device.key_id,
        "fingerprint": member.device.fingerprint,
        "name": member.device.name,
        # WHAT IT IS FOR (muster#70). Absent until now, so a console could show
        # a fleet of devices and not one of them said which policy it was on -
        # and the answer is the difference between a handset that carries a
        # write token and one that does not.
        "role": member.device.role,
        "first_seen": member.device.first_seen.isoformat(),
        "last_seen": member.device.last_seen.isoformat(),
        "certificates": member.certificates,
        "serial": member.current_serial,
        "not_after": member.not_after.isoformat() if member.not_after else None,
    }


# THE QUIET ZONE, IN MODULES, AND IT IS THE STANDARD'S OWN NUMBER. This QR is
# scanned off a monitor at arm's length by a phone that has been wiped, and the
# quiet zone is what lets a camera find the code at all. Four is what ISO/IEC
# 18004 asks for; this drew two, which a page's own background eats into first.
# Cheaper to draw than to explain to somebody holding a wiped handset that will
# not scan.
_QUIET_ZONE = 4
# Black on white, and NOT the brand's charcoal on warm white. The palette
# governs everything on the page a person reads; this is a target for a camera's
# threshold and contrast is its whole function. The SVG carries its own white
# rather than letting the page show through, so the quiet zone is white too
# whatever the QR is laid on - including a full-screen view and a printout.
_QR_DARK = "#000"
_QR_LIGHT = "#fff"
# The module size the SVG declares. The console sizes it with CSS and SVG scales
# losslessly, so this decides only what a `curl > qr.svg` gets: an image big
# enough to scan from the file, rather than one that needs zooming first.
_QR_SCALE = 8

# What the plain GET refuses to accept in its query string. Named rather than
# spelled out at the call site so it cannot drift from the body parameters the
# POST takes.
_WIFI_PARAMETERS = frozenset({"wifi_ssid", "wifi_password", "wifi_security"})


def _provision_qr(
    state: State,
    apk: pathlib.Path,
    *,
    hands_free: bool = True,
    role: str = "",
    wifi_ssid: str = "",
    wifi_password: str = "",
    wifi_security: str = "WPA",
) -> tuple[str, dict]:
    """The provisioning QR, and what it commits to, built from ONE payload.

    RETURNED TOGETHER BECAUSE THE TEXT IS THE ONLY PART A HUMAN CAN CHECK. A QR
    is opaque; the checksum inside it is the field that decides whether a wiped
    phone provisions or factory resets itself. Two calls that each built their
    own payload could describe a QR that is not the one on the screen, and the
    operator would have no way to tell - so the description is read back out of
    the same dict that was encoded, and cannot be of anything else.

    `extras` is handed over WHOLE rather than field by field, so a key added to
    that bundle shows up beside the QR without anybody remembering to add a row
    for it - WITH ONE EXCEPTION, BELOW, WHICH IS WHY THIS PARAGRAPH IS NO LONGER
    UNQUALIFIED. Reading generically is right for values an operator is meant to
    check; it is wrong for a value they are meant to hold.

    `hands_free` MINTS A PAIRING CODE INTO THAT BUNDLE, which is what takes the
    last person off the handset (enroll.Shape, CONTEXT.md). The code itself is
    then taken back OUT of the description, on exactly the argument the wifi
    password is: it is in the QR, that is the point, and `pairing` says so - but
    a second copy in a second response is a second place it can be read from, and
    this one would be rendered as text on a page beside the image it is already
    inside. Nothing about the code is a value a human can usefully check; when it
    dies is, so that is what is described.

    THE WIFI PASSWORD IS NOT DESCRIBED BACK either, for the same reason, and
    `carries_password` is what says it is in there.
    """
    code = ""
    if hands_free:
        # THE ROLE RIDES THE CODE (muster#70). Minting is the one moment an
        # administrator is deciding what this device is for - "make it a zippie
        # android" - and the device's key_id, which policy is keyed on, does not
        # exist until issuance. So it travels on the code and is written into
        # the kith when the certificate is signed.
        code = state.enrollment.mint(shape=Shape.SCANNED, role=role)
        # NEVER THE CODE, in the event or in the tags. telemetry.event drops a
        # `code=` field, but the honest thing is not to hand it one at all - see
        # telemetry.py's first rule.
        telemetry.event(
            "pairing code minted",
            ttl_s=DEFAULT_CODE_TTL_S,
            shape=Shape.SCANNED.value,
        )
        state.telemetry.count(
            "enroll.code.minted", tags=[f"shape:{Shape.SCANNED.value}"]
        )
    # DESCRIBED BACK, unlike the code and the wifi password. Those are values an
    # operator HOLDS; this is one they CHECK - "did I make this a zippie
    # android?" is exactly the question the text beside a QR is for, and getting
    # it wrong is a phone that comes up as the wrong kind of device.
    data = provisioning.payload(
        component=provisioning.ADMIN_COMPONENT_DEFAULT,
        download_url=f"{state.base_url.rstrip('/')}/agent.apk",
        checksum=provisioning.signature_checksum(apk),
        server_url=state.base_url,
        pairing_code=code,
        wifi_ssid=wifi_ssid,
        wifi_password=wifi_password,
        wifi_security=wifi_security,
    )
    import segno

    buffer = io.BytesIO()
    segno.make(provisioning.encode(data), error="m").save(
        buffer,
        kind="svg",
        scale=_QR_SCALE,
        border=_QUIET_ZONE,
        dark=_QR_DARK,
        light=_QR_LIGHT,
    )
    extras = dict(data.get(provisioning.ADMIN_EXTRAS, {}))
    # OUT OF THE DESCRIPTION, AND THIS LINE IS THE GUARD. Everything else in the
    # bundle is passed through generically so new keys appear beside the QR for
    # free; this key is a credential and would be rendered as text on the page
    # next to the image that already carries it. Popped rather than filtered by
    # a list of allowed keys, so the generic pass-through keeps working.
    carries_code = extras.pop(provisioning.EXTRA_PAIRING_CODE, "") != ""
    described = {
        "component": data[provisioning.COMPONENT],
        "download_url": data[provisioning.DOWNLOAD],
        "signature_checksum": data[provisioning.SIGNATURE_CHECKSUM],
        # Named as well as present in `extras`, because "the server address this
        # device will enroll against" is one of the three things the operator is
        # being asked to check, and it should not depend on knowing which key it
        # travels under.
        "server_url": extras.get(provisioning.EXTRA_SERVER_URL, ""),
        "extras": extras,
        # WHAT MAKES THIS QR PERISHABLE, and the one field a console has to act
        # on. Everything else here is stable for the life of the signing key; a
        # pairing code dies in minutes, and a QR left on a monitor past that is a
        # phone that provisions and then cannot enroll with nothing on the
        # handset explaining why. `expires_in_s` is what a countdown is drawn
        # from; the code itself is deliberately absent.
        "pairing": {
            "carries_code": carries_code,
            "expires_in_s": int(DEFAULT_CODE_TTL_S) if carries_code else None,
            # DESCRIBED BACK, unlike the code beside it. The code is a value an
            # operator HOLDS; the role is one they CHECK - "did I make this a
            # zippie android?" is exactly what the text beside a QR is for, and
            # getting it wrong is a phone that comes up the wrong kind of
            # device with nothing on it saying so.
            "role": role if carries_code else "",
        },
        "wifi": (
            {
                "ssid": data[provisioning.WIFI_SSID],
                "security": data[provisioning.WIFI_SECURITY],
                "carries_password": bool(data.get(provisioning.WIFI_PASSWORD)),
            }
            if provisioning.WIFI_SSID in data
            else None
        ),
    }
    return buffer.getvalue().decode(), described


def _register_agent_routes(app: FastAPI, state: State, admin) -> None:
    """Serving the agent, and the QR that installs it. Same reasoning."""
    # ---- the agent, and the QR that installs it --------------------------

    def _apk_path() -> pathlib.Path:
        if not state.agent_apk:
            raise HTTPException(
                status_code=503,
                detail="no agent APK is published on this server",
            )
        path = pathlib.Path(state.agent_apk)
        if not path.is_file():
            raise HTTPException(
                status_code=503,
                detail=f"the configured agent APK is not on disk: {path}",
            )
        return path

    @app.get("/agent.apk")
    def agent_apk():
        """The agent, for a provisioning device to download.

        UNAUTHENTICATED, and it has to be: the downloader here is Android's
        setup wizard on a device that has no credential and no way to be given
        one. That is safe because the QR carries the SHA-256 of the signing
        certificate and the platform refuses anything that does not match - so
        serving this openly gives an attacker a copy of an APK they could also
        have got by asking a phone, and nothing else.
        """
        path = _apk_path()
        # The ONLY signal a provisioning attempt began. The wizard fetches this
        # before the device has any identity, so if this never increments while
        # somebody is holding a wiped phone, the QR is the thing to look at.
        state.telemetry.count("agent.apk.served")
        telemetry.event("agent APK served", bytes=path.stat().st_size)
        return FileResponse(
            path,
            media_type="application/vnd.android.package-archive",
            filename="muster-agent.apk",
            # NEVER CACHED, AND THIS COST A HANDSET.
            #
            # Cloudflare caches by file extension when the origin says nothing,
            # and .apk is on that list. It cached this response for four hours
            # (max-age=14400) while /agent.json - 31 bytes, no extension - came
            # back DYNAMIC and uncached. So the two endpoints disagreed: the
            # checksum advertised described the APK in the pod, and the bytes a
            # phone downloaded were the previous build from the edge.
            #
            # That is precisely the skew the image bakes the APK in to prevent,
            # reintroduced a layer further out, and it fails SILENTLY: a stale
            # APK signed with the same key still matches the QR's certificate
            # checksum, so the platform accepts it and the device provisions
            # against the wrong agent - or, as happened here, resets itself.
            #
            # 12MB per provisioning attempt is not a bandwidth problem worth
            # trading a wipe for.
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/agent.json")
    def agent_metadata(response: Response):
        """What is published, so a human can check it without downloading 12MB.

        Uncached for the same reason as the APK beside it: this endpoint's whole
        job is to describe the bytes that endpoint serves, and a cached answer
        describes whatever was true when it was cached.
        """
        response.headers["Cache-Control"] = "no-store"
        path = _apk_path()
        # `no-store` above is about the EDGE, not about this process: it stops a
        # proxy describing an APK that has since been replaced. Answering from
        # memory here is safe as long as the bytes have not changed, which is
        # what the (size, mtime) key checks - and it stops the console's
        # settings panel reading and hashing 12MB every time somebody looks at
        # it. The APK is baked into the image, so in the pod the key never
        # moves; on a laptop, rebuilding an APK changes both halves of it.
        stat = path.stat()
        signature = (str(path), stat.st_size, stat.st_mtime_ns)
        described = _APK_DESCRIPTIONS.get(signature)
        if described is not None:
            return described
        try:
            checksum = provisioning.signature_checksum(path)
        except provisioning.NotSigned as unsigned:
            # Loud rather than absent: an APK whose certificate cannot be read
            # cannot be provisioned, and finding that out on a wiped phone is
            # the expensive way.
            raise HTTPException(status_code=500, detail=str(unsigned)) from unsigned
        described = {
            "bytes": stat.st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "signature_checksum": checksum,
            "component": provisioning.ADMIN_COMPONENT_DEFAULT,
        }
        # WHICH AGENT THIS IS, so a device can be told whether it is behind.
        # Read out of the APK by the build that produced it and carried beside
        # it ever since - not re-derived here, because parsing a binary manifest
        # in this process would be a second answer that can disagree with the
        # one CI verified.
        #
        # OMITTED RATHER THAN GUESSED when the file is absent or empty, which is
        # what an image built from an agent that predates the stamp looks like.
        # A fabricated 0 would read as an agent older than every device, and
        # every handset would try to downgrade to it.
        version = _agent_version_code()
        if version is not None:
            described["version_code"] = version
        # One entry per set of bytes ever served by this process, which in a pod
        # is one. Cleared wholesale rather than expired, because the only thing
        # that can grow it is somebody rebuilding an APK under a running server.
        if len(_APK_DESCRIPTIONS) > 8:
            _APK_DESCRIPTIONS.clear()
        _APK_DESCRIPTIONS[signature] = described
        return described

    @app.get("/v1/provision/qr.svg", dependencies=[admin])
    def provision_qr(request: Request, hands_free: bool = True, role: str = ""):
        """The six-tap provisioning QR, plain: the image and nothing else.

        ADMIN-ONLY, and the reason is what this payload can carry: the network
        password in clear text, and - since muster#48 - a pairing code. Either
        one is a credential on a monitor for as long as the QR is on screen.

        WIFI CREDENTIALS DO NOT TRAVEL IN A URL, and this refuses rather than
        ignoring them. A query string is written to this server's access log, to
        whatever proxy is in front of it, and to the browser's history - three
        places a password cannot be deleted from afterwards. Silently dropping
        the parameters would be worse than refusing: an operator copying the
        older command would get a QR with no wifi in it, find out on a wiped
        phone that will not join a network, and have nothing to read that says
        why.

        `hands_free` IS ALLOWED IN THE QUERY, and the difference is the whole
        point of the rule above: it is a boolean, not a credential. What it
        chooses is whether a pairing code is minted INTO the QR - the code
        itself never appears in the URL, the response body or the log.
        """
        offered = _WIFI_PARAMETERS & set(request.query_params)
        if offered:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"{', '.join(sorted(offered))} may not travel in a URL: a "
                    "query string is written to access logs, proxies and browser "
                    "history. POST /v1/provision/qr with them in the body, or "
                    "use the console's Provisioning section."
                ),
            )
        # ROLE IS ALLOWED IN THE QUERY where the wifi password is not, and the
        # difference is what the value is. A role is not a secret - it is the
        # name of a policy scope, it is printed beside the QR on purpose, and an
        # operator wanting a bookmarked URL for "a zippie android" should have
        # one. A password in a query string is a password in an access log.
        # A ROLE THAT IS NOT ONE IS A 400. `enroll.mint` raises ValueError, and
        # without this that surfaces as a 500 with a traceback in the log of the
        # process that holds the CA - for what is a typo in an operator's own
        # request. The message from `mint` says exactly what a role may be, so
        # it is passed through rather than replaced.
        try:
            svg, described = _provision_qr(
                state, _apk_path(), hands_free=hands_free, role=role
            )
        except ValueError as unusable:
            raise HTTPException(status_code=400, detail=str(unusable)) from unusable
        # NEVER CACHED, for the reason /agent.apk beside it is never cached -
        # and this path is the same trap with the same shape. The edge in
        # front of this service caches by file extension when the origin says
        # nothing, and `.svg` is on that list exactly as `.apk` is - the comment
        # on /agent.apk has the measurement. A cached QR describes an agent
        # that may since have been replaced, and a checksum that no longer matches the
        # download is a handset that wipes itself and says "can't set up device".
        #
        # It is now ALSO a replayed single-use pairing code: the second device
        # to scan an edge-cached QR is refused CODE_USED, which reads as an
        # attack rather than as a proxy being helpful.
        headers = {"Cache-Control": "no-store"}
        if described["pairing"]["carries_code"]:
            # A HEADER BECAUSE THIS ROUTE HAS NOWHERE ELSE TO PUT IT. The POST
            # beside it answers with JSON and says the same thing in `pairing`;
            # an image has no room, and somebody curling this endpoint would
            # otherwise have no way to know the QR they just saved is already a
            # few minutes from being useless.
            headers["X-Muster-Pairing-Expires-In"] = str(
                described["pairing"]["expires_in_s"]
            )
        return Response(
            content=svg,
            media_type="image/svg+xml",
            headers=headers,
        )

    @app.post("/v1/provision/qr", dependencies=[admin])
    def provision_qr_described(
        response: Response,
        wifi_ssid: str = Body(default="", embed=True),
        wifi_password: str = Body(default="", embed=True),
        wifi_security: str = Body(default="WPA", embed=True),
        hands_free: bool = Body(default=True, embed=True),
        role: str = Body(default="", embed=True),
    ):
        """The QR and the text that has to go beside it, in one answer.

        A POST THAT CHANGES NOTHING VISIBLE TO A CALLER, on purpose, for two
        reasons that both cost a handset when they were got wrong elsewhere:

          * A wifi password in a query string is a password in an access log.
            The body is the only place it can travel that is not written down
            by something between here and the browser.
          * NOTHING CACHES A POST. `Cache-Control: no-store` is set below as
            well, but the method is the part no edge gets to have an opinion
            about - and the four hours the edge held a copy of /agent.apk
            happened while the origin was serving the current one.

        SameSite=Lax means a browser does not attach the session to a cross-site
        POST, so this being a POST is also what stops another origin minting a
        QR with the operator's session. The same rule the vouch route follows.

        Wifi is opt-in per request rather than configured once, so a QR shown
        for a device that will join a network by hand never contains a password
        at all. `hands_free` is opt-OUT for the opposite reason: one scan being
        the whole ceremony is what this endpoint is for, and the QR to mint
        without a code is the one somebody intends to print or keep.
        """
        response.headers["Cache-Control"] = "no-store"
        try:
            svg, described = _provision_qr(
                state,
                _apk_path(),
                hands_free=hands_free,
                role=role,
                wifi_ssid=wifi_ssid,
                wifi_password=wifi_password,
                wifi_security=wifi_security,
            )
        except ValueError as unusable:
            # See the .svg route: a typo in a role is the operator's, not a
            # server fault, and a 500 here would put a traceback in the CA's log.
            raise HTTPException(status_code=400, detail=str(unusable)) from unusable
        return {"svg": svg, **described}


def app_from_env() -> FastAPI:
    """Wire from the environment, refusing to start if there is no way in."""
    provider = administrator.Provider.from_env()
    subjects = administrator.administrators_from_env()
    if provider is None:
        raise RuntimeError(
            "There is no way to administer this muster: administrator sign-in "
            "(MUSTER_OIDC_*) is not set. Refusing to start rather than exposing "
            "the administrator endpoints unauthenticated - an admin surface "
            "that comes up open because a variable was unset fails at the "
            "worst possible moment, the first time it is exposed."
        )
    if not subjects:
        # The pool this points at is shared with the rest of the estate, so
        # every account in it would be an administrator of muster. Nothing about
        # that is visible from the console, which would look exactly like a
        # correctly configured one.
        raise RuntimeError(
            "MUSTER_ADMIN_SUBJECTS is empty while administrator sign-in is "
            "configured, which would make every account in the estate's identity "
            "provider an administrator of muster. Set it to the subject claims "
            "allowed to vouch for devices."
        )
    import datetime as dt

    from cryptography import x509

    key_path = os.environ.get("MUSTER_CA_KEY")
    cert_path = os.environ.get("MUSTER_CA_CERT")
    if not key_path or not cert_path:
        raise RuntimeError("MUSTER_CA_KEY and MUSTER_CA_CERT must both be set")

    # The base URL goes INTO the QR, so a device gets the address and the code
    # in one scan. Read from the environment rather than derived from the
    # request: behind a tunnel the request's Host is whatever the proxy says,
    # and a device that trusts that can be pointed anywhere by anyone who can
    # set a header.
    agent_apk = os.environ.get("MUSTER_AGENT_APK", "")
    base_url = os.environ.get("MUSTER_BASE_URL", "")
    if not base_url:
        raise RuntimeError(
            "MUSTER_BASE_URL is not set. The pairing QR carries the address "
            "devices enroll against; deriving it from the request Host would let "
            "anyone who can set a header point a device somewhere else."
        )

    # Logging configured HERE, at the one place that wires from the
    # environment, so importing muster.api never reconfigures a host
    # application's logging as a side effect of an import.
    telemetry.configure_logging()
    emitter = telemetry.Telemetry.from_env()
    # SAY WHETHER IT IS ON, at boot, in the logs. An emitter that silently
    # no-ops because DD_AGENT_HOST was never set looks exactly like an estate
    # with nothing to report, and "configured but absent" is the failure this
    # estate keeps rediscovering. One line at startup makes it answerable
    # without an exec into the pod.
    telemetry.event(
        "muster starting",
        telemetry_enabled=emitter.enabled,
        dd_agent_host_set=bool(os.environ.get("DD_AGENT_HOST")),
        agent_apk_published=bool(agent_apk),
        base_url=base_url,
        administrators=len(subjects),
    )

    authority = Authority.load(key_path, cert_path)
    clock = lambda: dt.datetime.now(dt.timezone.utc).timestamp()  # noqa: E731

    sign_in = None
    if provider is not None:
        # The callback URL is derived from MUSTER_BASE_URL rather than
        # configured separately, for the reason that variable exists at all: the
        # request's Host is whatever a proxy says it is, and a redirect URL
        # taken from a header is one an attacker can aim. It must match the one
        # registered with the provider exactly - see docs/administrator-sign-in.md.
        sign_in = administrator.SignIn(
            provider=provider,
            administrators=subjects,
            redirect_uri=base_url.rstrip("/") + "/auth/callback",
        )

    # The kith is wired from the environment too, and it does NOT refuse to
    # start without a database - see kith.from_env. A control plane that
    # CrashLoopBackOffs when its store is unreachable has turned the store into
    # the thing that decides whether devices can renew, which is the one
    # property this design exists to avoid.
    kith = kith_store.from_env(
        clock=lambda: dt.datetime.now(dt.timezone.utc), emitter=emitter
    )
    telemetry.event(
        "kith store wired",
        **{f"kith_{k}": v for k, v in kith.status().items()},
    )

    # Where the configuration devices fetch comes from. Optional, and it does
    # NOT refuse to start without one - same argument as the kith store, and
    # said out loud here and on /readyz so that "no policy directory" cannot be
    # mistaken for "no policy configured".
    policies = policy.from_env()
    assets_held = asset_store.from_env()
    telemetry.event(
        "policy source wired",
        **{f"policy_{k}": v for k, v in policies.status().items()},
        **{f"asset_{k}": v for k, v in assets_held.status().items()},
    )

    ca_cert = x509.load_pem_x509_certificate(authority.certificate_pem)
    return create_app(
        State(
            enrollment=Enrollment(clock=clock),
            authority=authority,
            sign_in=sign_in,
            cookie_secure=os.environ.get("MUSTER_COOKIE_SECURE", "true").lower()
            != "false",
            proofs=Proofs(clock=clock, ca_certificate=ca_cert),
            base_url=base_url,
            agent_apk=agent_apk,
            telemetry=emitter,
            kith=kith,
            policies=policies,
            assets=assets_held,
        )
    )
