"""The device channel: one way to prove a device, one way to refuse it.

THE MIDDLE AUDIENCE IN api.py's TABLE, split out of that module by audience
(muster#218). Everything an enrolled device says to muster arrives here:
configuration down, diagnostics and its report up, an asset, a renewal, and the
acknowledgements of a wipe or a reboot. Each route states its domain answer and
inherits the rest from three things in this module:

  * `_proven_device`, THE ONE PLACE A DEVICE IS AUTHENTICATED. Every route calls
    it before reading anything a route adds, and every field a route adds is
    defaulted, so a caller with no identity is refused by the proof and never
    by the schema.
  * `UncachedRoute`, the route class every device route is registered with. It
    puts `Cache-Control: no-store` on the answer AND on every refusal, raised
    or validated. FastAPI merges an injected Response's headers only on a
    normal return, so a route that set the header in its body had set it on
    exactly the path that did not need it most.
  * `refusing`, which maps a store outage or a policy that cannot be read to a
    503 with its telemetry. Code that catches `Unreachable` refuses; it does not
    substitute, because the agent removes a file a SUCCESSFUL answer did not
    mention, and a smaller 200 is an instruction to withdraw.

Each 503 keeps the sentence it had in api.py, because the sentence is what tells
a device, or the operator reading its log, what is still in force.
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import time
from typing import TYPE_CHECKING, Annotated, Callable

from cryptography.hazmat.primitives import serialization
from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

from muster import assets as asset_store
from muster import kith as kith_store
from muster import policy, short_renewal, standing, telemetry
from muster.ca import BACKDATE, Identity, Untrusted
from muster.enroll import fingerprint, key_id
from muster.proof import Verdict

if TYPE_CHECKING:
    from muster.api import State

# The header every device answer and every device refusal carries.
NO_STORE = {"Cache-Control": "no-store"}



def register(app: FastAPI, state: State) -> None:
    """Every route a device reaches over the identity it holds, plus the proof.

    The challenge and the bare verify are here because they are the proof
    exchange itself; every other route is a sibling POST that calls
    `_proven_device` and states its domain answer.
    """
    _register_proof_routes(app, state)
    _register_device_routes(app, state)
    _register_asset_route(app, state)


class UncachedRoute(APIRoute):
    """A device route: never cached, whether it answers or refuses.

    NOT A HEADER EACH ROUTE REMEMBERS. Before muster#218 each device route set
    no-store on its injected Response, which covers only a normal return, and
    passed `headers=` on the refusals it thought of. The diagnostics and report
    rate limits, the renewal refusals and the schema's own 422 went out with no
    cache header at all. A cached refusal is a device that cannot be served
    again until the entry expires, on a phone nobody is holding.
    """

    def get_route_handler(self) -> Callable:
        handler = super().get_route_handler()

        async def uncached(request: Request) -> Response:
            try:
                response = await handler(request)
            except HTTPException as refused:
                refused.headers = {**(refused.headers or {}), **NO_STORE}
                raise
            except RequestValidationError as invalid:
                response = await request_validation_exception_handler(
                    request, invalid
                )
            response.headers.update(NO_STORE)
            return response

        return uncached


def _post(app: FastAPI, path: str, **options) -> Callable:
    """`@app.post`, registered as an `UncachedRoute`. The only way a route joins."""

    def register(endpoint: Callable) -> Callable:
        app.router.add_api_route(
            path,
            endpoint,
            methods=["POST"],
            route_class_override=UncachedRoute,
            **options,
        )
        return endpoint

    return register


@contextlib.contextmanager
def refusing(
    state: State,
    *errors: type[Exception],
    detail: Callable[[Exception], str] | str,
    counter: str | None = None,
    tags: Callable[[Exception], list[str]] | list[str] | None = None,
    event: str | None = None,
    **fields,
):
    """Refuse with an uncached 503 when one of `errors` is raised inside.

    THE ONE SHAPE FOR "MUSTER CANNOT SAY". A store that cannot be read, a policy
    that cannot be read and an asset share that does not answer all mean the
    same thing to a device: keep what you have and ask again. The cause is
    chained for the traceback, `counter` (with `tags`) is what a monitor reads,
    and `event`, when given, is logged with `fields` and the error.

    `detail` and `tags` may be functions of the exception, for the routes whose
    sentence quotes it or whose tag names which kind of refusal it was.
    """
    try:
        yield
    except errors as cannot_say:
        said = detail(cannot_say) if callable(detail) else detail
        if counter is not None:
            state.telemetry.count(
                counter, tags=tags(cannot_say) if callable(tags) else tags
            )
        if event is not None:
            telemetry.event(event, **fields, error=str(cannot_say))
        raise HTTPException(
            status_code=503, detail=said, headers=dict(NO_STORE)
        ) from cannot_say


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


def _serial_of(certificate_pem: bytes) -> str:
    """A certificate's serial in the form the kith stores it: uppercase hex,
    which is also what `openssl x509 -serial` prints."""
    from cryptography import x509

    return f"{x509.load_pem_x509_certificate(certificate_pem).serial_number:X}"


def _key_id_of(certificate_pem: bytes) -> str:
    """Which device in the kith a certificate belongs to.

    Re-parses a certificate that proof.verify has already parsed, which is a
    few microseconds spent to avoid widening `verify`'s return type from a
    verdict into a verdict-and-a-certificate. The verdict is the interesting
    thing about that function and it should stay the whole of it.
    """
    from cryptography import x509

    return key_id(_spki_der(x509.load_pem_x509_certificate(certificate_pem).public_key()))


DIAGNOSTIC_MAX_BYTES = 4096
DIAGNOSTIC_MAX_LINES = 16
DIAGNOSTIC_INTERVAL_S = 60


def _take_diagnostic_slot(
    state: "State", key_id: str, ledger: dict[str, float] | None = None
) -> bool:
    """Allow one upload per device per minute; discard expired identities.

    `ledger` defaults to the diagnostics one; the report route passes its own.
    """
    sent = state.diagnostic_last_sent if ledger is None else ledger
    now = time.monotonic()
    with state.diagnostic_lock:
        expired = [
            device for device, sent_at in sent.items()
            if now - sent_at >= DIAGNOSTIC_INTERVAL_S
        ]
        for device in expired:
            del sent[device]
        last = sent.get(key_id, float("-inf"))
        if now - last < DIAGNOSTIC_INTERVAL_S:
            return False
        sent[key_id] = now
        return True


# WHAT A DEVICE SAYS IT DID (muster#146). Bounded per field like diagnostics,
# because this is a row every device rewrites every check-in: thirty-two steps
# is three times BootPlan's eleven, and sixty-four packages is more managed
# applications than any policy file here names.
REPORT_MAX_STEPS = 32
REPORT_MAX_CONCERNS = 32
REPORT_MAX_PACKAGES = 64
# THE WHOLE ROW, NOT ONLY EACH FIELD. The per-field limits above multiply out to
# half a megabyte; a real check-in is a few kilobytes, and this is the bound
# that keeps a device from making its own row large.
REPORT_MAX_BYTES = 16384
# The agent's own package-name rule (AppInstallPolicy.PACKAGE), so a name the
# device could never have installed cannot become a row.
_PACKAGE = r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$"


class StepIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    outcome: str = Field(..., max_length=telemetry.DIAGNOSTIC_LINE_CHARS)
    concerns: list[
        Annotated[str, Field(max_length=telemetry.DIAGNOSTIC_LINE_CHARS)]
    ] = Field(..., max_length=REPORT_MAX_CONCERNS)


class PackageIn(BaseModel):
    package: str = Field(..., max_length=255, pattern=_PACKAGE)
    # None is "not installed", which is an answer and not a missing field.
    version_code: int | None = Field(..., ge=0)


def _kept_step(step: StepIn) -> kith_store.StepReport:
    """One reported step, sanitized the way a diagnostic line is before it is kept."""
    return kith_store.StepReport(
        name=telemetry.sanitize_diagnostic(step.name),
        outcome=telemetry.sanitize_diagnostic(step.outcome),
        concerns=tuple(telemetry.sanitize_diagnostic(c) for c in step.concerns),
    )


def _report_bytes(steps: tuple[kith_store.StepReport, ...]) -> int:
    """The UTF-8 size of every string a report's steps carry."""
    return sum(
        len(text.encode("utf-8"))
        for step in steps
        for text in (step.name, step.outcome, *step.concerns)
    )


# Refusals a device can act on. 401 for a certificate we did not issue is
# deliberate rather than 403: the device is not forbidden, it is unrecognised,
# and the fix is to enroll. 409 for expired requires enrollment again.
_PROOF_STATUS = {
    Verdict.NO_SUCH_NONCE: 400,
    Verdict.NONCE_EXPIRED: 408,
    Verdict.BAD_SIGNATURE: 401,
    Verdict.CERT_EXPIRED: 409,
    Verdict.CERT_NOT_OURS: 401,
}


def _refusal_detail(verdict: Verdict, expired_detail: str | None) -> str:
    """The refusal text: the verdict's own value, unless a route words expiry itself.

    Only a route whose caller can act on expiry (renewal: enroll again) passes
    `expired_detail`. Every other device route keeps `cert-expired`, which
    clients already match on.
    """
    if verdict is Verdict.CERT_EXPIRED and expired_detail is not None:
        return expired_detail
    return verdict.value


def _holds_certificate(
    state: State, member: kith_store.Member | None, serial: str
) -> bool:
    """Whether the kith already records the certificate a device presented.

    The current serial answers the ordinary case without a second query. A
    device still presenting the certificate before its latest renewal costs one
    lookup by serial. Raises `Unreachable`, like every read.
    """
    if member is None:
        return False
    if member.current_serial == serial:
        return True
    return state.kith.certificate_status(serial) is not None


def _record_presented(state: State, proven: str, certificate_pem: bytes) -> None:
    """Write down a certificate this CA signed and the kith never recorded (muster#166).

    CALLED ONLY AFTER `proofs.verify` ANSWERED OK, and that is the whole of its
    safety: the certificate verified against muster's own CA certificate and
    the device signed the nonce with its key. A certificate another CA signed,
    or a copy of one of ours presented without the key, is refused before this
    runs, so it can never write a row.

    Everything recorded is read off the certificate itself, so the row carries
    its real serial and dates. `issued_at` and `first_seen` are when it was
    SIGNED, which the CA backdated `not_before` from, so a certificate recorded
    late takes its true place in the device's history rather than becoming the
    current one. The role is NOT recoverable - it is in the pairing code, not
    the certificate - so the device has none until an administrator sets it.

    Deferred like the issuance it replaces. A write that cannot land joins the
    backlog and `Kith.unrecorded` names it, rather than failing a proof.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    certificate = x509.load_pem_x509_certificate(certificate_pem)
    serial = f"{certificate.serial_number:X}"
    signed_at = certificate.not_valid_before_utc + BACKDATE
    common = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    state.kith.issued(
        kith_store.Device(
            key_id=proven,
            fingerprint=fingerprint(_spki_der(certificate.public_key())),
            name=str(common[0].value) if common else "",
            first_seen=signed_at,
            last_seen=signed_at,
        ),
        kith_store.Certificate(
            serial=serial,
            # Which enrollment it came from is not in the certificate. Named
            # after its source the way renewals are (`renew-<serial>`).
            request_id=f"presented-{serial}",
            not_before=certificate.not_valid_before_utc,
            not_after=certificate.not_valid_after_utc,
            issued_at=signed_at,
            certificate_pem=certificate_pem.decode(),
            # The device is holding it, so it has been collected. NULL would
            # leave it open to collection by its made-up request id.
            collected_at=state.kith.now(),
        ),
    )
    telemetry.event(
        "recorded a certificate the kith did not hold", key_id=proven, serial=serial
    )
    state.telemetry.count("proof.unrecorded")


def _proven_device(
    state: State,
    nonce: str,
    signature_b64: str,
    certificate_pem: str,
    check_in_interval_s: int | None = None,
    expired_detail: str | None = None,
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
            status_code=_PROOF_STATUS[verdict],
            detail=_refusal_detail(verdict, expired_detail),
            headers=uncached,
        )

    state.telemetry.count("proof.verified", tags=["verdict:ok"])
    state.telemetry.check_in()
    proven = _key_id_of(certificate_pem.encode())
    presented = _serial_of(certificate_pem.encode())
    # WHICH CERTIFICATE, NOT ONLY WHICH DEVICE (muster#66). After a renewal
    # the previous certificate stays valid for months, so "this key proved" is
    # the same line whether the device moved to its new certificate or never
    # did. The serial of the one actually presented is what tells them apart,
    # and it is public - it is printed on every certificate and served by OCSP.
    telemetry.event("device proven", key_id=proven, serial=presented)

    # STILL OURS? A valid signature over a valid certificate proves the device
    # is who it says. It does not prove anybody still wants to hear from it, and
    # those are different questions - which is why this check is HERE and not in
    # `proofs.verify`. The proof layer answers "is this the key we issued to";
    # the kith answers "is this key still one of ours".
    #
    # IT LIVES IN THE ONE PLACE A DEVICE IS AUTHENTICATED, per this function's
    # own docstring. A revocation enforced on the config route and not on the
    # renewal route would be a revoked device that cannot be configured and can
    # still extend its own certificate for another ninety days, forever. Every
    # route a device reaches calls this; that is the whole reason it exists.
    #
    # 503 ON AN UNREACHABLE STORE, NOT AN ALLOW. This module's read contract is
    # "reads raise, never lie" (kith.py), and a revocation check that fails open
    # is a revocation an attacker can defeat by making the database unreachable.
    # The cost is real and bounded: while the store is down, devices cannot
    # refresh or renew. They keep working on what they have cached, and muster
    # issues at a third of certificate life, so a device has sixty days of slack
    # before an outage could cost it anything at all.
    with refusing(
        state,
        kith_store.Unreachable,
        detail="the kith store is unreachable, so this device cannot be "
               "confirmed as still enrolled. Retry.",
        counter="proof.revocation.unreachable",
    ):
        member = state.kith.member(proven)
        recorded = _holds_certificate(state, member, presented)
    # A MISSING ROW IS NOT A REFUSAL, and that is required rather than lenient.
    # `record_issuance` is DEFERRED like every other kith write, so between
    # muster signing a certificate and the backlog draining there is a device
    # holding a valid identity with no row yet. Refusing on `member is None`
    # would turn every issuance into a race, and a store outage during
    # enrollment into a handset that must be factory reset. The authority for
    # "did we sign this" is the CA and the proof, which have already answered
    # above; the kith answers only the narrower question of whether somebody has
    # since said stop.
    #
    # SO A MISSING ROW IS WRITTEN, FROM THE CERTIFICATE (muster#166). The read
    # above drained the backlog first, so a certificate still absent was never
    # recorded: signed before the store existed, or lost with a pod's backlog.
    # The proof just showed this CA signed it, so it is the evidence. Done
    # BEFORE the revocation check, so a revoked device's unrecorded certificate
    # reaches the CRL, which is built from these rows.
    if not recorded:
        _record_presented(state, proven, certificate_pem.encode())
    if member is not None and standing.served(standing.Standing.of(member.device)).refused:
        # COUNTED AND NAMED. A revoked device that keeps calling is either a
        # machine nobody switched off or a machine somebody took, and the two
        # look identical from here - so it is worth being able to see that it is
        # still trying rather than only that it is being refused.
        telemetry.event("revoked device refused", key_id=proven)
        state.telemetry.count("proof.refused", tags=["verdict:revoked"])
        raise HTTPException(
            status_code=403,
            detail=standing.REVOKED_DETAIL,
            headers=uncached,
        )

    # LAST SEEN, and this is the only place that can honestly set it. A proof is
    # the one moment muster knows a specific device was reachable and still
    # holds its key - an unauthenticated request proves only that somebody sent
    # bytes. Recording it anywhere else would make "last seen" a column that
    # means nothing.
    #
    # Only after Verdict.OK, so a failed proof cannot be used to keep a device
    # looking alive; and deferred like every other write, so a store outage
    # cannot turn a good proof into a 500.
    state.kith.seen(proven, _plausible_interval(check_in_interval_s))
    return proven


# A DAY AT MOST, A MINUTE AT LEAST. Anything outside is a bug or a lie, and the
# answer is to not record it rather than to refuse the request: this value only
# decides how a console row is drawn, and a configuration fetch must never fail
# over something cosmetic (muster#77).
_INTERVAL_BOUNDS_S = (60, 86_400)


def _plausible_interval(interval_s: int | None) -> int | None:
    if interval_s is None:
        return None
    low, high = _INTERVAL_BOUNDS_S
    return interval_s if low <= interval_s <= high else None


def _register_proof_routes(app: FastAPI, state: State) -> None:
    """Proof of possession.

    Split out of create_app because that function grew past the complexity cap
    as endpoints accumulated. Route registration is naturally additive, and one
    function that mounts everything gets steadily harder to read for no benefit
    - the groups here are the same audiences the module docstring already names.
    """
    # ---- proof of possession (muster#1) ----------------------------------

    @_post(app, "/v1/auth/challenge", status_code=201)
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

    @_post(app, "/v1/auth/verify")
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


# What each device acknowledgement is called where an operator reads it.
_ACKNOWLEDGED = {
    standing.ACK_WIPE: ("wipe", "device.wipe.acknowledged", "device wipe acknowledged"),
    standing.ACK_REBOOT: (
        "reboot", "device.reboot.acknowledged", "device reboot acknowledged",
    ),
}


def _acknowledge(state: State, proven: str, verb: str) -> None:
    """A device's acknowledgement of a waiting instruction, or the refusal `standing` gives.

    ONE FUNCTION FOR BOTH INSTRUCTIONS (muster#217). The wipe and reboot
    acknowledgements were two copies of one shape; the rule that decides
    whether each applies now lives in `standing.permits`, and this reads it.

    BOTH REFUSALS ARE THE SAME SENTENCE, DELIBERATELY. One is "this device was
    never told to"; the other is "something else already moved it out of that
    state" - two devices racing, or an administrator calling the instruction
    off between the proof and this line. A device cannot act differently on
    the two, and telling it which one it lost would say something about a
    state it is not entitled to know.

    THE `Unreachable` CASE GOES THROUGH `refusing`, like every other device
    route's, rather than through `_register_kith_routes`'s `_unreachable`
    closure, which is not in scope here (muster#59).
    """
    noun, counter, event = _ACKNOWLEDGED[verb]
    with refusing(
        state,
        kith_store.Unreachable,
        detail=lambda exc: (
            f"{exc}. The device is unaffected: nothing has acted on the {noun} "
            "instruction, whichever state it turns out to be in."
        ),
        counter="kith.read.refused",
        event=f"muster cannot say whether a device was asked to {noun}",
        key_id=proven,
    ):
        member = state.kith.member(proven)

    # A device with no row was never asked, which is the empty standing.
    now = (
        standing.Standing.of(member.device) if member is not None
        else standing.Standing()
    )
    answer = standing.permits(now, verb)
    if isinstance(answer, standing.Refusal):
        raise HTTPException(status_code=answer.status, detail=answer.detail)
    # THE TRANSITION IS THE AUTHORITY, not the read above. The store applies
    # it in one conditional write, so an administrator calling the instruction
    # off after that read leaves nothing to acknowledge.
    write = {
        standing.ACK_WIPE: state.kith.acknowledged_wipe,
        standing.ACK_REBOOT: state.kith.acknowledged_reboot,
    }[verb]
    if not write(proven):
        refusal = standing.permits(standing.Standing(), verb)
        raise HTTPException(status_code=refusal.status, detail=refusal.detail)

    state.telemetry.count(counter)
    telemetry.event(event, key_id=proven)


def _cannot_configure(
    state: State, proven: str, error: type[Exception], reason: str
):
    """The configuration route's refusal for a policy it cannot read, by reason."""
    return refusing(
        state,
        error,
        detail=lambda exc: (
            f"{exc} Retry - this device's existing configuration is unaffected "
            "and stays in force."
        ),
        counter="device.config.refused",
        tags=[f"reason:{reason}"],
        event="muster cannot say what a device should be",
        key_id=proven,
        reason=reason,
    )


def _register_device_routes(app: FastAPI, state: State) -> None:
    """What an enrolled device asks muster for, over the identity it holds.

    THE THIRD AUDIENCE in api.py's docstring, and the one everything a
    device will ever do arrives through. Configuration comes down here today
    (muster#46); diagnostics (muster#27) and inventory (muster#42) go up the
    same way, as sibling POSTs that call `_proven_device` and then act on the
    key_id it returns. The shape is fixed here on purpose so those two are a
    route each rather than an authentication design each.
    """

    @_post(app, "/v1/device/config")
    def device_config(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
        # OPTIONAL and last, so every agent build before muster#77 still fetches.
        check_in_interval_s: int | None = Body(None, embed=True),
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
        # `UncachedRoute` sets the header, on this answer and every refusal.
        proven = _proven_device(
            state, nonce, signature_b64, certificate_pem, check_in_interval_s
        )
        # WHAT THIS DEVICE IS FOR, read from the kith and NEVER sent by the
        # device (muster#70). A role selects which policy scope is served -
        # including `app-config`, which carries write tokens - so a device that
        # could name its own role could ask for another role's credentials.
        #
        # A STORE THAT IS DOWN IS A 503, NOT A SMALLER ANSWER. This block used
        # to say the opposite - that `member` answers None when the kith cannot
        # be read, so the route could fall back to the kith scope and keep a
        # device configured through a database outage. Both halves were wrong.
        #
        # `member` does NOT answer None. `kith.py`'s reads are filed under
        # "reads: raise, never lie" and `_read` raises `Unreachable` on an
        # unreadable store, so the fallback was unreachable code and an outage
        # escaped an endpoint catching only `policy.Unreadable`/`NoSource` -
        # an unhandled 500, and one that skipped `kith.read.refused` so the
        # outage went missing from the metric an operator would look at.
        #
        # And the fallback would have been wrong even if it had run. Role
        # selects the policy scope, so losing the role serves the SHARED scope
        # instead of the device's - a strictly smaller set of files. Read this
        # route's own docstring: the agent removes a file that a successful
        # fetch did not mention, so a smaller answer is an authoritative
        # instruction to WITHDRAW. "Keeps a device configured" would in fact
        # have stripped exactly the role-scoped files it meant to protect, by
        # the same argument that already makes an unreadable policy a 503.
        with refusing(
            state,
            kith_store.Unreachable,
            detail=lambda exc: (
                f"{exc}. The device keeps the configuration it already has: "
                "muster refuses to answer rather than answering with a scope it "
                "cannot confirm."
            ),
            counter="kith.read.refused",
            event="muster cannot say what role a device has",
            key_id=proven,
        ):
            member = state.kith.member(proven)
        role =member.device.role if member is not None else ""
        # WIPE-PENDING IS THE STATE THAT STILL GETS SERVED. `_proven_device`
        # above refuses only `revoked_at`, so this member can be both
        # authenticated and waiting to be erased. The wipe instruction must
        # arrive BEFORE the refusal, which is exactly the ordering this flag
        # carries into policy resolution.
        # REBOOT-REQUESTED IS SERVED THE SAME WAY, for the same reason: it must
        # reach the device before anything could refuse it, and nothing does -
        # `reboot_requested_at` never interacts with `revoked_at` (muster#58).
        # Both answers are `standing.served`, the one place that says so.
        given = standing.served(
            standing.Standing.of(member.device) if member is not None
            else standing.Standing()
        )
        # 503 AND NOT AN EMPTY ANSWER, and the difference is every managed
        # file on every device in the estate. The agent removes a file that
        # a SUCCESSFUL fetch did not mention, so "here is nothing" is an
        # authoritative instruction to withdraw - and a deleted secret
        # volume, an unmountable path and a file with a bad byte in it would
        # all have produced exactly that. muster refuses to answer rather
        # than answering something it cannot support.
        with _cannot_configure(state, proven, policy.NoSource, "no-source"), \
                _cannot_configure(state, proven, policy.Unreadable, "unreadable"):
            configuration = state.policies.for_device(
                proven,
                role=role,
                wipe_pending=given.wipe,
                reboot_requested=given.reboot,
            )

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
            # WHEN THIS DEVICE MAY RENEW, on every check-in (muster#22). Until
            # now a device learned this only from the answer to its last
            # renewal, so nothing muster decided later could reach it before
            # that date. An agent that reads this overwrites its stored value;
            # one that does not ignores an unknown key, as it always has.
            "renew_after": _advertised_renew_after(
                state, proven, certificate_pem
            ).isoformat(),
        }

    @_post(app, "/v1/device/diagnostics", status_code=202)
    def device_diagnostics(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
        diagnostics: list[str] = Body(..., embed=True, max_length=DIAGNOSTIC_MAX_LINES),
    ):
        """Accept a small device report after proving its enrolled identity."""
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        byte_count = sum(len(line.encode("utf-8")) for line in diagnostics)
        if any(len(line) > telemetry.DIAGNOSTIC_LINE_CHARS for line in diagnostics):
            raise HTTPException(status_code=413, detail="diagnostic line is too large")
        if byte_count > DIAGNOSTIC_MAX_BYTES:
            raise HTTPException(status_code=413, detail="diagnostic report is too large")
        if not _take_diagnostic_slot(state, proven):
            state.telemetry.count("device.diagnostics.refused", tags=["reason:rate-limit"])
            raise HTTPException(
                status_code=429,
                detail="diagnostics may be sent once per minute",
                headers={"Retry-After": str(DIAGNOSTIC_INTERVAL_S)},
            )
        safe_diagnostics = [telemetry.sanitize_diagnostic(line) for line in diagnostics]
        telemetry.event(
            "device diagnostics received",
            key_id=proven,
            diagnostics=safe_diagnostics,
        )
        state.telemetry.count("device.diagnostics.received")
        return {"accepted": True}

    @_post(app, "/v1/device/report", status_code=202)
    def device_report(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
        steps: list[StepIn] = Body(..., embed=True, max_length=REPORT_MAX_STEPS),
        packages: list[PackageIn] = Body(
            ..., embed=True, max_length=REPORT_MAX_PACKAGES
        ),
        security_patch: str | None = Body(None, embed=True),
        build_id: str | None = Body(None, embed=True),
        # A strict bool and nothing richer (muster#191): the device is not
        # trusted to put arbitrary JSON in the report. True means an OS update
        # is waiting, false none, absent that the agent could not ask.
        pending_update: Annotated[bool | None, Body(embed=True, strict=True)] = None,
    ):
        """What a device did at its last check-in, kept so the console can say (muster#146).

        Diagnostics go to the log and are gone; this is STORED, one row per
        device, because "did the install work" is a question asked after the
        fact - by an operator, or by a monitor alerting on a concern - and the
        only other place the answer lived was the status screen of a phone
        nobody is holding.

        Everything here is the device's own account. muster records it and
        does not act on it: a report cannot change policy, and a device that
        lies about a version only misleads the reader of its own row.
        """
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        if not _take_diagnostic_slot(state, proven, state.report_last_sent):
            state.telemetry.count("device.report.refused", tags=["reason:rate-limit"])
            raise HTTPException(
                status_code=429,
                detail="a report may be sent once per minute",
                headers={"Retry-After": str(DIAGNOSTIC_INTERVAL_S)},
            )
        kept = tuple(_kept_step(step) for step in steps)
        if _report_bytes(kept) > REPORT_MAX_BYTES:
            raise HTTPException(status_code=413, detail="report is too large")
        clean_patch = security_patch.strip()[:64] if security_patch is not None else None
        clean_build = build_id.strip()[:64] if build_id is not None else None
        # 503 and the device keeps going: it sends a fresher report at its
        # next check-in, which is worth more than this one anyway.
        with refusing(
            state,
            kith_store.Unreachable,
            detail=lambda exc: f"{exc}. The report was not kept; send the next one.",
            counter="device.report.refused",
            tags=["reason:unreachable"],
        ):
            state.kith.reported(
                proven,
                kept,
                tuple(
                    kith_store.PackageReport(package=p.package, version_code=p.version_code)
                    for p in packages
                ),
                security_patch=clean_patch,
                build_id=clean_build,
                pending_update=pending_update,
            )
        concerns = [f"{step.name}: {c}" for step in kept for c in step.concerns]
        state.telemetry.count("device.report.received")
        # A COUNT, NOT A TAG PER STEP. Step names arrive from the device, and a
        # tag a device chooses is unbounded cardinality; the concerns themselves
        # are in the event below, where a monitor can read which.
        state.telemetry.count("device.report.concerns", value=len(concerns))
        telemetry.event(
            "device report received",
            key_id=proven,
            concerns=concerns,
            versions={p.package: p.version_code for p in packages},
        )
        return {"accepted": True}

    @_post(app, "/v1/device/wipe", status_code=200)
    def device_wipe(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
    ):
        """A wipe-pending device says it has received the instruction and is acting on it.

        THIS IS THE SECOND HALF OF THE ORDERING. The administrator set
        `wipe_pending_at`, which `_proven_device` deliberately does NOT refuse,
        so the wipe file could travel on /v1/device/config. This endpoint is
        the device's acknowledgement: once it arrives, wipe-pending becomes
        `revoked_at`, and from then on `_proven_device` refuses the key on
        every route. A device that wiped without this transition would be able
        to renew back into the kith as soon as it rebooted.
        """
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        _acknowledge(state, proven, standing.ACK_WIPE)
        return {"key_id": proven, "revoked": True}

    @_post(app, "/v1/device/reboot")
    def device_reboot(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
    ):
        """A reboot-requested device says it has received the instruction and is acting on it.

        THE SAME ORDERING ARGUMENT AS WIPE (muster#58): this acknowledgement
        must land before `DevicePolicyManager.reboot()`, because that call is
        not guaranteed to return control to the process that made it. Once
        this arrives, `reboot_requested_at` clears - there is no second state
        to transition into the way wipe moves into `revoked_at`, because a
        rebooted device is expected back, not gone.
        """
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        _acknowledge(state, proven, standing.ACK_REBOOT)
        return {"key_id": proven, "reboot_acknowledged": True}

    @_post(app, "/v1/device/renew", status_code=201, include_in_schema=False)
    @_post(app, "/v1/enroll/renew", status_code=201)
    def device_renew(
        nonce: str = Body(..., embed=True),
        signature_b64: str = Body(..., embed=True),
        certificate_pem: str = Body(..., embed=True),
        # DEFAULTED RATHER THAN REQUIRED, so that PROOF IS ALWAYS CHECKED FIRST -
        # the same reasoning `device_asset` gives for `name`, and the parametrized
        # audience tests caught this route getting it wrong. A required field
        # makes FastAPI answer 422 from its own validation BEFORE the endpoint
        # body runs, so a caller with no identity at all learns the shape of the
        # request without ever being asked to prove anything, and a revoked
        # device is told its CSR is missing rather than that it is revoked.
        csr_pem: str = Body("", embed=True),
        # WHAT STARTED THIS RENEWAL, as the agent names it (muster#22): the
        # scheduled check-in, its catch-up run, a boot, or the sync button.
        # Logged, never trusted for a decision - it is the device's own word.
        trigger: str = Body("", embed=True),
    ):
        """A fresh certificate, for the device that signed this nonce.

        WHY THIS EXISTS (muster#10). Until now the only route to a certificate
        was `POST /v1/enroll/requests`, which needs a pairing code an
        administrator minted. So a device holding a valid, unexpired certificate
        could not obtain its next one, and `renew_after` - which muster computes
        and hands to every device - told it to start doing something it had no
        way to do. Every enrolled device therefore had a standing quarterly
        appointment with a human, or it fell off this channel silently.

        POSSESSION OF THE ENROLLED KEY IS THE VOUCH, and that is the whole
        argument. A pairing code exists to answer "should this stranger get a
        certificate". A device signing a nonce with a key muster has already
        vouched for is not a stranger - it is the same device, answering with
        the credential muster itself issued. Requiring it to enroll again from
        scratch is demanding a WEAKER proof than the one it is already holding.

        It is also the property `key_id` was chosen for. `_proven_device` returns
        a key id rather than a certificate serial precisely so that identity
        survives renewal ("a certificate serial changes every ninety days; the
        key does not") - and until this route existed, nothing could renew, so
        that property had never once been redeemable.

        RENEWAL, NOT ROTATION, and the check below is what keeps them apart. The
        CSR must carry the SAME public key as the certificate presented with it.
        A new key is a new `key_id`, and `key_id` is what every policy scope,
        every role and every kith row is filed under - so a device that could
        swap its key here would silently become a different device with another
        device's policy, without anybody vouching for the new key. CONTEXT.md
        already states the rule this enforces: "a device presenting a NEW key is
        a NEW device and has to be vouched for again".

        A REVOKED DEVICE CANNOT RENEW because `_proven_device` refuses it before
        this body runs (muster#11). That ordering is the entire reason
        revocation had to land first: automatic renewal without it would be a
        fleet that renews itself forever with nothing able to say stop, because
        lapse - muster's original revocation mechanism - only ever worked while
        renewal needed a human.

        AN EXPIRED CERTIFICATE CANNOT RENEW EITHER, and that falls out of the
        proof rather than being decided here: `proofs.verify` answers
        CERT_EXPIRED and `_proven_device` turns it into a 409. A device that let
        its identity lapse has no possession proof left to offer, so it goes back
        to a pairing code and a person. That is the same line muster has always
        drawn and this route does not move it.
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        proven = _proven_device(
            state,
            nonce,
            signature_b64,
            certificate_pem,
            expired_detail="certificate expired; enroll again with a pairing code",
        )

        # A certificate signed by this CA proves its key, but renewal belongs
        # only to a device already recorded in the kith. `_proven_device` has
        # just written the row if it was missing (muster#166), so a device with
        # none here is one whose record the store has not taken yet.
        with refusing(
            state,
            kith_store.Unreachable,
            detail="the kith store is unreachable, so this device cannot be "
                   "confirmed as enrolled. Retry.",
        ):
            member = state.kith.member(proven)
        if member is None:
            raise HTTPException(
                status_code=403,
                detail="this device is not in the kith and must enroll first",
            )

        # CHECKED HERE, AFTER THE PROOF, for the reason the parameter's own
        # comment gives: the emptiness of this field must never be answerable
        # without an identity.
        if not csr_pem:
            raise HTTPException(status_code=400, detail="no CSR in this request")
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except Exception as exc:  # noqa: BLE001 - every parse failure is one answer
            raise HTTPException(
                status_code=400, detail=f"unreadable CSR: {exc}"
            ) from exc

        offered = key_id(_spki_der(csr.public_key()))
        if offered != proven:
            # 403 AND NOT 400. The request is well formed; the device is asking
            # for something it is not allowed to have. Naming both key ids would
            # help nobody and hand a prober a comparison oracle, so the detail
            # says what the rule is instead.
            state.telemetry.count("device.renew.refused", tags=["reason:different-key"])
            telemetry.event("renewal offered a different key", key_id=proven)
            raise HTTPException(
                status_code=403,
                detail="the CSR carries a different public key. Renewal keeps "
                       "the enrolled key; a new key is a new device and needs a "
                       "pairing code and an administrator.",
            )

        # THE NAME COMES FROM THE CERTIFICATE muster ITSELF SIGNED, not from the
        # CSR and not from the kith. `ca.py` is emphatic that nothing in a CSR is
        # trusted except the public key, so the CSR's subject cannot be used. The
        # kith row would be the obvious other source and is the wrong one: it is
        # written by a DEFERRED write, so a device renewing inside the window
        # after an issuance - or during a store outage - would find no row and be
        # refused for a bookkeeping reason. The presented certificate is muster's
        # own signed assertion of this device's name, it has just been verified,
        # and it is always there.
        current = x509.load_pem_x509_certificate(certificate_pem.encode())
        common = current.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not common:
            raise HTTPException(
                status_code=422,
                detail="the presented certificate has no common name, so muster "
                       "cannot tell what to name the renewal",
            )
        device_name = str(common[0].value)

        # NOT BEFORE muster SAID SO. `renew_after` has been advisory until now -
        # a number handed to devices with nothing enforcing it. Enforcing it here
        # does two jobs: it makes a buggy or hostile client unable to mint a
        # certificate a second and fill `kith_certificate`, and it keeps the
        # answer to "when may a device renew" in ONE place, which is
        # `ca.Identity.renew_after` and not a second copy of that arithmetic.
        #
        # AN ARMED SHORT RENEWAL (muster#22) is the one exception, and it is an
        # administrator's decision about this key_id, never the device's.
        #
        # TAKEN ONCE, HERE, BEFORE THE CHECK, so the decision is atomic. A peek
        # here and a take at issuance would let two concurrent renewals both
        # pass the gate while only one found the entry - and the other would
        # be issued a standard certificate before renew_after.
        said = _renewal_trigger(trigger)
        earliest = _natural_renew_after(current)
        armed = state.short_renewals.take(proven)
        if armed is None and state.kith.now() < earliest:
            state.telemetry.count("device.renew.refused", tags=["reason:too-early"])
            telemetry.event(
                "renewal refused as too early",
                key_id=proven, old_serial=f"{current.serial_number:X}",
                renew_after=earliest.isoformat(), trigger=said,
            )
            raise HTTPException(
                status_code=409,
                detail=f"too early; this certificate may be renewed from "
                       f"{earliest.isoformat()}",
            )

        # NOT AGAIN SO SOON (muster#228). The check above reads the certificate
        # the device PRESENTED, and a device whose last renewal never landed
        # (an unparseable answer, a full disk) presents the old one again, so
        # that check passes on every check-in and each pass would sign another
        # certificate. This reads what muster ITSELF last recorded for the key.
        #
        # AN ARMED SHORT RENEWAL SKIPS IT: one administrator action, one
        # certificate, and refusing after `take` would spend the request.
        #
        # NOT ATOMIC with the issuance below, so two renewals racing inside one
        # request's time can both pass. The storm this bounds is sequential,
        # one per check-in; the race is bounded by the device's own concurrency.
        if armed is None:
            with refusing(
                state,
                kith_store.Unreachable,
                detail="the kith store is unreachable, so muster cannot tell "
                       "when this device last renewed. Retry.",
            ):
                last = state.kith.latest_issued(proven, state.kith.now())
            if last is not None and state.kith.now() - last < RENEWAL_SPACING:
                again = last + RENEWAL_SPACING
                state.telemetry.count(
                    "device.renew.refused", tags=["reason:recently-issued"]
                )
                telemetry.event(
                    "renewal refused as recently issued",
                    key_id=proven, old_serial=f"{current.serial_number:X}",
                    last_issued=last.isoformat(), trigger=said,
                )
                raise HTTPException(
                    status_code=409,
                    detail=f"a certificate was issued to this device recently; "
                           f"renew again from {again.isoformat()}",
                )

        identity = _issue_renewal(
            state, proven, csr.public_bytes(serialization.Encoding.DER),
            device_name, armed,
        )

        # HANDED BACK HERE, NOT LEFT TO BE COLLECTED. Enrollment issues into
        # the kith and makes the device poll, because there a human has to
        # vouch in between. Here the proof already happened in this request, so a
        # collection step would only add a second round trip and a request id
        # that has to travel.
        now = state.kith.now()
        state.kith.issued(
            kith_store.Device(
                key_id=proven,
                fingerprint=fingerprint(_spki_der(csr.public_key())),
                name=device_name,
                first_seen=now,
                last_seen=now,
                # EMPTY, WHICH PRESERVES. `record_issuance` refuses to let an
                # empty role overwrite a set one - written for exactly this, so a
                # re-enrolment cannot silently strip a device. Reading the role
                # out of the kith to write it back would turn every renewal into
                # a store read that could fail, to achieve what leaving it blank
                # already achieves.
                role="",
            ),
            kith_store.Certificate(
                serial=f"{identity.serial:X}",
                request_id=f"renew-{identity.serial:X}",
                not_before=identity.not_before,
                not_after=identity.not_after,
                issued_at=now,
                certificate_pem=identity.certificate_pem.decode(),
                # COLLECTED AT ONCE, because it was: the bytes are in this
                # response. Leaving it NULL would make every renewed certificate
                # look like one a device never picked up.
                collected_at=now,
            ),
        )
        # EVERYTHING muster#22's scheduled-renewal check needs, on one line:
        # which device, which certificate it gave up and which it got, what
        # started the request, and whether this was the one short issuance.
        telemetry.event(
            "device renewed",
            key_id=proven,
            device_name=device_name,
            old_serial=f"{current.serial_number:X}",
            new_serial=f"{identity.serial:X}",
            not_after=identity.not_after.isoformat(),
            renew_after=identity.renew_after().isoformat(),
            trigger=said,
            short_lived_hours=(
                armed.lifetime.total_seconds() / 3600 if armed is not None else None
            ),
        )
        state.telemetry.count(
            "device.renew.issued",
            tags=[f"short:{str(armed is not None).lower()}"],
        )
        return {
            "certificate_pem": identity.certificate_pem.decode(),
            "ca_pem": state.authority.certificate_pem.decode(),
            "not_after": identity.not_after.isoformat(),
            "renew_after": identity.renew_after().isoformat(),
        }


# The least time between two certificates signed for one key by renewal
# (muster#228). Without it a device whose renewal never landed asked again at
# every check-in, up to 96 certificates a day, each one a kith_certificate row
# and a CRL serial. Well under the shortest lifetime an administrator may arm
# (`short_renewal.MIN_HOURS`), so the renewal after a short one is never held
# past that certificate's expiry.
RENEWAL_SPACING = dt.timedelta(hours=1)


# What a device may say started its renewal. Anything else is logged as
# `other`, so a hostile client cannot write arbitrary text into the log line
# muster#22 is read from; an agent that says nothing is `unstated`.
RENEWAL_TRIGGERS = frozenset({"check-in", "catch-up", "boot", "sync"})


def _renewal_trigger(raw: str) -> str:
    if not raw:
        return "unstated"
    return raw if raw in RENEWAL_TRIGGERS else "other"


def _natural_renew_after(certificate) -> dt.datetime:
    """When this certificate may be renewed, through `ca.Identity` and nowhere else."""
    return Identity(
        certificate_pem=b"",
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        serial=certificate.serial_number,
    ).renew_after()


def _advertised_renew_after(
    state: State, proven: str, certificate_pem: str
) -> dt.datetime:
    """What a check-in tells a device about renewing (muster#22).

    The presented certificate's own renew_after, unless an administrator armed a
    short renewal for this key - then now, so the device's next pass renews.
    Disarming goes back to the natural value at the next check-in, so a device
    told "now" by mistake is corrected within one pass.
    """
    from cryptography import x509

    if state.short_renewals.peek(proven) is not None:
        return state.kith.now()
    return _natural_renew_after(
        x509.load_pem_x509_certificate(certificate_pem.encode())
    )


def _issue_renewal(
    state: State,
    proven: str,
    csr_der: bytes,
    device_name: str,
    armed: short_renewal.Armed | None,
) -> Identity:
    """Sign the renewal: short if an administrator armed it, standard otherwise.

    `armed` WAS ALREADY TAKEN by the route, under the store's lock, so two
    renewals racing cannot both come back short. PUT BACK ON FAILURE,
    deliberately: nothing was issued and the device still holds the
    certificate it presented, so a transient refusal must not spend the
    operator's one-shot request, unless the operator cancelled or re-armed
    while it was in flight. The outcome is logged.
    """

    def restore() -> None:
        if armed is not None:
            restored = state.short_renewals.put_back(proven, armed)
            telemetry.event(
                "short renewal restored after a failed issuance" if restored
                else "short renewal not restored: cancelled or re-armed meanwhile",
                key_id=proven,
            )

    try:
        with state.telemetry.timed("ca.issue.duration"):
            if armed is None:
                identity = state.authority.issue(csr_der, device_name)
            else:
                identity = state.authority.issue(
                    csr_der, device_name,
                    lifetime=armed.lifetime, waive_runway_floor=True,
                )
    except Untrusted as bad:
        restore()
        state.telemetry.count("ca.issue.refused", tags=["reason:untrusted-csr"])
        raise HTTPException(status_code=422, detail=str(bad)) from bad
    except BaseException:
        restore()
        raise
    if armed is not None:
        state.short_renewals.spent(proven, armed)
    return identity


def _asset_unavailable(
    state: State, error: type[Exception], reason: str, event: str, **fields
):
    """The asset route's 503 for a store that cannot answer, by reason."""
    return refusing(
        state,
        error,
        detail=str,
        counter="device.asset.refused",
        tags=[f"reason:{reason}"],
        event=event,
        **fields,
    )


def _register_asset_route(app: FastAPI, state: State) -> None:
    """One operator file, for a proven device (muster#45).

    A DEVICE ROUTE, registered with the others since muster#218. It used to sit
    in `_register_kith_routes`, the administrator's registrar, although no
    administrator ever reaches it.
    """

    @_post(app, "/v1/device/asset")
    def device_asset(
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
        # Cloudflare caches on. `UncachedRoute` sets the header on all of them.
        proven = _proven_device(state, nonce, signature_b64, certificate_pem)
        # 503 AND NOT 404 for no source, and the difference is where somebody
        # goes to look. "The operator has not uploaded it" is a policy edit;
        # "the secret did not mount" is a deployment. An optional secret volume
        # that is absent mounts as an empty directory, so these two are
        # indistinguishable from the filesystem and have to be told apart here
        # or not at all.
        #
        # 503, AND NOT A 404, for a share that stopped answering: the asset is
        # almost certainly still there. A 404 would tell the device its
        # wallpaper had been withdrawn, and the agent acts on that - see
        # ConfigurationPolicy: a file absent from a SUCCESSFUL answer is
        # removed from the handset. Retryable is the honest answer.
        with _asset_unavailable(
            state, asset_store.NoSource, "no-source", "muster has no asset store",
            key_id=proven,
        ), _asset_unavailable(
            state, asset_store.Unavailable, "unavailable", "asset store did not answer",
            key_id=proven, name=name,
        ), _asset_unavailable(
            state, asset_store.Unreadable, "unreadable", "asset could not be read",
            key_id=proven, name=name,
        ):
            try:
                asset = state.assets.fetch(name)
            except asset_store.Unknown as unknown:
                # THE SAME ANSWER FOR A MISSING FILE AND AN UNUSABLE NAME. The
                # difference is only ever useful to a caller probing for one - so
                # the cause is chained for the traceback and kept out of `detail`.
                state.telemetry.count("device.asset.refused", tags=["reason:unknown"])
                telemetry.event("device asked for an asset muster does not have",
                                key_id=proven, name=name)
                raise HTTPException(status_code=404, detail="no such asset") from unknown
            except asset_store.TooLarge as too_large:
                state.telemetry.count("device.asset.refused", tags=["reason:too-large"])
                telemetry.event("asset is larger than muster serves",
                                key_id=proven, name=name, error=str(too_large))
                raise HTTPException(status_code=413, detail=str(too_large)) from too_large

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
