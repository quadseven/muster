"""The HTTP surface: four audiences, two of them the open internet.

WHO CAN REACH WHAT, because this is the part that gets it wrong:

    device, unauthenticated    POST /v1/enroll/requests
                               GET  /v1/enroll/requests/{id}/identity
                               POST /v1/auth/challenge
                               POST /v1/auth/verify
                               GET  /agent.apk, /agent.json
    device, proven             POST /v1/device/config
                               POST /v1/device/diagnostics
                               POST /v1/device/report
    administrator, signed in   PUT  /v1/assets/{name}
                               POST /v1/enroll/codes
                               GET  /v1/enroll/requests
                               POST /v1/enroll/requests/{id}/vouch
                               GET  /v1/provision/qr.svg
                               POST /v1/provision/qr
                               GET  /v1/kith
                               GET  /v1/kith/unrecorded
                               GET  /v1/kith/{key_id}
    public, on their own       GET  https://<MUSTER_CRL_URL>
       hostnames               POST https://<MUSTER_OCSP_URL>

THE FOURTH AUDIENCE IS MOUNTED ON HOSTNAMES, NOT PATHS (muster#17). Both
standards conventionally live at `/`, which the console already serves, so
the CRL and the OCSP responder are Starlette Host routes: the hostname from
MUSTER_CRL_URL / MUSTER_OCSP_URL decides which surface answers, and a
request to any other hostname falls through to the console. The URLs are
also stamped into every issued certificate - the CRL distribution point and
the OCSP AIA extension - which is why app_from_env refuses to start without
them: a default there would mint certificates pointing at one hostname while
this pod answers on another, and nothing inside muster would ever notice.

THE MIDDLE AUDIENCE IS A DEVICE THAT HAS ENROLLED (muster#46), and it is the one
that has to be got right next, because everything a device will ever say to
muster goes through it: configuration down, diagnostics up (muster#27),
inventory up (muster#42). Authenticated by the CERTIFICATE and nothing else -
`_proven_device` in device_channel.py is the whole of it, shared with
/v1/auth/verify so there is one scheme rather than two. There is deliberately
no device token: a bearer
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

THIS MODULE IS THE APP FACTORY, AND THE ROUTES LIVE BY AUDIENCE (muster#218):

    routes_enroll.py       enrollment, the device's half and the administrator's
    device_channel.py      a proven device: `_proven_device`, config,
                           diagnostics, report, asset, renewal, wipe, reboot
    routes_kith.py         kith administration
    routes_revocation.py   the CRL and OCSP Host routes
    routes_agent.py        the agent APK and the provisioning QR

`create_app` registers them in the order their paths must match, and keeps the
state, the administrator dependency, asset upload and the health probes.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from muster.ca import Authority
from muster.proof import Proofs
from muster import administrator, console, policy
from muster import assets as asset_store
from muster import kith as kith_store
from muster import device_channel, routes_agent, routes_enroll, routes_kith
from muster import routes_revocation, telemetry
from muster.enroll import Enrollment
from muster.short_renewal import ShortRenewals

# RE-EXPORTED, NOT DEFINED HERE. The enrollment refusal map lives with the
# enrollment routes (routes_enroll.py) since muster#218; these names stay
# importable from muster.api because that is where the status map has been
# read from, including by tools/check_status_map.py before it moved.
_STATUS = routes_enroll._STATUS
DEVICE_FACING = routes_enroll.DEVICE_FACING


CHECK_IN_METRIC_INTERVAL_S = float(
    os.environ.get("MUSTER_CHECK_IN_METRIC_INTERVAL_S", "60")
)
if CHECK_IN_METRIC_INTERVAL_S <= 0:
    raise ValueError("MUSTER_CHECK_IN_METRIC_INTERVAL_S must be positive")


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
    # Certificates signed but not yet collected, BY REQUEST ID. A cache of the
    # kith store, not the only copy (muster#243): the certificate is written
    # to the store at issuance too, so any replica can hand it over, and this
    # only spares the store read - which is what serves the poll during a
    # store outage, when that read would 503.
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
    diagnostic_lock: threading.Lock = field(default_factory=threading.Lock)
    diagnostic_last_sent: dict[str, float] = field(default_factory=dict)
    # A SEPARATE LEDGER, same lock. The agent sends diagnostics and its report
    # at the end of the same check-in, so one shared slot would refuse the
    # second every time.
    report_last_sent: dict[str, float] = field(default_factory=dict)
    # Which device gets its NEXT renewal short-lived (muster#22). In memory on
    # purpose: see short_renewal.py for why a restart forgetting it is safe.
    short_renewals: ShortRenewals = field(default_factory=ShortRenewals)


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


async def _check_in_absence_ticks(
    emitter: telemetry.Telemetry,
    stop: asyncio.Event,
    interval_s: float = CHECK_IN_METRIC_INTERVAL_S,
) -> None:
    """Keep the DogStatsD check-in count series present during quiet periods."""
    if interval_s <= 0:
        raise ValueError("check-in metric interval must be positive")
    while True:
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
            return
        except TimeoutError:
            emitter.check_in_absence_tick()


@contextlib.asynccontextmanager
async def _check_in_metric_lifecycle(emitter: telemetry.Telemetry):
    """Run and stop the periodic check-in metric task with the application."""
    stop = asyncio.Event()
    task = asyncio.create_task(_check_in_absence_ticks(emitter, stop))
    try:
        yield
    finally:
        stop.set()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


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
        """Start the things that must run without a request, and stop them.

        The kith flusher retries deferred writes; the enrollment sweeper bounds
        the pairing-code table. WITHOUT EITHER, the mechanism is decoration:
        deferred writes are otherwise replayed only by the next enrollment,
        proof or console load, and muster is quiet by design - devices renew
        every ninety days. A store that comes back an hour after it went away
        would keep the rows in memory until something happened to knock on it,
        and a pod restarted first loses them; codes minted by every drawn QR
        would accumulate on the CA process for the life of the pod.
        """
        state.kith.start_flushing()
        state.enrollment.start_sweeping()
        try:
            async with _check_in_metric_lifecycle(state.telemetry):
                yield
        finally:
            state.enrollment.stop_sweeping()
            state.kith.stop_flushing()

    app = FastAPI(
        title="muster", version="0.1.0", lifespan=lifespan,
        docs_url=None, redoc_url=None,
    )
    routes_revocation.register(app, state)
    # Before any route is registered, and in an order this asserts: who is
    # acting has to be established before anything writes down what they did.
    console.install_middleware(app, state)
    admin = Depends(_require_admin(state))

    # ---- administrator ---------------------------------------------------

    @app.put("/v1/assets/{name}", dependencies=[admin])
    async def upload_asset(name: str, request: Request):
        """Publish one asset from an authenticated operator session."""
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > asset_store.MAX_BYTES:
                    raise HTTPException(status_code=413, detail="asset is too large")
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail="invalid content length"
                ) from exc

        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > asset_store.MAX_BYTES:
                raise HTTPException(status_code=413, detail="asset is too large")
            chunks.append(chunk)
        # OFF THE EVENT LOOP. This route is `async` so it can stream the body,
        # and `put` blocks: a bounded wait on the share, then an fsync of up to
        # MAX_BYTES to it. Called directly it would hold the one loop every
        # other route is served from, so a wedged share under one upload
        # would stall /readyz, configuration and renewal for the full bound.
        try:
            asset = await run_in_threadpool(state.assets.put, name, b"".join(chunks))
        except asset_store.Unknown as unknown:
            raise HTTPException(status_code=400, detail=str(unknown)) from unknown
        except asset_store.TooLarge as too_large:
            raise HTTPException(status_code=413, detail=str(too_large)) from too_large
        except asset_store.NoSource as no_store:
            raise HTTPException(status_code=503, detail=str(no_store)) from no_store
        except asset_store.Unavailable as unavailable:
            raise HTTPException(status_code=503, detail=str(unavailable)) from unavailable

        state.telemetry.count("admin.asset.uploaded")
        telemetry.event(
            "asset uploaded",
            name=asset.name,
            bytes=len(asset.content),
            digest=asset.digest,
        )
        return {
            "name": asset.name,
            "bytes": len(asset.content),
            "digest": asset.digest,
        }

    # BY AUDIENCE, in the order the routes must match: the kith registrar
    # puts `/v1/kith/unrecorded` ahead of `/v1/kith/{key_id}` itself.
    routes_enroll.register(app, state, admin)
    device_channel.register(app, state)
    routes_agent.register(app, state, admin)
    routes_kith.register(app, state, admin)
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

    # The revocation URLs go INTO every certificate muster issues - the CRL
    # distribution point and the OCSP entry of the authority information
    # access extension - and each hostname is the one the matching public
    # endpoint below answers on. Read from the environment rather than
    # defaulted, for the same reason MUSTER_BASE_URL is: nothing inside
    # muster ever follows either URL, so a default that ships is a silent
    # one. A pod that comes up half-configured here would mint certificates
    # pointing at an unreachable example URI, and listen for revocation
    # checks on a hostname no request ever arrives with.
    crl_url = os.environ.get("MUSTER_CRL_URL", "")
    ocsp_url = os.environ.get("MUSTER_OCSP_URL", "")
    if not crl_url or not ocsp_url:
        raise RuntimeError(
            "MUSTER_CRL_URL and MUSTER_OCSP_URL must both be set. Each is "
            "stamped into every certificate muster issues - the CRL "
            "distribution point and the OCSP entry of the authority "
            "information access extension - and each hostname is the one "
            "the matching public endpoint answers on. Defaulting them would "
            "mint certificates pointing at an unreachable example URI and "
            "listen for revocation checks on a hostname no request arrives "
            "with, and neither failure is visible from inside muster."
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
        crl_url=crl_url,
        ocsp_url=ocsp_url,
        administrators=len(subjects),
    )

    authority = Authority.load(
        key_path, cert_path, crl_url=crl_url, ocsp_url=ocsp_url
    )
    clock = lambda: dt.datetime.now(dt.timezone.utc).timestamp()  # noqa: E731

    # The callback URL is derived from MUSTER_BASE_URL rather than configured
    # separately, for the reason that variable exists at all: the request's
    # Host is whatever a proxy says it is, and a redirect URL taken from a
    # header is one an attacker can aim. It must match the one registered with
    # the provider exactly - see docs/administrator-sign-in.md.
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
    #
    # The enrollment ceremony shares the same store (muster#243): one records
    # object, handed to both the kith and the pairing-code state machine, so
    # a code minted by one replica is claimable on another.
    records = kith_store.records_from_env()
    kith = kith_store.Kith(
        records,
        clock=lambda: dt.datetime.now(dt.timezone.utc),
        emitter=emitter,
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

    return create_app(
        State(
            enrollment=Enrollment(clock=clock, store=records),
            authority=authority,
            sign_in=sign_in,
            cookie_secure=os.environ.get("MUSTER_COOKIE_SECURE", "true").lower()
            != "false",
            proofs=Proofs(
                clock=clock,
                ca_certificate=authority.certificate_chain[0],
                ca_chain=authority.certificate_chain,
            ),
            base_url=base_url,
            agent_apk=agent_apk,
            telemetry=emitter,
            kith=kith,
            policies=policies,
            assets=assets_held,
        )
    )
