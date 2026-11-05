"""Agent distribution: the APK, its description, and the QR that installs it.

Split out of api.py by audience (muster#218). `/agent.apk` and `/agent.json`
are open, because Android's setup wizard on a wiped phone has no credential;
the provisioning QR is administrator-only, because its payload can carry a
network password and a pairing code.
"""
from __future__ import annotations

import hashlib
import io
import os
import pathlib
from typing import TYPE_CHECKING

from fastapi import Body, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse

from muster import provisioning, telemetry
from muster.enroll import DEFAULT_SCANNED_CODE_TTL_S, Shape

if TYPE_CHECKING:
    from muster.api import State


# What /agent.json has already worked out, keyed by the bytes it describes.
# Module level rather than per-app so a test that builds several apps over one
# APK does not re-hash it each time; the key includes the path, so two apps
# serving different files cannot read each other's answer.
_APK_DESCRIPTIONS: dict[tuple[str, int, int], dict] = {}


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
            ttl_s=DEFAULT_SCANNED_CODE_TTL_S,
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
            "expires_in_s": int(DEFAULT_SCANNED_CODE_TTL_S) if carries_code else None,
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


def register(app: FastAPI, state: State, admin) -> None:
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
