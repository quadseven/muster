"""The console: signing in, signing out, what is recorded, and what may run.

The whole point of this file is the things that are true when nobody is
watching - that the record of a vouch names a person, that the page cannot load
anything from anywhere else, and that a stack of middleware in the wrong order
is caught at startup rather than discovered when somebody needs the log.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import re
import urllib.parse

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from muster import console
from muster.administrator import Provider
from muster.api import State, create_app
from muster.ca import Authority
from muster.enroll import Enrollment
from tests.conftest import (
    ADMIN_SUBJECT,
    AUTHORIZE_URL,
    CLIENT_ID,
    ISSUER,
    JWKS_URL,
    STRANGER_SUBJECT,
    TOKEN_URL,
)

def build_state(provider, **overrides) -> State:
    settings = {
        "enrollment": Enrollment(clock=lambda: 1000.0),
        "authority": Authority.create(
            "muster test CA",
            clock=lambda: dt.datetime(2026, 8, 18, tzinfo=dt.timezone.utc),
        ),
        "sign_in": provider.sign_in(),
        # TestClient talks http, and a browser does not store a Secure cookie
        # from an http origin - so the tests that follow a session turn it off
        # and one test below asserts it is on by default.
        "cookie_secure": False,
        "base_url": "https://muster.example.test",
    }
    settings.update(overrides)
    return State(**settings)


@pytest.fixture()
def state(provider):
    return build_state(provider)


@pytest.fixture()
def client(state):
    return TestClient(create_app(state))


def sign_in_with(client, provider) -> None:
    """Walk the whole flow the way a browser would, and leave it signed in."""
    started = client.get("/auth/signin", follow_redirects=False)
    assert started.status_code == 303
    code, flow = provider.redeem(started.headers["location"])
    landed = client.get(
        f"/auth/callback?code={code}&state={urllib.parse.quote(flow)}",
        follow_redirects=False,
    )
    assert landed.status_code == 303, landed.text
    assert landed.headers["location"] == "/"


# ---- signing in -----------------------------------------------------------


def test_an_administrator_signs_in_and_can_vouch(client, provider):
    """The acceptance criterion, end to end: no token typed anywhere."""
    assert client.get("/v1/enroll/requests").status_code == 401

    sign_in_with(client, provider)

    session = client.get("/v1/session").json()
    assert session["signed_in"] is True
    assert session["subject"] == ADMIN_SUBJECT
    assert client.get("/v1/enroll/requests").status_code == 200


def test_the_browser_is_sent_to_the_provider_and_nowhere_else(client, provider):
    started = client.get("/auth/signin", follow_redirects=False)
    assert started.headers["location"].startswith(AUTHORIZE_URL)


def test_a_session_can_be_ended(client, provider):
    sign_in_with(client, provider)
    assert client.get("/v1/enroll/requests").status_code == 200

    client.post("/auth/signout")

    assert client.get("/v1/session").json()["signed_in"] is False
    assert client.get("/v1/enroll/requests").status_code == 401


def test_signing_out_says_where_to_end_it_at_the_provider_too(provider):
    """Otherwise signing out here leaves a session there that signs the next
    person straight back in with one click and no password."""
    state = build_state(
        provider,
        sign_in=provider.sign_in(
            provider=Provider(
                issuer=ISSUER,
                jwks_url=JWKS_URL,
                authorize_url=AUTHORIZE_URL,
                token_url=TOKEN_URL,
                client_id=CLIENT_ID,
                end_session_url="https://identity.example.test/logout",
            )
        ),
    )
    client = TestClient(create_app(state))
    sign_in_with(client, provider)

    onward = client.post("/auth/signout").json()["next"]
    assert onward.startswith("https://identity.example.test/logout?")


def test_a_callback_in_a_browser_that_did_not_start_it_is_refused(client, provider):
    """Login CSRF, which the `state` parameter alone does not stop.

    The flow store is one dict for the whole process, so a returned state proves
    that SOME browser started a sign-in here. An attacker starts one, takes the
    state, and hands the operator a link carrying an authorization code for
    their own account - and the operator is signed in as somebody else without
    noticing, on the console that vouches for devices. The flow cookie is what
    makes the two the same browser.
    """
    started = client.get("/auth/signin", follow_redirects=False)
    code, flow = provider.redeem(started.headers["location"])
    client.cookies.delete(console.FLOW_COOKIE, path="/auth")

    landed = client.get(
        f"/auth/callback?code={code}&state={flow}", follow_redirects=False
    )

    assert landed.status_code == 403
    assert "did not start in this browser" in landed.text
    # And the code was never spent: the exchange is refused before it happens.
    assert provider.token_requests == []


def test_a_browser_holding_a_stale_cookie_can_still_sign_in(client, provider):
    """The bug this was written against, found by actually signing in.

    A cookie left over from a server that has been restarted cannot be verified,
    so the middleware clears it - correctly. But it saw the request as it
    ARRIVED, and on the callback the handler has just set a good session on the
    way out. Clearing over the top of that deletes the session the browser was
    just given, and the symptom is a sign-in button that appears to do nothing,
    forever, with nothing in the log.
    """
    client.cookies.set(console.SESSION_COOKIE, "left-over-from-a-previous-run")

    started = client.get("/auth/signin", follow_redirects=False)
    code, flow = provider.redeem(started.headers["location"])
    landed = client.get(
        f"/auth/callback?code={code}&state={flow}", follow_redirects=False
    )

    assert landed.status_code == 303
    attached = landed.headers.get_list("set-cookie")
    session = [v for v in attached if v.startswith(console.SESSION_COOKIE)]
    assert len(session) == 1, attached
    assert "Max-Age=0" not in session[0]
    assert client.get("/v1/session").json()["signed_in"] is True


def test_the_session_cookie_is_out_of_reach_of_any_script(client, provider):
    """A cookie a script can read is the shared token in a different shirt."""
    started = client.get("/auth/signin", follow_redirects=False)
    code, flow = provider.redeem(started.headers["location"])
    landed = client.get(
        f"/auth/callback?code={code}&state={flow}", follow_redirects=False
    )

    attached = landed.headers.get_list("set-cookie")
    session = [value for value in attached if value.startswith(console.SESSION_COOKIE)]
    assert session, attached
    assert "HttpOnly" in session[0]
    assert "SameSite=lax" in session[0].replace("samesite", "SameSite")


def test_the_session_cookie_is_marked_secure_unless_told_otherwise(provider):
    state = build_state(provider, cookie_secure=True)
    client = TestClient(create_app(state))
    started = client.get("/auth/signin", follow_redirects=False)
    code, flow = provider.redeem(started.headers["location"])
    landed = client.get(
        f"/auth/callback?code={code}&state={flow}", follow_redirects=False
    )
    assert "Secure" in landed.headers.get_list("set-cookie")[0]


def test_somebody_else_in_the_estate_is_told_why_they_cannot_come_in(
    client, provider
):
    """The pool is shared. Having an account is not being an administrator, and
    a refusal that says nothing sends the operator to read server logs."""
    provider.subject = STRANGER_SUBJECT
    started = client.get("/auth/signin", follow_redirects=False)
    code, flow = provider.redeem(started.headers["location"])

    refused = client.get(
        f"/auth/callback?code={code}&state={flow}", follow_redirects=False
    )

    assert refused.status_code == 403
    assert STRANGER_SUBJECT in refused.text
    assert "Back to Muster" in refused.text
    assert client.get("/v1/session").json()["signed_in"] is False


def test_a_session_is_renewed_in_place_rather_than_interrupting_a_vouch(
    client, provider, state
):
    """An hour-old console must not bounce the operator to the provider in the
    middle of comparing a fingerprint."""
    client.cookies.set(console.SESSION_COOKIE, provider.id_token(expires_in=-60))
    client.cookies.set(console.RENEWAL_COOKIE, "renewal-token")

    response = client.get("/v1/enroll/requests")

    assert response.status_code == 200
    assert any(
        value.startswith(console.SESSION_COOKIE)
        for value in response.headers.get_list("set-cookie")
    )
    assert "custom.muster.auth.session.renewed:1|c" in state.telemetry.sent


def test_requests_racing_to_renew_spend_the_token_once(provider):
    """A refresh token presented twice is a replay, and it is answered as one.

    Every request from a browser with an expired session tries to renew, and the
    console has several in flight at any moment - a poll, a page load, a section
    change. Without a single flight they all post the SAME refresh token: a
    provider that rotates accepts the first and refuses the rest, so five of six
    responses would clear the cookie and the operator would be signed out. On a
    provider with reuse detection it revokes the whole family.

    TestClient cannot express this - it is serial - so this drives the app
    directly with six coroutines in flight at once.
    """
    state = build_state(provider)
    app = create_app(state)
    session = provider.id_token(expires_in=-60)

    async def race():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://muster.test"
        ) as client:
            client.cookies.set(console.SESSION_COOKIE, session)
            client.cookies.set(console.RENEWAL_COOKIE, "renewal-token")
            return await asyncio.gather(
                *(client.get("/v1/session") for _ in range(6))
            )

    answers = asyncio.run(race())

    assert [a.json()["signed_in"] for a in answers] == [True] * 6
    assert len(provider.token_requests) == 1, provider.token_requests


def test_a_provider_having_a_bad_morning_does_not_sign_anybody_out(provider):
    """Clearing the cookie here would be the worst possible response: the
    operator is signed out, and cannot sign back in either, because the thing
    that is down is the thing they would sign in at."""

    def unreachable(request):
        raise httpx.ConnectError("no route to host")

    state = build_state(
        provider, sign_in=provider.sign_in(transport=httpx.MockTransport(unreachable))
    )
    client = TestClient(create_app(state))
    client.cookies.set(console.SESSION_COOKIE, provider.id_token())

    response = client.get("/v1/enroll/requests")

    assert response.status_code == 401
    assert not response.headers.get_list("set-cookie")
    assert client.cookies.get(console.SESSION_COOKIE)


def test_a_session_that_cannot_be_verified_is_cleared(client, state):
    """Otherwise a cookie left over from a reconfigured provider wedges the
    console for good, and the only symptom is a button that does nothing."""
    client.cookies.set(console.SESSION_COOKIE, "not-a-token")

    response = client.get("/v1/session")

    assert response.json()["signed_in"] is False
    assert any(
        value.startswith(console.SESSION_COOKIE) and "Max-Age=0" in value
        for value in response.headers.get_list("set-cookie")
    ), response.headers.get_list("set-cookie")
    assert any(
        line.startswith("custom.muster.auth.session.refused:1|c|#reason:")
        for line in state.telemetry.sent
    )


def test_a_server_with_no_sign_in_configured_says_so_rather_than_pretending(
    provider,
):
    state = build_state(provider, sign_in=None)
    client = TestClient(create_app(state))

    assert client.get("/v1/session").json()["sign_in_configured"] is False
    assert client.get("/auth/signin").status_code == 503
    assert client.get("/v1/enroll/requests").status_code == 401


# ---- what gets written down -----------------------------------------------


def test_an_administrative_action_records_which_identity_performed_it(
    client, provider, state, caplog
):
    caplog.set_level(logging.INFO, logger="muster")
    sign_in_with(client, provider)

    client.post("/v1/enroll/codes", json={})

    recorded = [r for r in caplog.records if r.message == "administrative action"]
    assert recorded, [r.message for r in caplog.records]
    assert recorded[-1].fields["actor"] == ADMIN_SUBJECT
    assert recorded[-1].fields["route"] == "/v1/enroll/codes"
    assert "custom.muster.admin.action:1|c|#principal:administrator,outcome:accepted" in (
        state.telemetry.sent
    )


def test_the_record_of_a_vouch_never_carries_the_request_id(
    client, provider, caplog
):
    """The request id is a bearer secret - it is all a device needs to collect
    a certificate - so the raw path must never reach the log stream, which is
    the one place a secret cannot be deleted from afterwards."""
    caplog.set_level(logging.INFO, logger="muster")
    sign_in_with(client, provider)

    client.post(
        "/v1/enroll/requests/a-request-id-that-is-a-secret/vouch",
        json={"fingerprint": "whatever"},
    )

    recorded = [r for r in caplog.records if r.message == "administrative action"]
    assert recorded[-1].fields["route"] == "/v1/enroll/requests/{request_id}/vouch"
    assert "a-request-id-that-is-a-secret" not in str(recorded[-1].fields)


def test_reading_the_pending_list_is_not_recorded_as_an_action(
    client, provider, caplog
):
    """The console polls this every two seconds. A record per poll buries the
    one line that matters under a thousand that do not."""
    caplog.set_level(logging.INFO, logger="muster")
    sign_in_with(client, provider)
    caplog.clear()

    client.get("/v1/enroll/requests")

    assert not [r for r in caplog.records if r.message == "administrative action"]


def test_a_device_enrolling_is_not_an_administrative_action(client, caplog):
    caplog.set_level(logging.INFO, logger="muster")

    client.post(
        "/v1/enroll/requests",
        json={"code": "000000", "csr_pem": "nonsense", "device_name": "pixel-6a"},
    )

    assert not [r for r in caplog.records if r.message == "administrative action"]


# ---- the order that makes the record worth having --------------------------


def test_the_middleware_order_is_asserted_at_composition_time(state):
    """Not documented and hoped for. A reorder has to fail loudly at startup,
    because its only other symptom is a log that says anonymous forever."""
    wrong = FastAPI()
    wrong.add_middleware(console.AdministratorMiddleware, state=state)
    wrong.add_middleware(console.ActionRecordMiddleware, state=state)

    with pytest.raises(RuntimeError) as complaint:
        console.assert_middleware_order(wrong)
    assert "anonymous" in str(complaint.value)


def test_recording_before_identity_would_record_nobody(
    client, state, provider, caplog
):
    """The failure the assertion above prevents, demonstrated rather than
    asserted about. With the stack upside down the request is still served, the
    vouch still happens, and nothing is written down at all."""
    sign_in_with(client, provider)
    session_cookie = client.cookies[console.SESSION_COOKIE]

    caplog.set_level(logging.INFO, logger="muster")
    upside_down = FastAPI()
    upside_down.add_middleware(console.AdministratorMiddleware, state=state)
    upside_down.add_middleware(console.ActionRecordMiddleware, state=state)

    @upside_down.post("/v1/enroll/codes")
    def mint():
        return {"code": "123456"}

    upside_down_client = TestClient(upside_down)
    upside_down_client.cookies.set(console.SESSION_COOKIE, session_cookie)
    assert upside_down_client.post("/v1/enroll/codes", json={}).status_code == 200

    assert not [r for r in caplog.records if r.message == "administrative action"]


# ---- what the page may load ------------------------------------------------


def test_the_console_permits_no_script_it_did_not_ship_with(client):
    """docs/observability.md records why: this is the page the administrator's
    credential is handled on, on the service that holds the CA. A promise in a
    document is not a control, so the header enumerates what may run."""
    response = client.get("/")
    policy = response.headers["content-security-policy"]

    assert "default-src 'none'" in policy
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    # Nothing from anywhere else, by any route a script could take.
    assert "connect-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "https://" not in policy


def test_only_the_page_muster_served_may_run(client):
    """The nonce is the mechanism: an injected <script> without it does not run,
    and it cannot be guessed because it changes every response."""
    first = client.get("/")
    second = client.get("/")

    nonce = re.search(r"script-src 'nonce-([^']+)'", first.headers["content-security-policy"])
    assert nonce is not None
    assert f'<script nonce="{nonce.group(1)}">' in first.text
    assert first.headers["content-security-policy"] != (
        second.headers["content-security-policy"]
    )


def test_no_script_on_the_console_touches_the_way_in(client):
    """What muster#40 deleted, stated as the rule rather than as the symptom.

    A session lives in an HttpOnly cookie the browser attaches on its own; no
    script on the page can read it, and none should be able to name a header
    or a credential to attach by hand.

    THE WIFI PASSWORD IS NOT THAT, and the distinction is worth stating rather
    than leaving to whoever reads this next. The script does read that field:
    it is the payload of a QR the operator is deliberately putting on their own
    screen, it is a credential for a network and not for muster, and no amount
    of it grants anything here. The console says so in the clear beside the
    field.
    """
    body = client.get("/").text
    assert "MUSTER_ADMIN_TOKEN" not in body
    assert "Authorization" not in body, "the page is attaching a credential by hand"


def test_the_provisioning_qr_is_reachable_from_the_page(client):
    """muster#47's complaint, as a test: the endpoint existed, worked, was
    admin-only, and was in no console anywhere. The QR that provisioned the
    first handset was generated from a terminal, which is not a thing an
    operator can be asked to do while holding a wiped phone.

    An endpoint nothing links to is an endpoint nobody has.
    """
    body = client.get("/").text

    assert "/v1/provision/qr" in body, "the console cannot show a provisioning QR"
    assert 'data-section="provision"' in body, "there is no way to get to it"
    # The three things a QR commits to that a person can check. Named on the
    # page, because a QR is opaque and the checksum is the field that decides
    # whether a wiped phone provisions or resets itself.
    for fact in ("Download URL", "Signing certificate", "Server address"):
        assert fact in body, f"the QR does not say what it commits to: {fact}"
    # And the check that it describes what is published right now.
    assert "/agent.json" in body


def test_the_console_draws_no_qr_that_nothing_can_read(client):
    """The pairing QR had no consumer: the agent declares no CAMERA permission,
    contains no scanner, and EnrollActivity has only MAIN/LAUNCHER. Drawing it
    taught an operator to expect a scan that could never happen."""
    body = client.get("/").text

    # The pairing QR's path, and nothing else on the page, starts this way:
    # minting posts to /v1/enroll/codes with no trailing slash.
    assert "/v1/enroll/codes/" not in body, "the console is drawing the pairing QR again"
    assert "Pairing QR" not in body


def test_the_page_asks_a_different_question_of_a_scanned_request(client):
    """THE CHECK THAT CANNOT BE MADE MUST NOT BE ASKED FOR.

    The vouch dialog told every operator to "read the fingerprint on the
    device's own screen". On a request that presented from a provisioning QR
    there is no device screen and no second copy of that fingerprint anywhere -
    the whole point is that nobody is holding the phone. Asking anyway leaves an
    operator two moves, and both are bad: cancel a device that is theirs, or
    click through and learn that the words above the button mean nothing.

    So the page carries BOTH questions and picks on `shape`, which the pending
    list reports. See CONTEXT.md for what a scanned vouch actually confirms.
    """
    body = client.get("/").text

    # THE CALL SITE, NOT THE DEFINITION. Wording written for both shapes and
    # then never selected between is the failure this whole repository keeps
    # finding: it reads correct, the page renders, and every operator is asked
    # the same wrong question. So this asserts the lookup is BY SHAPE.
    assert "CONFIRM[request.shape]" in body, (
        "the confirm dialog picks its words without looking at the shape, so "
        "one of the two requests is being asked a question it cannot answer"
    )
    assert "confirm-lede" in body and "confirm-question" in body, (
        "the dialog's words are fixed in the markup, so nothing can swap them"
    )
    # Both shapes the server can report have wording written for them.
    for shape in ("typed:", "scanned:"):
        assert shape in body, f"no wording for a {shape} request"
    # And the scanned wording does NOT ask for a comparison that cannot be made.
    scanned = body.split("scanned: {", 1)[1].split("},", 1)[0]
    assert "no second copy" in scanned
    assert "device's own screen" not in scanned, (
        "the scanned wording still points at a screen nobody is looking at"
    )


def test_a_pending_row_says_which_kind_of_vouch_it_is_asking_for(client):
    """Before the operator opens anything. Two rows drawn identically is the
    console telling them a fingerprint with no second copy is one they
    compared - and the row is where they decide which to open first."""
    body = client.get("/").text

    assert "SHAPES[request.shape]" in body, (
        "the pending row does not draw the shape, so both look the same"
    )
    assert "typed: 'typed on the device'" in body
    assert "scanned: 'scanned from a QR'" in body


def test_the_page_counts_down_the_qr_it_is_showing(client):
    """A QR carrying a pairing code stops working while it is on the monitor.

    Everything else the QR commits to is stable for the life of the signing key.
    The code dies in minutes, and a QR scanned after that provisions a phone
    that then cannot enroll - with nothing on the handset explaining why, which
    is the worst place for this to be discovered.
    """
    body = client.get("/").text

    # CALLED, not merely written. A countdown function nobody invokes leaves the
    # panel exactly as it was before this existed - a QR with no expiry on it -
    # while every assertion about the function's contents still passes.
    assert "describePairing(facts, qr.pairing)" in body, (
        "the countdown is defined and never drawn"
    )
    assert "setInterval" in body, "a static number is wrong the moment it is drawn"
    assert "clearInterval" in body, "the countdown outlives the QR it describes"
    assert "Draw a new one" in body, "it says time is up without saying what to do"


def test_the_pairing_code_is_never_rendered_as_text_beside_its_own_qr(client):
    """The page prints every key in the admin extras bundle generically, which
    is right for values an operator checks and wrong for one they hold. The
    server pops the code out before answering; this asserts the page is not
    quietly putting it back, because a credential printed beside the image that
    already carries it is a second place it can be read from."""
    body = client.get("/").text

    assert "muster.pairing_code" not in body, (
        "the console names the pairing code key, which is how it would come to "
        "be rendered"
    )


def test_wifi_credentials_are_opt_in_and_said_out_loud(client):
    """The endpoint's docstring already says this payload can carry a network
    password in clear text. The console has to say it where somebody is about
    to do it, not in a docstring they will never open."""
    body = client.get("/").text

    assert "<details id=\"wifi\"" in body, "wifi is not opt-in"
    assert "clear text" in body
    assert "photograph" in body, "it does not say what putting it on a screen means"


def test_the_console_shows_no_number_that_is_always_wrong(client):
    """docs/brand.md: muster has no concept of a device being online, so an
    Offline count would report a healthy estate as broken. It manages Android,
    and it collects no posture. These are the things most likely to be added by
    accident, because they are the easiest to draw."""
    body = client.get("/").text
    visible = re.sub(r"<!--.*?-->", "", body, flags=re.S)
    for invention in ("Offline", "Online", "iOS", "macOS", "Windows", "Compliance"):
        assert invention not in visible, f"the console invented {invention}"


def test_the_devices_section_can_queue_and_cancel_a_named_wipe(client):
    """The destructive device action belongs on the device row, not in a
    terminal, and every confirmation has to identify the device it will erase.

    The revoke control is disabled while an erase is pending: D29 says that
    revoking first removes the only channel the erase can travel down.
    """
    body = client.get("/").text

    assert "refreshDevices" in body
    assert "/v1/kith/" in body and "/wipe" in body
    assert "Queue erase" in body
    assert "Call off erase" in body
    assert "Erase queued - waiting for check-in" in body
    assert "revoke.disabled" in body
    assert "Do not revoke it first" in body
    assert "device-action-name" in body


def test_the_product_is_capitalized_wherever_a_person_reads_it(client):
    """The Android agent already has this guard (#32). The console is the other
    surface a person reads, and it was the one still saying it in lower case."""
    body = client.get("/").text
    visible = re.sub(
        r"<!--.*?-->|<style.*?</style>|<script.*?</script>", "", body, flags=re.S
    )
    # THE VERB IS EXCLUDED, and the exclusion is the interesting part. "To
    # muster is to assemble a company and take the roll" is the sentence
    # CONTEXT.md and the README both open with, and capitalizing it there would
    # be wrong in the same way capitalizing a hostname would be. The Android
    # guard excludes URLs for exactly this reason.
    visible = visible.replace("To muster is to assemble a company", "")
    assert "Muster" in visible
    assert "muster" not in visible, "lower-case muster is on screen"


# ---- roles in the console (muster#70) ------------------------------------


def _console_html() -> str:
    from muster.console import _CONSOLE_HTML

    return _CONSOLE_HTML


def test_the_console_offers_a_role_when_minting_a_qr():
    """muster#70's first criterion, which is otherwise a claim about markup
    nobody checked. The field has to exist, and the request has to carry it -
    an input that is never read is the same as no input."""
    html = _console_html()
    assert 'id="qr-role"' in html, "no role field on the provisioning form"
    assert "role: $('qr-role').value.trim()" in html, "the field is never sent"


def test_the_console_shows_the_role_beside_the_qr():
    """muster#70's second criterion. The role is the one thing on that panel an
    operator can actually check before scanning - everything else is opaque or
    stable - and getting it wrong is a phone that comes up the wrong kind of
    device with nothing on it saying so."""
    html = _console_html()
    assert "pairing.role" in html, "the role is never drawn beside the QR"
    # And it says something when there is none, rather than showing a blank row
    # that reads like a bug.
    assert "kith policy and nothing else" in html


def test_the_console_never_prints_a_pairing_code_beside_its_own_qr():
    """Unchanged by roles and re-asserted here because the role sits in the same
    dict: the code is a value an operator HOLDS, the role is one they CHECK, and
    adding the second must not have loosened the first."""
    html = _console_html()
    assert "pairing.code" not in html
