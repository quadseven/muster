"""The console's HTTP surface: who is driving it, and what that is recorded as.

TWO MIDDLEWARE, AND THE ORDER BETWEEN THEM IS LOAD-BEARING.

    outer   AdministratorMiddleware   works out who is acting
    inner   ActionRecordMiddleware    writes down what they did

`ActionRecordMiddleware` reads the actor the one above it stamped, on the way
in. Swapped, there would be nothing to read: no exception, no failing request,
just a log where every record says `anonymous` - one that looks healthy and
answers no question anyone will ever ask it. The estate has hit this exact trap
before, so `assert_middleware_order` turns it into a startup crash rather than
trusting the next person to read this comment.

NEITHER MIDDLEWARE EVER REFUSES A REQUEST. Establishing who is acting and
deciding whether that is enough are separate jobs, and only the second one
belongs on a route. Enrollment depends on it: a device presenting a CSR has no
credential and cannot be given one, so `/v1/enroll/requests` and the proof
endpoints must stay reachable by a caller with nothing. A middleware that
rejects by path prefix cannot express that anyway - `POST /v1/enroll/requests`
is the device's way in and `GET /v1/enroll/requests` is the administrator's
pending list, same path, different audience. So authorization stays where the
audience is already documented: a dependency on each administrator route, and a
test that every route in the app is deliberately on one side or the other.

THE PAGE CARRIES A CSP AND THAT IS THE POINT. docs/observability.md records why
this page takes no third-party script: it is the administrator's surface on the
service that holds the CA, so anything running here runs with their session and
can vouch for a device. A promise in a document is not a control, so the header
enumerates what may run - a per-response nonce and nothing else - and a test
asserts it. The framework's own /docs page is off for the same reason: it loads
its script from a public CDN, on this origin.
"""
from __future__ import annotations

import html
import pathlib
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from muster import administrator as admin_module
from muster import telemetry

if TYPE_CHECKING:  # pragma: no cover - import cycle, types only
    from muster.api import State

# The session token, and the token that renews it. Both HttpOnly: a script on
# this page must never be able to read either, which is the whole reason the
# session lives in a cookie instead of in a variable the way the shared token
# used to.
SESSION_COOKIE = "muster_session"
RENEWAL_COOKIE = "muster_renewal"

# The sign-in in progress, which is how muster knows the browser that came back
# is the browser that left. The flow store on the server is one dict for the
# whole process: matching a returned `state` against it proves only that SOME
# sign-in started here. An attacker can start one, take the state, and hand the
# operator a link to /auth/callback carrying an authorization code for their own
# account - and the operator would be signed in as them without noticing.
#
# SameSite=Lax and not Strict, deliberately. The callback is a top-level GET
# navigation FROM the provider, which is cross-site: Strict withholds the cookie
# on exactly that navigation, and every sign-in would fail with a message about
# not having started in this browser.
FLOW_COOKIE = "muster_flow"

# NEITHER SESSION COOKIE CARRIES A Max-Age, so both die when the browser does.
# The token inside the first one expires on its own `exp` claim within the hour
# anyway; giving the second one a lifetime in days would be saying that a closed
# browser is still signed in to the service that holds the CA. Renewal exists to
# get an operator through a long afternoon, not through a weekend.


@dataclass(frozen=True)
class Actor:
    """Who is making this request.

    `kind` is a closed set so it can be a metric tag. `subject` is the
    provider's immutable handle for a person and is empty for everything else.
    """

    kind: str
    subject: str = ""
    email: str = ""

    @property
    def signed_in(self) -> bool:
        return self.kind != "anonymous"

    @property
    def record(self) -> str:
        """What goes in the log. The subject, because it identifies exactly one
        account forever; never the email, which can move to somebody else."""
        return self.subject or self.kind


ANONYMOUS = Actor(kind="anonymous")

_METHODS_THAT_CHANGE_SOMETHING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Refusals that describe the provider rather than the cookie. A session that
# fails for one of these is worth presenting again in a minute; one that fails
# for any other reason never will be.
_WORTH_RETRYING = frozenset(
    {
        admin_module.Outcome.PROVIDER_UNREACHABLE,
        # A key muster has not seen may be a rotation it picks up on the next
        # fetch, which administrator.py allows once a minute.
        admin_module.Outcome.UNKNOWN_KEY,
    }
)


def set_session_cookies(
    response: Response, tokens: admin_module.Tokens, *, secure: bool
) -> None:
    """Attach the session. SameSite=Lax, which is also the CSRF control.

    Lax means the browser does not attach these cookies to a cross-site POST, so
    a page on another origin cannot make the operator mint a code or vouch for a
    device. That holds only while every state-changing route stays a POST - a
    GET that changes something would be reachable cross-site with the cookie
    attached, because Lax does send cookies on top-level GET navigation.
    """
    response.set_cookie(
        SESSION_COOKIE,
        tokens.session,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    if tokens.renewal:
        response.set_cookie(
            RENEWAL_COOKIE,
            tokens.renewal,
            httponly=True,
            secure=secure,
            samesite="lax",
            path="/",
        )


def clear_session_cookies(response: Response, *, secure: bool) -> None:
    """Remove the session.

    Every attribute that was set has to be repeated. A browser matches a
    deletion against a live cookie on name, path, domain AND the security
    attributes; omit one and the two are different cookies, the deletion lands
    on nothing, and the operator stays signed in after pressing sign out.
    """
    for name in (SESSION_COOKIE, RENEWAL_COOKIE):
        response.delete_cookie(
            name, path="/", httponly=True, secure=secure, samesite="lax"
        )


class AdministratorMiddleware(BaseHTTPMiddleware):
    """Work out who is acting, and stamp it on the request. Never refuses.

    One way in: a session cookie, a person signed in at the estate's identity
    provider. A request with none is anonymous, which is the normal state of
    every device endpoint in this service and not an error.
    """

    def __init__(self, app, state: "State") -> None:
        super().__init__(app)
        self.state = state

    async def dispatch(self, request: Request, call_next):
        actor = ANONYMOUS
        renewed: admin_module.Tokens | None = None
        clear = False

        if self.state.sign_in is not None:
            actor, renewed, clear = await self._from_session(request)

        request.state.actor = actor
        response = await call_next(request)

        # WHAT THE HANDLER DECIDED WINS, and both branches below check it.
        # Sign-in and sign-out both write these cookies, and this middleware saw
        # the request as it ARRIVED - carrying whatever the browser had before
        # either happened. Writing over that answer on the way out is how a
        # browser holding one stale cookie can never sign in again: the callback
        # hands it a good session, this deletes it on the same response, and the
        # symptom is a sign-in button that appears to do nothing. Found by
        # signing in with a cookie left over from a previous run.
        handed_a_session = (f"{SESSION_COOKIE}=",)
        handler_set_the_session = any(
            value.startswith(handed_a_session)
            for value in response.headers.getlist("set-cookie")
        )
        if handler_set_the_session:
            return response
        if renewed is not None:
            set_session_cookies(response, renewed, secure=self.state.cookie_secure)
        elif clear:
            # A session that cannot be verified is cleared rather than left to
            # fail on every subsequent request. Without this a cookie from a
            # provider that has been reconfigured wedges the console for good,
            # and the only visible symptom is, again, a button that does nothing.
            clear_session_cookies(response, secure=self.state.cookie_secure)
        return response

    async def _from_session(
        self, request: Request
    ) -> tuple[Actor, admin_module.Tokens | None, bool]:
        sign_in = self.state.sign_in
        session = request.cookies.get(SESSION_COOKIE, "")
        if not session:
            return ANONYMOUS, None, False
        try:
            person = await sign_in.administrator_for(session)
            return _actor_for(person), None, False
        except admin_module.Refused as refused:
            if refused.outcome is not admin_module.Outcome.EXPIRED:
                return ANONYMOUS, None, self._note(refused, "session refused")
            # EXPIRED falls through to the renewal below. It is the one refusal
            # with a remedy that does not involve the operator, which is why
            # administrator.py keeps it as its own outcome.

        renewal = request.cookies.get(RENEWAL_COOKIE, "")
        if not renewal:
            return ANONYMOUS, None, True
        try:
            person, tokens = await sign_in.renew(renewal)
        except admin_module.Refused as refused:
            return ANONYMOUS, None, self._note(refused, "session renewal refused")
        self.state.telemetry.count("auth.session.renewed")
        return _actor_for(person), tokens, False

    def _note(self, refused: admin_module.Refused, message: str) -> bool:
        """Record a refused session, and say whether the cookie is worth keeping.

        NOT EVERY NO IS THE COOKIE'S FAULT. A JWKS fetch that timed out, or a
        signing key rotated a minute ago, says nothing about the token in the
        browser - and clearing on those signs the operator out because somebody
        else's service had a bad morning, at which point they cannot sign back
        in either, because the same provider is still unreachable. Only a token
        that can never work again is worth throwing away.
        """
        self.state.telemetry.count(
            "auth.session.refused", tags=[f"reason:{refused.outcome.value}"]
        )
        telemetry.event(message, reason=refused.outcome.value)
        return refused.outcome not in _WORTH_RETRYING


class ActionRecordMiddleware(BaseHTTPMiddleware):
    """Write down that somebody with a name changed something.

    ONLY REQUESTS THAT CHANGE SOMETHING, and only from a caller who is signed
    in. The console polls the pending list every two seconds; a record per poll
    buries the one line that matters - a vouch - under a thousand that do not.

    THE ROUTE TEMPLATE, NOT THE PATH. `/v1/enroll/requests/{request_id}/vouch`
    carries a request id, and api.py's docstring is explicit that the id is a
    bearer secret: it is the only thing a device needs to collect a certificate.
    Recording the raw path would put it in the log stream, which is the one
    place a secret cannot be deleted from afterwards.
    """

    def __init__(self, app, state: "State") -> None:
        super().__init__(app)
        self.state = state

    async def dispatch(self, request: Request, call_next):
        # READ ON THE WAY IN, and this is the line the middleware order
        # protects. Starlette backs `request.state` with the connection scope,
        # so a value stamped by a middleware BELOW this one is visible up here
        # afterwards - reading the actor after `call_next` would produce a
        # correct record while the stack that guarantees it was upside down, and
        # the day something else moved, the record would quietly go anonymous.
        # Reading first means the record is made from what was known when the
        # request arrived, which is also the honest answer to "who did this".
        actor: Actor = getattr(request.state, "actor", ANONYMOUS)
        response = await call_next(request)
        if not actor.signed_in:
            return response
        if request.method not in _METHODS_THAT_CHANGE_SOMETHING:
            return response
        # Available only after the router has matched, which is why this reads
        # it on the way out rather than on the way in.
        route = request.scope.get("route")
        template = getattr(route, "path", "") or "unmatched"
        outcome = "accepted" if response.status_code < 400 else "refused"
        telemetry.event(
            "administrative action",
            actor=actor.record,
            principal=actor.kind,
            method=request.method,
            route=template,
            status=response.status_code,
        )
        self.state.telemetry.count(
            "admin.action", tags=[f"principal:{actor.kind}", f"outcome:{outcome}"]
        )
        return response


# Outer to inner, which is the order Starlette lists them in and the order a
# request meets them. Locked here rather than left to the reading order of the
# add_middleware calls, because getting it wrong is silent - see this module's
# docstring.
MIDDLEWARE_ORDER = (AdministratorMiddleware, ActionRecordMiddleware)


def install_middleware(app: FastAPI, state: "State") -> None:
    """Add both, then check the stack is what this file says it is.

    add_middleware is last-in-outermost, so this reads backwards on purpose.
    """
    app.add_middleware(ActionRecordMiddleware, state=state)
    app.add_middleware(AdministratorMiddleware, state=state)
    assert_middleware_order(app)


def assert_middleware_order(app: FastAPI) -> None:
    """Refuse to come up with the stack in an order that records nothing.

    At composition time, so a reorder crashes the pod at startup and every test
    that builds an app - rather than shipping a service whose only symptom is
    that its audit trail says `anonymous` and nobody looks until they need it.
    """
    actual = tuple(
        middleware.cls
        for middleware in app.user_middleware
        if middleware.cls in MIDDLEWARE_ORDER
    )
    if actual != MIDDLEWARE_ORDER:
        raise RuntimeError(
            "muster's middleware is in the wrong order. Expected outer to inner "
            f"{[cls.__name__ for cls in MIDDLEWARE_ORDER]}, got "
            f"{[cls.__name__ for cls in actual]}. ActionRecordMiddleware reads "
            "the actor AdministratorMiddleware stamps; with them the other way "
            "round every administrative action is recorded as anonymous and the "
            "record is quietly worthless."
        )


def _actor_for(person: admin_module.Administrator) -> Actor:
    return Actor(kind="administrator", subject=person.subject, email=person.email)


# ---- the page ------------------------------------------------------------

_CONSOLE_HTML = (pathlib.Path(__file__).with_name("console.html")).read_text()
_NONCE_PLACEHOLDER = "__CSP_NONCE__"


def _csp(nonce: str) -> str:
    """What this page is allowed to load. Everything not listed is refused.

    `default-src 'none'` first, so anything added later has to be named here
    deliberately instead of inheriting a permissive default. `blob:` on images
    is not decoration: the pairing QR is fetched with credentials and turned
    into a blob URL, because an <img src> cannot carry a header and a code in a
    query string ends up in logs and history.
    """
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        "img-src 'self' blob:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )


def _page(body: str, nonce: str) -> HTMLResponse:
    return HTMLResponse(
        body, headers={"Content-Security-Policy": _csp(nonce), "Cache-Control": "no-store"}
    )


def register_console_routes(app: FastAPI, state: "State") -> None:
    """The page, and who it reports itself as talking to."""

    @app.get("/", response_class=HTMLResponse)
    def console() -> HTMLResponse:
        """The console.

        Served without a session, deliberately: it is the page the sign-in
        button is on, and there is nothing in it that is not in this repository.
        Everything it shows comes from calls that carry the session cookie, so
        an unauthenticated reader gets the shell and no data.
        """
        nonce = secrets.token_urlsafe(16)
        return _page(_CONSOLE_HTML.replace(_NONCE_PLACEHOLDER, nonce), nonce)

    @app.get("/v1/session")
    def whoami(request: Request, response: Response) -> dict:
        """Who the console is talking as, and whether signing in is possible.

        Open, because it is the question a signed-out browser needs answered to
        know what to draw. It reports nothing a caller did not already supply.

        Never cached. This answer changes the moment somebody signs out, and a
        cached "signed in" would draw the whole console for a browser that has
        no session left - every button on it failing one at a time.
        """
        response.headers["Cache-Control"] = "no-store"
        actor: Actor = getattr(request.state, "actor", ANONYMOUS)
        return {
            "signed_in": actor.signed_in,
            "kind": actor.kind,
            "subject": actor.subject,
            "email": actor.email,
            "sign_in_configured": state.sign_in is not None,
        }

    _register_sign_in_routes(app, state)


def _register_sign_in_routes(app: FastAPI, state: "State") -> None:
    """The provider's three steps, and the way out."""

    @app.get("/auth/signin")
    def signin() -> Response:
        if state.sign_in is None:
            raise _not_configured()
        started = state.sign_in.start()
        response = RedirectResponse(started.url, status_code=303)
        response.set_cookie(
            FLOW_COOKIE,
            started.state,
            httponly=True,
            secure=state.cookie_secure,
            samesite="lax",
            path="/auth",
            max_age=int(admin_module.FLOW_TTL_S),
        )
        return response

    @app.get("/auth/callback")
    async def callback(
        request: Request,
        code: str = "",
        # The provider calls this parameter `state`, which is also what this
        # file calls muster's composition object, so it arrives under an alias.
        flow: str = Query("", alias="state"),
        error: str = "",
    ) -> Response:
        """Where the provider sends the browser back to."""
        if state.sign_in is None:
            raise _not_configured()
        if not flow or request.cookies.get(FLOW_COOKIE) != flow:
            # Not the browser that started it. Refused before the code is
            # exchanged, so a code somebody else obtained is never spent.
            return _refusal(
                state,
                admin_module.Outcome.NO_SUCH_FLOW,
                "This sign-in did not start in this browser. Start again from "
                "the console.",
            )
        if error:
            # The provider refused before muster was ever involved - a cancelled
            # sign-in, or a client that is not allowed this redirect URL.
            return _refusal(
                state, admin_module.Outcome.PROVIDER_REFUSED, html.escape(error)
            )
        try:
            person, tokens = await state.sign_in.finish(code, flow)
        except admin_module.Refused as refused:
            return _refusal(state, refused.outcome, html.escape(str(refused)))

        state.telemetry.count("auth.signin.completed")
        telemetry.event("administrator signed in", actor=person.subject)
        response = RedirectResponse("/", status_code=303)
        set_session_cookies(response, tokens, secure=state.cookie_secure)
        _clear_flow_cookie(response, secure=state.cookie_secure)
        return response

    @app.post("/auth/signout")
    def signout(request: Request) -> JSONResponse:
        """End the session here, and say where to go to end it at the provider.

        A POST, so a link or an image on another page cannot sign the operator
        out. Open, because signing out with no session is a no-op and refusing
        it would mean the one way to clear a broken cookie needs the broken
        cookie to work.
        """
        actor: Actor = getattr(request.state, "actor", ANONYMOUS)
        if actor.signed_in:
            state.telemetry.count("auth.signout")
            telemetry.event("administrator signed out", actor=actor.record)
        onward = ""
        if state.sign_in is not None and state.base_url:
            onward = state.sign_in.end_session_url(state.base_url.rstrip("/") + "/")
        response = JSONResponse({"next": onward})
        clear_session_cookies(response, secure=state.cookie_secure)
        return response


def _clear_flow_cookie(response: Response, *, secure: bool) -> None:
    """Every attribute repeated, or the browser keeps the live one - same rule
    as the session cookies above."""
    response.delete_cookie(
        FLOW_COOKIE, path="/auth", httponly=True, secure=secure, samesite="lax"
    )


def _not_configured() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=(
            "administrator sign-in is not configured on this server. See "
            "docs/administrator-sign-in.md for what an operator must apply."
        ),
    )


def _refusal(state: "State", outcome: admin_module.Outcome, detail: str) -> HTMLResponse:
    """Say no on a page, because a browser is looking at this URL.

    The detail is escaped and shown: a sign-in that fails silently, or with a
    JSON blob, is one the operator cannot fix. The refusal reason is a closed
    set and goes out as a tag - `not-an-administrator` and `wrong-audience` are
    somebody else knocking and a misconfigured client, and a single total hides
    both behind each other.
    """
    state.telemetry.count("auth.signin.refused", tags=[f"reason:{outcome.value}"])
    telemetry.event("sign-in refused", reason=outcome.value)
    return _not_signed_in_page(state, detail)


def _not_signed_in_page(state: "State", detail: str) -> HTMLResponse:
    """403 with a sentence on it, and every cookie cleared on the way out."""
    nonce = secrets.token_urlsafe(16)
    body = (
        "<!doctype html><meta charset=utf-8><title>Muster</title>"
        f"<style nonce=\"{nonce}\">"
        "body{margin:0;background:#FAF7F2;color:#1D1F23;"
        "font:16px/1.6 Satoshi,ui-sans-serif,-apple-system,system-ui,sans-serif}"
        "main{max-width:34rem;margin:0 auto;padding:4rem 1.25rem}"
        "h1{font-size:1.5rem;margin:0 0 .5rem}p{color:#6B7280}"
        "a{color:#1D1F23}</style>"
        "<main><h1>Not signed in</h1>"
        f"<p>{detail}</p>"
        '<p><a href="/">Back to Muster</a></p></main>'
    )
    response = _page(body, nonce)
    response.status_code = 403
    clear_session_cookies(response, secure=state.cookie_secure)
    _clear_flow_cookie(response, secure=state.cookie_secure)
    return response
