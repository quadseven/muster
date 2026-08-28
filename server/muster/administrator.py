"""Who the administrator is, and how they prove it.

A WORD ON THE WORD. CONTEXT.md gives "identity" exactly one meaning: the client
certificate a vouched DEVICE holds. A human never has one of those, so nothing
in this module is called an identity. A human signs in and gets a SESSION; the
device path is untouched and stays that way.

WHY A SIGN-IN AND NOT A PASSWORD BOX. The console is served by the process that
holds the CA. Typing a credential into that page means the page can read it, and
the whole point of putting the administrator behind a real account is to stop
one shared string being the entire authorization story. So muster never sees a
password: the browser is sent to the estate's identity provider, comes back with
an authorization code, and muster exchanges that code for a signed token it can
verify itself. What arrives here is a JWT, not a secret to be compared.

THE SHAPE IS OIDC AND NOTHING ELSE. Every endpoint is configuration - issuer,
JWKS, authorize, token - so this file names no provider and can be pointed at
whichever one the estate runs. That is deliberate: a public repository should
not have to be edited when the estate changes providers, and an interface
described by the standard is one a reader can check against the standard.

AUTHORIZATION KEYS ON THE SUBJECT, NEVER THE EMAIL. `sub` is the provider's
immutable handle for one account; an email address can be changed, released and
re-registered by somebody else. Allowing by email means an address that leaves
the estate's control is an administrator again. The email is carried for display
and nothing more.

THE ALLOWLIST IS NOT OPTIONAL. The pool this points at is shared with other
services in the estate, so "has an account" is not "may vouch for devices".
`app_from_env` refuses to start with a provider configured and no allowed
subjects, for the same reason it refuses to start with no way in at all: an
admin surface that comes up open because a variable was unset fails at the worst
possible moment.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from enum import Enum

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

# Everything a session needs and nothing more. `openid` is what makes this an
# OIDC request at all (without it the provider hands back a bare OAuth token
# with no identity in it); `email` is for the "signed in as" line. muster calls
# no API on the operator's behalf, so it asks for no other scope.
SCOPES = "openid email"

# How long a half-finished sign-in is remembered. Long enough to type a password
# and answer a second factor, short enough that an abandoned attempt is not a
# slot somebody else can fill.
FLOW_TTL_S = 600.0

# The cap exists because /auth/signin is reachable without a session - it has to
# be, it is the way in. Without a cap, a stranger looping it grows a dict on the
# process that holds the CA until the pod is OOMKilled. Oldest out first.
MAX_PENDING_FLOWS = 32

# A signing key we have never seen may be a rotation rather than an attack, so
# one unknown `kid` earns one refetch - but not more often than this, or an
# attacker with a made-up kid has a way to make muster hammer the provider.
JWKS_REFETCH_INTERVAL_S = 60.0

# The provider is on the internet and this call sits in front of the console.
# No timeout means a hung connection holds the request forever.
HTTP_TIMEOUT_S = 10.0

# How long one renewal's answer is handed to requests that asked for the same
# one. It only has to cover requests already in flight when the first arrived,
# so it is seconds rather than minutes: any longer and a refresh token that has
# been spent keeps buying a session for no reason.
RENEWAL_MEMORY_S = 30.0


class Outcome(str, Enum):
    """Why a sign-in was refused. Every no is a distinct no.

    Same discipline as `enroll.Outcome`, and for the same reason: these become
    `reason:` tags. "Sign-in is failing" is not an answerable question when a
    wrong audience (a misconfigured client id), an unknown key (a rotation muster
    has not picked up) and a subject that is not on the allowlist (somebody else
    in the estate's pool trying the door) all arrive as one total. The set is
    closed, so tagging by it cannot explode cardinality.
    """

    OK = "ok"
    NO_SESSION = "no-session"
    MALFORMED = "malformed-token"
    UNKNOWN_KEY = "unknown-key"
    BAD_SIGNATURE = "bad-signature"
    EXPIRED = "expired"
    WRONG_AUDIENCE = "wrong-audience"
    WRONG_ISSUER = "wrong-issuer"
    WRONG_NONCE = "wrong-nonce"
    NO_SUCH_FLOW = "no-such-flow"
    NOT_AN_ADMINISTRATOR = "not-an-administrator"
    PROVIDER_REFUSED = "provider-refused"
    PROVIDER_UNREACHABLE = "provider-unreachable"


class Refused(Exception):
    """A sign-in step said no. Carries the Outcome so callers can tag with it."""

    def __init__(self, outcome: Outcome, detail: str = "") -> None:
        super().__init__(detail or outcome.value)
        self.outcome = outcome


@dataclass(frozen=True)
class Administrator:
    """One human who may mint codes and vouch for devices.

    `subject` is the authorization key and the only thing worth putting in a
    log. `email` is for the console to show and must never be compared against
    an allowlist - see the module docstring.
    """

    subject: str
    email: str
    expires_at: int


@dataclass(frozen=True)
class Tokens:
    """What the provider handed back. `renewal` is absent when it does not rotate."""

    session: str
    renewal: str | None


@dataclass(frozen=True)
class Provider:
    """Where the estate's identity provider lives. All of it configuration."""

    issuer: str
    jwks_url: str
    authorize_url: str
    token_url: str
    client_id: str
    # A confidential client authenticates the token exchange with a secret. A
    # public one does not have one and leans on PKCE, which muster sends either
    # way - so both shapes work and neither is assumed.
    client_secret: str = ""
    # Optional: ending the session at the provider as well as here. Without it,
    # signing out of muster leaves the provider's own cookie alone and the next
    # sign-in is one click with no password. That is a real difference on a
    # shared machine, so the URL is worth configuring.
    end_session_url: str = ""

    ENV_PREFIX = "MUSTER_OIDC_"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Provider | None":
        """Read the provider from the environment. None means "not configured".

        HALF-CONFIGURED IS THE DANGEROUS STATE and it raises. A deployment with
        an issuer and no token URL would otherwise start, serve a sign-in button
        that cannot work, and look identical to one where nobody has set any of
        this up yet.
        """
        source = os.environ if env is None else env
        read = {
            name: source.get(f"{cls.ENV_PREFIX}{name.upper()}", "").strip()
            for name in ("issuer", "jwks_url", "authorize_url", "token_url",
                         "client_id", "client_secret", "end_session_url")
        }
        required = ("issuer", "jwks_url", "authorize_url", "token_url", "client_id")
        if not any(read[name] for name in required):
            return None
        missing = [name for name in required if not read[name]]
        if missing:
            raise RuntimeError(
                "administrator sign-in is half-configured. Missing: "
                + ", ".join(f"{cls.ENV_PREFIX}{name.upper()}" for name in missing)
                + ". Refusing to start rather than serving a sign-in button that "
                "cannot work and looks exactly like one nobody has set up yet."
            )
        # CHECKED AT BOOT, because the alternative is that it is checked on
        # every request forever. A URL httpx cannot parse - a typo in the port
        # is enough - raises from inside the middleware, so a single mistyped
        # character in a secret would make every request that carries a cookie
        # a 500 with nothing saying why. Here it is a pod that will not start.
        for name in ("jwks_url", "authorize_url", "token_url", "end_session_url"):
            if read[name]:
                _must_be_a_url(f"{cls.ENV_PREFIX}{name.upper()}", read[name])
        return cls(**read)


def _must_be_a_url(name: str, value: str) -> None:
    try:
        parsed = httpx.URL(value)
    except httpx.InvalidURL as exc:
        raise RuntimeError(f"{name} is not a usable URL: {exc}") from exc
    if parsed.scheme not in ("https", "http") or not parsed.host:
        raise RuntimeError(
            f"{name} needs a scheme and a host, and has {value!r}. Anything "
            "else is a browser sent nowhere, or a token exchange posted to a "
            "path on this server."
        )


def administrators_from_env(env: dict | None = None) -> frozenset[str]:
    """The subjects allowed to administer this muster.

    Comma separated because that is what a Kubernetes env var can carry without
    ceremony. Empty is a legitimate READ - `app_from_env` is where an empty
    allowlist beside a configured provider becomes a refusal to start, because
    that is the place that knows both.
    """
    source = os.environ if env is None else env
    raw = source.get("MUSTER_ADMIN_SUBJECTS", "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class _NotOursToClose(httpx.AsyncBaseTransport):
    """Pass requests to a transport somebody else owns.

    `httpx.AsyncClient` closes its transport when its context manager exits,
    including one it was handed rather than built. Since every call here builds
    a client, the second call through an injected transport would find it shut.
    The fake transport the tests use has a no-op close, so nothing would have
    said so until the first real one - a proxy-aware or retrying transport -
    was wired in.
    """

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        return None


@dataclass
class _Flow:
    """One sign-in that has been started and not yet come back."""

    verifier: str
    nonce: str
    started_at: float


@dataclass(frozen=True)
class Started:
    """Where to send the browser, and the handle to expect back from it.

    The state comes out separately because the caller has to put it somewhere
    only THIS browser can return: the store below is one dict for the whole
    process, so matching a returned state against it proves the sign-in started
    here, not that it started in the browser that came back. See the flow cookie
    in console.py.
    """

    url: str
    state: str


class SignIn:
    """The sign-in exchange: start it, finish it, and check a session token.

    Every network call builds its own client rather than holding one open. The
    calls are rare - a sign-in is a few times a week - and a client cached on
    this object outlives the event loop that created it, which is a failure that
    only shows up after the first loop is gone and reads like the provider went
    away.
    """

    def __init__(
        self,
        provider: Provider,
        administrators: frozenset[str],
        redirect_uri: str,
        clock=time.time,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.provider = provider
        self.administrators = administrators
        self.redirect_uri = redirect_uri
        self.clock = clock
        # httpx's own test seam. A fake transport lets the tests exercise the
        # real request building, the real JSON handling and the real JWT
        # verification against real signatures, with no network. Wrapped,
        # because a client closes the transport it was handed on the way out of
        # its context manager whether or not it owns it - so the second call
        # through an injected transport would raise "already closed".
        self._transport = _NotOursToClose(transport) if transport else None
        self._flows: dict[str, _Flow] = {}
        self._keys: dict[str, dict] = {}
        # NEGATIVE INFINITY, NOT ZERO. "Never fetched" has to read as older than
        # the interval whatever the clock counts from. Zero works against a wall
        # clock and silently stops working against one that starts near zero -
        # a monotonic clock on a freshly booted host - where the first fetch
        # would be skipped and the first sign-in refused with no key to check
        # it against. The sentinel should not depend on the epoch.
        self._keys_fetched_at = float("-inf")
        self._keys_lock = asyncio.Lock()
        # ONE RENEWAL AT A TIME, and a short memory of the last one. Every
        # request from a browser holding an expired session tries to renew, and
        # the console polls every two seconds: without this, six requests spend
        # the SAME refresh token six times. A provider that rotates refresh
        # tokens accepts the first and refuses the rest as replays - which reads
        # here as five broken sessions and signs the operator out, and on a
        # provider with reuse detection revokes the whole family.
        self._renewal_lock = asyncio.Lock()
        self._last_renewal: tuple[str, Administrator, Tokens, float] | None = None

    # ---- starting ---------------------------------------------------------

    def start(self) -> Started:
        """The URL to send the browser to, with a flow recorded to come back to.

        `state` is half of what ties the browser that comes back to the browser
        that left; the other half is the caller putting it in a cookie. Without
        both, anyone can start a sign-in here, take the state, and hand the
        operator a link to /auth/callback carrying an authorization code for
        THEIR account - and the operator's console quietly becomes somebody
        else's session.

        PKCE (`code_challenge`) is sent whether or not the client has a secret.
        It costs one hash and it means an authorization code intercepted on the
        way back is worthless without the verifier, which never leaves this
        process.
        """
        self._expire_flows()
        state = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        nonce = secrets.token_urlsafe(24)
        self._flows[state] = _Flow(
            verifier=verifier, nonce=nonce, started_at=self.clock()
        )
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.provider.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": SCOPES,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in self.provider.authorize_url else "?"
        return Started(
            url=f"{self.provider.authorize_url}{separator}{query}", state=state
        )

    def _expire_flows(self) -> None:
        # `pop` with a default rather than `del`, and a copy to iterate. Sign-in
        # runs in a sync route handler, which the framework puts on a worker
        # thread, so two browsers starting at once are two threads in here - and
        # a `del` for a key another thread just removed is a KeyError on the way
        # in to the console.
        now = self.clock()
        for state, flow in list(self._flows.items()):
            if now - flow.started_at > FLOW_TTL_S:
                self._flows.pop(state, None)
        while len(self._flows) >= MAX_PENDING_FLOWS:
            # min() over a snapshot, not over the live dict. Iterating one
            # dictionary while another thread pops from it is a RuntimeError,
            # and the lookup inside the key function is a second chance to miss.
            oldest = min(list(self._flows.items()), key=lambda pair: pair[1].started_at)
            self._flows.pop(oldest[0], None)

    # ---- finishing --------------------------------------------------------

    async def finish(self, code: str, state: str) -> tuple[Administrator, Tokens]:
        """Trade the authorization code for a session, or say why not."""
        flow = self._flows.pop(state, None)
        if flow is None:
            # Covers both an unknown state and one that expired while the
            # operator was away. Same answer either way: start again.
            raise Refused(
                Outcome.NO_SUCH_FLOW,
                "this sign-in did not start here, or it took too long",
            )
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.provider.client_id,
            "code_verifier": flow.verifier,
        }
        granted = await self._post_to_token_endpoint(payload)
        return await self._session_from(granted, expect_nonce=flow.nonce)

    async def renew(self, renewal_token: str) -> tuple[Administrator, Tokens]:
        """Silently extend a session whose token has expired.

        Without this the operator is bounced to the provider every time the
        token's hour is up, in the middle of vouching for a device.

        ONE AT A TIME, AND THE ANSWER IS REMEMBERED BRIEFLY. Requests arrive in
        parallel - the console polls while the page is also loading - and they
        all carry the same expired session and the same refresh token. The lock
        makes the first one do the exchange; the memory is what the others get,
        because re-presenting a refresh token a provider has already rotated is
        a replay, and it is answered as one.
        """
        async with self._renewal_lock:
            remembered = self._last_renewal
            if (
                remembered is not None
                and remembered[0] == renewal_token
                and self.clock() - remembered[3] <= RENEWAL_MEMORY_S
            ):
                return remembered[1], remembered[2]

            payload = {
                "grant_type": "refresh_token",
                "refresh_token": renewal_token,
                "client_id": self.provider.client_id,
            }
            granted = await self._post_to_token_endpoint(payload)
            # A provider that does not rotate refresh tokens returns none here,
            # and the caller must keep the one it already has rather than
            # clearing it.
            administrator, tokens = await self._session_from(
                granted, expect_nonce=None
            )
            renewed = Tokens(
                session=tokens.session, renewal=tokens.renewal or renewal_token
            )
            self._last_renewal = (
                renewal_token,
                administrator,
                renewed,
                self.clock(),
            )
            return administrator, renewed

    async def _post_to_token_endpoint(self, payload: dict) -> dict:
        auth = None
        if self.provider.client_secret:
            auth = (self.provider.client_id, self.provider.client_secret)
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=HTTP_TIMEOUT_S
            ) as client:
                response = await client.post(
                    self.provider.token_url, data=payload, auth=auth
                )
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # InvalidURL is NOT an HTTPError - it inherits straight from
            # Exception - so a configured URL that httpx cannot parse would
            # otherwise escape this middleware as a 500 on every request that
            # carries a cookie, with no reason attached anywhere.
            raise Refused(Outcome.PROVIDER_UNREACHABLE, str(exc)) from exc
        if response.status_code != 200:
            # The body can carry an authorization code and, on some providers,
            # the client secret echoed back in an error description. Only the
            # status and the standard `error` code come out of here.
            error = ""
            try:
                error = str(response.json().get("error", ""))
            except ValueError:
                pass
            raise Refused(
                Outcome.PROVIDER_REFUSED,
                f"the identity provider refused the exchange: {response.status_code} {error}".strip(),
            )
        try:
            return response.json()
        except ValueError as exc:
            raise Refused(Outcome.MALFORMED, "the token response was not JSON") from exc

    async def _session_from(
        self, granted: dict, expect_nonce: str | None
    ) -> tuple[Administrator, Tokens]:
        token = granted.get("id_token") or ""
        if not token:
            raise Refused(
                Outcome.MALFORMED,
                "the provider returned no id token - check that the client is "
                "allowed the openid scope",
            )
        administrator, claims = await self._verify(token)
        if expect_nonce is not None and claims.get("nonce") != expect_nonce:
            # The nonce ties this token to the sign-in muster started. Without
            # the check, a token minted for a different session of the same
            # client is accepted here - which is exactly what a replayed
            # authorization code produces.
            raise Refused(Outcome.WRONG_NONCE, "this token belongs to another sign-in")
        self._require_administrator(administrator)
        return administrator, Tokens(
            session=token, renewal=granted.get("refresh_token") or None
        )

    # ---- checking a session ------------------------------------------------

    async def administrator_for(self, session_token: str) -> Administrator:
        """Verify a session token and confirm its subject may administer muster."""
        if not session_token:
            raise Refused(Outcome.NO_SESSION, "no session")
        administrator, _ = await self._verify(session_token)
        self._require_administrator(administrator)
        return administrator

    def _require_administrator(self, administrator: Administrator) -> None:
        if administrator.subject not in self.administrators:
            # The subject is in the message on purpose. It is the operator's
            # own, it is not a secret, and it is the string that has to go into
            # MUSTER_ADMIN_SUBJECTS - so one refused sign-in tells them exactly
            # what to configure instead of sending them to look it up.
            raise Refused(
                Outcome.NOT_AN_ADMINISTRATOR,
                f"this account is not an administrator of this muster (subject "
                f"{administrator.subject})",
            )

    async def _verify(self, token: str) -> tuple[Administrator, dict]:
        """Check the signature and every claim that decides who this is."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise Refused(Outcome.MALFORMED, f"unreadable token header: {exc}") from exc
        kid = header.get("kid")
        if not kid:
            raise Refused(Outcome.MALFORMED, "the token names no signing key")
        key = await self._signing_key(kid)

        try:
            claims = jwt.decode(
                token,
                key=key,
                # THE ALGORITHM COMES FROM HERE, NEVER FROM THE TOKEN. A
                # verifier that trusts the header's `alg` accepts `none`, or
                # accepts HS256 signed with the public key it published. Both
                # are somebody else's session, silently.
                algorithms=["RS256"],
                issuer=self.provider.issuer,
                audience=self.provider.client_id,
                # EVERY ONE OF THESE MUST BE PRESENT, not merely valid when
                # present. The library checks `exp` if a token carries one and
                # says nothing when it does not - so a token with the claim
                # left out would never expire, and one with no `aud` would skip
                # the audience check entirely. All five are required of a
                # sign-in token by the standard, so demanding them refuses
                # nothing a correct provider issues.
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            # Separated from every other failure because it is the only one with
            # a remedy that is not "sign in again": the caller can renew.
            raise Refused(Outcome.EXPIRED, "the session token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise Refused(Outcome.WRONG_AUDIENCE, str(exc)) from exc
        except jwt.InvalidIssuerError as exc:
            raise Refused(Outcome.WRONG_ISSUER, str(exc)) from exc
        except jwt.InvalidSignatureError as exc:
            raise Refused(Outcome.BAD_SIGNATURE, str(exc)) from exc
        except jwt.PyJWTError as exc:
            raise Refused(Outcome.MALFORMED, str(exc)) from exc

        # Providers that stamp what a token is FOR say so here. An access token
        # is not a session: it is addressed to a resource server, and accepting
        # one as proof of who is driving the console would take a token minted
        # for another service in the estate as a muster sign-in.
        purpose = claims.get("token_use")
        if purpose is not None and purpose != "id":
            raise Refused(
                Outcome.MALFORMED, f"this is a {purpose} token, not a sign-in"
            )
        subject = claims.get("sub") or ""
        if not subject:
            raise Refused(Outcome.MALFORMED, "the token names no subject")
        return (
            Administrator(
                subject=subject,
                email=str(claims.get("email") or ""),
                expires_at=int(claims.get("exp") or 0),
            ),
            claims,
        )

    async def _signing_key(self, kid: str):
        # THE LOCK IS HELD ACROSS THE FETCH, deliberately. It means every other
        # request waits out one fetch, which is the point: without it, a restart
        # under any concurrency sends one request to the provider per request in
        # flight, and the first thing muster would do on coming back is a small
        # flood. `HTTP_TIMEOUT_S` bounds how long that wait can be, and the
        # traffic here is a console opened a few times a week.
        async with self._keys_lock:
            if kid not in self._keys and self._may_refetch():
                await self._fetch_keys()
            key = self._keys.get(kid)
        if key is None:
            if not self._keys:
                # Nothing has ever been fetched, so this is not a token naming a
                # key that does not exist - it is muster never having seen the
                # provider. Saying "unknown key" here sends the operator to look
                # at a token that is fine.
                raise Refused(
                    Outcome.PROVIDER_UNREACHABLE,
                    "no signing keys have been read from the identity provider",
                )
            raise Refused(
                Outcome.UNKNOWN_KEY,
                f"no published signing key matches {kid}",
            )
        try:
            return RSAAlgorithm.from_jwk(key)
        except Exception as exc:  # noqa: BLE001 - any malformed JWK lands here
            raise Refused(Outcome.MALFORMED, f"unusable signing key: {exc}") from exc

    def _may_refetch(self) -> bool:
        return self.clock() - self._keys_fetched_at >= JWKS_REFETCH_INTERVAL_S

    async def _fetch_keys(self) -> None:
        # STAMPED IN A finally, INCLUDING WHEN THE FETCH FAILED, and that is the
        # whole point of the stamp. A failed fetch is exactly when the interval
        # matters: the console polls every two seconds, and a provider that is
        # down answers slowly or not at all, so "only rate-limit successes"
        # means an outage turns every poll into another attempt - each one
        # waiting out HTTP_TIMEOUT_S while holding the lock, until the request
        # queue on the pod that also serves enrolling devices is minutes deep.
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=HTTP_TIMEOUT_S
            ) as client:
                response = await client.get(self.provider.jwks_url)
                response.raise_for_status()
                document = response.json()
        except (httpx.HTTPError, httpx.InvalidURL, ValueError) as exc:
            raise Refused(Outcome.PROVIDER_UNREACHABLE, str(exc)) from exc
        finally:
            self._keys_fetched_at = self.clock()
        self._keys = {
            key["kid"]: key for key in document.get("keys", []) if key.get("kid")
        }

    def end_session_url(self, after: str) -> str:
        """Where to send the browser to end the provider's session too.

        Empty when no URL is configured, which the caller reads as "there is
        nowhere to send them" rather than as an error - ending muster's own
        session is the part that has to work.
        """
        if not self.provider.end_session_url:
            return ""
        query = urllib.parse.urlencode(
            {"client_id": self.provider.client_id, "logout_uri": after}
        )
        separator = "&" if "?" in self.provider.end_session_url else "?"
        return f"{self.provider.end_session_url}{separator}{query}"
