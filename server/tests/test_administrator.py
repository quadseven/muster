"""Signing in, and every way it says no.

The tests that matter here are the refusals. A sign-in that works is one line;
a sign-in that accepts a token it should not is somebody else vouching for
devices, and nothing on the screen would look wrong.

`asyncio.run` per test rather than a plugin: these are a handful of coroutines
and each one wants its own loop anyway, so a dependency would buy nothing.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import urllib.parse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from muster import administrator
from muster.administrator import Outcome, Refused
from tests.conftest import (
    ADMIN_SUBJECT,
    AUTHORIZE_URL,
    CLIENT_ID,
    ISSUER,
    JWKS_URL,
    REDIRECT_URI,
    STRANGER_SUBJECT,
    TOKEN_URL,
)


def run(coroutine):
    return asyncio.run(coroutine)


def query_of(url: str) -> dict:
    return {
        key: value[0]
        for key, value in urllib.parse.parse_qs(urllib.parse.urlparse(url).query).items()
    }


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


# ---- starting a sign-in ---------------------------------------------------


def test_the_authorize_url_carries_everything_the_provider_needs(sign_in):
    query = query_of(sign_in.start().url)

    assert query["response_type"] == "code"
    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == REDIRECT_URI
    # openid is what makes this a sign-in rather than a bare authorization: a
    # provider asked without it hands back a token with no identity in it.
    assert "openid" in query["scope"]
    assert query["state"] and query["nonce"]
    assert query["code_challenge_method"] == "S256"


def test_the_challenge_is_a_hash_of_something_that_never_leaves(provider):
    """PKCE, checked rather than assumed.

    An authorization code intercepted on the way back is worthless without the
    verifier, and the verifier only exists in this process. If the challenge
    were the verifier - which is what a wrong implementation of this looks like
    - intercepting the code would be enough.
    """
    sign_in = provider.sign_in()
    query = query_of(sign_in.start().url)
    code, state = provider.redeem(AUTHORIZE_URL + "?" + urllib.parse.urlencode(query))
    run(sign_in.finish(code, state))

    verifier = provider.token_requests[0]["form"]["code_verifier"]
    digest = hashlib.sha256(verifier.encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == query["code_challenge"]
    assert verifier != query["code_challenge"]


def test_two_sign_ins_never_share_a_state(sign_in):
    assert sign_in.start().state != sign_in.start().state


def test_a_callback_that_did_not_start_here_is_refused(sign_in):
    """The whole reason `state` exists.

    Without this, a link handed to the operator carrying somebody else's
    authorization code signs them into somebody else's account, on the console
    that vouches for devices.
    """
    with pytest.raises(Refused) as refused:
        run(sign_in.finish("a-code", "a-state-nobody-here-issued"))
    assert refused.value.outcome is Outcome.NO_SUCH_FLOW


def test_a_sign_in_left_half_finished_expires(provider):
    clock = Clock()
    sign_in = provider.sign_in(clock=clock)
    code, state = provider.redeem(sign_in.start().url)

    clock.advance(administrator.FLOW_TTL_S + 1)
    sign_in.start()  # any later sign-in sweeps the expired one

    with pytest.raises(Refused) as refused:
        run(sign_in.finish(code, state))
    assert refused.value.outcome is Outcome.NO_SUCH_FLOW


def test_abandoned_sign_ins_cannot_grow_without_bound(sign_in):
    """/auth/signin is reachable by anyone - it has to be, it is the way in.

    Without a cap, a stranger looping it grows a dict inside the process that
    holds the CA until the pod is killed for memory.
    """
    for _ in range(administrator.MAX_PENDING_FLOWS * 3):
        sign_in.start()
    assert len(sign_in._flows) <= administrator.MAX_PENDING_FLOWS


# ---- finishing one --------------------------------------------------------


def test_an_administrator_comes_back_with_a_session(provider):
    sign_in = provider.sign_in()
    code, state = provider.redeem(sign_in.start().url)

    person, tokens = run(sign_in.finish(code, state))

    assert person.subject == ADMIN_SUBJECT
    assert person.email == "administrator@example.test"
    assert tokens.session and tokens.renewal == "renewal-token"
    assert provider.token_requests[0]["form"]["grant_type"] == "authorization_code"


def test_a_confidential_client_authenticates_the_exchange(provider):
    sign_in = provider.sign_in(
        provider=administrator.Provider(
            issuer=ISSUER,
            jwks_url=JWKS_URL,
            authorize_url=AUTHORIZE_URL,
            token_url=TOKEN_URL,
            client_id=CLIENT_ID,
            # The stand-in provider's, and the assertion below is precisely
            # that it never leaves the Authorization header.
            client_secret="a-client-secret",  # noqa: S106
        )
    )
    code, state = provider.redeem(sign_in.start().url)
    run(sign_in.finish(code, state))

    # In the header, never in the form: a secret in a body is a secret in an
    # access log the moment anything decides to record request bodies.
    assert provider.token_requests[0]["authorization"].startswith("Basic ")
    assert "client_secret" not in provider.token_requests[0]["form"]


def test_a_token_minted_for_another_sign_in_is_refused(provider):
    """The nonce check, which is what makes a replayed code useless."""
    sign_in = provider.sign_in()
    code, state = provider.redeem(sign_in.start().url)
    provider.nonce_to_return = "a-nonce-from-somebody-elses-sign-in"

    with pytest.raises(Refused) as refused:
        run(sign_in.finish(code, state))
    assert refused.value.outcome is Outcome.WRONG_NONCE


def test_a_stranger_in_the_same_pool_is_not_an_administrator(provider):
    """The pool is shared with the rest of the estate.

    Having an account is not the same as being allowed to vouch for devices,
    and this is the only thing standing between the two.
    """
    provider.subject = STRANGER_SUBJECT
    sign_in = provider.sign_in()
    code, state = provider.redeem(sign_in.start().url)

    with pytest.raises(Refused) as refused:
        run(sign_in.finish(code, state))
    assert refused.value.outcome is Outcome.NOT_AN_ADMINISTRATOR
    # The subject is in the message so one refused sign-in tells the operator
    # exactly what to put in MUSTER_ADMIN_SUBJECTS.
    assert STRANGER_SUBJECT in str(refused.value)


def test_a_provider_that_refuses_the_exchange_keeps_its_body_to_itself(provider):
    provider.token_status = 400
    provider.token_body = {
        "error": "invalid_grant",
        "error_description": "code was for client secret sh-hhh",
    }
    sign_in = provider.sign_in()
    code, state = provider.redeem(sign_in.start().url)

    with pytest.raises(Refused) as refused:
        run(sign_in.finish(code, state))
    assert refused.value.outcome is Outcome.PROVIDER_REFUSED
    # The standard error code comes out; the description does not, because a
    # provider is free to echo the request into it.
    assert "invalid_grant" in str(refused.value)
    assert "sh-hhh" not in str(refused.value)


def test_a_provider_that_cannot_be_reached_is_its_own_refusal(provider):
    def refuse(request):
        raise httpx.ConnectError("no route to host")

    sign_in = provider.sign_in(transport=httpx.MockTransport(refuse))
    code, state = provider.redeem(sign_in.start().url)

    with pytest.raises(Refused) as refused:
        run(sign_in.finish(code, state))
    # Distinct from every other no, because it is the one the operator cannot
    # fix by signing in again.
    assert refused.value.outcome is Outcome.PROVIDER_UNREACHABLE


def test_a_grant_with_no_id_token_is_refused(provider):
    provider.token_body = {"access_token": "not-a-sign-in", "token_type": "Bearer"}
    sign_in = provider.sign_in()
    code, state = provider.redeem(sign_in.start().url)

    with pytest.raises(Refused) as refused:
        run(sign_in.finish(code, state))
    assert refused.value.outcome is Outcome.MALFORMED


# ---- checking a session token ---------------------------------------------


def test_a_valid_session_names_its_administrator(provider, sign_in):
    person = run(sign_in.administrator_for(provider.id_token()))
    assert person.subject == ADMIN_SUBJECT


def test_no_session_is_a_refusal_and_not_a_crash(sign_in):
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(""))
    assert refused.value.outcome is Outcome.NO_SESSION


def test_a_tampered_token_is_refused(provider, sign_in):
    token = provider.id_token()
    header, payload, signature = token.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged["sub"] = STRANGER_SUBJECT
    swapped = (
        base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    )

    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(f"{header}.{swapped}.{signature}"))
    assert refused.value.outcome is Outcome.BAD_SIGNATURE


def test_a_token_signed_by_a_key_the_provider_never_published_is_refused(
    provider, sign_in
):
    somebody_else = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = provider.id_token(key=somebody_else)

    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(token))
    assert refused.value.outcome is Outcome.BAD_SIGNATURE


def test_an_unsigned_token_is_refused(provider, sign_in):
    """`alg: none`, the oldest attack on this format.

    A verifier that reads the algorithm out of the token it is checking will
    happily agree that a token claiming to need no signature has a valid one.
    """
    unsigned = jwt.encode(
        {
            "sub": STRANGER_SUBJECT,
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": 99999999999,
        },
        None,
        algorithm="none",
        headers={"kid": provider.kid},
    )
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(unsigned))
    assert refused.value.outcome is Outcome.MALFORMED


def test_a_token_signed_with_the_published_key_as_a_password_is_refused(
    provider, sign_in
):
    """Algorithm confusion, built by hand because no library will build it.

    The provider publishes its public key. If the verifier let the token choose
    the algorithm, an attacker could sign one with HS256 using that published
    key as the shared secret - and it would verify, because the verifier has the
    same public key. muster names RS256 itself and never asks the token.
    """
    public_pem = provider.key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def segment(payload: dict) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing_input = ".".join(
        [
            segment({"alg": "HS256", "typ": "JWT", "kid": provider.kid}),
            segment(
                {
                    "sub": STRANGER_SUBJECT,
                    "iss": ISSUER,
                    "aud": CLIENT_ID,
                    "exp": 99999999999,
                }
            ),
        ]
    )
    signature = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    forged = (
        signing_input
        + "."
        + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    )

    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(forged))
    assert refused.value.outcome is Outcome.MALFORMED


def test_an_expired_session_is_its_own_refusal(provider, sign_in):
    """Separated from every other no because it is the only one with a remedy
    that is not "sign in again": the middleware renews it in place."""
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(provider.id_token(expires_in=-60)))
    assert refused.value.outcome is Outcome.EXPIRED


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "aud", "iss"])
def test_a_token_missing_any_claim_that_decides_who_this_is_is_refused(
    provider, sign_in, missing
):
    """Present-and-valid is not the same as required.

    The library checks a claim it finds and says nothing about one that is
    absent, so a token with no `exp` never expires and one with no `aud` skips
    the audience check. All five are required of a sign-in token by the
    standard.
    """
    signed = provider.id_token()
    header, payload, signature = signed.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    del claims[missing]
    # Re-signed with the provider's real key, so this is a perfectly valid
    # signature over a token that is missing something.
    forged = jwt.encode(
        claims, provider.key, algorithm="RS256", headers={"kid": provider.kid}
    )

    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(forged))
    # Which no it is depends on the claim - a missing `aud` fails the audience
    # check, a missing `exp` fails the requirement. That it is a no at all is
    # the assertion.
    assert refused.value.outcome in {
        Outcome.MALFORMED,
        Outcome.WRONG_AUDIENCE,
        Outcome.WRONG_ISSUER,
    }


def test_a_token_for_another_audience_is_refused(provider, sign_in):
    """A token minted for a different service in the same estate.

    It is signed by the same provider with the same key, so the signature is
    perfect. Only the audience says it was never meant for muster.
    """
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(provider.id_token(audience="some-other-service")))
    assert refused.value.outcome is Outcome.WRONG_AUDIENCE


def test_a_token_from_another_issuer_is_refused(provider, sign_in):
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(provider.id_token(issuer="https://elsewhere")))
    assert refused.value.outcome is Outcome.WRONG_ISSUER


def test_an_access_token_is_not_a_sign_in(provider, sign_in):
    """Providers that stamp a token's purpose are believed about it."""
    with pytest.raises(Refused) as refused:
        run(
            sign_in.administrator_for(
                provider.id_token(token_use="access")  # noqa: S106 - a claim name
            )
        )
    assert refused.value.outcome is Outcome.MALFORMED


def test_a_token_naming_no_key_is_refused(provider, sign_in):
    token = jwt.encode({"sub": "x"}, provider.key, algorithm="RS256")
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(token))
    assert refused.value.outcome is Outcome.MALFORMED


def test_the_first_fetch_happens_whatever_the_clock_counts_from(provider):
    """"Never fetched" must read as older than the interval on any clock.

    A zero sentinel works against a wall clock and stops working against one
    that starts near zero - a monotonic clock on a freshly booted host - where
    the first fetch would be skipped and the first sign-in refused for want of a
    key. The sentinel should not depend on the epoch.
    """
    at_zero = Clock()
    at_zero.t = 0.0
    sign_in = provider.sign_in(clock=at_zero)

    person = run(sign_in.administrator_for(provider.id_token()))

    assert person.subject == ADMIN_SUBJECT
    assert provider.jwks_fetches == 1


def test_a_key_rotation_is_picked_up_without_a_restart(provider):
    clock = Clock()
    sign_in = provider.sign_in(clock=clock)
    run(sign_in.administrator_for(provider.id_token()))

    provider.kid = "key-2"
    clock.advance(administrator.JWKS_REFETCH_INTERVAL_S)
    person = run(sign_in.administrator_for(provider.id_token()))

    assert person.subject == ADMIN_SUBJECT
    assert provider.jwks_fetches == 2


def test_an_unknown_key_does_not_let_a_stranger_hammer_the_provider(provider):
    """One refetch per interval, not one per request.

    The key id comes from a token anybody can supply, so "fetch whenever the kid
    is unknown" is a way to make muster flood the identity provider from a
    single unauthenticated endpoint.
    """
    clock = Clock()
    sign_in = provider.sign_in(clock=clock)
    run(sign_in.administrator_for(provider.id_token()))

    for _ in range(5):
        with pytest.raises(Refused) as refused:
            run(sign_in.administrator_for(provider.id_token(kid="invented")))
        assert refused.value.outcome is Outcome.UNKNOWN_KEY

    assert provider.jwks_fetches == 1


def test_keys_that_cannot_be_fetched_are_a_refusal_not_an_exception(provider):
    def refuse(request):
        raise httpx.ConnectError("no route to host")

    sign_in = provider.sign_in(transport=httpx.MockTransport(refuse))
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(provider.id_token()))
    assert refused.value.outcome is Outcome.PROVIDER_UNREACHABLE


def test_a_provider_that_is_down_is_not_asked_again_every_two_seconds(provider):
    """THE INTERVAL HAS TO APPLY TO FAILURES, which is when it matters.

    The console polls every two seconds. If only a successful fetch started the
    clock, an outage would turn every poll into another attempt - each one
    waiting out the ten-second timeout while holding the lock, on the single pod
    that also answers enrolling devices. Rate-limiting only the happy path is
    rate-limiting the case that was never a problem.
    """
    attempts = []

    def refuse(request):
        attempts.append(request.url)
        raise httpx.ConnectError("no route to host")

    clock = Clock()
    sign_in = provider.sign_in(transport=httpx.MockTransport(refuse), clock=clock)

    for _ in range(10):
        with pytest.raises(Refused):
            run(sign_in.administrator_for(provider.id_token()))

    assert len(attempts) == 1, attempts

    # And it does try again once the interval is up, or an outage would be
    # permanent until somebody restarted the pod.
    clock.advance(administrator.JWKS_REFETCH_INTERVAL_S)
    with pytest.raises(Refused):
        run(sign_in.administrator_for(provider.id_token()))
    assert len(attempts) == 2


def test_a_provider_never_reached_is_not_reported_as_an_unknown_key(provider):
    """Two different problems, and only one of them is about the token."""

    def refuse(request):
        raise httpx.ConnectError("no route to host")

    sign_in = provider.sign_in(transport=httpx.MockTransport(refuse))
    with pytest.raises(Refused) as refused:
        run(sign_in.administrator_for(provider.id_token()))
    assert refused.value.outcome is Outcome.PROVIDER_UNREACHABLE

    with pytest.raises(Refused) as again:
        run(sign_in.administrator_for(provider.id_token()))
    assert again.value.outcome is Outcome.PROVIDER_UNREACHABLE


def test_an_injected_transport_survives_more_than_one_call(provider):
    """A client closes the transport it was handed, whether or not it owns it.

    Nothing would say so today, because the fake transport's close is a no-op -
    it would surface the first time somebody wired in a real one, as every
    second request failing.
    """
    closed = []
    inner = httpx.MockTransport(provider.handler)

    class Counting(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return await inner.handle_async_request(request)

        async def aclose(self):
            closed.append(True)

    sign_in = provider.sign_in(transport=Counting())
    run(sign_in.administrator_for(provider.id_token()))
    run(sign_in.administrator_for(provider.id_token()))

    assert closed == []


def test_a_url_that_cannot_be_parsed_is_refused_at_startup(provider):
    """Not on every request, forever, as a 500 with nothing saying why."""
    with pytest.raises(RuntimeError) as complaint:
        administrator.Provider.from_env(
            {
                "MUSTER_OIDC_ISSUER": ISSUER,
                "MUSTER_OIDC_JWKS_URL": "https://identity.example.test:notaport/keys",
                "MUSTER_OIDC_AUTHORIZE_URL": AUTHORIZE_URL,
                "MUSTER_OIDC_TOKEN_URL": TOKEN_URL,
                "MUSTER_OIDC_CLIENT_ID": CLIENT_ID,
            }
        )
    assert "MUSTER_OIDC_JWKS_URL" in str(complaint.value)


def test_a_url_with_no_host_is_refused_at_startup():
    with pytest.raises(RuntimeError) as complaint:
        administrator.Provider.from_env(
            {
                "MUSTER_OIDC_ISSUER": ISSUER,
                "MUSTER_OIDC_JWKS_URL": JWKS_URL,
                "MUSTER_OIDC_AUTHORIZE_URL": "/authorize",
                "MUSTER_OIDC_TOKEN_URL": TOKEN_URL,
                "MUSTER_OIDC_CLIENT_ID": CLIENT_ID,
            }
        )
    assert "MUSTER_OIDC_AUTHORIZE_URL" in str(complaint.value)


# ---- renewing -------------------------------------------------------------


def test_a_session_is_renewed_without_sending_the_operator_back(provider, sign_in):
    person, tokens = run(sign_in.renew("renewal-token"))

    assert person.subject == ADMIN_SUBJECT
    assert provider.token_requests[0]["form"]["grant_type"] == "refresh_token"
    assert tokens.session


def test_a_provider_that_does_not_rotate_keeps_the_token_we_have(provider):
    """Most do not rotate. Reading "no new refresh token" as "you have none"
    would sign the operator out an hour after they signed in."""
    provider.refresh_token = None
    sign_in = provider.sign_in()

    _, tokens = run(sign_in.renew("the-one-we-already-had"))

    assert tokens.renewal == "the-one-we-already-had"


# ---- configuration --------------------------------------------------------


def test_nothing_configured_is_not_an_error():
    assert administrator.Provider.from_env({}) is None


def test_a_half_configured_provider_refuses_to_start():
    """The state that would otherwise serve a sign-in button that cannot work,
    and look exactly like a server where nobody has set this up yet."""
    with pytest.raises(RuntimeError) as complaint:
        administrator.Provider.from_env(
            {"MUSTER_OIDC_ISSUER": ISSUER, "MUSTER_OIDC_CLIENT_ID": CLIENT_ID}
        )
    assert "MUSTER_OIDC_TOKEN_URL" in str(complaint.value)


def test_a_fully_configured_provider_is_read():
    read = administrator.Provider.from_env(
        {
            "MUSTER_OIDC_ISSUER": ISSUER,
            "MUSTER_OIDC_JWKS_URL": JWKS_URL,
            "MUSTER_OIDC_AUTHORIZE_URL": AUTHORIZE_URL,
            "MUSTER_OIDC_TOKEN_URL": TOKEN_URL,
            "MUSTER_OIDC_CLIENT_ID": CLIENT_ID,
        }
    )
    assert read is not None and read.client_id == CLIENT_ID
    assert read.client_secret == ""


def test_the_allowlist_is_a_list_and_tolerates_spaces():
    subjects = administrator.administrators_from_env(
        {"MUSTER_ADMIN_SUBJECTS": " one, two ,, three "}
    )
    assert subjects == frozenset({"one", "two", "three"})


def test_no_allowlist_reads_as_nobody():
    assert administrator.administrators_from_env({}) == frozenset()


def test_ending_the_session_at_the_provider_is_optional(provider):
    """No URL configured means there is nowhere to send them, not an error.
    Ending muster's own session is the part that has to work."""
    assert provider.sign_in().end_session_url("https://muster.example.test/") == ""

    with_logout = provider.sign_in(
        provider=administrator.Provider(
            issuer=ISSUER,
            jwks_url=JWKS_URL,
            authorize_url=AUTHORIZE_URL,
            token_url=TOKEN_URL,
            client_id=CLIENT_ID,
            end_session_url="https://identity.example.test/logout",
        )
    )
    url = with_logout.end_session_url("https://muster.example.test/")
    assert url.startswith("https://identity.example.test/logout?")
    assert query_of(url)["client_id"] == CLIENT_ID
