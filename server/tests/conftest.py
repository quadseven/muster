"""A stand-in identity provider, so sign-in can be tested without one.

REAL KEYS, REAL SIGNATURES, FAKE NETWORK. The fake mints tokens with an RSA key
it generates and publishes the matching JWKS, and muster verifies them with the
same code path it uses in production. What is faked is only the transport: httpx
takes a handler in place of a socket, so the request muster builds - the form it
posts, the PKCE verifier it sends, the URL it fetches keys from - is the real
one and a test can look at it.

That matters more here than in most places. A test that stubs out verification
proves that the code around verification works, which is not the thing anybody
is worried about.
"""
from __future__ import annotations

import base64
import time
import urllib.parse
from dataclasses import dataclass, field

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from muster import administrator

ISSUER = "https://identity.example.test/pool"
JWKS_URL = "https://identity.example.test/pool/keys"
AUTHORIZE_URL = "https://identity.example.test/authorize"
TOKEN_URL = "https://identity.example.test/token"  # noqa: S105 - a URL, not a token
CLIENT_ID = "muster-console"
ADMIN_SUBJECT = "s-0001-administrator"
STRANGER_SUBJECT = "s-9999-somebody-else"
REDIRECT_URI = "https://muster.example.test/auth/callback"


def _b64(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass
class FakeProvider:
    """One key, one pool, and a memory of what muster asked it for."""

    kid: str = "key-1"
    key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
    )
    token_requests: list[dict] = field(default_factory=list)
    jwks_fetches: int = 0
    # Set by `redeem`, so the token endpoint can echo the nonce muster sent.
    last_nonce: str = ""
    # Overrides a test can reach for without rewriting the handler.
    nonce_to_return: str | None = None
    # A fixed string so a test can assert which token was presented back to
    # this fake provider. S105 reads the field name; nothing here is secret.
    refresh_token: str | None = "renewal-token"  # noqa: S105
    subject: str = ADMIN_SUBJECT
    token_status: int = 200
    token_body: dict | None = None

    def jwks(self) -> dict:
        numbers = self.key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self.kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64(numbers.n),
                    "e": _b64(numbers.e),
                }
            ]
        }

    def id_token(
        self,
        *,
        subject: str | None = None,
        email: str = "administrator@example.test",
        nonce: str | None = None,
        issuer: str = ISSUER,
        audience: str = CLIENT_ID,
        expires_in: int = 3600,
        kid: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        algorithm: str = "RS256",
        **extra,
    ) -> str:
        claims = {
            "sub": self.subject if subject is None else subject,
            "email": email,
            "iss": issuer,
            "aud": audience,
            "token_use": "id",
            "iat": int(time.time()) - 5,
            "exp": int(time.time()) + expires_in,
        }
        if nonce is not None:
            claims["nonce"] = nonce
        claims.update(extra)
        signing_key = key or self.key
        return jwt.encode(
            claims,
            signing_key,
            algorithm=algorithm,
            headers={"kid": kid or self.kid},
        )

    def redeem(self, authorize_url: str) -> tuple[str, str]:
        """Play the browser and the provider: hand back a code and the state.

        Remembers the nonce muster put in the authorize URL so the token
        endpoint can put it back in the token, which is what ties the two halves
        of one sign-in together.
        """
        query = urllib.parse.parse_qs(urllib.parse.urlparse(authorize_url).query)
        self.last_nonce = query["nonce"][0]
        return "an-authorization-code", query["state"][0]

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith(JWKS_URL):
            self.jwks_fetches += 1
            return httpx.Response(200, json=self.jwks())
        if url.startswith(TOKEN_URL):
            self.token_requests.append(
                {
                    "form": dict(urllib.parse.parse_qsl(request.content.decode())),
                    "authorization": request.headers.get("authorization", ""),
                }
            )
            if self.token_status != 200:
                return httpx.Response(
                    self.token_status, json=self.token_body or {"error": "invalid_grant"}
                )
            if self.token_body is not None:
                return httpx.Response(200, json=self.token_body)
            nonce = (
                self.nonce_to_return
                if self.nonce_to_return is not None
                else self.last_nonce
            )
            body = {"id_token": self.id_token(nonce=nonce), "token_type": "Bearer"}
            if self.refresh_token:
                body["refresh_token"] = self.refresh_token
            return httpx.Response(200, json=body)
        raise AssertionError(f"the fake provider was asked for {url}")

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    @property
    def config(self) -> administrator.Provider:
        return administrator.Provider(
            issuer=ISSUER,
            jwks_url=JWKS_URL,
            authorize_url=AUTHORIZE_URL,
            token_url=TOKEN_URL,
            client_id=CLIENT_ID,
        )

    def sign_in(self, **kwargs) -> administrator.SignIn:
        settings = {
            "provider": self.config,
            "administrators": frozenset({ADMIN_SUBJECT}),
            "redirect_uri": REDIRECT_URI,
            "transport": self.transport,
        }
        settings.update(kwargs)
        return administrator.SignIn(**settings)


@pytest.fixture()
def provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture()
def sign_in(provider: FakeProvider) -> administrator.SignIn:
    return provider.sign_in()
