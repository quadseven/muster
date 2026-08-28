"""Prove possession of an issued key, over a connection that strips client certs.

WHY THIS EXISTS INSTEAD OF mTLS (muster#1). Two independent walls:

  * Cloudflare only accepts a custom CA for client-certificate validation on
    ENTERPRISE accounts. muster.casa is Free.
  * Even on Enterprise it would not reach us. Cloudflare Tunnel opens a NEW
    connection to the origin, so a certificate presented at the edge never gets
    to the pod. The application would be trusting headers a proxy wrote, which
    is a different trust model wearing mTLS's clothes.

So possession is proven at the APPLICATION layer: muster issues a nonce, the
device signs it with the key in its Android Keystore, and muster verifies the
signature against the certificate it issued to that device. The proof then
survives Cloudflare, tunnels, and anything else in the path, because it never
depended on the transport.

THE THREE THINGS THAT MAKE IT A PROOF RATHER THAN A RITUAL:

  1. The nonce is SERVER-ISSUED. A client-chosen challenge is not a challenge -
     an attacker replays one they already have a signature for.
  2. It is SINGLE USE. Verified once, consumed, whatever the outcome. A nonce
     that survives a failed attempt is one an attacker can grind against.
  3. It EXPIRES. Bounded replay window if a signature is ever observed.
"""
from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass, field
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

# Long enough for a phone on a slow link to sign and come back, short enough
# that an observed signature is worthless by the time anyone could use it.
NONCE_TTL_S = 120.0

# 256 bits. The nonce is not a secret - it goes out in the clear - but it must
# be unguessable, or an attacker precomputes signatures for likely values.
NONCE_BYTES = 32


class Verdict(str, Enum):
    OK = "ok"
    NO_SUCH_NONCE = "no-such-nonce"
    NONCE_EXPIRED = "nonce-expired"
    NONCE_USED = "nonce-used"
    BAD_SIGNATURE = "bad-signature"
    CERT_EXPIRED = "cert-expired"
    CERT_NOT_OURS = "cert-not-ours"


@dataclass
class Challenge:
    nonce: str
    issued_at: float
    ttl_s: float
    used: bool = False

    def expired_at(self, now: float) -> bool:
        return now - self.issued_at >= self.ttl_s


@dataclass
class Proofs:
    """Issues challenges and checks the answers.

    `clock` injected: every rule here is about time, and a test that cannot move
    time can only ever assert the happy path.
    """

    clock: object
    ca_certificate: x509.Certificate
    challenges: dict = field(default_factory=dict)

    def _now(self) -> float:
        return self.clock()  # type: ignore[operator]

    def challenge(self, ttl_s: float = NONCE_TTL_S) -> Challenge:
        nonce = secrets.token_urlsafe(NONCE_BYTES)
        entry = Challenge(nonce=nonce, issued_at=self._now(), ttl_s=ttl_s)
        self.challenges[nonce] = entry
        return entry

    def verify(
        self, nonce: str, signature: bytes, certificate_pem: bytes
    ) -> Verdict:
        """Did the holder of this certificate's key sign this nonce?

        The nonce is consumed on EVERY path out of here, including failures.
        Leaving it alive after a bad signature hands an attacker unlimited
        attempts against one challenge, which is the whole value of a nonce.
        """
        entry = self.challenges.pop(nonce, None)
        if entry is None:
            return Verdict.NO_SUCH_NONCE
        if entry.used:
            return Verdict.NONCE_USED
        if entry.expired_at(self._now()):
            return Verdict.NONCE_EXPIRED

        try:
            cert = x509.load_pem_x509_certificate(certificate_pem)
        except Exception:  # noqa: BLE001 - unparseable is just not ours
            return Verdict.CERT_NOT_OURS

        # Issued by US, checked with the library's own routine rather than a
        # hand-rolled issuer-plus-signature comparison. Comparing issuer names
        # alone proves nothing - a name is a string an attacker can put in their
        # own self-signed certificate - and hand-verifying the signature means
        # getting the hash algorithm out of the certificate, which is Optional
        # and would be a TypeError on the one input designed to be hostile.
        try:
            cert.verify_directly_issued_by(self.ca_certificate)
        except (InvalidSignature, ValueError, TypeError):
            return Verdict.CERT_NOT_OURS

        now = dt.datetime.fromtimestamp(self._now(), dt.timezone.utc)
        if now >= cert.not_valid_after_utc:
            # LAPSED is how revocation works here (CONTEXT.md), so this is not
            # an edge case - it is the mechanism, and it has to be enforced at
            # the point of use or it is not enforced at all.
            return Verdict.CERT_EXPIRED

        try:
            cert.public_key().verify(
                signature, nonce.encode(), ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return Verdict.BAD_SIGNATURE

        return Verdict.OK

    def sweep(self) -> int:
        """Drop expired challenges. Returns how many went."""
        now = self._now()
        dead = [n for n, c in self.challenges.items() if c.expired_at(now)]
        for nonce in dead:
            del self.challenges[nonce]
        return len(dead)
