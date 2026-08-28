"""Proving possession of an issued key, and every way the proof fails.

The three that carry the security are `a_nonce_cannot_be_replayed`,
`a_self_signed_certificate_is_refused`, and `a_signature_over_a_different_nonce
_is_refused`. Between them they say: you cannot reuse an answer, you cannot
bring your own certificate, and you cannot answer a question nobody asked.
"""
from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from muster.ca import Authority
from muster.proof import Proofs, Verdict


class Clock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def ca(clock):
    return Authority.create(
        "muster test CA",
        clock=lambda: dt.datetime.fromtimestamp(clock(), dt.timezone.utc),
    )


@pytest.fixture()
def proofs(clock, ca):
    return Proofs(
        clock=clock,
        ca_certificate=x509.load_pem_x509_certificate(ca.certificate_pem),
    )


def _enrolled(ca, name="pixel-6a-new", valid_days=90):
    """A device with a key and a certificate muster issued to it."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "whatever")]))
        .sign(key, hashes.SHA256())
    )
    identity = ca.issue(
        csr.public_bytes(serialization.Encoding.DER), name, valid_days=valid_days
    )
    return key, identity.certificate_pem


def _sign(key, nonce: str) -> bytes:
    return key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))


# ---- the happy path ------------------------------------------------------


def test_an_enrolled_device_proves_possession(proofs, ca):
    key, cert_pem = _enrolled(ca)
    challenge = proofs.challenge()
    assert proofs.verify(challenge.nonce, _sign(key, challenge.nonce), cert_pem) is Verdict.OK


def test_the_nonce_is_unguessable_and_unique(proofs):
    seen = {proofs.challenge().nonce for _ in range(50)}
    assert len(seen) == 50
    assert all(len(n) > 40 for n in seen)


# ---- the three that carry the security -----------------------------------


def test_a_nonce_cannot_be_replayed(proofs, ca):
    """Consumed on every path, success included. A signature observed on the
    wire must be worth nothing the second time."""
    key, cert_pem = _enrolled(ca)
    challenge = proofs.challenge()
    signature = _sign(key, challenge.nonce)

    assert proofs.verify(challenge.nonce, signature, cert_pem) is Verdict.OK
    assert proofs.verify(challenge.nonce, signature, cert_pem) is Verdict.NO_SUCH_NONCE


def test_a_failed_attempt_also_consumes_the_nonce(proofs, ca):
    """Otherwise one challenge can be ground against indefinitely, which is the
    entire value of a nonce gone."""
    _key, cert_pem = _enrolled(ca)
    challenge = proofs.challenge()

    assert proofs.verify(challenge.nonce, b"rubbish", cert_pem) is Verdict.BAD_SIGNATURE
    assert proofs.verify(challenge.nonce, b"rubbish", cert_pem) is Verdict.NO_SUCH_NONCE


def test_a_self_signed_certificate_is_refused(proofs):
    """Holding a key and signing correctly proves possession of A key - not that
    muster ever vouched for it. Without this the whole ceremony is decorative."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pixel-6a-new")])
    now = dt.datetime.now(dt.timezone.utc)
    impostor = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=90))
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)

    challenge = proofs.challenge()
    assert proofs.verify(
        challenge.nonce, _sign(key, challenge.nonce), impostor
    ) is Verdict.CERT_NOT_OURS


def test_a_certificate_claiming_our_issuer_name_is_still_refused(proofs, ca):
    """An issuer name is a STRING. An attacker puts ours in their own
    self-signed certificate; only the signature says otherwise."""
    key = ec.generate_private_key(ec.SECP256R1())
    ours = x509.load_pem_x509_certificate(ca.certificate_pem).subject
    now = dt.datetime.now(dt.timezone.utc)
    forged = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pixel")]))
        .issuer_name(ours)                      # claims to be issued by muster
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=90))
        .sign(key, hashes.SHA256())             # but signed by itself
    ).public_bytes(serialization.Encoding.PEM)

    challenge = proofs.challenge()
    assert proofs.verify(
        challenge.nonce, _sign(key, challenge.nonce), forged
    ) is Verdict.CERT_NOT_OURS


def test_a_signature_over_a_different_nonce_is_refused(proofs, ca):
    """Answering a question nobody asked. This is what stops a signature
    captured from one exchange being presented in another."""
    key, cert_pem = _enrolled(ca)
    asked = proofs.challenge()
    other = proofs.challenge()
    assert proofs.verify(asked.nonce, _sign(key, other.nonce), cert_pem) is Verdict.BAD_SIGNATURE


def test_a_signature_from_a_different_key_is_refused(proofs, ca):
    _key, cert_pem = _enrolled(ca)
    someone_else = ec.generate_private_key(ec.SECP256R1())
    challenge = proofs.challenge()
    assert proofs.verify(
        challenge.nonce, _sign(someone_else, challenge.nonce), cert_pem
    ) is Verdict.BAD_SIGNATURE


# ---- time ----------------------------------------------------------------


def test_an_expired_nonce_is_refused(proofs, ca):
    key, cert_pem = _enrolled(ca)
    challenge = proofs.challenge(ttl_s=120.0)
    proofs.clock.advance(120.0)
    assert proofs.verify(challenge.nonce, _sign(key, challenge.nonce), cert_pem) is Verdict.NONCE_EXPIRED


def test_a_lapsed_certificate_is_refused(proofs, ca):
    """Not renewing IS the revocation mechanism (CONTEXT.md), so this is not an
    edge case - it is the mechanism, and it has to be enforced where the
    certificate is USED or it is not enforced anywhere."""
    key, cert_pem = _enrolled(ca, valid_days=90)
    proofs.clock.advance(91 * 86_400)
    challenge = proofs.challenge()
    assert proofs.verify(challenge.nonce, _sign(key, challenge.nonce), cert_pem) is Verdict.CERT_EXPIRED


def test_an_unknown_nonce_is_refused(proofs, ca):
    key, cert_pem = _enrolled(ca)
    assert proofs.verify("never-issued", _sign(key, "never-issued"), cert_pem) is Verdict.NO_SUCH_NONCE


def test_garbage_where_a_certificate_should_be(proofs, ca):
    key, _cert = _enrolled(ca)
    challenge = proofs.challenge()
    assert proofs.verify(
        challenge.nonce, _sign(key, challenge.nonce), b"not a certificate"
    ) is Verdict.CERT_NOT_OURS


def test_sweep_drops_expired_challenges_only(proofs):
    old = proofs.challenge(ttl_s=120.0)
    proofs.clock.advance(121.0)
    fresh = proofs.challenge(ttl_s=120.0)

    assert proofs.sweep() == 1
    assert old.nonce not in proofs.challenges
    assert fresh.nonce in proofs.challenges
