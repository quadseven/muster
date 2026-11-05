"""The signed times on revocation artifacts (muster#230 item 8).

Issuance backdates `not_before` so a device with a slow clock does not reject
a certificate that is not valid yet. A CRL or OCSP answer whose thisUpdate is
the signing instant has the same failure at a relying party whose clock runs
behind: an artifact from its future. These tests pin the backdate and the
cache header that has to follow it.
"""
from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from muster import kith as kith_store
from muster import revocation
from muster.ca import Authority
from muster.routes_revocation import _cache_headers

NOW = dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.timezone.utc)


def _responder():
    authority = Authority.create(
        "muster test CA", clock=lambda: NOW - dt.timedelta(days=1)
    )
    kith = kith_store.Kith(kith_store.MemoryRecords(), clock=lambda: NOW)
    return authority, revocation.Responder(authority, kith, clock=lambda: NOW)


def _ocsp_request_der(authority):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
    )
    identity = authority.issue(
        csr.public_bytes(serialization.Encoding.DER), "pixel"
    )
    cert = x509.load_pem_x509_certificate(identity.certificate_pem)
    ca_cert = x509.load_pem_x509_certificate(authority.certificate_pem)
    return (
        ocsp.OCSPRequestBuilder()
        .add_certificate(cert, ca_cert, hashes.SHA256())
        .build()
        .public_bytes(serialization.Encoding.DER)
    )


def test_the_crl_this_update_is_backdated_for_relying_party_clock_skew():
    _authority, responder = _responder()

    artifact = responder.crl()
    crl = x509.load_der_x509_crl(artifact.content)

    assert crl.last_update_utc == NOW - revocation.CLOCK_SKEW
    assert crl.next_update_utc == NOW + revocation.FRESHNESS
    assert artifact.produced_at == NOW


def test_the_ocsp_this_update_is_backdated_for_relying_party_clock_skew():
    authority, responder = _responder()

    artifact = responder.ocsp(_ocsp_request_der(authority))
    parsed = ocsp.load_der_ocsp_response(artifact.content)

    assert parsed.this_update_utc == NOW - revocation.CLOCK_SKEW
    assert parsed.next_update_utc == NOW + revocation.FRESHNESS
    assert artifact.produced_at == NOW


def test_max_age_runs_from_when_the_artifact_was_made_not_from_this_update():
    """The backdate widens thisUpdate to nextUpdate. A max-age measured from
    thisUpdate would let a cache serve the artifact past its signed
    nextUpdate by exactly the backdate."""
    _authority, responder = _responder()

    headers = _cache_headers(responder.crl())

    assert headers["Cache-Control"] == (
        f"public, max-age={int(revocation.FRESHNESS.total_seconds())}, "
        "must-revalidate"
    )
