"""The signed times on revocation artifacts (muster#230 item 8).

Issuance backdates `not_before` so a device with a slow clock does not reject
a certificate that is not valid yet. A CRL or OCSP answer whose thisUpdate is
the signing instant has the same failure at a relying party whose clock runs
behind: an artifact from its future. These tests pin the backdate and the
cache header that has to follow it.
"""
from __future__ import annotations

import base64
import datetime as dt
import urllib.parse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from muster import kith as kith_store
from muster import revocation, routes_revocation
from muster.api import State, create_app
from muster.ca import Authority
from muster.enroll import Enrollment
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


def _revocation_app():
    authority = Authority.create(
        "muster test CA", clock=lambda: NOW - dt.timedelta(days=1)
    )
    kith = kith_store.Kith(kith_store.MemoryRecords(), clock=lambda: NOW)
    state = State(
        enrollment=Enrollment(clock=lambda: NOW.timestamp()),
        authority=authority,
        kith=kith,
    )
    return authority, state, create_app(state)


def test_crl_route_offloads_to_threadpool(monkeypatch):
    authority, _state, app = _revocation_app()
    calls: list[str] = []
    real_offload = routes_revocation.run_in_threadpool

    async def spy(func, *args, **kwargs):
        calls.append(func.__name__)
        return await real_offload(func, *args, **kwargs)

    monkeypatch.setattr(routes_revocation, "run_in_threadpool", spy)
    crl_url = urllib.parse.urlsplit(authority.crl_url)

    with TestClient(app) as client:
        response = client.get(
            crl_url.path or "/",
            headers={"host": crl_url.hostname or ""},
        )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pkix-crl"
    assert calls == ["crl"]


def test_ocsp_routes_offload_to_threadpool(monkeypatch):
    authority, _state, app = _revocation_app()
    calls: list[tuple[str, bytes]] = []
    real_offload = routes_revocation.run_in_threadpool

    async def spy(func, *args, **kwargs):
        calls.append((func.__name__, args[0]))
        return await real_offload(func, *args, **kwargs)

    monkeypatch.setattr(routes_revocation, "run_in_threadpool", spy)
    request_der = _ocsp_request_der(authority)
    ocsp_url = urllib.parse.urlsplit(authority.ocsp_url)
    host = ocsp_url.hostname or ""
    base_path = ocsp_url.path.rstrip("/")
    encoded = urllib.parse.quote(base64.b64encode(request_der).decode("ascii"), safe="")

    with TestClient(app) as client:
        post_resp = client.post(
            ocsp_url.path or "/",
            content=request_der,
            headers={"host": host, "content-type": "application/ocsp-request"},
        )
        get_resp = client.get(
            f"{base_path}/{encoded}",
            headers={"host": host},
        )

    assert post_resp.status_code == 200
    assert get_resp.status_code == 200
    assert post_resp.headers["content-type"] == "application/ocsp-response"
    assert get_resp.headers["content-type"] == "application/ocsp-response"
    assert calls == [("ocsp", request_der), ("ocsp", request_der)]
