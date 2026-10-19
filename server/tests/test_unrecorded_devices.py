from __future__ import annotations

import datetime as dt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from muster import kith as kith_store
from muster.api import State, create_app
from muster.ca import Authority
from muster.proof import Proofs
from muster.enroll import Enrollment
from tests.conftest import FakeProvider

_ADMIN_PROVIDER = FakeProvider()
ADMIN = { "session": _ADMIN_PROVIDER.id_token() } # Simplification for test

def state():
    return State(
        enrollment=Enrollment(clock=lambda: dt.datetime.now(dt.timezone.utc)),
        authority=Authority.create("muster test CA"),
        sign_in=_ADMIN_PROVIDER.sign_in(),
    )

@pytest.fixture()
def client(state):
    return TestClient(create_app(state))

def _create_signed_cert(authority, name="pixel"):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)]))
        .sign(key, hashes.SHA256())
    )
    identity = authority.issue(csr.public_bytes(serialization.Encoding.DER), name)
    return key, identity

def test_device_presenting_valid_cert_gets_kith_row(client, state):
    # 1. Create a certificate signed by this CA but NOT in the kith
    key, identity = _create_signed_cert(state.authority)
    cert_pem = identity.certificate_pem.decode()
    
    # Use the launderer for Proofs setup
    state.proofs = Proofs(
        ca_certificate=state.authority.certificate_pem,
    )

    # 2. Device proves possession (e.g. via /v1/auth/verify)
    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    import base64
    sig_b64 = base64.b64encode(signature).decode()

    # This call should trigger the "recording" of the unrecorded device
    response = client.post("/v1/auth/verify", json={
        "nonce": nonce,
        "signature_b64": sig_b64,
        "certificate_pem": cert_pem,
    })
    assert response.status_code == 200
    
    # 3. Verify it's now in the kith
    from muster.enroll import key_id
    pk_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = key_id(pk_der)
    
    member = state.kith.member(kid)
    assert member is not None
    assert member.device.name == "pixel"

def test_invalid_cert_cannot_create_kith_row(client, state):
    # 1. Create a certificate signed by a DIFFERENT CA
    other_ca = Authority.create("other CA")
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "impostor")]))
        .sign(key, hashes.SHA256())
    )
    identity = other_ca.issue(csr.public_bytes(serialization.Encoding.DER), "impostor")
    cert_pem = identity.certificate_pem.decode()
    state.proofs = Proofs(
        clock=state.enrollment.clock,
        ca_certificate=state.authority.certificate_pem,
    )


    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    import base64
    sig_b64 = base64.b64encode(signature).decode()

    response = client.post("/v1/auth/verify", json={
        "nonce": nonce,
        "signature_b64": sig_b64,
        "certificate_pem": cert_pem,
    })
    assert response.status_code == 401
    
    # Verify no row was created
    from muster.enroll import key_id
    pk_der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = key_id(pk_der)
    assert state.kith.member(kid) is None
