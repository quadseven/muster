"""The device channel at its interface: proof first, honest refusals, never cached.

muster#218 moved the device routes out of api.py into muster/device_channel.py.
The tests in the first half of this file were written against api.py BEFORE the
move and passed there, so they pin behavior the move had to keep: the proof is
checked before any field a route adds, the CRL and OCSP answer by hostname, and
each 503 keeps the sentence that tells a device what its existing state is.

The second half pins what the shared interface added: every refusal on a device
route is uncached, not only the ones a route remembered to mark, and every
device route is registered through that one interface.
"""
from __future__ import annotations

import base64
import urllib.parse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from muster import kith as kith_store
from muster import standing
from muster.api import State, create_app
from muster.ca import Authority
from muster.enroll import Enrollment
from tests.test_api import (
    _ADMIN_PROVIDER,
    DEVICE_PROVEN,
    Clock,
    _enrolled,
    _past_renew_after,
    _proof_client,
)


@pytest.fixture()
def state():
    """The same state test_api.py's fixture builds, so its helpers apply."""
    import datetime as dt

    return State(
        enrollment=Enrollment(clock=Clock()),
        authority=Authority.create(
            "muster test CA",
            clock=lambda: dt.datetime(2026, 8, 18, tzinfo=dt.timezone.utc),
        ),
        sign_in=_ADMIN_PROVIDER.sign_in(),
    )


def _signed(client, key, identity, path, **extra):
    """One proven POST to a device route: challenge, sign, send."""
    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    return client.post(path, json={
        "nonce": nonce,
        "signature_b64": base64.b64encode(signature).decode(),
        "certificate_pem": identity.certificate_pem.decode(),
        **extra,
    })


def _csr_pem(key, name="whatever"):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )


def _unreachable_after(state, monkeypatch, method, calls=1):
    """Let `calls` reads of `method` through, then make the store unreachable.

    The proof reads the kith before a route does, so a store that is down from
    the start answers the proof's 503 and never reaches the route's own.
    """
    real = getattr(state.kith, method)
    seen = {"n": 0}

    def flaky(*args, **kwargs):
        seen["n"] += 1
        if seen["n"] > calls:
            raise kith_store.Unreachable("the kith store cannot be read")
        return real(*args, **kwargs)

    monkeypatch.setattr(state.kith, method, flaky)


def _count(state, line):
    return f"custom.muster.{line}" in state.telemetry.sent


# ---- characterization: these passed against api.py before the move -------


@pytest.mark.parametrize("path", ["/v1/enroll/renew", "/v1/device/renew", "/v1/device/asset"])
def test_a_revoked_device_is_told_it_is_revoked_before_any_field_is_read(state, path):
    """PROOF BEFORE BODY VALIDATION. The route's own fields are defaulted, so
    a revoked device with no CSR or name hears it is revoked, not 422."""
    client = _proof_client(state)
    key, identity, key_id = _enrolled(state, record=True)
    assert state.kith.set_revoked(key_id, True)

    response = _signed(client, key, identity, path)

    assert response.status_code == 403, response.text
    assert response.json()["detail"] == standing.REVOKED_DETAIL
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("path", ["/v1/enroll/renew", "/v1/device/renew", "/v1/device/asset"])
def test_a_caller_with_no_proof_is_refused_by_the_proof_and_not_by_the_schema(
    state, path
):
    client = _proof_client(state)

    response = client.post(path, json={
        "nonce": "a-nonce-nobody-issued",
        "signature_b64": "",
        "certificate_pem": "not a certificate",
    })

    assert response.status_code == 400, response.text
    assert response.json()["detail"] == "no-such-nonce"
    assert response.headers["Cache-Control"] == "no-store"


def test_the_crl_and_ocsp_answer_on_their_own_hostnames_and_nowhere_else(state):
    client = TestClient(create_app(state))
    crl_host = urllib.parse.urlsplit(state.authority.crl_url).hostname
    ocsp_host = urllib.parse.urlsplit(state.authority.ocsp_url).hostname

    crl = client.get("/", headers={"Host": crl_host})
    console_root = client.get("/")
    ocsp = client.post(
        "/", content=b"", headers={"Host": ocsp_host,
                                   "Content-Type": "application/ocsp-request"}
    )

    assert crl.headers["content-type"] == "application/pkix-crl"
    assert console_root.headers["content-type"].startswith("text/html")
    assert ocsp.headers["content-type"] == "application/ocsp-response"
    assert client.post("/", content=b"").headers["content-type"] != (
        "application/ocsp-response"
    )


@pytest.mark.parametrize("method,path", sorted(DEVICE_PROVEN))
def test_a_refused_proof_is_uncached_on_every_device_route(state, method, path):
    client = _proof_client(state)

    response = client.request(method, path, json={
        "nonce": "a-nonce-nobody-issued",
        "signature_b64": "not base64!!",
        "certificate_pem": "x",
        "diagnostics": [],
        "steps": [],
        "packages": [],
    })

    assert response.status_code == 400, response.text
    assert response.headers["Cache-Control"] == "no-store"


def test_an_unreachable_store_during_the_proof_keeps_its_explanation(
    state, monkeypatch
):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)
    _unreachable_after(state, monkeypatch, "member", calls=0)

    response = _signed(client, key, identity, "/v1/device/config")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "the kith store is unreachable, so this device cannot be confirmed as "
        "still enrolled. Retry."
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert _count(state, "proof.revocation.unreachable:1|c")


def test_config_with_an_unreachable_role_keeps_its_explanation(state, monkeypatch):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)
    _unreachable_after(state, monkeypatch, "member")

    response = _signed(client, key, identity, "/v1/device/config")

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "the kith store cannot be read. The device keeps the configuration it "
        "already has: muster refuses to answer rather than answering with a "
        "scope it cannot confirm."
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert _count(state, "kith.read.refused:1|c")


def test_config_with_no_policy_source_keeps_its_explanation(state):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)

    response = _signed(client, key, identity, "/v1/device/config")

    assert response.status_code == 503
    assert response.json()["detail"].endswith(
        " Retry - this device's existing configuration is unaffected and stays "
        "in force."
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert _count(state, "device.config.refused:1|c|#reason:no-source")


def test_a_report_the_store_cannot_keep_keeps_its_explanation(state, monkeypatch):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)

    def down(*_args, **_kwargs):
        raise kith_store.Unreachable("the kith store cannot be written")

    monkeypatch.setattr(state.kith, "reported", down)

    response = _signed(
        client, key, identity, "/v1/device/report", steps=[], packages=[]
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "the kith store cannot be written. The report was not kept; send the "
        "next one."
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert _count(state, "device.report.refused:1|c|#reason:unreachable")


@pytest.mark.parametrize("path,noun", [
    ("/v1/device/wipe", "wipe"),
    ("/v1/device/reboot", "reboot"),
])
def test_an_acknowledgement_the_store_cannot_read_keeps_its_explanation(
    state, monkeypatch, path, noun
):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)
    _unreachable_after(state, monkeypatch, "member")

    response = _signed(client, key, identity, path)

    assert response.status_code == 503
    assert response.json()["detail"] == (
        f"the kith store cannot be read. The device is unaffected: nothing has "
        f"acted on the {noun} instruction, whichever state it turns out to be in."
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert _count(state, "kith.read.refused:1|c")


@pytest.mark.parametrize("path", ["/v1/enroll/renew", "/v1/device/renew"])
def test_a_renewal_the_store_cannot_confirm_keeps_its_explanation(
    state, monkeypatch, path
):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)
    _unreachable_after(state, monkeypatch, "member")

    response = _signed(client, key, identity, path, csr_pem=_csr_pem(key))

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "the kith store is unreachable, so this device cannot be confirmed as "
        "enrolled. Retry."
    )
    assert response.headers["Cache-Control"] == "no-store"


def test_a_renewal_the_store_cannot_space_keeps_its_explanation(state, monkeypatch):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)
    _past_renew_after(state, monkeypatch, identity)
    _unreachable_after(state, monkeypatch, "latest_issued", calls=0)

    response = _signed(
        client, key, identity, "/v1/enroll/renew", csr_pem=_csr_pem(key)
    )

    assert response.status_code == 503
    assert response.json()["detail"] == (
        "the kith store is unreachable, so muster cannot tell when this device "
        "last renewed. Retry."
    )
    assert response.headers["Cache-Control"] == "no-store"


def test_an_asset_with_no_store_keeps_its_explanation(state):
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)

    response = _signed(client, key, identity, "/v1/device/asset", name="wall.png")

    assert response.status_code == 503
    assert response.json()["detail"]
    assert response.headers["Cache-Control"] == "no-store"
    assert _count(state, "device.asset.refused:1|c|#reason:no-source")


# ---- what the shared interface adds (muster#218) ------------------------


def test_every_device_route_is_registered_through_the_device_channel(state):
    """ONE INTERFACE, NOT A HABIT. A device route registered any other way
    would have to remember no-store on its own refusals again."""
    from muster import device_channel

    app = create_app(state)
    registered = {
        (method, route.path): route
        for route in app.routes
        for method in getattr(route, "methods", set())
    }
    for method, path in sorted(DEVICE_PROVEN | {("POST", "/v1/auth/verify")}):
        route = registered[(method, path)]
        assert isinstance(route, device_channel.UncachedRoute), (method, path)
        assert route.endpoint.__module__ == "muster.device_channel", (method, path)


@pytest.mark.parametrize("method,path", sorted(DEVICE_PROVEN))
def test_a_body_the_schema_refuses_is_uncached_too(state, method, path):
    client = _proof_client(state)

    response = client.request(method, path)

    assert response.status_code == 422
    assert response.headers["Cache-Control"] == "no-store"


def test_a_route_refusal_after_the_proof_is_uncached(state):
    """Refusals a route raises for its own reasons, which used to go out with
    no cache header because each route marked only the ones it remembered."""
    client = _proof_client(state)
    key, identity, _ = _enrolled(state, record=True)
    stranger = ec.generate_private_key(ec.SECP256R1())

    answers = [
        _signed(client, key, identity, "/v1/device/diagnostics",
                diagnostics=["x" * 100_000]),
        _signed(client, key, identity, "/v1/device/diagnostics", diagnostics=["a"]),
        _signed(client, key, identity, "/v1/device/diagnostics", diagnostics=["b"]),
        _signed(client, key, identity, "/v1/device/report", steps=[], packages=[]),
        _signed(client, key, identity, "/v1/device/report", steps=[], packages=[]),
        _signed(client, key, identity, "/v1/enroll/renew"),
        _signed(client, key, identity, "/v1/enroll/renew",
                csr_pem=_csr_pem(stranger)),
        _signed(client, key, identity, "/v1/enroll/renew", csr_pem=_csr_pem(key)),
    ]

    assert [a.status_code for a in answers] == [413, 202, 429, 202, 429, 400, 403, 409]
    assert answers[2].headers["Retry-After"] == "60"
    for answer in answers:
        assert answer.headers["Cache-Control"] == "no-store", answer.text


def test_the_refusal_helper_maps_an_outage_to_an_uncached_503(state):
    from fastapi import HTTPException

    from muster import device_channel

    outage = kith_store.Unreachable("the kith store cannot be read")
    with pytest.raises(HTTPException) as refused:
        with device_channel.refusing(
            state,
            kith_store.Unreachable,
            detail=lambda exc: f"{exc}. Nothing changed.",
            counter="kith.read.refused",
            event="muster cannot say",
            key_id="k",
        ):
            raise outage

    assert refused.value.status_code == 503
    assert refused.value.detail == "the kith store cannot be read. Nothing changed."
    assert refused.value.headers == {"Cache-Control": "no-store"}
    assert refused.value.__cause__ is outage
    assert _count(state, "kith.read.refused:1|c")
