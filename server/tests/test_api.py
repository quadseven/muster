"""The HTTP surface, including the parts a stranger can reach.

Two of these endpoints are open to the internet by necessity - a device that has
not enrolled has no credential to present - so the tests that matter are the
ones asserting what an unauthenticated caller CANNOT do, and that the full
happy path still ends with a real certificate.

`test_the_whole_ceremony_end_to_end` is the readable one: mint, present, vouch,
collect, and the certificate that comes out is signed by the CA and carries the
name the administrator vouched for rather than the one the device asked for.
"""
from __future__ import annotations

import datetime as dt
import io

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from muster import console
from muster.api import State, create_app
from muster.ca import Authority
from muster.enroll import DEFAULT_CODE_TTL_S, MAX_ATTEMPTS, Enrollment
from tests.conftest import FakeProvider

# One shared fake identity provider for every test in this file that needs "an
# administrator, signed in" - not the bootstrap token, which has been removed.
# A single instance so its signing key is consistent everywhere `ADMIN` is
# presented as a cookie: any `State` built with `_ADMIN_PROVIDER.sign_in()`
# will verify it.
_ADMIN_PROVIDER = FakeProvider()
ADMIN = {console.SESSION_COOKIE: _ADMIN_PROVIDER.id_token()}


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def state(clock):
    return State(
        enrollment=Enrollment(clock=clock),
        authority=Authority.create(
            "muster test CA",
            clock=lambda: dt.datetime(2026, 8, 18, tzinfo=dt.timezone.utc),
        ),
        sign_in=_ADMIN_PROVIDER.sign_in(),
    )


@pytest.fixture()
def client(state):
    return TestClient(create_app(state))


def _csr_pem(common_name="whatever-the-device-claims"):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key


# ---- the ceremony --------------------------------------------------------


def test_the_whole_ceremony_end_to_end(client, state):
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]

    csr_pem, key = _csr_pem(common_name="i-would-like-to-be-admin")
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr_pem, "device_name": "pixel-6a-new"},
    )
    assert presented.status_code == 202
    request_id = presented.json()["request_id"]
    fingerprint = presented.json()["fingerprint"]

    # The administrator sees the same fingerprint the device is displaying.
    listed = client.get("/v1/enroll/requests", cookies=ADMIN).json()["pending"]
    assert [p["fingerprint"] for p in listed] == [fingerprint]

    vouched = client.post(
        f"/v1/enroll/requests/{request_id}/vouch",
        json={"fingerprint": fingerprint},
        cookies=ADMIN,
    )
    assert vouched.status_code == 200

    collected = client.get(f"/v1/enroll/requests/{request_id}/identity")
    assert collected.status_code == 200
    cert = x509.load_pem_x509_certificate(collected.json()["certificate_pem"].encode())

    # The name is the vouched one, not the requested one.
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "pixel-6a-new"
    # And it certifies the key the device actually holds.
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


def test_an_identity_is_handed_over_only_once(client):
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr_pem, _ = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr_pem, "device_name": "pixel"},
    ).json()
    client.post(
        f"/v1/enroll/requests/{presented['request_id']}/vouch",
        json={"fingerprint": presented["fingerprint"]},
        cookies=ADMIN,
    )

    first = client.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    second = client.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    assert first.status_code == 200
    assert second.status_code == 404, (
        "a certificate left collectable forever is a credential guarded only by "
        "a request id that has, by then, travelled"
    )


def test_collecting_before_a_vouch_says_wait_rather_than_no(client):
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr_pem, _ = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr_pem, "device_name": "pixel"},
    ).json()

    waiting = client.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    assert waiting.status_code == 202, "202 is retry; 404 would tell the device to stop"


# ---- what a stranger cannot do -------------------------------------------


@pytest.mark.parametrize(
    "method,path",
    [("post", "/v1/enroll/codes"),
     ("get", "/v1/enroll/requests"),
     ("post", "/v1/enroll/requests/anything/vouch")],
)
def test_admin_endpoints_refuse_without_a_token(client, method, path):
    # GET takes no body in this client, so the kwarg cannot be passed blindly.
    kwargs = {"json": {}} if method == "post" else {}
    response = getattr(client, method)(path, **kwargs)
    assert response.status_code == 401


def test_admin_endpoints_refuse_a_wrong_token(client):
    response = client.post(
        "/v1/enroll/codes", json={}, headers={"Authorization": "Bearer nope"}
    )
    assert response.status_code == 401


def test_a_bare_token_without_the_bearer_prefix_is_refused(client):
    response = client.post(
        "/v1/enroll/codes", json={}, headers={"Authorization": "test-admin-token"}
    )
    assert response.status_code == 401


def test_a_racer_who_guesses_the_code_gets_nothing_without_a_vouch(client):
    """The attack, over HTTP this time. The racer presents successfully - that
    endpoint is open by necessity - and then cannot get past the vouch, because
    the administrator is comparing against the fingerprint on their own device."""
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]

    attacker_csr, _ = _csr_pem()
    attacker = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": attacker_csr, "device_name": "not-your-phone"},
    ).json()

    honest_fingerprint = "AAAA BBBB CCCC DDDD"
    refused = client.post(
        f"/v1/enroll/requests/{attacker['request_id']}/vouch",
        json={"fingerprint": honest_fingerprint},
        cookies=ADMIN,
    )
    assert refused.status_code == 409
    assert client.get(
        f"/v1/enroll/requests/{attacker['request_id']}/identity"
    ).status_code == 202


# ---- refusals map to statuses a device can act on ------------------------


def test_a_wrong_code_is_403(client):
    minted = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    wrong = f"{(int(minted) + 1) % 10 ** 6:06d}"
    csr_pem, _ = _csr_pem()
    response = client.post(
        "/v1/enroll/requests",
        json={"code": wrong, "csr_pem": csr_pem, "device_name": "pixel"},
    )
    assert response.status_code == 403


def test_an_expired_code_is_410_not_403(client, clock):
    """410 and 403 are both no; only one of them means "ask for a new code"."""
    code = client.post(
        "/v1/enroll/codes", json={"ttl_s": 300.0}, cookies=ADMIN
    ).json()["code"]
    clock.advance(301.0)
    csr_pem, _ = _csr_pem()
    response = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr_pem, "device_name": "pixel"},
    )
    assert response.status_code == 410


def test_a_reused_code_is_409(client):
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr_pem, _ = _csr_pem()
    body = {"code": code, "csr_pem": csr_pem, "device_name": "pixel"}
    client.post("/v1/enroll/requests", json=body)
    assert client.post("/v1/enroll/requests", json=body).status_code == 409


def test_an_unreadable_csr_is_400(client):
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    response = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": "not a csr", "device_name": "pixel"},
    )
    assert response.status_code == 400


# ---- startup -------------------------------------------------------------


def test_the_app_refuses_to_start_without_administrator_sign_in(monkeypatch):
    """An admin surface that comes up open because a variable was unset fails at
    the worst moment: the first time it is exposed, before anyone is watching."""
    from muster.api import app_from_env

    for name in _SIGN_IN_ENV:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError) as caught:
        app_from_env()
    assert "MUSTER_OIDC" in str(caught.value)


def test_health_endpoints_need_no_token(client):
    assert client.get("/livez").status_code == 200
    assert client.get("/readyz").status_code == 200


# ---- the console ---------------------------------------------------------


def test_the_console_is_served_and_carries_no_secrets(client):
    """Unauthenticated on purpose - it is the page the sign-in button is on,
    and there is nothing in it that is not in this repository. Everything it
    shows comes from calls that carry the session cookie, so a reader who is
    not signed in gets the shell and no data."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    body = response.text
    assert "PRIVATE KEY" not in body


def test_the_console_makes_the_operator_confirm_the_fingerprint(client):
    """The security model is a comparison between two screens. A one-click
    approve makes it a comparison between a human and their own impatience, so
    the page must open a confirmation that shows the fingerprint alone."""
    body = client.get("/").text
    assert "openConfirm" in body
    assert "Does this match the device?" in body
    # The vouch call must send a fingerprint, not just an id.
    assert "fingerprint: pendingRequest.fingerprint" in body


def test_the_console_does_not_persist_a_credential(client):
    """The session is an HttpOnly cookie the browser attaches on its own, so
    there is nothing for the page to keep - and a credential a script can read
    is the shared token in a different shirt."""
    body = client.get("/").text
    # Checks for CALLS, not for the word: the page carries a comment explaining
    # why it stores nothing, and an assertion that trips on its own
    # documentation teaches people to delete the comment.
    for store in ("localStorage", "sessionStorage"):
        for call in (f"{store}.setItem", f"{store}["):
            assert call not in body, f"the console persists a credential via {call}"


# ---- the pairing QR, which is gone ---------------------------------------


def test_there_is_no_pairing_qr_because_nothing_could_ever_read_it(client):
    """A QR nothing can scan is worse than no QR (muster#47).

    This endpoint rendered the pairing code as a QR "so a freshly provisioned
    device needs neither typed at it", and no device could read it: the agent
    declares no CAMERA permission, contains no scanner, and EnrollActivity has
    only a MAIN/LAUNCHER intent-filter. Drawing it taught an operator to hold a
    phone up to a monitor and wait for something that would never happen.

    Asserted rather than deleted quietly, because the tempting fix for "the QR
    does nothing" is to add the endpoint back rather than the scanner.
    """
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    assert client.get(f"/v1/enroll/codes/{code}/qr.svg", cookies=ADMIN).status_code == 404


# ---- proof of possession over HTTP ---------------------------------------


def _proof_client(state):
    from muster.proof import Proofs
    from cryptography import x509 as _x509

    state.proofs = Proofs(
        clock=state.enrollment.clock,
        ca_certificate=_x509.load_pem_x509_certificate(state.authority.certificate_pem),
    )
    return TestClient(create_app(state))


def test_a_device_proves_possession_over_http(state):
    import base64

    client = _proof_client(state)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
    )
    identity = state.authority.issue(csr.public_bytes(serialization.Encoding.DER), "pixel")

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    response = client.post("/v1/auth/verify", json={
        "nonce": nonce,
        "signature_b64": base64.b64encode(signature).decode(),
        "certificate_pem": identity.certificate_pem.decode(),
    })
    assert response.status_code == 200
    assert response.json()["verdict"] == "ok"


def test_an_unrecognised_certificate_is_401_not_403(state):
    """401 says 'I do not know you, enroll'; 403 would say 'I know you and you
    may not'. A device acting on the wrong one does the wrong recovery."""
    import base64

    client = _proof_client(state)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")])
    now = dt.datetime.now(dt.timezone.utc)
    selfsigned = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    response = client.post("/v1/auth/verify", json={
        "nonce": nonce,
        "signature_b64": base64.b64encode(signature).decode(),
        "certificate_pem": selfsigned.decode(),
    })
    assert response.status_code == 401


def test_unanswered_challenges_do_not_accumulate_forever(state, clock):
    """`Proofs.sweep` HAD TESTS AND NO CALLER, which is this codebase's own
    recurring failure - a mechanism that is written, green, and unreachable.

    It matters more now that every device asks for a nonce at every boot
    (muster#46): a challenge nobody answers stayed in memory for the life of the
    process, so anyone who could reach this open endpoint could grow the pod
    that holds the CA without limit, one request at a time.
    """
    from muster.proof import NONCE_TTL_S

    client = _proof_client(state)
    for _ in range(20):
        assert client.post("/v1/auth/challenge", json={}).status_code == 201
    assert len(state.proofs.challenges) == 20

    clock.advance(NONCE_TTL_S + 1)
    client.post("/v1/auth/challenge", json={})

    assert len(state.proofs.challenges) == 1, (
        "expired challenges were never reclaimed"
    )


def test_a_signature_that_is_not_base64_is_400(state):
    client = _proof_client(state)
    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    response = client.post("/v1/auth/verify", json={
        "nonce": nonce, "signature_b64": "not base64!!", "certificate_pem": "x",
    })
    assert response.status_code == 400


# ---- a device fetching its own configuration (muster#46) -----------------
#
# The tests that carry the security are
# `one_devices_secrets_never_reach_another` and
# `a_served_secret_never_reaches_a_log_or_a_metric`. The one that carries the
# rule in CONTEXT.md is `an_unreadable_policy_is_503_and_not_an_empty_answer`:
# operation must not need the internet, so an answer muster is not sure of must
# be refused rather than shortened, or a device withdraws policy over a bad byte.


def _enrolled(state, name="pixel"):
    """A device with a real certificate from this state's CA, and its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .sign(key, hashes.SHA256())
    )
    identity = state.authority.issue(csr.public_bytes(serialization.Encoding.DER), name)
    from muster.enroll import key_id as _key_id

    return key, identity, _key_id(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _collect_identity(client, state, request_id=None):
    """The certificate a self-vouched device is issued, as the device sees it.

    Goes through the polling endpoint the handset actually uses rather than
    reaching into `state.issued`, so the test exercises the same path.
    """
    from muster.ca import Identity

    if request_id is None:
        request_id = next(iter(state.issued))
    body = client.get(f"/v1/enroll/requests/{request_id}/identity").json()
    return Identity(
        certificate_pem=body["certificate_pem"].encode(),
        not_before=dt.datetime.now(dt.timezone.utc),
        not_after=dt.datetime.now(dt.timezone.utc),
        serial=0,
    )


def _fetch_config(client, key, identity):
    """The whole exchange a device makes: challenge, sign, fetch."""
    import base64

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    return client.post(
        "/v1/device/config",
        json={
            "nonce": nonce,
            "signature_b64": base64.b64encode(signature).decode(),
            "certificate_pem": identity.certificate_pem.decode(),
        },
    )


def _policy_root(tmp_path):
    from muster import policy

    return policy.Policies(root=tmp_path)


def test_an_enrolled_device_fetches_its_configuration_with_no_cable(state, tmp_path):
    """THE POINT OF THE WHOLE ISSUE. No adb, no `run-as`, no debuggable build -
    just the certificate the device already holds and the key it cannot
    export."""
    state.policies = _policy_root(tmp_path)
    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    response = _fetch_config(client, key, identity)

    assert response.status_code == 200
    assert response.json()["files"]["restrictions"] == "DISALLOW_SAFE_BOOT\n"
    assert response.json()["revision"]
    # Every device asks the same URL and the answers differ per device. An
    # intermediary that cached one would hand another device's write tokens to
    # whoever asked next - a worse version of the stale-APK failure /agent.apk
    # carries this header for.
    assert response.headers["Cache-Control"] == "no-store"


def test_a_device_that_cannot_prove_itself_gets_no_configuration(state, tmp_path):
    """A certificate muster did not issue is a stranger, whatever it says on it.

    This is the test that makes "authenticated by the device's identity" mean
    something: without it the endpoint is an open read of the estate's policy,
    which includes another device's write tokens.
    """
    import base64

    state.policies = _policy_root(tmp_path)
    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    client = _proof_client(state)

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")])
    now = dt.datetime.now(dt.timezone.utc)
    selfsigned = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    response = client.post("/v1/device/config", json={
        "nonce": nonce,
        "signature_b64": base64.b64encode(signature).decode(),
        "certificate_pem": selfsigned.decode(),
    })

    assert response.status_code == 401
    assert "DISALLOW_SAFE_BOOT" not in response.text
    # NO-STORE ON THE REFUSAL, not only on the answer. FastAPI merges an
    # injected Response's headers on a normal return and NOT when the endpoint
    # raises, so a route that sets the header in its body has set it on exactly
    # the path that needed it least. A cached 401 is a device that cannot be
    # configured again until the entry expires, on a phone nobody is holding.
    assert response.headers["Cache-Control"] == "no-store"


def test_a_nonce_cannot_be_replayed_to_fetch_twice(state, tmp_path):
    """The single-use rule is the whole value of a nonce, and it has to hold on
    a request that RETURNS something rather than only on the one that says
    yes."""
    import base64

    state.policies = _policy_root(tmp_path)
    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    body = {
        "nonce": nonce,
        "signature_b64": base64.b64encode(
            key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
        ).decode(),
        "certificate_pem": identity.certificate_pem.decode(),
    }
    assert client.post("/v1/device/config", json=body).status_code == 200
    assert client.post("/v1/device/config", json=body).status_code == 400


def test_one_devices_secrets_never_reach_another(state, tmp_path):
    """`announceToken` is a write token for one leg of the estate. A device
    that could read another's has been handed the ability to speak as it."""
    state.policies = _policy_root(tmp_path)
    client = _proof_client(state)

    kitchen_key, kitchen_identity, kitchen_id = _enrolled(state, "kitchen")
    hallway_key, hallway_identity, hallway_id = _enrolled(state, "hallway")
    for key_id_, token in ((kitchen_id, "kitchen-token"), (hallway_id, "hallway-token")):
        (tmp_path / f"{key_id_}.app-config").write_text(
            f"set app.zippie.companion announceToken {token}\n"
        )

    kitchen = _fetch_config(client, kitchen_key, kitchen_identity)
    hallway = _fetch_config(client, hallway_key, hallway_identity)

    assert "kitchen-token" in kitchen.text
    assert "hallway-token" not in kitchen.text
    assert "hallway-token" in hallway.text
    assert "kitchen-token" not in hallway.text


def test_a_served_secret_never_reaches_a_log_or_a_metric(state, tmp_path):
    """THE TEST THAT SHOULD FAIL IF A TOKEN CAN LEAK.

    A log is the one place a credential cannot be deleted from afterwards, and
    a metric tag is the other. Both are asserted against the same real fetch
    rather than against `telemetry.event` in isolation, because the way this
    breaks is a call site passing the wrong field - not the guard forgetting
    how to drop one.
    """
    import io
    import json as _json

    from muster import telemetry as _telemetry

    state.policies = _policy_root(tmp_path)
    client = _proof_client(state)
    key, identity, key_id_ = _enrolled(state)
    (tmp_path / f"{key_id_}.app-config").write_text(
        "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
    )

    stream = io.StringIO()
    _telemetry.configure_logging(stream)
    response = _fetch_config(client, key, identity)
    assert "zk_live_7f3a91c4e08b46d2a5" in response.text, "the DEVICE still gets it"

    written = stream.getvalue()
    assert "zk_live_7f3a91c4e08b46d2a5" not in written, "the token reached a log"
    assert "\n".join(state.telemetry.sent).find("zk_live") == -1, "and a metric"

    served = [
        line for line in written.splitlines()
        if _json.loads(line)["message"] == "device configuration served"
    ]
    assert served, "the fetch was not logged at all, which is its own failure"
    assert _json.loads(served[0])["file_names"] == ["app-config"], (
        "the NAMES are what makes a fetch answerable"
    )


def test_an_unreadable_policy_is_503_and_not_an_empty_answer(state, tmp_path):
    """A SHORTER ANSWER IS AN INSTRUCTION TO WITHDRAW.

    The agent removes a file that a successful fetch does not mention, because
    that is how a device stops being managed. So muster must never shorten an
    answer it is unsure of: 503 tells the device to keep what it has, which is
    exactly what CONTEXT.md's second rule requires.
    """
    state.policies = _policy_root(tmp_path)
    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    (tmp_path / "kith.visible-apps").write_bytes(b"app.muster.agent\n\xff\xfe")
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    response = _fetch_config(client, key, identity)

    assert response.status_code == 503
    assert "restrictions" not in response.text or "DISALLOW" not in response.text
    assert "stays in force" in response.json()["detail"]


def test_a_muster_with_no_policy_source_refuses_rather_than_answering_nothing(state):
    """THE FAILURE THAT WOULD ACTUALLY HAVE HAPPENED, over HTTP.

    `muster-policy` is an OPTIONAL secret volume and kubelet mounts an absent
    one as an EMPTY DIRECTORY, so a deleted or misnamed secret reads exactly
    like a policy nobody has written. Answering that with 200 and no files is
    an authoritative instruction to the whole fleet to delete every file muster
    manages, because the agent removes what a successful fetch does not mention.
    503 tells the device to keep what it has, which is the only recoverable
    reading of the two.
    """
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    response = _fetch_config(client, key, identity)

    assert response.status_code == 503
    assert "stays in force" in response.json()["detail"]
    assert response.headers["Cache-Control"] == "no-store", (
        "a cached refusal is a device that cannot be configured again"
    )


def test_an_empty_policy_directory_refuses_too(state, tmp_path):
    """The same failure with the volume present. This is exactly what an
    optional secret that does not exist looks like from inside the pod."""
    state.policies = _policy_root(tmp_path)
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    assert _fetch_config(client, key, identity).status_code == 503


def test_readyz_counts_the_policy_files_because_readable_proves_nothing(state, tmp_path):
    """An absent optional secret mounts as an empty readable directory, so
    `readable` is true for the exact failure this field exists to surface. The
    count is what tells a live policy source from a deleted one, and there is
    already an http_check on /readyz."""
    state.policies = _policy_root(tmp_path)
    assert TestClient(create_app(state)).get("/readyz").json()["policy"] == {
        "directory": str(tmp_path),
        "readable": True,
        "files": 0,
    }

    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    assert TestClient(create_app(state)).get("/readyz").json()["policy"]["files"] == 1

    from muster import policy

    state.policies = policy.Policies(root=None, configured="/etc/muster/policy")
    assert TestClient(create_app(state)).get("/readyz").json()["policy"] == {
        "directory": "/etc/muster/policy",
        "readable": False,
        "files": 0,
    }


# ---- serving the agent, and the QR that installs it ----------------------


def _published(state, tmp_path):
    """A state with a signed APK published, built rather than fixtured."""
    from tests.test_provisioning import _fake_apk  # noqa: PLC0415

    apk, _cert = _fake_apk(tmp_path / "agent.apk")
    state.agent_apk = str(apk)
    state.base_url = "https://enroll.muster.casa"
    return TestClient(create_app(state)), apk


def _published_and_proving(state, tmp_path):
    """Both halves of a full ceremony: a published APK AND working proofs.

    `_published` alone leaves `state.proofs` unset, so /v1/auth/challenge
    answers a refusal rather than a nonce - which surfaces much later as a
    KeyError on 'nonce' in a test that looks like it is about something else.
    """
    from tests.test_provisioning import _fake_apk  # noqa: PLC0415
    from muster.proof import Proofs  # noqa: PLC0415
    from cryptography import x509 as _x509  # noqa: PLC0415

    apk, _cert = _fake_apk(tmp_path / "agent.apk")
    state.agent_apk = str(apk)
    state.base_url = "https://enroll.muster.casa"
    state.proofs = Proofs(
        clock=state.enrollment.clock,
        ca_certificate=_x509.load_pem_x509_certificate(state.authority.certificate_pem),
    )
    return TestClient(create_app(state)), apk


def test_the_agent_apk_is_served_unauthenticated(state, tmp_path):
    """It HAS to be: the downloader is Android's setup wizard on a device with
    no credential and no way to be given one. Safe because the QR carries the
    signing-certificate checksum and the platform refuses a mismatch."""
    client, apk = _published(state, tmp_path)
    response = client.get("/agent.apk")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/vnd.android.package-archive"
    assert response.content == apk.read_bytes()


def test_neither_agent_endpoint_may_be_cached(state, tmp_path):
    """The bug that reset a handset, one layer out from where it was designed.

    The APK is baked into the image so /agent.apk and /agent.json always
    describe the same file. Cloudflare then cached the APK by file extension -
    four hours - while /agent.json, having no extension and 31 bytes of body,
    stayed DYNAMIC. The pair disagreed: the advertised checksum described the
    build in the pod, and a phone downloaded the previous build from the edge.

    It fails SILENTLY, which is what makes it worth a test. A stale APK signed
    with the same key still satisfies the QR's certificate checksum, so the
    platform accepts it and provisions against the wrong agent.
    """
    client, _apk = _published(state, tmp_path)

    for path in ("/agent.apk", "/agent.json"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert response.headers.get("cache-control") == "no-store", (
            f"{path} may be cached; an edge copy can shadow the bytes the "
            "checksum was computed from, and the phone finds out by wiping"
        )


def test_no_published_agent_says_so_rather_than_404ing(state):
    """503 with a sentence beats a 404 that reads like a typo in the URL."""
    client = TestClient(create_app(state))
    response = client.get("/agent.apk")
    assert response.status_code == 503
    assert "no agent APK" in response.json()["detail"]


def test_a_configured_apk_that_is_missing_is_reported_as_missing(state, tmp_path):
    state.agent_apk = str(tmp_path / "not-there.apk")
    client = TestClient(create_app(state))
    response = client.get("/agent.apk")
    assert response.status_code == 503
    assert "not on disk" in response.json()["detail"]


def test_metadata_lets_a_human_check_without_downloading_it(state, tmp_path):
    client, apk = _published(state, tmp_path)
    body = client.get("/agent.json").json()
    assert body["bytes"] == apk.stat().st_size
    assert len(body["sha256"]) == 64
    assert body["component"] == "app.muster.agent/.MusterDeviceAdminReceiver"
    # The signature checksum is the certificate digest, NOT the file digest.
    assert body["signature_checksum"] != body["sha256"]


def test_the_published_agent_is_only_read_once_per_set_of_bytes(
    state, tmp_path, monkeypatch
):
    """Describing it means reading and hashing twelve megabytes.

    The console's settings panel asks for this, so it went from a thing a human
    ran occasionally to a thing a page requests - and the APK is baked into the
    image, so in a running pod the answer cannot change.
    """
    from muster import provisioning

    client, apk = _published(state, tmp_path)
    reads = []
    real = provisioning.signature_checksum
    monkeypatch.setattr(
        provisioning,
        "signature_checksum",
        lambda path: (reads.append(path), real(path))[1],
    )

    first = client.get("/agent.json").json()
    second = client.get("/agent.json").json()

    assert first == second
    assert len(reads) == 1, reads


def test_a_replaced_agent_is_described_again(state, tmp_path):
    """The cache is keyed on the bytes, not on the path. Somebody rebuilding an
    APK under a running server must not be told about the old one."""
    from tests.test_provisioning import _fake_apk

    client, apk = _published(state, tmp_path)
    before = client.get("/agent.json").json()

    replacement, _cert = _fake_apk(tmp_path / "replacement.apk", filler=b"v2" * 2048)
    apk.write_bytes(replacement.read_bytes())

    assert client.get("/agent.json").json() != before


def test_the_provisioning_qr_is_admin_only(state, tmp_path):
    """THE reason it is gated: this payload can carry the wifi password in
    clear text. The pairing QR is safe on a screen in a shared room; this is
    not."""
    client, _apk = _published(state, tmp_path)
    assert client.get("/v1/provision/qr.svg").status_code == 401


def test_the_provisioning_qr_omits_wifi_unless_asked(state, tmp_path):
    """Opt-in per request, so a QR printed for a device that will join a
    network by hand never contains a password at all."""
    from muster import provisioning

    client, apk = _published(state, tmp_path)
    data = provisioning.payload(
        component=provisioning.ADMIN_COMPONENT_DEFAULT,
        download_url="https://enroll.muster.casa/agent.apk",
        checksum=provisioning.signature_checksum(apk),
        server_url=state.base_url,
    )
    assert provisioning.WIFI_PASSWORD not in data
    assert client.get("/v1/provision/qr.svg", cookies=ADMIN).status_code == 200


def test_the_provisioning_qr_points_at_this_servers_own_apk(state, tmp_path):
    """The download URL must be reachable from a phone mid-setup. Deriving it
    from base_url keeps it consistent with the address the QR also hands the
    agent for enrollment."""
    from muster import provisioning

    client, apk = _published(state, tmp_path)
    data = provisioning.payload(
        component=provisioning.ADMIN_COMPONENT_DEFAULT,
        download_url=f"{state.base_url}/agent.apk",
        checksum=provisioning.signature_checksum(apk),
        server_url=state.base_url,
    )
    assert data[provisioning.DOWNLOAD] == "https://enroll.muster.casa/agent.apk"
    assert data[provisioning.ADMIN_EXTRAS]["muster.server_url"] == "https://enroll.muster.casa"

    response = client.get("/v1/provision/qr.svg", cookies=ADMIN)
    assert response.status_code == 200
    assert b"<svg" in response.content


def test_neither_provisioning_qr_may_be_cached(state, tmp_path):
    """THE SAME BUG AS /agent.apk, one path along, and it fails the same way.

    The edge in front of this service caches by file extension when the origin
    says nothing, and `.svg` is on that list exactly as `.apk` is - which cost
    four hours of a stale APK once already. A cached QR describes an agent that
    may since have been replaced, and a checksum that no longer matches the
    download is a device that fails mid-setup after it has already been wiped.
    """
    client, _apk = _published(state, tmp_path)

    plain = client.get("/v1/provision/qr.svg", cookies=ADMIN)
    assert plain.status_code == 200
    assert plain.headers.get("cache-control") == "no-store", (
        "an edge that caches this by extension shows an operator a QR for an "
        "agent that is no longer published"
    )

    described = client.post("/v1/provision/qr", json={}, cookies=ADMIN)
    assert described.status_code == 200
    assert described.headers.get("cache-control") == "no-store"


def test_wifi_credentials_may_not_travel_in_a_url(state, tmp_path):
    """A query string is written to this server's access log, to whatever proxy
    is in front of it, and to the browser's history.

    Refused rather than ignored: an operator copying the older `curl` would
    otherwise get a QR with no wifi in it, find out on a wiped phone that will
    not join a network, and have nothing to read that says why.
    """
    client, _apk = _published(state, tmp_path)

    refused = client.get(
        "/v1/provision/qr.svg?wifi_ssid=house&wifi_password=hunter2", cookies=ADMIN
    )
    assert refused.status_code == 400
    detail = refused.json()["detail"]
    assert "wifi_password" in detail and "/v1/provision/qr" in detail
    # The refusal is about the URL, so it must not put the value in the answer.
    assert "hunter2" not in detail

    assert client.get("/v1/provision/qr.svg", cookies=ADMIN).status_code == 200


def test_the_text_beside_the_qr_describes_the_qr_that_was_drawn(state, tmp_path):
    """A QR is opaque, and these three fields are the only part a human can
    check. They are read back out of the payload that was encoded, so they
    cannot describe a different one."""
    from muster import provisioning

    client, apk = _published(state, tmp_path)
    described = client.post("/v1/provision/qr", json={}, cookies=ADMIN).json()

    assert described["download_url"] == "https://enroll.muster.casa/agent.apk"
    assert described["signature_checksum"] == provisioning.signature_checksum(apk)
    assert described["server_url"] == "https://enroll.muster.casa"
    assert described["component"] == provisioning.ADMIN_COMPONENT_DEFAULT
    assert described["wifi"] is None
    assert described["svg"].startswith("<?xml")
    # Handed over whole rather than field by field, so a key added to the bundle
    # - muster#48 may put enrollment in it - reaches the console without the
    # page or this endpoint being rewritten for it.
    assert described["extras"] == {"muster.server_url": "https://enroll.muster.casa"}


def test_the_description_agrees_with_what_this_server_publishes(state, tmp_path):
    """The console refuses to draw a QR when these two disagree, because a
    disagreement means something between the browser and muster is serving a
    copy. They can only be made to agree here by coming from one read."""
    client, _apk = _published(state, tmp_path)

    described = client.post("/v1/provision/qr", json={}, cookies=ADMIN).json()
    published = client.get("/agent.json").json()

    assert described["signature_checksum"] == published["signature_checksum"]
    assert described["component"] == published["component"]


def test_the_wifi_password_goes_in_the_qr_and_nowhere_else(state, tmp_path):
    """It has to be in the payload - that is what the operator asked for - and
    it must not come back as text beside it. The QR is on a screen for as long
    as it takes to scan; a second copy in a JSON body is one more place it can
    be read from, logged, or left in a tab."""
    client, _apk = _published(state, tmp_path)

    response = client.post(
        "/v1/provision/qr",
        json={"wifi_ssid": "house", "wifi_password": "correct-horse-battery"},
        cookies=ADMIN,
    )
    described = response.json()

    assert described["wifi"] == {
        "ssid": "house",
        "security": "WPA",
        "carries_password": True,
    }
    assert "correct-horse-battery" not in response.text
    # And it really did change the payload: a QR that quietly dropped the
    # credentials would look identical and join no network.
    without = client.post("/v1/provision/qr", json={}, cookies=ADMIN).json()
    assert described["svg"] != without["svg"]


def test_the_qr_is_drawn_to_be_scanned_off_a_monitor(state, tmp_path):
    """Not decoration: this is read by a phone camera at arm's length.

    The quiet zone is what lets a camera find the code at all, and four modules
    is what ISO/IEC 18004 asks for - this drew two, which the page's own
    background eats into first. The white is carried by the image rather than
    borrowed from whatever it is laid on, so the quiet zone stays white in the
    full-screen view and in a printout.
    """
    import re as _re

    client, _apk = _published(state, tmp_path)
    svg = client.get("/v1/provision/qr.svg", cookies=ADMIN).text

    background = _re.search(r'<path fill="#fff" d="M0 0h(\d+)v(\d+)', svg)
    assert background is not None, "the QR does not carry its own white"
    dark = _re.search(r'stroke="#000" d="M(\d+) ', svg)
    assert dark is not None, "the modules are not drawn in black"
    quiet = int(dark.group(1))
    assert quiet == 4, f"the quiet zone is {quiet} modules, and the standard asks 4"
    # The white covers the quiet zone on the far side too, not just the modules.
    assert int(background.group(1)) >= quiet * 2

# ---- one scan, and nobody types ------------------------------------------
#
# The provisioning QR now carries a pairing code, which is what takes the last
# person off the handset. Read enroll.py's module docstring first: the security
# question these tests are the answer to is what replaces the fingerprint
# comparison when nobody is looking at the device's screen.


def _minted(state):
    """The one code the QR endpoint minted."""
    from muster.enroll import Shape  # noqa: PLC0415

    scanned = [c for c in state.enrollment.codes.values() if c.shape is Shape.SCANNED]
    assert len(scanned) == 1, f"expected one scanned code, got {len(scanned)}"
    return scanned[0]


def _qr_for(state, apk, code):
    """The SVG this endpoint MUST have produced, rebuilt from first principles.

    Comparing rendered bytes rather than decoding the QR: there is no decoder in
    this dependency set, and a QR is a deterministic rendering of its payload -
    so an identical SVG is proof the served payload is identical too. It catches
    the failure that matters, which is a code being minted and then not reaching
    the bundle: on a handset that looks like a phone which provisions perfectly
    and then sits waiting to be typed at.

    The drawing constants come from muster.api rather than being repeated, so
    this cannot pass by both sides being wrong in the same way.
    """
    import segno  # noqa: PLC0415

    from muster import api as _api  # noqa: PLC0415
    from muster import provisioning  # noqa: PLC0415

    data = provisioning.payload(
        component=provisioning.ADMIN_COMPONENT_DEFAULT,
        download_url=f"{state.base_url}/agent.apk",
        checksum=provisioning.signature_checksum(apk),
        server_url=state.base_url,
        pairing_code=code,
    )
    buffer = io.BytesIO()
    segno.make(provisioning.encode(data), error="m").save(
        buffer,
        kind="svg",
        scale=_api._QR_SCALE,
        border=_api._QUIET_ZONE,
        dark=_api._QR_DARK,
        light=_api._QR_LIGHT,
    )
    return buffer.getvalue().decode()


def test_the_provisioning_qr_carries_a_code_nobody_has_to_type(state, tmp_path):
    """THE acceptance criterion: one scan is the whole ceremony up to the vouch.

    Rebuilding the SVG proves the minted code actually reached the admin extras
    bundle. Minting one and forgetting to put it in is the failure this catches,
    and it is invisible from the server: the QR renders, the endpoint answers
    200, and the phone comes up unable to enroll.
    """
    client, apk = _published(state, tmp_path)
    response = client.get("/v1/provision/qr.svg", cookies=ADMIN)

    assert response.status_code == 200
    assert response.text == _qr_for(state, apk, _minted(state).code)


def test_the_code_in_the_qr_is_one_a_device_can_actually_present_with(
    state, tmp_path
):
    """THE WHOLE CEREMONY, with nobody typing and nobody clicking twice.

    An administrator renders a QR; a wiped phone presents against it; the
    certificate exists. That is the entire flow, and the queue this test used to
    assert against is empty on purpose - a row there is a console asking for an
    approval that was already given when the QR was made.
    """
    client, _apk = _published(state, tmp_path)
    client.get("/v1/provision/qr.svg", cookies=ADMIN)
    csr, _key = _csr_pem()

    presented = client.post(
        "/v1/enroll/requests",
        json={"code": _minted(state).code, "csr_pem": csr, "device_name": "pixel-6a"},
    )
    assert presented.status_code == 202

    # Nothing waiting for a human.
    assert client.get("/v1/enroll/requests", cookies=ADMIN).json()["pending"] == []

    # And the identity is already there for the device's first poll - which is
    # why no change to the agent was needed: it already polls this.
    identity = client.get(
        f"/v1/enroll/requests/{presented.json()['request_id']}/identity"
    )
    assert identity.status_code == 200
    assert "BEGIN CERTIFICATE" in identity.json()["certificate_pem"]


def test_the_pairing_code_goes_in_the_qr_and_nowhere_else(state, tmp_path):
    """THE SAME RULE THE WIFI PASSWORD FOLLOWS, one field along.

    `extras` is handed back whole so a key added to the bundle reaches the
    console without anybody adding a row for it - which is right for values an
    operator is meant to CHECK and wrong for one they are meant to HOLD. The
    console renders that dict as text, so a code left in it would be printed on
    the page beside the image that already carries it, and would sit in the
    response body of an endpoint whose whole output is otherwise checkable.
    """
    client, _apk = _published(state, tmp_path)
    response = client.post("/v1/provision/qr", json={}, cookies=ADMIN)
    described = response.json()
    code = _minted(state).code

    assert described["pairing"] == {
        "carries_code": True,
        "expires_in_s": 300,
        # Described back on purpose: a role is a value the operator CHECKS, not
        # one they hold. See the dict's own comment.
        "role": "",
    }
    assert "muster.pairing_code" not in described["extras"]
    assert code not in response.text, "the code came back as text beside its own QR"
    # And the server address is still passed through generically beside it.
    assert described["extras"] == {"muster.server_url": "https://enroll.muster.casa"}


def test_a_qr_meant_to_be_printed_can_be_minted_without_a_code(state, tmp_path):
    """The rest of this payload is stable for the life of the signing key, which
    is the whole argument for the certificate checksum. A code expires in
    minutes, so a printed QR carrying one has a hands-free half that is always
    dead. Such a device still provisions and is enrolled by hand afterwards."""
    client, apk = _published(state, tmp_path)

    plain = client.get("/v1/provision/qr.svg?hands_free=false", cookies=ADMIN)
    assert plain.status_code == 200
    assert state.enrollment.codes == {}, "a printed QR must mint nothing"
    assert "x-muster-pairing-expires-in" not in plain.headers
    assert plain.text == _qr_for(state, apk, "")

    described = client.post(
        "/v1/provision/qr", json={"hands_free": False}, cookies=ADMIN
    ).json()
    assert described["pairing"] == {
        "carries_code": False,
        "expires_in_s": None,
        # No code means no role travelled either: a printed QR with no pairing
        # code enrols nobody, so a role on it would describe an intention that
        # nothing acts on.
        "role": "",
    }
    assert state.enrollment.codes == {}


def test_the_plain_qr_says_how_long_it_has_left(state, tmp_path):
    """A header, because an image has nowhere else to put it and the POST beside
    it says the same thing in JSON. A stale QR costs a wiped phone that
    provisions and then cannot enroll, with nothing on the handset saying why."""
    client, _apk = _published(state, tmp_path)
    response = client.get("/v1/provision/qr.svg", cookies=ADMIN)
    assert response.headers["x-muster-pairing-expires-in"] == "300"


def test_choosing_hands_free_in_a_url_is_not_a_credential_in_a_url(state, tmp_path):
    """The wifi parameters are refused in the query string because a password in
    a URL is a password in three logs. A boolean is not that, and refusing it
    would leave the plain GET unable to mint the QR somebody wants to print."""
    client, _apk = _published(state, tmp_path)
    assert (
        client.get("/v1/provision/qr.svg?hands_free=false", cookies=ADMIN).status_code
        == 200
    )


def test_the_qr_mints_a_code_that_cannot_be_guessed(state, tmp_path):
    """The security answer, asserted where it is reachable from HTTP.

    Nobody is holding the phone, so there is no second copy of the fingerprint
    for the administrator to compare - the racer the vouch catches on the typed
    path is uncatchable here. So the racer is made impossible instead: a code
    that nothing has to read aloud is not constrained to six digits.
    """
    client, _apk = _published(state, tmp_path)
    client.get("/v1/provision/qr.svg", cookies=ADMIN)
    code = _minted(state).code
    assert not code.isdigit()
    assert len(code) >= 32


def test_a_stale_qr_and_a_replayed_one_are_told_apart(state, tmp_path):
    """Both refuse the device, and they call for opposite responses: stale means
    render another, replayed means a second device used a code that was on your
    monitor. Separable in telemetry, because averaged into one number neither
    question is answerable."""
    client, _apk = _published(state, tmp_path)
    csr, _key = _csr_pem()

    client.get("/v1/provision/qr.svg", cookies=ADMIN)
    replayed = _minted(state).code
    client.post(
        "/v1/enroll/requests",
        json={"code": replayed, "csr_pem": csr, "device_name": "pixel-6a"},
    )
    again = client.post(
        "/v1/enroll/requests",
        json={"code": replayed, "csr_pem": csr, "device_name": "pixel-6a"},
    )

    state.enrollment.codes.clear()
    client.get("/v1/provision/qr.svg", cookies=ADMIN)
    stale = _minted(state).code
    state.enrollment.codes[stale].created_at -= DEFAULT_CODE_TTL_S + 1
    expired = client.post(
        "/v1/enroll/requests",
        json={"code": stale, "csr_pem": csr, "device_name": "pixel-6a"},
    )

    assert again.status_code == 409, "replayed"
    assert expired.status_code == 410, "stale"
    for reason in ("code-used", "code-expired"):
        assert (
            f"custom.muster.enroll.present.refused:1|c|#reason:{reason},shape:scanned"
            in state.telemetry.sent
        ), state.telemetry.sent


def test_a_refusal_that_names_no_code_names_no_shape(state, tmp_path):
    """`unknown` rather than a guess. Classifying by the FORM of what arrived
    would let an attacker choose which bucket their traffic lands in, and then
    "the QR path is failing" is answered from attacker input."""
    client, _apk = _published(state, tmp_path)
    csr, _key = _csr_pem()
    client.post(
        "/v1/enroll/requests",
        json={"code": "000000", "csr_pem": csr, "device_name": "pixel-6a"},
    )
    assert (
        "custom.muster.enroll.present.refused:1|c|#reason:no-such-code,shape:unknown"
        in state.telemetry.sent
    ), state.telemetry.sent


def test_the_typed_path_is_untouched_by_any_of_this(state, tmp_path):
    """A device enrolled AFTER provisioning, or re-enrolled after a lapse, has
    no QR to scan - somebody is holding it and typing. That path is the one with
    a real fingerprint comparison behind it and it must not have been traded
    away for the scan."""
    client, _apk = _published(state, tmp_path)
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    assert len(code) == 6 and code.isdigit()

    csr, _key = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr, "device_name": "pixel-6a"},
    ).json()
    pending = client.get("/v1/enroll/requests", cookies=ADMIN).json()["pending"]
    assert [p["shape"] for p in pending] == ["typed"]

    vouched = client.post(
        f"/v1/enroll/requests/{presented['request_id']}/vouch",
        json={"fingerprint": presented["fingerprint"]},
        cookies=ADMIN,
    )
    assert vouched.status_code == 200


def test_a_typed_device_is_still_refused_a_certificate_until_vouched(state, tmp_path):
    """The conservative half of the design, and it is UNCHANGED.

    This test used to make the same assertion about a scanned code and said
    that removing the vouch there had to be a decision rather than a
    convenience. It was made deliberately - see enroll.py's module docstring -
    and only for the scanned shape.

    Six digits is guessable by design, so on this path the fingerprint really is
    a second copy, read off a handset somebody is holding. Nothing here moves.
    """
    client, _apk = _published(state, tmp_path)
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr, _key = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr, "device_name": "pixel-6a"},
    ).json()

    collected = client.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    assert collected.status_code == 202
    assert "vouch" in collected.json()["status"]
    # And it IS waiting for a human, which is the whole difference.
    assert client.get("/v1/enroll/requests", cookies=ADMIN).json()["pending"]


def test_a_qr_enrolled_device_lands_in_the_kith_without_anybody_clicking(
    state, tmp_path
):
    """The kith write is the half that would be easy to lose.

    Issuance moved into a helper so the scanned path and the typed path share
    one copy; if they had been two, this is the line the QR path - the one
    nobody watches - would have forgotten.
    """
    client, _apk = _published(state, tmp_path)
    client.get("/v1/provision/qr.svg", cookies=ADMIN)
    csr, _key = _csr_pem()
    client.post(
        "/v1/enroll/requests",
        json={"code": _minted(state).code, "csr_pem": csr, "device_name": "pixel-6a"},
    )

    roll = client.get("/v1/kith", cookies=ADMIN).json()["devices"]
    assert [d["name"] for d in roll] == ["pixel-6a"]


def test_an_unsignable_csr_on_the_qr_path_fails_the_presentation(state, tmp_path):
    """A phone must not be left polling for a certificate nobody will sign.

    On the typed path an unsignable CSR surfaces when an administrator clicks
    vouch and gets a 422. On this path there is no click, and the request was
    never queued - so if this returned 202 the handset would poll forever
    against a spent code with nothing on the other end.
    """
    client, _apk = _published(state, tmp_path)
    client.get("/v1/provision/qr.svg", cookies=ADMIN)

    # An RSA CSR: parseable and self-signed, so it reaches the CA and is
    # refused there. Devices generate P-256; anything else did not come from
    # our agent.
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong-key")]))
        .sign(rsa_key, hashes.SHA256())
    )

    presented = client.post(
        "/v1/enroll/requests",
        json={
            "code": _minted(state).code,
            "csr_pem": rsa_csr.public_bytes(serialization.Encoding.PEM).decode(),
            "device_name": "pixel-6a",
        },
    )
    assert presented.status_code == 422
    # And nothing was left behind for a human to find.
    assert client.get("/v1/enroll/requests", cookies=ADMIN).json()["pending"] == []


def test_a_scanned_qr_does_not_burn_a_typed_codes_budget_or_the_reverse(
    state, tmp_path
):
    """Wrong guesses must still cost the typed codes their attempts - that is
    what bounds a guessing run - while leaving a provisioning run in flight
    alone. Both halves, because getting either wrong is silent."""
    client, _apk = _published(state, tmp_path)
    typed = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    client.get("/v1/provision/qr.svg", cookies=ADMIN)
    scanned = _minted(state).code
    csr, _key = _csr_pem()

    for _ in range(MAX_ATTEMPTS):
        client.post(
            "/v1/enroll/requests",
            json={"code": "000001", "csr_pem": csr, "device_name": "guesser"},
        )

    burned = client.post(
        "/v1/enroll/requests",
        json={"code": typed, "csr_pem": csr, "device_name": "pixel-6a"},
    )
    survived = client.post(
        "/v1/enroll/requests",
        json={"code": scanned, "csr_pem": csr, "device_name": "pixel-6a"},
    )
    assert burned.status_code == 429
    assert survived.status_code == 202, (
        "five wrong six-digit guesses from anywhere must not strand a phone "
        "that has already been wiped and provisioned"
    )


# ---- observability, wired to the endpoints -------------------------------
#
# SEPARATE FROM test_telemetry.py ON PURPOSE. That file proves the emitter
# works; these prove it is CONNECTED. An emitter with perfect unit tests that
# no endpoint ever calls is the shape this estate keeps finding, and it passes
# every test in the other file.


def test_minting_a_code_is_counted(client, state):
    """Tagged with the SHAPE, because the two are minted by different endpoints
    for different ceremonies and "codes are being minted" answers neither."""
    client.post("/v1/enroll/codes", json={}, cookies=ADMIN)
    assert "custom.muster.enroll.code.minted:1|c|#shape:typed" in state.telemetry.sent


def test_a_refused_presentation_is_counted_with_its_reason(client, state):
    """THE metric that makes enrollment failures diagnosable. Without the tag,
    a code that expired and somebody guessing at codes are the same number."""
    _csr, _key = _csr_pem()
    client.post(
        "/v1/enroll/requests",
        json={"code": "000000", "csr_pem": _csr, "device_name": "pixel-6a"},
    )
    assert any(
        line.startswith("custom.muster.enroll.present.refused:1|c|#reason:")
        for line in state.telemetry.sent
    ), state.telemetry.sent


def test_a_fingerprint_mismatch_is_counted_as_itself(client, state):
    """Somebody enrolling against the operator's code while they watch. It must
    never be averaged into a total with 'the code expired'."""
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr, _key = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr, "device_name": "pixel-6a"},
    ).json()

    client.post(
        f"/v1/enroll/requests/{presented['request_id']}/vouch",
        json={"fingerprint": "not the one on the screen"},
        cookies=ADMIN,
    )
    assert (
        "custom.muster.enroll.vouch.refused:1|c|#reason:fingerprint-mismatch"
        in state.telemetry.sent
    ), state.telemetry.sent


def test_issuing_a_certificate_is_counted_and_timed(client, state):
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr, _key = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr, "device_name": "pixel-6a"},
    ).json()
    client.post(
        f"/v1/enroll/requests/{presented['request_id']}/vouch",
        json={"fingerprint": presented["fingerprint"]},
        cookies=ADMIN,
    )

    assert (
        "custom.muster.enroll.present.accepted:1|c|#shape:typed"
        in state.telemetry.sent
    )
    assert "custom.muster.ca.issued:1|c" in state.telemetry.sent
    assert any(
        line.startswith("custom.muster.ca.issue.duration:") and line.endswith("|ms")
        for line in state.telemetry.sent
    ), state.telemetry.sent


# ---- the kith, over HTTP -------------------------------------------------
#
# The acceptance criteria of muster#34, exercised through the endpoints rather
# than against the store directly. The store's own rules are in test_kith.py;
# what these check is that the API is actually wired to it - a store nothing
# calls is a store that works perfectly and remembers nothing.


def _kith_state(records=None, clock_=None):
    """A State whose kith is one a test can hold on to and break."""
    from muster import kith as kith_store

    records = records if records is not None else kith_store.MemoryRecords()
    at = clock_ or (lambda: dt.datetime(2026, 8, 19, tzinfo=dt.timezone.utc))
    state = State(
        enrollment=Enrollment(clock=Clock()),
        authority=Authority.create(
            "muster test CA",
            clock=lambda: dt.datetime(2026, 8, 18, tzinfo=dt.timezone.utc),
        ),
        sign_in=_ADMIN_PROVIDER.sign_in(),
        kith=kith_store.Kith(records, clock=at),
    )
    return state, records


def _enroll(client, key=None, name="Pixel 6a", collect=True):
    """Mint, present, vouch and (usually) collect. Returns what came back.

    `key` is how a renewal is staged: a renewal is the SAME key asking for a new
    certificate, so passing the key back in is exactly what a renewing device
    does. There is no renew endpoint yet, so this is the closest the HTTP
    surface can get to one - and it is the same store path either way.
    """
    if key is None:
        key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "whatever")]))
        .sign(key, hashes.SHA256())
    )
    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    presented = client.post(
        "/v1/enroll/requests",
        json={
            "code": code,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "device_name": name,
        },
    ).json()
    vouched = client.post(
        f"/v1/enroll/requests/{presented['request_id']}/vouch",
        json={"fingerprint": presented["fingerprint"]},
        cookies=ADMIN,
    )
    assert vouched.status_code == 200, vouched.text
    if collect:
        client.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    return key, presented, vouched.json()


def test_a_vouched_device_survives_a_pod_restart():
    """muster#34's first acceptance criterion, and the reason it was filed.

    A restart is modeled as what it actually is: the same store, and everything
    else new. The pending queue and the collectable certificate lived in a
    process that has gone, so if the device is still there afterwards it is
    because the kith was written down.
    """
    state, records = _kith_state()
    client = TestClient(create_app(state))
    _key, presented, _ = _enroll(client, name="Pixel 6a", collect=False)

    # The pod is replaced. New enrollment queue, new issued-but-uncollected map,
    # same CA and the same store.
    restarted, _ = _kith_state(records=records)
    restarted.authority = state.authority
    after = TestClient(create_app(restarted))

    roll = after.get("/v1/kith", cookies=ADMIN).json()
    assert [d["name"] for d in roll["devices"]] == ["Pixel 6a"]

    # And the certificate it had not collected yet is still collectable, rather
    # than a 404 telling a freshly wiped phone to enroll all over again.
    collected = after.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    assert collected.status_code == 200, collected.text
    assert "BEGIN CERTIFICATE" in collected.json()["certificate_pem"]
    assert collected.json()["renew_after"] < collected.json()["not_after"]


def test_a_renewal_is_one_device_with_two_certificates():
    """muster#34's second acceptance criterion.

    The same key enrolling again is what renewal is: the device keeps the
    private key it generated in its own hardware and asks for a fresh
    certificate over it. A store keyed on the certificate would show two phones
    here, and a fleet that had not changed would grow one every ninety days.
    """
    state, _records = _kith_state()
    client = TestClient(create_app(state))

    key, _, first = _enroll(client, name="Pixel 6a")
    _, _, second = _enroll(client, key=key, name="Pixel 6a")
    assert first["serial"] != second["serial"], "a renewal is a NEW certificate"

    devices = client.get("/v1/kith", cookies=ADMIN).json()["devices"]
    assert len(devices) == 1, devices
    assert devices[0]["certificates"] == 2

    detail = client.get(f"/v1/kith/{devices[0]['key_id']}", cookies=ADMIN).json()
    assert len(detail["certificates"]) == 2
    assert {int(c["serial"], 16) for c in detail["certificates"]} == {
        first["serial"], second["serial"]
    }


def test_the_kith_is_only_readable_by_an_administrator():
    state, _ = _kith_state()
    client = TestClient(create_app(state))
    assert client.get("/v1/kith").status_code == 401
    assert client.get("/v1/kith/anything").status_code == 401


def test_an_unknown_device_is_404_not_an_empty_record():
    state, _ = _kith_state()
    client = TestClient(create_app(state))
    assert client.get("/v1/kith/nosuchkey", cookies=ADMIN).status_code == 404


def test_readiness_stays_ready_when_the_kith_store_is_unreachable():
    """The single most important line in api.py to get right.

    Reporting unready would have Kubernetes pull the pod out of the Service,
    which stops enrollment and renewal for every device - the exact outcome the
    deferred writes exist to prevent, arrived at through the health check
    instead of through the code.
    """
    from tests.test_kith import Breakable

    records = Breakable()
    state, _ = _kith_state(records=records)
    client = TestClient(create_app(state))
    records.up = False

    _enroll(client, name="Pixel 6a")  # must still issue

    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ok"
    assert ready.json()["kith"]["state"] == "deferring"
    assert ready.json()["kith"]["deferred"] > 0


def test_vouching_still_issues_when_the_kith_store_is_down():
    """A store outage must not turn a vouch into a 500 for a signed certificate.

    On renewal the same failure is worse than an error message: a device that
    cannot renew LAPSES, and lapse means a pairing code and a human holding the
    handset.
    """
    from tests.test_kith import Breakable

    records = Breakable()
    state, _ = _kith_state(records=records)
    client = TestClient(create_app(state))
    records.up = False

    _key, presented, issued = _enroll(client, name="Pixel 6a", collect=False)
    assert issued["serial"]

    collected = client.get(f"/v1/enroll/requests/{presented['request_id']}/identity")
    assert collected.status_code == 200, "the device could not collect what was signed"


def test_the_roll_refuses_rather_than_showing_an_empty_kith():
    """503, not an empty list. An empty list reads exactly like a fleet that
    vanished, and sends the operator looking for phones instead of a database."""
    from tests.test_kith import Breakable

    records = Breakable()
    state, _ = _kith_state(records=records)
    client = TestClient(create_app(state))
    _enroll(client, name="Pixel 6a")
    records.up = False

    response = client.get("/v1/kith", cookies=ADMIN)
    assert response.status_code == 503
    assert "unreachable" in response.json()["detail"]


def test_collecting_during_a_store_outage_says_retry_not_gone():
    """404 and 503 are a re-enrollment apart.

    The agent reads 404 as Gone and stops polling for good; anything it does not
    recognize it retries with backoff (EnrollmentClient.kt). Answering 404
    because the DATABASE is unreachable would tell a device to abandon a
    certificate muster really did sign.
    """
    from tests.test_kith import Breakable

    records = Breakable()
    state, _ = _kith_state(records=records)
    client = TestClient(create_app(state))
    records.up = False

    response = client.get("/v1/enroll/requests/never-heard-of-it/identity")
    assert response.status_code == 503, response.text
    assert "do not start a new enrollment" in response.json()["detail"]


def test_a_proof_of_possession_moves_last_seen():
    """"Last seen" has to mean something, and only a proof can honestly set it.

    An unauthenticated request proves that somebody sent bytes. A verified
    signature proves THIS device was reachable and still holds its key.
    """
    import base64

    from muster.proof import Proofs

    moving = [dt.datetime(2026, 8, 19, tzinfo=dt.timezone.utc)]
    state, _ = _kith_state(clock_=lambda: moving[0])
    state.proofs = Proofs(
        clock=state.enrollment.clock,
        ca_certificate=x509.load_pem_x509_certificate(state.authority.certificate_pem),
    )
    client = TestClient(create_app(state))

    key, _, _ = _enroll(client, name="Pixel 6a")
    device = client.get("/v1/kith", cookies=ADMIN).json()["devices"][0]
    assert device["last_seen"] == device["first_seen"]

    moving[0] += dt.timedelta(days=1)
    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    certificate = state.authority.issue(
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER),
        "Pixel 6a",
    )
    verified = client.post("/v1/auth/verify", json={
        "nonce": nonce,
        "signature_b64": base64.b64encode(
            key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
        ).decode(),
        "certificate_pem": certificate.certificate_pem.decode(),
    })
    assert verified.json()["verdict"] == "ok"

    after = client.get("/v1/kith", cookies=ADMIN).json()["devices"][0]
    assert after["last_seen"] > after["first_seen"], "a proof did not move last_seen"
    assert after["first_seen"] == device["first_seen"]


def test_fetching_configuration_moves_last_seen_too(tmp_path):
    """A DEVICE THAT FETCHES HAS PROVED ITSELF, so it has been seen.

    This is what makes "last seen" answer the question people actually ask.
    /v1/auth/verify proves possession and asks for nothing, so nothing on a
    device had a reason to call it on a schedule; a configuration fetch is a
    thing every device does at every boot, and it carries the same proof.
    """
    from muster.proof import Proofs

    moving = [dt.datetime(2026, 8, 19, tzinfo=dt.timezone.utc)]
    state, _ = _kith_state(clock_=lambda: moving[0])
    state.policies = _policy_root(tmp_path)
    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    state.proofs = Proofs(
        clock=state.enrollment.clock,
        ca_certificate=x509.load_pem_x509_certificate(state.authority.certificate_pem),
    )
    client = TestClient(create_app(state))

    key, _, _ = _enroll(client, name="Pixel 6a")
    device = client.get("/v1/kith", cookies=ADMIN).json()["devices"][0]
    assert device["last_seen"] == device["first_seen"]

    moving[0] += dt.timedelta(days=1)
    certificate = state.authority.issue(
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER),
        "Pixel 6a",
    )
    fetched = _fetch_config(client, key, certificate)
    assert fetched.status_code == 200, fetched.text

    after = client.get("/v1/kith", cookies=ADMIN).json()["devices"][0]
    assert after["last_seen"] > after["first_seen"], "a fetch did not move last_seen"


def test_a_name_a_certificate_or_a_database_cannot_hold_is_refused_at_the_door():
    """An unauthenticated string that becomes a Common Name and a Postgres row.

    The NUL byte is the one that costs something beyond a bad name: kith writes
    replay in order, so one undeliverable row blocks every write behind it and
    makes a healthy database report as unreachable. The store now recognizes
    that and drops it, but nothing should have to.
    """
    state, records = _kith_state()
    client = TestClient(create_app(state))

    for bad, why in [
        ("", "empty"),
        ("   ", "whitespace only"),
        ("Pixel\x006a", "a NUL byte, which Postgres text cannot hold"),
        ("Pixel\n6a", "a newline"),
        ("p" * 65, "longer than a Common Name may be"),
    ]:
        code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
        csr, _key = _csr_pem()
        response = client.post(
            "/v1/enroll/requests",
            json={"code": code, "csr_pem": csr, "device_name": bad},
        )
        assert response.status_code == 400, f"{why} was accepted: {response.text}"

    assert records.roll() == [], "a refused name still reached the kith"


def test_the_flusher_runs_for_the_life_of_the_app_and_no_longer():
    """The retry thread has to be STARTED, and a test suite is where that gets
    forgotten: nothing else in this file enters the lifespan, so a `start_flushing`
    that was never wired would pass every other test here."""
    import threading

    state, _ = _kith_state()
    app = create_app(state)

    assert "kith-flusher" not in {t.name for t in threading.enumerate()}
    with TestClient(app):
        assert "kith-flusher" in {t.name for t in threading.enumerate()}
    assert "kith-flusher" not in {t.name for t in threading.enumerate()}


def test_nothing_secret_reaches_the_kith():
    """muster#34: nothing is stored that is not already in the certificate.

    The two things worth checking are the pairing code, which is the one live
    secret in the ceremony, and a private key, which by design never arrives
    here at all. The certificate itself is public - a device hands it to
    anything that asks - so storing it costs nothing.
    """
    state, records = _kith_state()
    client = TestClient(create_app(state))

    minted = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(key, hashes.SHA256())
    )
    presented = client.post(
        "/v1/enroll/requests",
        json={
            "code": minted,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "device_name": "Pixel 6a",
        },
    ).json()
    client.post(
        f"/v1/enroll/requests/{presented['request_id']}/vouch",
        json={"fingerprint": presented["fingerprint"]},
        cookies=ADMIN,
    )

    written = repr(records.roll()) + repr(
        records.history(records.roll()[0].device.key_id)
    )
    assert minted not in written, "the pairing code was written into the kith"
    assert "PRIVATE KEY" not in written


# ---- who may reach what, made executable ---------------------------------
#
# THE TABLE IN api.py's MODULE DOCSTRING, AS A TEST. Documenting an audience in
# a comment and enforcing it on a route are two different things, and the gap
# between them is where an endpoint quietly changes sides. Every route the app
# registers has to appear in exactly one of these sets, so adding one is a
# decision somebody makes on purpose rather than a default nobody noticed.

OPEN_TO_ANYONE = {
    # A device with no credential, which is the whole problem enrollment solves.
    ("POST", "/v1/enroll/requests"),
    ("GET", "/v1/enroll/requests/{request_id}/identity"),
    ("POST", "/v1/auth/challenge"),
    ("POST", "/v1/auth/verify"),
    # Android's setup wizard, on a phone that has just been wiped.
    ("GET", "/agent.apk"),
    ("GET", "/agent.json"),
    # The console shell and the steps of signing into it - all reached by a
    # browser that has no session yet, by definition.
    ("GET", "/"),
    ("GET", "/v1/session"),
    ("GET", "/auth/signin"),
    ("GET", "/auth/callback"),
    ("POST", "/auth/signout"),
    # Probes. The kubelet has no credential either.
    ("GET", "/livez"),
    ("GET", "/readyz"),
    # What FastAPI mounts on its own. It describes the API rather than exposes
    # it, and it is listed here so that the day it starts doing something else,
    # this test is what says so. /docs and /redoc are turned off - see below.
    ("GET", "/openapi.json"),
}

# A DEVICE THAT HAS ENROLLED, proving it with the key in its keystore. Neither
# of the other two sets: an administrator session here would mean a phone in a
# cupboard could never be configured, and leaving it open would mean anyone who
# guessed a key_id could read another device's write tokens.
#
# muster#27 (diagnostics up) and muster#42 (inventory up) belong in this set
# when they land, which is the point of it existing as a set rather than as one
# route with a comment.
DEVICE_PROVEN = {
    ("POST", "/v1/device/config"),
    # muster#45: the bytes an operator put in the store, for the device that
    # was told to expect them. Not open, because the store is where an APK is
    # about to live; not administrator-only, because a phone in a cupboard has
    # to be able to fetch its own wallpaper.
    ("POST", "/v1/device/asset"),
}

ADMINISTRATOR_ONLY = {
    ("POST", "/v1/enroll/codes"),
    ("GET", "/v1/enroll/requests"),
    ("POST", "/v1/enroll/requests/{request_id}/vouch"),
    # The provisioning QR, and the same QR with what it commits to beside it.
    # Administrator-only because the payload can carry a network password in
    # clear text - see the endpoint's own docstring.
    ("GET", "/v1/provision/qr.svg"),
    ("POST", "/v1/provision/qr"),
    # The roll and one device on it (muster#34). Administrator-only because the
    # kith is the answer to "which devices are yours", which is not a question
    # the internet gets to ask.
    ("GET", "/v1/kith"),
    ("GET", "/v1/kith/{key_id}"),
    # muster#73: changing what a device is FOR. Administrator-only rather than
    # device-proven, because a role selects which policy scope is served -
    # including app-config, which carries write tokens.
    ("POST", "/v1/kith/{key_id}/role"),
}


def _registered(app):
    return {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if method != "HEAD"
    }


def _walkable(path):
    for name in ("{request_id}", "{code}", "{key_id}"):
        path = path.replace(name, "x")
    return path


def test_every_route_is_deliberately_open_or_deliberately_not(client):
    """A new endpoint defaults to reachable by anyone, which is the right
    default for this service and the wrong one to leave unexamined."""
    assert _registered(client.app) == OPEN_TO_ANYONE | DEVICE_PROVEN | ADMINISTRATOR_ONLY


def test_the_three_audiences_do_not_overlap():
    """A route in two sets would pass whichever test ran first and prove
    nothing. Cheap here, and the sets are about to grow (muster#27, #42)."""
    assert not OPEN_TO_ANYONE & DEVICE_PROVEN
    assert not DEVICE_PROVEN & ADMINISTRATOR_ONLY
    assert not OPEN_TO_ANYONE & ADMINISTRATOR_ONLY


@pytest.mark.parametrize("path", ["/docs", "/redoc"])
def test_the_interactive_api_browser_is_not_served(client, path):
    """FastAPI's own documentation pages load their JavaScript from a public
    CDN, which would put a third-party script on the SAME ORIGIN as the
    console. Same-origin is the whole problem: such a script can call every
    administrator endpoint with the operator's session cookie attached, and the
    console's policy header cannot reach it, because a policy applies to the
    response it arrives on."""
    assert client.get(path).status_code == 404


@pytest.mark.parametrize("method,path", sorted(ADMINISTRATOR_ONLY))
def test_an_administrator_route_refuses_a_caller_with_nothing(client, method, path):
    assert client.request(method, _walkable(path)).status_code == 401


@pytest.mark.parametrize("method,path", sorted(OPEN_TO_ANYONE))
def test_an_open_route_never_asks_a_device_to_sign_in(client, method, path):
    """THE TEST THAT PROTECTS ENROLLMENT.

    A device presenting a CSR has no credential and no way to be given one -
    that is the entire design. If administrator sign-in ever spreads onto these
    paths, every device in the estate stops being able to enroll or renew, and
    the only sign of it is a 401 on a phone nobody is looking at. Put an admin
    dependency on `present` and this test says so.
    """
    response = client.request(method, _walkable(path))
    assert response.status_code != 401, f"{method} {path} now demands a session"


@pytest.mark.parametrize("method,path", sorted(DEVICE_PROVEN))
def test_a_device_route_asks_for_a_proof_and_not_for_a_session(client, method, path):
    """THE SAME GUARD AS ABOVE, for a device that HAS enrolled.

    An administrator dependency landing on one of these is the failure that
    reads as "the endpoint is protected" and is actually "every device in the
    estate is now unconfigurable, and nobody will find out until one is opened".
    422 is the schema refusing an empty body, which is the proof being asked
    for - a 401 would be a person being asked for.
    """
    response = client.request(method, _walkable(path))
    assert response.status_code == 422, f"{method} {path} refused for the wrong reason"


@pytest.mark.parametrize("method,path", sorted(DEVICE_PROVEN))
def test_a_device_route_refuses_a_well_formed_request_with_no_proof(client, method, path):
    """A body of the right SHAPE and the wrong content gets nothing. The nonce
    is server-issued and single use, so one nobody minted is unknown."""
    response = client.request(
        method,
        _walkable(path),
        json={
            "nonce": "a-nonce-nobody-issued",
            "signature_b64": "",
            "certificate_pem": "not a certificate",
        },
    )
    assert response.status_code in (400, 503), response.text


def test_a_device_enrolls_end_to_end_while_sign_in_is_configured():
    """The same guard again, with a provider actually wired up.

    The device half of the ceremony carries no cookie, no token and no header,
    from the first request to the certificate coming out.
    """
    state = State(
        enrollment=Enrollment(clock=Clock()),
        authority=Authority.create(
            "muster test CA",
            clock=lambda: dt.datetime(2026, 8, 18, tzinfo=dt.timezone.utc),
        ),
        sign_in=_ADMIN_PROVIDER.sign_in(),
        cookie_secure=False,
    )
    client = TestClient(create_app(state))

    code = client.post("/v1/enroll/codes", json={}, cookies=ADMIN).json()["code"]
    csr_pem, _key = _csr_pem()
    presented = client.post(
        "/v1/enroll/requests",
        json={"code": code, "csr_pem": csr_pem, "device_name": "pixel-6a"},
    )
    assert presented.status_code == 202, presented.text
    request_id = presented.json()["request_id"]

    client.post(
        f"/v1/enroll/requests/{request_id}/vouch",
        json={"fingerprint": presented.json()["fingerprint"]},
        cookies=ADMIN,
    )
    collected = client.get(f"/v1/enroll/requests/{request_id}/identity")

    assert collected.status_code == 200, collected.text
    assert "BEGIN CERTIFICATE" in collected.json()["certificate_pem"]


# ---- refusing to start without a way in ----------------------------------

_SIGN_IN_ENV = (
    "MUSTER_OIDC_ISSUER",
    "MUSTER_OIDC_JWKS_URL",
    "MUSTER_OIDC_AUTHORIZE_URL",
    "MUSTER_OIDC_TOKEN_URL",
    "MUSTER_OIDC_CLIENT_ID",
    "MUSTER_ADMIN_SUBJECTS",
)


def _ca_on_disk(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    ca = Authority.create("muster test CA")
    key, cert = tmp_path / "ca.key", tmp_path / "ca.crt"
    key.write_bytes(
        ca._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert.write_bytes(ca.certificate_pem)
    monkeypatch.setenv("MUSTER_CA_KEY", str(key))
    monkeypatch.setenv("MUSTER_CA_CERT", str(cert))
    monkeypatch.setenv("MUSTER_BASE_URL", "https://enroll.muster.casa")


def _configure_sign_in(monkeypatch):
    monkeypatch.setenv("MUSTER_OIDC_ISSUER", "https://identity.example.test/pool")
    monkeypatch.setenv(
        "MUSTER_OIDC_JWKS_URL", "https://identity.example.test/pool/keys"
    )
    monkeypatch.setenv(
        "MUSTER_OIDC_AUTHORIZE_URL", "https://identity.example.test/authorize"
    )
    monkeypatch.setenv("MUSTER_OIDC_TOKEN_URL", "https://identity.example.test/token")
    monkeypatch.setenv("MUSTER_OIDC_CLIENT_ID", "muster-console")


def test_sign_in_alone_is_a_way_in(monkeypatch, tmp_path):
    """Administrator sign-in, fully configured, is enough on its own to start
    and to answer that it is the way in - no bearer credential is accepted."""
    from muster.api import app_from_env

    _ca_on_disk(tmp_path, monkeypatch)
    _configure_sign_in(monkeypatch)
    monkeypatch.setenv("MUSTER_ADMIN_SUBJECTS", "s-0001-administrator")

    client = TestClient(app_from_env())

    assert client.get("/v1/session").json()["sign_in_configured"] is True
    assert (
        client.get(
            "/v1/enroll/requests", headers={"Authorization": "Bearer anything"}
        ).status_code
        == 401
    )


def test_a_provider_with_nobody_allowed_refuses_to_start(monkeypatch, tmp_path):
    """The pool is shared with the rest of the estate. An empty allowlist means
    every account in it can vouch for devices, and the console would look
    exactly like a correctly configured one."""
    from muster.api import app_from_env

    _ca_on_disk(tmp_path, monkeypatch)
    _configure_sign_in(monkeypatch)
    monkeypatch.delenv("MUSTER_ADMIN_SUBJECTS", raising=False)

    with pytest.raises(RuntimeError) as caught:
        app_from_env()
    assert "MUSTER_ADMIN_SUBJECTS" in str(caught.value)


# --------------------------------------------------------------------------
# Assets a device fetches over its own identity (muster#45).
#
# The route the wallpaper travels, and the one an APK will travel when
# muster#42 lands. The tests that matter most are the two about what a device
# is NOT allowed to fetch: this endpoint turns a caller-supplied name into a
# path, on a pod that also holds the CA.


def _fetch_asset(client, key, identity, name):
    """The whole exchange a device makes for one asset."""
    import base64

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    signature = key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
    return client.post(
        "/v1/device/asset",
        json={
            "nonce": nonce,
            "signature_b64": base64.b64encode(signature).decode(),
            "certificate_pem": identity.certificate_pem.decode(),
            "name": name,
        },
    )


def _asset_store(tmp_path):
    from muster import assets

    root = tmp_path / "assets"
    root.mkdir(exist_ok=True)
    (root / "wall.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"wallpaper bytes")
    return assets.Assets(root=root, configured=str(root))


def test_an_enrolled_device_fetches_an_asset_and_its_digest(state, tmp_path):
    """THE POINT OF muster#45. The image reaches a phone on somebody else's
    network, over the identity it already holds, with no cable and no router
    serving files for the fleet."""
    import hashlib

    state.assets = _asset_store(tmp_path)
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    response = _fetch_asset(client, key, identity, "wall.png")

    assert response.status_code == 200
    assert response.content.startswith(b"\x89PNG")
    assert response.headers["Content-Type"] == "image/png"
    # THE DIGEST IS THE POINT. Cloudflare served a stale APK for hours while
    # the endpoint describing it stayed current; an asset the device cannot
    # check inherits exactly that bug.
    assert response.headers["X-Muster-Digest"] == hashlib.sha256(response.content).hexdigest()
    assert response.headers["Cache-Control"] == "no-store"


def test_an_asset_is_not_served_to_a_caller_with_no_identity(state, tmp_path):
    """Open, this is a read of any file in the store by anyone who guesses a
    name - and the store is where an APK is about to live."""
    state.assets = _asset_store(tmp_path)
    client = _proof_client(state)
    assert client.post("/v1/device/asset", json={
        "nonce": "x", "signature_b64": "x", "certificate_pem": "x", "name": "wall.png",
    }).status_code in (400, 401)


@pytest.mark.parametrize("name", ["../../etc/passwd", "../secret", "a/b.png", ".env"])
def test_a_proven_device_still_cannot_read_outside_the_store(state, tmp_path, name):
    """Proving you are a device buys you an asset, not a file.

    The pod holds the CA. A device with a valid certificate is not a caller
    this endpoint may hand an arbitrary path to.
    """
    state.assets = _asset_store(tmp_path)
    (tmp_path / "secret").write_bytes(b"the CA key")
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    assert _fetch_asset(client, key, identity, name).status_code == 404


def test_an_asset_that_is_not_there_is_a_404_and_not_a_500(state, tmp_path):
    state.assets = _asset_store(tmp_path)
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)
    assert _fetch_asset(client, key, identity, "nothing.png").status_code == 404


def test_a_missing_store_is_a_503_rather_than_a_missing_asset(state, tmp_path):
    """The difference between "the operator has not uploaded it" and "the
    secret did not mount" is the difference between editing policy and fixing
    a deployment, and a 404 sends somebody to the wrong one."""
    from muster import assets

    state.assets = assets.Assets(root=None, configured="/etc/muster/assets")
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)
    assert _fetch_asset(client, key, identity, "wall.png").status_code == 503


def test_an_asset_fetch_is_never_cached_even_when_it_fails(state, tmp_path):
    """A cached 404 is a device that cannot fetch a wallpaper the operator has
    since uploaded, on a phone nobody is holding. Same reasoning as the
    no-store on _proven_device's own refusals."""
    state.assets = _asset_store(tmp_path)
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)
    response = _fetch_asset(client, key, identity, "nothing.png")
    assert response.headers["Cache-Control"] == "no-store"


def test_the_asset_store_is_reported_on_readyz(state, tmp_path):
    """A store that did not mount and a fleet nobody has uploaded to answer
    every device identically, and only a count tells them apart."""
    state.assets = _asset_store(tmp_path)
    client = _proof_client(state)
    assert client.get("/readyz").json()["assets"]["assets"] == 1


# ---- roles, end to end (muster#70) ---------------------------------------


def test_a_qr_minted_as_a_role_produces_a_device_that_gets_that_roles_policy(
    state, tmp_path
):
    """THE WHOLE ASK: "make it a zippie android so it does zippie config".

    One administrator action - mint a QR for a role - and a wiped phone comes up
    holding that role's policy, including the app config the kith may not carry.
    Nothing types a code and nobody clicks a second time.
    """
    from muster import policy as policy_mod

    root = tmp_path / "policy"
    root.mkdir()
    (root / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    (root / "role-zippie.app-config").write_text(
        "set app.zippie.companion announceToken tok\n"
    )
    state.policies = policy_mod.Policies(root=root)
    client, _apk = _published_and_proving(state, tmp_path)

    described = client.post(
        "/v1/provision/qr", json={"role": "zippie"}, cookies=ADMIN
    ).json()
    assert described["pairing"]["role"] == "zippie"

    csr, key = _csr_pem()
    client.post(
        "/v1/enroll/requests",
        json={"code": _minted(state).code, "csr_pem": csr, "device_name": "pixel-6a"},
    )

    # The kith remembers what it is for.
    roll = client.get("/v1/kith", cookies=ADMIN).json()["devices"]
    assert [d["name"] for d in roll] == ["pixel-6a"]

    # And the device is served the role's policy over its own identity.
    identity = _collect_identity(client, state)
    served = _fetch_config(client, key, identity).json()["files"]
    assert "announceToken" in served["app-config"]
    assert served["restrictions"] == "DISALLOW_SAFE_BOOT\n"


def test_a_device_cannot_choose_its_own_role(state, tmp_path):
    """A role selects which policy scope is served, INCLUDING `app-config`,
    which carries write tokens. A device that could name its own role could ask
    for another role's credentials, so the role is read from the kith and a
    `role` in the request body is ignored."""
    from muster import policy as policy_mod

    root = tmp_path / "policy"
    root.mkdir()
    (root / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    (root / "role-zippie.app-config").write_text("set app.zippie.companion t s\n")
    state.policies = policy_mod.Policies(root=root)
    client, _apk = _published_and_proving(state, tmp_path)

    # Enrolled with NO role.
    client.post("/v1/provision/qr", json={}, cookies=ADMIN)
    csr, key = _csr_pem()
    client.post(
        "/v1/enroll/requests",
        json={"code": _minted(state).code, "csr_pem": csr, "device_name": "pixel-6a"},
    )
    identity = _collect_identity(client, state)

    import base64

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    served = client.post(
        "/v1/device/config",
        json={
            "nonce": nonce,
            "signature_b64": base64.b64encode(
                key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
            ).decode(),
            "certificate_pem": identity.certificate_pem.decode(),
            "role": "zippie",
        },
    ).json()["files"]
    assert "app-config" not in served, "a device talked its way into a role"


def test_a_role_that_is_not_a_role_is_a_400_rather_than_a_500(state, tmp_path):
    client, _apk = _published(state, tmp_path)
    for bad in ("../etc", "has.dot", "UPPER"):
        assert client.post(
            "/v1/provision/qr", json={"role": bad}, cookies=ADMIN
        ).status_code == 400, bad


# ---- re-roling a device (muster#73) --------------------------------------


def _enrolled_device(client, state, tmp_path, role=""):
    client.post("/v1/provision/qr", json={"role": role}, cookies=ADMIN)
    csr, key = _csr_pem()
    client.post(
        "/v1/enroll/requests",
        json={"code": _minted(state).code, "csr_pem": csr, "device_name": "pixel-6a"},
    )
    roll = client.get("/v1/kith", cookies=ADMIN).json()["devices"]
    return roll[0]["key_id"], key


def test_a_device_can_be_re_roled_and_gets_the_new_policy_at_its_next_fetch(
    state, tmp_path
):
    """THE POINT OF THE TICKET. A handset enrolled with no role becomes a zippie
    android without being wiped, and the policy follows at its next check-in
    because the scope is resolved from the kith on every fetch."""
    from muster import policy as policy_mod

    root = tmp_path / "policy"
    root.mkdir()
    (root / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    (root / "role-zippie.app-config").write_text("set app.zippie.companion t s\n")
    state.policies = policy_mod.Policies(root=root)
    client, _apk = _published_and_proving(state, tmp_path)

    key_id, key = _enrolled_device(client, state, tmp_path)
    identity = _collect_identity(client, state)

    # Before: the kith's policy and nothing else.
    assert "app-config" not in _fetch_config(client, key, identity).json()["files"]

    assert client.post(
        f"/v1/kith/{key_id}/role", json={"role": "zippie"}, cookies=ADMIN
    ).status_code == 200

    # After: no wipe, no re-enrolment, no new certificate.
    assert "app-config" in _fetch_config(client, key, identity).json()["files"]


def test_a_role_can_be_taken_off_a_device(state, tmp_path):
    """An empty role CLEARS, and it has to: `record_issuance` refuses to let an
    empty one overwrite a set role, so without this there is no way back."""
    client, _apk = _published_and_proving(state, tmp_path)
    key_id, _key = _enrolled_device(client, state, tmp_path, role="zippie")

    client.post(f"/v1/kith/{key_id}/role", json={"role": ""}, cookies=ADMIN)
    assert client.get(f"/v1/kith/{key_id}", cookies=ADMIN).json()["device"]["role"] == ""


def test_re_roling_needs_an_administrator(state, tmp_path):
    """A role selects which policy scope is served, INCLUDING app-config, which
    carries write tokens. Open, this endpoint hands anyone another role's
    credentials by way of a device they can already reach."""
    client, _apk = _published_and_proving(state, tmp_path)
    key_id, _key = _enrolled_device(client, state, tmp_path)
    assert client.post(
        f"/v1/kith/{key_id}/role", json={"role": "zippie"}
    ).status_code == 401


def test_re_roling_a_device_that_is_not_in_the_kith_is_a_404(state, tmp_path):
    client, _apk = _published_and_proving(state, tmp_path)
    assert client.post(
        f"/v1/kith/{'a' * 64}/role", json={"role": "zippie"}, cookies=ADMIN
    ).status_code == 404


def test_a_role_that_is_not_a_role_is_a_400_here_too(state, tmp_path):
    client, _apk = _published_and_proving(state, tmp_path)
    key_id, _key = _enrolled_device(client, state, tmp_path)
    for bad in ("../etc", "has.dot", "UPPER"):
        assert client.post(
            f"/v1/kith/{key_id}/role", json={"role": bad}, cookies=ADMIN
        ).status_code == 400, bad


# ---- which agent is this? (muster#67 self-update) -------------------------


def test_agent_json_says_which_version_it_serves(state, tmp_path, monkeypatch):
    """WITHOUT THIS MUSTER CANNOT UPDATE ITS OWN AGENT. A device installs only
    when it is carrying a LOWER version than it is told, so an operator naming
    the agent in `install-apps` has to know the number - and until now nothing
    anywhere reported it."""
    from tests.test_provisioning import _fake_apk

    apk, _cert = _fake_apk(tmp_path / "agent.apk")
    apk.with_name("agent-version.txt").write_text("72")
    state.agent_apk = str(apk)
    monkeypatch.setenv("MUSTER_AGENT_APK", str(apk))
    client = TestClient(create_app(state))

    assert client.get("/agent.json").json()["version_code"] == 72


def test_an_unstamped_agent_is_not_given_a_made_up_version(state, tmp_path, monkeypatch):
    """THE FABRICATION THAT WOULD BE WORST. An image built from an agent that
    predates the stamp has no version file. Reporting 0 would read as an agent
    older than every device in the fleet, and every handset would try to
    downgrade itself to it. Absent means muster does not know, and says so by
    omitting the field."""
    from tests.test_provisioning import _fake_apk

    apk, _cert = _fake_apk(tmp_path / "agent.apk")
    state.agent_apk = str(apk)
    monkeypatch.setenv("MUSTER_AGENT_APK", str(apk))
    client = TestClient(create_app(state))

    assert "version_code" not in client.get("/agent.json").json()


def test_a_version_file_that_is_not_a_number_is_not_reported(state, tmp_path, monkeypatch):
    from tests.test_provisioning import _fake_apk

    apk, _cert = _fake_apk(tmp_path / "agent.apk")
    apk.with_name("agent-version.txt").write_text("probably-72")
    state.agent_apk = str(apk)
    monkeypatch.setenv("MUSTER_AGENT_APK", str(apk))
    client = TestClient(create_app(state))

    assert "version_code" not in client.get("/agent.json").json()


def test_a_kith_outage_does_not_500_the_device_config_route(state, tmp_path, monkeypatch):
    """The route's own comment says a store outage means no role, not no
    configuration - and the mechanism it names does not exist.

    `api.py` reads `member = state.kith.member(proven)` under a comment
    asserting "`member` answers None when the kith cannot be read", then falls
    back to the kith scope. But `kith.py`'s `_read` raises `Unreachable` on an
    unreadable store; it never returns None. Its own section header says so:
    "reads: raise, never lie".

    So the documented degradation is unreachable code. During a store outage
    the exception escapes an endpoint that catches only `policy.Unreadable` and
    `policy.NoSource`, and a device asking what it should be gets an unhandled
    500 instead of either the intended kith-scope answer or the deliberate 503
    that five other routes in this file already return via `_unreachable`.

    A 500 also skips the `kith.read.refused` counter, so the outage is missing
    from the metric the operator would look at.
    """
    import base64

    from muster import kith as kith_store

    state.policies = _policy_root(tmp_path)
    (tmp_path / "kith.restrictions").write_text("DISALLOW_SAFE_BOOT\n")
    client = _proof_client(state)
    key, identity, _ = _enrolled(state)

    def unreadable(_key_id):
        raise kith_store.Unreachable("the kith store cannot be read")

    monkeypatch.setattr(state.kith, "member", unreadable)

    nonce = client.post("/v1/auth/challenge", json={}).json()["nonce"]
    response = client.post("/v1/device/config", json={
        "nonce": nonce,
        "signature_b64": base64.b64encode(
            key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))
        ).decode(),
        "certificate_pem": identity.certificate_pem.decode(),
    })

    assert response.status_code == 503, (
        f"expected a deliberate 503, got {response.status_code} - a kith outage "
        "raised straight through the device-config route"
    )
    # 503 AND NOT A SMALLER ANSWER. Falling back to the shared scope would
    # serve fewer files than this device's role earns, and the agent removes a
    # file a successful fetch did not mention - so the "keep it configured"
    # fallback would have withdrawn the very files it meant to protect.
    assert "DISALLOW_SAFE_BOOT" not in response.text
    assert response.headers["Cache-Control"] == "no-store"
