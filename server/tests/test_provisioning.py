"""The provisioning QR, and the checksum everybody gets wrong.

`test_the_checksum_is_of_the_certificate_not_the_apk` is the one to read. Both
values are a SHA-256 of something inside the same file, both look plausible in a
QR, and the wrong one fails on the handset as "can't set up device" with nothing
naming the cause.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import zipfile

import pytest

from muster import provisioning
from muster.provisioning import NotSigned, encode, payload, signature_checksum

COMPONENT = "app.muster.agent/.MusterDeviceAdminReceiver"


def _signer():
    """One keypair + certificate, reusable so two APKs can share a signer."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "muster agent")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _fake_apk(path, signer=None, *, with_signature_block=True, filler=b"v1"):
    """An APK-shaped zip. `filler` varies so two builds differ byte-for-byte."""
    key, cert = signer or _signer()
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", "not really")
        z.writestr("classes.dex", filler)
        if with_signature_block:
            z.writestr("META-INF/CERT.RSA", _pkcs7_der(key, cert))
    return path, cert


def _pkcs7_der(key, cert) -> bytes:
    """A real PKCS#7 blob carrying one certificate, built rather than fixtured."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7 as p7

    return (
        p7.PKCS7SignatureBuilder()
        .set_data(b"x")
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [p7.PKCS7Options.DetachedSignature])
    )


# ---- the checksum --------------------------------------------------------


def _expected(cert) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding

    return base64.urlsafe_b64encode(
        hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()
    ).decode().rstrip("=")


def test_the_checksum_is_of_the_certificate_not_the_apk(tmp_path):
    """THE trap. Both are a SHA-256 of something in the same file."""
    apk, cert = _fake_apk(tmp_path / "agent.apk")
    from cryptography.hazmat.primitives.serialization import Encoding

    cert_der = cert.public_bytes(Encoding.DER)
    expected = base64.urlsafe_b64encode(hashlib.sha256(cert_der).digest()).decode().rstrip("=")

    assert signature_checksum(apk) == expected

    apk_file_digest = base64.urlsafe_b64encode(
        hashlib.sha256(apk.read_bytes()).digest()
    ).decode().rstrip("=")
    assert signature_checksum(apk) != apk_file_digest, (
        "the checksum must not be of the APK file - that is the deprecated "
        "PACKAGE_CHECKSUM, and it changes on every build"
    )


def test_the_checksum_is_url_safe_and_unpadded(tmp_path):
    """Standard base64 puts + and / in the string, which survive a QR and then
    get mangled by anything URL-shaped downstream."""
    apk, _cert = _fake_apk(tmp_path / "agent.apk")
    value = signature_checksum(apk)
    assert "+" not in value and "/" not in value and "=" not in value


def test_the_checksum_is_stable_across_rebuilds(tmp_path):
    """THE reason to use the certificate rather than the package. Two genuinely
    different builds, same signing key: one printed QR keeps working across
    releases, where a package checksum would need reprinting every time."""
    signer = _signer()
    first, _ = _fake_apk(tmp_path / "one" / "agent.apk", signer, filler=b"build-1")
    second, _ = _fake_apk(tmp_path / "two" / "agent.apk", signer, filler=b"build-2")

    assert first.read_bytes() != second.read_bytes(), "the two builds must differ"
    assert signature_checksum(first) == signature_checksum(second)
    assert _expected(signer[1]) == signature_checksum(first)


def test_an_apk_with_no_v1_signature_raises_rather_than_guessing(tmp_path):
    """A checksum computed from the wrong thing produces a QR that fails on the
    handset with no diagnosis - the worst possible place to find out. Our own
    debug APK hit this: AGP signs v2/v3 only by default."""
    apk, _cert = _fake_apk(tmp_path / "agent.apk", with_signature_block=False)
    with pytest.raises(NotSigned) as caught:
        signature_checksum(apk)
    assert "v2/v3" in str(caught.value)


# ---- the payload ---------------------------------------------------------


def test_the_payload_carries_what_the_platform_reads(tmp_path):
    data = payload(
        component=COMPONENT,
        download_url="https://enroll.muster.example/agent.apk",
        checksum="abc",
    )
    assert data[provisioning.COMPONENT] == COMPONENT
    assert data[provisioning.DOWNLOAD].startswith("https://")
    assert data[provisioning.SIGNATURE_CHECKSUM] == "abc"


def test_system_apps_are_left_enabled_by_default():
    """False strips system apps the DPC does not explicitly enable, which on a
    Pixel means losing the launcher, the camera and Settings - a very managed
    device that nobody can use."""
    data = payload(component=COMPONENT, download_url="https://x/agent.apk", checksum="c")
    assert data[provisioning.LEAVE_SYSTEM_APPS] is True


def test_the_server_url_rides_in_the_admin_extras(tmp_path):
    """This is what makes it a no-cable path: the device comes up already
    knowing where to enroll, so nobody types a URL on a phone keyboard."""
    data = payload(
        component=COMPONENT, download_url="https://x/agent.apk", checksum="c",
        server_url="https://enroll.muster.example/",
    )
    assert data[provisioning.ADMIN_EXTRAS] == {"muster.server_url": "https://enroll.muster.example"}


def test_the_pairing_code_rides_beside_the_server_url_not_instead_of_it():
    """The bundle is passed to the DPC verbatim and the platform does not merge.

    Two assignments to ADMIN_EXTRAS would drop one key silently, and the symptom
    is a phone that provisions healthy and then has an address with no code, or
    a code with nowhere to send it - neither of which says anything on the
    handset.
    """
    data = payload(
        component=COMPONENT, download_url="https://x/agent.apk", checksum="c",
        server_url="https://enroll.muster.example/", pairing_code="a-scanned-code",
    )
    assert data[provisioning.ADMIN_EXTRAS] == {
        provisioning.EXTRA_SERVER_URL: "https://enroll.muster.example",
        provisioning.EXTRA_PAIRING_CODE: "a-scanned-code",
    }


def test_a_payload_with_no_pairing_code_is_the_one_that_existed_before():
    """A QR meant to be PRINTED must not carry a code: the rest of this payload
    is stable for the life of the signing key and a code expires in minutes, so
    a printed one would have a hands-free half that is always dead. Such a
    device provisions, comes up owned, and waits to be enrolled by hand."""
    data = payload(
        component=COMPONENT, download_url="https://x/agent.apk", checksum="c",
        server_url="https://enroll.muster.example",
    )
    assert data[provisioning.ADMIN_EXTRAS] == {
        provisioning.EXTRA_SERVER_URL: "https://enroll.muster.example"
    }
    assert provisioning.EXTRA_PAIRING_CODE not in data[provisioning.ADMIN_EXTRAS]


def test_the_extras_keys_are_the_ones_the_agent_reads():
    """These are OURS, not Android's - the platform never looks inside the
    bundle - so they are an interface with ProvisioningPolicy.kt and nothing
    else. A rename on one side is a device that provisions and knows nothing."""
    assert provisioning.EXTRA_SERVER_URL == "muster.server_url"
    assert provisioning.EXTRA_PAIRING_CODE == "muster.pairing_code"

    agent = (
        pathlib.Path(__file__).resolve().parents[2]
        / "agent/android/app/src/main/java/app/muster/agent/ProvisioningPolicy.kt"
    ).read_text()
    for key in (provisioning.EXTRA_SERVER_URL, provisioning.EXTRA_PAIRING_CODE):
        assert f'"{key}"' in agent, f"{key} is not read by the agent"


def test_wifi_is_optional_but_complete_when_given():
    """A device has no network before provisioning and needs one to fetch the
    agent. Half a wifi config is worse than none - it fails mid-setup."""
    without = payload(component=COMPONENT, download_url="https://x", checksum="c")
    assert provisioning.WIFI_SSID not in without

    with_wifi = payload(
        component=COMPONENT, download_url="https://x", checksum="c",
        wifi_ssid="house", wifi_password="hunter2",  # noqa: S106 - a fixture for a payload-shape test, not a credential
    )
    assert with_wifi[provisioning.WIFI_SSID] == "house"
    assert with_wifi[provisioning.WIFI_SECURITY] == "WPA"
    assert with_wifi[provisioning.WIFI_PASSWORD] == "hunter2"


def test_an_open_network_needs_no_password():
    data = payload(
        component=COMPONENT, download_url="https://x", checksum="c", wifi_ssid="cafe",
    )
    assert provisioning.WIFI_PASSWORD not in data


def test_encode_is_compact_and_parses_back():
    data = payload(component=COMPONENT, download_url="https://x", checksum="c")
    text = encode(data)
    assert ", " not in text, "whitespace is wasted QR modules"
    assert json.loads(text) == data
