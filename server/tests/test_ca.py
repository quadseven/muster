"""What the CA must refuse, and what it must never copy from a request.

The test to read first is `test_the_subject_comes_from_the_vouch_not_the_csr`.
A CSR is written by whoever is enrolling; signing one "as submitted" is how a
device enrolls itself as CN=admin and then authenticates as one. Everything else
here is ordinary certificate hygiene.
"""
from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from muster.ca import (
    BACKDATE,
    DEFAULT_VALIDITY_DAYS,
    Authority,
    Untrusted,
)


class Clock:
    def __init__(self) -> None:
        self.t = dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += dt.timedelta(**kw)


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def ca(clock):
    return Authority.create("muster development CA", clock=clock)


def _csr(common_name="whatever-the-device-claims", key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER), key


def _issued(ca, csr_der, name="pixel-6a-old", **kw):
    identity = ca.issue(csr_der, name, **kw)
    return x509.load_pem_x509_certificate(identity.certificate_pem), identity


# ---- the rule that matters ----------------------------------------------


def test_the_subject_comes_from_the_vouch_not_the_csr(ca):
    """THE rule. A CSR's subject is attacker-controlled input."""
    csr_der, _key = _csr(common_name="admin")
    cert, _ = _issued(ca, csr_der, name="pixel-6a-old")

    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert subject == "pixel-6a-old"
    assert subject != "admin"


def test_the_public_key_does_come_from_the_csr(ca):
    """The one thing that IS taken from the request - it is the whole point."""
    csr_der, key = _csr()
    cert, _ = _issued(ca, csr_der)

    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


def test_a_csr_whose_signature_does_not_verify_is_refused(ca):
    """A CSR is self-signed by the key it carries. If that does not verify, the
    sender does not hold the private key for the key they want certified, which
    is the entire claim being made."""
    csr_der, _key = _csr()
    tampered = bytearray(csr_der)
    tampered[-1] ^= 0xFF  # break the signature, keep the structure

    with pytest.raises(Untrusted) as caught:
        ca.issue(bytes(tampered), "pixel-6a-old")
    assert "does not hold the key" in str(caught.value) or "parseable" in str(caught.value)


def test_garbage_is_refused_rather_than_crashing(ca):
    with pytest.raises(Untrusted):
        ca.issue(b"this is not a CSR", "pixel-6a-old")


def test_a_non_ec_key_is_refused(ca):
    """Our agent generates P-256. Anything else did not come from it, and a CA
    that signs whatever turns up cannot say what its devices hold."""
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .sign(rsa_key, hashes.SHA256())
    )
    with pytest.raises(Untrusted) as caught:
        ca.issue(csr.public_bytes(serialization.Encoding.DER), "pixel-6a-old")
    assert "EC key" in str(caught.value)


# ---- what the certificate is allowed to do -------------------------------


def test_a_device_certificate_is_client_auth_only(ca):
    """Without this, a certificate issued to a phone is equally usable to
    impersonate the SERVER to another device."""
    csr_der, _ = _csr()
    cert, _ = _issued(ca, csr_der)

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]


def test_a_device_certificate_cannot_sign_other_certificates(ca):
    csr_der, _ = _csr()
    cert, _ = _issued(ca, csr_der)

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign is False
    assert usage.digital_signature is True


def test_the_ca_itself_cannot_issue_intermediates(ca):
    root = x509.load_pem_x509_certificate(ca.certificate_pem)
    basic = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True and basic.path_length == 0


# ---- time ----------------------------------------------------------------


def test_the_certificate_is_backdated_for_devices_with_no_clock(ca, clock):
    """The GL-MT3000 has no RTC and often no NTP: it can boot believing it is
    hours off. A not-yet-valid certificate is indistinguishable from a broken
    one, and the device cannot fix its clock without the network the certificate
    is for."""
    csr_der, _ = _csr()
    _cert, identity = _issued(ca, csr_der)
    assert identity.not_before == clock() - BACKDATE


def test_the_default_lifetime_is_ninety_days(ca, clock):
    csr_der, _ = _csr()
    _cert, identity = _issued(ca, csr_der)
    assert identity.not_after == clock() + dt.timedelta(days=DEFAULT_VALIDITY_DAYS)


def test_renewal_starts_at_a_third_of_life(ca, clock):
    """Wide enough that a router switched off for a fortnight still wakes inside
    the window. At 90 days that is a 60-day runway."""
    csr_der, _ = _csr()
    _cert, identity = _issued(ca, csr_der)

    runway = identity.not_after - identity.renew_after()
    assert dt.timedelta(days=59) < runway < dt.timedelta(days=62)


def test_two_devices_do_not_share_a_serial(ca):
    a, _ = _csr()
    b, _ = _csr()
    assert _issued(ca, a)[1].serial != _issued(ca, b)[1].serial


# ---- the CA's own key ----------------------------------------------------


def test_the_ca_is_never_created_as_a_side_effect_of_loading(tmp_path):
    """A CA that mints itself a new key when it cannot find one silently
    invalidates every device it has ever issued to, at the moment somebody
    mounts the wrong volume. `load` must fail instead."""
    with pytest.raises(Exception):
        Authority.load(tmp_path / "absent.key", tmp_path / "absent.crt")


def test_the_published_ca_certificate_carries_no_private_key(ca):
    """This is the blob devices pin, and it goes everywhere."""
    pem = ca.certificate_pem
    assert b"BEGIN CERTIFICATE" in pem
    assert b"PRIVATE KEY" not in pem
