"""The certificate authority: turn a vouched CSR into a device identity.

A device's certificate IS its membership of the kith (CONTEXT.md). There is no
separate enabled flag, because a flag can disagree with what the device can
actually do and a certificate cannot.

THE RULE THAT MATTERS MOST HERE: **nothing in the CSR is trusted except the
public key.** A CSR is a self-signed blob written by whoever is enrolling, so
its subject, its SANs and its extensions are attacker-controlled input. Signing
a CSR "as submitted" is how a device enrolls itself as `CN=admin` and then
authenticates as one. `issue()` therefore reads the public key out of the CSR
and builds the subject itself, from the name the administrator vouched for.
Everything else in the request is discarded, deliberately and by construction
rather than by validation - there is no list of fields to remember to strip.

WHY SHORT-LIVED, AND WHY LAPSE IS THE REVOCATION. There is no CRL and no OCSP
here on purpose. A revocation list has to REACH the verifier, and this estate's
devices are routers in hotels and phones in drawers - offline for days at a
time is the normal case, not the failure case. An identity that simply stops
being renewed needs to reach nobody: the device's certificate expires on its
own clock and it falls out of the kith. That only works if lifetimes are short
enough for expiry to be a timely answer, so the default is deliberately not a
year.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# 90 days, as specified. Long enough that renewal is not constant chatter, short
# enough that "stop renewing" is a revocation an operator can live with - a
# stolen device stays trusted for at most this long.
DEFAULT_VALIDITY_DAYS = 90

# Renew at a third of life. Not half, and not at the last minute: these devices
# travel, and the window has to be wide enough that a router which is off for a
# fortnight still wakes up inside it. At 90 days this gives a 60-day runway.
RENEW_AFTER_FRACTION = 1 / 3

# Clock skew allowance on not_valid_before. The GL-MT3000 has no RTC and often
# no NTP, so it can boot believing it is 1970 or several hours off. A
# certificate that is not yet valid according to the device is indistinguishable
# from a broken one, and the device cannot fix its own clock without the network
# the certificate is for.
BACKDATE = dt.timedelta(hours=12)


class Untrusted(Exception):
    """The request cannot be turned into an identity."""


@dataclass
class Identity:
    certificate_pem: bytes
    not_before: dt.datetime
    not_after: dt.datetime
    serial: int

    def renew_after(self) -> dt.datetime:
        """When the holder should start trying to replace this."""
        life = self.not_after - self.not_before
        return self.not_before + life * RENEW_AFTER_FRACTION


class Authority:
    """A CA that signs device certificates.

    The key is passed in, never generated as a side effect of construction. A CA
    that quietly mints itself a new key when it cannot find one is a CA that
    silently invalidates every device it has ever issued to, at the exact moment
    somebody mounts the wrong volume.
    """

    def __init__(self, key, certificate, clock=None) -> None:
        self._key = key
        self._cert = certificate
        self._clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    # ---- construction ----------------------------------------------------

    @classmethod
    def create(cls, common_name: str, *, clock=None, valid_days: int = 3650):
        """A fresh CA. For a first run and for tests; not for reload."""
        now = (clock or (lambda: dt.datetime.now(dt.timezone.utc)))()
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + dt.timedelta(days=valid_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert, clock=clock)

    @classmethod
    def load(cls, key_path: Path, cert_path: Path, *, password: bytes | None = None,
             clock=None):
        key = serialization.load_pem_private_key(
            Path(key_path).read_bytes(), password=password
        )
        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        return cls(key, cert, clock=clock)

    @property
    def certificate_pem(self) -> bytes:
        """What devices pin. Public, and safe to ship anywhere."""
        return self._cert.public_bytes(serialization.Encoding.PEM)

    # ---- issuance --------------------------------------------------------

    def issue(self, csr_der: bytes, device_name: str,
              valid_days: int = DEFAULT_VALIDITY_DAYS) -> Identity:
        """Sign a vouched CSR, using ONLY its public key.

        `device_name` comes from the vouch, not from the request. See the module
        docstring: everything else in a CSR is written by the enrolling party.
        """
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except Exception as exc:  # noqa: BLE001 - any parse failure is the same answer
            raise Untrusted(f"not a parseable CSR: {exc}") from exc

        # A CSR is self-signed by the key it carries. If that signature does not
        # verify, the sender does not hold the private key for the public key
        # they are asking us to certify - which is the entire claim being made.
        if not csr.is_signature_valid:
            raise Untrusted(
                "the CSR's self-signature does not verify: the sender does not "
                "hold the key they are asking to have certified"
            )

        public_key = csr.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise Untrusted(
                f"expected an EC key, got {type(public_key).__name__}. Devices "
                "generate P-256; anything else did not come from our agent."
            )
        # THE CURVE, NOT JUST THE TYPE. The message above has always said
        # "Devices generate P-256", but the check above only asked whether the
        # key was EC at all - so a CSR on secp192r1 was certified clean, and a
        # ~96-bit key carried a full device identity signed by this CA. Every
        # EC curve passes an isinstance test; only this line makes the sentence
        # above true.
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise Untrusted(
                f"expected a P-256 key, got {public_key.curve.name} "
                f"({public_key.key_size}-bit). Devices generate P-256; anything "
                "else did not come from our agent."
            )

        now = self._clock()
        not_before = now - BACKDATE
        not_after = now + dt.timedelta(days=valid_days)
        serial = x509.random_serial_number()

        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_name)])
            )
            .issuer_name(self._cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(
                # A device certificate is for authenticating a client, and only
                # that. Without this a certificate issued to a phone is equally
                # usable to impersonate the SERVER to another device.
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )

        return Identity(
            certificate_pem=cert.public_bytes(serialization.Encoding.PEM),
            not_before=not_before,
            not_after=not_after,
            serial=serial,
        )
