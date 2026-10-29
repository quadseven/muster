from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from muster.ca import Authority
from muster.proof import Proofs, Verdict


NOW = dt.datetime(2026, 10, 28, 12, tzinfo=dt.timezone.utc)


class Clock:
    def __call__(self) -> float:
        return NOW.timestamp()


def _make_ca(name: str, issuer: x509.Certificate | None = None,
             issuer_key=None, path_length: int = 0):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_name = issuer.subject if issuer else subject
    signer = issuer_key or key
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(signer, hashes.SHA256())
    )
    return key, cert


def _hierarchy(root_name: str):
    root_key, root = _make_ca(root_name, path_length=1)
    intermediate_key, intermediate = _make_ca(
        "muster intermediate", root, root_key, path_length=0
    )
    return Authority(
        intermediate_key, intermediate, certificate_chain=(intermediate, root)
    ), intermediate, root


def _issue(authority: Authority):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")]))
        .sign(key, hashes.SHA256())
    )
    identity = authority.issue(csr.public_bytes(serialization.Encoding.DER), "device")
    return key, identity.certificate_pem


def _sign(key, nonce: str) -> bytes:
    return key.sign(nonce.encode(), ec.ECDSA(hashes.SHA256()))


def test_authority_loads_and_publishes_the_intermediate_chain(tmp_path):
    authority, intermediate, root = _hierarchy("trusted root")
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca-chain.pem"
    key_path.write_bytes(
        authority._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(
        intermediate.public_bytes(serialization.Encoding.PEM)
        + root.public_bytes(serialization.Encoding.PEM)
    )

    loaded = Authority.load(key_path, cert_path)

    assert loaded.certificate_chain == (intermediate, root)
    assert loaded.certificate_pem == cert_path.read_bytes()
    key, leaf_pem = _issue(loaded)
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    leaf.verify_directly_issued_by(intermediate)
    proofs = Proofs(
        clock=Clock(), ca_certificate=loaded.certificate_chain[0],
        ca_chain=loaded.certificate_chain,
    )
    challenge = proofs.challenge()
    assert proofs.verify(
        challenge.nonce, _sign(key, challenge.nonce), leaf_pem
    ) is Verdict.OK


def test_authority_loads_a_legacy_self_signed_ca(tmp_path):
    legacy = Authority.create("legacy self-signed CA")
    key_path = tmp_path / "legacy.key"
    cert_path = tmp_path / "legacy.pem"
    key_path.write_bytes(
        legacy._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(legacy.certificate_pem)

    loaded = Authority.load(key_path, cert_path)

    assert len(loaded.certificate_chain) == 1
    loaded.certificate_chain[0].verify_directly_issued_by(loaded.certificate_chain[0])


def test_authority_rejects_an_intermediate_with_an_untrusted_parent(tmp_path):
    authority, intermediate, _trusted_root = _hierarchy("trusted root")
    _wrong_key, wrong_root = _make_ca("wrong root", path_length=1)
    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca-chain.pem"
    key_path.write_bytes(
        authority._key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(
        intermediate.public_bytes(serialization.Encoding.PEM)
        + wrong_root.public_bytes(serialization.Encoding.PEM)
    )

    with pytest.raises(ValueError, match="certificate chain"):
        Authority.load(key_path, cert_path)


def test_proofs_accept_a_leaf_from_the_trusted_intermediate():
    authority, intermediate, root = _hierarchy("trusted root")
    proofs = Proofs(
        clock=Clock(), ca_certificate=intermediate,
        ca_chain=(intermediate, root),
    )
    key, leaf_pem = _issue(authority)
    challenge = proofs.challenge()

    assert proofs.verify(challenge.nonce, _sign(key, challenge.nonce), leaf_pem) is Verdict.OK


def test_proofs_refuse_a_leaf_from_a_different_parent_with_the_same_name():
    trusted, intermediate, root = _hierarchy("trusted root")
    rogue, rogue_intermediate, _rogue_root = _hierarchy("different root")
    assert rogue_intermediate.subject == intermediate.subject
    proofs = Proofs(
        clock=Clock(), ca_certificate=intermediate,
        ca_chain=(intermediate, root),
    )
    key, leaf_pem = _issue(rogue)
    challenge = proofs.challenge()

    assert proofs.verify(
        challenge.nonce, _sign(key, challenge.nonce), leaf_pem
    ) is Verdict.CERT_NOT_OURS