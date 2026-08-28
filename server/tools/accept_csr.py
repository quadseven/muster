#!/usr/bin/env python3
"""Does muster's CA accept a CSR built by the Android agent?

THE SEAM THIS EXISTS FOR. The agent builds PKCS#10 in Kotlin with BouncyCastle;
the CA parses and signs it in Python with `cryptography`. Both halves can be
perfectly self-consistent and still disagree - a signature algorithm identifier
one encodes and the other rejects, a curve named differently, an attributes
block one omits and the other requires. Neither test suite can see it, because
each only ever talks to itself.

So CI takes the CSR the JVM test just wrote and puts it through the real
`Authority.issue()`. Run by hand the same way:

    uv run --group dev python tools/accept_csr.py path/to/agent.csr
"""
from __future__ import annotations

import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from muster.ca import Authority

VOUCHED_NAME = "pixel-6a-new"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <csr.pem>", file=sys.stderr)
        return 2

    path = pathlib.Path(argv[1])
    if not path.is_file():
        print(f"no CSR at {path}", file=sys.stderr)
        return 1

    csr = x509.load_pem_x509_csr(path.read_bytes())
    requested = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    requested_name = requested[0].value if requested else "(none)"

    authority = Authority.create("cross-language check CA")
    identity = authority.issue(
        csr.public_bytes(serialization.Encoding.DER), VOUCHED_NAME
    )
    cert = x509.load_pem_x509_certificate(identity.certificate_pem)

    issued_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if issued_name != VOUCHED_NAME:
        print(
            f"::error::the CA used the CSR's own subject ({issued_name}). A CSR's "
            "subject is written by whoever is enrolling.",
            file=sys.stderr,
        )
        return 1

    if cert.public_key().public_numbers() != csr.public_key().public_numbers():
        print("::error::the issued certificate is for a different key", file=sys.stderr)
        return 1

    print(f"the agent asked to be '{requested_name}' and was issued '{issued_name}'")
    print(f"::notice::the CA accepted the agent's CSR and issued to CN={issued_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
