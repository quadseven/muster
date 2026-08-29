"""Generate muster's CA straight into SSM. The key never touches a file."""
import sys
import boto3
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from muster.ca import Authority

KEY_PARAM = "/infra/muster/ca/private_key"
CERT_PARAM = "/infra/muster/ca/certificate"

ssm = boto3.client("ssm")

# Refuse to clobber. A CA regenerated over the top of a live one silently
# invalidates every device it has ever issued to.
for name in (KEY_PARAM, CERT_PARAM):
    try:
        ssm.get_parameter(Name=name)
        print(f"REFUSING: {name} already exists. A second CA would orphan every "
              "device the first one issued to.")
        sys.exit(1)
    except ssm.exceptions.ParameterNotFound:
        pass

authority = Authority.create("muster root", valid_days=3650)
key_pem = authority._key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()

ssm.put_parameter(Name=KEY_PARAM, Value=key_pem, Type="SecureString",
                  Description="muster CA private key - root of trust for every enrolled device")
ssm.put_parameter(Name=CERT_PARAM, Value=authority.certificate_pem.decode(), Type="String",
                  Description="muster CA certificate - public, pinned by devices and by Cloudflare")

cert = x509.load_pem_x509_certificate(authority.certificate_pem)
print("CA created and stored in SSM.")
print(f"  subject:  {cert.subject.rfc4514_string()}")
print(f"  serial:   {cert.serial_number}")
print(f"  expires:  {cert.not_valid_after_utc.date()}")
print(f"  sha256:   {cert.fingerprint(__import__('cryptography.hazmat.primitives.hashes', fromlist=['SHA256']).SHA256()).hex()[:32]}")
