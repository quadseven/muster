# Offline root signing ceremony for the device CA

This is a human procedure. It is documentation only; the root key must never
be copied to a server, CI runner, repository, or chat. Do not run it until the
operator has scheduled the cutover and measured the active device count.

## Before signing

1. Confirm that the offline household root is the approved trust anchor and
   that it is allowed to sign one device-identity intermediate.
2. Read the active device count from the live device store and record the
   result, timestamp, and source in the cutover record. This count determines
   how many existing identities need re-enrollment.
3. Generate the intermediate private key in the approved secret boundary that
   will hold the online issuer key. Never export that private key. Create a
   certificate-signing request from it and transfer only the CSR to the
   offline signing environment.
4. Confirm the CSR public key is the one intended for the service and its
   subject identifies only the device issuer. The issuer is not a server CA.

## Sign offline

Create an extension file on the offline signing system with exactly this
profile:

```ini
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
```

Using the locally held root certificate and key, sign only the reviewed CSR.
The resulting certificate must be a CA with path length zero, so it can issue
device leaves but cannot create another intermediate. Do not sign a second
CSR as part of the same operation.

Verify the result before it leaves the offline environment:

```sh
openssl verify -CAfile household-root.pem muster-intermediate.pem
openssl x509 -in muster-intermediate.pem -noout -subject -issuer -text
```

The first command must report `OK`. Review the subject, issuer, validity,
basic constraints, key usage, subject key identifier, and authority key
identifier. The issuer must be the chosen root, and the CSR public key must
match the signed intermediate. Reject the result if any check is unexpected.

## Install and cut over

1. Return only the signed intermediate certificate and the root certificate
   to the service secret boundary. Keep the intermediate private key there.
2. Assemble the public certificate bundle in this order: intermediate, then
   root. `Authority.load` expects the private key to match the first
   certificate and validates every signature in that path.
3. Apply the separately reviewed deployment change. Confirm startup succeeds
   and a newly issued leaf verifies against the intermediate and root.
4. Re-enroll the active devices counted above, then confirm each presents a
   leaf issued by the new intermediate. Existing leaves do not become valid
   under the new issuer automatically.
5. Record the completed count and the verification evidence. Keep the offline
   root key offline. Never put a certificate private key, password, secret
   path, device identifier, or live endpoint in this repository.

This procedure does not define how to revoke the intermediate. Leaf CRL and
OCSP responses do not revoke it. Define and test a separate offline-root
revocation procedure before relying on intermediate revocation.
