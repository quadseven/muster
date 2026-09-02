-- The kith, written down. Applied by an operator with `psql -f` when the
-- database is created, and re-applied by muster itself whenever it opens a
-- connection. It is the same file both times, so what shipped and what was run
-- by hand cannot disagree about what the tables are.
--
-- SAFE TO RUN FROM THE SERVER, and this paragraph is the argument rather than a
-- habit. The three reasons not to migrate from a serving process are concurrent
-- replicas racing, a rolling deploy where two versions disagree about the
-- schema, and a destructive statement running unattended. None apply here:
-- muster is replicas: 1 with strategy Recreate (the Deployment manifest in the
-- operator's ops repository, not in this one; read live 2026-09-02).
--
-- THIS FILE SAID "there is not an ALTER or a DROP in this file. The first
-- change that needs one is the point at which this needs a real migration
-- story." That change arrived (muster#70, roles), so here is the story.
--
-- There is now exactly ONE ALTER, at the bottom, and it is additive and
-- idempotent: `ADD COLUMN IF NOT EXISTS ... NOT NULL DEFAULT ''`. It cannot
-- lose a row, cannot rewrite one, and running it twice is a no-op - so it
-- breaks none of the three reasons above. Postgres 11+ adds a defaulted column
-- without rewriting the table, so it does not lock anything for long either.
--
-- WHAT WOULD NOT BE SAFE, so the line is somewhere rather than nowhere: a DROP
-- of anything, a column whose default has to be computed from existing rows, a
-- type change, or a NOT NULL added to a column that already holds nulls. The
-- first of those is the point at which this needs a real migration tool, and
-- adding one here would be the wrong place to find out.

-- ONE ROW PER KEY, NOT PER CERTIFICATE, and that is the point of this table.
-- Renewal issues a NEW certificate to the SAME device: the device keeps the
-- private key it generated in its own hardware and asks for a fresh certificate
-- over it. A table keyed on the certificate would therefore grow a second, a
-- third, a fourth "device" every renewal cycle, and the device list would
-- quietly become a certificate list wearing the wrong noun.
--
-- The key is the identity because the key is what an administrator vouched for
-- (CONTEXT.md: "A vouch is made against a KEY FINGERPRINT"). It follows that a
-- device presenting a NEW key is a NEW device and has to be vouched for again.
-- That is not a limitation to work around; it is the same rule read backwards.
CREATE TABLE IF NOT EXISTS kith_device (
    -- The full SHA-256 of the SubjectPublicKeyInfo DER, lowercase hex. The FULL
    -- digest, not the 16-character form on the screens: that one is truncated
    -- on purpose so a human can compare it by eye, and 64 bits is a fine thing
    -- to read aloud and a poor thing to key a table on.
    key_id      text PRIMARY KEY,
    -- The same digest in the grouped form the console and the device show, so
    -- an operator searching for what they read off a phone finds the row.
    fingerprint text NOT NULL,
    -- From the VOUCH, never from the CSR. See ca.py: nothing in a CSR is
    -- trusted except the public key.
    name        text NOT NULL,
    first_seen  timestamptz NOT NULL,
    last_seen   timestamptz NOT NULL
);

-- Every certificate muster has ever signed for a device, renewals included.
-- This is the history the device row deliberately does not carry.
CREATE TABLE IF NOT EXISTS kith_certificate (
    -- TEXT, not bigint. x509.random_serial_number() returns up to 159 bits and
    -- bigint holds 63, so the wrong type here is not a rare overflow, it is
    -- every row. Uppercase hex, which is what `openssl x509 -serial` prints and
    -- what docs/state-of-play.md quotes off a handset.
    serial          text PRIMARY KEY,
    key_id          text NOT NULL REFERENCES kith_device (key_id) ON DELETE CASCADE,
    -- Which enrollment request this was issued against, so a device that was
    -- vouched for and then lost its pod before collecting can still collect.
    request_id      text NOT NULL,
    not_before      timestamptz NOT NULL,
    not_after       timestamptz NOT NULL,
    issued_at       timestamptz NOT NULL,
    -- NULL until the device has picked it up. Not a secret in either state: a
    -- certificate is public, and the private key it belongs to never left the
    -- device that generated it.
    collected_at    timestamptz,
    certificate_pem text NOT NULL
);

CREATE INDEX IF NOT EXISTS kith_certificate_key_id_idx
    ON kith_certificate (key_id);

-- Collection looks a certificate up by request id, on the path a freshly wiped
-- phone is polling. Without this it is a sequential scan.
CREATE INDEX IF NOT EXISTS kith_certificate_request_id_idx
    ON kith_certificate (request_id);

-- What a device is FOR, chosen when its pairing code was minted (muster#70).
--
-- Policy is looked up device, then role, then kith, so this column is what lets
-- one edit reach every zippie android and no other handset. Empty is the
-- ordinary case and means "the kith's policy and nothing else".
--
-- ADDED RATHER THAN DECLARED ABOVE because rows already exist in this table on
-- a live muster, and a CREATE TABLE IF NOT EXISTS does not revisit them. See
-- the header for why this particular ALTER is safe to run from the server.
--
-- DEFAULT '' AND NOT NULL, so nothing downstream has to distinguish "no role"
-- from "role unknown". Those would be the same thing here and having two
-- spellings of it is how a `WHERE role = ''` quietly misses half the fleet.
ALTER TABLE kith_device
    ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT '';

-- WHEN AN ADMINISTRATOR SAID THIS DEVICE IS NO LONGER OURS. NULL is the
-- ordinary case and means "still ours".
--
-- THIS ROW IS WHAT MUSTER CHECKS; THE CRL IS DERIVED FROM IT. Until muster#23
-- this comment said "this is not a CRL, deliberately", because muster was the
-- only issuer and the only verifier and every device request already goes
-- through `_proven_device`, which is one function with this table behind it.
-- That half is still true and is why muster's own routes never read the CRL.
-- What changed is that a third party may now ask: `revocation.py` builds a CRL
-- and OCSP answers FROM this column, joined through the certificate serial, so
-- there is still exactly one place revocation is recorded and the artifacts
-- can never disagree with it by more than their freshness window (D28).
--
-- NULLABLE RATHER THAN NOT NULL DEFAULT, unlike `role` above. A timestamp has
-- no honest zero value: `'epoch'` would mean "revoked in 1970" to every query
-- that did not know better, and the whole point of a nullable column is that
-- "never" and "at some time" are different shapes. It also keeps the ALTER
-- trivially safe - a nullable column with no default touches no existing row.
--
-- WHAT REVOKING DOES NOT DO, so nobody discovers it during an incident: it
-- stops muster answering this device. It cannot reach into a device that has
-- already cached a credential. A stolen router keeps the datapath key it holds
-- until the FAR END rotates, which is why revocation is only half of the
-- action and `docs/` pairs it with a rotation.
ALTER TABLE kith_device
    ADD COLUMN IF NOT EXISTS revoked_at timestamptz;

-- WHEN AN ADMINISTRATOR ASKED FOR THIS DEVICE TO BE ERASED. NULL means no
-- wipe is waiting.
--
-- THIS IS THE STATE THAT MUST COME BEFORE `revoked_at` (muster#15).
-- `_proven_device` refuses a revoked key before serving anything, so a wipe
-- that was recorded as a revocation would remove the only channel the wipe
-- instruction could travel down. Wipe-pending therefore clears `revoked_at`
-- when it is set; only the device's own acknowledgement moves it back to
-- `revoked_at`.
--
-- NULLABLE for the same reason `revoked_at` is: a timestamp has no honest
-- zero value, and "never asked" and "asked at this time" must be different
-- shapes.
ALTER TABLE kith_device
    ADD COLUMN IF NOT EXISTS wipe_pending_at timestamptz;

-- The roll is read most often to answer "what is still ours". Without this it
-- is a sequential scan over every device that has ever enrolled, including the
-- revoked ones the query exists to exclude.
CREATE INDEX IF NOT EXISTS kith_device_revoked_at_idx
    ON kith_device (revoked_at);

-- A console listing devices during a wipe request needs this for the same
-- reason: without it, "what is still waiting to erase itself" is a sequential
-- scan behind the same question for revocation.
CREATE INDEX IF NOT EXISTS kith_device_wipe_pending_at_idx
    ON kith_device (wipe_pending_at);
