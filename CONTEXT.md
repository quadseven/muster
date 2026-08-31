# muster - the words we use

Written 2026-08-18, at the start. Read this before the code: the same five nouns
appear in the server, the agents and the console, and they mean exactly one
thing each.

Amended 2026-08-19, when a provisioning QR started carrying a pairing code so
that nobody has to touch a wiped handset. That changes what a **vouch** can
prove, and the words below say how rather than leaving the code and this file
disagreeing.

To **muster** is to assemble a company and take the roll. That is the whole
product: know which devices are yours, prove it cryptographically, and act on
them from one place.

## The nouns

**device** - one physical endpoint. A phone, a router, a laptop, a thermostat.
It holds a private key it generated itself and never sent anywhere.

**kith** - the set of devices muster recognizes. A device is in the kith or it is
not; there is no partial membership. Named separately from "the database"
because the kith is the answer to a question ("is this yours?"), not a table.

**pairing code** - short-lived, single use. Proof that a human intends THIS
enrollment to happen. It comes in two SHAPES, and which one it is depends
entirely on whether a person has to read it:

    typed     six digits, because somebody reads it off the console and types
              it on a phone. NOT a secret in the cryptographic sense: 10^6 is
              guessable, and the code is not what makes this enrollment safe.
    scanned   192 bits of url-safe text, because nobody reads it at all - it
              rides in a provisioning QR and the device lifts it out of the
              admin extras bundle. Six digits was a usability number; with the
              typing gone, nothing constrains the length, and this one is not
              guessable.

**vouch** - the administrator's act of authorizing one enrollment. This is what
makes enrollment safe. **WHEN it happens depends on the shape of the code.**

On a TYPED code the vouch is a separate step, made against a KEY FINGERPRINT
shown on both the console and the device - so vouching for a stranger who
guessed the six digits means approving a fingerprint you are not looking at.

On a SCANNED code **the mint IS the vouch**. An authenticated administrator
asking muster for a provisioning QR is asking for exactly one device to be
enrolled, and that request is the authorization. There is no second step,
because there was never any second information: see below.

**A SCANNED REQUEST HAS NO SECOND SCREEN, WHICH IS WHY THE VOUCH MOVED.** The
whole point of the QR is that nobody touches the handset, so nobody is reading a
fingerprint off it - and an administrator comparing the fingerprint on the
console against the console has compared nothing. That step was a ritual, not a
check, and it cost the thing the QR exists for: a wiped phone came up owned and
then sat waiting for a human to go and approve it.

What holds a scanned request up is the shape of its code: a stranger cannot
guess 192 bits, so the stranger the comparison exists to catch cannot reach the
queue at all. So the authorization happens where the administrator actually
decides something - at mint - and the code carries it to issuance.

**Each request says which shape it is, and the console asks the matching
question.** A typed row is asked "does this match the device?"; a scanned one is
asked "is this the device you scanned?" and told there is no second copy to
compare against. Asking the first question about a scanned request would be worse
than asking nothing - it teaches a check that cannot be made, and an operator who
learns that the words above the button mean nothing stops reading them on the
path where they do.

**What that does not cover, stated plainly:** somebody who photographs the QR off
that monitor inside the code's few minutes can provision a device of their own
against it, and it will look exactly like the real one. That is why the QR
endpoint is administrator-only, why the code is spent by the first device to use
it, and why the window was not widened to make provisioning more comfortable.

**The vouch is still required on both paths - it just happens at different
times.** This paragraph used to say the trade "belongs to whoever runs the estate
and has not been made". It has been made, deliberately, and only for the scanned
shape. What did NOT change is that a pairing code is never the whole security: a
scanned code is minted only by an authenticated administrator, is spent by the
first device to use it, and dies in minutes. A typed code, which is guessable by
design, keeps its separate vouch and its fingerprint comparison.

**role** - what a device is FOR, chosen when its QR is minted. It selects a
policy scope between the device and the kith, so one edit reaches every zippie
android and no other handset. Optional: most devices have none and get the
kith's policy. A device never names its own role - it is read from the kith,
because a role can carry credentials.

**identity** - the client certificate a vouched device receives. Short-lived and
self-renewing. A device's identity IS its membership: there is no separate
enable/disable flag, because a flag can be out of step with what the device can
actually do and a certificate cannot.

## The verbs, in order

    mint      an administrator generates a pairing code
    scan      a wiped device reads a provisioning QR and comes up carrying one
    present   a device sends its CSR and the code, and waits
    vouch     an administrator authorizes ONE enrollment - at mint on the
              scanned path, and as a separate fingerprint check on the typed one
    issue     muster signs, and the device has an identity
    renew     the device replaces its certificate before it expires, over the
              identity it already holds and with nobody present
    lapse     an identity expires and is not renewed
    revoke    an administrator says a device is no longer ours, and muster
              stops answering it from that moment

**Scan replaces the typing AND the second click.** A device that scanned arrives
already knowing where to enroll and with what, presents itself, and is issued an
identity in the same breath - so an administrator makes a QR and the handset is
a member of the kith by the time its setup finishes, with nothing else to do. A
device that did not scan - one provisioned earlier, or re-enrolling after a
lapse - is typed at and vouched for separately, and that path is unchanged and
still needed.

**Lapse and revoke are different acts, and until muster#11 there was only one
of them.** Lapse is passive: an identity expires, nobody renews it, and the
device falls out of the kith by itself. Revoke is an administrator saying so, at
a moment they choose.

Lapse was the whole mechanism for as long as renewal needed a human. Declining
to renew WAS declining to trust, so the two were the same act and the vocabulary
above said so in as many words. Automatic renewal (muster#10) breaks that
identity: a device that renews itself never lapses, so a design with only lapse
in it would be a fleet that can never be cut off. Revocation had to exist first,
and does.

**A device renews with the key it already holds, and that is the whole
authorization.** A pairing code answers "should this stranger get a
certificate". A device signing a nonce with a key muster has already vouched for
is not a stranger - so demanding it enroll again is asking for a weaker proof
than the one it is holding. `POST /v1/device/renew`.

**Renewing is not rotating.** The CSR must carry the SAME public key; a new key
is a new `key_id`, and `key_id` is what every policy scope, role and kith row is
filed under. That is the rule above read forwards: a device presenting a new key
is a new device and has to be vouched for again.

**Neither reaches a device that is switched off.** That is not a flaw in either
one - nothing sent to a handset in a drawer arrives - and it is why muster
enforces at the point a device ASKS rather than by pushing anything at it.
Revoke takes effect on the revoked device's next request and not before, and the
credentials it already holds are still in its hands. Cutting those off is a
rotation at the other end, which is a second act and a deliberate one.

**Still no CRL, and that is a decision.** A revocation list exists so a third
party can check without asking the issuer. muster has no third party: it is the
only issuer and the only verifier, and the check is one row in the kith.

## Two rules that shape everything

**The private key never moves.** Devices generate their own and send a CSR. A
control plane holding every device's private key is one breach away from being
every device.

**Enrollment may need the internet; operation must not.** A device enrolls at
home and then works anywhere, including where muster is unreachable. Any design
that makes a device useless when the control plane is down has failed at the
thing this estate actually needs.
