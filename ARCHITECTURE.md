# Architecture

muster is a device enrollment and identity plane. A device generates a private
key it never sends anywhere, presents a certificate signing request with a
short-lived pairing code, an administrator vouches for exactly one enrollment,
and muster issues a short-lived client certificate. That certificate **is** the
device's identity and its membership. It renews itself, and revocation is simply
not renewing it.

On top of that identity, muster pushes and pulls configuration: what a device is
restricted from doing, which applications it shows, how those applications are
configured, what it installs, and what it displays.

This document explains what the system is, why the problem is hard, what the
pieces are, and how a device gets from a factory reset to a managed, configured
endpoint. It assumes you know what a CA is and roughly how a mobile device
management plane behaves. It does not assume you have read any source.

Read [CONTEXT.md](CONTEXT.md) first for the vocabulary - `device`, `kith`,
`pairing code`, `vouch`, `role`, `identity` - which the server, the agents and
the console all use to mean exactly one thing each.
[DECISIONS.md](DECISIONS.md) records why the system has this shape, incident by
incident.

---

## 1. The problem

The ask is modest: push and pull configuration to a device I own, from one
place. Every product tried first said no to it.

- **A mainstream commercial management product** applies policy on its free
  tier but will not install an application. That is a paid tier, and installing
  an application is the one thing actually needed.
- **An open-source alternative** works and is free, but owns the launcher and
  brings a whole management model that was not wanted.
- **The platform vendor's own management API** will not have us at all. Its
  permissible-usage policy restricts it to commercial enterprise-mobility
  developers, device-trust providers and device manufacturers, and explicitly
  prohibits "solutions developed and used exclusively for first party in-house
  applications". Device quota is zero, and the handset's own error at zero
  devices enrolled is "your organization has reached its usage limits".

So the choice was to build the identity plane rather than rent one. The
constraints that follow are not preferences. They come from what the platform
actually permits, measured on handsets rather than inferred from documentation -
see [docs/android-constraints.md](docs/android-constraints.md), which carries a
dated open/closed status for every route with a primary source for each closed
verdict.

## 2. Why this is hard

**Device ownership can only be established on an unprovisioned device.** Once
anyone finishes setup once, the device is provisioned and cannot be enrolled as
fully managed. There is no conversion path; the fix is a factory reset. That
restriction exists so malware cannot seize a device already in use, and it means
every mistake in this area costs a wipe.

**The management app can be deleted by the platform's own app store.** On a
fully managed device, managed distribution reconciles the installed set against
the enterprise policy and removes what is not in it - measured, with every
relevant security override applied. So sideloading is not a fallback; publishing
is the only route on that path.

**Provisioning failures factory-reset the handset.** If the agent does not
answer the intents the platform sends during provisioning, provisioning fails,
and the documented response to a failed provisioning is a reset. A wrong answer
here does not throw an exception - it wipes a phone.

**Devices are offline for days, and that is normal.** A router in a hotel, a
phone in a drawer. Any revocation mechanism that has to *reach* the device does
not work. Any design that makes a device useless when the control plane is down
has failed at the thing this actually needs.

**Devices boot without a person.** The relevant storage does not exist before
first unlock, a freshly installed application receives no broadcasts at all
until something explicit reaches it, and clocks can be wrong by hours or by
decades on hardware without a real-time clock.

**Nothing here can be recovered by asking a user to tap something.** These are
appliances in cupboards and cars.

## 3. The trust model

Two rules shape everything.

**The private key never moves.** Devices generate their own inside hardware-
backed storage and send only a certificate signing request. A control plane
holding every device's private key is one breach away from *being* every device.
On the agent this is not a policy but a property: the key is generated inside
the keystore and there is no API that returns its bytes - what comes back is a
handle that signs on its behalf.

**Enrollment may need the internet; operation must not.** A device enrolls
somewhere convenient and then works anywhere, including where muster is
unreachable.

### The exchange

```
  administrator                 muster                        device
       |                          |                             |
       |--- mint pairing code --->|                             |
       |<-- code (+ QR) ----------|                             |
       |                                                        |
       |============ code reaches the device ===================|
       |     typed by a person, or carried in a provisioning QR |
       |                                                        |
       |                          |<--- present: CSR + code ----|
       |                          |                             |
       |     [TYPED path]         |                             |
       |<-- pending request, with the key fingerprint           |
       |--- vouch(request, fingerprint) ->|                     |
       |                          |                             |
       |     [SCANNED path]       |                             |
       |     the mint WAS the vouch; muster issues at present   |
       |                          |                             |
       |                          |--- issue: certificate ----->|
       |                          |                             |
       |                          |<--- renew, before expiry ---|
       |                          |                             |
       |                        lapse: the device is not renewed,
       |                        its certificate expires, and it
       |                        falls out of the kith
```

### The pairing code is not the security

Six digits is a million possibilities. Against a public endpoint that is
guessable in seconds, and no amount of rate limiting makes a six-digit code a
credential. It is not trying to be one. It proves that a human **intended** an
enrollment to happen around now, and nothing more.

The security is the vouch, **and only if the vouch is made against the key**.
The administrator sees the fingerprint of the public key in the request; the
device displays the same fingerprint. Approving means "yes, that is the
fingerprint on the screen in my hand". A racer who guesses the code lands in the
pending queue with a fingerprint the administrator is not looking at, and gets
declined. Vouching by request id alone would confirm only "yes, I did start an
enrollment", which is exactly what the racer already assumed - so the vouch call
takes a fingerprint and refuses to work without one.

### Two shapes of code, because one has no second screen

Every sentence above rests on a person looking at the device's screen.
Provisioning a wiped handset from a QR on a monitor removes that person, and
with them the second copy of the fingerprint. The comparison that catches the
racer is simply not available.

The answer is not to trust the code more. It is to make the racer impossible.

| shape     | code                     | who reads it | vouch                        |
|-----------|--------------------------|--------------|------------------------------|
| `TYPED`   | six digits               | a person     | a separate fingerprint check |
| `SCANNED` | 192 bits of URL-safe text| nobody       | the mint **is** the vouch    |

Six digits is a **usability** number: it is short because somebody has to read
it off a console and type it on a phone. Take the typing away and nothing
constrains the length.

On the scanned path the vouch moves rather than disappears. An authenticated
administrator asking for a provisioning QR is asking for exactly one device to
be enrolled, and that request **is** the authorization. The second click added
no information - on a scanned request the administrator reads the fingerprint
off the same console page they are clicking, comparing a value against itself.

Each pending request carries its shape, and the console asks the matching
question. A typed row is asked "does this match the device?". A scanned one is
asked "is this the device you scanned?", and told plainly that there is no
second copy to compare against. Asking the first question about a scanned
request would be worse than asking nothing: it teaches a check that cannot be
made, and an operator who learns the words above the button mean nothing stops
reading them on the path where they do.

What that does not cover is stated rather than implied: somebody who photographs
the QR off a monitor within the code's few-minute life can provision a device of
their own against it. That is why the QR endpoint is administrator-only, why the
code is spent by the first device to use it, and why the window was not widened
to make provisioning more comfortable.

### The certificate authority

Nothing in a signing request is trusted except the public key. A request is a
self-signed blob written by whoever is enrolling, so its subject, its subject
alternative names and its extensions are attacker-controlled input. Signing one
as submitted is how a device enrolls itself as an administrator and then
authenticates as one.

So issuance reads the public key out and **builds the subject itself**, from the
name the administrator vouched for. Everything else is discarded by construction
rather than by a list of fields somebody has to remember to strip. It refuses a
request whose self-signature does not verify (the sender does not hold the key
they want certified, which is the entire claim), anything on the wrong curve,
and garbage. Certificates are client-auth only and cannot sign other
certificates - without that constraint, a certificate issued to a phone is
equally usable to impersonate the server to another device.

Three numbers, each with a reason:

- **90 days.** Long enough that renewal is not constant chatter, short enough
  that "stop renewing" is a revocation an operator can live with.
- **Renew at a third of life.** Not half, and not at the last minute: a router
  that is off for a fortnight has to wake up still inside the window. Coming
  back with a dead identity means enrolling again from a fresh pairing code with
  a human holding the handset, which on an owned device means a factory reset.
- **Backdate twelve hours.** Hardware without a real-time clock can boot
  believing it is decades ago. A not-yet-valid certificate is indistinguishable
  from a broken one on a device that cannot fix its clock without the network
  the certificate is for.

The authority never creates a CA as a side effect of failing to find one. One
that mints itself a key silently invalidates every device it has issued to, at
the moment somebody mounts the wrong volume.

### Lapse is the revocation mechanism

There is no revocation list and no push. A device that must not be trusted is
simply not renewed, and it falls out of the kith when its certificate expires.
A revocation list has to *reach* the verifier; this is the only revocation that
reaches a device switched off in a drawer or sitting in a hotel with no
internet.

That is also why a device's membership **is** its certificate and there is no
separate enabled flag. A flag can disagree with what a device can actually do.
A certificate cannot.

## 4. Proving possession afterward

Client certificate authentication is the obvious way for a device to prove
itself on later requests, and it was not available. Two independent walls: the
edge in front of this service only accepts a custom CA for client-certificate
validation on its most expensive tier, and even there it would not help, because
the tunnel to the origin opens a **new** connection - a certificate presented at
the edge never reaches the application, which would then be trusting headers a
proxy wrote. That is a different trust model wearing mutual TLS's clothes.

So possession is proven at the application layer:

```
  device                              muster
    |--- GET  /v1/auth/challenge ------>|   (unauthenticated by necessity:
    |<-- nonce -------------------------|    the thing being authenticated
    |                                   |    is the ANSWER)
    |--- POST nonce, signature, cert -->|
    |                                   |   verify the signature against the
    |                                   |   certificate MUSTER ISSUED
    |<-- ok / a specific refusal -------|
```

The proof survives the edge, the tunnel and anything else in the path, because
it never depended on the transport.

Three properties make it a proof rather than a ritual, and each has a test:

1. **The nonce is server-issued.** A client-chosen challenge is not a
   challenge - an attacker replays one they already hold a signature for.
2. **It is single use, consumed on failure too.** A nonce that survives a
   failed attempt is one an attacker can grind against.
3. **It expires.** Bounded replay window if a signature is ever observed.

Two refusals matter most. A self-signed certificate is rejected, because signing
correctly proves possession of *a* key, not that muster vouched for it. And a
certificate that merely *claims* our issuer name is rejected, because an issuer
name is a string an attacker puts in their own certificate and only the
signature says otherwise. A lapsed certificate is refused at the point of use,
because not renewing **is** the revocation mechanism and a mechanism enforced
nowhere is not one.

Every device-facing route that needs an identity goes through this one function.
A second authentication scheme for the second thing a device asks for is a
second chance to get it wrong.

## 5. The kith, and why its store is allowed to fail

CONTEXT.md calls the kith "the set of devices muster recognizes - the answer to
a question, not a table". The store module is deliberately **not** that answer:

```
  the certificate     decides whether a device is in the kith
  the store           remembers what muster did about it
```

Nothing in the store is ever consulted to decide whether to sign. That is the
whole availability design, and the reasoning is asymmetric:

| failure                        | consequence                                    |
|--------------------------------|------------------------------------------------|
| store down, issuance continues | a device list missing rows, filled in later    |
| store down, issuance stops     | a fleet that lapses, one factory reset each    |

Lapse is close to irreversible: a lapsed device cannot renew its way back, it
has to enroll again from a fresh pairing code with a human holding the handset.
Trading the second failure for the first is not a close call.

Revocation is the deliberate version of the same outcome and IS reversible -
`POST /v1/kith/{key_id}/revoke` with `revoked: false` readmits, because an
administrator can revoke the wrong key_id and the alternative to a way back is
wiping a device.

So:

- **Every write is deferred, never refused.** What happened is appended to a
  bounded backlog and then drained. In the healthy case the drain succeeds on
  the same call; in an outage it accumulates and replays. One code path, not a
  happy one and a fallback one - a fallback that only runs during an outage is a
  path that is broken during every outage.
- **Reads raise rather than returning empty.** An empty list is a lie that reads
  as "you have no devices" on a console. The API turns it into a 503, which says
  the same thing honestly.
- **Deferred must not mean forever.** The backlog is ordered and replayed from
  the head, so a row the store will *never* accept is a wedge rather than a
  delay - every write behind it waits, and a failed drain opens the breaker, so
  reads start reporting an outage while the database is perfectly healthy. The
  store is therefore asked to classify its own failures, and a row that was
  *refused* is dropped loudly, while anything that did not reach a server at all
  is always retried.
- **Nothing may hang.** Queries have timeouts, connections have keepalives, a
  failed store is left alone for a cooldown, and the readiness status takes no
  lock and does no I/O - so a slow database can never make the orchestrator pull
  the pod out of service and stop issuance *through the health check*.

A device is its **key**, not its certificate, so renewal writes a second
certificate against the same device rather than inventing a second phone every
ninety days.

## 6. Policy: what a device is told to be

The files a device fetches are the exact byte content its stewards already read
out of local storage. Building a second apply path would mean two vocabularies,
two sets of refusals, and one of them untested on a handset.

```
  <root>/kith.restrictions          every device in the kith
  <root>/kith.visible-apps
  <root>/kith.wallpaper
  <root>/role-<name>.restrictions   every device carrying this role
  <root>/role-<name>.app-config
  <root>/<key_id>.restrictions      this device only
  <root>/<key_id>.app-config
```

**Three scopes, resolved most-specific-first, per file.** Per file rather than
per device, because a role says what is *different* about a set of devices, and
making it restate the whole fleet's policy is how the two drift - silently,
because both files look maintained.

**A role is chosen when a device's QR is minted**, because that is the only
moment anything knows what a device will be, and at that moment the device has
no identity to key anything on. The role rides the pairing code and the
certificate writes it into the kith. **A device never names its own role** - it
is read from the kith on every fetch, because a device that could name one could
ask for another role's credentials. A role can also be changed later without
wiping the device, since policy is resolved on every check-in.

**The kith-wide application configuration file is never read, on purpose.** That
is the file that carries credentials - write tokens for other applications - and
a credential under the shared scope is a credential handed to every device in
the estate. Refusing to serve it is loud; serving it widely is silent, and
silent is how a token ends up on a phone in a drawer that somebody later sells.
A **role** may carry one, and that is the point of roles: the credential is
shared by every device carrying the role, which is exactly what a role asserts.

**Anything that is not text travels its own route.** A megabyte of base64 inside
a response that already carries a device's write tokens would be a decision made
by accident. So a `wallpaper` policy file *names* an asset and the digest to
expect, and the bytes come from a separate asset route the device also
authenticates to. The closed vocabulary stays the only thing deciding what a
device acts on, and a substituted image is caught against a file the device
fetched over its own identity rather than trusted because it arrived.

## 7. The agent

One Android application whose first job is to hold device ownership. Everything
that decides anything is a pure function with a JVM test; everything that
touches the platform is a thin steward that does the call and then **asks the
device what actually happened**.

```
  BootPlan.STEPS, run at boot, on a timer, and from the status screen:

    1. fetch configuration    over the device's own identity
    2. wallpaper              named in policy, fetched by digest
    3. restrictions           reconciled both ways
    4. install applications   everything except muster itself
    5. app configuration      values, permission grants, and a wake
    6. application visibility hide what an appliance has no business showing
    7. install muster         last, because committing it ends the process
```

Four properties of that list are load-bearing.

**Ordering is a decision, not an arrangement.** Committing muster's own install
ends the process, so it must be last, and anything queued behind it would never
run - a boot that updated the agent would silently skip every step after it.
Installing *other* applications has to come **before** configuring and revealing
them, or the package does not exist when the grant is attempted. That was
observed on a handset: the application sat installed, unconfigured and hidden
until the next pass, with the launcher icon missing for the same reason. So the
install work is split by scope rather than moved wholesale, and a test asserts
that the two passes together install exactly what one pass would have.

**Every steward reads back.** Adding a user restriction does not reject a key
the platform does not know; setting a secure setting prints nothing on success
and nothing when it silently fails to stick. So the effective set is read back
after being written, and what is reported is what the device says, not what was
asked for.

**Reconciling goes both ways.** A name deleted from the configuration comes off
the device. Policy that only ever adds is a ratchet whose only reverse gear is a
wipe. What to *add* is decided from what is actually in force, so every boot
re-asserts rather than remembering having asserted; what to *clear* is decided
from what muster itself set, so another administrator's restriction is never
withdrawn.

**Every step has to be able to say what went wrong.** The step list is typed to
return an outcome that can enumerate the things a person has to go and look at.
A convention that lives in a formatting method cannot be queried, and reading
severity back out of a rendered line rots the first time a key is renamed. Two
outcomes that read as the quietest possible success are deliberately classed as
concerns, because a device that runs every step and enforces none of them is
indistinguishable from one nobody configured.

### Waking a stopped application

A freshly installed application that has never been launched sits in a stopped
state and receives **no** broadcasts at all, including boot. Its own boot
receiver never fires. So muster installs an application, configures it
correctly, and it never starts - with nothing in any log to say why.

The only mechanism that reaches it is an explicit intent carrying the
include-stopped-packages flag, which also clears the stopped state so every
later broadcast arrives normally. There is no management API for this.

The component to wake is **named in policy** rather than guessed, because it is
a contract with another application's manifest, and a convention muster invented
would break silently the first time that application moved a class.

A wake is sent only when this pass changed something for that package - a wake
every fifteen minutes forever is battery spent telling an application what it
already knows. That gate needed a durable ledger to be correct, and the ledger
needed more care than it looks (see DECISIONS.md D18).

## 8. Assets and installs

The asset store started as a mounted secret and moved to a network share, and
the route in front of it did not change - a name, a digest the device verifies,
and a no-store header. That was the point of putting the contract in the route
rather than in the storage.

Three properties the share forced:

- **Unavailability blocks rather than erroring.** A measured 90-second
  host-level drop hung a plain directory listing for 106 seconds and then
  returned success. muster is a control plane, so an unbounded touch is a
  request thread it never gets back, and enough of those stop enrollment and
  renewal - at which point devices lapse. A wallpaper nobody can read must
  degrade to "no wallpaper", never to "no certificates". Every touch is bounded
  and abandoned after the bound, with a small fixed pool so abandoned threads
  cannot accumulate one per request.
- **A health check on that storage must touch that storage.** A wedged share
  keeps the listener accepting while nothing behind it can read.
- **muster's own mount is read-only.** It holds a certificate authority, and a
  process that can rewrite what it serves to devices is a process that can serve
  a device something else.

Installing is what makes hiding the app store defensible: hide it and you have
taken responsibility for updates you must then be able to perform. A device
owner's install session commits without anybody tapping anything, which is the
whole point on an appliance.

**What makes it safe is the digest.** The bytes are checked against a digest
named in a policy file the device fetched over its own identity - not against
anything the server said while handing them over. An agent that installs
whatever it is given is a remote code execution primitive carrying a
certificate. A line without a digest is refused rather than warned about.

**A version number makes it idempotent** without hashing what is already there,
and a device carrying a *newer* version is left alone: the platform refuses a
downgrade, so attempting one is a guaranteed failure reported at every boot -
and a newer version is also what a hand-installed build looks like.

**One refused line does not withhold the others**, deliberately the opposite of
application visibility. Installing is additive; withholding every install
because one line is wrong denies a device software in order to protect it from
having software.

## 9. The console and who is allowed to use it

One HTML page, no build step, no dependencies. A build step here would put a
package manager on the path of the process that signs certificates, and a
framework would reach a supply chain to the same box - for a page with a list
and two buttons.

**The design constraint is that vouching must not be one click.** The security
model is a comparison between two screens; a single approve button turns it into
a comparison between a human and their own impatience. Approving opens a dialog
that shows the fingerprint alone, names what happens if it does not match, and
only then vouches - sending the fingerprint, never just the id.

Administrators sign in at an external identity provider using the standard
authorization-code flow with PKCE; muster verifies a signed token and never sees
a password. Authorization keys on the **immutable subject claim**, never on
email - a subject is stable, an email address can be changed by whoever holds
the account, and an allowlist keyed on one is an allowlist that can be joined.
The provider is configured entirely by standard URLs, so this repository names
no vendor.

Two middleware run, and **their order is load-bearing**: who is acting is
established before anything writes down what they did. Swapped, nothing errors -
every record just says anonymous, which is a log that looks healthy and answers
no question anybody will ever ask it. The order is asserted at composition time,
so a reorder crash-loops at startup instead of shipping a worthless audit trail.

Neither middleware ever refuses a request. Authorization is a dependency on each
administrator route, because that is the only thing that can express this
service's shape: posting an enrollment request is a *device's* way in, and
listing pending requests is the administrator's. **The route table is a test** -
every route is deliberately on one side of the line, and no open route may ever
answer 401.

The page carries a content security policy permitting one nonced style block,
one nonced script and images from this origin, which is what makes "no
third-party script on the console" a control rather than a promise. The
framework's own interactive API documentation is off for the same reason: it
loads JavaScript from a public CDN, on the same origin as the console, where it
would run with the administrator's session.

## 10. Observability

The rule everything follows: **nothing secret is emitted, and telemetry never
takes the service down.**

A fixed set of field names is dropped in **one** place rather than at each of a
dozen call sites, because the site that gets forgotten is always the failure path
nobody exercises. A pairing code is never truncated into a tag either - a prefix
narrows a million to something a script walks while the code is still alive.
Fingerprints *are* emitted; they exist to be read aloud off two screens.

Every send is wrapped, and the transport is UDP. A control plane that stops
issuing certificates because a metrics socket went away has traded a working
estate for a graph. The emitter is a few lines of standard library rather than a
vendor package, because a dependency added to the process that signs
certificates is a dependency in the blast radius of the CA.

**The refusal reason is the point.** "Devices are failing to enroll" is not
answerable without it: an expired code is an operator who was slow,
too-many-attempts is somebody guessing, and a fingerprint mismatch is somebody
enrolling against your code *while you watch*. A single total hides the one that
matters. The reasons are closed sets, so the tags cannot explode cardinality.

Real-user monitoring is deliberately **not** added, with the reason written
down: the console is where an administrator's session lives, and that would put
a third-party script on that page.

## 11. What ships

```
  server/muster/enroll.py         the trust decision: mint, present, vouch, issue
  server/muster/ca.py             turning a vouched request into an identity
  server/muster/proof.py          proving possession after enrollment
  server/muster/kith.py           what muster remembers, and why the store may fail
  server/muster/policy.py         what one device is told to be, and from where
  server/muster/assets.py         bytes too big for a policy file
  server/muster/administrator.py  who the human is, and how they sign in
  server/muster/console.py        sessions, and what gets recorded
  server/muster/api.py            the HTTP surface and its two audiences
  server/muster/provisioning.py   the payload a wiped handset scans
  server/muster/cli.py            the operator's side of a cable
  agent/android/                  the device agent: policies, stewards, boot plan
  agent/tools/jvm-tests.sh        typecheck and run the pure sources with no SDK
  docs/                           constraints, runbooks, and what is deployed
```

The server is a container image with its dependencies resolved from a committed
lock file, not installed at start - a container that fetches packages when it
boots is one that fails to come up when the index is unreachable, on the service
every device phones home to. The base image is pinned by digest.

**The agent is baked into the server image rather than mounted beside it.** One
route serves the bytes and another advertises the digest of the certificate
those bytes are signed with, and the two **must** describe the same file. A
mounted file can drift from the image that advertises it, and the platform
reports that mismatch only as "can't set up device" - discovered on a phone that
has already been wiped. Shipping them as one artifact makes the skew impossible
instead of unlikely, and two build gates enforce it: the image build fails when
no agent was downloaded, and a step reads the signing certificate out of the
agent *inside the built image*.

## 12. What this deliberately does not do

- **Report whether a device is online.** muster has no such concept, and adding
  one would be an accident of dashboard design. Lapse is the revocation
  mechanism precisely *because* devices are expected to be unreachable for days,
  so a red "offline" count would report the normal state of a working estate as
  a fault.
- **Manage anything but Android, today.** The identity plane is
  platform-neutral by construction - a key, a request, a certificate - and the
  agent is where the platform lives.
- **Hold a device's private key, ever.** See section 3.
- **Run more than one replica.** The kith is shared state, but the short-lived
  half of the ceremony - pairing codes, pending requests, and the certificate
  held between a vouch and the device collecting it - is still in memory. Shared
  state first, then the number, as two decisions rather than discovering both at
  once.
