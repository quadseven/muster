# Decisions

The decisions that shaped this system, with the failures that caused them.

muster manages devices that cost a factory reset when you get it wrong, so most
of what follows was learned on handsets rather than designed on paper. Each
entry records the context, what else was on the table, what was chosen, and -
where there was one - the incident that forced it.

**How to read the evidence.** Every entry cites a file in this repository. The
comments in those files carry the reasoning next to the thing being justified,
so it survives the session that produced it. Dates are the date the decision
landed. Where a statement is inference rather than a record, it says so.

A note on history: this repository was recreated from a clean snapshot, so the
commit log here starts later than the dates below. The dates and measurements
come from the development record that preceded it; the code and comments they
describe are the code and comments in this tree.

---

## Contents

- [Why this exists at all](#why-this-exists-at-all) - D1
- [The trust decision](#the-trust-decision) - D2 to D7
- [Staying up](#staying-up) - D8 to D10
- [Getting onto a handset](#getting-onto-a-handset) - D11 to D14
- [Telling a device what to be](#telling-a-device-what-to-be) - D15 to D19
- [Not destroying things](#not-destroying-things) - D20 to D22
- [Who is allowed in](#who-is-allowed-in) - D23 to D26

---

## Why this exists at all

### D1. Build the identity plane rather than rent one

**2026-08-18.** Evidence: [README.md](README.md),
[docs/android-constraints.md](docs/android-constraints.md).

**Context.** The requirement was one sentence: push and pull configuration to a
device I own, from one place. Three products were tried before anything was
written.

**What each of them said no to.**

*A mainstream commercial management product* applies policy on the free tier and
will not install an application. Installing an application is a paid tier, and
it is the one thing actually needed.

*An open-source alternative* works and is free, but owns the launcher and brings
a management model that was not wanted.

*The platform vendor's own management API* excludes this use outright. Its
permissible-usage policy restricts it to commercial enterprise-mobility
developers, device-trust providers and device manufacturers, and explicitly
prohibits "solutions developed and used exclusively for first party in-house
applications" - which is precisely a household managing its own phone. Device
quota is zero until a business justification is approved as a commercial
provider. The handset's own error, at **zero devices enrolled**, is "your
organization has reached its usage limits", which is what that eligibility gate
looks like from the phone.

The first product is also a wrapper over the same vendor API, so the same gate
applies underneath it.

**Chosen.** Build it. A domain, a certificate and a handshake change none of
that, because the gates are on eligibility and on an application's standing with
the platform's own protection service - so the enrollment experience has to be
designed around what the platform actually permits.

**What was done about the uncertainty.** A dated document lists every route to
device ownership with an OPEN or CLOSED status and the gate that decides it,
each closed verdict citing a primary source. That file exists because a route
was recorded as closed on reasoning rather than measurement - the QR flow was
marked shut behind a protection-service allowlist, and three documents were
written around a cable-only workflow as a result. The verdict had never been
tested: the first attempt failed *earlier*, on the provisioning intents in D11,
and the gate was never reached. A wiped handset later came through the QR route
with no cable at any point.

That correction is recorded as "open, measured once, one device, one platform
version, one day, past a check that behaves like a heuristic" rather than as
"open". The cable route is kept as the fallback, and it is what makes attempting
the QR route safe.

---

## The trust decision

### D2. The pairing code is not the security; the vouch is, and only against the key

**2026-08-18, foundational.** Evidence: `server/muster/enroll.py` (module
docstring), [CONTEXT.md](CONTEXT.md).

**Context.** A device presents a certificate signing request with a short code.
The obvious reading is that the code authenticates the enrollment.

**Why that reading is wrong.** Six digits is a million possibilities. Against a
public endpoint that is guessable in seconds, and no rate limit makes six digits
a credential. It is not trying to be one: it proves a human **intended** an
enrollment around now, and nothing more.

**Chosen.** The vouch is the security, and it takes the **key fingerprint** the
administrator is reading off the device in their hand. A racer who guesses the
code lands in the pending queue under a fingerprint nobody is looking at, and
gets declined.

Vouching by request id alone would confirm only "yes, an enrollment is pending",
which is exactly what the racer arranged. So the vouch call takes a fingerprint
in its schema and there is no route through the endpoint that approves without
comparing.

**Where this was built, and why that is part of the decision.** The exchange is
a state machine with no HTTP, no storage and no clock of its own, because every
rule in it is about time or about a wrong answer, and both are miserable to
exercise through a web framework. The racer has a test.

---

### D3. On a scanned code, the mint *is* the vouch

**2026-08-21.** Evidence: `server/muster/enroll.py` (`Shape`),
[CONTEXT.md](CONTEXT.md), `server/muster/console.html`.

**What went wrong.** An administrator makes a QR, wipes a phone, scans, and the
phone comes up owned - and then sits waiting for a human to go to a console and
approve it. That is the thing the QR exists to avoid. Worse, the row it left
behind was clickable: approving it a second time minted a **second identity for
one handset**, which is what happened on a real device.

**The reasoning that had been deferred.** The module docstring had said since it
was written that removing the vouch from a scanned request would make the
pairing code the entire security of the system, and that the choice belonged to
whoever runs the estate.

**Chosen, and the argument is not "trust the code more".** A scanned code is
minted by an **authenticated administrator asking for exactly one device to be
enrolled**, and that request is the authorization. The second click added no
information: on a scanned request the administrator reads the fingerprint off
the same console page they are clicking, so they compare a value against itself.
That is not a check, it is a ritual, and asking the same person the same question
twice does not improve the answer.

So the vouch **moves** to where a decision is actually made rather than
disappearing. What stands behind it is unchanged: 192 bits (D4), single use,
minutes long, administrator-only.

**The typed shape is untouched.** Six digits is guessable by design, the human
is standing at the device, and the fingerprint on its screen is a real second
copy. Everything the scanned argument says is false there.

**A self-vouched request is never put in the pending queue,** because nothing
about it is pending. That is what removes the clickable row rather than hiding
it.

**The console had to change with it, and this is the sharpest part.** The
confirm dialog asked every request "read the fingerprint on the device's own
screen" - which on a QR-provisioned device is a check that **cannot be made**,
because nobody is holding the phone. That is worse than asking nothing. The
operator either cancels a device that is theirs, or clicks through and learns
that the words above the button mean nothing, and then stops reading them on the
path where they do. So each request carries its shape, the pending row says
which it is before anything is opened, and the console asks the matching
question.

**The agent needed no change**, which is why this was worth doing at that
moment: it already presents and then polls for its certificate, so issuing at
presentation just means the first poll is the one that succeeds.

**Issuance became one helper called from both paths.** Two copies would have
been two chances to forget the kith write, and the QR path - the one nobody
watches - is the copy that would have forgotten.

---

### D4. Take the typing away and the code stops being six digits

**2026-08-19.** Evidence: `server/muster/enroll.py`,
`server/muster/provisioning.py`.

**Context.** Enrollment needed six digits typed into a handset. Putting the code
in the provisioning QR means a wiped device presents itself with nobody touching
the phone - and removes the second copy of the fingerprint that D2 rests on.

**Chosen.** Six digits was a **usability** number: it is short because somebody
has to read it off a console and type it on a phone. With the typing gone,
nothing constrains the length, so a scanned code is 192 bits of URL-safe text.
The racer the fingerprint comparison exists to catch cannot reach the pending
queue at all.

Four things came with it, each because the code now matters more:

- **No-store on the QR endpoint.** A cached QR is a replayed single-use code.
- **A wrong guess no longer burns a scanned code.** Five bogus six-digit posts
  would otherwise strand a phone that has already been wiped.
- **Refusals gained a shape tag** beside the reason, so a stale QR and an
  operator mistyping stop being one number.
- **A non-ASCII code** reached a constant-time comparison and produced a 500
  from an unauthenticated endpoint. It is a wrong guess like any other now.

**The pairing code is deliberately not drawn beside its own QR.** The console
prints every extras key as text, which would put a readable copy next to the
image that already carries it. The same argument keeps the wifi password out of
that panel.

**What this does not cover, stated rather than implied.** Somebody who
photographs the QR off a monitor within the code's few-minute life can provision
a device of their own against it, and it will look exactly like the real one.
That is why the endpoint is administrator-only, why the code is spent by the
first device to use it, and why the window was not widened to make provisioning
more comfortable.

---

### D5. Nothing in a signing request is trusted except the public key

**2026-08-18, foundational.** Evidence: `server/muster/ca.py` (`issue`).

**Context.** A certificate signing request is a self-signed blob written by
whoever is enrolling. Its subject, its subject alternative names and its
extensions are attacker-controlled input.

**What signing one as submitted buys an attacker.** A device enrolls itself as
an administrator and then authenticates as one.

**Chosen.** Read the public key out and build the subject from the name the
**administrator** vouched for. Everything else in the request is discarded **by
construction** rather than by validation - there is no list of fields to remember
to strip, which is the failure mode of the alternative.

Three refusals sit beside it:

- a request whose self-signature does not verify, because the sender does not
  hold the key they want certified, which is the entire claim;
- anything on the wrong curve, and garbage;
- issuing anything but a client-authentication certificate that cannot sign
  other certificates - without that constraint, a certificate issued to a phone
  is equally usable to impersonate the server to another device.

**And the authority never creates a CA as a side effect of failing to find
one.** One that mints itself a key when it cannot find one silently invalidates
every device it has issued to, at the moment somebody mounts the wrong volume.

**A cross-language check, because both halves can be self-consistent and still
disagree.** An algorithm identifier one side encodes and the other rejects, a
curve named differently, an attributes block one omits - neither test suite can
see it, because each only talks to itself. So a device-side test writes a real
signing request to disk and CI puts it through the real issuing path, asserting
that the CA discards the request's own subject and certifies the key that was
actually requested. Verified by hand against an independently generated request
that asked to be an administrator and was issued the name it was vouched for.

---

### D6. Lapse is the revocation mechanism, and the numbers follow from that

**2026-08-18, foundational.** Evidence: `server/muster/ca.py`
(`DEFAULT_VALIDITY_DAYS`, `RENEW_AFTER_FRACTION`, `BACKDATE`),
`agent/android/app/src/main/java/app/muster/agent/IdentityLifecycle.kt`.

**Context.** Something has to be able to say a device is no longer trusted.

**Alternatives.** A revocation list, or an online status protocol, or a separate
enabled flag in a database.

**Why none of them.** A revocation list has to **reach** the verifier, and this
estate's devices are routers in hotels and phones in drawers - offline for days
is the normal case, not the failure case. And a flag can disagree with what a
device can actually do; a certificate cannot. So a device's membership **is** its
certificate, and revocation is not renewing it.

**Chosen, with each number reasoned rather than picked:**

- **90 days.** Long enough that renewal is not constant chatter, short enough
  that "stop renewing" is a revocation an operator can live with. A stolen
  device stays trusted for at most that long.
- **Renew at a third of life.** Not half, and not at the last minute: a router
  that is off for a fortnight has to wake up still inside the window. Coming
  back with a dead identity means enrolling again from a fresh pairing code with
  a human holding the handset, which on an owned device costs a factory reset.
- **Backdate twelve hours.** Hardware without a real-time clock, which this
  estate has, can boot believing it is 1970 or several hours off. A not-yet-valid
  certificate is indistinguishable from a broken one on a device that cannot fix
  its clock without the network the certificate is for.

**The renewal decision is not "if now is past expiry".** Three states a naive
check gets wrong, each of which strands a device that was working:

- an **expired** identity reports *lapsed*, with how long ago, not
  *unenrolled* - because "not enrolled" reads as somebody having wiped the
  device;
- a **clock behind** the certificate's own not-before is reported as skew, not
  as an invalid certificate, because concluding "invalid" there is a device
  deleting a good identity because it does not know the date;
- backoff is **capped at an hour** rather than growing without limit, because
  the usual reason renewal fails is no network, and the moment there is one the
  device must not be sitting in a day-long wait.

---

### D7. Prove possession at the application layer, because mutual TLS cannot reach us

**2026-08-18.** Evidence: `server/muster/proof.py`, `server/muster/api.py`
(`_proven_device`).

**Context.** Client certificate authentication is the obvious way for an
enrolled device to prove itself on later requests.

**Two independent walls.** The edge in front of this service only accepts a
custom CA for client-certificate validation on its most expensive tier. And even
there it would not help: the tunnel to the origin opens a **new** connection, so
a certificate presented at the edge never reaches the application - which would
then be trusting headers a proxy wrote. That is a different trust model wearing
mutual TLS's clothes.

**Chosen.** The device signs a server-issued nonce with the key in its keystore
and muster verifies against the certificate it issued. The proof survives the
edge, tunnels and any proxy, because it never depended on the transport.

Three properties make it a proof rather than a ritual, each with a test:

1. **Server-issued.** A client-chosen challenge is not a challenge - an
   attacker replays one they already hold a signature for.
2. **Single use, consumed on failure too.** A nonce that survives a failed
   attempt is one an attacker can grind against.
3. **Expires.** A bounded replay window if a signature is ever observed.

**Two refusals matter most.** A self-signed certificate is rejected, because
signing correctly proves possession of *a* key, not that muster vouched for it.
And a certificate that merely **claims** our issuer name is rejected too - an
issuer name is a string an attacker puts in their own certificate, and only the
signature says otherwise. That verification uses the library's own
directly-issued-by check rather than a hand-rolled issuer comparison; a type
checker caught that the hand-rolled first version would have thrown on a
certificate with no signature hash algorithm, which is exactly the input
designed to be hostile.

A lapsed certificate is refused at the point of use, because not renewing **was**
the revocation mechanism (D6) and a mechanism enforced nowhere is not one.

It is no longer the only one. `_proven_device` also refuses a device an
administrator has revoked (muster#11), which had to arrive before automatic
renewal (muster#10, now shipped): a device that renews itself never lapses, so
lapse alone would have left a fleet nothing could cut off. `POST
/v1/device/renew` calls the same function, so it inherits the refusal rather
than restating it. The check is in the same function
for the same reason everything else about a device is - and it FAILS CLOSED, 503
rather than an allow, because a revocation you can defeat by making the database
unreachable is not one.

**One function, shared by every device-facing route.** A second authentication
scheme for the second thing a device asks for is a second chance to get it
wrong.

---

## Staying up

### D8. The store may fail; issuance may not

**2026-08-19.** Evidence: `server/muster/kith.py` (module docstring).

**Context.** muster had no datastore at all: a device presented, was vouched
for, got a certificate, and the server forgot. A restart lost everything.

**The decision that shaped the whole module is what happens when the store is
unreachable.**

| failure                        | consequence                                 |
|--------------------------------|---------------------------------------------|
| store down, issuance continues | a device list missing rows, filled in later |
| store down, issuance stops     | a fleet that lapses, one factory reset each |

Lapse is close to irreversible (D6). Trading the second for the first is not a
close call, and it is why the store is a **record** of what muster did rather
than the answer to whether a device is a member. Nothing in it is ever consulted
to decide whether to sign.

**So every write is deferred, never refused.** What happened is appended to a
bounded backlog and drained; in the healthy case the drain succeeds on the same
call. One code path, not a happy one and a fallback one - **a fallback path that
only runs during an outage is a path that is broken during every outage**.

**Reads are not deferred. They raise.** An empty list is a lie that reads as
"you have no devices" on a console; the API turns the exception into a 503,
which says the same thing honestly. Certificate collection answers 503 rather
than 404 for the same reason, because the agent reads 404 as "stop polling for
good".

**And deferred must not mean forever.** The backlog is ordered and replayed from
the head, so an entry the store will *never* accept - a device name carrying a
byte a text column cannot hold - is a **wedge**, not a delay: every write behind
it waits, and because a failed drain opens the breaker, reads start reporting an
outage while the database is perfectly healthy. So the store classifies its own
failures, and a row that was **refused** is dropped loudly, while anything that
did not reach a server at all is always retried. That distinction is drawn
conservatively, because the two mistakes are not symmetric.

**Five bugs found on the way, each of the kind that only shows in production
behind a healthy-looking pod:** the breaker cleared its own flag on the clock so
the recovery signal was unreachable; a connection whose schema statement failed
was leaked, one socket per retry; there was no statement timeout, so a silent
peer hung inside a lock the readiness probe also took - three probe failures
would have taken the pod out of service and stopped issuance for the whole fleet
*through the health check*; a wedged backlog reported a healthy database as
unreachable; and a mistyped connection string raises the same exception class as
"this row will never insert", so the wedge fix would have silently discarded
every device.

**Nothing may hang.** Queries have timeouts, connections have keepalives, a
failed store is left alone for a cooldown, and the status the readiness probe
publishes takes no lock and does no I/O.

**A device is its key, not its certificate**, so renewal writes a second
certificate against the same device rather than inventing a second phone every
ninety days.

---

### D9. A network share is not a drop-in for a mounted secret

**2026-08-21.** Evidence: `server/muster/assets.py`.

**Context.** The asset store started as a mounted secret. A secret tops out near
a megabyte - lower still through a client-side apply - and the agent package is
over twelve. That ceiling was the only thing standing between muster and
installing an application or updating its own agent, so the store moved to a
network share. The route, its digest contract and its no-store header are
unchanged; this is the backing store behind them, which the module always said
would move.

**Three properties of the share had to be answered rather than discovered.**

**Unavailability blocks rather than erroring.** A measured 90-second host-level
drop hung a plain directory listing for **106 seconds** and then returned
success. The soft mount does not produce an I/O error. muster is a control
plane, so an unbounded touch is a request thread it never gets back - and enough
of those stop enrollment and renewal, at which point a device lapses, and lapse
on an owned phone means a wipe. **A wallpaper nobody can read must degrade to
"no wallpaper", never to "no certificates".** Every touch is now bounded and
abandoned after the bound, with a small fixed pool so abandoned threads cannot
accumulate one per request for as long as the share is away.

**A health check on that storage must touch that storage.** A wedged share keeps
the listener accepting while nothing behind it can read. Readiness reports what
it actually got from the share, within the bound - so it answers rather than
hanging and getting the pod killed for it, which a restart could not have fixed
anyway. "Readable" now means muster can read the share, not that a path was
configured. On a mounted secret those were the same thing.

**The mount stays read-only.** muster holds a certificate authority, and a
process that can rewrite what it serves to devices is a process that can serve a
device something else.

**And an asset the share cannot answer for is a 503, never a 404**, because the
agent removes a file absent from a *successful* answer - so a 404 tells a device
its wallpaper was withdrawn.

**A related discovery in the earlier storage, worth keeping.** A mounted secret
does not place files. It places a timestamped directory, a symlink to it, and
one symlink **per key** pointing through that - which is how the whole secret is
swapped atomically. So every asset was a symlink, and the fetch refused symlinks
outright. Worse, the *count* disagreed with the fetch, because the existence
check follows a link and the symlink check does not: the store said one asset
and served none, and the first place that sends somebody is the policy file.
What the guard was actually for is a link pointing **out** of the store, and
containment is the check for that - resolve, then require the result to still be
inside the resolved root. Every test in the suite wrote plain files, so all of
them passed.

---

### D10. Reconcile on a timer, and let a device that half-starts fix itself

**2026-08-22.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/CheckInJob.kt`,
`agent/android/app/src/main/java/app/muster/agent/CheckInSchedulePolicy.kt`.

**What went wrong.** Configuration was fetched at boot only, so a device that
came up wrong stayed wrong until somebody rebooted it or pressed a button on its
screen.

The incident that made it urgent: two phones acting as bond legs for another
project drained flat overnight and rebooted. Their relay starts before first
unlock, deliberately, so a phone locked in a car still relays - but the console
write token is deliberately **not** cached before first unlock, because it is a
credential rather than configuration. Each relay came up forwarding bytes and
unable to announce itself. No announce, no leg, and the router lost every uplink
it had. There is no self-heal path on that side.

What fixes it is re-delivering the configuration to the **live process**: the
receiving application's restrictions-changed receiver assigns the configuration
*and* starts announcing. Nothing was re-delivering anything.

**Chosen.** A periodic job running the same step list a boot runs and the same
list the status button runs, so a check-in cannot drift from a boot.

Four properties, each a decision:

- **Fifteen minutes, because that is the floor the platform honors.** Asking for
  less does not fail, it silently becomes fifteen - and a constant that lies
  about what the device does is worse than a slower one that does not.
- **No network constraint, deliberately.** Most of the plan is local, and those
  local steps are exactly what a half-started device is missing. Requiring a
  network would mean a device sitting on a dead router - the case this exists
  for - never reconciling at all.
- **Rescheduling restarts the interval**, so whether to schedule is a *decision*
  rather than an unconditional call. A device that rewrote its schedule on every
  boot and every supervision pass would push its own next check-in permanently
  into the future - and from outside that is indistinguishable from a schedule
  that works.
- **A network-gated catch-up job, with its own id.** The cost of carrying no
  network constraint is that a failed fetch waits the whole interval; for a
  device whose router just came back that is seconds versus fifteen minutes. It
  needs a separate id, because sharing the periodic one would **replace** it -
  the device would recover once and then never reconcile again, which is worse
  than the bug and would look like a success.

---

## Getting onto a handset

### D11. Answer the provisioning intents, or the handset resets itself

**2026-08-19.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/ProvisioningModeActivity.kt`,
`agent/android/app/src/main/java/app/muster/agent/PolicyComplianceActivity.kt`.

**What went wrong.** A wiped handset scanned a provisioning QR, downloaded the
agent - logged server-side, 200, twelve and a half megabytes - and then **reset
itself** with "Something went wrong" and no cause named.

The agent declared no activity for either intent the platform sends during
provisioning. The platform's own documentation says that will cause provisioning
to fail, and that a failed provisioning factory-resets the device.

**Chosen.** Answer both. The provisioning-mode activity asks for fully managed
and **refuses anything that cannot hold device ownership** - a work profile would
enroll, look healthy, and be unable to carry out a single policy. The decision is
a plain object with tests, because a wrong answer here does not throw, it wipes a
handset.

**The same fix gave the server address its first reader.** That value had been
traveling in the admin extras bundle of every provisioning QR with nothing in the
agent referencing it, so a QR-provisioned phone came up owned and with nowhere to
enroll - fixable only over the cable the QR exists to avoid.

**Every line in that activity's creation path is inside a guard**, because a
throw escaping it is a crashed activity, which is a failed provisioning, which is
a reset. A later review found the one line that was not: handing work to a
background thread can be rejected, so the guard was nearly complete rather than
complete. The worker also catches errors, not just exceptions - an error there
kills the process, which takes the main loop and the watchdog with it.

---

### D12. Never cache the agent

**2026-08-19.** Evidence: `server/muster/api.py` (the agent routes),
`docs/state-of-play.md`.

**What went wrong.** The image bakes the agent in so the download and its
advertised checksum always describe the same file (D13). The edge then cached
the package **by file extension** for four hours, while the tiny metadata
document beside it stayed dynamic. The pair disagreed: the checksum advertised
described the build in the pod, and a phone downloading the package got the
previous build from the edge.

```
  cf-cache-status: HIT   age: 1165   cache-control: max-age=14400
  content-length: 12606023        <- previous build
  pod:            12635564        <- what the metadata described
```

**Why it fails silently, which is what makes it worth a header and a test rather
than a note.** A stale package signed with the same key still satisfies the QR's
certificate checksum, so the platform accepts it and provisions a device against
the wrong agent - or, with the provisioning activities missing from that older
build, factory-resets it. Twelve megabytes per provisioning attempt is not a
bandwidth saving worth trading a wipe for.

**And the fix took two changes, which is its own lesson.** The headers were
merged and nothing repinned the running image, so the origin still sent no cache
headers at all. Decoding both, the cached copy was the **pre-D11** build. The
same key signed both, so the certificate checksum matched either.

That is also why a no-store header was later put on the QR endpoints: the edge
caches by extension, and a vector graphic is on that list exactly as a package
is. A cached QR is a replayed single-use code.

---

### D13. Checksum the signing certificate, not the file; bake the file into the image

**2026-08-19.** Evidence: `server/muster/provisioning.py`,
`.github/workflows/build.server-image.yml`.

**Context.** The provisioning payload has to tell a wiped handset where to fetch
the agent and how to know the download is genuine.

**The checksum everybody gets wrong.** Both the signing certificate's digest and
the package file's digest are a hash of something in the same file, both look
plausible in a QR, and the wrong one fails on the handset as "can't set up
device" with nothing naming the cause. The certificate one is also **stable
across releases**, so one printed QR keeps working, where the file digest would
need reprinting every build.

Tested by building two genuinely different packages with one signing key and
asserting the checksum matches.

**A defect found while building it.** The debug package was signed with the
modern schemes only, which is the current default, so there was no legacy
signing block to read the certificate out of. Legacy signing is now explicitly
enabled: it costs a slightly larger package and buys the checksum being
computable by any archive reader. The reader **raises** rather than guessing when
the block is absent, because a checksum computed from the wrong thing is
undiagnosable on the handset.

**And the file is baked into the image rather than mounted beside it.** One route
serves the bytes; another advertises the checksum of the certificate those bytes
are signed with. The two **must** describe the same file, and a mounted file can
drift from the image that advertises it. Shipping them as one artifact makes the
skew impossible rather than unlikely, with two gates: the image build fails when
no package was downloaded, and a step reads the certificate out of the package
**inside the built image**, so an unsigned or modern-only package fails there.

**A trap that cost a wipe, recorded because it recurred three times in one day.**
Two image builds can run on the same commit and publish **different** images -
one triggered by the server change and one by the agent build finishing - and
they bake different agents. Pinning the newest image by timestamp shipped the old
agent inside a new digest. Every later pin records which build it is and why, and
whether a superseding rebuild exists.

**One more default worth stating:** the payload leaves all system applications
enabled. Disabling them strips anything the agent does not explicitly enable,
which on a handset means losing the launcher, the camera and settings - a very
managed device nobody can use.

---

### D14. Write configuration through the application, and prove the bytes

**2026-08-19.** Evidence: `server/muster/provision.py` (`place_file`,
`write_as`).

**What went wrong.** The operator commands staged a file in a shared temporary
directory and copied it into the agent's own storage, on the strength of a
comment saying that directory was world-traversable. It is not - it is owned by
the application's user with no other access, measured on a handset. The shell
user is a different account, so nothing ever landed, and only the read-back at
the end of the command noticed.

**Chosen.** All writes go through one function that writes **as the
application**, using the platform's run-as facility. That needs a debuggable
package, so this path ends at the release-signing ceremony rather than degrading
- said in the code, in the runbook and in the state of play, so the failure is
loud when it arrives.

**The read-back had to change too, and this is the interesting part.** A byte
count was the wrong verification. An older debug bridge runs the remote command
under a pseudo-terminal, whose line discipline turns every carriage return
arriving on standard input into a newline - a substitution that **leaves the
length alone**. A common image format's own signature contains exactly that byte
pair, and the signature exists to catch exactly this. Under a length check the
push reports success, the file is corrupt, and the only witness is a decoder
returning nothing at the next boot in a log nobody watches.

So the device computes a digest and that answer is the verdict. Three things
follow from asking it properly:

- **The device's words explain a failure and no longer decide one.** Returning
  early on any output failed a good write on a version-mismatch message from the
  local machine, and a terminal echoing the payload back would have buried the
  operator in it. The explanation is truncated and only decorates a "no".
- **A write that never finishes returns an exit code**, because the timeout on
  the one call that feeds megabytes down standard input is none of the expected
  statuses and this runs from scripts.
- **A zero-byte file still verifies**, because an empty restrictions file is a
  valid instruction and means "withdraw everything".

**Every value in a configuration file is treated as a credential**, since muster
cannot know which of another application's keys are secret. No value reaches a
log, a refusal, a metric or a string representation.

**A refusal that leaked one anyway, and the fix.** The file's syntax is
`set <package> <key> <value>`, and the syntax an operator is most likely to
actually type is `key=value` - which makes a three-word line. The refusal quoted
all three words, into the platform log on the spot and into the boot outcome's
string representation at every boot after. A write token in the log forever, from
the one file built to keep it out. The rule now is that the third word is named
only when a fourth follows, because that is exactly when its column is provable.

---

## Telling a device what to be

### D15. Reconcile both ways, from what is in force, and read back

**2026-08-19.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/RestrictionPolicy.kt`,
`agent/android/app/src/main/java/app/muster/agent/RestrictionSteward.kt`,
`agent/android/app/src/main/java/app/muster/agent/BootPlan.kt`.

**What went wrong.** The agent enforced nothing. The single restriction in the
codebase was added by a method whose only possible caller was reached with a
parameter nothing anywhere passed as true. Its decision function carried three
passing unit tests over a path production could not reach, so the suite stayed
green across a capability that did not exist.

**Chosen.** A decision object, a steward that applies it, and a boot plan that is
a **list** the receiver iterates - so a test can assert the wiring rather than
the intent.

Four rules:

- **Reconciling goes both ways.** A name deleted from the configuration comes off
  the device. Policy that only ever adds is a ratchet whose only reverse gear is
  a wipe.
- **What to add is decided from what is actually in force**, so every boot
  re-asserts policy instead of remembering having asserted it.
- **What to clear is decided from what muster itself set**, so another
  administrator's restriction is never withdrawn.
- **An unrecognized name is refused and named in the log, not skipped.** A
  silently ignored line leaves a device unrestricted with a configuration file
  that reads as though it is not.

**Restrictions are read back from the effective set after being written**,
because adding one does not reject a key the platform does not know.

**Two of them carry an explicit stranding warning**, because they are the ones
that can take away the recovery: disabling factory reset is what left another
managed handset unable to be freed from its own settings, and disabling debugging
features removes the access that is the only route to a setting no management API
can write.

**The key names were read out of the platform's own source rather than derived**,
and the file cites where and when. One of them proves the derivation is
impossible: the constant name and the string it maps to have their words in the
opposite order.

---

### D16. An allowlist that cannot be read in full hides nothing

**2026-08-19.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/AppVisibilityPolicy.kt`,
`agent/android/app/src/main/java/app/muster/agent/AppVisibilitySteward.kt`.

**Context.** A muster-owned handset came up with the whole consumer launcher on
it - store, mail, drive, photos - on a device whose entire purpose is to be a
relay.

**Chosen.** Hide, not uninstall. The package stays and the same call with the
opposite argument puts the icon back.

**The sharpest decision, and it went in after a review found it the hard way.**
This is an **allowlist**, which is the difference from the restrictions file next
door. A restriction name muster does not recognize costs one restriction. A
package name muster cannot read costs an application that gets **hidden**. So the
obvious way to build the file - piping the platform's own package listing into
it, where every line carries a prefix - used to parse as "keep nothing" and strip
the launcher.

Any unreadable line now withholds the **hide** direction for the whole reconcile,
and so does a device that names no home screen at all. **Unhiding still runs**: it
gives something back and cannot strand a phone, so a typo made while trying to
un-strand a device is not what leaves it stranded. Unhiding also runs **first**,
because it is the only recovery an appliance in a cupboard gets and it must not
be queued behind forty writes.

**Only packages with a launcher entry are candidates**, which is the load-bearing
safety property rather than an implementation detail. The system UI, the
permission controller and the setup wizard are not things this can hide even if
the file tries.

**What cannot be hidden is decided by asking this device**, not by matching a
table: the agent's own package, whatever answers the home intent, whatever
answers the settings intent, whatever answers the setup-wizard category. A
declared table exists **as well**, because a resolve can come back empty and the
setup wizard disables itself once setup finishes. A wrong name there protects a
package that is not on the device and costs nothing; a missing one costs a
handset, so the table is generous.

**Three platform facts that are silent when wrong**, all verified against the
platform's own source:

- a hidden package is not "available" to the package manager, so without the
  right query flag, hiding an application removes it from the query that would
  find it again - and the reverse gear becomes a factory reset;
- both direct-boot query flags are needed together, because the platform fills
  them in from the unlock state when the caller expresses no opinion, and before
  first unlock almost nothing on a launcher matches;
- asking whether a package the device has never heard of is hidden answers
  **yes**, so the steward asks only about packages the device itself reported.

**And no new manifest permission.** Enumerating packages is filtered from a
recent platform version and being a device owner does not exempt an application -
checked against the platform's own filtering code, which exempts the calling
application, low user ids and force-queryable packages, and has no device-owner
case anywhere in it. The broad query permission would be a **fifth** permission,
and the four-permission profile is the only input to the protection service's
approval heuristic this project controls (D25). A declaration-scoped query
element is used instead, which is not a permission - pinned twice, in the source
and in the built package, because dropping it breaks nothing visibly: the build
stays green and the agent comes up able to see only itself.

---

### D17. Serve a device its own configuration over its own identity

**2026-08-19.** Evidence: `server/muster/policy.py`,
`agent/android/app/src/main/java/app/muster/agent/ConfigurationPolicy.kt`.

**What went wrong.** A device that provisioned by QR and enrolled over the air
came up owned, restricted by nothing, showing every application it shipped with,
and identical to a factory phone until somebody enabled wireless debugging and
pushed six files. Every configuration muster could apply traveled over a cable -
and that route has an expiry date on it, because the run-as write in D14 needs a
debuggable package and stops working the day the release-signed agent ships,
which is the day the project becomes real.

**Chosen.** An enrolled device fetches the same files from the control plane,
authenticated by D7.

**The files are the interface, and they are the same files.** What is served is
the exact byte content the agent already reads out of its own storage, so the
existing stewards and their read-back guards keep working unchanged. Building a
second apply path would mean two vocabularies, two sets of refusals, and one of
them untested on a handset.

**Because they are that directory, they are also the cache.** When muster is
unreachable, refuses, or answers with something that will not parse, nothing is
written and the device keeps enforcing the last configuration that arrived. That
rule was originally a branch in a steward with no tests - the single most
destructive decision in the feature, mutable without breaking anything - and is
now a pure exhaustive function that a test enumerates.

**muster refuses in the same direction, and this is the part review caught.** The
policy source is an **optional** mounted secret, and the orchestrator mounts an
optional secret that does not exist as an **empty directory**. So a secret
deleted, misnamed or never created read exactly like a policy nobody had written
- served as 200 with no files, and the agent removes every managed file a
*successful* fetch does not mention. One typo in a secret name would have
withdrawn the whole fleet's configuration at its next boot, and the readiness
probe would have said "readable: true".

An empty or absent policy source is a 503 now. Saying "assert nothing"
deliberately is still one file - an empty restrictions file - which is the
vocabulary the agent already speaks. Readiness reports the file **count**,
because "readable" is true for both.

**A vocabulary that only one side knows is silent in both directions.** Adding a
file type to the server and not the agent means it is served, refused at the
handset, and never written. That happened while the wallpaper route was being
built, so a CI check now compares the two vocabularies.

---

### D18. Roles, and a wake ledger that survives being wrong

**2026-08-21 to 2026-08-23.** Evidence: `server/muster/policy.py`,
`agent/android/app/src/main/java/app/muster/agent/WakeLedger.kt`,
`agent/android/app/src/main/java/app/muster/agent/AppConfigSteward.kt`.

**Context.** Policy was keyed on a device's key id or served to the whole kith
and nothing in between, which breaks the moment two devices are not the same kind
of thing. A per-device file means writing the same configuration again per
handset, keyed on an id that does not exist until *after* the device has
enrolled.

**That last part is the shape of the problem.** The only moment anything knows
what a device will be is when its QR is minted, and at that moment the device has
no identity to key anything on. So the role rides the pairing code and the
certificate writes it into the kith.

**Resolved most-specific-first, per file.** Per file rather than per device,
because a role says what is *different* about a set of handsets, and making it
restate the fleet's whole policy is how the two drift - silently, because both
files look maintained.

**A role may carry a configuration file with credentials in it and the kith may
not.** That is the point of roles, and it is a deliberate trade: the credential
is shared by every device carrying the role, which is exactly what a role asserts
- that those devices are interchangeable, and interchangeable devices share what
they run. Serving the same file at kith scope hands a credential to every device
in the estate; refusing is loud, serving widely is silent, and silent is how a
token ends up on a phone somebody later sells.

**A device never names its own role.** It is read from the kith on every fetch,
because a device that could name one could ask for another role's credentials.
An empty role never overwrites a set one on issuance, or re-enrolling a handset
against a plain QR would strip it silently - but an administrator setting an
empty role **does** clear it, because there they are saying so in as many words
and refusing would leave no way back. That endpoint is administrator-only, and
it is **synchronous** rather than deferred (D8): there is a person waiting on the
answer who is about to go and look at a handset expecting different policy, so a
write that quietly joined a backlog would report success for something that had
not happened.

**Two bugs found on the way, both the same shape and neither about roles.** Two
store methods rebuilt the device record field by field, so every field added
afterwards was silently dropped - and one of them runs on **every** proven
request, so a device lost its role on the way in to the very fetch that needed
it. The other store implementation kept it, so the two disagreed and only the
in-memory one is exercised by tests. And the first regression test for it ran
against a frozen clock, where that method returns early and does nothing at all,
so it passed whatever the code did. Caught by mutation testing, not by reading.

### The wake ledger

Installing an application that has never run leaves it in a stopped state where
it receives no broadcasts at all, so muster has to wake it explicitly
(ARCHITECTURE.md section 7). A wake every fifteen minutes forever is battery
spent telling an application what it already knows, so the wake is gated on "did
this pass change something".

**That gate made a missed wake permanent.** The install step commits and returns;
installation completes asynchronously. So the configuration step that follows can
fire a wake at a package that does not exist for another second or two, and the
send reports nothing either way. The next pass finds the configuration already
matching, short-circuits, and nothing wakes the application again - ever. A
handset sat exactly there: correct build installed, correctly configured, process
alive, relay never started, port closed from the router, and nothing in the
system that would ever try again.

**Chosen.** The question becomes "has **this** package been told about **this**
configuration", answered by a durable per-package ledger. A fingerprint is
recorded **only** after a wake is sent to a package the platform confirms is
installed, so a wake that could not have landed is never remembered as delivered.
Installation is asked of the platform rather than inferred from "we just
installed it", because believing our own install reintroduces the same race.

**Six further defects were found in that ledger by adversarial review, and every
one of them is the same family: a silent drop recorded as a delivery.**

1. The early return for "this plan changes nothing" ran *before* the wake
   reconciliation - so the ledger was unreachable on the one path it was written
   for. Correct in isolation, inert in place.
2. The fingerprint came from the **delta** rather than the full intent, so the
   value computed on the pass that writes differs from the value on every
   steady-state pass afterwards. The ledger would never match and the
   application would have been woken every fifteen minutes forever - the exact
   battery burn the gate exists to prevent, arriving from the opposite
   direction.
3. It was estate-wide, so editing one application's configuration re-woke every
   other managed application.
4. The component was **parsed** rather than resolved, and a parse succeeds for
   any well-formed name whether or not the class exists. A rename would have
   been recorded as told and never retried.
5. The encoding was ambiguous and truncated: configuration values are routinely
   structured text carrying the delimiters, so two different configurations
   could share a fingerprint - and a 32-bit hash collides around 65,000
   configurations. Length-prefixed fields and a real digest now.
6. The ledger was keyed by **package**, and a package may declare more than one
   wake target, so a send to one marked the others as told - and in the failure
   interleaving it recorded the **failed** one as delivered. Keyed by component
   and action now.

Three silent-drop conditions were added as refusals for the same reason: a
receiver declared unexported, a receiver disabled by any of the several disabled
states rather than only the obvious one, and a runtime enablement setting that
the manifest value does not reflect. One condition is noted and explicitly not
fixed, because it cannot be at this layer: a force-stopped application passes
every check and the broadcast still dies. The ledger is best-effort by nature.

**And the ledger is stamped with the boot count.** A reboot stops every
application again, so every record became false the moment the device came back
while the records survived in storage - and an application that fails to start
itself on boot would never be woken again. Clearing the ledger from the boot
receiver was the first fix and was replaced by review, because it bound
correctness to a broadcast arriving: that broadcast can be minutes late under
boot pressure, other readers can run before it, and for a stopped package it may
not arrive at all. Each entry now carries the boot it was written on, so the
question moves to **read** time where it cannot be missed. On an impossible read
the count is a sentinel and every entry fails to match - so the failure mode is
waking an application that did not need it rather than leaving one asleep that
did.

---

### D19. A step that cannot say what went wrong has not reported

**2026-08-20.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/SyncReport.kt`,
`agent/tools/jvm-tests.sh`.

**What went wrong.** A phone enrolled by QR fetched its policy, ran every step,
hid nothing, and reported "Managed - Current". Every steward had already worked
out precisely why it changed nothing - withheld, refused, kept visible, did not
take, threw - and each of those facts reached the platform log and stopped there.
An appliance enrolled hands-free has no cable, so that log is not a place its
owner can look, and a device enforcing nothing was indistinguishable from one
nobody had configured.

**The cause was at the caller boundary rather than in any steward.** The step
list was typed to return anything, which left the status screen no question it
could ask; it stringified the result, logged it, and painted the screen from the
identity facts instead. The five outcome types **did** share a convention - bad
news is shouted in the string representation - but a convention that lives in a
formatting method cannot be queried, and reading severity back out of a rendered
line would rot the first time a key was renamed.

**Chosen.** The convention becomes a type. Every outcome can enumerate the things
a person has to go and look at, each steward names its own bad news because only
it knows what bad means there, and the step list is tightened to return one - so
**a step added later cannot compile until it can say what went wrong**.

Two outcomes that read as the quietest possible success were reclassified as
concerns, and both describe the device in hand: "no wallpaper configured", which
is what every device reports because no wallpaper is among the files served, and
"nothing to present", which is a phone that will run all six steps and enforce
none of them.

**A harness came with it**, because the loop that found those two bugs did not
exist: it typechecks the pure sources and runs their tests with no platform SDK
installed. Its self-test feeds the compiler a deliberate type error, because a
harness that silently accepts anything looks exactly like a clean build - and the
first run of that self-test reported teeth when the compiler had in fact died on
a missing standard library, so it now requires a real type-mismatch diagnostic
rather than a non-zero exit.

---

## Not destroying things

### D20. Never delete an application on evidence that was not established

**2026-08-23.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/AppInstallPolicy.kt`,
`agent/android/app/src/main/java/app/muster/agent/AppInstallSteward.kt`,
`agent/android/app/src/main/java/app/muster/agent/InstallReport.kt`.

**Context.** Two handsets in the same role were running different builds of the
same application with no way to converge, which is the state a management plane
exists to prevent. One of them had received a build signed by a keypair a
pull-request pipeline generates per run and deletes when the job ends. The
platform identifies an application by its signing certificate for as long as it
is installed, so the newer build could not replace it, and the key that could
sign a successor **does not exist anywhere**. The only exit was a factory reset.

**Chosen.** An opt-in flag on a policy line authorizes muster to remove the
installed copy first. Never inferred, because removing an application destroys
its data, and deciding that for an operator because an install failed would be
muster choosing data loss on their behalf. A misspelling of the flag is
**refused** rather than read as absence: a typo in the one flag that authorizes
deletion would otherwise silently withhold the only thing the line was added to
do.

Without the flag, a signer mismatch is a **stated refusal** rather than a
download loop. That failure is not transient - no number of retries makes a
different key acceptable - and the previous behavior spent nearly twenty
megabytes per check-in on an install that could never succeed, four times in
eleven minutes over a metered link.

**Then adversarial review found four ways it could destroy data anyway, and each
correction is a general rule.**

1. **A boolean had to pick a side, and it picked "differs".** The signer
   comparison returned true or false, so every failure - including a write that
   throws on a full disk, which these handsets reach - became "differs", which is
   the value that authorizes uninstalling. The safe direction depends on which
   downstream action reads the answer, which is precisely what a boolean cannot
   express. It is now four values, and only "differs" may authorize removal.
2. **The platform decides first.** Judging "this cannot install" ourselves
   reimplemented the platform's signature logic and got it wrong for key
   rotation, where a package signed by a rotated key carries a lineage proving
   continuity and installs in place - while a set comparison of certificate
   digests calls it a mismatch and deletes an application that needed no
   deleting. Attempting the install first makes that the platform's call.
3. **A refusal was being misdiagnosed.** Inferring "it refused because the signer
   differs" from "it refused, and the signers differ" reads every *other* refusal
   - a full disk, a transient package-manager error - as a signature conflict,
   and the action that follows destroys data. The install report already received
   the platform's status and only logged it; a removal now requires the platform
   to have named the conflict. **A verdict that has not arrived is not a refusal
   and is not read as one.**
4. **A time-of-check window was still open while a comment claimed it was
   closed.** The signer was read before the commit and acted on up to a minute
   later, during which the store or a system update can legitimately replace the
   package. It is read again immediately before the decision.

Two smaller ones from the same review: committing a session means the *session*
was committed, not that the package changed - installation is asynchronous and a
refusal arrives through a broadcast this process does not listen for, so the
platform is asked what it now carries; and the signer check wrote to a fixed
filename in a cache directory, so two packages examined in one pass overwrote
each other's bytes and both resolved to unknown, silently withholding installs.

---

### D21. muster updates itself last, and may never uninstall itself

**2026-08-21 and 2026-08-23.** Evidence:
`agent/android/app/src/main/java/app/muster/agent/BootPlan.kt`,
`agent/android/app/src/main/java/app/muster/agent/AppInstallPolicy.kt`.

**Context.** muster hides the app store because an appliance has no business
showing one, and thereby takes responsibility for updates it must then be able to
perform. The only route from a built package to a handset was a factory reset and
a QR scan - which also throws away the device's identity, its policy and its
enrollment, to change a file.

**Chosen, and the ordering rule is not a detail.** Committing muster's own
install **ends the process**, so it is the last step in the plan and muster is the
last entry within it. A boot that updates the agent has already applied the
restrictions, the configuration and the visibility; anything queued behind it
would never run, and the next boot would find the agent current and skip it all
again.

Nothing after the commit is relied on. The next reconcile asks the **platform**
what is installed, which is the answer that cannot go stale or be missed because
a process died. The install-result receiver is a log line and says so in its own
documentation, so nobody later builds a decision on it: for muster's own package
it runs inside the application being replaced and may never be delivered.

**It shipped one line away from being wrong.** The step was inserted beside the
wallpaper step, which left the visibility step running after it - so a boot that
updated the agent would have killed the process before that step ever ran. Caught
by an index assertion written in the same change, in CI rather than locally
because that test imports a platform type and sits outside the pure harness.

**A later split for the same reason in the other direction.** Installing an
application had to come **before** configuring and revealing it: on a handset,
the configuration step ran first, the package did not exist when the grant was
attempted, and the application sat installed, unconfigured and hidden until the
next pass, with the launcher icon missing for the same reason. Reordering
wholesale is not the fix, so the work splits by scope, and a test asserts the two
passes together install exactly what one pass would have - because a split that
quietly dropped something would look like everything working.

**And muster may never be a target of the replace flag (D20).** A policy line
saying so would make the agent uninstall itself, which removes device ownership -
and ownership cannot be re-established on a provisioned device without a factory
reset, which destroys every other application's data on the way back. The handset
would be permanently unmanaged, which is precisely the outcome the flag exists to
avoid. It is refused at **read** time rather than guarded in the steward, because
this is not a decision that should be reachable at all.

A signer change on muster itself is a real situation with a real answer, and the
answer is a wipe - which is why the signing ceremony exists and why it says to
perform it **before** a phone is enrolled.

---

### D22. A version that does not increment cannot replace anything

**2026-08-22.** Evidence: `.github/workflows/check.agent-android.yml`,
`server/muster/api.py` (the agent metadata route).

**What went wrong.** muster shipped an installer that can update its own agent
over the air, and it could never have worked. The build reads a version code from
the environment and falls back to 1, and **nothing had ever set it** - so every
agent muster published was version 1. The install policy installs only when the
device carries a lower version, so 1 could never replace 1, and the platform
refuses a same-version install anyway. The feature was implemented and inert.

It was found because the operator objected to being told to plug in a cable, and
the honest answer required checking whether "over the air from now on" was even
true.

**Chosen.** Derive it from the commit count of the history: monotonic, survives
the workflow being renamed or recreated, and two builds of one commit produce the
**same** number rather than two versions of identical bytes.

**Read back out of the built package, not echoed from the variable that went
in.** A stamp the build silently ignored would otherwise be reported as applied,
which is the same class of lie as a green suite that ran no tests. The file the
image carries is written by the step that did that verification, so it cannot
describe different bytes - and the server does not re-derive it, because two
answers about which agent is deployed is the failure the metadata route exists to
prevent.

**Omitted rather than guessed when unknown.** An image built from an agent
predating the stamp has no version file, and that is a real state. A fabricated
zero would read as an agent older than every device in the fleet, and every
handset would try to downgrade to it.

**And the first version of the fix reintroduced the bug one layer down.** CI
reported version 1 again: the checkout is shallow by default, so counting the
history returns 1 on every build forever. The read-back check passed and was
right to - 1 genuinely did reach the package. It proved the stamp **landed**, not
that it **meant** anything. The guard now refuses a version of 1 outright, since
a shallow checkout and a genuine single-commit repository are indistinguishable
by the number alone and this repository has hundreds.

---

## Who is allowed in

### D23. The console signs in at an external provider, keyed on an immutable subject

**2026-08-19 to 2026-08-21, tightened 2026-08-27.** Evidence:
`server/muster/administrator.py`, `server/muster/console.py`,
[docs/administrator-sign-in.md](docs/administrator-sign-in.md).

**Context.** The console was a token box: one shared string, held in a browser
tab, forgotten on reload, with no accounts, no sessions, no sign-out and no way
to tell who did anything - on the surface that mints pairing codes and vouches
for devices.

**Chosen.** An administrator signs in at an external identity provider using the
authorization-code flow with PKCE, and muster verifies a signed token. muster
never sees a password, and the exchange is configured entirely by standard URLs,
so this repository names no vendor and can be pointed at whichever provider is
available.

**Authorization keys on the immutable subject claim, never on email.** A subject
is stable; an email address can be changed by whoever holds the account, and an
allowlist keyed on one is an allowlist that can be **joined**.

**And which directory matters as much as the mechanism.** The first wiring
pointed at a consumer application's user pool, because "sign in the same way" was
read as "the same directory". That pool has open self-registration and no
multi-factor requirement, which would have made the identity source for a control
plane holding a CA a directory strangers can add themselves to. The subject
allowlist was the right control and the only one, over an open door. It now uses
a pool that is administrator-create-only, multi-factor capable, and demands a
long password. The sign-in experience is identical; the cost is one extra
password.

**Two middleware, and the order between them is load-bearing.** Who is acting is
established before anything writes down what they did. Swapped, nothing errors -
every record just says anonymous, which is a log that looks healthy and answers
no question anybody will ever ask it. The order is asserted at composition time,
so a reorder crash-loops at startup rather than shipping a worthless audit trail.

**Neither middleware ever refuses a request.** Authorization stays a dependency
on each administrator route, which is the only thing that can express this
service's shape: posting an enrollment request is a **device's** way in and
listing pending requests is the administrator's. A device that has not enrolled
has no credential and cannot be given one. So the route table is a **test** -
every route deliberately on one side of it, and no open route ever answering 401.

**The shared token survived as a break-glass credential and was then removed.**
It was for before sign-in was configured, or the day the provider is unreachable.
Once sign-in was what actually gets used day to day, the fallback was retired and
the application refuses to start unless sign-in is configured, full stop. The test
suite's admin shortcut moved from a bearer token to a real signed session cookie
across every call site, so coverage of every gated route was preserved rather
than dropped.

**Ten defects were found and fixed while building it**, six by an async-runtime
review and one by driving the running console in a browser: a browser holding one
stale cookie could never sign in again; a provider that was down was asked again
every two seconds; concurrent requests spent the same refresh token; login CSRF;
a token with no expiry never expired; a mistyped URL was a 500 on every request
rather than a refusal to start; an injected transport was closed underneath us;
and the agent metadata route re-hashed twelve megabytes per request.

---

### D24. No third-party script on the page where the session lives

**2026-08-19.** Evidence: `server/muster/console.html`, `server/muster/api.py`,
[docs/observability.md](docs/observability.md).

**Context.** The console is one HTML file with no build step and no dependencies.
A build step would put a package manager on the path of the process that signs
certificates, and a framework would reach a supply chain to the same box - for a
page with a list and two buttons.

**Chosen, and enforced rather than promised.** The page carries a content
security policy permitting one nonced style block, one nonced script and images
from this origin. The framework's own interactive API documentation is turned
**off** for the same reason: it loads its JavaScript from a public CDN, on the
same origin as the console, where it would run with the administrator's session.

**Real-user monitoring is deliberately not added**, with the reason written down
rather than left as an omission: the console is where an administrator's session
lives, and that would put a third-party script on that page. The observability
document states what it would take to do it safely.

**The token, when there was one, lived in a variable and not in storage.** One
that survives a reload survives the laptop being borrowed. Unlocking proved it
against the API first, so a wrong one says so rather than rendering an empty list
that reads as "no devices are waiting".

**The page itself is served unauthenticated**, because it carries no secrets, and
gating it would mean either a second authentication mechanism for browsers or a
token in a URL - which ends up in history, logs and referrers.

**A lockout worth recording, because the failure named nothing.** The stored
admin secret ended in a newline: a common way to print a value appends one, the
common way to load it from standard input stores it verbatim, and the console
trims what an operator types - so the server expected a token no human could ever
produce. A correct token simply failed. Three changes, because fixing one leaves
the trap live: the configured value is stripped, the documented setup command no
longer appends a newline, and the failure is recorded beside the other
deployment traps. The test asserts the **lockout** rather than the strip, so with
the fix removed it fails on a token typed without the newline, which is exactly
the symptom.

---

### D25. Four permissions, and an argument required to add a fifth

**2026-08-19, exercised 2026-08-23.** Evidence:
`server/tests/test_agent_manifest.py`, `.github/workflows/check.agent-android.yml`.

**Context.** A wiped handset cleared the platform's protection service and
provisioned with exactly four permissions declared. Nobody can prove which
addition would tip that check back, and the cost of being wrong is a wiped
handset that fails provisioning with "App blocked to protect your device".

**Chosen.** A test pins the permission profile at exactly four, so a new
permission is a **decision somebody argues for** rather than a line that arrives
with a feature. CI also reads the permission set back out of the shipped package,
beside the checks that already read back the version code, the admin component
and the signing certificate - because a permission the code needs and the
manifest omits is not a build error, it is a security exception at the moment the
feature is first used.

**The guard did its job four days later.** A freshly provisioned handset
crash-looped in front of the operator, mid-enrollment: the job scheduler refuses a
job carrying a connectivity constraint from an application that does not hold the
network-state permission, and it **throws** rather than returning false. The
catch-up job of D10 sets exactly that constraint - it *is* the job's purpose - so
that code had been broken since it was written.

Nothing noticed because the periodic check-in deliberately carries no network
constraint and never needed the permission. The only path that did is the one
that runs after a fetch has **already** failed, so the gap could only surface on
a device that was already having a bad time, which is when a crash loop is least
affordable. This handset's pairing code had expired; the recovery path for that
failure was itself the fatal one.

The test refused the change, which is the guard working. The argument was written
into it: why it is needed, why it cannot be avoided (a connectivity callback needs
the same permission, and the only alternative is deleting the catch-up and making
a device whose router just came back wait out the full interval), and why it is
thought safe (granted at install without a prompt, revealing whether a network
exists rather than anything about it, and among the most commonly declared
permissions on the platform). The docstring is explicit that the last part is a
judgement and not a proof, and that the next provisioning run is where it gets
tested.

**The schedule calls are also wrapped now, and that is the general part.** The
permission fixes this instance; the **shape** is the problem. Scheduling throws on
an objection to a job's shape, this runs on a scheduler worker, and an uncaught
exception there kills the process and reschedules the job. A recovery path that
can take the process down makes every ordinary failure fatal.

---

### D26. Sign only on a reviewed push, and never let the pin be circular

**2026-08-23.** Evidence: `.github/workflows/check.agent-android.yml`,
[docs/signing-ceremony.md](docs/signing-ceremony.md).

**Context.** The provisioning QR carries the digest of the signing certificate,
and a device owner cannot be replaced by a package signed with a different key.
So the key the first device enrolls against is the key **forever**, and changing
it later means factory-resetting every enrolled phone. CI was producing a
debug-signed package from a keystore the SDK generates on the build machine and
nobody backs up.

**And the ceremony could be performed exactly as written and change nothing.**
The documented steps seed repository secrets; the build reads a keystore path on
disk; nothing connected the two, and the check workflow assembled a debug build
unconditionally. Key generated, backed up, stored, seeded - and every subsequent
build still debug-signed.

**Chosen, in three corrections, each from an adversarial review.**

**The key is never given to a pull request.** A same-repository pull request
receives repository secrets, and this job checks out and executes the candidate's
own build logic - the build wrapper and scripts - so a pull request could have
read the keystore and its passwords off the runner. That key is the permanent
update identity for every installed agent; losing control of it ends the fleet's
upgrade path rather than causing a leak to rotate past.

**Excluding pull requests was not enough.** The workflow also has manual
dispatch, and whoever can dispatch it chooses **any** branch - that branch's build
wrapper then runs with the keystore decoded on disk, unreviewed, around branch
protection entirely. Signing is gated on a push to the default branch, the only
event whose code has necessarily been reviewed. Everything else builds debug.

**The pin was circular.** Reading the certificate digest out of the first signed
build and copying it into a repository variable authenticates nothing: the pin
would describe whatever CI happened to sign with, so a mis-seeded or substituted
keystore would be published first and legitimized afterwards by its own digest.
The ceremony now reads the digest off the keystore **before** seeding the
secrets, and a release-signed build with no pin is a hard failure rather than a
warning - so the ordering cannot be skipped.

**The check that came before it did not do what its comment claimed.** It tested
the certificate *subject* for the debug key's name, citing an incident whose
throwaway key carried a subject byte-identical to a real one - so it would have
passed exactly that build. Every wrong key produces a different digest; only the
right key produces the pinned one.

**A missing keystore secret fails closed** rather than quietly downgrading the
default branch to a debug build that the image then publishes - which would leave
release-signed handsets unable to upgrade and newly provisioned ones bound to a
disposable key.

**One residual risk is accepted rather than fixed, and it is written where
somebody granting the secret will read it:** this is a persistent self-hosted
runner that also executes pull-request code, so event-gating the key stops a pull
request reading it during its own run but does not isolate the machine. That is
tolerable only while the writer set is small and controlled on a private
repository. Going public is the moment to revisit it, which is why a comment now
sits next to the runner declaration in the workflow files themselves rather than
only in a document a reviewer might not open.

---

## Three rules that generalize

Almost every entry above is an instance of one of these.

**The dangerous failure is the silent one.** A feature implemented and never
wired. A version stamp that landed and meant nothing. A wake recorded as
delivered that was dropped by the framework. An absent secret mounted as an empty
directory and served as an empty policy. A green build that tested nothing. In
every case the mechanism looked healthy and did nothing.

**Ask the device, not your own record of what you asked for.** Restrictions are
read back from the effective set. Installs are confirmed against what the
platform now carries. Ownership is confirmed by asking the device afterward,
because the provisioning tool prints failures on standard output and its output
is not a verdict. A configuration file is verified by a digest the device
computes.

**Every irreversible action needs evidence that was actually established.** Only
a platform-named conflict authorizes removing an application. Only an
administrator saying so clears a role. Only "differs" - never "unknown" - can
delete. The asymmetry between the two mistakes decides which way an uncertain
answer falls.
