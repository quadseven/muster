# muster

To muster is to assemble a company and take the roll.

muster is a device enrollment and identity plane for one household's endpoints -
phones, routers, laptops, IoT. A device generates its own key, presents a CSR
with a short-lived pairing code, an administrator **vouches** for it, and muster
issues a short-lived client certificate. That certificate is the device's
identity and its membership; it renews itself, and revocation is simply not
renewing.

The pairing code is either typed on the device by a person comparing a key
fingerprint on two screens, or carried in the provisioning QR so nobody touches
the handset at all. The two are not equally strong and
[CONTEXT.md](CONTEXT.md) says exactly how they differ - read it before assuming
either.

Read [CONTEXT.md](CONTEXT.md) first - the same five nouns run through the server,
the agents and the console, and they mean exactly one thing each.

[ARCHITECTURE.md](ARCHITECTURE.md) is the tour: the trust model, the two shapes
of pairing code, the certificate authority, and how a device gets from a factory
reset to a managed endpoint. [DECISIONS.md](DECISIONS.md) records why it has
that shape, each entry with the failure that caused it.

muster exists because of a decision made in
[zippie](https://github.com/quadseven/zippie): a device should fetch its own
identity over its own credential, rather than have a deploy pipeline splice a
static secret into its config. Several decisions here started as incidents
there.

## Why this exists

Every product tried first said no to the same modest ask - push and pull
configuration to a device I own, from one place.

- **A mainstream commercial MDM** applies policy on the free tier but will not
  install an application; that is Premium, and it is the one thing needed.
- **An open-source MDM** works and is free, but owns the launcher and brings a
  management model that is not wanted.
- **Android Management API** will not have us at all: its permissible-usage
  policy excludes "solutions developed and used exclusively for first party
  in-house applications", and enrollment fails on the handset at zero devices.

See [docs/android-constraints.md](docs/android-constraints.md) for what Android
actually permits, dated and cited. **Read it before designing any enrollment UX.**
The six-tap QR flow provisioned a Pixel on 2026-08-19 with no cable, which is one
device on one day past a Play Protect check that behaves like a heuristic - so
that file records it as open and measured once, and keeps the adb route as the
fallback.

## Layout

    server/muster/enroll.py         the trust decision: mint, present, vouch, issue
    server/muster/kith.py           what muster remembers, and why the store may fail
    server/muster/administrator.py  who the human is, and how they sign in
    server/muster/console.py        the console's session, and what gets recorded
    server/tests/                   every way the exchange says no
    agent/                          per-platform agents; Android first
    docs/                           constraints and runbooks

## State

Early. The enrollment exchange is implemented and tested with no HTTP, storage
or device involved, which is deliberate: it is the part that has to be right.
An administrator signs in at the estate's identity provider
([docs/administrator-sign-in.md](docs/administrator-sign-in.md)); a device
enrolling has no credential and never needs one.

The same command CI runs, so a green run here means a green run there:

    cd server && uv run --group dev --python 3.12 python -m pytest -q
