# AGENTS.md

For anyone changing this code, human or model. It is deliberately short: the
reasoning lives elsewhere and this file's job is to stop you walking into the
things that have already bitten someone.

Read in this order. `CONTEXT.md` first, always - five nouns mean exactly one
thing each here, and a change that uses them loosely reads as correct and is
not. Then `ARCHITECTURE.md` for the tour, and `DECISIONS.md` when you want to
know why something has the shape it has. Every entry there names the failure
that caused it.

## Five things that will bite you

**1. muster does not use mTLS. Do not "fix" that.**

The name says "short-lived certificates" and the device holds one, so mTLS
looks like the obvious mechanism and is the wrong one. Cloudflare only accepts
a custom CA for client certificates on Enterprise, and a Tunnel opens a fresh
origin connection - so a certificate presented at the edge never reaches the
pod. `server/muster/proof.py` documents this at the top.

Instead the device signs a server-issued nonce and presents the signature with
its certificate, and the application verifies it end to end. Nothing in the
path between the client and the app can forge that, which is the property mTLS
was supposed to provide and could not here.

**2. There is one place a device is authenticated, and it stays one place.**

`_proven_device` in `server/muster/api.py`. Its docstring says why: a second
scheme invented for the second route would be a second chance to get it wrong,
and the one that got it wrong would be the one nobody tested against a handset.
If you are adding a route a device will reach, call it. Do not write a variant.

It returns `key_id`, not a certificate serial. A serial changes every ninety
days; the key does not, so identity survives renewal.

**3. Reads raise. They never lie.**

`server/muster/kith.py` files its reads under exactly that heading, and `_read`
raises `Unreachable` when the store cannot be read. It does not return `None`,
and it does not return an empty answer.

This matters because an empty answer is indistinguishable from a real one. The
device agent removes a file that a *successful* fetch did not mention, so
"here is nothing" is an authoritative instruction to withdraw. A route that
degrades a store outage into a smaller answer therefore strips managed files
from every device in the estate. `/v1/device/config` returns 503 for exactly
this reason - it once carried a comment claiming `member` answered `None` on
an outage, which was false, and the fallback it justified would have been
wrong even if the mechanism had existed.

If you catch `Unreachable`, refuse. Do not substitute.

**4. `app-config` is never served under the shared scope.**

`server/muster/policy.py` excludes it deliberately: that scope carries write
tokens, and a credential under a shared scope is a credential handed to
everyone. Per-device and per-role scopes exist for this. A role means "these
devices are interchangeable" - so anything pairwise (a key that identifies one
endpoint to one peer) belongs at device scope, not role scope.

**5. The device channel is not Android-only.**

The agent implementation is Android. The wire protocol is not: enrollment,
proof and configuration are ordinary HTTPS with a signature, reachable by
anything that can sign a nonce. `openssl` on an OpenWrt router is enough. If
you find yourself adding a second channel for a non-Android device, you are
solving a problem that does not exist.

## Working on it

```bash
cd server && uv run pytest          # 500+ tests, seconds, no network needed
```

Tests are the contract, not decoration. A change that needs its tests rewritten
has changed behavior - say so in the PR rather than adjusting the assertion.
Where you add a guard, prove it fails without the fix; a test that passes
against the unfixed code is not evidence.

There is no ruff gate in CI. That means lint is your responsibility, not that
it does not matter - and note that a `# noqa` for a rule outside this project's
own selection reads as an unused directive locally while a stricter reviewer
still wants it. Prefer writing the code so the rule does not fire.

## This repository is public

`server/tests/test_no_live_hostnames.py` exists because a scrub removed the
operator's domain from 42 places and nothing stopped it coming back. Do not add
real hostnames, addresses, or personal identifiers - not in code, not in
comments, not in test fixtures. Use documentation ranges and reserved names.

One caveat that has caused a real outage in the sibling project: a reserved
placeholder that reaches a running system fails silently. `.invalid` never
resolves and `192.0.2.0/24` is not routable. If a value is dialed, resolved or
compared at runtime, parameterize it - do not substitute a plausible-looking
fake.

## Related

[zippie](https://github.com/quadseven/zippie) is why muster exists: a device
should fetch its own identity over its own credential rather than have a deploy
pipeline splice a static secret into its config. Several decisions here started
as incidents there.
