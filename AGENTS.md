# This repository is public

Everything here — code, commit history, issues, pull requests, comments,
review threads, discussions, releases, wiki pages, GitHub Pages content —
is visible to anyone on the internet, forever, including after deletion
(forks, caches, and search-engine indexes outlive an edit or a delete).
Treat every write to this repo, in any surface, as something a stranger
reads the moment you make it.

This file exists because that got violated repeatedly before it was
written down. Real personal names, a real home network's addresses, real
device identifiers, and a live unrotated credential all ended up in public
issue trackers and public git history — not through carelessness in the
code, but through ordinary conversational writing in issues, PR bodies, and
code comments, where the discipline that already existed for the shipped
code was never applied. This file is the fix: the same discipline,
extended to every surface an agent writes to, not just the diff.

## The rule

**Nothing that identifies a specific person, a specific private network,
or a specific credential may appear anywhere in this repository, in any
form, ever.** Not in code. Not in a code comment. Not in an issue body. Not
in a PR description. Not in a commit message. Not in a comment reply. Not
in a test fixture. Not "just this once because it's only in a closed
issue" — closed does not mean hidden, and neither does deleted.

This is broader than "don't commit secrets." A secret scanner catches an
API key. It does not catch a sentence like *"[a real first name]'s home
server, reachable at their usual address, needed a restart"* — nothing
there matches a secret
pattern, and it is exactly the kind of sentence that put a real name, a
real domain, and a real IP into a public tracker tonight. Write for a
stranger from the first word, not just the code.

### Concretely, never write any of the following into this repo, on any surface

- A real personal name — yours, a collaborator's, anyone's. Refer to
  people by role ("the maintainer," "the operator," "a reviewer") the same
  way this file does.
- A real hostname, domain, or subdomain that resolves to a private network
  or a real person's infrastructure (a home VPN suffix, a personal tailnet
  domain, a work-in-progress product's real URL before it's meant to be
  public). Use a placeholder that is visibly fake: `example.com`,
  `your-server.internal`, `<your-domain>`.
- A real IP address on any network you actually operate — home, cloud, or
  otherwise. Use an RFC 5737 documentation range (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) or an obviously fictional one
  (`10.0.0.X` as a *labeled example* is fine; a live address copy-pasted
  from a real `curl`/`dig`/log output is not).
- A real device identifier: a serial number, a MAC address, an IMEI, a
  hardware ID, an account ID, a database GUID tied to a live system.
- A credential of any kind, live or "already rotated" — a key, a token, a
  password, a signing certificate, a webhook URL with a token embedded in
  the path. "It's already been rotated" is not a reason to leave the old
  value visible; redact it anyway, because the *pattern* (which SSM path,
  which naming convention, which provider) is itself information.
- A path that reveals a real local username (`/Users/<name>/...`,
  `C:\Users\<name>\...`) or a real machine's hostname.
- A quote attributed to a specific named person, even an accurate one.
  Paraphrase instead: "the operator decided..." not "Alice said...".
- An `@`-mention of anyone who is not already part of the conversation.
  A mention notifies that account and subscribes it to the thread, and
  neither can be undone by editing or deleting the text. `@grug` in
  particular is an unrelated real user, not the review bot: the bot is
  `grug-tribe[bot]` and takes slash commands (`/grug improve` re-runs the
  code review, `/grug recheck` re-runs the plan check). To name a handle
  in prose, put it in backticks, which GitHub does not treat as a mention.
- The name of another private repository, service, or internal system
  that isn't itself meant to be discoverable. Cross-repo references
  belong in the *private* tracker, not migrated wholesale into a public
  one.

### If you are migrating or importing content

Content that already exists elsewhere — an issue being moved from a
private repo, a comment thread being copied in, history being subtree-split
into a new repo — is not exempt from this rule because it was written
before this file existed. **Migration is not a scrub.** Before content
from anywhere else lands in this repo, on any surface, re-read it against
every bullet above and rewrite what fails. If a whole issue's substance is
inseparable from the personal/private detail it's built on, don't migrate
it — summarize the generic problem it represents instead, or leave it out.

Wholesale-copying a private issue tracker into a public one because it was
"faster" is exactly how this happened the first time.

### If you find a violation already in the repo

Fix the current tree, then say plainly in your response that older
issues/PRs/comments/history may still carry it and that this needs a
human decision, not a silent edit-and-move-on. Do not delete or rewrite
someone else's public comment without asking first — you may not always
know why it was worded that way. Editing your own agent-authored content
to remove a violation is always fine and encouraged.

## The other half: this repo must be genuinely reusable

A stranger must be able to clone this repository, supply their **own**
configuration and secrets, and have it work — without reading anything
beyond the README and an example config file to know what to change.

- Every value specific to one deployment (a hostname, an IP, a region, an
  account ID, a device identifier) is a variable, an environment variable,
  or a config file entry — never a literal baked into source, a workflow
  file, or a script.
- Ship a `.env.example` / `config.example.*` alongside any file that reads
  real config, with every key present and an obviously-placeholder value
  (`YOUR_DOMAIN_HERE`, not a real one with the last octet changed).
- If a CI/CD pipeline assumes infrastructure that doesn't ship with the
  repo (a specific runner pool, a specific cloud account, a specific
  private reusable workflow), say so explicitly in the README rather than
  let a stranger discover it as a mysterious failure. "This requires your
  own self-hosted runner and your own AWS account" is an honest
  dependency; a silent reference to `uses: <this-operator>/infra-private/...`
  is not.
- Prefer this repo's own already-public reusable workflows
  (`quadseven/infra-public/...`) over hand-rolled CI where one already
  exists — they're already written to take config as input rather than
  assume it.

## Why this file, not just a smarter secret scanner

A pattern-matching scanner catches shapes: an AWS key, a PEM block, a
32-character hex string. It cannot catch a paragraph of ordinary prose
that happens to name a real person or describe a real network in plain
words — which is where nearly everything this file exists to prevent
actually showed up. Scanners still belong in CI as a backstop for the
shapes they *can* catch; this file is the layer above that, for the judgment
a scanner doesn't have.

<!-- Everything above the next line is synced from quadseven/infra-public and replaced on every sync. Put this repo's own content below it. -->
<!-- repo-specific below -->

# AGENTS.md

For anyone changing this code, human or model. It is deliberately short: the
reasoning lives elsewhere and this file's job is to stop you walking into the
things that have already bitten someone.

Read in this order. `CONTEXT.md` first, always - five nouns mean exactly one
thing each here, and a change that uses them loosely reads as correct and is
not. Then `ARCHITECTURE.md` for the tour, and `DECISIONS.md` when you want to
know why something has the shape it has. Every entry there names the failure
that caused it.

**Never write a bare `@grug` anywhere on GitHub** - issues, PRs, comments,
commit messages. That handle belongs to a real GitHub user unrelated to this
project; each mention notifies them and subscribes them to the thread, and
neither can be undone. It happened twice here (#62, #69). The review bot is
`grug-tribe[bot]` and takes slash commands: `/grug improve` re-runs the code
review, `/grug recheck` re-runs only the plan check. In prose write `grug` in
backticks. Check any text for `@grug` before posting it.

## Six things that will bite you

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

**5. "Lapse is the revocation mechanism" is no longer true, and half the repo
still says it is.**

It WAS true, and for a good reason: renewal needed a human, so declining to
renew was declining to trust, and the two were one act. `CONTEXT.md` defined the
verb that way, `DECISIONS.md` argued it, and `console.html` designed a page
around it.

Automatic renewal (muster#10) breaks that. A device that renews itself never
lapses, so a design with only lapse in it is a fleet nothing can cut off. That
is why `revoked_at` and `POST /v1/kith/{key_id}/revoke` exist (muster#11), and
why the check lives in `_proven_device` rather than on whichever route somebody
remembered - so `POST /v1/device/renew` inherits it and a revoked device cannot
renew its way back. That ordering is the point; do not move the check into the
routes.

If you are reading an older comment that says lapse is how revocation works,
it is describing the design before this. Revocation is now a thing an
administrator does; lapse is still what happens to a device nobody renews.

Two properties worth keeping when you touch it: it FAILS CLOSED (an unreadable
kith is a 503, never an allow - a revocation you can defeat by taking the
database down is not one), and `record_issuance` deliberately leaves
`revoked_at` out of its `DO UPDATE SET`, so a renewal cannot readmit a revoked
device. Both have tests that die if you change them.

**6. The device channel is not Android-only.**

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
