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

## How work moves here

Several AI brains work this repo beside the operator: Claude Code, Muse, Dot and the Loom factory. Loom has a station that dispatches, a brain that briefs and merges, and lanes that build. No brain outranks another. Each acts under its own GitHub App, never a person's account, and signs posts `-- <name>`.

**Claims.** Put `claim:<name>` on a ticket before starting, and create the label if this repo lacks it. Check first and skip a ticket already held. One claim per ticket: the station keeps the earliest and removes the rest. A claim expires after 2 hours with no real activity, unless a comment holds it with `waiting: <what> until <time>`, or an open PR the claimer wrote and referenced holds it for up to 7 days. `claim:quadseven` is a person: leave those tickets alone. On stopping, push the work and say what is done, what is next, and the branch and head. Take over only an expired or plainly dead claim, after reading the holder's comments and open PRs.

**Labels.** Loom sets one state label per ticket:

`loom:triage` (not ready) -> `loom:queued` (no lane) -> `loom:briefed` + `lane:<name>` -> `loom:running` -> `loom:pr` -> `loom:merged` -> `loom:shipped` -> `loom:verified`, then closed.

`loom:ticket` marks every ticket. `loom:failed` means the runner gave up; the reason is on the ticket. `wait:*` names why a ticket is held. `needs:human` is an ask for a person. `loom:factory` marks a fault in the factory itself.

**CI and required checks.** Required checks differ per repo, so read them live: `gh api repos/<owner>/<repo>/rules/branches/<default-branch>`. Every repo needs a PR and `Grug - Chief`; some add test jobs; some add `Grug - Elder`. Run each command in `.loom/validation.conf` before pushing, and read the failing workflow file before guessing at a red check.

- Shared workflows come from `quadseven/infra-public`, pinned by full SHA.
- Leak scan: reads the diff and the PR title and body, and a scan that cannot run is red. It has 9 rules: tailnet hosts, tailnet IPs, private-range IPs, server names, node names, user paths, MAC addresses, the stray mention, and cross-repo refs. A ref of the form `name#N` or `owner/name#N` to any other repo fails, public or not, unless the leak scan's `allowed-repo-refs` input lists that repo. Bare `#N` means this repo. A line with `leak-guard-allow` is exempt and visible in review; use it only for a real false positive.
- Trust gate: a job on self-hosted workflows that admits collaborators only and can reject an App token. A repo with no self-hosted jobs has none.
- Other guards, where a repo calls them: workflow hygiene, size ratchet, CI config freshness, and close completeness, which reopens an issue closed with unticked boxes.
- Agent Apps cannot push `.github/workflows` changes.

**`grug`.** The bot is `grug-tribe[bot]`, driven by slash commands in a PR comment. Its handle takes no at-sign.

- `Grug - Chief` reads the PR body. It wants `## Why` (5+ words), `## Acceptance criteria` (3+ bullets), `## Out of scope`, `Size: XS|S|M|L`, and `Refs <owner>/<repo>#N` or `Refs #N` to a ticket that is an epic or sits under one. Text in HTML comments does not count. Closing keywords are out: tickets close when their boxes are ticked.
- A body with an agent marker (such as a session link) from an App author, or a Loom lane footer, gets a neutral Chief: `Hunt Plan skipped`. Neutral passes. A body with no marker gets the full check, so write the full shape every time.
- `Grug - Elder` reviews the code by LLM. `/grug improve` re-runs it. `/grug recheck` re-runs Chief only. Five pushes in ten minutes pause Elder until `/grug resume`.
- A degraded or partial review says `Degraded review (<reason>): not a verdict`. It is not a pass, whether it concludes failure or neutral. Run `/grug improve` once the backend recovers.
- `Grug - Guard` scans for security problems and is advisory unless the repo turns on blocking. Haunt, once called Sentinel, comments when a PR closes over an unresolved critical finding. It posts no check; answer its comment and re-verify.

**Merge gate.** Rulesets enforce less than this, and this binds: CI green, `Grug - Elder` success on the head (neutral is not enough), `Grug - Chief` success or neutral, not behind base, every bot thread answered, and a test that fails without the fix. `gh pr checks` does not show threads, so read `reviewThreads` by GraphQL and `pulls/<n>/reviews`. Anyone merges what they built. Outside shadow, which today means `quadseven/loom` and `quadseven/grug`, Loom merges docs, test and app code tiers alone and holds deploy, security and cross-repo tiers for the operator. Every other Loom repo is in shadow: Loom runs every gate and records each merge or close for the operator instead of taking it, until the operator graduates the repo. A change to how brains merge, close or rewrite needs a fleet chat line and a 5 minute wait. Never use `--admin`.

**Human line.** People do: permanent deletion of records, creating, rotating or entering credentials, access grants, new spending, accepting terms. People decide: another brain's role and the fleet goal text. A second brain must agree, in writing, to clear a lane demotion, lift another brain's hold, or reopen a sound close. Everything else needs nobody. Ask with `needs:human` and one exact question. A relayed yes is not a yes. Never print a credential.

**When stuck.** Labels and stages: `docs/BRAIN.md` in `quadseven/loom`. Reusable workflows: `docs/reusables.md` in `quadseven/infra-public`. Chief's rules and every `/grug` verb: the README in `quadseven/grug`, whose `make chief-check` tests a body before posting. Fleet log: issue 30 in `quadseven/loom`. File a factory fault there as `loom:factory`. Poll `gh` at most once per 5 minutes.

<!-- Everything above the next line is synced from quadseven/infra-public and replaced on every sync. Put this repo's own content below it. -->
<!-- repo-specific below -->

# AGENTS.md

For anyone changing this code, human or model. muster enrolls one household's phones, routers, laptops and IoT devices, and gives each a short-lived client certificate as its identity. The server is Python and FastAPI; the device agent is Android first.

This file is short on purpose: the reasoning lives elsewhere, and its job is to stop a change walking into what has already bitten someone.

Read in this order. `CONTEXT.md` first, always: five nouns mean exactly one thing each here, and a change that uses them loosely reads as correct and is not. Then `ARCHITECTURE.md` for the tour, and `DECISIONS.md` for why something has its shape. Every entry there names the failure that caused it. `docs/state-of-play.md` holds dated live state.

## Layout

    server/muster/    the control plane; enroll.py holds the trust decision
    server/tests/     pytest suite
    server/tools/     operator scripts, such as bootstrap_ca.py
    agent/android/    the Android agent (Kotlin, Gradle)
    agent/tools/      jvm-tests.sh, Kotlin unit tests with no Android SDK
    site/             static splash page, no build step
    docs/             constraints and runbooks

## Commands

```bash
# The one lane check in .loom/validation.conf, and the required `server tests` job.
# 800+ tests, under a minute, no network.
cd server && uv run --group dev --python 3.12 python -m pytest -q

# Serve locally. It refuses to start until the settings in the README are set.
cd server && uv run --python 3.12 uvicorn --factory muster.api:app_from_env --port 8000

# Agent unit tests in CI. Needs an Android SDK, which CI has on its self-hosted Mac.
cd agent/android && ./gradlew --no-daemon testDebugUnitTest

# Agent tests with no SDK: sources with no `android.*` import, using the Gradle cache.
# Needs a JDK for this CPU. `--selftest` proves the harness can fail.
agent/tools/jvm-tests.sh
```

CI has no lint, format or type gate. Lint is the author's job all the same, and the repo holds no ruff config. Write code so a rule does not fire rather than add a `# noqa`.

## Checks and shipping

Required on `main`: a PR, `server tests` and `Grug - Chief`. Other checks run without being required: the leak scan, `server image (build + publish)` on `server/**`, `agent - android` on `agent/android/**`, workflow hygiene on `.github/**`, `Grug - Elder` and CodeQL. This repo calls no size ratchet, CI config freshness or close completeness guard.

`server/tests/test_readme_standard.py` pins the README's structure, and `server/tests/test_no_live_hostnames.py` fails on a real hostname.

**A merge does not deploy.** `build - server image` publishes `ghcr.io/quadseven/muster-server:sha-<12>` from `main`, and a finished `agent - android` run on `main` rebuilds it, because the image carries the agent APK. The deployment manifest is pinned by digest and lives outside this repo. Take the digest from the run summary of `build - server image`, and repin before applying: `docs/what-is-deployed.md` has the order. `site/` is Cloudflare Pages with no workflow here. Change icons only through `site/icons/src/render.py`.

## Six things that will bite

**1. muster does not use mTLS. Do not "fix" that.**

The name says "short-lived certificates" and the device holds one, so mTLS looks like the obvious mechanism and is the wrong one. Cloudflare only accepts a custom CA for client certificates on Enterprise, and a Tunnel opens a fresh origin connection, so a certificate presented at the edge never reaches the pod. `server/muster/proof.py` documents this at the top.

Instead the device signs a server-issued nonce and presents the signature with its certificate, and the application verifies it end to end. Nothing between the client and the app can forge that, which is the property mTLS was supposed to provide and could not here.

**2. There is one place a device is authenticated, and it stays one place.**

`_proven_device` in `server/muster/api.py`. Its docstring says why: a second scheme invented for the second route would be a second chance to get it wrong, and the one that got it wrong would be the one nobody tested against a handset. A new route a device will reach calls it. Do not write a variant.

It returns `key_id`, not a certificate serial. A serial changes every ninety days; the key does not, so identity survives renewal.

**3. Reads raise. They never lie.**

`server/muster/kith.py` files its reads under exactly that heading, and `_read` raises `Unreachable` when the store cannot be read. It does not return `None` or an empty answer.

An empty answer is indistinguishable from a real one. The device agent removes a file that a *successful* fetch did not mention, so "here is nothing" is an authoritative instruction to withdraw. A route that degrades a store outage into a smaller answer strips managed files from every device in the estate. `/v1/device/config` returns 503 for exactly this reason.

Code that catches `Unreachable` refuses. It does not substitute.

**4. `app-config` is never served under the shared scope.**

`server/muster/policy.py` excludes it deliberately: that scope carries write tokens, and a credential under a shared scope is a credential handed to everyone. Per-device and per-role scopes exist for this. A role means "these devices are interchangeable", so anything pairwise (a key that identifies one endpoint to one peer) belongs at device scope, not role scope.

**5. "Lapse is the revocation mechanism" is no longer true, and older text still says it is.**

It was true while renewal needed a human: declining to renew was declining to trust. Automatic renewal (#10) broke that. A device that renews itself never lapses, so a design with only lapse in it is a fleet nothing can cut off. That is why `revoked_at` and `POST /v1/kith/{key_id}/revoke` exist (#11), and why the check lives in `_proven_device`: `POST /v1/enroll/renew` inherits it, so a revoked device cannot renew its way back. Do not move the check into the routes.

Revocation is a thing an administrator does; lapse is what happens to a device nobody renews.

Two properties to keep. It FAILS CLOSED: an unreadable kith is a 503, never an allow, because a revocation defeated by taking the database down is not one. And `record_issuance` leaves `revoked_at` out of its `DO UPDATE SET`, so a renewal cannot readmit a revoked device. Both have tests that die on a change.

**6. The device channel is not Android-only.**

The agent implementation is Android. The wire protocol is not: enrollment, proof and configuration are ordinary HTTPS with a signature, reachable by anything that can sign a nonce. `openssl` on an OpenWrt router is enough. A second channel for a non-Android device solves a problem that does not exist.

## Working on it

Tests are the contract, not decoration. A change that needs its tests rewritten has changed behavior: say so in the PR rather than adjust the assertion. A new guard must be proven to fail without the fix; a test that passes against the unfixed code is not evidence.

## This repository is public

`server/tests/test_no_live_hostnames.py` exists because a scrub removed the operator's domain from 42 places and nothing stopped it coming back. Use documentation ranges and reserved names.

A reserved placeholder that reaches a running system fails silently, which caused a real outage in the sibling project. `.invalid` never resolves and `192.0.2.0/24` is not routable. A value that is dialed, resolved or compared at runtime gets a parameter, not a plausible fake.

## Related

[zippie](https://github.com/quadseven/zippie) is why muster exists: a device should fetch its own identity over its own credential rather than have a deploy pipeline splice a static secret into its config. Several decisions here started as incidents there.

## Notes on the shared section

The section `How work moves here` above is synced. These lines are where this repo differs.

- Leak scan: exceptions are in `allowed-repo-refs` in `check.leak-scan.yml`.
- Trust gate: this repo calls none. Its self-hosted jobs skip pull requests from forks.
