# What muster reports about itself

Written 2026-08-19, when muster had none of this: no metrics, no traces, no RUM,
and the server had not a single log line.

## The rule everything else follows

**Nothing secret is ever emitted, and telemetry never takes the service down.**

This process holds the CA private key and hands out pairing codes. A metric tag
or a log line is the easiest way for either to reach somewhere it cannot be
deleted from, so `telemetry.event()` drops a fixed set of field names (`code`,
`pairing_code`, `token`, `secret`) and records that it did. The
guard is in one function rather than at each call site: there are a dozen places
that could log a code and only one that has to be right.

A code is never truncated into a tag either. Six digits is 10^6, and a prefix
narrows that to something a script walks well inside the code's lifetime.

Fingerprints **are** emitted. They exist to be read aloud off two screens, so
they are not secret, and they are the only way to follow one device through a
log.

Every send is wrapped and DogStatsD is UDP, fire and forget. A control plane
that stops issuing certificates because a metrics socket went away has traded a
working estate for a graph.

## Metrics

All `custom.muster.*`, matching `custom.zippie`. DogStatsD to the node-local
agent at `status.hostIP:8125`.

    enroll.code.minted              #shape:typed|scanned
    enroll.present.accepted         #shape:typed|scanned
    enroll.present.refused          #reason:<why>,shape:typed|scanned|unknown
    enroll.vouch.refused            #reason:<why>
    ca.issued                       a certificate was issued
    ca.issue.refused                #reason:untrusted-csr
    ca.issue.duration               ms, emitted even when signing raises
    proof.verified                  #verdict:ok
    proof.refused                   #verdict:<why>
    device.config.served            a device fetched its own configuration
    device.config.refused           #reason:no-source|unreadable
    agent.apk.served                a device downloaded the agent
    auth.signin.completed           an administrator signed in
    auth.signin.refused             #reason:<why>
    auth.session.renewed            a session was extended without a password
    auth.session.refused            #reason:<why>
    auth.signout                    a session was ended deliberately
    admin.action                    #principal:<who>,#outcome:<accepted|refused>
    kith.write                      #kind:issued|seen|collected
    kith.store.unreachable          a call FAILED; #operation:read|write
    kith.store.recovered            a call succeeded after one had failed
    kith.write.dropped              a deferred write fell off a full backlog
    kith.write.poison               a row the store will never accept, dropped
    kith.deferred                   gauge, how much is owed to the store
    kith.read.unreachable           a read short-circuited by the cooldown
    kith.read.refused               /v1/kith answered 503
    enroll.collect.from_store       a certificate collected after a pod restart
    enroll.collect.unreachable      collection answered 503 rather than 404

**The `reason` and `verdict` tags are the point.** "Devices are failing to
enroll" is not an answerable question without them:

- `code-expired` is an operator who took too long.
- `too-many-attempts` is somebody guessing at codes.
- `fingerprint-mismatch` is somebody enrolling against your code **while you
  watch** - and it must never be averaged into a total with the other two.
- `nonce-used` on a proof is a replay; `cert-expired` is a device that stopped
  renewing. Opposite responses, and a single total hides both.

**`device.config.refused{reason:no-source}` is the one to alert on.** It means
muster could not say what a device should be - an empty or absent policy
directory, which on this deployment is a `muster-policy` secret that was
deleted, misnamed, or never created. Devices keep what they have, so nothing
breaks; but nothing changes either, and the only other sign is a `files` count
of zero on `/readyz`.

**`device.config.served` is the one that says whether devices are configuring
themselves at all.** It increments once per device per boot (#46), so a fleet
that has stopped fetching is a rate that goes to zero rather than an absence
somebody has to notice. It is NOT tagged by device: a per-device tag on a fleet
metric is cardinality, and the `key_id` is in the log line beside it, with the
`revision` that says which policy that device is now on. Neither the metric nor
the log ever carries the configuration itself - `app-config` holds write tokens,
and `telemetry._NEVER_LOG` refuses the field one would arrive in.

**`shape` is the same argument one level out.** A QR whose code expired before a
phone finished downloading and installing the agent, and an operator mistyping
six digits, are the same `code-expired` without it - and the responses are not
the same at all. `shape:scanned` is a provisioning run that failed with a wiped
handset in somebody's hand; `shape:typed` is a person who can simply try again.

`shape:unknown` on a refusal means the code named nothing muster ever minted,
which is the `no-such-code` case. It is deliberately not inferred from the FORM
of what arrived: classifying by length would let whoever is sending the traffic
choose which bucket it lands in, and then "is the QR path failing" is a question
answered from attacker input.

The reasons are a closed set (`enroll.Outcome`, `proof.Verdict`), so tagging by
them cannot explode cardinality. They are emitted as `.value`, not as the enum:
`f"{Outcome.CODE_EXPIRED}"` on a `(str, Enum)` mixin yields
`Outcome.CODE_EXPIRED`, and a tag carrying a Python repr is one nobody can group
a graph by. A wiring test caught exactly that.

`agent.apk.served` deserves its own note: it is the **only** signal that a
provisioning attempt began. The setup wizard fetches the APK before the device
has any identity, so if that counter stays flat while somebody is standing there
with a wiped phone, the QR is the thing to look at.

**The sign-in reasons are the same idea one layer up.** `not-an-administrator`
is somebody else in the estate's pool trying the console door;
`wrong-audience` is a misconfigured client id; `provider-unreachable` is not
muster's problem at all and is the one nobody can fix by signing in again. A
single `auth.signin.refused` total hides all three behind each other. The set is
closed (`administrator.Outcome`), so tagging by it cannot explode cardinality.

**`admin.action` is tagged by PRINCIPAL, not by person.** Which administrator
it was belongs in the log line, where it is one subject rather than a tag
dimension.

**`kith.write.dropped` is the one to alert on.** The kith store is allowed to be
unreachable - muster keeps issuing and holds what it recorded to write later
(`what-is-deployed.md`) - so `kith.store.unreachable` on its own is a survivable
condition and not a page. `kith.write.dropped` is different: the backlog has
overflowed, and every increment is a device that exists and will not be listed
again until it renews. That is the point at which an outage has started costing
something that does not come back on its own.

`kith.write.poison` is the other one worth an alert, and it means something
completely different from every metric beside it: the store READ the statement
and refused it, so the database is fine and one specific row is not. It is
accompanied by a log line naming what was dropped, which is the only way anybody
learns which device. It should be zero forever - `enroll.clean_device_name`
refuses the names that cause it before they can be stored - so a non-zero value
means either a new field is reaching the store unvalidated or the schema and the
code have drifted apart.

`kith.store.recovered` is emitted only on a DEMONSTRATED success - a write that
landed or a read that answered - never on the cooldown timer expiring. A metric
that fired because a clock passed would say the database was back while nothing
had spoken to it, which is the shape of graph that gets an outage closed early.

**These four do not partition the failures, so do not build a ratio out of
them.** `kith.store.unreachable` counts a call that actually failed;
`kith.read.unreachable` counts a read that never ran because the cooldown was
still open; and `kith.read.refused` counts only `/v1/kith` answering 503, while
the collect endpoint reports `enroll.collect.unreachable` instead. The first
failure of an outage therefore increments `store.unreachable` and not
`read.unreachable`, and every one after it does the opposite. Add them and you
get "how many requests met the outage", which is the useful number; treat either
as the total and it will look like the other is dropping events.

## Logs

One JSON object per line on stdout, collected by the
`ad.datadoghq.com/muster.logs` annotation as `source:python`. Structured so that
`status:refused reason:fingerprint-mismatch` is a filter rather than a grep
somebody has to invent under pressure.

`propagate` is off, or every line appears twice: once as JSON here and once as
plain text through the root handler.

**The startup line is load-bearest.** `muster starting` carries
`telemetry_enabled`, `dd_agent_host_set`, `agent_apk_published`, `base_url` and
`administrators`. An emitter that silently no-ops because `DD_AGENT_HOST` was
never set looks exactly like an estate with nothing to report - "configured
but absent" is a failure this estate keeps rediscovering, and one line at boot
makes it answerable without an exec into the pod.

**`administrative action` is the record of who did what.** It carries the
actor's subject, the method, the route TEMPLATE and the status.
The template rather than the path, because
`/v1/enroll/requests/{request_id}/vouch` contains a request id and that id is
all a device needs to collect its certificate.

## What the cluster does

    tags.datadoghq.com/service, /env   on the Deployment AND the pod template
    ad.datadoghq.com/muster.logs       stdout as python logs
    ad.datadoghq.com/muster.*check*    http_check against /readyz
    DD_AGENT_HOST                      status.hostIP, the estate's convention

The labels are repeated on the pod deliberately. The agent reads the **pod's**
labels; tagging only the Deployment leaves every metric and log from the running
container untagged.

The http_check is not redundant with the kubelet probes. Those restart a wedged
container; the http_check is what notices the service is unreachable while the
container looks perfectly healthy, which a liveness probe cannot see by
construction.

## Deliberately NOT done

**Browser RUM on the console.** Not a style objection - a concrete one. The
console is the administrator's surface on the service that holds the CA, and RUM
means loading a third-party script into it. A compromised or substituted
browser-agent bundle on that page runs with the administrator's session, on the
page whose buttons mint pairing codes and vouch for devices. That is a real path
onto the CA, in exchange for page-load timings on a single-operator admin page
that is opened a few times a week.

**This is now enforced rather than promised.** The console is served with a
`Content-Security-Policy` that starts at `default-src 'none'` and permits one
nonced style block, one nonced script and images from this origin - so a script
from anywhere else does not run, whether it arrived by injection or by somebody
pasting a snippet. `test_console.py` asserts the header.

Signing in moved the password itself off this page entirely - it is typed at the
identity provider - and the session is an HttpOnly cookie no script can read.
Both reduce what a hostile script could take; neither is a reason to invite one
in.

If RUM is wanted anyway, the way to do it safely is to vendor the SDK into the
image, serve it same-origin, and widen that policy by exactly one nonce - so it
is a decision with work attached, not a snippet to paste. Worth deciding
deliberately rather than by default.

**The Datadog Android SDK in the agent.** The DPC asks for four permissions
(`RECEIVE_BOOT_COMPLETED`, `SET_WALLPAPER`, `INTERNET`, `BIND_DEVICE_ADMIN`),
and that clean profile is what may get it past the Play Protect approved-DPC
heuristic - see `docs/android-constraints.md`. Adding an analytics SDK grows the
APK and the permission surface on the one app whose installability is still an
open empirical question.

It is also mostly unnecessary: enrollment, renewal and proof all traverse the
server, so `enroll.*`, `ca.*` and `proof.*` already describe device behaviour
without shipping anything to the phone. What genuinely cannot be seen
server-side is a device that never gets far enough to make a request - and the
answer to that is `agent.apk.served` staying flat.

## Not yet done

- **No APM traces.** `ddtrace` would add a dependency to the process holding the
  CA. The `ca.issue.duration` timing covers the one operation whose latency
  matters today; traces become worth it when there is more than one hop.
- **No monitors.** Nothing alerts on any of this yet. The metrics that deserve
  one first are `enroll.vouch.refused{reason:fingerprint-mismatch}` (any
  occurrence) and `proof.refused{verdict:nonce-used}` (a replay).
