# What is actually deployed, and how to recreate it

Written 2026-08-19, the day the control plane first went up. Everything here was
applied by hand while standing it up; this file is what stops that being the only
record. **If it is not in here it is not reproducible**, and a cluster is not a
backup.

## The live state

**The deployment manifest itself is not in this repo.** It carries real,
identifying infrastructure IDs - a Cloudflare tunnel, a Cognito pool, the
operator's own admin identity - that have no business in an open-source repo.
It lives in a private operations repository, unmodified, comments and all;
this doc describes the shape rather than the exact bytes.

`muster.example` below stands in for whatever zone an operator actually runs
this on. It is RFC 2606 documentation space and will never resolve - substitute
your own hostname, and set `MUSTER_BASE_URL` to it (the server refuses to start
without it, deliberately: see `docs/administrator-sign-in.md`).

    zone        muster.example                   Cloudflare, active
    hostname    enroll.muster.example            CNAME -> cfargotunnel, proxied
    tunnel      a Cloudflare Tunnel, routing enroll.muster.example to the cluster
    route       enroll.muster.example            -> http://muster.muster.svc.cluster.local:80
    namespace   muster
    workload    Deployment muster, replicas 1    ghcr.io/quadseven/muster-server
                THE DIGEST LIVES IN THE MANIFEST AND NOWHERE ELSE.
                It was written out here too once and drifted within a day: a
                repin of the manifest left this line holding the old value,
                so the file whose job is to say what is running was wrong
                about the one field that identifies it. A value copied
                into prose is a value that will disagree with the thing
                that ships - which is why this doc no longer states it.
    service     muster                           :80 -> :8000
    CA          SSM /infra/muster/ca/            CN=<ca-subject>, expires 2036-08-16
    secrets     muster-ca, muster-sign-in, ghcr, muster-db
    kith store  Postgres, CloudNativePG on the LAN
                postgres-rw.databases.svc.cluster.local:5432, database muster
                NOT CREATED YET as of 2026-08-19. Until it is, muster keeps the
                kith in memory, says so at boot and on /readyz, and keeps
                issuing. Step 7 below is what creates it.

## The order it has to be done in

**1. The CA, once and only once.**

```sh
cd server && uv run --group dev --with boto3 python tools/bootstrap_ca.py
```

It REFUSES if `/infra/muster/ca/private_key` already exists. A second CA over
the top of a live one does not fail - it silently orphans every device the first
one ever issued to, and they only find out when their certificate expires.

**2. Secrets into the cluster.** The CA comes from SSM. Administrator sign-in
(`muster-sign-in`, `docs/administrator-sign-in.md`) is no longer optional -
the shared bootstrap token that used to stand in for it before that secret
existed has been removed, so `app_from_env` refuses to start without it:

```sh
kubectl create namespace muster
KEY=$(aws ssm get-parameter --name /infra/muster/ca/private_key --with-decryption --query Parameter.Value --output text)
CERT=$(aws ssm get-parameter --name /infra/muster/ca/certificate --query Parameter.Value --output text)
kubectl -n muster create secret generic muster-ca --from-literal=ca.key="$KEY" --from-literal=ca.crt="$CERT"
unset KEY CERT
```

**3. The image pull secret.** muster is a private repo, so its GHCR package is
private. The token needs `read:packages`:

```sh
kubectl -n muster create secret docker-registry ghcr \
  --docker-server=ghcr.io --docker-username=quadseven --docker-password="$(gh auth token)"
```

**4. The workload.**

```sh
kubectl apply -f <your-deployment-manifest.yaml>
```

See `secret.template.yaml.example`-style documentation for what the five
secrets above need to contain - the manifest itself is intentionally not
checked into this repo (see "The live state" above).

**5. The public route.**

Point your ingress (a Cloudflare Tunnel, or whatever fronts your cluster) at
`enroll.muster.example -> http://muster.muster.svc.cluster.local:80`, then add
the DNS record for it.

**6. Allowlist the domain in NextDNS**, or it is unreachable from the house.
See below - this one is not optional and it does not look like DNS when it bites.

**7. The kith store.** Everything above works without this; what it buys is
muster remembering the devices it has issued to across a restart. NOT YET RUN -
these are the steps, written so the first person to run them is not inventing
them. Each command is against the estate's existing CloudNativePG cluster, from
a machine with `kubectl` on the tailnet.

**Repin the image digest in your deployment manifest FIRST.** An old digest
names a build from before the kith existed, and the manifest is pinned by
digest precisely so it cannot quietly deploy code it does not describe.
Applying it without repinning sets `MUSTER_DATABASE_URL` on an image that has
never heard of it: nothing breaks, and nothing is recorded either, with
`/readyz` carrying no `kith` field at all to say so. The digest comes from
the run summary of `build - server image` on main.

muster gets its OWN database rather than a schema inside an existing one. That
is not tidiness: a different service in this estate once shared one database
and one migration chain with a second app, and running the migration from the
second app wedged that database for two days. A separate database makes that
class of failure impossible rather than unlikely, and muster's whole schema is
two tables.

```sh
# a) The role and the database, on the CNPG primary. The password is generated
#    here and never written to a file - the DSN below is the only copy, and it
#    goes straight to SSM.
kubectl -n databases exec -it postgres-1 -- psql -c \
  "CREATE ROLE muster LOGIN PASSWORD '<generated>'"
kubectl -n databases exec -it postgres-1 -- psql -c \
  "CREATE DATABASE muster OWNER muster"

# b) The tables. The SAME file the server applies on every reconnect, so what
#    was run by hand and what ships cannot disagree about what the tables are.
kubectl -n databases exec -i postgres-1 -- psql -U muster -d muster \
  < server/muster/sql/0001_kith.sql

# c) The DSN into SSM, beside the CA. SSM is the record; the k8s Secret is a
#    copy of it, and a cluster is not a backup.
aws ssm put-parameter --name /infra/muster/database-url --type SecureString \
  --value 'postgresql://muster:<generated>@postgres-rw.databases.svc.cluster.local:5432/muster'

# d) The Secret. --from-literal, NOT --from-file: see the trailing-newline trap
#    below, which cost real time once already on the admin token. The server
#    .strip()s this too, so the trap cannot come back, but a command that plants
#    it is a command the next person copies.
DSN=$(aws ssm get-parameter --name /infra/muster/database-url --with-decryption \
        --query Parameter.Value --output text)
kubectl -n muster create secret generic muster-db --from-literal=MUSTER_DATABASE_URL="$DSN"
unset DSN

# e) Restart, and CHECK. The pod picks the store up at boot and nowhere else.
kubectl -n muster rollout restart deployment/muster
kubectl -n muster exec deploy/muster -- wget -qO- localhost:8000/readyz
#   {"status":"ok", ..., "kith":{"records":"postgres","state":"ok","deferred":0}}
#   "records":"memory" means the Secret is not being read. The env var is
#   optional in the manifest on purpose, so this is the check that replaces the
#   crash you would otherwise get.
```

The role needs CREATE on its own database, because the server re-applies
`0001_kith.sql` every time it opens a connection. That is deliberate: a store
that came back empty - a restored volume, a recreated cluster, a database
nobody ran the SQL against - otherwise leaves the pod perfectly healthy with
every write going to a backlog that will never drain. The file is create-only
and has no ALTER and no DROP in it, and muster is `replicas: 1` with `Recreate`,
so there is no second pod to race and no rolling deploy where two versions
disagree. **The first change that needs an ALTER is the point at which this
needs a real migration story**, and doing it by re-applying a create-only file
will not stretch to one.

## The asset store, and how to put something in it

Bytes a proven device may fetch: the wallpaper today, an agent APK and zippie's
when muster can install (muster#67). **A share on the UNAS, not a Secret** - a
Secret tops out near a megabyte and an APK is ~12.7 MB, which was the only thing
standing between muster and installing an application or updating its own agent.

```sh
# The PVC uses an SMB-backed StorageClass that auto-creates
# k8s/<namespace>/<pvc> as the subdirectory. A hand-made SMB PV does NOT - you
# get `mount error(2)` - which is why this uses the class.
#
# The one thing not in the manifest is the credential, bootstrapped out of
# band like every other SMB consumer in this estate:
kubectl -n muster create secret generic <smb-creds-secret-name> \
  --from-literal=username=... --from-literal=password=...
```

**muster's own mount is read-only, and that is deliberate.** The pod holds a
certificate authority; a process that can rewrite what it serves to devices is a
process that can serve a device something else. Assets are written out of band -
either onto the share directly, or through a short-lived pod with the claim
mounted read-write.

```sh
# Then name it in policy. `muster asset <file>` prints the digest and stanza:
uv run --group dev python -m muster.cli asset ./zippie-wall.png

# kith.wallpaper:
#   image zippie-wall.png sha256 6674edd...
#   surfaces system lock

kubectl -n muster exec deploy/muster -- wget -qO- 127.0.0.1:8000/readyz
#   "assets":{"directory":"/etc/muster/assets","readable":true,"assets":1}
```

`readable` now means muster can ACTUALLY read the share, not that a path was
configured. On a Secret volume those were the same thing; on a share that can
stop answering they are not.

**THREE THINGS THIS STORAGE DOES THAT A SECRET DID NOT**, all of which the code
now accounts for:

- **Unavailability BLOCKS rather than erroring.** A measured 90-second drop hung
  a plain `ls` for 106 seconds and then returned success. Every touch in
  `assets.py` is bounded by `STORAGE_TIMEOUT_S` and abandoned after it, because
  an unbounded read is a request thread muster never gets back - and enough of
  those stop enrollment, not just wallpapers.
- **The SMB CSI driver only runs on nodes that can reach the share.** The
  deployment carries a `nodeSelector` restricting muster to those nodes.
  Without it muster is schedulable somewhere it cannot start, and a pod stuck
  in `ContainerCreating` does not reschedule itself back.
- **A health check must touch STORAGE, not a socket.** A wedged share keeps the
  listener accepting while nothing behind it can read, so `/readyz` reports what
  it actually got from the share - within the bound, so it answers rather than
  hanging and getting the pod killed for it.

An asset the share cannot answer for is a **503**, never a 404. The agent
removes a file absent from a SUCCESSFUL answer, so a 404 would tell a device its
wallpaper had been withdrawn.

## Things that cost time on the first run

**A new domain is dead on this network until it is allowlisted.** The NextDNS
profile has `ddns` and `typosquatting` on, and a freshly registered domain on a
cheap TLD trips one of them. It answers `0.0.0.0`, and the failure presents as
"couldn't connect" rather than as anything mentioning DNS. Every device on the
house network, including the phones muster is for, gets the same answer.

```sh
curl -X POST -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' \
  "https://api.nextdns.io/profiles/$CFG/allowlist" -d '{"id":"muster.example","active":true}'
```

macOS then holds the old answer in its own resolver cache for a while after the
allowlist lands, which reads as the fix not having worked.

**A trailing newline in the admin token locks the console out completely.**
This one was live and cost real time. `print()` appends a newline,
`--from-file=/dev/stdin` stores it, so the server expected `"<token>\n"` while
the console trims what is typed. The correct token returned 401 forever, with
nothing on the login screen to suggest why. The server now `.strip()`s the
configured token, so the trap cannot come back, but the command above is fixed
too - a fix in one place only is a fix that the next person's copy-paste undoes.

**A new image can need a new env var, and the pod is right to refuse.** The
deploy that first served the agent endpoints crashed on `MUSTER_BASE_URL is not
set`. That is the guardrail, not a bug: the provisioning QR carries the address
a device enrolls against, and deriving it from the request `Host` would let anyone
who can set a header point a freshly wiped phone at their own server. The manifest
now states it. Worth knowing because `replicas: 1` means the old pod is gone
before the new one is ready, so this shape of failure is a short outage rather
than a blocked rollout.

**muster#17 added two more variables of that shape.** `MUSTER_CRL_URL` and
`MUSTER_OCSP_URL` are both required: the pod refuses to start without them,
and it refuses to start unless both are plain `http://` URLs with a hostname.
Not https: a verifier fetching a CRL over TLS would need the CRL host's own
certificate verified first, so the standards and every verifier that follows
these URIs use http, and the artifact is trusted because the issuer signs it.
(Until 2026-09-01 the check demanded https; setting the live env to http
against that build crashed the pod for 2m37s. The check is now the other way.)
Each is stamped into every certificate muster issues - the CRL distribution
point and the OCSP entry of the authority information access extension - and
each hostname is the one the matching public endpoint answers on. The refusal
exists because the failure it prevents is a silent one: nothing inside muster
ever follows either URL, so a default would ship unreachable example URIs in
every certificate and serve the endpoints on a hostname no request arrives
with, and nothing would disagree until a relying party did.

**The CA volume needs an fsGroup.** A secret volume is owned by root and the
container runs as 10001, so `defaultMode: 0400` gives `PermissionError` on
`ca.key` and a CrashLoopBackOff. `fsGroup: 10001` plus `0440` is what makes it
readable. The pod crashing there is correct behaviour, not a bug: `Authority.load`
refuses to invent a CA it cannot read.

**`gh auth refresh` fails after a username change.** `hosts.yml` caches the old
name, the browser returns the new one, and gh refuses the mismatch rather than
swapping credentials. Renaming the `user` and `users` keys in
`~/.config/gh/hosts.yml` fixes it and keeps the existing token.

## How the agent APK reaches the pod

Baked into the server image, not mounted beside it.

    check.agent-android.yml   builds the APK on the mac mini, uploads artifact
    build.server-image.yml    downloads the newest successful one from main,
                              COPYs it in at /app/agent/muster-agent.apk
    deployment                MUSTER_AGENT_APK points at that path

The reason it is baked rather than mounted: `/agent.apk` serves bytes and
`/agent.json` advertises the SHA-256 of the certificate those bytes are signed
with, and the two must describe the same file. A separately mounted APK can
drift from the image advertising it, and Android reports that mismatch only as
a generic "can't set up device" - on a phone that has already been wiped.

Two gates make a bad image impossible to publish rather than unlikely:

- The Dockerfile `COPY` fails the build if no APK was downloaded, so an image
  is never published whose provisioning QR points at a 404.
- A build step reads the signing certificate out of the APK **inside the built
  image** and prints the checksum to the run summary. An APK that is unsigned,
  or signed only with v2/v3, fails here rather than on the handset.

A `workflow_run` trigger rebuilds the image when the agent workflow succeeds on
main; without it a new agent would be built and never served.

## What happens when the kith store is unreachable

**muster keeps issuing and keeps renewing.** This is the deliberate answer, it is
in `server/muster/kith.py` and it is tested; it is not a hope about how Postgres
behaves.

The reason is that the two failures are not comparable. A device's membership of
the kith IS its certificate - there is no enable flag (`CONTEXT.md`) - so nothing
in the database is ever consulted to decide whether to sign. If it were:

    store down, issuance continues   a device list missing some rows, filled in
                                     when the store answers again
    store down, issuance stops       every device whose certificate expires
                                     during the outage LAPSES

and lapse is not a retry. A lapsed device cannot renew its way back; it enrolls
again from a fresh pairing code with a human holding it, and for a Device Owner
phone that means a factory reset. A stale device list is a worse graph. A lapsed
fleet is a day of work per handset.

So, concretely, while Postgres is away:

- **Writes are deferred, never refused.** Issuance, "last seen" and "collected"
  go into a bounded in-memory backlog and are replayed when the store answers.
  A background thread retries every 60s, because muster is quiet by design and
  waiting for the next request could be weeks.
- **Reads return 503, never an empty list.** `GET /v1/kith` says the store is
  unreachable. An empty list reads exactly like a fleet that has vanished, and
  sends whoever is looking after phones instead of after a database.
- **`/readyz` stays 200** and reports the store as a field. Going unready would
  have Kubernetes pull the pod out of the Service, which stops enrollment and
  renewal for everything - the outage this design survives, arrived at through
  the health check instead of through the code.
  THAT HAPPENED ANYWAY, ONCE, BY TIMEOUT RATHER THAN BY VERDICT (2026-09-02
  05:40:13Z to 05:41:14Z, 61s). The probe in the ops-repo manifest allows
  `timeoutSeconds: 1`; at 05:40:00Z four cron jobs started on the pod's node,
  `/readyz` (a few filesystem touches through a thread pool) took longer than
  a second eight probes running, and the pod left the Service with no
  restart, no error, and `/livez` passing throughout. Nothing was refused
  that the logs can see - the next handset check-in was 05:41:29Z - but
  with `Recreate` and one replica that minute was an enrollment outage. The
  fix is the probe timeout in the manifest, which is Infra's; it landed as
  Deployment revision 44 at 05:49Z the same morning (readiness and liveness
  `timeoutSeconds: 5`, same image, http env), applied from the ops repo.
- **Collection answers 503, not 404.** The agent treats 404 as "gone, stop
  polling" and anything unrecognized as retryable, so a 404 caused by a database
  would tell a device to abandon a certificate muster really did sign.
- **The store is left alone for 30s after a failure**, so requests during an
  outage do not each pay a connect timeout. "It does not fail" is not enough; it
  must not block either, or a control plane that is merely very slow gets
  debugged as though it were down.

**What is genuinely lost.** A deferred write lives in one pod's memory. If the
store is unreachable AND the pod restarts before it recovers, those rows are gone
- the devices keep working, because their certificates are their membership, but
muster will not list them again until they renew or prove possession. The backlog
holds 512 entries and drops the oldest beyond that, counting
`custom.muster.kith.write.dropped` when it does; an unbounded one would turn a
store outage into an OOM kill, which would stop issuance by the back door.

Metrics worth a monitor: `custom.muster.kith.store.unreachable`,
`custom.muster.kith.write.dropped`, and the `deferred` count on `/readyz`.

## Why replicas: 1, and what it would take to change

**Still the enrollment queue, no longer the kith.** The kith is now written down
and shared, so a device that has been issued to survives a restart and would be
visible to any pod. What is still in memory is the short-lived half of the
ceremony: the pairing codes, the pending requests, and the certificate held
between a vouch and the device collecting it. A device that presents to pod A is
still invisible to a console talking to pod B, and the vouch still returns 404.

Making the queue shared is the remaining piece, and it is a genuinely different
decision from this one: pending state is minutes-lived and costs one pairing code
to recreate, so the availability argument that shaped the kith store does not
transfer to it unchanged. Shared state first, then the number - two decisions, in
that order.

## What is NOT done yet

- **Edge mTLS.** Cloudflare has not been given the CA, so nothing validates
  client certificates at the edge. `/v1/enroll/*` must stay open regardless - a
  device enrolling has no certificate to present - but everything else should
  require one.
- **Access on the console.** Administrator sign-in (Cognito) is the only way
  in - the shared bootstrap token was removed. It needs an application client
  in the estate's identity provider and a `muster-sign-in` secret, both of
  which are a human's job - `docs/administrator-sign-in.md` says exactly what.
  `app_from_env` refuses to start without it. Like everything else here, none
  of it is in Pulumi yet.
- **The revocation hostnames ARE at the edge, by hand (2026-09-01 22:01Z).**
  Until that moment this bullet said "the tunnel still routes only
  `enroll.muster.example`" and warned that the extensions in issued
  certificates pointed somewhere unreachable. Now the tunnel's remotely
  managed ingress (configuration version 12) routes `crl.*` and `ocsp.*` to
  the same Service as `enroll.*`, two proxied CNAMEs exist in the zone, and
  the Deployment (revision 43, since 22:32Z; revision 39 first set them, over
  https, which was wrong) sets `MUSTER_CRL_URL` and `MUSTER_OCSP_URL` to
  those hostnames over plain http. What is still true: certificates issued BEFORE that moment
  carry no distribution point and gain one at renewal, at the pace devices
  choose; and every one of those three changes was applied by hand, so the
  next bullet applies to them too. The tunnel's ingress in particular is
  declared in Pulumi as a shorter list than what is live, and an apply of
  that path would remove these routes along with every other hand-added one.
- **Nothing is in Pulumi.** The estate's standing rule is that infrastructure is
  IaC; all of the above was applied by hand to get the thing standing. This file
  is the interim record, not the destination.
