# State of play

Dated 2026-08-19. **Everything here was verified live on that date, not
remembered.** The reference docs beside this one explain *how* each piece works;
this one says what is standing, what is not, and what the next person should not
rediscover the hard way.

## What works, proven end to end

Verified against `enroll.muster.example`, not inferred from a green build:

    admin sign-in            200 with the token, 401 without
    mint a pairing code      6 digits, single use, expires in minutes
    GET /agent.apk           200, 12.6 MB
    GET /agent.json          checksum computed from the bytes served
    proof of possession      challenge / verify

The enrollment ceremony and the identity machinery are the finished part.

## Revocation is wired, not measured

Written 2026-09-01 with no handset attached. An administrator can revoke a
device with `POST /v1/kith/{key_id}/revoke`, and `_proven_device` refuses that
key on its next request. The agent turns the resulting 403 into
`ConfigurationClient.Fetched.Revoked`, records the state in device-protected
storage, and keeps enforcing its last known configuration. Wipe is a separate
state and must be delivered before revocation; see D27 and D29 in
`DECISIONS.md`.

This is written, not measured on a device. The server and JVM suites prove the
refusal, the response mapping and the durable agent state, but no handset has
made a post-revoke request in this period. The next-request behavior, including
the fifteen-minute periodic path, remains unmeasured on hardware.

## Periodic check-in is wired, not measured

Written 2026-09-01 with no handset attached. `CheckInJob` is declared in the
manifest and scheduled from `MusterDeviceAdminReceiver`; its fifteen-minute
periodic run executes the same `BootPlan.STEPS` as boot and the status-screen
sync. That means configuration fetch and renewal are reached by the existing
check-in rather than by separate schedulers. `CheckInSchedulePolicy` carries
the interval and the network/catch-up rules.

This is written, not measured on a device. JVM tests prove the schedule shape
and that the job runs the boot plan, but no handset has run the periodic job or
shown that a real network check-in reaches muster.

## Automatic renewal is wired, not measured

Written 2026-09-01 with no handset attached. The agent now puts renewal in
`BootPlan.STEPS`, so the existing fifteen-minute check-in acts on
`IdentityLifecycle.Stance.ShouldRenew`; the request proves possession with the
same nonce, signature and certificate as configuration fetches, and its CSR is
made from the existing keystore key. JVM tests prove that request shape, that
the CSR carries the existing public key, and that all four returned identity
fields, including `renew_after`, reach the identity store. The server suite
proves that the same key remains one device with two certificates.

That is not the acceptance measurement. No test without a handset proves that
Android Keystore signs both the proof and CSR in direct-boot conditions, that
the periodic job reaches the route on a real network, or that the replacement
certificate authenticates the next check-in. Date-mark this measured only after
a device past `renew_after` has done those things with no person present and
`GET /v1/kith/{key_id}` reports one device with two certificates.

**That first line is the deployed pod, not the code.** Since #36 an administrator
signs in at the estate's identity provider, but nothing is applied: it needs an
application client and a secret, which are a human's job.
`docs/administrator-sign-in.md` says what, and `docs/what-is-deployed.md`
carries the same caveat.

**The console's Provisioning section is code, not a measurement.** #47 puts the
provisioning QR on the page, checked against `/agent.json` before it is drawn,
and there is no pairing QR any more because nothing on a device could read it.
That was driven in a browser against a local server; it has not yet been used
against `enroll.muster.example`, so it is deliberately not in the list above.

**And, later the same day, on hardware.** A wiped Pixel 6a - <device-serial>,
Android 17 - scanned a provisioning QR and came up owned by muster, with no
cable attached at any point:

    Device Owner: app.muster.agent/.MusterDeviceAdminReceiver  testOnlyAdmin=false
    Device policy global restrictions: no_safe_boot, no_config_date_time
    files/server-url    written 11:25, during provisioning
    files/identity/device.crt   546 bytes, 11:31

Read carefully, because these prove different amounts and the temptation is to
quote them as one result:

- **Provisioning by QR is proven.** Ownership, from a QR, without a cable. This
  is the route `android-constraints.md` recorded as CLOSED until that morning.
- **The server address arriving in the QR is proven.** Nothing on a laptop wrote
  that file; the admin extras bundle did, during setup.
- **A pairing code arriving the same way is NOT proven.** Written 2026-08-19,
  after that run, so no handset has ever carried one. It travels in the same
  bundle, is written to the same directory by the same activity, and is read back
  the same way - which makes it likely and does not make it measured. What is
  unmeasured is the whole hands-free path: the code landing, the agent presenting
  itself during provisioning, and the certificate being collected before the
  compliance screen gives up. The typed path is what has actually put a
  certificate on a phone.
- **Policy enforcement is proven.** Two restrictions in force after a reboot.
- **The issued identity is proven, but only because the certificate itself was
  read.** The directory alone would not have shown it: `files/identity/` is
  created by the identity store's constructor when the enrollment screen opens,
  so its existence says the agent launched and nothing more. What settles it is
  `device.crt`, parsed off the device:

        subject = CN=Pixel 6a
        issuer  = CN=<ca-subject>
        serial  = <device-cert-serial-hex>
        notAfter= Nov 17 15:30:14 2026 GMT

  That serial is `<device-cert-serial-decimal>` in decimal,
  which is the one the CA logged when it signed. Server-side issue and
  device-side possession are the same certificate, not two claims that agree.

**One device, one Android version, one day.** The Play Protect approved-DPC
check behaves like a heuristic rather than a strict list, so this is a
measurement and not a guarantee. `android-constraints.md` carries the caveats in
full and they are not decoration.

## The one thing blocking a real device

**The agent is debug-signed.** Its signing-certificate checksum on 2026-08-19
was `sFwqKgjnKGoge3NeLs3_WsiUni6Dzxe24CQuX4KYnYE`.

The provisioning QR carries the SHA-256 of the signing certificate, and a Device
Owner **cannot** be replaced by an APK signed with a different key. So the key
the first device enrolls against is the key forever, and changing it later means
factory-resetting every enrolled device.

`docs/signing-ceremony.md` has the ceremony. It is interactive by design -
`keytool` prompts, passwords never in an argument list - so it is a human's job
and not something to automate. Everything around it is already wired: the build
reads the keystore from the environment, refuses one inside the checkout, fails
loudly on half-seeded secrets, and makes an unsigned `packageRelease` a red
build.

> **Do not generate and scan a provisioning QR, for any device that matters,
> until the ceremony is done.** `/v1/provision/qr.svg` is admin-only so nothing
> enrolls by accident, but a QR minted today installs a debug-signed agent and
> binds that handset to a throwaway key that lives, unbacked-up, on one mac
> mini.

**That warning was overridden once, deliberately, on 2026-08-19.**
<device-serial> was provisioned by QR carrying nothing anybody needs, to answer
the Play Protect question the only way it can be answered. The cost is exactly
what this section says: that phone is bound to the debug key and owes one more
factory reset when the release-signed agent ships. `check.agent-android.yml`
still runs only `assembleDebug`, which is the reason to believe that is the key
it carries - inferred from the build rather than read off the handset. The
warning stands for every other device.

After the ceremony: seed the four repo secrets, switch `check.agent-android.yml`
to build and publish the release variant, redeploy, and record the new checksum
in `docs/what-is-deployed.md`.

**The ceremony also takes `muster wallpaper`, `muster restrictions`,
`muster visible-apps`, `muster app-config` and `muster provision --server-url`
away.** All five write into a directory only the app can write to, using
`run-as`, and `run-as` refuses a package that is not debuggable. They fail
loudly rather than silently.

**The replacement now exists for three of the five** (#46): an enrolled device
fetches `restrictions`, `visible-apps` and `app-config` from the control plane
over the identity it holds, at every boot - `POST /v1/device/config`, described
in `policy.md`. `muster wallpaper` still needs a cable, because a PNG needs
asset hosting (#45), and `muster provision --server-url` is how a device that
has no identity yet learns where to enroll, which is by definition before it can
fetch anything.

**Not measured on a handset.** Written on 2026-08-19 with no device attached.

## What the agent actually enforces

**Whatever the restrictions file says**, from a fixed vocabulary. See
`policy.md`. **Measured on a device, not just tested:** `no_safe_boot` and
`no_config_date_time` were read back in force off <device-serial> on 2026-08-19,
after a reboot, which is the boot reconcile doing its job on hardware.

**Whatever the `visible-apps` allowlist says**, since #35: the packages named
stay on the launcher and everything else with an icon is hidden, both ways, with
Settings, the launcher, the setup wizard and muster itself refused. `policy.md`
has the whole thing, including the two `PackageManager` flags without which it
would silently do nothing. **Written and tested on a laptop, and NOT measured on
a handset** - nobody has looked at a launcher since it was written, which is the
only place it can be confirmed.

Getting that file onto a device was the broken half. `muster restrictions` and
`muster wallpaper` copied through `/data/local/tmp`, and the agent's files
directory is `0700` rather than world-traversable as the code assumed, so
nothing landed - that is #20, and the `run-as` command recorded there is how the
two restrictions above reached that phone by hand. Both commands now write that
way, and so does `muster provision --server-url`, which had the same defect.
**Fixed in code, unproven on hardware:** nothing has been run against a handset
since the change. It is also still the argument for serving configuration from
the control plane instead: a device that enrolled over the air should not need a
laptop on its LAN to be configured, and `run-as` only works while the agent is
debug-signed.

Until 2026-08-19 the honest answer was **nothing**. `DISALLOW_SET_WALLPAPER` was
the only restriction in the codebase and it was added by `WallpaperSteward.lock()`,
whose one possible caller was `reconcile(lockAfterwards = false)` - and nothing
anywhere passed `true`. The decision function had three passing unit tests over a
path production could not reach, so the suite was green across a capability that
did not exist. Worth remembering as a shape, not just as a fixed bug.

The wish list is wallpaper, an 80% charge cap, installing zippie, and settings.
Of those:

- **Wallpaper** - done.
- **80% charge cap** - *impossible from the QR.* Android allowlists which secure
  settings a Device Owner may write and charging-optimization is not among them.
  quadseven/zippie's `docs/android-device-management.md` established this
  independently; zippie sets it over adb
  (`settings put secure charge_optimization_mode 1`). Wireless adb works, so it
  need not be a cable, but it will always be a step outside enrollment.
- **Settings** - done, as user restrictions; `policy.md` lists what is
  managed and the two entries that can strand a device.
- **Configuring an app on the device** - built, and **not proven on a
  handset**. `setApplicationRestrictions` and `setPermissionGrantState`, driven
  from an `app-config` file pushed the same way as the restrictions one, which
  is what lets a write token reach zippie's relay without a person typing it
  into the phone. The parser, the plan and the refusals have JVM unit tests; the
  two platform calls have none, because they need hardware. **What settles it is
  the phone appearing in the bond, not the call returning** - the same
  distinction that cost this repo three documents once already. No new manifest
  permission: both are Device Owner privileges, so the four-permission profile
  that cleared Play Protect is untouched.
- **Installing zippie** - not built. The agent side is genuinely
  buildable (a Device Owner installs silently through
  `PackageInstaller`, and needs no extra manifest permission to do
  it), but there is nowhere for an APK to live yet: the pod is
  `readOnlyRootFilesystem: true` with no volume, so distribution is
  a storage decision before it is a Kotlin one. `cli.py provision
  --also-install` already covers the cable case.

Because a stable release key makes every later agent update a silent install
over the top, this policy work costs no additional wipe **provided the ceremony
happens first**. That ordering is the whole reason it comes first.

## The kith is a record now, and what that has NOT been run against

muster remembers the devices it has issued to: `server/muster/kith.py`, two
tables in `server/muster/sql/0001_kith.sql`, and `GET /v1/kith`. A device is its
KEY, so a renewal is a second certificate on the same device rather than a second
device - which is the property the tables exist for.

**Unproven, and it is the important half.** There is no Postgres on the
workstation and none on the CI runner, so the SQL in `0001_kith.sql` and every
statement in `PostgresRecords` **has never been EXECUTED by a real server.** Read
that precisely, because three different amounts of proof are easy to run
together:

- **Syntax is proven.** `pglast` embeds PostgreSQL's own parser and the suite
  parses every statement and the schema on each run. That settles `serial` as a
  column name, `GREATEST` on `timestamptz`, and the `GROUP BY` on the primary
  key.
- **The driver and the failure path are proven.** `app_from_env()` has been
  booted with a DSN pointing at a port with nothing on it: the pod comes up, a
  certificate is signed and collected, `/v1/kith` answers 503, and the whole run
  takes under a second rather than a connect timeout per request. The image build
  runs the same shape inside the alpine image, which is what caught psycopg being
  packaged wrongly.
- **Meaning is NOT proven.** A column that does not exist parses perfectly, and
  nothing here has checked that the `muster` role may actually CREATE, INSERT or
  SELECT. That is settled by step 7 of `what-is-deployed.md` being run once, and
  `/readyz` then reporting `"records":"postgres"` with `"state":"ok"` and
  `"deferred":0`.

Everything else about the kith - the identity rule, the deferral, the cooldown,
the backlog bound, the poison-row drop, readiness staying ready - is tested
against a store that can be broken and mended on demand, and does not depend on
a database at all.

The store does not exist yet either. Until an operator creates it, muster keeps
the kith in memory, says so at boot and on `/readyz`, and keeps issuing.

## Deliberately not done

- **Browser RUM on the console.** The console is the administrator's surface on
  the service that holds the CA, and RUM means a third-party script running
  there with their session. The page now carries a `Content-Security-Policy`
  that refuses one, so this is enforced rather than promised. See
  `docs/observability.md` for what it would take to do safely.
- **The Datadog Android SDK in the agent.** Its four-permission profile is what
  a QR-provisioned Pixel cleared the Play Protect approved-DPC heuristic with on
  2026-08-19 (`docs/android-constraints.md`), and the server already sees
  enrollment, renewal and proof without shipping anything to the phone. Which
  permission mattered is not knowable from one result, so a fifth permission is
  now a decision with a wipe behind it rather than a dependency bump.
- **Edge mTLS** (#1). Cloudflare accepts a custom CA for client certificates on
  Enterprise only, and Tunnel opens a new origin connection so a certificate
  presented at the edge never reaches the pod. That is why possession is proven
  at the application layer in `proof.py`. Settled; not worth re-deciding.
- **Pulumi for muster's k8s and Cloudflare resources.** Still hand-applied.
  `docs/what-is-deployed.md` is the interim record, not the destination.

## Traps already paid for

Each of these cost real time once. They are recorded where they belong, listed
here so nobody has to find them twice.

- **A trailing newline in the admin token locks the console out completely**, and
  does it while showing a correct token being rejected. See
  `docs/what-is-deployed.md`.
- **`replicas: 1` with `Recreate`** kills the old pod before the new one is
  ready, so a bad environment variable is a short outage rather than a blocked
  rollout.
- **v1 signing must stay on for release builds.** apksigner chooses by minSdk and
  at 29 it skips the v1 JAR signature - but muster reads the signing certificate
  out of the v1 PKCS#7 block. A v2-only APK builds green and can never provision
  anything. Checked twice: pinned in the build, and re-read out of the baked APK
  by the image build.
- **A DPC that cannot answer the provisioning intents factory-resets the phone.**
  Measured 2026-08-19: a wiped Pixel scanned a QR, downloaded the agent (logged
  server-side, 200, 12,606,023 bytes) and then failed with "Something went
  wrong" and a Reset button. The agent declared no activity for
  `GET_PROVISIONING_MODE` or `ADMIN_POLICY_COMPLIANCE`, which AOSP says "will
  cause the provisioning to fail" - and "if provisioning fails, the device is
  factory reset". This is also the correction to `android-constraints.md`:
  Route 2 was recorded as closed behind Play Protect, and that gate was never
  actually reached. The next attempt, once both activities existed, provisioned
  cleanly - so the file now records Route 2 as open, measured once.
- **A verdict can be a failure that happened before the gate.** The CLOSED
  finding above was a real failure plus real documentation about a real gate,
  added together into a conclusion nothing had tested. It cost three documents
  written around a cable. Worth remembering as a shape: when something fails
  short of the thing you were trying to test, the thing you were trying to test
  is still untested.
- **`custom.muster.agent.apk.served` is the signal that a provisioning attempt
  began**, and it earned its place here: it is what proved the download
  succeeded and moved the search past the QR, the checksum and the network.
- **The agent's own directory is closed to the adb shell user.** Measured on
  <device-serial>, 2026-08-19: `muster restrictions` staged the file in
  `/data/local/tmp` and `cp`-ed it across, and nothing arrived. The directory is
  `drwx------` owned by the app's uid, so uid 2000 cannot write in it or even
  traverse it - and the comment in the code claimed the opposite. The read-back
  at the end of the command was the only thing that noticed, which is the whole
  argument for ending every device command by asking the device.
- **The agent can only be built in CI.** There is no Android SDK on the
  workstation; `check.agent-android.yml` on the mac mini is the build, not a
  duplicate of a local one.
- **A pty turns a diagnostic into a credential leak.** `place_file` streams its
  payload down stdin and ends by quoting whatever the device said; an adb
  without shell protocol v2 runs the remote command under a pty, and a pty
  echoes stdin back on stdout. That was harmless mojibake for a wallpaper and
  is a write token on a terminal for `muster app-config`. The payload is now
  declared secret at that one call site rather than trusted not to come back -
  the same shape as `telemetry.event`, where one function drops the secret
  instead of a dozen call sites remembering to.
