# What muster makes a device do, and what it cannot

Written 2026-08-19. Policy here is three things a Device Owner controls:

- **user restrictions** - the `DISALLOW_*` surface, which is what the device
  itself may do. Deliberately not `setSecureSetting`, which Android has narrowed
  to a handful of keys across releases; restrictions are the part that has
  stayed.
- **managed application configuration** - what an app on the device is
  configured with, and which runtime permissions it holds. See
  [below](#configuring-an-app-on-the-device); it is the difference between
  owning a phone and managing one.
- **which applications a person can see and launch** - the allowlist at the end,
  under "Which applications the device shows".

Restrictions come first below, then app configuration, then the allowlist. How
any of it reaches a device is ["How policy reaches a
device"](#how-policy-reaches-a-device), near the end.

Read `android-constraints.md` first if you have not. It explains why this agent
is a Device Owner at all, by which of the two routes - QR since 2026-08-19, or
adb - and it is where the device-measured findings quoted below come from.

## Where the restrictions live

A plain text file in the agent's device-protected files directory, beside the
wallpaper and the server URL:

    /data/user_de/0/app.muster.agent/files/restrictions

One name per line, `#` starts a comment, blank lines ignored:

    # kitchen display - it is an appliance, not a phone
    DISALLOW_SET_WALLPAPER
    DISALLOW_UNINSTALL_APPS
    DISALLOW_SAFE_BOOT

Push it with:

```sh
uv run --group dev python -m muster.cli restrictions <serial> --file ./kitchen.restrictions
```

That writes the file **as the agent**, with `run-as`. The directory is
`drwx------` owned by the app's uid, so nothing the adb shell user does can put
a file in it; `run-as` in turn needs a debuggable package, so this route ends at
the signing ceremony rather than degrading. It fails loudly when it does, and
the device is asked for the file's sha256 afterwards rather than trusted.

**A device that has enrolled does not need this at all any more.** It fetches
the same file from the control plane - see ["How policy reaches a
device"](#how-policy-reaches-a-device). This route is for a device that has not
enrolled yet, and for a cable in hand.

**Fixed in code on 2026-08-19 and not yet re-measured on a handset.** The
`run-as` command itself did place a file on <device-serial> by hand; the command
above has not been run against a phone since it changed.

**It is a file and not a build for the same reason the wallpaper is.** This app
is Device Owner, so anything baked into the APK can only be changed by a
release, and a release eventually costs a factory reset when the signing key
moves.

## When it takes effect, and how to see what happened

At the next boot. The agent reconciles at `BOOT_COMPLETED` and
`LOCKED_BOOT_COMPLETED`, which is why the file lives in device-protected
storage - an appliance on a charger in a cupboard may not be unlocked for days.

Anything the agent will not act on is named in the log:

```sh
adb logcat -s muster
```

That is not a nicety. A restriction name that muster does not recognize is
**refused rather than skipped**, because a silently ignored line leaves a device
with no restriction and a config file on it that reads as though it has one.

## Erasing a device, and how long that takes

An administrator can tell a device to erase itself:

    POST /v1/kith/{key_id}/wipe   {"wipe": true}

**Order matters and the API enforces it.** Revoking a device stops muster
answering it at all, which also removes the channel a wipe would travel down.
So wipe is a separate state that is deliberately still served: mark the device
wipe-pending, let it collect the instruction, and revoke afterwards. Revoking
first produces a wipe that can never arrive. `DECISIONS.md` D29 has the full
argument.

It is reversible - `{"wipe": false}` calls it off - because an administrator can
name the wrong `key_id` and the alternative to a way back is a factory reset
nobody intended.

**HOW LONG IT TAKES, STATED HONESTLY, because the number is the whole value of
the feature:**

    powered, networked, awake     <= 15 minutes (the check-in floor)
    doze or a rare standby bucket hours
    no network                    until it returns - unbounded
    powered off                   until it boots - unbounded

**The worst case is unbounded**, which is the same sentence `CONTEXT.md` uses to
justify lapse. Read that before relying on this:

- Against a holder who is careless, or does not know the device is managed, and
  against decommissioning a device you have in your hand - this works, and
  fifteen minutes is genuinely fast.
- Against somebody competent it does nothing. They put the handset in airplane
  mode, or pull the SIM, before anybody acts, and the wipe never lands.

Reaching a device that has gone dark requires the device to enforce a deadline
on itself with no network, which is a different and considerably more dangerous
mechanism - a phone whose router breaks for long enough would erase itself.

## An absent restrictions file and an empty one mean different things

    no file        nothing has been configured; the device is left as it is
    empty file     no restrictions; anything muster set is withdrawn

Collapsing those two would make a first boot on an unconfigured device
indistinguishable from a deliberate instruction to unlock everything.

Reconciling goes **both ways**. A name deleted from the file comes off the
device at the next boot. Policy that only ever adds is a ratchet, and the only
way to undo a ratchet on a Device Owner is a factory reset.

## What muster manages

Only these are ever **cleared** by muster. A restriction set by something else is
left exactly as it is - muster is not necessarily the only admin that ever
touched this device, and a reconciler that withdraws what it does not recognize
is one that quietly undoes somebody else's decision.

| Name | What it is for |
|---|---|
| `DISALLOW_SET_WALLPAPER` | the appliance keeps the picture it was given |
| `DISALLOW_UNINSTALL_APPS` | zippie cannot be removed from Settings |
| `DISALLOW_APPS_CONTROL` | nor force-stopped, nor its data cleared |
| `DISALLOW_INSTALL_UNKNOWN_SOURCES` | nothing sideloads onto an appliance |
| `DISALLOW_SAFE_BOOT` | safe mode starts the device with admins disabled |
| `DISALLOW_ADD_USER` | a second user is a second place policy does not apply |
| `DISALLOW_CONFIG_DATE_TIME` | the clock is load-bearing; see below |

**The clock one is not housekeeping.** The agent decides whether to renew its
certificate by comparing now against its own certificate's dates, and
`IdentityLifecycle` is tested against exactly the state a wrong clock produces.
A device whose time can be moved by hand can be talked out of renewing, or into
believing it has already lapsed.

## Installing applications

muster hid the Play Store because an appliance has no business showing one, and
thereby took responsibility for updates it could not perform. Until muster#67
the only route from a built APK to a handset was a factory reset and a QR scan -
which also threw away the device's identity, its policy and its enrolment, to
change a file.

`install-apps` is a managed file that NAMES applications rather than carrying
them, the same shape as `wallpaper`:

    install app.zippie.companion zippie-0.1.0.apk sha256 3f2a... version 72

The bytes come from the asset store over the device's own identity and are
checked against that digest before anything is installed. **A line without a
digest is refused, not warned about.** An agent that installs whatever a server
hands it is a remote code execution primitive carrying a certificate.

`version` is the APK's `versionCode`, and it is what makes this idempotent
without hashing what is already installed: a device at or past that number does
nothing. Without it, every boot re-downloads twelve megabytes.

**A device already carrying a NEWER version is left alone.** Android refuses a
downgrade, so attempting one is a guaranteed failure reported at every boot -
and a newer version is also what a hand-installed build looks like.

**One refused line does not withhold the others**, which is deliberately the
opposite of `visible-apps`. Hiding is destructive and a typo there strips a
phone. Installing is additive, and withholding every install because one line is
wrong denies a device the software it needs in order to protect it from having
extra software.

### muster updates itself last, twice over

Committing muster's own install ends the process. So `install-apps` is the LAST
step in the boot plan, and muster is the LAST entry within it. A boot that
updates the agent has already applied the restrictions, the app configuration
and the app visibility; anything queued behind the agent would simply never run,
and the next boot would find the agent current and skip it all again.

Nothing after a commit is relied on. The next reconcile asks the platform what
version is installed, which is the answer that cannot go stale and cannot be
missed because a process died mid-way.

### The signing key is now load-bearing for the whole fleet

**An update requires the SAME signing key.** A different key is refused as
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`, and a Device Owner cannot be uninstalled
without a factory reset - so a key change is a wipe of every enrolled device,
permanently, with no way back.

That makes the keystore the single most valuable thing in this project. See
`docs/signing-ceremony.md`; do the ceremony BEFORE enrolling devices you would
mind wiping, because every device enrolled before it is enrolled against a key
that is going to change.

## Roles: what a device is FOR

A role is chosen when a provisioning QR is minted, and it is the only moment
anything knows what a device will be - it has no identity yet, and policy is
keyed on one. So the role rides the pairing code, and the certificate that comes
back writes it into the kith.

Policy is then looked up MOST SPECIFIC FIRST, per file:

    <key_id>.restrictions        this device
    role-zippie.restrictions     every device with this role
    kith.restrictions            every device

**The fallback is per FILE, not per device.** A role says what is DIFFERENT
about a set of devices; making it restate the fleet's whole policy is how the
two drift, and the drift is silent because both files look maintained.

**A role MAY carry `app-config`. The kith may not.** That is the point of roles
and it is a deliberate security trade. `kith.app-config` is never served because
that file holds write tokens and the kith is every device in the estate. A role
is narrower and is exactly what "make it a zippie android so it does zippie
config" means: the zippie token reaches the zippie androids. It is still a
credential shared by every device carrying the role - a role is a statement that
those devices are interchangeable, and interchangeable devices share what they
run.

**A device never names its own role.** It is read from the kith on every fetch.
A device that could name one could ask for another role's credentials.

**An empty role never overwrites a set one.** Re-enrolling a handset against a
plain QR would otherwise strip it silently, and the symptom is a zippie android
that quietly stops being one. To CHANGE a role, mint a QR naming the new one.

**A role survives renewal**, because it is on the device rather than the
certificate. A device does not stop being a zippie android in ninety days.

Roles are `[a-z]([a-z0-9-]*[a-z0-9])?`, at most 31 characters. Narrow because a
role becomes half of a policy file name and therefore a Kubernetes Secret key;
a dot is refused outright, since the scope is split on the first one and
`role-a.b` would silently address a scope nobody wrote.

## The wallpaper, and the screens it goes on

`wallpaper` is a managed file like the others, and it is the only one that does
not carry what it describes. It NAMES an asset and the digest to expect:

```
image wall.png sha256 3f2a...
surfaces system lock
```

The bytes travel over their own route (`POST /v1/device/asset`) and are checked
against that digest before anything is applied. So a substituted image is caught
by a file the device fetched over its own identity, rather than trusted because
it arrived - and this estate has already had a CDN serve a handset a stale APK
for four hours while the endpoint describing it stayed current.

`surfaces` may name `system`, `lock`, or both, and defaults to both. Before
muster#41 the agent called the one-argument `setBitmap`, which sets `FLAG_SYSTEM`
alone - so a managed appliance carried its own background behind the apps and a
stock one on the screen anybody walking past actually sees.

**The record says which screens, not just which image.** A device that applied a
wallpaper before the policy gained a `surfaces lock` line would otherwise
believe it was done and never apply it.

**A screen the policy stops naming is reported, not cleared.** Clearing a
wallpaper is destructive and irreversible from the device's side - the image it
replaced is gone - and the trigger would be a word disappearing from a text
file, which is as easily a typo as an instruction. The device says so on its
status screen instead.

**Three ways this reports nothing happening**, all of which reach the status
screen and `logcat -s muster:E`:

| what it says | what it means |
| --- | --- |
| `SUBSTITUTED` | the bytes arrived and are not the bytes the policy named |
| `COULD_NOT_FETCH` | named an asset and could not get usable bytes for it |
| `REFUSED` | a line of the file could not be acted on - usually a typo |

## The two that can strand a device

These are real and occasionally wanted, and neither is reachable by a typo. Each
needs the word `accept-stranding` on the same line:

    DISALLOW_FACTORY_RESET accept-stranding

**`DISALLOW_FACTORY_RESET`** removes the last local way back into a device.
`android-constraints.md` records this measured on <device-serial>: a commercial
MDM set it, and the phone "cannot be freed from Settings" as a result. The
supported exit was the vendor's own remote wipe. **muster has no wipe command.**

**`DISALLOW_DEBUGGING_FEATURES`** turns off adb, and adb is the only route to the
80% charge cap - which no Device Owner can set by policy at any API level.
Setting this remotely closes the door from the inside: undoing it is itself a
change on a device nobody can reach any more.

Neither is in the managed table above, so muster will never withdraw one on its
own. Taking one back off is a decision to make in front of the device.

## Configuring an app on the device

Restrictions say what the device may do. This says what an app on it is
configured with, and it is the part that turns an installed application into a
contributing one.

Measured on <device-serial>, 2026-08-19:

    package:app.zippie.companion   installer=null
    ps: app.zippie.companion running
    dumpsys activity services app.zippie.companion: NOTHING

Installed, launched, and absent from the bond it exists to join - because
announcing itself needs a write token that only a human could type in. A Device
Owner can push that token as an **application restriction**, which the app reads
through `RestrictionsManager`. muster does that, and grants runtime permissions
the same way with `setPermissionGrantState`.

### Where it lives

A second plain text file beside the first:

    /data/user_de/0/app.muster.agent/files/app-config

Verb first, then the package, then the key, then the value:

    # a LAN-local relay leg
    set       app.zippie.companion homeHost       192.168.1.11
    set       app.zippie.companion announceToken  <the write token>
    set-bool  app.zippie.companion autoStartRelay true
    grant     app.zippie.companion android.permission.POST_NOTIFICATIONS

Push it with:

```sh
uv run --group dev python -m muster.cli app-config <serial> --file ./kitchen.appconfig
```

Same route as the restrictions file, with the same expiry date on it: written as
the agent with `run-as`, verified by the sha256 the device computes, and dead the
day the release-signed agent ships. Applied at the next boot.

### The format, and the two places it is deliberately awkward

**The package is on every line.** There is no section header. A mistyped
`[package]` header silently assigns every key beneath it to the wrong app, and
the key most likely to be under one is a write token. A wrong package on one
line is one wrong line.

**A `#` only starts a comment at the start of a line.** The restrictions file
strips trailing comments; this one must not, because a value here may be a
credential and truncating one at a `#` produces a device that authenticates with
something almost right - which looks like a server problem for as long as anyone
is willing to look.

Everything else is refused loudly and named by line number in the log:

```sh
adb logcat -s muster
```

`set-bool` exists because a boolean is the one type that is not guessable from
the text. Nothing else is inferred: a token of digits is a string, and an
inferred integer is a credential that silently does not apply.

### The merge rule belongs to the app, not to muster

The receiving app merges what it is given over what it has stored, by a rule
written down in its own source:

> a key **present and non-blank** overrides local storage; a key **absent or
> blank** leaves local storage alone. Managed configuration can add and change;
> it cannot silently subtract.

That is not a nicety. Android hands an app an empty Bundle in perfectly ordinary
situations - no policy set, a device that was never managed, a policy that
configures only some keys - so treating absent as "clear" would wipe a working
local configuration on every unmanaged phone.

muster's whole job is to deliver the bundle faithfully. It does not reorder,
rename, translate or invent keys, and it has no vocabulary of its own for them:
the names in the file are the app's names, spelled the app's way.

Three consequences follow, and they are all deliberate:

- **A blank value is refused**, not pushed. The app cannot tell blank from
  absent, so a blank line reads as "clear this" and does nothing at all. Delete
  the line instead.
- **A key deleted from the file leaves the bundle** at the next boot. The app
  then falls back to what it has stored, which is where the value it was given
  already lives. muster stops pushing a value; it does not reach in and blank
  one.
- **There is no way to blank an app's whole bundle** from this file. An app the
  file gives no values to is left exactly as it is - including one named only to
  grant it a permission. Otherwise `grant` would be a destructive line, and
  deleting one line would do more damage than deleting two. Correcting a wrong
  value means pushing the right one.

**This file is therefore NOT symmetric with the restrictions file, and do not
assume it is.** An empty restrictions file is a deliberate instruction to
withdraw everything; an empty app-config file is the same as no app-config file
at all. The difference is that withdrawing a restriction changes what a device
may do, and withdrawing a bundle changes nothing an app can observe - it just
falls back to what it has stored.

### Secrets

`announceToken` and `ddClientToken` are credentials, and **muster does not know
which of an app's keys are.** The next app will draw that line somewhere else.
So every value is treated as one:

- No value reaches a log, a refusal message, a metric or a `toString`. Refusals
  name the line number and, where muster can prove it is safe, the verb, the
  package and the key. Never the value.
- `muster app-config` never prints the file, and it tells `place_file` the
  payload is secret. That matters because an adb without shell protocol v2 runs
  the remote command under a pty, and **a pty answers a write by echoing the
  payload back** - which the command would otherwise quote as "the device said".
- On the server, `telemetry.event` drops `value` and `values` outright, on the
  same principle: a list of the key names we happen to know today rots the first
  time somebody adds a key; refusing the field a value would arrive in does not.

### Permissions

`grant <package> <permission>` sets `PERMISSION_GRANT_STATE_GRANTED`, which is
how a Device Owner gives an app a runtime permission with nobody touching the
phone. `POST_NOTIFICATIONS` is the one that prompted this: zippie's relay is
deliberately a foreground service, and a foreground service with no notification
permission is a relay that dies in a pocket.

**`POST_NOTIFICATIONS` only exists from Android 13 (API 33).** The agent's
`minSdk` is 29, and on anything below 33 that permission is not a runtime
permission at all: `setPermissionGrantState` returns false, and the agent
reports it as not taken **at every boot**, with an error line that looks exactly
like a real failure. Do not put that line in the file for a device older than
13. Nothing can check this from the laptop - the CLI deliberately does not know
the vocabulary - so it is a thing to know rather than a thing that is caught.

**muster grants; it does not revoke.** There is no platform answer to "did
muster set this grant state" - unlike user restrictions, where
`getUserRestrictions(admin)` says exactly what this admin set - so a reconciler
that reset a permission to `DEFAULT` would be resetting grants somebody else
made. Taking a permission back is a decision to make in front of the device.

### What is verified, and what is not

The agent reads the bundle back with `getApplicationRestrictions` after writing
it and logs any key that did not take, because `setApplicationRestrictions`
returns nothing and a bundle that never arrived looks exactly like one that did.
It checks a grant twice: the policy state muster set, and whether the app
actually holds the permission.

**None of that proves the app is reading it.** The bundle existing is muster's
half. The other half is the app appearing where it is supposed to appear - for
zippie, in the bond. Do not quote a green log as that.

## How policy reaches a device

Written 2026-08-19, for #46. Two routes, and only one of them survives the
signing ceremony.

### The device fetches it

An enrolled device asks muster for its own configuration at every boot, over the
identity it already holds. No cable, no wireless debugging, no `run-as`, and
nothing that needs a debuggable build.

    device                                            muster
      |  POST /v1/auth/challenge                        |
      |<------------------------ nonce -----------------|
      |  sign the nonce with the keystore key           |
      |  POST /v1/device/config                         |
      |    { nonce, signature_b64, certificate_pem }    |
      |<--------- { revision, files: {...} } -----------|
      |  write the files, then reconcile as usual       |

**Authenticated by the certificate, not by a token.** `server/muster/proof.py`
explains why possession is proven at the application layer rather than with
mTLS: Cloudflare will not pass a client certificate through a Tunnel, so a
proof that depended on the transport would never reach the pod. A device token
would also be a credential that can be copied off a device, which is exactly
what the key in the Android Keystore cannot be.

**The same channel diagnostics (#27) and inventory (#42) will use.** They are
sibling `POST /v1/device/...` routes carrying the same three fields;
`api._proven_device` is the one place a device is authenticated and it hands
back the `key_id` those reports would be filed under.

**It writes the same files this document already describes**, into the same
device-protected directory, so everything the stewards do - reconciling both
ways, refusing a name they do not know, reading the platform back, withholding a
hide on a file they cannot read in full - keeps working unchanged.

### Nothing in that exchange is Android-specific

Written 2026-08-29, when a second kind of device came to the same door.

Everything above this heading describes a handset, because a handset is what
existed. The *protocol* never assumed one, and it is worth saying so out loud
before somebody adds an assumption to a path that is now shared.

`POST /v1/auth/challenge` and `POST /v1/device/config` take and return plain
JSON. `api._proven_device` is the one place a device is authenticated and it
knows nothing about platforms - it verifies an ECDSA-P256 signature against a
certificate this CA issued. The Android Keystore is where *that* agent keeps its
key; it is not where the scheme lives.

The three things a second client actually needs, none of which is a code change
here:

- **A P-256 key and a CSR.** `openssl ecparam -genkey` and `openssl req -new`
  are enough. `ca.py` refuses anything that is not an EC key, so an Ed25519
  library - `libsodium`, `pynacl` - cannot be substituted, which is worth
  knowing before planning around one that is already installed.
- **A signature over the nonce's bytes with nothing appended.** `proof.verify`
  calls `public_key.verify(sig, nonce.encode(), ECDSA(SHA256))`. Every naive
  `echo "$nonce" | openssl dgst -sign` appends a newline, signs a different
  message, and gets `BAD_SIGNATURE` - which reads exactly like the wrong key and
  gets debugged as an enrollment problem.
- **A `User-Agent` that is not the language runtime's default.** Measured
  2026-08-29 from an OpenWrt router: `Python-urllib/3.9` is answered **403 by
  Cloudflare** before the request reaches this server, while the identical
  request with any other User-Agent is answered 201. muster's logs show nothing
  either way, because muster never saw it.

Not because it makes a client easy - because it is the reason `proof.py` exists.
A scheme that depended on the transport would have had to be reimplemented for
every kind of device; this one is the same three fields everywhere.

### A device may decline to implement withdrawal, and one does

`ConfigurationPolicy.kt` removes a managed file that a **successful** fetch did
not mention, and that is right for a handset: policy that only ever adds is a
ratchet, and the only way to undo a ratchet on a Device Owner is a factory reset.

It is not right for every device, and the first one to say so is a travel router
whose `app-config` carries the key to its only uplink. Obeying "withdraw" there
would make this control plane able to island a device **by omission** - one
mistyped Secret key, and the router cannot be reached to fix it. Its client
reports an absent `app-config` and changes nothing.

So the rule is not "the device deletes what muster stopped sending". It is:

> muster's answer is complete and authoritative, and a device may refuse to act
> on part of it in a direction it cannot recover from. What it may never do is
> act on a **partial** answer - and it cannot be handed one, because muster
> returns 503 rather than a shorter list.

The asymmetry is deliberate and it is the whole reason the 503 above exists. A
device that is wrong about "add" gets a wrong file; a device that is wrong about
"remove" gets no way back.

### Where the policy is kept

A flat directory, `MUSTER_POLICY_DIR`, mounted from the `muster-policy` Secret:

    kith.restrictions        every device in the kith
    kith.visible-apps
    <key_id>.restrictions    this device only, and it REPLACES the kith file
    <key_id>.visible-apps
    <key_id>.app-config

`<key_id>` is the device's key id, the 64-character value the console shows and
the kith is keyed on. It is the same device before and after a renewal, which is
why policy is keyed on it rather than on a certificate serial.

Flat rather than nested because a Kubernetes Secret key may only contain
`[-._a-zA-Z0-9]`, so a nested layout would need every file enumerated under the
volume's `items:` and adding a device would be an edit to the deployment
manifest. The split is on the first dot, which is unambiguous: a key id is hex
and no managed file name contains one.

```sh
kubectl -n muster create secret generic muster-policy \
  --from-file=kith.restrictions=./kitchen.restrictions \
  --from-file=<key_id>.app-config=./kitchen.appconfig
```

**`kith.app-config` is never read.** It is the file that holds credentials, and
a credential under the shared scope is a credential handed to every device in
the estate. muster refuses to serve it rather than serving it widely, because
serving it widely is silent.

**An empty policy directory is refused, not served.** `muster-policy` is an
optional volume, and Kubernetes mounts an optional secret that does not exist as
an *empty directory* - so a secret that was deleted, misnamed or never created
looks exactly like a policy nobody has written. Serving that as "you have no
policy" would tell every device in the estate to delete every file muster
manages, on its next boot, from one typo. muster answers **503** instead, and
`/readyz` reports the file count rather than a boolean, because "readable" is
true for both.

To say "assert nothing" deliberately, write an **empty** `kith.restrictions`.
That is the vocabulary the agent already speaks: an absent file leaves a device
alone, an empty one withdraws.

**A wallpaper cannot travel this way yet.** It is a PNG, and serving one means
asset hosting (#45). It stays an adb step.

### What happens when muster is unreachable

Nothing. **The device keeps enforcing the last configuration that arrived**, and
there is no separate cache to go stale, because the files it fetched into are
the files the stewards read. That is CONTEXT.md's second rule - enrollment may
need the internet; operation must not - and a device that lost its policy
because a server went away would have broken it.

The same is true of every answer that is not a configuration: a refusal, a body
that will not parse, a captive portal's login page, a keystore that will not
sign. `ConfigurationClient` models each one separately and none of them can
produce an empty configuration, because an empty configuration is a real
instruction - it withdraws every file the device holds.

muster is careful on its side too. A configured file it cannot read - and a
policy source that is empty or absent - makes the whole answer a **503**, not a
shorter list. A half-answer is indistinguishable from an operator having deleted
a policy, and the device would take a restriction back off because a byte went
bad or a volume did not mount.

### What a fetch changes, and what it withdraws

    served, different from the file on the device   written
    served, identical                               left alone
    NOT served, present on the device               removed
    served under a name muster does not manage      refused, and logged

The removal line is what makes this a reconciler rather than a ratchet: without
it, policy could be added remotely and only ever withdrawn with a cable. It is
safe in the direction that matters, because the agent already treats an absent
file as "leave this device as it is" rather than as "strip it".

A name outside `restrictions`, `visible-apps` and `app-config` is refused by the
device, not just omitted by the server. Anything else would make this a remote
write into the agent's private storage, and the first file it would be pointed
at is `server-url` - the one that decides which control plane the device answers
to.

**Removing a file is not the same as undoing what it did.** It stops muster
asserting; it does not reach into the platform. Deleting `<key_id>.app-config`
takes the file off the device and leaves the managed configuration bundle - and
the `announceToken` in it - in place, because `AppConfigSteward` treats an
absent file as "do nothing" (see "The merge rule belongs to the app" above).
Deleting `<key_id>.visible-apps` likewise leaves hidden packages hidden.
Correcting either means pushing the right content, not withdrawing the file.
There is no over-the-air way to take a credential back out of an app's bundle
today.

### `place_file` stays

`muster restrictions`, `muster visible-apps` and `muster app-config` are still
how a device that has **not enrolled yet** is configured, and how anything is
done with a cable in hand. They are the bootstrap, not the mechanism, and they
still stop working the day the release-signed agent ships - `run-as` needs a
debuggable package. That is now a route ending rather than the route ending.

**A file placed by hand does not survive a successful fetch.** Those three
commands write exactly the three names the control plane manages, so on an
enrolled device the policy directory decides their contents and a name muster
does not serve is removed at the next boot. That is what a reconciler is for; it
also means a cable-placed file is temporary unless the same content is in the
secret. muster refusing to answer at all leaves them alone.

### What is not proven

**None of this has run on a handset.** Written and tested on 2026-08-19 with no
device attached. The server half is covered end to end by
`server/tests/test_api.py` and `server/tests/test_policy.py`; the device's
decisions are covered by JVM unit tests. What no test here can see is the boot
receiver actually completing a network fetch inside its broadcast budget, the
keystore signing a nonce, or the files landing where the stewards look. The
first device to try it is the measurement.

**Policy reaches a device at its next boot**, not within minutes of the edit,
and a failed fetch is not retried until the next one. There is no periodic
fetch, and adding one needs a scheduler component and a device to prove its
direct-boot behavior on. A device whose network is not yet up at
`LOCKED_BOOT_COMPLETED` therefore keeps its existing configuration - correct,
and the whole point - but will not pick up a change until it reboots or somebody
presses sync on its status screen.

**The response is not signed.** The proof authenticates the *device* to muster,
over a channel that survives Cloudflare (`proof.py`). Nothing authenticates
muster to the device beyond TLS, which Cloudflare terminates. The closed
vocabulary of file names bounds what a TLS-terminating intermediary could do -
it cannot write `server-url` - but it does not bound the contents, so such a
party could serve restrictions or an allowlist the operator did not write.
Signing the response with the CA key the device already holds is the answer and
is not built.

## What is not policy, and never will be

**The 80% charge cap.** Android allowlists which secure settings a Device Owner
may write and charging optimization is not among them. It stays an adb step:

```sh
adb -s <serial> shell settings put secure charge_optimization_mode 1
```

Wireless adb works, so it need not be a cable - but it will never come from the
QR, and it will never come from this file.

## Which applications the device shows

Written 2026-08-19, for #35. A muster-owned Pixel comes up with the whole
consumer launcher on it - Play Store, Gmail, Drive, Photos - on a device whose
entire purpose is to be a relay. This is the allowlist that takes them off.

**Hidden, not uninstalled.** The mechanism is
`DevicePolicyManager.setApplicationHidden`. The package stays on the device and
the same call with `false` puts the icon back. Removing a system app for a user
is a different and much less reversible act, and it is deliberately not what
this does.

A second plain text file, beside the restrictions:

    /data/user_de/0/app.muster.agent/files/visible-apps

One package name per line, `#` starts a comment, blank lines ignored:

    # kitchen display - it is an appliance, not a phone
    app.muster.agent
    com.android.settings
    app.zippie.companion

Push it with:

```sh
uv run --group dev python -m muster.cli visible-apps <serial> --file ./kitchen.visible-apps
```

Same route as the restrictions file, with the same expiry date on it: written
as the agent with `run-as`, which needs a debuggable package, so it ends at the
signing ceremony. An enrolled device fetches this file instead - see ["How
policy reaches a device"](#how-policy-reaches-a-device).

**Not measured on a handset.** Written and tested on a laptop on 2026-08-19.
Nothing here has been read off a phone's launcher, which is the only place this
can actually be confirmed.

### What is a candidate to be hidden, and what is not

Only packages that answer `ACTION_MAIN` + `CATEGORY_LAUNCHER` - that is, only
things with an icon a person can see and press. Everything else on the device
is not a candidate at all, whether or not the allowlist mentions it. That is a
deliberate safety property rather than a convenience: the setup wizard, SystemUI
and the permission controller carry no launcher icon, so they cannot be reached
by this even by a config file that tries.

### An absent file and an empty file mean different things

    no file        nothing has been configured; the launcher is left as it is
    empty file     an allowlist naming nothing; everything with an icon goes,
                   except what can never be hidden

The same distinction as the restrictions file, and the same reason: a first boot
on an unconfigured device must not be indistinguishable from a deliberate
instruction to strip it.

**A file of nothing but comments is an empty file, not an absent one.**
Commenting every line out is not how you turn this off - it reads as an
allowlist naming nothing, and strips the launcher. Deleting the file is how you
turn it off.

### A file muster cannot read in full hides nothing

**This is the difference between an allowlist and a list of restrictions, and it
is worth reading twice.** A restriction name muster does not recognize costs one
restriction that does not get set. A package name muster cannot read costs an
application that gets **hidden**, because an allowlist asks for a hide by
staying silent. So a file with any line the agent will not act on hides nothing
at all until the file reads clean. It still **unhides**: that direction gives
something back and cannot strand a phone, so a typo made while trying to
un-strand a device does not leave it stranded.

The route this closes is not hypothetical. The obvious way to build the file is

```sh
adb shell pm list packages > kitchen.visible-apps
```

and every line of that output begins `package:`, which is not a package name.
Read line by line, that file is an allowlist naming nothing.

The same withholding applies when **the device names no home screen at all**.
Every Android device has a home app, so an empty answer means the question was
not asked properly - package visibility filtering, or a `queries` element that
does not match what this handset declares - and it arrives as an absence, which
is the one thing nobody spots in a log. The agent says so instead:

    visible-apps: HIDING WITHHELD - ...
    visible-apps: would have hidden [...]

Reconciling goes **both ways**. A package deleted from the file is hidden at the
next boot; a package added back is unhidden. Policy that only hides is a
ratchet, and the reverse gear on a ratchet a Device Owner is holding is a
factory reset.

**The reverse is by naming, not by deleting the file.** Removing the file stops
muster managing the launcher; it does not unhide anything. To bring an
application back, put it in the file. What was hidden, and when, is in the log:

```sh
adb logcat -s muster
```

### What can never be hidden, whatever the file says

muster refuses these, and the refusal is logged with what hiding it would cost.
Unlike a stranding restriction there is **no word that unlocks one**. Two
reasons: an allowlist asks for a hide by staying silent, so there is no line to
write a magic word on; and the damage is worse in kind, because a device with
`DISALLOW_FACTORY_RESET` set still has Settings and still has adb, and a device
with no Settings icon has neither.

Found **by asking this device**, not by matching a table:

| Asked | What it finds |
|---|---|
| the agent's own package name | muster - the status screen is how anybody learns what the device thinks it is |
| `ACTION_MAIN` + `CATEGORY_HOME` | this device's launcher, whatever it is called |
| `android.settings.SETTINGS` | this device's Settings |
| `ACTION_MAIN` + `CATEGORY_SETUP_WIZARD` | this device's setup wizard, when it has not yet disabled itself |

Declared by name as well, because a resolve can come back empty and the setup
wizard disables itself once setup finishes: `com.android.settings`,
`com.android.systemui`, `com.android.shell`, `com.android.provision`,
`com.google.android.setupwizard`, `com.android.launcher3`,
`com.google.android.apps.nexuslauncher`, `com.android.permissioncontroller`,
`com.google.android.permissioncontroller`. The `com.android.*` names were read
out of the `package=` attribute of their own AOSP manifests on 2026-08-19; the
three `com.google.*` names are the Pixel builds of the same things and are
documented rather than measured. A name that is wrong here protects a package
that is not on the device, which costs nothing. A name that is missing costs a
handset.

**A package it hid is also a package it puts back.** A protected package found
hidden - by an older allowlist, or by somebody's `pm hide` - is unhidden at the
next boot. That is the only recovery an appliance in a cupboard is going to get.

**That recovery reaches exactly what muster can hide, and no further.** Only
things with a launcher icon are ever enumerated, so on a Pixel that is Settings
and muster itself. `pm hide com.google.android.apps.nexuslauncher` from a shell
is **not** walked back, because the launcher has no launcher entry of its own to
be found by. Written down because the first draft of this section claimed
otherwise, and a recovery somebody believes in and does not have is worse than
one they know they lack.

### It costs no new manifest permission

Enumerating other packages is filtered from targetSdk 30, and **being Device
Owner does not exempt an app from that**. Checked rather than assumed:
`AppsFilterBase.shouldFilterApplication` in AOSP, read 2026-08-19, exempts the
calling app itself, uids below `FIRST_APPLICATION_UID` and force-queryable
packages, and has no device owner, profile owner or device admin case anywhere
in it. Google's list of automatically visible packages does not mention a DPC
either.

The two ways out are `QUERY_ALL_PACKAGES`, which is a fifth permission, and a
`queries` element in the manifest, which is not a permission at all. muster
takes the second. `android-constraints.md` records why the fifth permission is
not free: the four-permission profile is the only input to Play Protect's
approved-DPC heuristic this project controls, and the way to find out what a
change to it did is a wiped handset.

The block is pinned by `server/tests/test_agent_manifest.py`, because dropping
it breaks nothing visibly - the build stays green, the APK installs, and the
agent comes up able to see only itself.

### Two package manager flags that are not optional

Both verified against AOSP on 2026-08-19, and both silent when wrong.

**`MATCH_UNINSTALLED_PACKAGES`.** A hidden package is not "available" to
`PackageManager`: `PackageUserStateUtils.isAvailable` returns false for
`installed && hidden` unless the flag is set. Without it, hiding an application
removes it from the very query that would find it again - so putting a package
back in the file would unhide nothing, and the reverse gear would be a factory
reset after all.

**`MATCH_DIRECT_BOOT_AWARE` and `MATCH_DIRECT_BOOT_UNAWARE`, together.**
`ComputerEngine.updateFlags` fills these in from the user's unlock state when
the caller expresses no opinion, and at `LOCKED_BOOT_COMPLETED` that means
direct-boot-aware components only. Almost nothing on a launcher is direct-boot
aware, so the query would come back nearly empty and the reconcile would do
nothing - on precisely the boot an appliance in a cupboard gets.

## Known gap

**Nothing reads either policy back off a device from the laptop.** The agent
verifies its own work on both - it re-reads the effective restrictions after
setting them, because `addUserRestriction` does not reject a key the platform
does not know, and it asks `isApplicationHidden` after every hide and unhide,
because the platform keeps a policy-exempt list an app cannot read. But `muster
verify` still reports only ownership and package versions.

Closing that means parsing `dumpsys device_policy` for restrictions, whose
format varies by release. It is deliberately not written blind: a parser nobody
has run against a real handset is a verifier that can report anything. The
allowlist side would be the per-user `hidden=` flag `dumpsys package` prints,
and it is unwritten for exactly the same reason.

**Nothing checks a config key against the app's own declaration either.** An app
declares which keys an MDM may set in its `res/xml/app_restrictions.xml`, and a
key spelled wrong is pushed, stored, and read by nobody - which looks exactly
like the feature not working. `RestrictionsManager.getManifestRestrictions` is
the route to closing it, as a warning rather than a refusal: zippie reads
`consoleUrl` and does not declare it, so refusing an undeclared key would break
a legitimate push on the first app this was built for.

**No handset has run the app-config half.** Written and tested on 2026-08-19
with no device attached. The parser, the plan and the refusals are covered by
JVM unit tests; the two platform calls are not, and cannot be without hardware.
