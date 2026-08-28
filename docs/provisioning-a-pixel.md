# Provisioning a Pixel, start to finish

Written 2026-08-18 for the first real run, when the cable was the only way in.
**Rewritten 2026-08-19**, the day a phone provisioned by QR instead. Follow one
route in order; every step here exists because skipping it costs a factory
reset.

Read [android-constraints.md](android-constraints.md) first if you have not.
The short version is that there are now two routes:

    Route A   QR, six taps, no cable       measured working once, 2026-08-19
    Route B   adb, one cable per device    older, slower, and the fallback

**Take A, keep B.** The gate Route A clears is a Play Protect heuristic that
said yes on one device on one day; if it says no, the phone in your hand has
already been wiped and Route B is how it gets provisioned anyway.

## What this gets you, and what it does not

**Does:** the phone leaves whatever MDM owns it, comes up owned by
`app.muster.agent`, keeps the stock Pixel launcher, and can have applications
sideloaded onto it that nothing will delete. That last part is the whole point -
a device provisioned this way is not enrolled in managed Google Play, so there
is no enterprise app set for Play to reconcile against.

**Also does, as of 2026-08-19:** reconciles user restrictions at boot from a
file on the device, and carries an enrollment screen that presents a CSR and a
pairing code and shows the key fingerprint to compare against the console.
`no_safe_boot` and `no_config_date_time` were read back in force off
<device-serial> the same day. `policy.md` is the vocabulary and the two names
that can strand a device.

**Also does, written 2026-08-19 and NOT measured on a handset:** hides every
application that is not in a `visible-apps` allowlist, so the stock launcher
stops being a consumer launcher. Settings, the launcher, the setup wizard and
muster itself are refused. Step B4c, and `policy.md` for the whole thing.

**Changed on 2026-08-19 and not yet re-measured:** configuration pushed from the
laptop. `muster restrictions` and `muster wallpaper` used to stage a file in
`/data/local/tmp` and copy it into the agent's files directory, which cannot
work - that directory is `0700` and owned by the app's uid, not
world-traversable as the code assumed. Measured on the same phone; #20 has the
evidence. They now write through the app with `run-as`, which is the command #20
records placing a file by hand - but nobody has run the fixed commands against a
handset, so the steps below that push a file are still unproven end to end.

## Before you start, either route

**The APK is debug-signed.** A Device Owner app cannot be replaced by a
differently-signed APK, and Device Owner cannot be reassigned without a factory
reset - so the eventual release-signed agent will cost one more wipe of this
device. That is a deliberate trade for proving the route on hardware now, on a
phone that carries nothing. Do not do this to a phone you are relying on, and
read the warning in `state-of-play.md` before pointing either route at one.

Have ready:

- the phone, and the ability to unenroll it from whatever owns it
- for Route A: an administrator token, and the control plane reachable from
  wherever the phone will sit
- for Route B: a cable, and the `muster-agent-debug-apk` artifact from the
  newest green `agent - android` run
- zippie's companion APK, if you want the phone to be a leg

## 1. Free the device from its current owner

Both routes need the same wiped device, so this step is shared.

The new Pixel is managed by a commercial MDM, which has set
`userRestriction_no_factory_reset`, so **Settings will not offer a reset**. Use
its own wipe or unenroll command from its console; that is free-tier, unlike
installing an application.

The old Pixel is managed by an open-source MDM and is a different job - and it
is currently carrying household traffic, so do not start there.

## Route A: the QR, no cable

### A1. Mint the provisioning QR

**From the console, which is where this belongs.** Sign in, open
**Provisioning**, and press *Show the QR*. It is drawn as large as the panel
allows, with a *Full screen* view for the moment somebody is holding a phone up
to the monitor, and what it commits to is printed beside it: the download URL,
the signing-certificate checksum and the server address the device will enroll
against. The console checks that checksum against `/agent.json` before it draws
anything, and refuses to draw a QR when they disagree - a QR whose checksum does
not describe the download is a phone that fails mid-setup, after it has already
been wiped.

Wi-Fi is opt-in there, behind a disclosure that says what it does: **the network
password goes into the QR in clear text**, and the QR goes on a screen. Leave it
closed and join a network by hand in the setup wizard if the room is not yours.

From a shell, if the console is not reachable:

    GET  /v1/provision/qr.svg    admin-only, the image, no wifi
        ?hands_free=false        a QR to print or keep - see below
    POST /v1/provision/qr        admin-only, the image AND what it commits to,
                                 with wifi in the BODY: {"wifi_ssid": "...",
                                 "wifi_password": "...", "wifi_security": "WPA",
                                 "hands_free": true}

The wifi parameters used to be accepted in the query string and are now refused
there, with a message saying so. A query string is written to this server's
access log, to whatever proxy is in front of it, and to the browser's history -
three places a password cannot be deleted from afterwards. `hands_free` is
allowed in the query, because it is a boolean and not a credential - what it
chooses is whether a pairing code is minted INTO the QR, and the code itself
never appears in a URL, a response body or a log.

**Admin-only for two reasons now.** This payload can carry the wifi password in
clear text, which used to be the one genuinely secret thing in the whole
enrollment flow. It also carries a pairing code.

What the QR carries, none of which anybody types on the phone:

    the admin component     app.muster.agent/.MusterDeviceAdminReceiver
    where to download       <base URL>/agent.apk
    a checksum              SHA-256 of the SIGNING CERTIFICATE, not the APK
    muster.server_url       the control plane's own base URL
    muster.pairing_code     a scanned pairing code, unless hands_free=false

**The code makes this QR perishable, and it expires in five minutes.** Everything
else in the payload is stable for the life of the signing key. Draw it when the
phone is in your hand, not before. The console counts the seconds down beside the
image and says plainly when it has run out; from a shell, the plain GET answers
`X-Muster-Pairing-Expires-In` and the POST says the same in `pairing`. A device
that scans a stale QR still provisions - it just comes up waiting to be enrolled
by hand, which is A4b below.

**Do not print a QR that carries a code.** Use `?hands_free=false` for anything
kept, printed or pasted into a runbook: the payload is then exactly what it was
before this existed, and the device is enrolled by hand afterwards.

**Read CONTEXT.md on what the code in the QR costs.** With nobody holding the
handset there is no second copy of the key fingerprint, so the comparison an
administrator makes when they vouch is weaker on this path. The code is 192 bits
rather than six digits precisely because of that. Somebody who photographs this
QR off your monitor within the window can provision a device of their own
against it, and you will not be able to tell.

**The server address rides in the QR, and this is what makes Route A a route.**
It travels in the admin extras bundle, the agent's policy-compliance activity
reads it during setup and writes it into device-protected storage, and the
enrollment screen reads it from there afterwards. On <device-serial> that file
was written at 11:25, during provisioning, with no cable attached. There is no
adb step to give a device its server address.

The certificate checksum rather than the APK checksum is deliberate and is
`server/muster/provisioning.py`'s longest comment: the certificate one is stable
for the life of the signing key, so one printed QR keeps working across agent
releases.

### A2. Bring it to the welcome screen and stop there

Factory reset it (step 1 above), let it boot, and **do not start setup**. The
six-tap flow lives on the very first welcome screen; going past it, and
especially adding a Google account, means another reset.

### A3. Six taps, scan, walk away

Tap the same spot on the welcome screen six times. That opens a scanner. Scan
the QR from A1.

The device joins wifi if the QR carried it, downloads the agent from
`/agent.apk`, checks it against the certificate checksum, installs it, asks it
which provisioning mode to use, hands it the admin extras, and finishes setup
owned by muster.

**Watch it from the control plane, not from the phone.**
`custom.muster.agent.apk.served` and the `agent APK served` event are the only
signal a provisioning attempt began; the handset says nothing useful. If that
counter never moves while somebody is holding a wiped phone, the problem is the
QR, the network or DNS - not the agent. `observability.md` has the rest.

Two failures look similar and are not:

    "App blocked to protect your device"    Play Protect refused the DPC
    "Something went wrong / contact your    the agent failed to answer a
     IT admin", then a Reset button          provisioning intent

The first is the gate in `android-constraints.md`; fall back to Route B. The
second is ours, was fixed on 2026-08-19, and should not come back - a test
asserts the manifest declares both activities.

### A4. Vouch for it, without touching the phone

**Written 2026-08-19 and NOT measured on a handset.** The extras half was - the
server address landed on <device-serial> during provisioning with no cable - but
nobody has watched a phone present itself. If it does not, A4b is how the device
gets in, and that path is unchanged.

The agent presents itself while setup is still finishing, using the code out of
the QR. So the phone is on the last screen of its own setup and there is a
pending request on the console. Go to the console and vouch for it.

**What you are checking is not what you check on the typed path, and the console
says so.** A scanned request is marked `scanned`, and there is no second copy of
the fingerprint anywhere - the phone is not showing you one. What you are
confirming is that this is the only request against the QR that was on your own
monitor and that it arrived while you were standing there. `CONTEXT.md` has the
reasoning and what it does not cover.

The screen waits ninety seconds. If you take longer, the phone finishes setup
anyway with its request already lodged, and collects the certificate at its next
boot or when somebody taps Sync - nothing is lost and nothing has to be redone.

### A4b. Enroll it by hand, if it did not present itself

This is also the path for a device provisioned from a `hands_free=false` QR, and
for one re-enrolling after its identity lapsed.

Open the muster agent on the phone, mint a pairing code on the console, type the
six digits, and **vouch by comparing the key fingerprint on both screens**. The
fingerprint is the point of that screen; the pairing code only proves somebody
intended this enrollment to happen.

The agent already knows where to send it, because A1 put the address in the QR.

If a device will not enroll and you have adb on it, the two files provisioning
left behind are in the agent's device-protected files directory:

    pairing-code      the code out of the QR, deleted once used or refused
    enroll-request    the id of a request already lodged with muster

### A5. Check it, later, over adb

Verification still goes over adb - wireless is fine, it does not need the cable
Route A avoided. Enable developer options and wireless debugging on the phone,
then:

```sh
cd server
uv run --group dev python -m muster.cli verify <serial> --package app.zippie.companion
```

This is a check and not a provisioning step. It reports the owner and the
version of each package **as the device reports them**, and exits non-zero if
the phone is not what it should be. Run it a week later, after a reboot, after
somebody else has touched it.

## Route B: the cable

Slower, and still the fallback. Steps 1 (above) then 2 through 6 here.

### B2. Bring it up WITHOUT signing in

This is the step that quietly ruins provisioning. `dpm set-device-owner` refuses
on a device that has any account on it, and completing setup wizard while signed
in is enough to do it.

- skip Wi-Fi if it offers to, or join but **do not add a Google account**
- skip restore, skip everything optional
- enable Developer options, then USB debugging
- plug in and accept the debugging prompt on the screen

### B3. Ask before you act

```sh
cd server
uv run --group dev python -m muster.cli preflight <serial>
```

It answers `ready`, or refuses and says why. The refusals are the point:
`has-accounts` means go back to step B2, `already-owned` means step 1 did not
finish, `unauthorized` means the prompt on the phone is still waiting.

Do not skip this and do not add a flag to skip it. The failure it prevents costs
another factory reset.

### B4. Provision

```sh
uv run --group dev python -m muster.cli provision <serial> \
    --apk /path/to/app-debug.apk \
    --also-install /path/to/zippie-companion.apk \
    --package app.zippie.companion \
    --server-url https://muster.example.invalid
```

This preflights again, installs the agent, takes ownership, installs anything
named by `--also-install` while the cable is still attached, and then **reads the
device back** and asserts what it found. `dpm` prints failures on stdout, so its
output is not a verdict; the device's own policy state is.

Exit codes: `0` provisioned and verified, `2` refused before touching anything,
`3` tried and the device did not end up as expected.

The `--server-url` is written to the device rather than compiled in, because a
hostname baked into a Device Owner APK cannot change without a release and a
release there eventually costs a factory reset. Route A gets the same value out
of the QR instead; this flag is how a cable-provisioned device gets it. Omit it
until there is a server to point at; the agent then simply has nowhere to
enroll.

### B4a. Wallpaper, if you want one

```sh
uv run --group dev python -m muster.cli wallpaper <serial> --image ~/some.png
```

The agent applies it at the next boot, once, keyed on a hash of the image bytes.
Both this and the server URL go into the agent's DEVICE-PROTECTED files
directory - `/data/user_de/0/...`, not the `/data/user/0/...` one - because the
agent reads them before first unlock. Pushing to the wrong one succeeds, leaves
the file genuinely on disk, and the agent never sees it.

**The wallpaper, the server URL, the restrictions file and the app
configuration below are all written through the app, with `run-as`, and that has
an expiry date on it.** The agent's directory is `drwx------` owned by the app's
uid, so `adb push` and a `cp` from `/data/local/tmp` cannot reach it - measured
on <device-serial>, 2026-08-19, and that is what these commands used to do.
`run-as` can reach it, but only while the agent is debug-signed: after the
signing ceremony it refuses with `package not debuggable` and all four commands
stop working. They fail loudly rather than silently. What replaces them is open
- see #20.

### B4b. Restrictions, if this is an appliance

```sh
uv run --group dev python -m muster.cli restrictions <serial> --file ./kitchen.restrictions
```

One `DISALLOW_*` name per line. The agent reconciles at the next boot and names
anything it refuses in `adb logcat -s muster` - an unrecognized name is refused
rather than skipped, so a typo cannot leave a device unrestricted while a file
on it says otherwise.

Two names can strand a device and each needs `accept-stranding` spelled out on
the line. One of them, `DISALLOW_DEBUGGING_FEATURES`, would remove the adb
access that step B5 below depends on. `policy.md` has the full list and the
reasoning.

**Same as B4a**: the reconcile is proven on hardware, the push through `run-as`
is not yet.

### B4c. Which applications stay on the launcher

```sh
uv run --group dev python -m muster.cli visible-apps <serial> --file ./kitchen.visible-apps
```

One package name per line, and everything else with an icon is hidden -
`setApplicationHidden`, so the package stays on the device and putting the name
back brings the icon back. A phone that has been through B4 alone still shows
Play Store, Gmail, Drive and Photos, which is not what an appliance is.

Settings, the launcher, the setup wizard and muster itself are never hidden
whatever the file says, and the agent names each one it kept in `adb logcat -s
muster` along with what hiding it would have cost. `policy.md` has the whole
thing, including why there is no `accept-stranding` equivalent here.

**Neither half is proven on hardware.** The reconcile has never run on a phone
and nobody has looked at a launcher, which is the only place it can be
confirmed - unlike B4b, where the restrictions themselves were read back in
force off a handset.

### B4d. Configuring an app on the device

```sh
uv run --group dev python -m muster.cli app-config <serial> --file ./kitchen.appconfig
```

This is what turns an installed app into a contributing one: it pushes the
credential a person would otherwise have to type into the phone, and grants the
runtime permissions the app needs.

    set       app.zippie.companion homeHost       192.168.1.11
    set       app.zippie.companion announceToken  <the write token>
    set-bool  app.zippie.companion autoStartRelay true
    grant     app.zippie.companion android.permission.POST_NOTIFICATIONS

`policy.md` has the format, the merge rule the receiving app imposes, and why a
blank value is refused rather than pushed.

**The `grant` line above is for Android 13 or later.** `POST_NOTIFICATIONS` does
not exist below API 33, so on an older handset the agent reports it as not
granted at every boot, in a line that reads like a real failure.

**The file holds credentials.** Nothing prints it, and the device is not quoted
verbatim when a write fails - a pty answers a write by echoing the payload back.
Keep the file itself somewhere a repository is not.

**Unproven on hardware.** Written 2026-08-19 with no device attached. What
settles it is the configured app appearing where it is supposed to appear, not
this command exiting 0.

### B5. Charge cap

Not something any Device Owner can do - Android allowlists which secure settings
a DPC may write and charging optimization is not among them. It stays an adb
step, which is free here because the cable is still attached:

```sh
cd ../zippie/companion-android/mdm && ./provision-device.sh
```

On a Route A device this is the one thing that still needs somebody to go and
enable wireless debugging.

### B6. Check it again later

```sh
uv run --group dev python -m muster.cli verify <serial> --package app.zippie.companion
```

Run this whenever you want the truth about a device - a week later, after a
reboot, after somebody else has touched it. It reports the owner and the version
of each package as the DEVICE reports them, and exits non-zero if the phone is
not what it should be.

## Reaching a phone that is not on this network

If the phones live on a router's LAN that is not directly routable (a travel
router on a Tailscale-reachable network, for example), forward through it:

```sh
ssh -f -N -L 5556:<phone-lan-ip>:<wireless-debug-port> root@<router-tailnet-ip>
adb connect 127.0.0.1:5556
```

The serial is then `127.0.0.1:5556`. The port on the phone changes every time
wireless debugging is restarted, so read it off the phone rather than trusting
this file.
