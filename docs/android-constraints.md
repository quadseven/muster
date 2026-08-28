# What Android actually permits us, and what it does not

Written 2026-08-18, at the start of muster, from findings measured on real
devices rather than inferred from documentation. **Read this before designing
any enrollment experience.** One of the three obvious routes to managing an
Android device is closed to us by Google policy, and it does not close for a
technical reason a better server would fix.

**Corrected 2026-08-19, on hardware.** This file used to record two routes as
closed. The QR route was one of them and the verdict was wrong: a wiped Pixel 6a
provisioned through it that morning, with no cable at any point. Route 2 below
records what the device did, and - just as important - what one device on one
day does not prove.

**Date-mark everything here.** Google moved these gates during 2025-2026. If you
are reading this months later, re-check the support pages before trusting a
CLOSED verdict, and re-run Route 2 before trusting an OPEN one: the gate it
cleared behaves like a heuristic, and a heuristic is allowed to change its mind.

## The three routes, and their status

| Route | Status | The gate |
|---|---|---|
| Call the Android Management API ourselves | **CLOSED** | Commercial-EMM eligibility |
| Our own DPC, provisioned by QR / six-tap | **OPEN**, once | Play Protect's approved-DPC check - see below |
| Our own DPC, provisioned by `adb dpm set-device-owner` | **OPEN** | A USB cable, once per device |

## Route 1: AMAPI directly - closed

Tried and retired in quadseven/zippie#125 on 2026-08-10. Enterprise creation and
policy push both **succeeded**; enrollment is where it stops. The handset refused
provisioning with "your organization has reached its usage limits" **at zero
devices enrolled** - the eligibility rule seen from the device, not a spent quota.

Google's [permissible usage policy](https://developers.google.com/android/management/permissible-usage)
restricts the API to "commercial Enterprise Mobility Management (EMM)
developers", who "must offer solutions commercially to external customers", and
explicitly prohibits:

> Solutions developed and used exclusively for first party in-house applications

That is exactly this project.

**This is also the entire explanation for the mainstream commercial MDM's
Android story.** Its fully-managed Android works because it holds that
eligibility. Its Premium tier is not a feature flag over an API we could call
ourselves - it is access to a door we cannot open.

## Route 2: our own DPC by QR - open, measured once

This is the flow everyone asks for by name: factory reset, tap the welcome screen
six times, scan a QR, walk away. On 2026-08-19 it worked here.

**Measured on <device-serial>, Android 17, 2026-08-19.** A wiped Pixel 6a scanned
a provisioning QR from `/v1/provision/qr.svg`, downloaded the agent, and
completed setup owned by muster. Its own policy state afterwards:

    Device Owner: app.muster.agent/.MusterDeviceAdminReceiver  testOnlyAdmin=false

`testOnlyAdmin=false` is the part to read twice. This is not the throwaway admin
a `--test-only` development shortcut leaves behind; it is the same ownership the
cable route produces, reached without a cable. That serial is also the phone the
2026-08-18 table at the bottom of this file records as owned by the commercial
MDM with `no_factory_reset` set - it was freed and re-provisioned.

### What this does not prove

**One device, one Android version, one day.** The gate cleared here is Play
Protect's approved-DPC check, and everything known about it says it behaves like
a harmful-app heuristic rather than a strict list: devices sometimes offer a
"continue", and developers have cleared it by dropping permissions that read as
dangerous. A heuristic that said yes to this APK, on this handset, on this
Android build, on this date, has promised nothing about the next one - and
Google can move it without announcing anything, which is how it arrived in the
first place.

So: take Route 2 first, and keep Route 3 working. The cost of the heuristic
changing its mind is a handset that has already been wiped.

### What this corrects, and why the old verdict was wrong

This section used to record the route as CLOSED behind the allowlist. **That
verdict was never tested.** The first real attempt failed earlier, for a
different and entirely fixable reason: the agent declared no activity for either
intent the platform sends during provisioning. The phone downloaded the agent
successfully - the control plane logged `agent APK served`, 12,606,023 bytes,
HTTP 200, from the handset's address - then showed "Something went wrong /
contact your IT admin" and factory-reset itself. AOSP `DevicePolicyManager`
states the requirement and the consequence:

> admin apps must implement activities with intent filters for the
> `ACTION_GET_PROVISIONING_MODE` and `ACTION_ADMIN_POLICY_COMPLIANCE` intent
> actions ... will cause the provisioning to fail

> If provisioning fails, the device is factory reset.

Both activities now exist and a test asserts the manifest declares them, because
the failure costs a wipe and names no cause on the handset. The run recorded
above is the next attempt after that fix.

The lesson outlives the correction: **a gate nothing ever reached had been
written down as a result.** The evidence for CLOSED was a failure that happened
before the gate, plus documentation about the gate, and the two got added
together.

### The gate itself, still worth knowing

The approved-DPC allowlist is real and still documented, and a DPC it does stop
fails with a distinct screen:

> App blocked to protect your device

Worth knowing apart from "Something went wrong": one is Play Protect refusing to
install, the other is our own manifest failing to answer. The
[approval page](https://support.google.com/work/android/answer/16694822)
describes criteria and an appeal form, and Google's DPC documentation carries the
caution that Android Enterprise **"is no longer accepting new registrations for
custom device policy controllers."** Public reports through 2025-2026 describe
appeals taking months and being repeatedly rejected, including for commercial
products. The open-source MDM's agent was blocked for a period before being
allowlisted again.

**A domain, a certificate, an mTLS handshake and a beautiful console change none
of this.** The one variable we do control is the permission profile, and it is
the bet that appears to have paid - inferred, not measured, because nothing on
the handset says why it was allowed through. The agent asks for four
permissions: `RECEIVE_BOOT_COMPLETED`, `SET_WALLPAPER`, `INTERNET`,
`BIND_DEVICE_ADMIN`. No SMS, no notification listener, no accessibility. Adding a
fifth is no longer a free decision - it changes the only input to that heuristic
we have any influence over, and the way to find out what it did is another wipe.

## Route 3: our own DPC by adb - open, and still needed

`adb shell dpm set-device-owner <pkg>/<receiver>` still works. It is documented
as a development and testing path, which is precisely why it is not
allowlist-gated: it is a shell command on a device someone is physically holding,
not an enterprise provisioning flow.

Conditions, all of which this project meets:

- the device must be freshly factory reset, with **no Google account added** and
  no secondary users - the same wiped state the QR flow needs anyway
- USB debugging on, cable attached, **once** per device
- the DPC APK is sideloaded first, which works because a device provisioned this
  way is not enrolled in managed Google Play, so there is no enterprise app set
  for Play to reconcile against and delete

It is no longer the only way in, and as of 2026-08-19 it is no longer the one to
reach for first. What it is still for:

- **provisioning at all, if Play Protect refuses** - the fallback that makes
  attempting Route 2 a safe thing to do
- **the 80% charge cap**, which no Device Owner can set by policy at any API
  level (below)
- **anything that needs a shell**, which today includes getting a configuration
  file into the agent at all: #20

Either route ends at the same place, which is the point of keeping both:

- silent install and update of applications, no prompts
- wallpaper set programmatically, and locked against change
- lock-task / kiosk, or fully managed with the stock launcher
- configuration delivered directly, because we own both ends

So the realistic experience is now **wipe, six taps, scan, walk away** - with a
cable kept in the drawer rather than in the plan.

## What no Device Owner can do

Worth stating because it is always on the wish list: **the 80% charge cap cannot
be set by policy.** Android allowlists which secure settings a Device Owner may
write, and the charging-optimization setting is not among them. It stays an adb
step. That used to be free, because route 3 already had a cable attached at
exactly that moment; on a device provisioned by QR it is a step somebody has to
go and take. Wireless adb works, so it need not be a cable - but it will never
come from the QR.

## Measured device state, 2026-08-18

Two Pixel 6a, both Android 17 (`CP2A.260705.006`), read over adb:

    <device-serial>   Device Owner com.example.ossmdm.launcher   (open-source MDM)
                     app.zippie.companion 0.1.0-107, sideloaded, surviving

    <device-serial>   Device Owner com.google.android.apps.work.clouddpc
                     com.example.commercialmdm.agent; NO companion, none possible
                     isOrganizationOwnedDevice=true
                     userRestriction_no_factory_reset

The second phone is worth dwelling on: the commercial MDM has set
`no_factory_reset`, so it cannot be freed from Settings. The supported exit is
its own wipe command - which is free-tier, unlike installing an application on
it.

## Measured device state, 2026-08-19

<device-serial> again, the same phone, after the QR run above. Read off the
device rather than remembered:

    Device Owner: app.muster.agent/.MusterDeviceAdminReceiver  testOnlyAdmin=false
    Device policy global restrictions: no_safe_boot, no_config_date_time
    files/server-url    written 11:25, during provisioning
    files/identity/     created 11:31

Those lines prove different amounts and should not be quoted as one result.

**The global restrictions are the agent enforcing policy.** It reconciles at
boot from a file, and those two names are `DISALLOW_SAFE_BOOT` and
`DISALLOW_CONFIG_DATE_TIME` as `policy.md` maps them. Measured, in force, after
a reboot.

**`server-url` written during provisioning is the QR's admin extras arriving.**
Nothing on a laptop wrote it - there was no cable. This is what makes Route 2 a
whole route rather than a way to own a phone that then has to be told over adb
where its control plane lives.

**`identity/` is the weakest of the three.** That directory is created by the
identity store's constructor, which runs when the enrollment screen opens, so it
proves the agent launched and got that far. It is not proof that a certificate
was issued: `device.crt` inside it is what would prove that, and nothing
measured on 2026-08-19 names that file. Recorded this way on purpose, so the
next reader does not quote a directory timestamp as an issued identity.
