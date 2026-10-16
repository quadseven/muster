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
CLOSED verdict, and do not treat Route 2 as OPEN until a run has been seen to pass the gate: it
behaves like a heuristic, and a heuristic is allowed to change its mind.

## The three routes, and their status

| Route | Status | The gate |
|---|---|---|
| Call the Android Management API ourselves | **CLOSED** | Commercial-EMM eligibility |
| Our own DPC, provisioned by QR / six-tap | **UNMEASURED** | Play Protect's approved-DPC check - no run has yet been attributed to it, see below |
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

## Route 2: our own DPC by QR - Play Protect's verdict unmeasured

This is the flow everyone asks for by name: factory reset, tap the welcome screen
six times, scan a QR, walk away. Whether Play Protect lets this agent through
has not been measured: the one attempt recorded below failed before that gate.

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

**The Play Protect verdict, either way.** The gate is the approved-DPC check, and
everything known about it says it behaves like
a harmful-app heuristic rather than a strict list: devices sometimes offer a
"continue", and developers have cleared it by dropping permissions that read as
dangerous. Even a pass on one APK, one handset, one Android build and one date would
promise nothing about the next one - and
Google can move it without announcing anything, which is how it arrived in the
first place.

So: keep Route 3 working, and treat each Route 2 attempt as a measurement. The
cost of the heuristic saying no is a handset that has already been wiped.

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

Both activities now exist and `ProvisioningManifestTest` fails if the manifest
stops declaring either, because the failure costs a wipe and names no cause on
the handset. No run has yet been recorded here with that fix in place.

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
the bet that it helps - a hypothesis, not a measurement, because no run has
shown the gate's answer. The agent declares four permissions:
`RECEIVE_BOOT_COMPLETED`, `SET_WALLPAPER`, `INTERNET`, `ACCESS_NETWORK_STATE`,
and guards its components with `BIND_DEVICE_ADMIN`, which only the system holds. No SMS, no notification listener, no accessibility. Adding a
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

It may not be the only way in, but until Route 2 has been measured end to end it
is the dependable one. What it is for:

- **provisioning at all, if Play Protect refuses** - the fallback that makes
  attempting Route 2 a safe thing to do
- **the 80% charge cap**, which no Device Owner can set by policy at any API
  level (below)
- **battery optimization exemption** for apps configured with a wake directive:
  no Device Owner API can grant this (below), so it stays an adb step
  (`adb shell dumpsys deviceidle whitelist +<package>`) during enrolment
- **anything that needs a shell**, which today includes getting a configuration
  file into the agent at all: #20

Either route ends at the same place, which is the point of keeping both:

- silent install and update of applications, no prompts
- wallpaper set programmatically, and locked against change
- lock-task / kiosk, or fully managed with the stock launcher
- configuration delivered directly, because we own both ends

So the realistic experience is now **wipe, six taps, scan, walk away** - with a
cable kept in the drawer rather than in the plan.

### Battery optimization exemption (required for wake)

For any application configured with a `wake` directive, battery optimization
exemption is a required enrolment step: without it, Android prevents wake from
starting a foreground service at all. Grant it via adb:

```sh
adb -s <serial> shell dumpsys deviceidle whitelist +<package>
```

## What no Device Owner can do

Worth stating because it is always on the wish list: **the 80% charge cap cannot
be set by policy.** Android allowlists which secure settings a Device Owner may
write, and the charging-optimization setting is not among them. It stays an adb
step. That used to be free, because route 3 already had a cable attached at
exactly that moment; on a device provisioned by QR it is a step somebody has to
go and take. Wireless adb works, so it need not be a cable - but it will never
come from the QR.

**Battery optimization exemption cannot be granted by policy.** Verified
against the Android 16 (`android-36`) platform APIs: `DevicePolicyManager` has
no grant path or method to allowlist or exempt an application from battery
optimization (the API contains nothing matching "exempt" or any power/idle
allowlist grant method). `PowerManager.isIgnoringBatteryOptimizations` is
strictly read-only and provides no setter or grant path for Device Owner.

The platform provides only two mechanisms to grant battery optimization
exemption:
1. An interactive prompt initiated by the application itself via
   `Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, requiring a human to
   tap a confirmation dialog on screen.
2. A shell command via adb:
   ```sh
   adb shell dumpsys deviceidle whitelist +<package>
   ```

This is not merely an optimization or a probabilistic risk: **the exemption is a
strict precondition for wake functionality.** Without it, Android's background
execution limits prevent background wake broadcasts from starting a foreground
service at all. Because Device Owner APIs cannot grant the exemption, it cannot
be delivered via policy or QR provisioning; it must be completed as an adb step
during device enrolment whenever an app-config carries a `wake` directive.

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

<device-serial> again, the same phone, after a QR run. Read off the device rather
than remembered. None of it measures Play Protect's verdict:

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
