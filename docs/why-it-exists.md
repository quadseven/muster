# Why muster exists

Moved from README.md on 2026-11-01 and not rechecked.


Every product tried first said no to the same modest ask - push and pull
configuration to a device the household owns, from one place.

- **A mainstream commercial MDM** applies policy on the free tier but will not
  install an application; that is Premium, and it is the one thing needed.
- **An open-source MDM** works and is free, but owns the launcher and brings a
  management model that is not wanted.
- **Android Management API** will not have us at all: its permissible-usage
  policy excludes "solutions developed and used exclusively for first party
  in-house applications", and enrollment fails on the handset at zero devices.

See [docs/android-constraints.md](android-constraints.md) for what Android
actually permits, dated and cited. **Read it before designing any enrollment
UX.** The six-tap QR flow provisioned a Pixel on 2026-08-19 with no cable,
which is one device on one day past a Play Protect check that behaves like a
heuristic - so that file records it as open and measured once, and keeps the
adb route as the fallback.

muster exists because of a decision made in
[zippie](https://github.com/quadseven/zippie): a device should fetch its own
identity over its own credential, rather than have a deploy pipeline splice a
static secret into its config. Several decisions here started as incidents
there.
