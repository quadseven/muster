# The muster brand, and what of it is real

Written 2026-08-19, from a design study supplied by the operator. The artwork
lives beside this file:

    docs/brand/muster-app-icon.png     the plate and mark, 1254px
    docs/brand/muster-brand-sheet.png  the full study

**Read the last section before building anything from the study.** Most of the
interface it shows does not exist, and some of it describes devices muster
cannot manage. It is a direction, not a specification.

## The mark

Three stacked plates seen in isometric, the middle one amber. It reads as layers
of a stack, which is the right idea for a control plane, and the amber middle
gives it a single point of emphasis that survives being shrunk to a favicon.

Now the Android agent's launcher icon. The adaptive foreground insets the plate
to 85% of the 108dp layer, because a launcher crops a third of that layer away
and artwork drawn to the edge loses its corners on exactly the devices using the
roundest mask.

## Palette

| Name | Hex | Where it goes |
|---|---|---|
| Charcoal | `#1D1F23` | text, the outer plates of the mark |
| Amber | `#FFB703` | the middle plate; one accent per view, not a theme |
| Warm White | `#FAF7F2` | page and plate background |
| Mist | `#E9ECEF` | dividers, card edges, inactive states |
| Stone | `#6B7280` | secondary text, labels, captions |

Amber is an accent and not a brand wash. In the study it appears once or twice
per surface - the middle plate, a status dot - and everything else is charcoal
on warm white. Using it as a fill for large areas would lose the thing that
makes the mark legible small.

## Type

Satoshi.

    Heading 1   Bold        48px
    Heading 2   SemiBold    32px
    Heading 3   Medium      24px
    Body        Regular     16px
    Caption     Regular     12px

**Check the licence before this ships anywhere public.** Satoshi is distributed
by Fontshare under terms that are free for most use but are not the same thing
as an open-source font licence, and a webfont served from our own origin is a
different question from one used in a design file. Nobody has checked. Until
somebody has, treat the stack as Satoshi with a system fallback rather than
assuming it can be self-hosted.

That is what the console does: it names Satoshi first and falls back to the
system stack, and it fetches no font from anywhere. Fetching one from somebody
else's origin would also be the third-party request that page is built without -
see `docs/observability.md`.

## What exists, and what the study invented

The console today is one file - `server/muster/console.html` - deliberately: it
lists a handful of rows, mints a code, and draws one QR. The study shows a
product several releases further on. Sorting the two apart is the point of this
section.

**Real today**

- Administrator sign-in at the estate's identity provider, and the vouch flow
- The shell the study shows: Overview, Provisioning, Devices, Policies,
  Settings, built from the palette and type scale above. Two of those five are
  honest empty states that say what will be there, which is the point of the
  last section below
- Minting a pairing code, which is read off the screen and typed on the handset
- The provisioning QR: drawn large, with a full-screen view for the moment
  somebody holds a wiped phone up to the monitor, and what it commits to printed
  beside it. There is no pairing QR any more - nothing on a device could read it
- One device, enrolled, holding a certificate

**Buildable next, and roughly what the study shows**

- A device list: the kith, with each device's certificate expiry
- A device detail view: fingerprint, issued/renewed dates, restrictions in force
- Enrollment history

**Invented for the study, and needs a decision before anyone builds it**

- **Total/Online/Offline/Alert counts.** muster has no concept of a device being
  online. `lapse` is the revocation mechanism precisely BECAUSE devices are
  expected to be unreachable for days - a dashboard leading with "12 Offline" in
  red would be reporting the normal state of a working estate as a fault.
- **Platform breakdown across iOS, macOS, Windows and Network.** muster manages
  Android. Nothing else has an agent, and the constraints that shaped this
  project are Android-specific.
- **Security Posture, Reports, Compliance passed.** No such data is collected.
- **"192 devices."** One.

The counts are the part most likely to be built by accident, because they are
the easiest thing on the page to implement and the hardest to notice are
meaningless. A number that is always wrong is worse than a page without it.

## Brand purpose, as given

Trusted - secure by design. Inviting - approachable and human centered.
Clarity - clean interface, actionable insights. Everywhere - manage all your
devices, from anywhere.

Worth holding the third one against the console when it grows: the current page
earns "clarity" by having almost nothing on it, and every addition spends some.
