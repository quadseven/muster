# Company-owned Android enrollment and recovery

Muster's Android agent can manage a company-owned, work-only handset as
Device Owner. The proposed Android Management API integration would use
Google's Android Device Policy as the controller and Muster as the console.
That integration remains a pilot plan.

## Enroll with the Muster agent

1. Choose a spare handset for the first run. Confirm that the existing
   administrator can release it, that needed data can be restored, and that
   authorized Factory Reset Protection recovery is available. Record how to
   recover any required eSIM before authorizing a reset.
2. Sign in to the Muster console and open Provisioning. Confirm that the
   published APK has the expected release signing certificate before wiping
   a company handset. A debug-signed APK is suitable for a disposable test
   only. The console's checksum check confirms that the QR and the published
   APK agree. Download `/agent.apk` from the intended deployment and use
   `apksigner verify --print-certs agent.apk` to compare its certificate
   SHA-256 digest with the approved signing pin. [Agent signing](signing-ceremony.md)
3. Use the existing controller's supported release or wipe procedure when
   the handset is managed. At the welcome screen after reset, follow the
   six-tap QR procedure. If Play Protect refuses the agent, use the documented
   cable fallback on a freshly reset handset with no accounts or secondary
   users. The cable fallback needs physical access and an authorized USB
   debugging session. [Pixel setup and cable fallback](provisioning-a-pixel.md)
4. Open the Muster status screen. Confirm that it reports `Muster (Device
   Owner)` and a valid identity. If a QR provisions the controller but
   leaves the device unenrolled, use a fresh typed pairing code and compare
   the key fingerprint shown on the handset and in the console before
   approving. Tap **Check in now** and confirm that a new report reaches the
   console. The handset's check-in timestamp alone tracks an attempt.

Verify the screen lock and timeout, encryption status and security update
state on the handset before handover. The Muster identity and check-in
screens do not attest to those three compliance requirements. Muster can
assign signed APKs through `install-apps` and report version drift for
packages named there. Public Play apps require manual installation wherever
Play is available. Signing in with a work account provides app access.
Controller ownership is set during provisioning. [App installation and drift](policy.md#installing-applications)

## Recover a Muster handset

| Observed state | Recovery |
| --- | --- |
| Device Owner is present and no identity has been issued | Use the typed pairing procedure and compare the fingerprint. Follow the console until the device collects its certificate. |
| The device is revoked and the certificate still works | After confirming the device should return to service, use **Readmit**, then verify a new report. |
| The clock is wrong or the certificate has lapsed | Correct the clock and check the status again. A genuinely lapsed certificate requires re-enrollment. The current form can refuse re-enrollment while the old certificate file remains, even when the status screen offers it. Plan approved reset and reprovisioning if the identity cannot be recovered. |
| Controller or signing key must change | Back up needed data and verify access with the current administrator. Reset through the supported procedure, then provision the approved controller and restore only the required apps and data. Recheck ownership, identity and policy. |

A queued erase means the handset has yet to act. The device needs a working
management connection to collect it. Erase can still be pending while a
handset is offline. Verify the reset on the handset before reassigning it.
[Muster erase behavior](policy.md#erasing-a-device-and-how-long-that-takes)

## Evaluate Android Management API separately

1. Confirm eligibility with Google before creating a test enterprise.
   Google's current policy restricts the API to eligible providers and
   prohibits exclusive first-party in-house use. Device enrollment requires
   Android Enterprise registration and approval, and the quickstart requires
   initial device quota. Obtain applicable product validation before
   production use. [Permissible usage](https://developers.google.com/android/management/permissible-usage)
   [Enrollment approval](https://developers.google.com/android/management/release-notes#november-2025)
   [Quickstart and quota](https://developers.google.com/android/management/quickstart)
   [Release requirements](https://developers.google.com/android/work/release-solution)
2. Use a separate approved test project and enterprise, a test-only policy,
   and a spare company-owned handset. Keep accounts, tokens, enterprise and
   device identifiers, and private policy values outside the public
   repository. Create an enrollment token with personal usage disallowed
   and scan its QR during setup on the reset handset. Verify that Android
   Device Policy owns the device and that its record belongs to the test
   enterprise. [Google's provisioning guide](https://developers.google.com/android/management/provision-device)
3. Test enrollment, policy reporting, and a public Play assignment end to
   end before advertising managed Play. Verify app installation on the
   handset and compare it with the device report. Treat an unverified
   outcome as unknown. Rehearse recovery with the spare handset. A
   company-owned wipe is a factory reset. Verify the reset before enrolling
   the handset again. [App distribution](https://developers.google.com/android/management/apps)
   [Wipe behavior](https://developers.google.com/android/management/deprovision-device)

Google's in-place DPC migration requires a custom controller integrated with
the AMAPI SDK and a device already enrolled through the Google Play EMM API
in a Managed Google Play Accounts enterprise. The transfer is one-way within
the same EMM and enterprise. Existing Muster enrollments lack these
prerequisites. A pilot uses a reset and fresh enrollment on a spare handset.
Returning it to the Muster agent requires reprovisioning from another reset.
[Google's DPC migration prerequisites](https://developers.google.com/android/management/dpc-migration)
