package app.muster.agent

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * The component that holds Device Owner.
 *
 * THIS CLASS'S NAME IS AN INTERFACE, not an implementation detail. It appears
 * in `adb shell dpm set-device-owner app.muster.agent/.MusterDeviceAdminReceiver`
 * and, once set, in the device's own policy state. Renaming it after a device
 * has been provisioned does not migrate that device - it strands it, because
 * the component the system holds no longer exists and Device Owner cannot be
 * reassigned without a factory reset. Rename only on something wiped.
 *
 * QR PROVISIONING WORKS, and this comment used to say it could not.
 *
 * It previously recorded that Google gates enterprise provisioning behind a
 * Play Protect allowlist of approved DPCs and that `adb dpm set-device-owner`
 * was therefore the only route - "the reason provisioning costs one cable". On
 * 2026-08-19 a wiped Pixel 6a scanned a provisioning QR and came up owned by
 * this receiver, with no cable at any point.
 *
 * The allowlist is real and the earlier failure was ours: the agent had no
 * activity for GET_PROVISIONING_MODE or ADMIN_POLICY_COMPLIANCE, so it never
 * reached the gate. See ProvisioningModeActivity. Whether Play Protect always
 * permits this DPC is one measurement, not a guarantee - which is why the
 * four-permission profile is pinned by a test.
 */
class MusterDeviceAdminReceiver : DeviceAdminReceiver() {

    companion object {
        private const val TAG = "muster"

        /** The component to hand to `dpm set-device-owner`. */
        fun component(context: Context): ComponentName =
            ComponentName(context, MusterDeviceAdminReceiver::class.java)

        /**
         * Are we Device Owner right now?
         *
         * Asked of the SYSTEM every time rather than cached in a preference.
         * Ownership can be lost - a factory reset, a `dpm remove-active-admin`
         * during development - and a cached "yes" would make every subsequent
         * policy call fail with a SecurityException that reads like a bug in
         * the call rather than like a device that is no longer ours.
         */
        fun isDeviceOwner(context: Context): Boolean {
            val dpm = context.getSystemService(DevicePolicyManager::class.java)
            return dpm?.isDeviceOwnerApp(context.packageName) == true
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        // Still deliberately quiet about PRIVILEGED work. This fires when the
        // admin is activated, which is BEFORE ownership is necessarily
        // established, so it remains the wrong place to start setting policy -
        // see isDeviceOwner above.
        Log.i(TAG, "device admin enabled; owner=${isDeviceOwner(context)}")

        // BUT THE CHECK-IN JOB IS SCHEDULED HERE, AND HAS TO BE.
        //
        // `ensureScheduled` was reachable from exactly one place: BootReceiver,
        // on BOOT_COMPLETED. On a device provisioned from a QR that event fired
        // long before this APK existed, so a freshly enrolled handset scheduled
        // NOTHING - it took its configuration once and went inert, with zero
        // jobs in `dumpsys jobscheduler`. Nothing reported an error because
        // nothing failed; the loop was simply never started, and only a reboot
        // could start it.
        //
        // Scheduling needs no ownership - it is JobScheduler, not
        // DevicePolicyManager - so it is safe at this point in a way that
        // policy work is not. `ensureScheduled` is idempotent, which is what
        // the comment on CheckInJob always claimed of its "both paths" while
        // only one existed.
        CheckInJob.ensureScheduled(context)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        Log.w(TAG, "device admin DISABLED - this device is no longer managed")
    }

    /**
     * Shown to a human before they are allowed to disable the admin.
     *
     * Empty string is not an option: the system shows this text in a
     * confirmation dialog, and a blank one reads as a broken app rather than as
     * a deliberate warning.
     */
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Disabling this removes muster's management of this device. " +
            "Configuration will stop being applied and the device will leave the kith."
}
