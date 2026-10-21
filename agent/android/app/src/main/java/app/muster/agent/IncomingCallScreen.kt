package app.muster.agent

import android.app.role.RoleManager
import android.content.Context
import android.telecom.Call
import android.telecom.CallScreeningService
import android.util.Log
import java.io.IOException

/**
 * Where `block-incoming` is enforced: every incoming call is rejected before
 * it rings.
 *
 * WHY A SCREENER AND NOT A RESTRICTION. AOSP has no user restriction that
 * refuses an incoming call. Telecom binds the app holding
 * `RoleManager.ROLE_CALL_SCREENING` for every new call and waits for this
 * service's answer before ringing, so holding the role is the one route a
 * Device Owner has to a handset that never rings.
 *
 * THE ROLE CANNOT BE TAKEN SILENTLY. No DevicePolicyManager call grants it; a
 * person accepts the platform's dialog once, which StatusActivity raises while
 * the file asks for `block-incoming` and the role is not held. [roleHeld] is
 * the read-back: the status screen and TelephonySteward ask the platform, not
 * this app's memory of having asked.
 *
 * WHAT IT CANNOT DO, from AOSP `CallScreeningService.java` (read 2026-10-21).
 * Telecom does not show the screener calls from a withheld or unknown number,
 * or from a number in the device's contacts, so those still ring - an
 * appliance has no contacts, and a withheld caller is what the carrier step
 * covers. `setSkipCallLog` is honoured only for the carrier and system
 * screeners, so a rejected call is still logged as BLOCKED. And a rejected
 * call can still be diverted to voicemail by the carrier, which is why the
 * MMI step in docs/policy.md stays.
 */
class IncomingCallScreen : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        val incoming = callDetails.callDirection == Call.Details.DIRECTION_INCOMING
        val reject = TelephonyPolicy.rejects(desired(), incoming)
        val response = CallScreeningService.CallResponse.Builder()
            .setDisallowCall(reject)
            .setRejectCall(reject)
            .setSkipCallLog(reject)
            .setSkipNotification(reject)
            .build()
        // Answered every time, allow included: telecom holds the ring until it
        // hears back or five seconds pass.
        respondToCall(callDetails, response)
        if (reject) Log.i(TAG, "incoming call rejected: telephony file asks for block-incoming")
    }

    /**
     * The telephony file as it stands now, not as it stood at boot, so a
     * policy change takes effect on the next call.
     *
     * An absent or unreadable file blocks nothing. Unreadable is logged as an
     * error: the operator asked for something this call is not getting.
     */
    private fun desired(): TelephonyPolicy.Desired {
        val file = TelephonySteward(this).configFile()
        if (!file.isFile) return TelephonyPolicy.read(null)
        return try {
            TelephonyPolicy.read(file.readText())
        } catch (e: IOException) {
            Log.e(TAG, "telephony file unreadable; letting the call through", e)
            TelephonyPolicy.read(null)
        }
    }

    companion object {
        private const val TAG = "muster"

        /** Whether the platform says this app is the call screener. */
        fun roleHeld(context: Context): Boolean =
            context.getSystemService(RoleManager::class.java)
                ?.isRoleHeld(RoleManager.ROLE_CALL_SCREENING) == true
    }
}
