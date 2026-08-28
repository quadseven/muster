package app.muster.agent

import android.content.Context

/**
 * When this device last did anything about its own configuration.
 *
 * Recorded because "last check-in" is the first thing anybody asks about a
 * device that is behaving oddly, and until now the only answer available was
 * `adb logcat`, which needs wireless debugging, a pairing, and a tunnel to
 * whatever LAN the phone happens to be on.
 *
 * DEVICE-PROTECTED, like everything else the boot path touches: the value is
 * written from BOOT_COMPLETED, which on a locked phone fires before first
 * unlock.
 */
object CheckIn {
    private const val PREFS = "muster-checkin"
    private const val KEY = "last-epoch-seconds"

    private fun prefs(context: Context) =
        context.createDeviceProtectedStorageContext()
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun record(context: Context, epochSeconds: Long) {
        prefs(context).edit().putLong(KEY, epochSeconds).apply()
    }

    /** Null means never, which must not render as "0 minutes ago". */
    fun last(context: Context): Long? =
        prefs(context).getLong(KEY, -1L).takeIf { it > 0 }
}
