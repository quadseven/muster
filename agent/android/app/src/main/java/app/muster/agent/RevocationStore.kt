package app.muster.agent

import android.content.Context

/** Device-protected storage for the revocation answer shown on status. */
object RevocationStore {
    private const val PREFS = "muster-revocation"
    private const val KEY = "revoked"

    private fun prefs(context: Context) =
        context.createDeviceProtectedStorageContext()
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun current(context: Context): Boolean = prefs(context).getBoolean(KEY, false)

    fun record(context: Context, fetched: ConfigurationClient.Fetched) {
        val before = current(context)
        val after = RevocationStatus.next(before, fetched)
        if (after != before) prefs(context).edit().putBoolean(KEY, after).apply()
    }
}
