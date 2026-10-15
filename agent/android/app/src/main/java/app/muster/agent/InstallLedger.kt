package app.muster.agent

import android.content.Context

/**
 * What earlier check-ins learned about installing each set of bytes, so the
 * next one does not have to download them to find out again (muster#146).
 *
 * Keyed by the sha256 the policy names. Those bytes cannot change under that
 * name, so neither can their signer, and a failure recorded against them is a
 * failure of exactly what would be fetched next. A policy that names a new
 * build names a new digest and starts clean.
 *
 * DEVICE-PROTECTED, like everything else the boot path touches: install-apps
 * runs from BOOT_COMPLETED, which on a locked phone fires before first unlock.
 * The decisions themselves are `InstallGate`'s; this only remembers.
 */
class InstallLedger(context: Context) {

    private val prefs = context.createDeviceProtectedStorageContext()
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun attempts(digest: String): InstallGate.Attempts? =
        InstallGate.readAttempts(prefs.getString(ATTEMPTS + digest, null))

    /** Record one more failed install of these bytes, and return the new wait. */
    fun failed(digest: String, nowS: Long): InstallGate.Attempts {
        val attempts = InstallGate.failed(attempts(digest), nowS)
        prefs.edit().putString(ATTEMPTS + digest, InstallGate.write(attempts)).apply()
        return attempts
    }

    /** The signer lineage a download of these bytes showed, if one did. */
    fun signers(digest: String): Set<String>? =
        InstallGate.readSigners(prefs.getString(SIGNERS + digest, null))

    fun rememberSigners(digest: String, lineage: Set<String>) {
        if (lineage.isEmpty()) return
        prefs.edit().putString(SIGNERS + digest, InstallGate.writeSigners(lineage)).apply()
    }

    /** These bytes installed: nothing about them needs remembering any more. */
    fun succeeded(digest: String) {
        prefs.edit().remove(ATTEMPTS + digest).remove(SIGNERS + digest).apply()
    }

    /**
     * Forget every digest the policy no longer names, so the record is bounded
     * by the install file rather than by every build ever published.
     */
    fun keepOnly(digests: Set<String>) {
        val stale = prefs.all.keys.filter { key ->
            val digest = key.removePrefix(ATTEMPTS).removePrefix(SIGNERS)
            digest !in digests
        }
        if (stale.isEmpty()) return
        val edit = prefs.edit()
        stale.forEach { edit.remove(it) }
        edit.apply()
    }

    private companion object {
        const val PREFS = "muster-install-ledger"
        const val ATTEMPTS = "attempts:"
        const val SIGNERS = "signers:"
    }
}
