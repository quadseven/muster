package app.muster.agent

/**
 * Whether to download an application's bytes at all, decided before spending
 * them (muster#146).
 *
 * WHY THIS EXISTS. An APK signed by a different key than the installed copy
 * can never install over it - Android answers INSTALL_FAILED_UPDATE_INCOMPATIBLE
 * every time - and the agent fetched the same 19.5 MB four times in eleven
 * minutes on a phone that is itself somebody's uplink, failing identically
 * each time, because nothing remembered the last attempt. Two rules end that:
 *
 *   BACK OFF. Bytes that failed to install are not fetched again until a wait
 *   that doubles with each failure has passed. Keyed by the DIGEST the policy
 *   names, so an operator who publishes a fixed build is not made to wait for
 *   the broken one's clock.
 *
 *   REFUSE RATHER THAN RETRY. Once a download has shown which key signed those
 *   bytes, that answer cannot change - the digest pins the bytes - so a later
 *   check-in compares it against the installed copy's signer WITHOUT
 *   downloading, and refuses with a concern naming the reason.
 *
 * Pure, so the deciding is tested on a JVM; `AppInstallSteward` reads the
 * signers off the platform and keeps the record in `InstallLedger`.
 */
object InstallGate {

    const val INCOMPATIBLE = "INSTALL_FAILED_UPDATE_INCOMPATIBLE"

    /**
     * Longer than the fifteen-minute check-in, or the first wait would expire
     * before the next run and backing off would change nothing.
     */
    const val FIRST_BACKOFF_S: Long = 30 * 60

    /** A day: a broken build is still retried daily, not abandoned. */
    const val MAX_BACKOFF_S: Long = 24 * 60 * 60

    /** How often installing one set of bytes has failed, and when to try again. */
    data class Attempts(val failures: Int, val retryAtS: Long)

    sealed interface Decision {
        object Fetch : Decision

        /** Failed recently; not fetched again until [attempts] says so. */
        data class Wait(val attempts: Attempts) : Decision

        /** Known to be signed by a key the installed copy will not accept. */
        object Incompatible : Decision
    }

    /**
     * @param installed the installed copy's signer digests; null when it is
     *   not installed, empty when they could not be read.
     * @param remembered the signer lineage of these exact bytes, from an
     *   earlier download; null when none has been seen.
     */
    fun decide(
        replaceIfSignerDiffers: Boolean,
        installed: Set<String>?,
        remembered: Set<String>?,
        attempts: Attempts?,
        nowS: Long,
    ): Decision {
        // THE REPLACE FLAG OPTS OUT OF THE REFUSAL, not out of the backoff: a
        // line that authorizes removing the installed copy is asking for the
        // mismatch to be resolved, and the steward does that after a download.
        val knownToDiffer = !replaceIfSignerDiffers && installed != null && remembered != null &&
            compatible(installed, remembered) == false
        return when {
            knownToDiffer -> Decision.Incompatible
            attempts != null && nowS < attempts.retryAtS -> Decision.Wait(attempts)
            else -> Decision.Fetch
        }
    }

    /**
     * Would Android accept bytes with this signer lineage over this install?
     *
     * THE LINEAGE, NOT ONLY THE CURRENT KEY. A v3 APK whose key rotated carries
     * the history back to the old one and installs in place; comparing current
     * keys alone would call that a mismatch and refuse an update that works.
     * Null when either side could not be read - "I could not tell" must never
     * read as "they differ".
     */
    fun compatible(installed: Set<String>, incomingLineage: Set<String>): Boolean? {
        if (installed.isEmpty() || incomingLineage.isEmpty()) return null
        return incomingLineage.containsAll(installed)
    }

    /** One more failure, and the wait before the next attempt. */
    fun failed(previous: Attempts?, nowS: Long): Attempts {
        val failures = (previous?.failures ?: 0) + 1
        return Attempts(failures, nowS + backoffS(failures))
    }

    private fun backoffS(failures: Int): Long {
        // Doubling stops well before a shift could overflow: 2^6 already
        // passes a day from half an hour.
        val doublings = (failures - 1).coerceIn(0, 16)
        return (FIRST_BACKOFF_S shl doublings).coerceAtMost(MAX_BACKOFF_S)
    }

    /** The concern for a refusal, naming the reason Android would give. */
    fun incompatible(packageName: String, asset: String): String =
        "$packageName: $INCOMPATIBLE - the installed copy is signed by a different " +
            "key, so $asset cannot install over it and is not downloaded again. " +
            "Add 'replace-if-signer-differs' to the policy line to remove it " +
            "first - THAT DELETES ITS DATA - or wipe the device."

    /** The concern for a wait, saying when the next attempt is. */
    fun waiting(packageName: String, attempts: Attempts, nowS: Long): String {
        val minutes = ((attempts.retryAtS - nowS).coerceAtLeast(0) + 59) / 60
        return "$packageName: installing failed ${attempts.failures} times; " +
            "next attempt in ${minutes}m"
    }

    fun write(attempts: Attempts): String = "${attempts.failures}:${attempts.retryAtS}"

    /** Null for anything damaged: no record is a fetch, never a refusal. */
    fun readAttempts(text: String?): Attempts? {
        val parts = text?.split(":")?.takeIf { it.size == 2 } ?: return null
        val failures = parts[0].toIntOrNull() ?: return null
        val retryAtS = parts[1].toLongOrNull() ?: return null
        return Attempts(failures, retryAtS)
    }

    fun writeSigners(signers: Set<String>): String = signers.sorted().joinToString(",")

    fun readSigners(text: String?): Set<String>? =
        text?.split(",")?.filter { it.isNotEmpty() }?.toSet()?.takeIf { it.isNotEmpty() }
}
