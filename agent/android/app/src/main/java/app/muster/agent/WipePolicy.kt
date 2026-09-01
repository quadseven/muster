package app.muster.agent

/**
 * Whether a wipe file on disk is a real instruction to erase the device.
 *
 * WHY THIS OBJECT EXISTS. `DevicePolicyManager.wipeData()` is irreversible and
 * cannot be unit tested: it needs hardware, and running it twice is not a test,
 * it is two wiped devices. So the decision is extracted here, as a pure
 * function, and the call stays in WipeSteward where no JVM test pretends to
 * prove it.
 *
 * THE FILE IS THE SAME VOCABULARY AS EVERY OTHER POLICY. The server returns
 * `wipe` in the same `files` map as `restrictions` and `app-config`, and
 * ConfigurationSteward writes it into device-protected storage. WipeSteward
 * reads that file later in the same boot plan, so the existing reconcile
 * machinery remains the only apply path.
 *
 * THE CONTENT IS COMPARED EXACTLY. An absent file means no instruction. An
 * empty file is a local write gone wrong or a partial answer and must not be
 * read as a wipe. Only the exact command the server synthesizes means yes.
 */
object WipePolicy {

    const val FILE_NAME = "wipe"

    /**
     * The exact bytes the server sends when the kith says a device is
     * wipe-pending. Kept as a newline-terminated line, like every other managed
     * file, rather than an empty file: an empty file would be indistinguishable
     * from a truncated write.
     */
    const val COMMAND = "wipe\n"

    data class Plan(val wipe: Boolean, val reason: String) {
        override fun toString(): String = "wipe=$wipe reason=$reason"
    }

    fun plan(onDevice: String?): Plan = when (onDevice) {
        null -> Plan(false, "no wipe instruction")
        COMMAND -> Plan(true, "the wipe instruction arrived")
        "" -> Plan(false, "wipe file is empty; refusing to treat a partial write as an erase")
        else -> Plan(false, "wipe file content is not the command; refusing to guess")
    }
}
