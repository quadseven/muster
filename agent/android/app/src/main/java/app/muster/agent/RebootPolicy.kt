package app.muster.agent

/**
 * Whether a reboot file on disk is a real instruction to restart the device.
 *
 * THE SAME SHAPE AS WipePolicy, ONE SEVERITY DOWN (muster#58).
 * `DevicePolicyManager.reboot()` needs hardware and is not something a JVM
 * test should pretend to prove, so the decision is extracted here as a pure
 * function and the call stays in RebootSteward where no test claims to have
 * exercised it.
 *
 * THE FILE IS THE SAME VOCABULARY AS WIPE. The server returns `reboot` in the
 * same `files` map as `restrictions` and `wipe`, synthesized from the kith's
 * `reboot_requested_at` rather than read from the policy directory - see
 * `policy.py`'s `for_device`.
 *
 * THE CONTENT IS COMPARED EXACTLY, for the same reason WipePolicy compares
 * exactly: an absent file means no instruction, and an empty file is a local
 * write gone wrong rather than a command.
 */
object RebootPolicy {

    const val FILE_NAME = "reboot"

    /**
     * The exact bytes the server sends when the kith says a device is
     * reboot-requested. Newline-terminated, matching every other managed file
     * and WipePolicy.COMMAND specifically, so an empty file cannot be
     * mistaken for this command by a truncated write.
     */
    const val COMMAND = "reboot\n"

    data class Plan(val reboot: Boolean, val reason: String, val isQuietHealthy: Boolean = false) {
        override fun toString(): String = "reboot=$reboot reason=$reason"
    }

    fun plan(onDevice: String?): Plan = when (onDevice) {
        // No instruction on the device is the quiet healthy case: the steward
        // did exactly what it was told, and the step must not read as a
        // concern - same reasoning as WipePolicy's own quiet-healthy case,
        // and for the same reason muster#44 exists.
        null -> Plan(false, "no reboot instruction", isQuietHealthy = true)
        COMMAND -> Plan(true, "the reboot instruction arrived")
        "" -> Plan(false, "reboot file is empty; refusing to treat a partial write as an instruction")
        else -> Plan(false, "reboot file content is not the command; refusing to guess")
    }
}
