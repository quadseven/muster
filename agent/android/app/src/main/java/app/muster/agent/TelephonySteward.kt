package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.UserManager
import android.util.Log
import java.io.File

/**
 * Put the device's telephony restrictions where the config file says they
 * should be.
 *
 * WHERE THE CONFIG COMES FROM, and why it is a file. Same reasoning as the
 * restrictions beside it: this app is Device Owner, so anything baked into
 * the APK can only be changed by a release, and a release eventually costs a
 * factory reset when the signing key moves. A file pushed over adb is the
 * difference between changing policy and shipping one.
 *
 * AN ABSENT FILE IS NOT AN EMPTY ONE. No file at all means nothing has been
 * configured, and the device is left exactly as it is. A file that exists and
 * is empty means "no telephony restrictions", and anything muster previously
 * set comes off.
 *
 * WHAT THE DEVICE CAN AND CANNOT ENFORCE. `block-outgoing` becomes
 * `no_outgoing_calls` through `DevicePolicyManager.addUserRestriction`, and
 * the platform enforces it (emergency calls always bypass). `block-incoming`
 * has no platform key at all - AOSP refuses nothing incoming - so it is an
 * operator step: an MMI divert code or a data-only plan that never rings. The
 * steward applies what it can and reports what it cannot.
 *
 * THE READ-BACK IS THE REASON THIS RETURNS A SHAPE RATHER THAN A BOOLEAN,
 * for the same reason as RestrictionSteward: `addUserRestriction` does not
 * reject a key the platform does not know, and asking what is actually in
 * force is the only question whose answer is about the device.
 */
class TelephonySteward(private val context: Context) {

    /** Where `muster telephony` pushes the file, and where ConfigurationSteward writes it. */
    fun configFile(): File = File(
        // Device-protected, like everything else the boot path reads: this runs
        // at LOCKED_BOOT_COMPLETED, before first unlock, and a credential-
        // protected read there fails in a way that looks like an empty config.
        context.createDeviceProtectedStorageContext().filesDir, TelephonyPolicy.FILE_NAME
    )

    /**
     * What happened, for the caller to log.
     *
     * [blockIncomingRequested] is the line that matters: the file asked for
     * incoming calls to be blocked, and the device cannot do it. It is
     * reported so the operator knows to set an MMI divert or a data-only plan
     * at the carrier instead.
     */
    data class Outcome(
        val added: List<String> = emptyList(),
        val cleared: List<String> = emptyList(),
        val refused: List<TelephonyPolicy.Refusal> = emptyList(),
        val didNotTake: List<String> = emptyList(),
        val blockIncomingRequested: Boolean = false,
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            inert?.let { add("nothing enforced - $it") }
            refused.forEach { add("REFUSED '${it.line}' - ${it.why}") }
            if (didNotTake.isNotEmpty()) add("DID_NOT_TAKE $didNotTake")
            if (blockIncomingRequested) {
                add("BLOCK_INCOMING requested but not device-enforceable - set an MMI divert or a data-only plan at the carrier")
            }
        }
        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            else -> buildString {
                append("added=$added cleared=$cleared")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
                if (didNotTake.isNotEmpty()) append(" DID_NOT_TAKE=$didNotTake")
                if (blockIncomingRequested) append(" BLOCK_INCOMING=requested-not-enforceable")
            }
        }
    }

    fun reconcile(): Outcome {
        val file = configFile()
        if (!file.isFile) return Outcome(inert = "no telephony file at ${file.absolutePath}")

        // Checked, not assumed. addUserRestriction without ownership throws
        // SecurityException, and at BOOT_COMPLETED that takes the receiver
        // down with it.
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            return Outcome(inert = "not device owner; telephony restrictions cannot be set")
        }
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Outcome(inert = "no DevicePolicyManager")
        val admin = MusterDeviceAdminReceiver.component(context)
        val users = context.getSystemService(UserManager::class.java)

        val desired = TelephonyPolicy.read(file.readText())
        // What is ACTUALLY in force, which is what decides whether to add.
        val inForce = users?.userRestrictions.asKeys()
        // What THIS admin recorded setting, which is what may be withdrawn.
        val setByUs = dpm.getUserRestrictions(admin).asKeys()

        val plan = TelephonyPolicy.plan(desired, inForce = inForce, setByUs = setByUs)
        for (refusal in plan.refused) {
            Log.w(TAG, "telephony refused: ${refusal.line} - ${refusal.why}")
        }
        if (plan.changesNothing && !plan.blockIncoming) {
            return Outcome(
                refused = plan.refused,
                blockIncomingRequested = plan.blockIncoming,
            )
        }

        for (key in plan.add) dpm.addUserRestriction(admin, key)
        for (key in plan.clear) dpm.clearUserRestriction(admin, key)

        // READ BACK. Asking what is actually in force is the only question
        // whose answer distinguishes a restriction from a string - and it is
        // what catches a wrong literal in the table on the first device
        // rather than the tenth.
        val after = users?.userRestrictions.asKeys()
        val didNotTake = if (users == null) emptyList() else plan.add.filterNot { it in after }

        for (key in didNotTake) {
            Log.e(TAG, "telephony restriction '$key' was set but is not in force - the platform ignored it")
        }
        Log.i(TAG, "telephony added=${plan.add} cleared=${plan.clear} blockIncoming=${plan.blockIncoming}")

        return Outcome(
            added = plan.add,
            cleared = plan.clear,
            refused = plan.refused,
            didNotTake = didNotTake,
            blockIncomingRequested = plan.blockIncoming,
        )
    }

    companion object {
        private const val TAG = "muster"

        /**
         * The restriction keys a Bundle actually asserts.
         *
         * A key present with a value of `false` is not a restriction, it is a
         * key - both bundles here can carry those, and treating a key set as a
         * restriction set would have muster believe policy was in force that
         * was not.
         */
        private fun Bundle?.asKeys(): Set<String> {
            val bundle = this ?: return emptySet()
            return bundle.keySet().filter { bundle.getBoolean(it, false) }.toSet()
        }
    }
}
