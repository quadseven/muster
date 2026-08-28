package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Bundle
import android.os.UserManager
import android.util.Log
import java.io.File

/**
 * Put the device's user restrictions where the config file says they should be.
 *
 * WHERE THE CONFIG COMES FROM, and why it is a file. Same reasoning as the
 * wallpaper beside it: this app is Device Owner, so anything baked into the APK
 * can only be changed by a release, and a release eventually costs a factory
 * reset when the signing key moves. A file pushed over adb is the difference
 * between changing policy and shipping one.
 *
 * AN ABSENT FILE IS NOT AN EMPTY ONE. No file at all means nothing has been
 * configured, and the device is left exactly as it is. A file that exists and
 * is empty means "no restrictions", and anything muster previously set comes
 * off. Collapsing those two would make a first boot on an unconfigured device
 * indistinguishable from a deliberate instruction to withdraw everything.
 */
class RestrictionSteward(private val context: Context) {

    /** Where `muster restrictions` pushes the file. */
    fun configFile(): File = File(
        // Device-protected, like everything else the boot path reads: this runs
        // at LOCKED_BOOT_COMPLETED, before first unlock, and a credential-
        // protected read there fails in a way that looks like an empty config.
        context.createDeviceProtectedStorageContext().filesDir, "restrictions"
    )

    /**
     * What happened, for the caller to log.
     *
     * [didNotTake] is the one that matters and the reason this returns a shape
     * rather than a boolean. A restriction that was asked for, did not error,
     * and is not in force afterwards is the failure this whole class exists to
     * make visible.
     */
    data class Outcome(
        val added: List<String> = emptyList(),
        val cleared: List<String> = emptyList(),
        val refused: List<RestrictionPolicy.Refusal> = emptyList(),
        val didNotTake: List<String> = emptyList(),
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            inert?.let { add("nothing enforced - $it") }
            refused.forEach { add("REFUSED '${it.line}' - ${it.why}") }
            if (didNotTake.isNotEmpty()) add("DID_NOT_TAKE $didNotTake")
        }
        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            else -> buildString {
                append("added=$added cleared=$cleared")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
                if (didNotTake.isNotEmpty()) append(" DID_NOT_TAKE=$didNotTake")
            }
        }
    }

    fun reconcile(): Outcome {
        val file = configFile()
        if (!file.isFile) return Outcome(inert = "no restrictions file at ${file.absolutePath}")

        // Checked, not assumed. addUserRestriction without ownership throws
        // SecurityException, and at BOOT_COMPLETED that takes the receiver down
        // with it - along with everything else the receiver was going to do.
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            return Outcome(inert = "not device owner; restrictions cannot be set")
        }
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Outcome(inert = "no DevicePolicyManager")
        val admin = MusterDeviceAdminReceiver.component(context)

        val desired = RestrictionPolicy.read(file.readText())
        val users = context.getSystemService(UserManager::class.java)

        // What is ACTUALLY in force, which is what decides whether to add.
        val inForce = users?.userRestrictions.asKeys()
        // What THIS admin recorded setting, which is what may be withdrawn.
        // Another admin's restriction is not ours to clear.
        val setByUs = dpm.getUserRestrictions(admin).asKeys()

        val plan = RestrictionPolicy.plan(desired, inForce = inForce, setByUs = setByUs)
        for (refusal in plan.refused) {
            Log.w(TAG, "restriction refused: ${refusal.line} - ${refusal.why}")
        }
        if (plan.changesNothing) {
            return Outcome(refused = plan.refused)
        }

        for (key in plan.add) dpm.addUserRestriction(admin, key)
        for (key in plan.clear) dpm.clearUserRestriction(admin, key)

        // READ BACK, and read back the EFFECTIVE set rather than the bundle we
        // just wrote to. addUserRestriction does not reject a key the platform
        // does not know: the call returns, the admin's own bundle can hold it,
        // and nothing enforces anything. Asking what is actually in force is
        // the only question whose answer distinguishes a restriction from a
        // string - and it is what catches a wrong literal in the table on the
        // first device rather than the tenth.
        val after = users?.userRestrictions.asKeys()
        // No UserManager means the verification could not be done, which is not
        // the same as it having failed. Reporting every restriction as having
        // not taken would be a false alarm on a device that is probably fine.
        val didNotTake = if (users == null) emptyList() else plan.add.filterNot { it in after }

        for (key in didNotTake) {
            Log.e(TAG, "restriction '$key' was set but is not in force - the platform ignored it")
        }
        Log.i(TAG, "restrictions added=${plan.add} cleared=${plan.clear}")

        return Outcome(
            added = plan.add,
            cleared = plan.clear,
            refused = plan.refused,
            didNotTake = didNotTake,
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
