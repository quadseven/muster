package app.muster.agent

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Fetch this device's configuration and put it where the other stewards read.
 *
 * FIRST IN THE BOOT PLAN, and the order is the point: everything after it -
 * wallpaper, restrictions, app configuration, the launcher allowlist - is a
 * reconciler over files in this directory, so fetching first means one boot
 * both collects a policy change and applies it. Fetching last would mean every
 * change took two boots, on appliances that may not boot for months.
 *
 * WHAT HAPPENS WHEN MUSTER IS UNREACHABLE, which is the property this class
 * exists to hold. Nothing. The files stay exactly as they are and the stewards
 * behind it reconcile against the last configuration that arrived - so a device
 * in a hotel, or one whose control plane is down, keeps enforcing its policy
 * and keeps its managed apps configured. There is no separate cache to go stale
 * or to disagree with what is being enforced: THE FILES ARE THE CACHE, because
 * they are the same files the stewards already read. CONTEXT.md's second rule
 * is that enrollment may need the internet and operation must not, and a device
 * that loses its policy because a server went away has broken it.
 *
 * `place_file` STILL WORKS AND IS STILL WANTED. A device that has not enrolled
 * has no identity to fetch with, and a cable is how the first one is set up.
 *
 * IT DOES NOT SURVIVE A SUCCESSFUL FETCH, AND THAT IS THE ORDER OF OPERATIONS
 * TO KNOW. `muster restrictions`, `muster visible-apps` and `muster app-config`
 * write exactly the three names in `ConfigurationPolicy.MANAGED`, so once this
 * device is enrolled, the control plane is what decides their contents - a name
 * muster does not serve is removed at the next boot. That is the whole point of
 * a reconciler, and it means a file placed by hand on an enrolled device is a
 * temporary measure unless the same content is in the policy directory. muster
 * refusing to answer at all (an empty or absent policy source) leaves them
 * alone; see server/muster/policy.py's NoSource for why that is not a 200.
 */
class ConfigurationSteward(private val context: Context) {

    /**
     * What happened, for the caller to log.
     *
     * NEVER carries content. `app-config` holds write tokens, `BootReceiver`
     * logs the outcome of every step, and a data class prints every field.
     */
    data class Outcome(
        val revision: String? = null,
        val wrote: List<String> = emptyList(),
        val removed: List<String> = emptyList(),
        val unchanged: List<String> = emptyList(),
        val refused: List<ConfigurationPolicy.Refusal> = emptyList(),
        val didNotLand: List<String> = emptyList(),
        val kept: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            kept?.let { add("no fresh policy - $it") }
            refused.forEach { add("REFUSED '${it.name}' - ${it.why}") }
            if (didNotLand.isNotEmpty()) add("DID_NOT_LAND $didNotLand")
        }
        override fun toString(): String = when {
            kept != null -> "kept the last known configuration: $kept"
            else -> buildString {
                append("revision=$revision wrote=$wrote removed=$removed unchanged=$unchanged")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.name }}")
                if (didNotLand.isNotEmpty()) append(" DID_NOT_LAND=$didNotLand")
            }
        }
    }

    /** Where every steward reads from, and therefore where this writes. */
    fun filesDir(): File = context.createDeviceProtectedStorageContext().filesDir

    fun reconcile(): Outcome {
        val baseUrl = KeystoreIdentity.serverBaseUrl(context)
        if (baseUrl.isBlank()) {
            return Outcome(kept = "no muster server configured on this device")
        }

        val client = ConfigurationClient(
            // SHORTER TIMEOUTS THAN ENROLLMENT'S, because the budget here is
            // not this request's - it is the whole boot plan's. A broadcast
            // receiver that has not finished is a boot being held up, and two
            // requests at enrollment's 10s/20s could spend a minute before the
            // restrictions step has started. Enrollment can afford to wait: a
            // person is standing there.
            transport = HttpTransport(baseUrl, connectTimeoutMs = 5_000, readTimeoutMs = 8_000),
            identity = KeystoreIdentity(context),
        )

        val fetched = client.fetch()
        // The decision itself lives in ConfigurationPolicy, where a test can
        // break it. This line only obeys it.
        val configuration = ConfigurationPolicy.instruction(fetched)
            ?: return Outcome(kept = why(fetched))
        return apply(configuration)
    }

    /**
     * Why this device is keeping what it already has, in the operator's terms.
     *
     * Named separately per outcome because the next move differs completely: an
     * unenrolled device needs a pairing code, an unrecognized one needs to
     * enroll again, an unreachable one needs nothing at all, and a device that
     * cannot sign needs a handset in somebody's hand. "It did not work" sends
     * every one of those to the control plane.
     */
    private fun why(fetched: ConfigurationClient.Fetched): String = when (fetched) {
        is ConfigurationClient.Fetched.Configuration ->
            // Unreachable: `instruction` returns this one non-null. Spelled out
            // rather than defaulted so the `when` stays exhaustive, which is
            // what makes a new outcome a compile error in both places.
            "nothing to keep"
        is ConfigurationClient.Fetched.NotEnrolled ->
            "this device has no identity yet; nothing to fetch with"
        is ConfigurationClient.Fetched.Unrecognized ->
            "muster does not recognize this device's certificate"
        is ConfigurationClient.Fetched.Unreachable ->
            "muster is unreachable (${fetched.detail})"
        is ConfigurationClient.Fetched.Refused ->
            "muster refused: ${fetched.status} ${fetched.detail}"
        is ConfigurationClient.Fetched.DeviceCannotAsk ->
            "this device could not ask: ${fetched.detail}"
    }

    private fun apply(fetched: ConfigurationClient.Fetched.Configuration): Outcome {
        val dir = filesDir()
        // TWO QUESTIONS, TWO ANSWERS, and answering both from one of them gets
        // one of them wrong - the same shape as RestrictionPolicy's inForce and
        // setByUs. `present` decides whether there is a file to REMOVE; the
        // content decides whether there is a file to REWRITE.
        //
        // A file that is there and cannot be read reports as present with no
        // content, so it is unequal to anything served and gets replaced. That
        // is the recoverable direction: a corrupt local file must not be the
        // thing that blocks the fetch which would fix it, and it must not throw
        // and take the whole step down either.
        val present = ConfigurationPolicy.MANAGED.filter { File(dir, it).isFile }.toSet()
        val onDevice = ConfigurationPolicy.MANAGED.associateWith { name -> read(File(dir, name)) }
        val plan = ConfigurationPolicy.plan(fetched.files, onDevice, present)
        for (refusal in plan.refused) {
            Log.w(TAG, "configuration refused: ${refusal.name} - ${refusal.why}")
        }

        val didNotLand = mutableListOf<String>()
        for ((name, content) in plan.write) {
            if (!write(File(dir, name), content)) didNotLand.add(name)
        }
        for (name in plan.remove) {
            val file = File(dir, name)
            if (!file.delete() && file.isFile) didNotLand.add(name)
        }

        // NAMES AND THE REVISION ONLY. This line is in logcat at every boot.
        Log.i(
            TAG,
            "configuration revision=${fetched.revision} wrote=${plan.write.keys.toList()} " +
                "removed=${plan.remove} unchanged=${plan.unchanged}",
        )
        return Outcome(
            revision = fetched.revision,
            wrote = plan.write.keys.toList(),
            removed = plan.remove,
            unchanged = plan.unchanged,
            refused = plan.refused,
            didNotLand = didNotLand,
        )
    }

    /** What a file on the device says, or null if it is absent or unreadable. */
    private fun read(file: File): String? = try {
        file.takeIf { it.isFile }?.readText()
    } catch (e: Exception) {
        Log.w(TAG, "could not read ${file.name}; treating it as needing replacement", e)
        null
    }

    /**
     * Write one file so that no reader ever sees half of it.
     *
     * A STEWARD MAY BE READING THIS DIRECTORY, and the one that reads
     * `visible-apps` treats a file it cannot parse in full as an allowlist
     * naming nothing - which strips a launcher. Writing in place would make a
     * truncated file a real state the device can boot into. Rename on the same
     * filesystem is atomic, so a reader gets the old file or the new one.
     */
    private fun write(target: File, content: String): Boolean = try {
        val staged = File(target.parentFile, "${target.name}.incoming")
        staged.writeText(content)
        val moved = staged.renameTo(target)
        if (!moved) {
            staged.delete()
            Log.e(TAG, "could not replace ${target.name}; it still holds the previous configuration")
        }
        moved
    } catch (e: Exception) {
        // Reported rather than thrown. One file that would not land must not
        // stop the others, and it must not stop the stewards behind this from
        // reconciling what did.
        Log.e(TAG, "could not write ${target.name}", e)
        false
    }

    // The identity this device signs with, and where its control plane lives,
    // both live in `KeystoreIdentity` now: an asset fetch needs the same two
    // things, and a second copy of the Base64 rule in that class is a second
    // chance to get it wrong (muster#45).

    companion object {
        private const val TAG = "muster"
    }
}
