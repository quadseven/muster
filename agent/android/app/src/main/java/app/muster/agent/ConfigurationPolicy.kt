package app.muster.agent

/**
 * What to do with a configuration muster served, given what is already on disk.
 *
 * WHY THIS EXISTS AT ALL (muster#46). Every configuration this agent acts on
 * used to arrive over a cable: `place_file` writes into this app's own files
 * directory through `adb shell run-as`. A device that provisioned by QR and
 * enrolled over the air therefore came up owned and configured by nothing, and
 * `run-as` needs a DEBUGGABLE package, so that route stops working the day the
 * release-signed agent ships. This is the device fetching the same files over
 * the identity it already holds.
 *
 * IT WRITES THE SAME FILES THE STEWARDS ALREADY READ, and that is the whole
 * design rather than an implementation detail. `restrictions`, `visible-apps`
 * and `app-config` land in device-protected storage exactly where
 * `RestrictionSteward`, `AppVisibilitySteward` and `AppConfigSteward` look for
 * them, so everything those already do - reconciling both ways, refusing a name
 * they do not know, reading the platform back afterwards, withholding a hide on
 * a file they cannot read in full - keeps working unchanged. A second apply
 * path would be a second vocabulary and a second set of refusals, and the one
 * that got it wrong would be the one nobody ran against a handset.
 *
 * ONLY A FETCH THAT SUCCEEDED IS AN INSTRUCTION, and [instruction] is where
 * that is decided, so it is a pure function a test can break. Nothing in [plan]
 * can tell "the server says this device has no restrictions file" from "the
 * server did not answer", and those two demand opposite behavior. Keeping the
 * last known configuration when muster is unreachable is CONTEXT.md's second
 * rule - enrollment may need the internet; operation must not.
 *
 * A NAME MUSTER DOES NOT MANAGE IS REFUSED, NOT WRITTEN. Anything else makes
 * this a remote write primitive over the agent's private storage, and the first
 * file it would be pointed at is `server-url` - the one that decides which
 * control plane this device answers to. The set is closed on both sides; this
 * half is the one that matters, because it is the half a compromised or
 * mistaken control plane cannot talk past.
 *
 * NO CONTENT EVER APPEARS IN A `toString`, for the same reason as
 * `AppConfigPolicy`: `app-config` carries write tokens, `BootReceiver` logs the
 * outcome of every step, and a generated `toString` prints every field.
 */
object ConfigurationPolicy {

    /**
     * The files that may travel from muster to this device.
     *
     * Deliberately NOT `wallpaper.png`: it is not text, and serving it means
     * asset hosting (muster#45). Deliberately NOT `server-url`: a control plane
     * that can rewrite the address of the control plane is one that can hand a
     * device to somebody else, and that value arrives once, from the
     * provisioning extras, in front of a person.
     */
    // THE SAME VOCABULARY AS `policy.MANAGED_FILES` ON THE SERVER, and the two
    // are checked against each other in CI (tools/check_managed_files.py). A
    // name the server serves and this set does not hold is REFUSED here and
    // never written, so the drift is silent on both sides: the operator sees a
    // file they wrote being served, and the device acts as though it was never
    // configured. That is not hypothetical - `wallpaper` was added to the
    // server first and did exactly this until the guard was written.
    val MANAGED: Set<String> = linkedSetOf(
        "restrictions",
        "visible-apps",
        "app-config",
        // NAMES an asset and the digest to expect; it is not the image. The
        // bytes travel over /v1/device/asset and are checked against it.
        "wallpaper",
        // NAMES applications, the assets that carry them and the digests to
        // expect. Like `wallpaper`, it is a reference and not the payload -
        // an APK is twelve megabytes and does not travel in a JSON body.
        "install-apps",
        // The instruction to erase this device. It arrives in the same files
        // map, is written to device-protected storage like every other managed
        // file, and is read by WipeSteward. It is device scope only on the
        // server; this half cannot make it less destructive, but it can ensure
        // the name is closed rather than a remote write primitive.
        "wipe",
    )

    /** How much of a name muster does not manage is worth putting in logcat. */
    const val NAME_IN_A_LOG = 64

    /** A served name that will not be acted on, and why, for the log. */
    data class Refusal(val name: String, val why: String)

    /**
     * The configuration to act on, or null if this answer is not one.
     *
     * THE SINGLE MOST DESTRUCTIVE LINE IN THIS FEATURE, expressed as a pure
     * function so a test can break it. [plan] removes every managed file that a
     * configuration does not mention, so handing it anything other than a real
     * answer from muster wipes the device - and "muster is unreachable" is the
     * ordinary state of a phone on hotel wifi, not an edge case.
     *
     * An EXHAUSTIVE `when` over the sealed interface rather than `as?`: adding
     * an outcome to `ConfigurationClient.Fetched` then fails to compile here,
     * which is the moment somebody has to decide whether it means "act" or
     * "keep what you have". A safe default is what makes that decision silently.
     */
    fun instruction(
        fetched: ConfigurationClient.Fetched,
    ): ConfigurationClient.Fetched.Configuration? = when (fetched) {
        is ConfigurationClient.Fetched.Configuration -> fetched
        is ConfigurationClient.Fetched.NotEnrolled -> null
        is ConfigurationClient.Fetched.Unrecognized -> null
        is ConfigurationClient.Fetched.Revoked -> null
        is ConfigurationClient.Fetched.Unreachable -> null
        is ConfigurationClient.Fetched.Refused -> null
        is ConfigurationClient.Fetched.DeviceCannotAsk -> null
    }

    /**
     * What applying a fetched configuration would do.
     *
     * [remove] is the half that makes this a reconciler rather than a ratchet.
     * A file the server did not mention is one this device is no longer
     * configured with, and leaving it in place would mean policy could be added
     * remotely and only ever withdrawn with a cable. The agent's own semantics
     * make that safe in the direction it matters: no `restrictions` file means
     * "leave the device as it is", not "strip it".
     */
    data class Plan(
        val write: Map<String, String>,
        val remove: List<String>,
        val unchanged: List<String>,
        val refused: List<Refusal>,
    ) {
        val changesNothing: Boolean get() = write.isEmpty() && remove.isEmpty()

        // Names only. `write` holds an app-config file with a write token in it.
        override fun toString(): String =
            "write=${write.keys.toList()} remove=$remove unchanged=$unchanged " +
                "refused=${refused.map { it.name }}"
    }

    /**
     * TWO SOURCES FOR THE DEVICE'S STATE, BECAUSE THERE ARE TWO QUESTIONS - the
     * same shape as `RestrictionPolicy.plan`, and for the same kind of reason.
     * Whether to REWRITE a file is decided from its content; whether to REMOVE
     * one is decided from whether it is there. A single map cannot answer both,
     * because a file that exists and could not be read has no content and must
     * still be removable - and must still be replaceable, which it is, since no
     * content equals nothing muster serves.
     *
     * @param served   what muster answered with, name to content
     * @param onDevice what is on disk now, name to content; null means absent
     *                 OR unreadable, which are the same instruction here
     * @param present  which managed files exist on the device at all
     */
    fun plan(
        served: Map<String, String>,
        onDevice: Map<String, String?>,
        present: Set<String> = onDevice.filterValues { it != null }.keys,
    ): Plan {
        val write = LinkedHashMap<String, String>()
        val unchanged = mutableListOf<String>()
        val refused = mutableListOf<Refusal>()

        for ((name, content) in served) {
            if (name !in MANAGED) {
                refused.add(
                    Refusal(
                        // BOUNDED, because this name came off the network and
                        // goes into logcat at every boot. The refusal bodies in
                        // ConfigurationClient are bounded for the same reason;
                        // a JSON key is no more this device's to trust.
                        name.take(NAME_IN_A_LOG),
                        "not a file muster manages on this device; known names are $MANAGED",
                    )
                )
                continue
            }
            // Compared by CONTENT, not by a revision or a timestamp. The
            // revision says the estate's policy changed; it says nothing about
            // whether THIS file did, and rewriting a file that has not changed
            // means the stewards re-reconcile from scratch at every boot.
            if (onDevice[name] == content) unchanged.add(name) else write[name] = content
        }

        // Present on disk, absent from an answer muster gave. Only ever names
        // from MANAGED: a file this agent does not manage was not put there by
        // muster, and deleting somebody else's file is not this object's to do.
        val remove = MANAGED.filter { it !in served && it in present }

        return Plan(write = write, remove = remove, unchanged = unchanged, refused = refused)
    }
}
