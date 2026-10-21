package app.muster.agent

/**
 * Telephony policy for an appliance: which calls it originates and which it
 * takes.
 *
 * WHY THIS EXISTS. These handsets are not phones. They carry a SIM so zippie
 * has a cellular leg; nobody is meant to place a call or send a message from
 * one, and both are attack surface and bill on a line bought for data.
 *
 * WHAT THE PLATFORM CAN AND CANNOT DO. AOSP has
 * `UserManager.DISALLOW_OUTGOING_CALLS` (`no_outgoing_calls`), which the
 * platform enforces and which emergency calls bypass. There is NO user
 * restriction for refusing an INCOMING call. `block-incoming` is enforced by
 * IncomingCallScreen instead, a CallScreeningService that rejects the call
 * before it rings, and only while Muster holds the call-screening role.
 * Voicemail is recorded by the carrier's network, not by anything on the
 * handset, so a rejected call can still reach it: that part stays an operator
 * step (MMI divert, or a data-only plan). Both are recognized lines; only one
 * has a restriction key.
 *
 * RECONCILING GOES BOTH WAYS. A restriction removed from the file comes off
 * the device. Policy that only ever adds is a ratchet, and the reverse gear
 * on a ratchet held by a Device Owner is a factory reset.
 *
 * ONLY RESTRICTIONS IN [MANAGED] ARE EVER CLEARED. Anything else found on the
 * device is left exactly as it is.
 *
 * NOTHING HERE TOUCHES ANDROID. Every decision below is a pure function over
 * strings. The Android calls, and reading the platform back afterwards, are in
 * TelephonySteward.
 */
object TelephonyPolicy {

    /**
     * The file this is read from, under the name muster serves it by and
     * ConfigurationSteward writes it as. One spelling, so a device
     * configured over the air holds the same file as one configured by hand.
     */
    const val FILE_NAME = "telephony"

    /**
     * Config name to platform key, for everything muster will manage.
     *
     * The key on the right is the value of the `UserManager.DISALLOW_*`
     * constant, which is what `addUserRestriction` and the Bundle returned by
     * `getUserRestrictions` both speak. Written as a literal rather than
     * referenced through `UserManager` so this whole object stays a plain JVM
     * class the unit tests can exercise without a device.
     *
     * A WRONG LITERAL HERE WOULD BE SILENT: `addUserRestriction` does not
     * reject a key it does not recognize, it just stores something nothing
     * enforces. That is why TelephonySteward reads the restrictions back
     * after writing them instead of trusting that the call returned.
     *
     * Checked against AOSP `core/java/android/os/UserManager.java` on
     * 2026-09-19. Do not pattern-match a new one from the ones already here.
     */
    val MANAGED: Map<String, String> = linkedMapOf(
        // THESE HANDSETS ARE NOT PHONES. Nobody is meant to place a call from
        // one, and it is attack surface and bill on a line bought for data.
        // Emergency calls are always allowed by the platform - this restriction
        // stops non-emergency outgoing calls, nothing else.
        "BLOCK_OUTGOING" to "no_outgoing_calls",
    )

    /** Recognized, and enforced by IncomingCallScreen: no restriction key refuses an incoming call. */
    const val BLOCK_INCOMING = "block-incoming"

    /** A config line that will not be acted on, and the reason, for logging. */
    data class Refusal(val line: String, val why: String)

    /** What muster wants, once the config file has been read. */
    data class Desired(
        val keys: Set<String>,
        val blockIncoming: Boolean,
        val refused: List<Refusal>,
    )

    /**
     * What reconciling would do. Add and clear are platform keys.
     *
     * [changesNothing] is what makes a second boot cheap, and what makes
     * "nothing happened" distinguishable from "nothing was configured" in
     * the log. `blockIncoming` being requested does not make this false -
     * the call screener enforces it, not a restriction, so there is nothing
     * to add or clear for it, and it is reported separately.
     */
    data class Plan(
        val add: List<String>,
        val clear: List<String>,
        val refused: List<Refusal>,
        val blockIncoming: Boolean,
    ) {
        val changesNothing: Boolean get() = add.isEmpty() && clear.isEmpty()
    }

    /**
     * Read the config file's text into a desired telephony state.
     *
     * One instruction per line, `#` starts a comment, blank lines ignored.
     * Flat text rather than JSON, matching `restrictions` and `server-url`
     * beside it: this file is written by a person over adb, and a missing
     * brace should not be the difference between a policy and no policy.
     *
     * AN UNRECOGNIZED NAME IS REFUSED, LOUDLY, NOT SKIPPED. A typo in an
     * instruction name is otherwise indistinguishable from not having asked
     * for it, and the device would come up with a config file that appears
     * to say otherwise.
     */
    fun read(text: String?): Desired {
        if (text.isNullOrBlank()) return Desired(emptySet(), false, emptyList())

        val keys = LinkedHashSet<String>()
        val refused = mutableListOf<Refusal>()
        var blockIncoming = false

        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue

            val words = line.split(Regex("\\s+"))
            val name = words[0].uppercase().replace('-', '_')

            val managed = MANAGED[name]
            if (managed != null) {
                keys.add(managed)
                continue
            }

            if (name == "BLOCK_INCOMING") {
                blockIncoming = true
                continue
            }

            refused.add(
                Refusal(line, "not a telephony instruction muster manages; known names are block-outgoing, block-incoming")
            )
        }
        return Desired(keys, blockIncoming, refused)
    }

    /**
     * Whether IncomingCallScreen should reject a call it is shown.
     *
     * Only incoming calls. Telecom shows the screener outgoing calls too, and
     * refusing those is `no_outgoing_calls`' job, which lets emergency calls
     * through - the screener must never stand in the way of one.
     */
    fun rejects(desired: Desired, incoming: Boolean): Boolean = incoming && desired.blockIncoming

    /**
     * Work out the difference between what is wanted and what the device has.
     *
     * TWO SOURCES, BECAUSE THERE ARE TWO QUESTIONS, and answering both from
     * one of them gets one of them wrong.
     *
     * What to ADD is decided from what is actually IN FORCE. Deciding it from
     * muster's own record instead would mean setting a restriction once and
     * never looking again: anything the platform quietly declined, or anything
     * cleared out from under us, would read as "already applied" on every
     * subsequent boot. Comparing against reality makes every boot re-assert
     * policy rather than remember having asserted it.
     *
     * What to CLEAR is decided from what MUSTER SET. A restriction that is in
     * force but that muster never set is not muster's to withdraw, and the
     * difference between those two only exists in this second set.
     *
     * @param inForce restrictions actually in effect on the device
     * @param setByUs restrictions this admin has recorded as its own
     */
    fun plan(desired: Desired, inForce: Set<String>, setByUs: Set<String>): Plan {
        val add = desired.keys.filterNot { it in inForce }
        // Only ever withdraw from the managed vocabulary, and only what muster
        // itself put there.
        val clear = MANAGED.values.filter { it in setByUs && it !in desired.keys }
        return Plan(add = add, clear = clear, refused = desired.refused, blockIncoming = desired.blockIncoming)
    }
}
