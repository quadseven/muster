package app.muster.agent

/**
 * The per-device wifi network (muster#195): which network a relay phone must
 * be able to join, so one that forgot it rejoins at its next check-in with no
 * person and no enrollment QR.
 *
 * THE FILE IS THE SERVER'S FORMAT, read the same way. `server/muster/policy.py`
 * `WifiNetwork.parse` is the other half, and a file it refuses is never served,
 * so a refusal here means the two parsers drifted:
 *
 *     ssid relay-net
 *     security WPA
 *     passphrase <the network passphrase>
 *
 * `security` is WPA (the default, as in the QR), WEP or NONE. `passphrase` is
 * required unless security is NONE.
 *
 * THE PASSPHRASE NEVER PRINTS. [Network.toString], [describe], every
 * [Outcome] string and every line handed to the log name the SSID and the
 * security type and nothing else. The applied digest is kept out of them too: a
 * bare sha256 of a short passphrase is an offline guessing oracle.
 *
 * AN ABSENT FILE LEAVES THE DEVICE ALONE. No file means muster has no opinion,
 * and networks a person added by hand stay exactly as they are. This policy
 * never removes a network.
 *
 * NOTHING HERE TOUCHES ANDROID, so the JVM harness runs every decision below.
 * The platform calls are WifiSteward's, behind [Target].
 */
object WifiPolicy {

    /** The name muster serves the file by and ConfigurationSteward writes it as. */
    const val FILE_NAME = "wifi"

    /** The digest of the last network the platform accepted. Not a managed name. */
    const val APPLIED_FILE = "wifi-applied"

    /** The same words as the provisioning QR and `policy.WIFI_SECURITY_TYPES`. */
    val SECURITY_TYPES: List<String> = listOf("WPA", "WEP", "NONE")

    private val KEYS = setOf("ssid", "security", "passphrase")

    /** One network. The passphrase is a field and never part of any string. */
    data class Network(val ssid: String, val security: String, val passphrase: String) {
        override fun toString(): String = "Network(ssid='$ssid', security=$security)"
    }

    /** What the served file says. */
    sealed interface Read
    data object Absent : Read
    data class Parsed(val network: Network) : Read

    /** What reconciling would do. */
    sealed interface Plan
    data object LeaveAlone : Plan

    /** The file could not be read as a network. [why] never quotes a value. */
    data class Refused(val why: String) : Read, Plan
    data class Unchanged(val network: Network) : Plan
    data class Apply(val network: Network, val digest: String, val kind: Kind) : Plan {
        override fun toString(): String = "Apply(network=$network, kind=$kind)"
    }

    enum class Kind {
        /** Not on the device: never applied, or forgotten since. */
        ADD,

        /** On the device, and the file changed since it was applied. */
        UPDATE,

        /** The device could not say whether it holds the network, so it is told again. */
        REASSERT,
    }

    /**
     * Read the served text. Null is an absent file.
     *
     * A REFUSAL NAMES THE KEY, NEVER THE LINE. A line with an unknown key may
     * be a passphrase typed under the wrong key, so quoting it would print it.
     */
    fun parse(text: String?): Read {
        if (text == null) return Absent
        val values = HashMap<String, String>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val key = line.substringBefore(' ')
            val value = if (' ' in line) line.substringAfter(' ').trim() else ""
            if (key !in KEYS) return Refused("a line names a key wifi does not have")
            if (key in values) return Refused("$key is named twice")
            values[key] = value
        }
        val ssid = values["ssid"].orEmpty()
        if (ssid.isEmpty() || ssid.toByteArray(Charsets.UTF_8).size > 32) {
            return Refused("ssid must be 1 to 32 bytes")
        }
        val security = values["security"].orEmpty().ifEmpty { "WPA" }
        if (security !in SECURITY_TYPES) return Refused("security must be one of $SECURITY_TYPES")
        val passphrase = values["passphrase"].orEmpty()
        if (security != "NONE" && passphrase.isEmpty()) {
            return Refused("security $security needs a passphrase")
        }
        return Parsed(Network(ssid, security, passphrase))
    }

    /**
     * The fingerprint recorded once the platform accepts a network, so an
     * identical file on the next fetch is recognized without a platform write.
     */
    fun digest(network: Network): String {
        val bytes = listOf(network.ssid, network.security, network.passphrase)
            .joinToString("\u0000")
            .toByteArray(Charsets.UTF_8)
        return java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
    }

    /**
     * Decide.
     *
     * THE DEVICE OUTRANKS THE RECORD. An identical file is [Unchanged] only
     * while the device still holds the network; one it forgot is added back,
     * which is the whole reason this exists. When the device cannot say
     * ([onDevice] null), the network is handed over again: the platform merges a
     * configuration with the same SSID and security rather than duplicating it.
     *
     * @param lastApplied the digest recorded the last time the platform accepted
     * @param onDevice whether the device holds this SSID, or null if it cannot say
     */
    fun plan(read: Read, lastApplied: String?, onDevice: (String) -> Boolean?): Plan = when (read) {
        Absent -> LeaveAlone
        is Refused -> read
        is Parsed -> {
            val network = read.network
            val digest = digest(network)
            when (onDevice(network.ssid)) {
                false -> Apply(network, digest, Kind.ADD)
                true -> if (digest == lastApplied) Unchanged(network) else Apply(network, digest, Kind.UPDATE)
                null -> Apply(network, digest, Kind.REASSERT)
            }
        }
    }

    /** One line for the log and the report. Never the passphrase, never the digest. */
    fun describe(plan: Plan): String = when (plan) {
        LeaveAlone -> "no wifi file; networks left as they are"
        is Refused -> "wifi file refused: ${plan.why}"
        is Unchanged -> "wifi '${plan.network.ssid}' (${plan.network.security}) unchanged"
        is Apply -> when (plan.kind) {
            Kind.ADD -> "wifi '${plan.network.ssid}' (${plan.network.security}) added"
            Kind.UPDATE -> "wifi '${plan.network.ssid}' (${plan.network.security}) updated"
            Kind.REASSERT -> "wifi '${plan.network.ssid}' (${plan.network.security}) handed over again; the device cannot list its networks"
        }
    }

    /** The platform half. WifiSteward implements it over WifiManager. */
    interface Target {
        /** Checked first: only a Device Owner may configure wifi for the device. */
        val isDeviceOwner: Boolean

        /** Whether the device holds this SSID, or null if it cannot say. */
        fun onDevice(ssid: String): Boolean?

        /** Add or update and enable the network. False is a platform refusal. */
        fun save(network: Network): Boolean
    }

    /** Where the applied digest lives. */
    interface Ledger {
        fun lastApplied(): String?
        fun record(digest: String)
    }

    /**
     * What happened, for the check-in report.
     *
     * @param saved whether the platform accepted an [Apply]; null when nothing was asked of it
     * @param inert why nothing was attempted, when a file was served and could not be acted on
     */
    data class Outcome(
        val plan: Plan,
        val saved: Boolean? = null,
        val inert: String? = null,
    ) : StepOutcome {
        override fun concerns(): List<String> = buildList {
            inert?.let { add("nothing done - $it") }
            if (plan is Refused) add(describe(plan))
            if (plan is Apply && saved == false) {
                add("DID_NOT_TAKE wifi '${plan.network.ssid}' - the platform refused the network")
            }
        }

        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            plan is Apply && saved == false -> "${describe(plan)} DID_NOT_TAKE"
            else -> describe(plan)
        }
    }

    /**
     * The whole step, over seams: read, decide, act, record, log.
     *
     * @param served the served file's text, or null when it is absent
     * @param log one line per outcome; never handed the passphrase or the digest
     */
    fun reconcile(served: String?, ledger: Ledger, target: Target, log: (String) -> Unit): Outcome {
        val read = parse(served)
        if (read is Parsed && !target.isDeviceOwner) {
            val outcome = Outcome(LeaveAlone, inert = "not device owner; the wifi network cannot be configured")
            log("wifi: $outcome")
            return outcome
        }
        val plan = plan(read, ledger.lastApplied(), target::onDevice)
        val outcome = if (plan is Apply) {
            val saved = target.save(plan.network)
            if (saved) ledger.record(plan.digest)
            Outcome(plan, saved = saved)
        } else {
            Outcome(plan)
        }
        log("wifi: $outcome")
        return outcome
    }

    /** An SSID or passphrase as WifiConfiguration takes it: in double quotes. */
    fun quoted(value: String): String = "\"$value\""

    /** A WEP key: 10, 26 or 58 hex digits go over as hex, anything else as text. */
    fun wepKey(key: String): String =
        if (key.length in setOf(10, 26, 58) && key.all { it in "0123456789abcdefABCDEF" }) key else quoted(key)
}
