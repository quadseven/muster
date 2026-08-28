package app.muster.agent

import org.json.JSONObject

/**
 * Fetching this device's configuration from muster, over the identity it holds.
 *
 * TWO REQUESTS, NOT ONE, and the order matters. muster issues the nonce, this
 * device signs it with the key in its keystore, and the signature travels WITH
 * the fetch. A client-chosen challenge is not a challenge, and a bearer token
 * would be a credential that can be copied off a device - which is exactly what
 * the keystore key cannot be. See server/muster/proof.py: the proof is at the
 * application layer because Cloudflare cannot pass a client certificate through
 * a Tunnel, so this survives every proxy in the path.
 *
 * THE STATES ARE MODELED BECAUSE THEY DEMAND OPPOSITE BEHAVIOR, exactly as in
 * `EnrollmentClient`. The one that decides whether this feature is safe is
 * [Fetched.Unreachable] against [Fetched.Configuration]: a configuration is an
 * instruction to reconcile, and everything else is an instruction to keep
 * enforcing what this device already has. Collapsing them into "it failed, use
 * empty" would strip a device's policy every time its network went away, which
 * is CONTEXT.md's second rule broken in the most expensive direction.
 *
 * THE VERDICT DETAIL IS DELIBERATELY NOT PARSED. muster answers a refused proof
 * with the verdict as text, and 409 covers both "that nonce was replayed" and
 * "your certificate has expired". Branching on a string would be a contract
 * neither test suite can see, and the two branches would do the same thing: a
 * device with an expired certificate needs renewal, which is a person or a
 * renewal path, not a different HTTP branch here.
 *
 * NOTHING RETRIES A FAILED FETCH, and that is worth knowing rather than
 * assuming. `IdentityLifecycle.backoffSeconds` is enrollment's, and no caller
 * here uses it: `ConfigurationSteward` runs from `BootPlan.STEPS`, which runs at
 * boot and when somebody presses sync on the status screen. So a device whose
 * network is not up yet at LOCKED_BOOT_COMPLETED keeps its existing
 * configuration - correct, and the whole point - but does not pick up a policy
 * change until it next boots. A periodic fetch needs a scheduler component and
 * a handset to prove its direct-boot behavior on; see docs/policy.md.
 */
class ConfigurationClient(
    private val transport: EnrollmentClient.Transport,
    private val identity: Identity,
) {

    /** What this device signs with, and what it signs as. */
    interface Identity {
        /**
         * The certificate muster issued, or null if this device has not
         * enrolled. Null is NOT a failure: an unenrolled device has nothing to
         * fetch with and nothing to fetch, and saying so is different from
         * saying the server refused it.
         */
        fun certificatePem(): String?

        /** Sign muster's nonce with the keystore key. Base64, as the API wants. */
        fun signBase64(nonce: String): String
    }

    sealed interface Fetched {
        /**
         * What this device is told to be. [files] is name to content; a managed
         * name ABSENT from it is a file this device is no longer configured
         * with, which is not the same as an empty one.
         */
        data class Configuration(val revision: String, val files: Map<String, String>) : Fetched {
            // `files` holds `app-config`, which holds write tokens.
            override fun toString(): String = "revision=$revision files=${files.keys.toList()}"
        }

        /** No certificate on this device yet. Nothing to do, and not an error. */
        object NotEnrolled : Fetched

        /** muster does not recognize this identity. Enrollment, not a retry. */
        object Unrecognized : Fetched

        /** Network, DNS, TLS. KEEP WHAT IS ON THE DEVICE. */
        data class Unreachable(val detail: String) : Fetched

        /** muster answered and it was not a configuration. KEEP WHAT IS ON THE DEVICE. */
        data class Refused(val status: Int, val detail: String) : Fetched

        /**
         * This device could not make the request. KEEP WHAT IS ON THE DEVICE.
         *
         * ITS OWN CASE RATHER THAN A `Refused` WITH A MADE-UP STATUS, because
         * the log is the entire diagnostic on a phone nobody is holding and the
         * two read completely differently. A keystore that will not sign is a
         * handset problem; "muster refused" sends somebody to the control plane.
         */
        data class DeviceCannotAsk(val detail: String) : Fetched
    }

    fun fetch(): Fetched {
        val certificate = identity.certificatePem() ?: return Fetched.NotEnrolled

        val nonce = when (val challenged = challenge()) {
            is Challenged.Nonce -> challenged.value
            is Challenged.Failed -> return challenged.why
        }

        val signature = try {
            identity.signBase64(nonce)
        } catch (e: Exception) {
            // The keystore refusing to sign is this device's problem, not the
            // server's, and it must not read as "muster is down" in the log -
            // the recovery is completely different and involves the handset.
            return Fetched.DeviceCannotAsk("could not sign muster's nonce: ${detail(e)}")
        }

        val body = JSONObject()
            .put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
            .toString()

        val reply = try {
            transport.post(CONFIG_PATH, body)
        } catch (e: Exception) {
            return Fetched.Unreachable(detail(e))
        }

        return when (reply.status) {
            200 -> read(reply.body)
            // The device is a stranger to this muster: a certificate it did not
            // issue, or a signature that does not match one it did. Retrying
            // cannot fix either.
            401 -> Fetched.Unrecognized
            else -> Fetched.Refused(reply.status, reply.body.take(REFUSAL_DETAIL_CHARS))
        }
    }

    private sealed interface Challenged {
        data class Nonce(val value: String) : Challenged
        data class Failed(val why: Fetched) : Challenged
    }

    private fun challenge(): Challenged {
        val reply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Challenged.Failed(Fetched.Unreachable(detail(e)))
        }
        if (reply.status != 201) {
            return Challenged.Failed(
                Fetched.Refused(reply.status, reply.body.take(REFUSAL_DETAIL_CHARS))
            )
        }
        return try {
            Challenged.Nonce(JSONObject(reply.body).getString("nonce"))
        } catch (e: Exception) {
            Challenged.Failed(Fetched.Refused(reply.status, "unreadable challenge: ${detail(e)}"))
        }
    }

    /**
     * Read the answer, or treat it as no answer at all.
     *
     * A BODY THIS CANNOT PARSE IS `Refused`, NEVER AN EMPTY CONFIGURATION. An
     * empty configuration is a real instruction - it withdraws every file this
     * device holds - so a truncated response or a captive portal's login page
     * must not be able to produce one. That is the single most expensive
     * mistake available in this file.
     */
    private fun read(body: String): Fetched = try {
        val json = JSONObject(body)
        val served = json.getJSONObject("files")
        val files = LinkedHashMap<String, String>()
        for (name in served.keys()) files[name] = served.getString(name)
        Fetched.Configuration(revision = json.getString("revision"), files = files)
    } catch (e: Exception) {
        Fetched.Refused(200, "muster's answer could not be read: ${detail(e)}")
    }

    /**
     * An exception as one word: its class name, and nothing else.
     *
     * NOT `e.message` AND NOT `e.toString()`. Both can carry the response body,
     * and this string goes into logcat at every boot - a configuration this
     * device could not parse is exactly the case where that body might be the
     * one that held a token. The class name says which of the six failures it
     * was, which is what the log is for.
     */
    private fun detail(e: Exception): String = e.javaClass.simpleName

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
        const val CONFIG_PATH = "/v1/device/config"

        /**
         * How much of a refusal body is worth keeping for the log.
         *
         * Bounded rather than whole: this ends up in logcat at every boot, and
         * an origin behind a captive portal answers with a page rather than
         * with muster's own JSON.
         */
        const val REFUSAL_DETAIL_CHARS = 200
    }
}
