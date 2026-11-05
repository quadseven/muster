package app.muster.agent

import org.json.JSONObject

/**
 * The proven exchange: challenge, sign, post, and what the answer means.
 *
 * ONE MODULE FOR EVERY DEVICE ROUTE (muster#219), because the server
 * authenticates every device route in one place (`_proven_device`) and the
 * client side of that should be one place too. Configuration, renewal,
 * assets, uploads and the wipe and reboot acknowledgements all go through
 * [exchange]; each caller supplies a path and its extra fields and reads one
 * sealed [Outcome]. Before this, five copies of the handshake had drifted.
 *
 * TWO REQUESTS, AND THE ORDER MATTERS. muster issues the nonce, this device
 * signs it with the key in its keystore, and the signature travels WITH the
 * request. A client-chosen challenge is not a challenge. See
 * server/muster/proof.py.
 *
 * 401 AND 403 MEAN SOMETHING ONLY ON THE PROVEN LEG. Before any proof was
 * sent, a refused challenge says nothing about this certificate, so it is
 * [Outcome.Refused] whatever its status. After the proof, 401 is a stranger
 * and 403 is a verified device an administrator revoked. Every other status is
 * [Outcome.Answered], and the caller decides which one is success.
 *
 * EXCEPTIONS ARE REPORTED BY CLASS NAME ONLY. A message can carry the URL or
 * the body, and these requests carry certificate material.
 */
class ProvenExchange(
    private val transport: EnrollmentClient.Transport,
    private val identity: ConfigurationClient.Identity,
) {
    sealed interface Outcome<out B> {
        /** muster, or something in front of it, answered the proven request. */
        data class Answered<out B>(val status: Int, val body: B) : Outcome<B>

        /** No certificate on this device. Nothing was sent. */
        object NotEnrolled : Outcome<Nothing>

        /** 401 on the proven leg: muster does not know this identity. */
        object Unrecognized : Outcome<Nothing>

        /** 403 on the proven leg: verified, and revoked by an administrator. */
        data class Revoked(val detail: String) : Outcome<Nothing>

        /** Network, DNS, TLS, on either leg. */
        data class Unreachable(val detail: String) : Outcome<Nothing>

        /** The challenge was refused or could not be read. Nothing was signed. */
        data class Refused(val status: Int, val detail: String) : Outcome<Nothing>

        /** This device could not read its identity or sign the nonce. */
        data class CannotSign(val detail: String) : Outcome<Nothing>
    }

    /**
     * What a sender read off the wire.
     *
     * @param detail text for a log line when the status is not success; for
     *   a text route that is the body, for a byte route the error body.
     */
    class Raw<out B>(val status: Int, val body: B, val detail: String)

    /** The common case: a JSON body answered with text. */
    fun post(path: String, fields: JSONObject): Outcome<String> =
        exchange(path, fields) { p, body ->
            val reply = transport.post(p, body)
            Raw(reply.status, reply.body, reply.body)
        }

    /**
     * Sign a fresh nonce, add the proof to [fields], and send it with [send].
     *
     * [send] is the proven leg only; the challenge always goes over the
     * transport this was built with.
     */
    fun <B> exchange(
        path: String,
        fields: JSONObject,
        send: (String, String) -> Raw<B>,
    ): Outcome<B> {
        val certificate = try {
            identity.certificatePem() ?: return Outcome.NotEnrolled
        } catch (_: Exception) {
            return Outcome.CannotSign(IDENTITY_UNAVAILABLE)
        }
        val nonce = when (val challenged = challenge()) {
            is Challenged.Nonce -> challenged.value
            is Challenged.Failed -> return challenged.why
        }
        val signature = try {
            identity.signBase64(nonce)
        } catch (e: Exception) {
            return Outcome.CannotSign("$SIGNING_FAILED: ${detail(e)}")
        }
        fields.put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
        val reply = try {
            send(path, fields.toString())
        } catch (e: Exception) {
            return Outcome.Unreachable(detail(e))
        }
        return when (reply.status) {
            401 -> Outcome.Unrecognized
            403 -> Outcome.Revoked(reply.detail.take(REFUSAL_DETAIL_CHARS))
            else -> Outcome.Answered(reply.status, reply.body)
        }
    }

    private sealed interface Challenged {
        data class Nonce(val value: String) : Challenged
        data class Failed(val why: Outcome<Nothing>) : Challenged
    }

    private fun challenge(): Challenged {
        val reply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Challenged.Failed(Outcome.Unreachable(detail(e)))
        }
        if (reply.status != CHALLENGE_ISSUED) {
            return Challenged.Failed(
                Outcome.Refused(reply.status, reply.body.take(REFUSAL_DETAIL_CHARS))
            )
        }
        return try {
            Challenged.Nonce(JSONObject(reply.body).getString("nonce"))
        } catch (e: Exception) {
            Challenged.Failed(Outcome.Refused(reply.status, "$UNREADABLE_CHALLENGE: ${detail(e)}"))
        }
    }

    private fun detail(e: Exception): String = e.javaClass.simpleName

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
        const val CHALLENGE_ISSUED = 201

        /**
         * How much of a refusal body is worth keeping for the log. Bounded,
         * because an origin behind a captive portal answers with a page.
         */
        const val REFUSAL_DETAIL_CHARS = 200

        const val IDENTITY_UNAVAILABLE = "identity unavailable"
        const val SIGNING_FAILED = "could not sign muster's nonce"
        const val UNREADABLE_CHALLENGE = "unreadable challenge"
    }
}

/**
 * One upload to muster carrying this device's proof, accepted on one status.
 *
 * Diagnostics and the check-in report go up through this. It is the proven
 * exchange read the way an upload reads it: accepted or not, with the coarser
 * failure states those callers have always logged.
 */
class ProvenPost(
    transport: EnrollmentClient.Transport,
    identity: ConfigurationClient.Identity,
) {
    private val exchange = ProvenExchange(transport, identity)

    sealed interface Sent {
        object Accepted : Sent
        data class Refused(val status: Int) : Sent
        data class Unreachable(val cause: String) : Sent
        object NotEnrolled : Sent
    }

    /**
     * Sign a fresh nonce and POST [fields] with the proof added.
     *
     * @param accepted the status muster answers when it took the upload.
     */
    fun send(path: String, fields: JSONObject, accepted: Int = 202): Sent =
        when (val outcome = exchange.post(path, fields)) {
            is ProvenExchange.Outcome.Answered ->
                if (outcome.status == accepted) Sent.Accepted else Sent.Refused(outcome.status)
            ProvenExchange.Outcome.NotEnrolled -> Sent.NotEnrolled
            ProvenExchange.Outcome.Unrecognized -> Sent.Refused(401)
            is ProvenExchange.Outcome.Revoked -> Sent.Refused(403)
            is ProvenExchange.Outcome.Unreachable -> Sent.Unreachable(outcome.detail)
            is ProvenExchange.Outcome.Refused ->
                // A challenge that arrived and would not parse has always read
                // as unreachable here, not as muster refusing the upload.
                if (outcome.status == ProvenExchange.CHALLENGE_ISSUED) {
                    Sent.Unreachable(ProvenExchange.UNREADABLE_CHALLENGE)
                } else {
                    Sent.Refused(outcome.status)
                }
            is ProvenExchange.Outcome.CannotSign ->
                if (outcome.detail == ProvenExchange.IDENTITY_UNAVAILABLE) {
                    Sent.Unreachable(ProvenExchange.IDENTITY_UNAVAILABLE)
                } else {
                    Sent.Unreachable("keystore signing failed")
                }
        }

    companion object {
        const val CHALLENGE_PATH = ProvenExchange.CHALLENGE_PATH
    }
}
