package app.muster.agent

import org.json.JSONObject

/**
 * The device's half of the enrollment ceremony: present, then poll to collect.
 *
 * WHY THE STATUS CODES ARE MODELLED RATHER THAN LUMPED INTO "it failed". Each
 * one asks the device for a different behavior, and getting them wrong is
 * invisible until a real enrollment goes sideways in someone's hand:
 *
 *   403 the code was wrong          -> the operator mistyped; ask again, same code
 *   410 the code expired            -> ask the operator for a NEW code
 *   409 the code was already used   -> somebody else claimed it; stop, do not retry
 *   429 too many attempts           -> the window is burned; stop
 *   202 waiting on a human          -> keep polling, this is the normal path
 *   404 unknown or already collected-> stop; polling forever will not fix it
 *
 * A device that treats 410 as retryable hammers an endpoint with a code that
 * can never work again. One that treats 202 as failure gives up while the
 * operator is walking to their laptop.
 *
 * The transport is injected because the interesting cases here are refusals,
 * and staging a real 429 against a real server for a test means arranging the
 * failure this class exists to handle.
 */
class EnrollmentClient(private val transport: Transport) {

    /** The smallest HTTP surface this needs. Real one uses HttpURLConnection. */
    interface Transport {
        fun post(path: String, body: String): Reply
        fun get(path: String): Reply
        data class Reply(val status: Int, val body: String)
    }

    sealed interface Presented {
        data class Accepted(val requestId: String, val fingerprint: String) : Presented
        /** Ask for the code again; the operator may have mistyped it. */
        object WrongCode : Presented
        /** Ask the operator to mint a NEW code. This one is dead. */
        object CodeExpired : Presented
        /** Someone else used it. Do not retry. */
        object CodeAlreadyUsed : Presented
        /** The window is burned. Do not retry. */
        object TooManyAttempts : Presented
        /** Our own CSR was rejected as unreadable - a bug on this side. */
        object MalformedRequest : Presented
        /** Network, DNS, TLS. Retry with backoff. */
        data class Unreachable(val detail: String) : Presented
        /**
         * A status this client does not model, or a modelled one whose body
         * could not be read (`reason`). The reason is short and fixed: the
         * body itself may be a captive portal's page and is never carried.
         */
        data class Unexpected(val status: Int, val reason: String? = null) : Presented
    }

    sealed interface Collected {
        data class Issued(
            val certificatePem: String,
            val caPem: String,
            val notAfter: String,
            val renewAfter: String,
        ) : Collected
        /** The normal path: a human has not vouched yet. Keep polling. */
        object Waiting : Collected
        /** Unknown, or already collected. Polling will not fix it. */
        object Gone : Collected
        data class Unreachable(val detail: String) : Collected
        /** As Presented.Unexpected. */
        data class Unexpected(val status: Int, val reason: String? = null) : Collected
    }

    fun present(code: String, csrPem: String, deviceName: String): Presented {
        val body = JSONObject()
            .put("code", code)
            .put("csr_pem", csrPem)
            .put("device_name", deviceName)
            .toString()

        val reply = try {
            transport.post("/v1/enroll/requests", body)
        } catch (e: Exception) {
            return Presented.Unreachable(e.message ?: e.javaClass.simpleName)
        }

        return when (reply.status) {
            202 -> reply.readBody<Presented> { json ->
                Presented.Accepted(
                    requestId = json.getString("request_id"),
                    fingerprint = json.getString("fingerprint"),
                )
            } ?: Presented.Unexpected(reply.status, MALFORMED)
            400 -> Presented.MalformedRequest
            403 -> Presented.WrongCode
            409 -> Presented.CodeAlreadyUsed
            410 -> Presented.CodeExpired
            429 -> Presented.TooManyAttempts
            else -> Presented.Unexpected(reply.status)
        }
    }

    fun collect(requestId: String): Collected {
        val reply = try {
            transport.get("/v1/enroll/requests/$requestId/identity")
        } catch (e: Exception) {
            return Collected.Unreachable(e.message ?: e.javaClass.simpleName)
        }

        return when (reply.status) {
            200 -> reply.readBody<Collected> { json ->
                Collected.Issued(
                    certificatePem = json.getString("certificate_pem"),
                    caPem = json.getString("ca_pem"),
                    notAfter = json.getString("not_after"),
                    renewAfter = json.getString("renew_after"),
                )
            } ?: Collected.Unexpected(reply.status, MALFORMED)
            202 -> Collected.Waiting
            404 -> Collected.Gone
            else -> Collected.Unexpected(reply.status)
        }
    }

    /**
     * Read a reply body as JSON, or null when it is not the JSON expected.
     *
     * Guarded like ConfigurationClient.read and RenewalClient.read (muster#229).
     * A captive portal answers 200 with an HTML page, which used to throw out
     * of the enrollment screen's executor and kill the process. The exception
     * is dropped on purpose: org.json puts the whole body in its message, and
     * that body would otherwise travel into logcat and the diagnostics upload.
     */
    private fun <T> Transport.Reply.readBody(read: (JSONObject) -> T): T? = try {
        read(JSONObject(body))
    } catch (e: org.json.JSONException) {
        null
    }

    companion object {
        /** The fixed reason a modelled status with an unreadable body reports. */
        const val MALFORMED = "malformed reply"

        /**
         * What this client believes each status means, as data.
         *
         * Exported so CI can compare it against the server's own map. The two
         * live in different languages and neither test suite can see the other,
         * which is exactly how a device ends up retrying something that will
         * never succeed. Same reasoning as the cross-language CSR check.
         */
        val STATUS_MEANINGS: Map<Int, String> = mapOf(
            400 to "malformed-request",
            403 to "no-such-code",
            409 to "code-used",
            410 to "code-expired",
            429 to "too-many-attempts",
        )
    }
}
