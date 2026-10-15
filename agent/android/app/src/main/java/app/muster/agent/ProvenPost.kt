package app.muster.agent

import org.json.JSONObject

/**
 * One POST to muster carrying this device's proof: challenge, sign, send.
 *
 * SHARED BY EVERY UPLOAD rather than written into each, because the server
 * authenticates every device route in one place (`_proven_device`) and the
 * client side of that should be one place too. Diagnostics and the check-in
 * report both go up through this; a third upload is a path and a body, not a
 * third copy of the handshake.
 */
class ProvenPost(
    private val transport: EnrollmentClient.Transport,
    private val identity: ConfigurationClient.Identity,
) {
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
    fun send(path: String, fields: JSONObject, accepted: Int = 202): Sent {
        val certificate = try {
            identity.certificatePem() ?: return Sent.NotEnrolled
        } catch (_: Exception) {
            return Sent.Unreachable("identity unavailable")
        }
        val nonce = when (val challenge = challenge()) {
            is Challenge.Nonce -> challenge.value
            is Challenge.Failed -> return challenge.sent
        }
        val signature = try {
            identity.signBase64(nonce)
        } catch (_: Exception) {
            return Sent.Unreachable("keystore signing failed")
        }
        fields.put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
        val reply = try {
            transport.post(path, fields.toString())
        } catch (e: Exception) {
            return Sent.Unreachable(e.javaClass.simpleName)
        }
        return if (reply.status == accepted) Sent.Accepted else Sent.Refused(reply.status)
    }

    private sealed interface Challenge {
        data class Nonce(val value: String) : Challenge
        data class Failed(val sent: Sent) : Challenge
    }

    private fun challenge(): Challenge {
        val reply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Challenge.Failed(Sent.Unreachable(e.javaClass.simpleName))
        }
        if (reply.status != 201) return Challenge.Failed(Sent.Refused(reply.status))
        return try {
            Challenge.Nonce(JSONObject(reply.body).getString("nonce"))
        } catch (_: Exception) {
            Challenge.Failed(Sent.Unreachable("unreadable challenge"))
        }
    }

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
    }
}
