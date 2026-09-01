package app.muster.agent

import org.json.JSONObject

/**
 * Replace this device's certificate over the identity it already holds.
 *
 * THE PROOF IS THE SAME TRIPLE AS A CONFIGURATION FETCH: a server-issued
 * nonce, its signature by the keystore key, and muster's certificate for that
 * key. Renewal does not invent a second device authentication path. The CSR is
 * one more field on the proven request, and the server refuses it unless it
 * carries that same public key.
 *
 * ONE REQUEST AFTER ONE CHALLENGE, with no polling. Enrollment polls because a
 * person has to vouch between presentation and issuance. Possession of the
 * enrolled key is the vouch here, so muster returns the certificate directly.
 */
class RenewalClient(
    private val transport: EnrollmentClient.Transport,
    private val identity: ConfigurationClient.Identity,
) {

    sealed interface Renewed {
        data class Identity(
            val certificatePem: String,
            val caPem: String,
            val notAfter: String,
            val renewAfter: String,
        ) : Renewed

        object NotEnrolled : Renewed
        object Unrecognized : Renewed
        data class Unreachable(val detail: String) : Renewed
        data class Refused(val status: Int, val detail: String) : Renewed
        data class DeviceCannotAsk(val detail: String) : Renewed
    }

    fun renew(csrPem: String): Renewed {
        val certificate = identity.certificatePem() ?: return Renewed.NotEnrolled
        val nonce = when (val challenged = challenge()) {
            is Challenged.Nonce -> challenged.value
            is Challenged.Failed -> return challenged.why
        }
        val signature = try {
            identity.signBase64(nonce)
        } catch (e: Exception) {
            return Renewed.DeviceCannotAsk("could not sign muster's nonce: ${detail(e)}")
        }
        val body = JSONObject()
            .put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
            .put("csr_pem", csrPem)
            .toString()
        val reply = try {
            transport.post(RENEW_PATH, body)
        } catch (e: Exception) {
            return Renewed.Unreachable(detail(e))
        }
        return when (reply.status) {
            201 -> read(reply.body)
            401 -> Renewed.Unrecognized
            else -> Renewed.Refused(reply.status, reply.body.take(REFUSAL_DETAIL_CHARS))
        }
    }

    private sealed interface Challenged {
        data class Nonce(val value: String) : Challenged
        data class Failed(val why: Renewed) : Challenged
    }

    private fun challenge(): Challenged {
        val reply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Challenged.Failed(Renewed.Unreachable(detail(e)))
        }
        if (reply.status != 201) {
            return Challenged.Failed(
                Renewed.Refused(reply.status, reply.body.take(REFUSAL_DETAIL_CHARS))
            )
        }
        return try {
            Challenged.Nonce(JSONObject(reply.body).getString("nonce"))
        } catch (e: Exception) {
            Challenged.Failed(
                Renewed.Refused(reply.status, "unreadable challenge: ${detail(e)}")
            )
        }
    }

    /** A malformed success is a refusal to replace a still-working identity. */
    private fun read(body: String): Renewed = try {
        val json = JSONObject(body)
        Renewed.Identity(
            certificatePem = json.getString("certificate_pem"),
            caPem = json.getString("ca_pem"),
            notAfter = json.getString("not_after"),
            renewAfter = json.getString("renew_after"),
        )
    } catch (e: Exception) {
        Renewed.Refused(201, "muster's renewal could not be read: ${detail(e)}")
    }

    // Class only, never the exception message: the request and response carry
    // certificate material, and neither belongs in logcat on a failure path.
    private fun detail(e: Exception): String = e.javaClass.simpleName

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
        const val RENEW_PATH = "/v1/device/renew"
        const val REFUSAL_DETAIL_CHARS = 200
    }
}
