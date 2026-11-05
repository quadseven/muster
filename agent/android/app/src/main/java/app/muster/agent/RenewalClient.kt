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
    transport: EnrollmentClient.Transport,
    identity: ConfigurationClient.Identity,
    /** What started this pass ([RenewalTrigger]), logged by muster (muster#22). */
    private val trigger: String? = null,
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

    private val exchange = ProvenExchange(transport, identity)

    fun renew(csrPem: String): Renewed {
        val fields = JSONObject()
            .put("csr_pem", csrPem)
            .apply {
                trigger?.let { put("trigger", it) }
            }
        return when (val outcome = exchange.post(RENEW_PATH, fields)) {
            is ProvenExchange.Outcome.Answered ->
                if (outcome.status == 201) {
                    read(outcome.body)
                } else {
                    Renewed.Refused(outcome.status, outcome.body.take(REFUSAL_DETAIL_CHARS))
                }
            ProvenExchange.Outcome.NotEnrolled -> Renewed.NotEnrolled
            ProvenExchange.Outcome.Unrecognized -> Renewed.Unrecognized
            // Renewed has no revoked outcome, and adding one changes what
            // RenewalFlow reports; a revoked device's renewal stays the
            // refusal it has always been, with muster's text.
            is ProvenExchange.Outcome.Revoked -> Renewed.Refused(403, outcome.detail)
            is ProvenExchange.Outcome.Unreachable -> Renewed.Unreachable(outcome.detail)
            is ProvenExchange.Outcome.Refused -> Renewed.Refused(outcome.status, outcome.detail)
            is ProvenExchange.Outcome.CannotSign -> Renewed.DeviceCannotAsk(outcome.detail)
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
        const val CHALLENGE_PATH = ProvenExchange.CHALLENGE_PATH
        const val RENEW_PATH = "/v1/enroll/renew"
        const val REFUSAL_DETAIL_CHARS = ProvenExchange.REFUSAL_DETAIL_CHARS
    }
}
