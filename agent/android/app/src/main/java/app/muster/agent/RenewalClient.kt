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
    private val exchange: ProvenExchange,
    private val identity: ConfigurationClient.Identity,
    private val endpoint: String,
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
        val payload = JSONObject().put("csr_pem", csrPem).toString()
        return when (val outcome = exchange.exchange(
            endpoint = endpoint,
            provePath = "/v1/enroll/renew",
            identity = identity,
            keyId = identity.keyId(),
            payload = payload
        )) {
            is Outcome.Answered -> read(outcome.body)
            is Outcome.NotEnrolled -> Renewed.NotEnrolled
            is Outcome.Unrecognized -> Renewed.Unrecognized
            is Outcome.Unreachable -> Renewed.Unreachable(outcome.cause.javaClass.simpleName)
            is Outcome.Refused -> Renewed.Refused(outcome.status, outcome.body.take(REFUSAL_DETAIL_CHARS))
            is Outcome.CannotSign -> Renewed.DeviceCannotAsk("could not sign muster's nonce: ${outcome.cause.javaClass.simpleName}")
            is Outcome.Revoked -> Renewed.Refused(403, "device revoked")
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
        const val REFUSAL_DETAIL_CHARS = 200

        fun create(
            transport: EnrollmentClient.Transport,
            identity: ConfigurationClient.Identity,
            baseUrl: String,
        ): RenewalClient {
            val exchange = DefaultProvenExchange(transport)
            return RenewalClient(exchange, identity, baseUrl)
        }
    }
}