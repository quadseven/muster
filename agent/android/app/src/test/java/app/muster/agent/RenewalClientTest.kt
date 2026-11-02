package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The device side of the challenge, proof, CSR, and renewed identity exchange. */
class RenewalClientTest {

    private class Reply(val status: Int, val body: String)

    private class FakeTransport(
        val challenge: Reply = Reply(
            201,
            JSONObject().put("nonce", "server-nonce").toString(),
        ),
        val renewal: Reply? = null,
        val throwing: Exception? = null,
        val throwingOn: String? = null,
    ) : EnrollmentClient.Transport {
        val paths = mutableListOf<String>()
        val bodies = mutableListOf<String>()

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            paths.add(path)
            bodies.add(body)
            throwing?.let { if (throwingOn == null || throwingOn == path) throw it }
            val reply = when (path) {
                ProvenPost.CHALLENGE_PATH -> challenge
                "/v1/enroll/renew" -> renewal!!
                else -> throw AssertionError("unexpected path: $path")
            }
            return EnrollmentClient.Transport.Reply(reply.status, reply.body)
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("renewal never GETs: $path")
    }

    private class FakeIdentity(
        val certificate: String? = "-----BEGIN CERTIFICATE-----\nmine\n",
        val signingThrows: Boolean = false,
        val keyId: String = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
    ) : ConfigurationClient.Identity {
        var signed: String? = null

        override fun certificatePem(): String? = certificate

        override fun signBase64(nonce: String): String {
            if (signingThrows) error("keystore unavailable")
            signed = nonce
            return "c2lnbmF0dXJl"
        }
        override fun keyId(): String = keyId
    }

    private fun issued(): Reply =
        Reply(
            201,
            JSONObject()
                .put("certificate_pem", "new certificate")
                .put("ca_pem", "authority")
                .put("not_after", "2026-12-01T00:00:00+00:00")
                .put("renew_after", "2026-10-01T00:00:00+00:00")
                .toString(),
        )

    @Test
    fun renewalSendsTheSameProofTripleAsConfigurationPlusTheCsr() {
        val transport = FakeTransport(renewal = issued())
        val identity = FakeIdentity()
        val exchange = DefaultProvenExchange(transport)
        val client = RenewalClient(exchange, identity, "https://enroll.muster.example")

        val result = client.renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Identity)
        assertEquals("server-nonce", identity.signed)
        assertEquals(
            listOf(ProvenPost.CHALLENGE_PATH, "/v1/enroll/renew"),
            transport.paths,
        )
        val sent = JSONObject(transport.bodies.last())
        assertEquals("server-nonce", sent.getString("nonce"))
        assertEquals("c2lnbmF0dXJl", sent.getString("signature_b64"))
        assertTrue(sent.getString("certificate_pem").contains("BEGIN CERTIFICATE"))
        assertEquals("a csr", sent.getString("csr_pem"))
    }

    @Test
    fun aDeviceWithoutACertificateDoesNotBurnAChallenge() {
        val transport = FakeTransport(renewal = issued())
        val identity = FakeIdentity(certificate = null)
        val exchange = DefaultProvenExchange(transport)
        val client = RenewalClient(exchange, identity, "https://enroll.muster.example")

        val result = client.renew("a csr")

        assertTrue(result is RenewalClient.Renewed.NotEnrolled)
        assertTrue(transport.paths.isEmpty())
    }

    @Test
    fun aRefusedChallengeStopsBeforeAnythingIsSigned() {
        val transport = FakeTransport(
            challenge = Reply(503, "proofs unavailable"),
        )
        val identity = FakeIdentity()
        val exchange = DefaultProvenExchange(transport)
        val client = RenewalClient(exchange, identity, "https://enroll.muster.example")

        val result = client.renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Refused)
        assertEquals(null, identity.signed)
        assertEquals(listOf(ProvenPost.CHALLENGE_PATH), transport.paths)
    }

    @Test
    fun aNetworkFailureAfterTheProofIsRetryableWithoutReplacingTheIdentity() {
        val transport = FakeTransport(
            throwing = java.net.SocketTimeoutException("timed out"),
            throwingOn = "/v1/enroll/renew",
        )
        val identity = FakeIdentity()
        val exchange = DefaultProvenExchange(transport)
        val client = RenewalClient(exchange, identity, "https://enroll.muster.example")

        val result = client.renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Unreachable)
    }

    @Test
    fun aKeystoreThatWillNotProvePossessionIsADeviceFailure() {
        val transport = FakeTransport(renewal = issued())
        val identity = FakeIdentity(signingThrows = true)
        val exchange = DefaultProvenExchange(transport)
        val client = RenewalClient(exchange, identity, "https://enroll.muster.example")

        val result = client.renew("a csr")

        assertTrue(result is RenewalClient.Renewed.DeviceCannotAsk)
        assertEquals(listOf(ProvenPost.CHALLENGE_PATH), transport.paths)
    }

    @Test
    fun anUnreadableSuccessNeverReplacesAWorkingIdentity() {
        val transport = FakeTransport(
            renewal = Reply(201, "not json"),
        )
        val identity = FakeIdentity()
        val exchange = DefaultProvenExchange(transport)
        val client = RenewalClient(exchange, identity, "https://enroll.muster.example")

        val result = client.renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Refused)
    }
}