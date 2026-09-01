package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The device side of the challenge, proof, CSR, and renewed identity exchange. */
class RenewalClientTest {

    private class FakeTransport(
        private val challenge: EnrollmentClient.Transport.Reply =
            EnrollmentClient.Transport.Reply(
                201,
                JSONObject().put("nonce", "server-nonce").toString(),
            ),
        private val renewal: EnrollmentClient.Transport.Reply? = null,
        private val throwingOn: String? = null,
    ) : EnrollmentClient.Transport {
        val paths = mutableListOf<String>()
        val bodies = mutableListOf<String>()

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            paths.add(path)
            bodies.add(body)
            if (path == throwingOn) throw java.net.SocketTimeoutException("timed out")
            return if (path == RenewalClient.CHALLENGE_PATH) challenge else renewal!!
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("renewal never GETs: $path")
    }

    private class FakeIdentity(
        private val certificate: String? = "-----BEGIN CERTIFICATE-----\nmine\n",
        private val signingThrows: Boolean = false,
    ) : ConfigurationClient.Identity {
        var signed: String? = null

        override fun certificatePem(): String? = certificate

        override fun signBase64(nonce: String): String {
            if (signingThrows) error("keystore unavailable")
            signed = nonce
            return "c2lnbmF0dXJl"
        }
    }

    private fun issued(): EnrollmentClient.Transport.Reply =
        EnrollmentClient.Transport.Reply(
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

        val result = RenewalClient(transport, identity).renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Identity)
        assertEquals("server-nonce", identity.signed)
        assertEquals(
            listOf(RenewalClient.CHALLENGE_PATH, RenewalClient.RENEW_PATH),
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

        val result = RenewalClient(transport, FakeIdentity(certificate = null)).renew("a csr")

        assertTrue(result is RenewalClient.Renewed.NotEnrolled)
        assertTrue(transport.paths.isEmpty())
    }

    @Test
    fun aRefusedChallengeStopsBeforeAnythingIsSigned() {
        val transport = FakeTransport(
            challenge = EnrollmentClient.Transport.Reply(503, "proofs unavailable"),
        )
        val identity = FakeIdentity()

        val result = RenewalClient(transport, identity).renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Refused)
        assertEquals(null, identity.signed)
        assertEquals(listOf(RenewalClient.CHALLENGE_PATH), transport.paths)
    }

    @Test
    fun aNetworkFailureAfterTheProofIsRetryableWithoutReplacingTheIdentity() {
        val transport = FakeTransport(throwingOn = RenewalClient.RENEW_PATH)

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Unreachable)
    }

    @Test
    fun aKeystoreThatWillNotProvePossessionIsADeviceFailure() {
        val transport = FakeTransport(renewal = issued())

        val result = RenewalClient(transport, FakeIdentity(signingThrows = true)).renew("a csr")

        assertTrue(result is RenewalClient.Renewed.DeviceCannotAsk)
        assertEquals(listOf(RenewalClient.CHALLENGE_PATH), transport.paths)
    }

    @Test
    fun anUnreadableSuccessNeverReplacesAWorkingIdentity() {
        val transport = FakeTransport(
            renewal = EnrollmentClient.Transport.Reply(201, "not json"),
        )

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertTrue(result is RenewalClient.Renewed.Refused)
    }
}
