package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
            listOf(RenewalClient.CHALLENGE_PATH, "/v1/enroll/renew"),
            transport.paths,
        )
        val sent = JSONObject(transport.bodies.last())
        assertEquals("server-nonce", sent.getString("nonce"))
        assertEquals("c2lnbmF0dXJl", sent.getString("signature_b64"))
        assertTrue(sent.getString("certificate_pem").contains("BEGIN CERTIFICATE"))
        assertEquals("a csr", sent.getString("csr_pem"))
    }

    @Test
    fun renewalNamesWhatStartedItWithoutClaimingLockState() {
        // muster#22: the server can tell a scheduled check-in from the sync
        // button when the request says which one sent it.
        val transport = FakeTransport(renewal = issued())

        RenewalClient(
            transport, FakeIdentity(),
            trigger = RenewalTrigger.CHECK_IN,
        ).renew("a csr")

        val sent = JSONObject(transport.bodies.last())
        assertEquals("check-in", sent.getString("trigger"))
        assertFalse(sent.has("direct_boot"))
    }

    @Test
    fun aRenewalThatKnowsNeitherLeavesBothOut() {
        val transport = FakeTransport(renewal = issued())

        RenewalClient(transport, FakeIdentity()).renew("a csr")

        val sent = JSONObject(transport.bodies.last())
        assertFalse(sent.has("trigger"))
        assertFalse(sent.has("direct_boot"))
    }

    @Test
    fun theTriggerIsSeenOnlyInsideThePassThatSetIt() {
        assertEquals(null, RenewalTrigger.current())
        val inside = RenewalTrigger.during(RenewalTrigger.SYNC) { RenewalTrigger.current() }

        assertEquals("sync", inside)
        assertEquals(null, RenewalTrigger.current())
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

    // ---- characterization of the proven exchange (muster#219) -------------
    //
    // Pinned before the exchange moved into ProvenExchange, and kept after.
    // A 403 on renewal stays a refusal carrying muster's text: Renewed has no
    // Revoked outcome, and adding one is a behavior change, not this move.

    @Test
    fun aRevokedDeviceRenewingIsARefusalWithMustersText() {
        val transport = FakeTransport(
            renewal = EnrollmentClient.Transport.Reply(403, "this device has been revoked"),
        )

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertEquals(RenewalClient.Renewed.Refused(403, "this device has been revoked"), result)
    }

    @Test
    fun anUnrecognizedCertificateIsNotARefusal() {
        val transport = FakeTransport(
            renewal = EnrollmentClient.Transport.Reply(401, "cert-not-ours"),
        )

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertTrue(result.toString(), result is RenewalClient.Renewed.Unrecognized)
    }

    @Test
    fun aSuccessStatusOtherThan201IsARefusal() {
        val transport = FakeTransport(
            renewal = EnrollmentClient.Transport.Reply(200, issued().body),
        )

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertTrue(result.toString(), result is RenewalClient.Renewed.Refused)
        assertEquals(200, (result as RenewalClient.Renewed.Refused).status)
    }

    @Test
    fun aRefusalBodyIsBounded() {
        val transport = FakeTransport(
            renewal = EnrollmentClient.Transport.Reply(502, "x".repeat(10_000)),
        )

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertEquals(
            RenewalClient.REFUSAL_DETAIL_CHARS,
            (result as RenewalClient.Renewed.Refused).detail.length,
        )
    }

    @Test
    fun anUnreadableChallengeIsARefusalWithTheChallengeStatus() {
        val transport = FakeTransport(
            challenge = EnrollmentClient.Transport.Reply(201, "not json"),
        )

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        result as RenewalClient.Renewed.Refused
        assertEquals(201, result.status)
        assertTrue(result.detail, result.detail.startsWith("unreadable challenge"))
    }

    @Test
    fun anUnreachableChallengeNamesTheExceptionClassOnly() {
        val transport = FakeTransport(throwingOn = RenewalClient.CHALLENGE_PATH)

        val result = RenewalClient(transport, FakeIdentity()).renew("a csr")

        assertEquals(RenewalClient.Renewed.Unreachable("SocketTimeoutException"), result)
    }

    @Test
    fun theRenewalCarriesTheProofAndTheCsrAndNoInterval() {
        // check_in_interval_s belongs to the configuration fetch only.
        val transport = FakeTransport(renewal = issued())

        RenewalClient(transport, FakeIdentity(), trigger = RenewalTrigger.SYNC).renew("a csr")

        assertEquals(
            setOf("nonce", "signature_b64", "certificate_pem", "csr_pem", "trigger"),
            JSONObject(transport.bodies.last()).keySet(),
        )
    }
}
