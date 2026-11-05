package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every outcome of the proven exchange, once, at its own interface (muster#219).
 *
 * The clients above it translate these outcomes into their own; their tests
 * pin that translation. This file pins the rules they no longer repeat: the
 * order of challenge, signature and post, which leg a failure came from, and
 * what 401 and 403 mean on the proven leg and only there.
 */
class ProvenPostTest {

    private class FakeTransport(
        val challenge: EnrollmentClient.Transport.Reply =
            EnrollmentClient.Transport.Reply(201, JSONObject().put("nonce", "n0nce").toString()),
        val answer: EnrollmentClient.Transport.Reply =
            EnrollmentClient.Transport.Reply(200, "{\"ok\":true}"),
        val throwingOn: String? = null,
    ) : EnrollmentClient.Transport {
        val paths = mutableListOf<String>()
        val bodies = mutableListOf<String>()

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            paths += path
            bodies += body
            if (path == throwingOn) throw java.net.UnknownHostException("muster.example.com")
            return if (path == ProvenExchange.CHALLENGE_PATH) challenge else answer
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("the proven exchange never GETs: $path")
    }

    private class FakeIdentity(
        val certificate: String? = "-----BEGIN CERTIFICATE-----\nexample\n",
        val certificateThrows: Exception? = null,
        val signingThrows: Exception? = null,
    ) : ConfigurationClient.Identity {
        var signed: String? = null
        override fun certificatePem(): String? {
            certificateThrows?.let { throw it }
            return certificate
        }

        override fun signBase64(nonce: String): String {
            signingThrows?.let { throw it }
            signed = nonce
            return "c2lnbmF0dXJl"
        }
    }

    private val path = "/v1/device/example"

    private fun reply(status: Int, body: String) = EnrollmentClient.Transport.Reply(status, body)

    @Test
    fun anAnswerCarriesItsStatusAndBodyAfterTheServersNonceWasSigned() {
        val transport = FakeTransport(answer = reply(200, "{\"ok\":true}"))
        val identity = FakeIdentity()

        val outcome = ProvenExchange(transport, identity)
            .post(path, JSONObject().put("name", "wallpaper"))

        assertEquals(ProvenExchange.Outcome.Answered(200, "{\"ok\":true}"), outcome)
        assertEquals(listOf(ProvenExchange.CHALLENGE_PATH, path), transport.paths)
        assertEquals("{}", transport.bodies.first())
        assertEquals("n0nce", identity.signed)
        val sent = JSONObject(transport.bodies.last())
        assertEquals(
            setOf("name", "nonce", "signature_b64", "certificate_pem"),
            sent.keySet(),
        )
        assertEquals("n0nce", sent.getString("nonce"))
        assertEquals("c2lnbmF0dXJl", sent.getString("signature_b64"))
        assertEquals("wallpaper", sent.getString("name"))
    }

    @Test
    fun everyStatusButTheTwoProofAnswersIsAnAnswer() {
        // The caller decides which status is success; a 409 or a 502 is
        // muster or an intermediary answering, and the caller reads it.
        for (status in listOf(200, 201, 202, 404, 409, 502)) {
            val outcome = ProvenExchange(FakeTransport(answer = reply(status, "b")), FakeIdentity())
                .post(path, JSONObject())
            assertEquals(ProvenExchange.Outcome.Answered(status, "b"), outcome)
        }
    }

    @Test
    fun a401OnTheProvenLegIsUnrecognized() {
        val outcome = ProvenExchange(FakeTransport(answer = reply(401, "cert-not-ours")), FakeIdentity())
            .post(path, JSONObject())

        assertEquals(ProvenExchange.Outcome.Unrecognized, outcome)
    }

    @Test
    fun a403OnTheProvenLegIsRevokedAndKeepsABoundedDetail() {
        val outcome = ProvenExchange(FakeTransport(answer = reply(403, "r".repeat(10_000))), FakeIdentity())
            .post(path, JSONObject())

        assertTrue(outcome.toString(), outcome is ProvenExchange.Outcome.Revoked)
        assertEquals(
            ProvenExchange.REFUSAL_DETAIL_CHARS,
            (outcome as ProvenExchange.Outcome.Revoked).detail.length,
        )
    }

    @Test
    fun aChallengeThatIsNot201IsRefusedAndNothingIsSigned() {
        // 401 and 403 included: before any proof was sent, neither says
        // anything about this device's certificate.
        for (status in listOf(401, 403, 503)) {
            val transport = FakeTransport(challenge = reply(status, "x".repeat(500)))
            val identity = FakeIdentity()

            val outcome = ProvenExchange(transport, identity).post(path, JSONObject())

            assertEquals(
                ProvenExchange.Outcome.Refused(status, "x".repeat(ProvenExchange.REFUSAL_DETAIL_CHARS)),
                outcome,
            )
            assertEquals(listOf(ProvenExchange.CHALLENGE_PATH), transport.paths)
            assertNull(identity.signed)
        }
    }

    @Test
    fun anUnreadableChallengeIsRefusedWithTheChallengeStatus() {
        val transport = FakeTransport(challenge = reply(201, "<html>portal</html>"))

        val outcome = ProvenExchange(transport, FakeIdentity()).post(path, JSONObject())

        assertEquals(ProvenExchange.Outcome.Refused(201, "unreadable challenge: JSONException"), outcome)
        assertEquals(listOf(ProvenExchange.CHALLENGE_PATH), transport.paths)
    }

    @Test
    fun anUnreachableChallengeNamesTheExceptionClassOnly() {
        val transport = FakeTransport(throwingOn = ProvenExchange.CHALLENGE_PATH)
        val identity = FakeIdentity()

        val outcome = ProvenExchange(transport, identity).post(path, JSONObject())

        assertEquals(ProvenExchange.Outcome.Unreachable("UnknownHostException"), outcome)
        assertNull(identity.signed)
    }

    @Test
    fun anUnreachableProvenLegNamesTheExceptionClassOnly() {
        val transport = FakeTransport(throwingOn = path)

        val outcome = ProvenExchange(transport, FakeIdentity()).post(path, JSONObject())

        assertEquals(ProvenExchange.Outcome.Unreachable("UnknownHostException"), outcome)
        assertEquals(listOf(ProvenExchange.CHALLENGE_PATH, path), transport.paths)
    }

    @Test
    fun aDeviceWithNoCertificateAsksForNothing() {
        val transport = FakeTransport()

        val outcome = ProvenExchange(transport, FakeIdentity(certificate = null))
            .post(path, JSONObject())

        assertEquals(ProvenExchange.Outcome.NotEnrolled, outcome)
        assertTrue(transport.paths.isEmpty())
    }

    @Test
    fun aKeystoreThatWillNotSignCannotSignAndSendsNoProof() {
        val transport = FakeTransport()

        val outcome = ProvenExchange(
            transport,
            FakeIdentity(signingThrows = IllegalStateException("keystore")),
        ).post(path, JSONObject())

        assertEquals(
            ProvenExchange.Outcome.CannotSign("could not sign muster's nonce: IllegalStateException"),
            outcome,
        )
        assertEquals(listOf(ProvenExchange.CHALLENGE_PATH), transport.paths)
    }

    @Test
    fun anIdentityThatCannotBeReadCannotSignAndAsksForNothing() {
        val transport = FakeTransport()

        val outcome = ProvenExchange(
            transport,
            FakeIdentity(certificateThrows = IllegalStateException("store")),
        ).post(path, JSONObject())

        assertEquals(ProvenExchange.Outcome.CannotSign("identity unavailable"), outcome)
        assertTrue(transport.paths.isEmpty())
    }

    @Test
    fun aCustomSenderCarriesItsOwnReplyType() {
        // The asset route answers bytes; the exchange hands back whatever the
        // sender read, with the status it read.
        val transport = FakeTransport()
        val outcome = ProvenExchange(transport, FakeIdentity()).exchange(path, JSONObject()) { p, body ->
            transport.post(p, body)
            ProvenExchange.Raw(200, byteArrayOf(1, 2, 3), detail = "")
        }

        outcome as ProvenExchange.Outcome.Answered<ByteArray>
        assertEquals(200, outcome.status)
        assertEquals(listOf<Byte>(1, 2, 3), outcome.body.toList())
    }

    // ---- ProvenPost, the upload built on the exchange ---------------------

    @Test
    fun anUploadIsAcceptedOnlyOnItsAcceptedStatus() {
        val post = ProvenPost(FakeTransport(answer = reply(202, "")), FakeIdentity())
        assertEquals(ProvenPost.Sent.Accepted, post.send(path, JSONObject()))

        val other = ProvenPost(FakeTransport(answer = reply(200, "")), FakeIdentity())
        assertEquals(ProvenPost.Sent.Refused(200), other.send(path, JSONObject()))
    }

    @Test
    fun anUploadKeepsItsOwnReadingOfEveryFailure() {
        fun send(transport: FakeTransport, identity: FakeIdentity = FakeIdentity()) =
            ProvenPost(transport, identity).send(path, JSONObject())

        assertEquals(ProvenPost.Sent.Refused(401), send(FakeTransport(answer = reply(401, ""))))
        assertEquals(ProvenPost.Sent.Refused(403), send(FakeTransport(answer = reply(403, ""))))
        assertEquals(ProvenPost.Sent.Refused(503), send(FakeTransport(challenge = reply(503, ""))))
        assertEquals(
            ProvenPost.Sent.Unreachable("unreadable challenge"),
            send(FakeTransport(challenge = reply(201, "not json"))),
        )
        assertEquals(
            ProvenPost.Sent.Unreachable("UnknownHostException"),
            send(FakeTransport(throwingOn = path)),
        )
        assertEquals(ProvenPost.Sent.NotEnrolled, send(FakeTransport(), FakeIdentity(certificate = null)))
        assertEquals(
            ProvenPost.Sent.Unreachable("identity unavailable"),
            send(FakeTransport(), FakeIdentity(certificateThrows = IllegalStateException())),
        )
        assertEquals(
            ProvenPost.Sent.Unreachable("keystore signing failed"),
            send(FakeTransport(), FakeIdentity(signingThrows = IllegalStateException())),
        )
    }
}
