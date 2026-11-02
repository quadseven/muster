package app.muster.agent

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The seven outcomes a device can read from the sealed exchange.
 *
 * Every test here fakes the transport and the keystore, because the
 * interesting cases are failures: staging a real captive portal, or a
 * keystore that refuses to sign, means arranging the failure the class
 * exists to handle.
 */
class ProvenExchangeTest {

    private class Reply(val status: Int, val body: String)

    private class FakeTransport(
        val challenge: Reply = Reply(201, JSONObject().put("nonce", "n0nce").toString()),
        val prove: Reply? = null,
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
                "/v1/device/config", "/v1/enroll/renew", "/v1/device/wipe", "/v1/device/reboot" -> prove!!
                else -> throw AssertionError("unexpected path: $path")
            }
            return EnrollmentClient.Transport.Reply(reply.status, reply.body)
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("proven exchange never GETs: $path")
    }

    private class FakeIdentity(
        val certificate: String? = "-----BEGIN CERTIFICATE-----\nmine\n",
        val keyId: String = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
        val signingThrows: Exception? = null,
    ) : ConfigurationClient.Identity {
        var signed: String? = null
        override fun certificatePem(): String? = certificate
        override fun signBase64(nonce: String): String {
            signingThrows?.let { throw it }
            signed = nonce
            return "c2lnbmF0dXJl"
        }
        override fun keyId(): String = keyId
    }

    private class Keys {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
    }

    private fun served(files: Map<String, String>, revision: String = "r1"): String {
        val body = JSONObject().put("revision", revision)
        val inner = JSONObject()
        files.forEach { (name, content) -> inner.put(name, content) }
        return body.put("files", inner).toString()
    }

    // ---- the seven outcomes -----------------------------------------------

    @Test
    fun challengeUnreachableIsUnreachable() {
        val exchange = DefaultProvenExchange(
            FakeTransport(throwing = java.net.UnknownHostException("enroll.muster.example")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Unreachable)
        assertEquals("UnknownHostException", (outcome as Outcome.Unreachable).cause.javaClass.simpleName)
    }

    @Test
    fun challengeRefusedIsRefused() {
        val exchange = DefaultProvenExchange(
            FakeTransport(challenge = Reply(503, "proofs are not configured")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Refused)
        assertEquals(503, (outcome as Outcome.Refused).status)
    }

    @Test
    fun challengeNotEnrolledIsNotEnrolled() {
        val exchange = DefaultProvenExchange(
            FakeTransport(challenge = Reply(404, "{}")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.NotEnrolled)
    }

    @Test
    fun challengeUnrecognizedIsUnrecognized() {
        val exchange = DefaultProvenExchange(
            FakeTransport(challenge = Reply(401, "cert-not-ours")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Unrecognized)
    }

    @Test
    fun challengeRevokedIsRevoked() {
        val exchange = DefaultProvenExchange(
            FakeTransport(challenge = Reply(403, "{\"detail\":\"this device has been revoked\"}")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Revoked)
    }

    @Test
    fun proveUnreachableIsUnreachable() {
        val exchange = DefaultProvenExchange(
            FakeTransport(
                throwing = java.net.SocketTimeoutException("read timed out"),
                throwingOn = "/v1/device/config",
            ),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Unreachable)
        assertEquals("SocketTimeoutException", (outcome as Outcome.Unreachable).cause.javaClass.simpleName)
    }

    @Test
    fun proveRefusedIsRefused() {
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(502, "bad gateway")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Refused)
        assertEquals(502, (outcome as Outcome.Refused).status)
    }

    @Test
    fun proveNotEnrolledIsNotEnrolled() {
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(404, "{}")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.NotEnrolled)
    }

    @Test
    fun proveUnrecognizedIsUnrecognized() {
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(401, "cert-not-ours")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Unrecognized)
    }

    @Test
    fun proveRevokedIsRevoked() {
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(403, "{\"detail\":\"this device has been revoked\"}")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Revoked)
    }

    @Test
    fun proveReturnsAnsweredWithBody() {
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(200, served(mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"), "abc"))),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.Answered)
        val answered = outcome as Outcome.Answered
        assertEquals("abc", JSONObject(answered.body).getString("revision"))
    }

    @Test
    fun aKeystoreThatWillNotSignIsCannotSign() {
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(200, "{}")),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(signingThrows = IllegalStateException("keystore")),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.CannotSign)
    }

    @Test
    fun noCertificateIsNotEnrolled() {
        val exchange = DefaultProvenExchange(
            FakeTransport(challenge = Reply(201, JSONObject().put("nonce", "n0nce").toString())),
        )

        val outcome = exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = FakeIdentity(certificate = null),
            keyId = "key-1",
            payload = "{}"
        )

        assertTrue(outcome is Outcome.NotEnrolled)
    }

    @Test
    fun theServersNonceIsWhatGetsSigned() {
        val identity = FakeIdentity()
        val exchange = DefaultProvenExchange(
            FakeTransport(prove = Reply(200, "{}")),
        )

        exchange.exchange(
            endpoint = "https://enroll.muster.example",
            provePath = "/v1/device/config",
            identity = identity,
            keyId = "key-1",
            payload = "{}"
        )

        assertEquals("n0nce", identity.signed)
        assertEquals(
            listOf(ProvenPost.CHALLENGE_PATH, "/v1/device/config"),
            (exchange as DefaultProvenExchange).transport.paths
        )
    }
}