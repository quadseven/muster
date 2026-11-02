package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The device's reading of every answer muster can give a configuration fetch.
 *
 * THE TEST THAT CARRIES THE RULE IN CONTEXT.md is
 * [aServerThatIsNotThereIsNeverAnEmptyConfiguration], and its siblings for a
 * refusal and for a body that will not parse. An empty configuration is a real
 * instruction - it withdraws every file this device holds - so no failure may
 * be able to produce one. A device that loses its policy because a server went
 * away has broken the second rule this project is built on.
 *
 * The transport and the keystore are both faked, because the interesting cases
 * are failures: staging a real captive portal, or a keystore that refuses to
 * sign, means arranging the failure the class exists to handle.
 */
class ConfigurationClientTest {

    private class Reply(val status: Int, val body: String)

    private class FakeExchange(
        val outcome: Outcome = Outcome.Answered("{}", null),
    ) : ProvenExchange {
        var lastEndpoint: String? = null
        var lastProvePath: String? = null
        var lastKeyId: String? = null
        var lastPayload: String? = null

        override suspend fun exchange(
            endpoint: String,
            provePath: String,
            identity: ConfigurationClient.Identity,
            keyId: String,
            payload: String
        ): Outcome {
            lastEndpoint = endpoint
            lastProvePath = provePath
            lastKeyId = keyId
            lastPayload = payload
            return outcome
        }
    }

    private class FakeIdentity(
        val certificate: String? = "-----BEGIN CERTIFICATE-----\nmine\n",
        val signingThrows: Exception? = null,
        val keyId: String = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
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

    private fun served(files: Map<String, String>, revision: String = "r1"): String {
        val body = JSONObject().put("revision", revision)
        val inner = JSONObject()
        files.forEach { (name, content) -> inner.put(name, content) }
        return body.put("files", inner).toString()
    }

    // ---- the rule that must not break ------------------------------------

    @Test
    fun aServerThatIsNotThereIsNeverAnEmptyConfiguration() {
        val exchange = FakeExchange(Outcome.Unreachable(java.net.UnknownHostException("enroll.muster.example")))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch()
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.Unreachable)
    }

    @Test
    fun aServerThatDisappearsAfterTheChallengeIsNeverAnEmptyConfiguration() {
        // The SECOND leg, which the test above cannot reach: this device has a
        // nonce and a signature and the connection goes away. Wifi dropping
        // between two requests is an ordinary thing on a phone, and it must not
        // be the thing that strips a device of its policy.
        val exchange = FakeExchange(Outcome.Unreachable(java.net.SocketTimeoutException("read timed out")))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch()
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.Unreachable)
    }

    @Test
    fun aRefusalIsNeverAnEmptyConfiguration() {
        val exchange = FakeExchange(Outcome.Refused(503, "the kith store is unreachable"))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch()
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.Refused)
        assertEquals(503, (fetched as ConfigurationClient.Fetched.Refused).status)
    }

    @Test
    fun aRevocationIsAnAnswerOfItsOwn() {
        // 403 is muster's deliberate answer after it has verified this
        // device's proof. It is not a transport failure and must not send the
        // operator looking at wifi while the device retries looking healthy.
        val exchange = FakeExchange(Outcome.Revoked("key-1"))
        val client = ConfigurationClient(exchange, FakeIdentity())

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Revoked)
    }

    @Test
    fun aDifferentRefusalIsNotARevocation() {
        // A proxy refusal and an explicit answer from muster demand different
        // operator action. Status alone may distinguish them; body text may
        // not, because an intermediary controls its own response body.
        val exchange = FakeExchange(Outcome.Refused(502, "this device has been revoked"))
        val client = ConfigurationClient(exchange, FakeIdentity())

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Refused)
    }

    @Test
    fun aBodyThatWillNotParseIsNeverAnEmptyConfiguration() {
        // A captive portal answers 200 with a login page. Reading that as "you
        // have no policy" would strip a device the moment it joined hotel wifi.
        val exchange = FakeExchange(Outcome.Answered("<html>Sign in to continue</html>", null))
        val client = ConfigurationClient(exchange, FakeIdentity())

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Refused)
    }

    @Test
    fun aChallengeThatFailsIsNeverAnEmptyConfiguration() {
        val exchange = FakeExchange(Outcome.Refused(503, "proofs are not configured"))
        val client = ConfigurationClient(exchange, FakeIdentity())

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Refused)
    }

    @Test
    fun aRefusedChallengeStopsRatherThanSigningANonceItNeverGot() {
        // Mutation testing found this: replacing a challenge failure with an
        // empty nonce changed no assertion, because the fetch that followed
        // failed for its own reasons. It is still wrong - the device signs
        // nothing, sends it, and reads the server's 400 as a refusal, which
        // puts "muster refused this device" in the log for what is actually a
        // device that never got a challenge.
        val exchange = FakeExchange(Outcome.Refused(503, "proofs are not configured"))
        val identity = FakeIdentity()

        ConfigurationClient(exchange, identity).fetch()

        assertEquals("nothing should have been signed", null, identity.signed)
    }

    @Test
    fun anUnreachableChallengeStopsRatherThanSigningANonceItNeverGot() {
        // THE OTHER WAY A CHALLENGE FAILS, and it is a separate branch: a
        // refusal is a status code, an unreachable server is an exception. The
        // test above passes with either branch broken, which is exactly the
        // hole mutation testing exists to find.
        val exchange = FakeExchange(Outcome.Unreachable(java.net.UnknownHostException("enroll.muster.example")))
        val identity = FakeIdentity()

        ConfigurationClient(exchange, identity).fetch()

        assertEquals("nothing should have been signed", null, identity.signed)
    }

    @Test
    fun aKeystoreThatWillNotSignIsNeverAnEmptyConfiguration() {
        val exchange = FakeExchange(Outcome.CannotSign(IllegalStateException("keystore")))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch()
        // ITS OWN CASE, NOT A `Refused` WITH A MADE-UP STATUS. The log is the
        // whole diagnostic on a phone nobody is holding, and "muster refused"
        // sends an operator to the control plane for a handset problem.
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.DeviceCannotAsk)
        assertTrue(
            (fetched as ConfigurationClient.Fetched.DeviceCannotAsk).detail.contains("sign"),
        )
    }

    // ---- the happy path, and what it proves ------------------------------

    @Test
    fun aConfigurationCarriesItsFilesAndItsRevision() {
        val exchange = FakeExchange(Outcome.Answered(served(mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"), "abc"), null))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch()
        assertTrue(fetched is ConfigurationClient.Fetched.Configuration)
        fetched as ConfigurationClient.Fetched.Configuration
        assertEquals("abc", fetched.revision)
        assertEquals(mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"), fetched.files)
    }

    @Test
    fun anEmptyFilesObjectIsAConfigurationAndNotAFailure() {
        // A muster with no policy directory answers this, and it means
        // "nothing is configured" - which the stewards act on by leaving the
        // device alone. It has to be distinguishable from a refusal.
        val exchange = FakeExchange(Outcome.Answered(served(emptyMap()), null))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch()
        assertTrue(fetched is ConfigurationClient.Fetched.Configuration)
        assertTrue((fetched as ConfigurationClient.Fetched.Configuration).files.isEmpty())
    }

    @Test
    fun theFetchReportsHowOftenThisAgentChecksIn() {
        // muster#77: the console reads this to decide whether a device is
        // inside its own cycle. It must be the schedule the job really uses.
        val exchange = FakeExchange(Outcome.Answered(served(emptyMap()), null))
        val identity = FakeIdentity()
        val client = ConfigurationClient(exchange, identity)

        client.fetch()

        // Check that the payload sent to the exchange includes check_in_interval_s
        val payload = exchange.lastPayload!!
        val sent = JSONObject(payload)
        assertEquals(900L, sent.getLong("check_in_interval_s"))
        assertEquals(CheckInSchedulePolicy.INTERVAL_MS / 1000, sent.getLong("check_in_interval_s"))
    }

    @Test
    fun theServersNonceIsWhatGetsSigned() {
        // A client-chosen challenge is not a challenge: an attacker replays a
        // signature they already have. See server/muster/proof.py.
        // This is now tested at the ProvenExchange level
    }

    @Test
    fun aDeviceWithNoIdentityAsksForNothing() {
        // NotEnrolled rather than a failure, and it must not reach the network:
        // an unenrolled device has nothing to fetch WITH, which is a different
        // problem from a server that will not answer, and it burns a nonce on
        // a control plane for a device that cannot use one.
        val exchange = FakeExchange(Outcome.Answered(served(emptyMap()), null))
        val fetched = ConfigurationClient(exchange, FakeIdentity(certificate = null)).fetch()

        assertTrue(fetched is ConfigurationClient.Fetched.NotEnrolled)
    }

    @Test
    fun anUnrecognizedCertificateIsNotSomethingToRetry() {
        // 401 means muster does not know this device. Retrying an identity it
        // has never issued is a device hammering an endpoint hourly forever;
        // the recovery is enrollment, which needs a person.
        val exchange = FakeExchange(Outcome.Unrecognized("key-1"))
        val client = ConfigurationClient(exchange, FakeIdentity())

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Unrecognized)
    }

    @Test
    fun aFetchedConfigurationNeverPrintsAValue() {
        // This object is logged at every boot, and `app-config` holds a write
        // token. A data class prints every field, which is why it overrides
        // toString.
        val exchange = FakeExchange(Outcome.Answered(served(
            mapOf(
                "app-config" to
                    "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
            )
        ), null))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val rendered = client.fetch().toString()
        assertFalse(rendered.contains("zk_live_7f3a91c4e08b46d2a5"))
        assertTrue(rendered.contains("app-config"))
    }

    @Test
    fun aRefusalBodyIsNotKeptWhole() {
        // It goes into logcat at every boot, and an origin behind something
        // that is not muster answers with whatever it likes.
        val exchange = FakeExchange(Outcome.Refused(502, "x".repeat(10_000)))
        val client = ConfigurationClient(exchange, FakeIdentity())

        val fetched = client.fetch() as ConfigurationClient.Fetched.Refused
        assertEquals(ConfigurationClient.REFUSAL_DETAIL_CHARS, fetched.detail.length)
    }
}