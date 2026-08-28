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

    private class FakeTransport(
        val challenge: Reply = Reply(201, JSONObject().put("nonce", "n0nce").toString()),
        val config: Reply? = null,
        val throwing: Exception? = null,
        // WHICH LEG THROWS, because the two are different failures. A device
        // that cannot reach the challenge endpoint never gets as far as asking
        // for a configuration; one that fails on the second leg has a nonce,
        // a signature, and no answer. Mutation testing found this: breaking the
        // fetch leg's catch changed nothing, because every test faked a failure
        // on the first leg.
        val throwingOn: String? = null,
    ) : EnrollmentClient.Transport {
        val paths = mutableListOf<String>()
        val bodies = mutableListOf<String>()

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            paths.add(path)
            bodies.add(body)
            throwing?.let { if (throwingOn == null || throwingOn == path) throw it }
            val reply = if (path == ConfigurationClient.CHALLENGE_PATH) challenge else config!!
            return EnrollmentClient.Transport.Reply(reply.status, reply.body)
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("a configuration fetch never GETs: $path")
    }

    private class FakeIdentity(
        val certificate: String? = "-----BEGIN CERTIFICATE-----\nmine\n",
        val signingThrows: Exception? = null,
    ) : ConfigurationClient.Identity {
        var signed: String? = null
        override fun certificatePem(): String? = certificate
        override fun signBase64(nonce: String): String {
            signingThrows?.let { throw it }
            signed = nonce
            return "c2lnbmF0dXJl"
        }
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
        val client = ConfigurationClient(
            FakeTransport(throwing = java.net.UnknownHostException("enroll.muster.casa")),
            FakeIdentity(),
        )

        val fetched = client.fetch()
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.Unreachable)
    }

    @Test
    fun aServerThatDisappearsAfterTheChallengeIsNeverAnEmptyConfiguration() {
        // The SECOND leg, which the test above cannot reach: this device has a
        // nonce and a signature and the connection goes away. Wifi dropping
        // between two requests is an ordinary thing on a phone, and it must not
        // be the thing that strips a device of its policy.
        val client = ConfigurationClient(
            FakeTransport(
                throwing = java.net.SocketTimeoutException("read timed out"),
                throwingOn = ConfigurationClient.CONFIG_PATH,
            ),
            FakeIdentity(),
        )

        val fetched = client.fetch()
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.Unreachable)
    }

    @Test
    fun aRefusalIsNeverAnEmptyConfiguration() {
        val client = ConfigurationClient(
            FakeTransport(config = Reply(503, "the kith store is unreachable")),
            FakeIdentity(),
        )

        val fetched = client.fetch()
        assertTrue(fetched.toString(), fetched is ConfigurationClient.Fetched.Refused)
        assertEquals(503, (fetched as ConfigurationClient.Fetched.Refused).status)
    }

    @Test
    fun aBodyThatWillNotParseIsNeverAnEmptyConfiguration() {
        // A captive portal answers 200 with a login page. Reading that as "you
        // have no policy" would strip a device the moment it joined hotel wifi.
        val client = ConfigurationClient(
            FakeTransport(config = Reply(200, "<html>Sign in to continue</html>")),
            FakeIdentity(),
        )

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Refused)
    }

    @Test
    fun aChallengeThatFailsIsNeverAnEmptyConfiguration() {
        val client = ConfigurationClient(
            FakeTransport(challenge = Reply(503, "proofs are not configured")),
            FakeIdentity(),
        )

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
        val transport = FakeTransport(challenge = Reply(503, "proofs are not configured"))
        val identity = FakeIdentity()

        ConfigurationClient(transport, identity).fetch()

        assertEquals(listOf(ConfigurationClient.CHALLENGE_PATH), transport.paths)
        assertEquals("nothing should have been signed", null, identity.signed)
    }

    @Test
    fun anUnreachableChallengeStopsRatherThanSigningANonceItNeverGot() {
        // THE OTHER WAY A CHALLENGE FAILS, and it is a separate branch: a
        // refusal is a status code, an unreachable server is an exception. The
        // test above passes with either branch broken, which is exactly the
        // hole mutation testing exists to find.
        val transport = FakeTransport(
            throwing = java.net.UnknownHostException("enroll.muster.casa"),
            throwingOn = ConfigurationClient.CHALLENGE_PATH,
        )
        val identity = FakeIdentity()

        ConfigurationClient(transport, identity).fetch()

        assertEquals(listOf(ConfigurationClient.CHALLENGE_PATH), transport.paths)
        assertEquals("nothing should have been signed", null, identity.signed)
    }

    @Test
    fun aKeystoreThatWillNotSignIsNeverAnEmptyConfiguration() {
        val client = ConfigurationClient(
            FakeTransport(config = Reply(200, served(emptyMap()))),
            FakeIdentity(signingThrows = IllegalStateException("keystore")),
        )

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
        val client = ConfigurationClient(
            FakeTransport(
                config = Reply(200, served(mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"), "abc"))
            ),
            FakeIdentity(),
        )

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
        val client = ConfigurationClient(
            FakeTransport(config = Reply(200, served(emptyMap()))),
            FakeIdentity(),
        )

        val fetched = client.fetch()
        assertTrue(fetched is ConfigurationClient.Fetched.Configuration)
        assertTrue((fetched as ConfigurationClient.Fetched.Configuration).files.isEmpty())
    }

    @Test
    fun theServersNonceIsWhatGetsSigned() {
        // A client-chosen challenge is not a challenge: an attacker replays a
        // signature they already have. See server/muster/proof.py.
        val identity = FakeIdentity()
        val transport = FakeTransport(config = Reply(200, served(emptyMap())))
        ConfigurationClient(transport, identity).fetch()

        assertEquals("n0nce", identity.signed)
        assertEquals(
            listOf(ConfigurationClient.CHALLENGE_PATH, ConfigurationClient.CONFIG_PATH),
            transport.paths,
        )
        val sent = JSONObject(transport.bodies.last())
        assertEquals("n0nce", sent.getString("nonce"))
        assertEquals("c2lnbmF0dXJl", sent.getString("signature_b64"))
        assertTrue(sent.getString("certificate_pem").contains("BEGIN CERTIFICATE"))
    }

    @Test
    fun aDeviceWithNoIdentityAsksForNothing() {
        // NotEnrolled rather than a failure, and it must not reach the network:
        // an unenrolled device has nothing to fetch WITH, which is a different
        // problem from a server that will not answer, and it burns a nonce on
        // a control plane for a device that cannot use one.
        val transport = FakeTransport(config = Reply(200, served(emptyMap())))
        val fetched = ConfigurationClient(transport, FakeIdentity(certificate = null)).fetch()

        assertTrue(fetched is ConfigurationClient.Fetched.NotEnrolled)
        assertTrue("nothing should have been asked of the server", transport.paths.isEmpty())
    }

    @Test
    fun anUnrecognizedCertificateIsNotSomethingToRetry() {
        // 401 means muster does not know this device. Retrying an identity it
        // has never issued is a device hammering an endpoint hourly forever;
        // the recovery is enrollment, which needs a person.
        val client = ConfigurationClient(
            FakeTransport(config = Reply(401, "cert-not-ours")),
            FakeIdentity(),
        )

        assertTrue(client.fetch() is ConfigurationClient.Fetched.Unrecognized)
    }

    @Test
    fun aFetchedConfigurationNeverPrintsAValue() {
        // This object is logged at every boot, and `app-config` holds a write
        // token. A data class prints every field, which is why it overrides
        // toString.
        val client = ConfigurationClient(
            FakeTransport(
                config = Reply(
                    200,
                    served(
                        mapOf(
                            "app-config" to
                                "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n"
                        )
                    ),
                )
            ),
            FakeIdentity(),
        )

        val rendered = client.fetch().toString()
        assertFalse(rendered.contains("zk_live_7f3a91c4e08b46d2a5"))
        assertTrue(rendered.contains("app-config"))
    }

    @Test
    fun aRefusalBodyIsNotKeptWhole() {
        // It goes into logcat at every boot, and an origin behind something
        // that is not muster answers with whatever it likes.
        val client = ConfigurationClient(
            FakeTransport(config = Reply(502, "x".repeat(10_000))),
            FakeIdentity(),
        )

        val fetched = client.fetch() as ConfigurationClient.Fetched.Refused
        assertEquals(ConfigurationClient.REFUSAL_DETAIL_CHARS, fetched.detail.length)
    }
}
