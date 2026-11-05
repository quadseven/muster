package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Acknowledge first, then act, and never act without the acknowledgement
 * (muster#219).
 *
 * THE ACTION HERE IS A RECORDING LAMBDA, NOT A FAKE WIPE. These tests prove
 * the ordering a wipe or a reboot depends on: whether the platform call was
 * reached, and only after muster answered. They say nothing about
 * `wipeData()` or `reboot()` themselves, which WipeSteward and RebootSteward
 * still call unfaked, on a handset.
 */
class AcknowledgedActionTest {

    private class FakeTransport(
        val challenge: EnrollmentClient.Transport.Reply =
            EnrollmentClient.Transport.Reply(201, JSONObject().put("nonce", "n0nce").toString()),
        val acknowledgement: EnrollmentClient.Transport.Reply =
            EnrollmentClient.Transport.Reply(200, "{}"),
        val throwingOn: String? = null,
        val events: MutableList<String> = mutableListOf(),
    ) : EnrollmentClient.Transport {
        val bodies = mutableListOf<String>()

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            events += "post $path"
            bodies += body
            if (path == throwingOn) throw java.net.SocketTimeoutException("muster.example.com")
            return if (path == ProvenExchange.CHALLENGE_PATH) challenge else acknowledgement
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("an acknowledgement never GETs: $path")
    }

    private class FakeIdentity(
        val certificate: String? = "-----BEGIN CERTIFICATE-----\nexample\n",
        val signingThrows: Boolean = false,
    ) : ConfigurationClient.Identity {
        override fun certificatePem(): String? = certificate
        override fun signBase64(nonce: String): String {
            if (signingThrows) error("keystore")
            return "c2lnbmF0dXJl"
        }
    }

    private val path = "/v1/device/example-action"

    private fun reply(status: Int, body: String = "") =
        EnrollmentClient.Transport.Reply(status, body)

    private fun run(
        transport: FakeTransport,
        identity: FakeIdentity = FakeIdentity(),
        action: () -> Unit = { transport.events += "ACT" },
    ): AcknowledgedAction.Acted =
        AcknowledgedAction(ProvenExchange(transport, identity), path, "example").run(action)

    @Test
    fun theActionRunsOnlyAfterMusterAnsweredTheAcknowledgement() {
        val transport = FakeTransport()

        val acted = run(transport)

        assertEquals(AcknowledgedAction.Acted.Done, acted)
        assertEquals(
            listOf("post ${ProvenExchange.CHALLENGE_PATH}", "post $path", "ACT"),
            transport.events,
        )
    }

    @Test
    fun theAcknowledgementCarriesOnlyTheProof() {
        // The wire format the wipe and reboot routes already take.
        val transport = FakeTransport()

        run(transport)

        assertEquals(
            setOf("nonce", "signature_b64", "certificate_pem"),
            JSONObject(transport.bodies.last()).keySet(),
        )
    }

    @Test
    fun noAnswerMeansNoAction() {
        // Every way the acknowledgement can fail to land, and in none of them
        // is the irreversible call reached.
        val cases = mapOf(
            "refused acknowledgement" to FakeTransport(acknowledgement = reply(409, "pending")),
            "other success status" to FakeTransport(acknowledgement = reply(202)),
            "unrecognized" to FakeTransport(acknowledgement = reply(401)),
            "revoked" to FakeTransport(acknowledgement = reply(403)),
            "refused challenge" to FakeTransport(challenge = reply(503)),
            "unreadable challenge" to FakeTransport(challenge = reply(201, "not json")),
            "unreachable challenge" to FakeTransport(throwingOn = ProvenExchange.CHALLENGE_PATH),
            "unreachable acknowledgement" to FakeTransport(throwingOn = path),
        )
        for ((name, transport) in cases) {
            val acted = run(transport)
            assertTrue("$name: $acted", acted is AcknowledgedAction.Acted.NotAcknowledged)
            assertTrue("$name acted: ${transport.events}", "ACT" !in transport.events)
        }
    }

    @Test
    fun aDeviceWithNoIdentityNeverActs() {
        val transport = FakeTransport()

        val acted = run(transport, FakeIdentity(certificate = null))

        assertEquals(
            AcknowledgedAction.Acted.NotAcknowledged("no identity certificate; cannot acknowledge the example"),
            acted,
        )
        assertTrue(transport.events.isEmpty())
    }

    @Test
    fun aKeystoreThatWillNotSignNeverActs() {
        val transport = FakeTransport()

        val acted = run(transport, FakeIdentity(signingThrows = true))

        assertTrue(acted.toString(), acted is AcknowledgedAction.Acted.NotAcknowledged)
        assertTrue("ACT" !in transport.events)
    }

    @Test
    fun theReasonsKeepTheStewardsWording() {
        assertEquals(
            AcknowledgedAction.Acted.NotAcknowledged("muster refused the example acknowledgement: 409"),
            run(FakeTransport(acknowledgement = reply(409))),
        )
        assertEquals(
            AcknowledgedAction.Acted.NotAcknowledged("muster refused the example challenge: 503"),
            run(FakeTransport(challenge = reply(503))),
        )
        assertEquals(
            AcknowledgedAction.Acted.NotAcknowledged("could not acknowledge the example: SocketTimeoutException"),
            run(FakeTransport(throwingOn = path)),
        )
    }

    @Test
    fun anActionThatThrowsIsReportedAfterTheAcknowledgement() {
        // The device is acknowledged and not acted on; the steward logs the
        // exception and an administrator can ask again.
        val transport = FakeTransport()
        val failure = IllegalStateException("ongoing call")

        val acted = run(transport) { throw failure }

        assertEquals(AcknowledgedAction.Acted.ActionFailed(failure), acted)
        assertEquals(
            listOf("post ${ProvenExchange.CHALLENGE_PATH}", "post $path"),
            transport.events,
        )
    }

    @Test
    fun theActionRunsOncePerAcknowledgement() {
        val transport = FakeTransport()
        var calls = 0

        run(transport) { calls += 1 }

        assertEquals(1, calls)
    }
}
