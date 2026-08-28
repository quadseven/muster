package app.muster.agent

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Enrollment as the operator experiences it, including the states where they
 * are standing there holding a phone.
 *
 * The one to read is `theKeyIsGeneratedOnceEvenAcrossRetries`. Generating per
 * attempt changes the fingerprint on the screen while the operator is comparing
 * it with the console, and on hardware-backed storage leaves a key the device
 * can never clean up.
 */
class EnrollmentFlowTest {

    private class CountingKeys : EnrollmentFlow.DeviceKeys {
        var generated = 0
        private var material: EnrollmentFlow.DeviceKeys.Material? = null

        override fun ensure(): EnrollmentFlow.DeviceKeys.Material {
            material?.let { return it }
            generated += 1
            val pair = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            val signer = Signature.getInstance(CertificateRequest.SIGNATURE_ALGORITHM)
            signer.initSign(pair.private)
            return EnrollmentFlow.DeviceKeys.Material(pair.public, signer).also { material = it }
        }
    }

    private class RecordingStore : EnrollmentFlow.IdentityStore {
        var saved: List<String>? = null
        override fun save(certificatePem: String, caPem: String, notAfter: String, renewAfter: String) {
            saved = listOf(certificatePem, caPem, notAfter, renewAfter)
        }
        override fun hasIdentity() = saved != null
    }

    private class ScriptedTransport(
        private val replies: MutableList<EnrollmentClient.Transport.Reply>,
    ) : EnrollmentClient.Transport {
        override fun post(path: String, body: String) = replies.removeAt(0)
        override fun get(path: String) = replies.removeAt(0)
    }

    private fun accepted(requestId: String = "req-1", fingerprint: String = "1379 A19A 1F30 6D87") =
        EnrollmentClient.Transport.Reply(
            202,
            JSONObject().put("request_id", requestId).put("fingerprint", fingerprint).toString(),
        )

    private fun issued() = EnrollmentClient.Transport.Reply(
        200,
        JSONObject()
            .put("certificate_pem", "CERT")
            .put("ca_pem", "CA")
            .put("not_after", "2026-11-16T00:00:00+00:00")
            .put("renew_after", "2026-09-17T00:00:00+00:00")
            .toString(),
    )

    private fun flow(
        replies: MutableList<EnrollmentClient.Transport.Reply>,
        keys: CountingKeys = CountingKeys(),
        store: RecordingStore = RecordingStore(),
    ) = Triple(
        EnrollmentFlow(keys, EnrollmentClient(ScriptedTransport(replies)), store, "pixel-6a-new"),
        keys,
        store,
    )

    // ---- THE one -------------------------------------------------------

    @Test
    fun theKeyIsGeneratedOnceEvenAcrossRetries() {
        // Three failed presentations then a good one. A key per attempt would
        // change the fingerprint under the operator mid-comparison.
        val replies = mutableListOf(
            EnrollmentClient.Transport.Reply(403, "{}"),
            EnrollmentClient.Transport.Reply(403, "{}"),
            EnrollmentClient.Transport.Reply(403, "{}"),
            accepted(),
        )
        val (subject, keys, _) = flow(replies)

        repeat(3) { subject.present("wrong") }
        val outcome = subject.present("714908")

        assertEquals("the key must be generated exactly once", 1, keys.generated)
        assertTrue(outcome is EnrollmentFlow.Step.AwaitingVouch)
    }

    @Test
    fun theFingerprintIsStableAcrossRetries() {
        val replies = mutableListOf(
            accepted(fingerprint = "AAAA BBBB CCCC DDDD"),
            accepted(fingerprint = "AAAA BBBB CCCC DDDD"),
        )
        val (subject, keys, _) = flow(replies)

        val first = subject.present("1") as EnrollmentFlow.Step.AwaitingVouch
        val second = subject.present("2") as EnrollmentFlow.Step.AwaitingVouch
        assertEquals(first.fingerprint, second.fingerprint)
        assertEquals(1, keys.generated)
    }

    // ---- the happy path --------------------------------------------------

    @Test
    fun aVouchedDeviceStoresItsIdentity() {
        val (subject, _, store) = flow(mutableListOf(accepted(), issued()))

        val presented = subject.present("714908") as EnrollmentFlow.Step.AwaitingVouch
        assertEquals("req-1", presented.requestId)
        assertNotNull(presented.fingerprint)

        assertSame(EnrollmentFlow.Step.Enrolled, subject.collect(presented.requestId))
        assertEquals(listOf("CERT", "CA", "2026-11-16T00:00:00+00:00", "2026-09-17T00:00:00+00:00"), store.saved)
    }

    // ---- what the operator is told ---------------------------------------

    @Test
    fun aMistypedCodeStopsWithSomethingActionableRatherThanRetrying() {
        // Retrying the same wrong code achieves nothing. The operator has to
        // act, and a spinner hides that from them.
        val (subject, _, _) = flow(mutableListOf(EnrollmentClient.Transport.Reply(403, "{}")))
        val outcome = subject.present("000000")
        assertTrue(outcome is EnrollmentFlow.Step.Stopped)
        assertTrue((outcome as EnrollmentFlow.Step.Stopped).reason.contains("not recognized"))
    }

    @Test
    fun anExpiredCodeAsksForANewOneRatherThanForTheSameOne() {
        val (subject, _, _) = flow(mutableListOf(EnrollmentClient.Transport.Reply(410, "{}")))
        val outcome = subject.present("714908") as EnrollmentFlow.Step.Stopped
        assertTrue(outcome.reason.contains("expired"))
        assertTrue(outcome.reason.contains("new one"))
    }

    @Test
    fun ourOwnMalformedRequestIsNotBlamedOnTheOperator() {
        val (subject, _, _) = flow(mutableListOf(EnrollmentClient.Transport.Reply(400, "{}")))
        val outcome = subject.present("714908") as EnrollmentFlow.Step.Stopped
        assertTrue(outcome.reason.contains("This device"))
    }

    // ---- polling ---------------------------------------------------------

    @Test
    fun waitingForAHumanDoesNotGrowTheBackoff() {
        // Someone is standing there. Counting their thinking time as failure
        // pushes the poll interval towards an hour while they watch.
        val replies = MutableList(5) { EnrollmentClient.Transport.Reply(202, "{}") }
        val (subject, _, _) = flow(replies)

        repeat(5) {
            val step = subject.collect("req-1") as EnrollmentFlow.Step.Retry
            assertEquals(EnrollmentFlow.POLL_INTERVAL_S, step.afterSeconds)
        }
    }

    @Test
    fun aNetworkFailureBacksOffAndGrows() {
        val (subject, _, _) = flow(mutableListOf())
        // Empty script: the transport throws IndexOutOfBounds, which the client
        // reports as Unreachable - a realistic stand-in for no network.
        val first = subject.collect("req-1") as EnrollmentFlow.Step.Retry
        val second = subject.collect("req-1") as EnrollmentFlow.Step.Retry
        assertTrue("backoff must grow", second.afterSeconds > first.afterSeconds)
    }

    @Test
    fun aGoneRequestStopsRatherThanPollingForever() {
        val (subject, _, _) = flow(mutableListOf(EnrollmentClient.Transport.Reply(404, "{}")))
        val outcome = subject.collect("req-1")
        assertTrue(outcome is EnrollmentFlow.Step.Stopped)
        assertTrue((outcome as EnrollmentFlow.Step.Stopped).reason.contains("new code"))
    }

    @Test
    fun aSuccessfulPresentationClearsEarlierBackoff() {
        // Otherwise a device that had no network for an hour then enrolls fine
        // is still sitting on an hour-long backoff for its next step.
        //
        // The script is fed step by step rather than up front: an empty list
        // makes the transport throw, which is the honest stand-in for no
        // network, and that only works if it is empty at the right moment.
        val replies = mutableListOf<EnrollmentClient.Transport.Reply>()
        val (subject, _, _) = flow(replies)

        // Three failures with no network. Backoff grows.
        repeat(3) { subject.collect("req-1") }
        val grown = (subject.collect("req-1") as EnrollmentFlow.Step.Retry).afterSeconds

        // Then the network comes back and a presentation succeeds.
        replies.add(accepted())
        assertTrue(subject.present("714908") is EnrollmentFlow.Step.AwaitingVouch)

        // The next failure must start from the floor again, not from where the
        // earlier run of failures left off.
        val afterReset = (subject.collect("req-1") as EnrollmentFlow.Step.Retry).afterSeconds
        assertTrue("backoff should have grown before the reset", grown > afterReset)
        assertEquals(IdentityLifecycle.backoffSeconds(1), afterReset)
    }
}
