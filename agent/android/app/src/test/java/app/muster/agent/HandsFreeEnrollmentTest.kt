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
 * Enrollment on a phone nobody is holding.
 *
 * Every case here is one that can only be arranged on hardware by wiping a
 * handset, and several of them - a stale QR, a replayed one, a vouch that
 * arrives after the provisioning screen has gone - cannot be arranged on demand
 * at all. That is why the decision is a plain object and this file exists.
 *
 * The one to read is `aRefusedCodeIsForgottenRatherThanRetriedForever`. A device
 * that kept re-presenting a spent code would report as CODE_USED at every boot,
 * which is the same refusal muster reports for somebody replaying a photographed
 * QR - so an appliance in a cupboard would look exactly like an attack.
 */
class HandsFreeEnrollmentTest {

    // ---- the fakes -------------------------------------------------------

    private class Keys : EnrollmentFlow.DeviceKeys {
        private var material: EnrollmentFlow.DeviceKeys.Material? = null
        override fun ensure(): EnrollmentFlow.DeviceKeys.Material {
            material?.let { return it }
            val pair = KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            val signer = Signature.getInstance(CertificateRequest.SIGNATURE_ALGORITHM)
            signer.initSign(pair.private)
            return EnrollmentFlow.DeviceKeys.Material(pair.public, signer).also { material = it }
        }
    }

    private class Identity(var present: Boolean = false) : EnrollmentFlow.IdentityStore {
        override fun save(certificatePem: String, caPem: String, notAfter: String, renewAfter: String) {
            present = true
        }
        override fun hasIdentity() = present
    }

    /** The files PolicyComplianceActivity writes, in memory. */
    private class Handover(
        private var code: String? = null,
        private var request: String? = null,
    ) : HandsFreeEnrollment.Handover {
        var forgotten = 0
        override fun pairingCode() = code
        override fun requestId() = request
        override fun rememberRequest(requestId: String) { request = requestId }
        override fun forget() {
            forgotten += 1
            code = null
            request = null
        }
    }

    private class Scripted(
        private val replies: MutableList<EnrollmentClient.Transport.Reply>,
    ) : EnrollmentClient.Transport {
        val posted = mutableListOf<String>()
        val fetched = mutableListOf<String>()
        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            posted.add(body)
            return replies.removeAt(0)
        }
        override fun get(path: String): EnrollmentClient.Transport.Reply {
            fetched.add(path)
            return replies.removeAt(0)
        }
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

    /** Counts how often the flow was BUILT, not how often it was called. */
    private class Built(private val make: () -> EnrollmentFlow) : () -> EnrollmentFlow {
        var times = 0
        private var made: EnrollmentFlow? = null
        override fun invoke(): EnrollmentFlow {
            made?.let { return it }
            times += 1
            return make().also { made = it }
        }
    }

    private fun subject(
        replies: MutableList<EnrollmentClient.Transport.Reply>,
        handover: Handover,
        identity: Identity = Identity(),
    ): Triple<HandsFreeEnrollment, Scripted, Built> {
        val transport = Scripted(replies)
        val built = Built {
            EnrollmentFlow(Keys(), EnrollmentClient(transport), identity, "pixel-6a")
        }
        return Triple(HandsFreeEnrollment(built, handover, identity), transport, built)
    }

    // ---- the whole point -------------------------------------------------

    @Test
    fun aCodeFromTheQrIsPresentedWithNobodyTyping() {
        val handover = Handover(code = "a-code-out-of-the-provisioning-qr")
        val (hands, transport, _built) = subject(mutableListOf(accepted()), handover)

        val move = hands.advance()

        assertTrue(move is HandsFreeEnrollment.Move.Presented)
        assertEquals(
            "1379 A19A 1F30 6D87",
            (move as HandsFreeEnrollment.Move.Presented).fingerprint,
        )
        assertTrue(transport.posted.single().contains("a-code-out-of-the-provisioning-qr"))
        // WRITTEN DOWN IMMEDIATELY. The code is spent the moment the server
        // accepts it, so a device that lost this id has no way back: presenting
        // again answers CODE_USED, and a certificate an administrator vouched
        // for would sit uncollected forever.
        assertEquals("req-1", handover.requestId())
    }

    @Test
    fun theVouchIsCollectedAndTheHandoverIsThrownAway() {
        val handover = Handover(code = "scanned", request = "req-1")
        val identity = Identity()
        val (hands, transport, _built) = subject(mutableListOf(issued()), handover, identity)

        assertTrue(hands.advance() is HandsFreeEnrollment.Move.Enrolled)
        assertTrue(identity.hasIdentity())
        assertEquals("/v1/enroll/requests/req-1/identity", transport.fetched.single())
        assertNull(handover.pairingCode())
        assertNull(handover.requestId())
    }

    @Test
    fun oneScanCarriesADeviceFromWipedToEnrolled() {
        // The acceptance criterion, end to end through the states a real device
        // passes: present, wait while a human walks to the console, collect.
        val handover = Handover(code = "scanned")
        val (hands, _transport, _built) = subject(
            mutableListOf(
                accepted(),
                EnrollmentClient.Transport.Reply(202, "{}"),
                issued(),
            ),
            handover,
        )

        val slept = mutableListOf<Long>()
        var clock = 0L
        val move = hands.runUntil(
            deadlineMillis = 90_000,
            now = { clock },
            sleep = { slept.add(it); clock += it },
        )

        assertTrue(move is HandsFreeEnrollment.Move.Enrolled)
        assertEquals(listOf(3_000L, 3_000L), slept)
    }

    // ---- refusals --------------------------------------------------------

    @Test
    fun aRefusedCodeIsForgottenRatherThanRetriedForever() {
        // 410: the QR was stale by the time the phone finished installing. The
        // device must not carry that code for the rest of its life - the server
        // answers a re-presented spent code with the same status it uses for
        // somebody replaying a photographed QR, so an appliance quietly retrying
        // in a cupboard is indistinguishable from an attack in the metrics.
        val handover = Handover(code = "a-stale-code")
        val (hands, _transport, _built) = subject(
            mutableListOf(EnrollmentClient.Transport.Reply(410, "")), handover,
        )

        val move = hands.advance()

        assertTrue(move is HandsFreeEnrollment.Move.Stopped)
        assertTrue((move as HandsFreeEnrollment.Move.Stopped).reason.contains("expired"))
        assertNull(handover.pairingCode())
        assertEquals(1, handover.forgotten)
    }

    @Test
    fun aReplayedCodeStopsTooAndSaysSomethingDifferent() {
        // 409 is the one that means somebody else claimed this code, and the
        // operator's response to it is not the same as to a stale one. The two
        // must not collapse into "enrollment failed".
        val handover = Handover(code = "already-used")
        val (hands, _transport, _built) = subject(
            mutableListOf(EnrollmentClient.Transport.Reply(409, "")), handover,
        )

        val move = hands.advance()

        assertTrue((move as HandsFreeEnrollment.Move.Stopped).reason.contains("already been used"))
    }

    @Test
    fun anUnreachableServerKeepsTheCodeForTheNextTry() {
        // The opposite of a refusal, and the distinction is a wiped phone. A
        // device provisioning in a house whose uplink is down has a perfectly
        // good code; throwing it away would strand the handset for good.
        val handover = Handover(code = "still-good")
        val (hands, _transport, _built) = subject(
            mutableListOf(EnrollmentClient.Transport.Reply(503, "")), handover,
        )

        assertTrue(hands.advance() is HandsFreeEnrollment.Move.Retry)
        assertEquals("still-good", handover.pairingCode())
        assertEquals(0, handover.forgotten)
    }

    // ---- the cases where it must do nothing ------------------------------

    @Test
    fun anEnrolledDeviceNeverPresentsAgain() {
        // A second request for a phone that is already in the kith lands in the
        // operator's pending queue with nothing marking it as a duplicate, and
        // they cannot tell it from a stranger's.
        val handover = Handover(code = "scanned", request = "req-1")
        val (hands, transport, built) = subject(
            mutableListOf(), handover, Identity(present = true),
        )

        assertTrue(hands.advance() is HandsFreeEnrollment.Move.AlreadyEnrolled)
        assertTrue(transport.posted.isEmpty() && transport.fetched.isEmpty())
        // AND THE HANDOVER IS THROWN AWAY. This is the one path that runs on a
        // device which scanned a hands-free QR, failed to present, and was then
        // enrolled by hand - and until the boot plan stopped making this
        // decision for itself, it returned before this ever ran and the spent
        // code stayed on the phone for the life of the device.
        assertNull(handover.pairingCode())
        assertNull(handover.requestId())
        assertEquals(0, built.times)
    }

    @Test
    fun aDeviceProvisionedWithoutACodeIsLeftAlone() {
        // A QR minted to be PRINTED carries no code on purpose: the rest of that
        // payload is stable for the life of the signing key and a code expires
        // in minutes. Such a device is enrolled by hand, and must not be sending
        // anything anywhere in the meantime.
        val (hands, transport, built) = subject(mutableListOf(), Handover())

        assertTrue(hands.advance() is HandsFreeEnrollment.Move.NothingToPresent)
        assertTrue(transport.posted.isEmpty() && transport.fetched.isEmpty())
        assertEquals(0, built.times)
    }

    @Test
    fun nothingIsBuiltOnTheBootOfADeviceThatHasNothingToDo() {
        // WHY THE FLOW IS A FACTORY. This runs at every boot of every enrolled
        // device for the life of the fleet, before the four stewards that
        // actually reconcile it, and building a flow costs reading the server
        // address off disk and standing up an HTTP client.
        //
        // The boot plan used to avoid that by asking `hasIdentity()` itself,
        // which is how a second copy of this decision got written and then
        // disagreed with the first. Pinned here so the cheap path stays cheap
        // WITHOUT anybody re-implementing the decision to keep it that way.
        val (enrolled, _t1, first) = subject(
            mutableListOf(), Handover(code = "scanned"), Identity(present = true),
        )
        enrolled.advance()
        assertEquals(0, first.times)

        val (bare, _t2, second) = subject(mutableListOf(), Handover())
        bare.advance()
        assertEquals(0, second.times)

        // And it IS built the moment there is something to send, or none of the
        // above would be testing anything.
        val (ready, _t3, third) = subject(
            mutableListOf(accepted()), Handover(code = "scanned"),
        )
        ready.advance()
        assertEquals(1, third.times)
    }

    // ---- the bounded wait ------------------------------------------------

    @Test
    fun theProvisioningScreenGivesUpRatherThanHoldingSetupOpen() {
        // "If provisioning fails, the device is factory reset" - AOSP. A loop
        // that waited for a vouch that never came would hold the setup wizard
        // on a blank compliance screen, and the phone in that state is one
        // nobody can use and nobody can diagnose.
        val handover = Handover(code = "scanned")
        val (hands, _transport, _built) = subject(
            mutableListOf(
                accepted(),
                EnrollmentClient.Transport.Reply(202, "{}"),
                EnrollmentClient.Transport.Reply(202, "{}"),
            ),
            handover,
        )

        var clock = 0L
        val move = hands.runUntil(
            deadlineMillis = 7_000,
            now = { clock },
            sleep = { clock += it },
        )

        // Out of time, not out of hope: still waiting on a human, with the
        // request lodged and its id on disk - so the next boot collects whatever
        // the administrator vouched for after this screen had gone.
        assertTrue(move is HandsFreeEnrollment.Move.Retry)
        assertEquals("req-1", handover.requestId())
        assertEquals(6_000L, clock)
    }

    @Test
    fun aDeadlineAlreadyPassedMakesExactlyOneAttempt() {
        // The boundary a `while (now < deadline)` loop gets wrong by never
        // trying at all - which on a device with a valid code is a phone that
        // provisions, sends nothing, and comes up unenrolled for no reason.
        val handover = Handover(code = "scanned")
        val (hands, transport, _built) = subject(mutableListOf(accepted()), handover)

        val move = hands.runUntil(deadlineMillis = 0, now = { 5_000 }, sleep = { })

        assertTrue(move is HandsFreeEnrollment.Move.Presented)
        assertEquals(1, transport.posted.size)
    }
}
