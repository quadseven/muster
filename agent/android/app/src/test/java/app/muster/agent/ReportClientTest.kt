package app.muster.agent

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * muster#146: the device says what it did, so the console can say whether it
 * worked without anybody holding the phone.
 */
class ReportClientTest {

    private class FakeTransport(private val status: Int = 202) : EnrollmentClient.Transport {
        val paths = mutableListOf<String>()
        val bodies = mutableListOf<String>()
        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            paths += path
            bodies += body
            return if (path == ProvenPost.CHALLENGE_PATH) {
                EnrollmentClient.Transport.Reply(201, "{\"nonce\":\"challenge\"}")
            } else {
                EnrollmentClient.Transport.Reply(status, "{}")
            }
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            error("a report does not make GET requests")
    }

    private class FakeIdentity(private val pem: String? = "public certificate") :
        ConfigurationClient.Identity {
        override fun certificatePem() = pem
        override fun signBase64(nonce: String) = "signature over $nonce"
    }

    private data class Said(val concerns: List<String>, val text: String) : StepOutcome {
        override fun concerns() = concerns
        override fun toString() = text
    }

    private val welded =
        "WELDED app.example.companion: INSTALL_FAILED_UPDATE_INCOMPATIBLE - refused"

    private val steps = listOf(
        SyncReport.Step("configuration", Said(emptyList(), "fetched revision 7")),
        SyncReport.Step("install-apps", Said(listOf(welded), "installed=[] current=0")),
    )

    private fun sent(transport: FakeTransport) = JSONObject(transport.bodies.last())

    @Test
    fun sendsEveryStepWithItsOutcomeAndConcernsAfterSigningTheNonce() {
        val transport = FakeTransport()

        val result = ReportClient(transport, FakeIdentity()).send(steps, emptyMap())

        assertEquals(ProvenPost.Sent.Accepted, result)
        assertEquals(listOf(ProvenPost.CHALLENGE_PATH, ReportClient.REPORT_PATH), transport.paths)
        val body = sent(transport)
        assertEquals("challenge", body.getString("nonce"))
        assertEquals("signature over challenge", body.getString("signature_b64"))
        val reported = body.getJSONArray("steps")
        assertEquals(2, reported.length())
        assertEquals("install-apps", reported.getJSONObject(1).getString("name"))
        assertEquals("installed=[] current=0", reported.getJSONObject(1).getString("outcome"))
        assertEquals(welded, reported.getJSONObject(1).getJSONArray("concerns").getString(0))
        assertEquals(0, reported.getJSONObject(0).getJSONArray("concerns").length())
    }

    @Test
    fun sendsTheInstalledVersionOfEveryManagedPackage() {
        val transport = FakeTransport()

        ReportClient(transport, FakeIdentity()).send(
            steps,
            linkedMapOf("app.example.companion" to 78L, "app.example.absent" to null),
        )

        val packages = sent(transport).getJSONArray("packages")
        assertEquals("app.example.companion", packages.getJSONObject(0).getString("package"))
        assertEquals(78L, packages.getJSONObject(0).getLong("version_code"))
        // NULL, NOT ZERO. Zero is a versionCode; "not installed" is not one.
        assertTrue(packages.getJSONObject(1).isNull("version_code"))
    }

    @Test
    fun sendsSecurityPatchBuildIdAndPendingUpdateState() {
        val transport = FakeTransport()

        ReportClient(transport, FakeIdentity()).send(
            steps = steps,
            versions = emptyMap(),
            securityPatch = "2026-10-05",
            buildId = "AP2A.241005.001",
            pendingUpdate = JSONObject().put("status", "pending"),
        )

        val body = sent(transport)
        assertEquals("2026-10-05", body.getString("security_patch"))
        assertEquals("AP2A.241005.001", body.getString("build_id"))
        assertEquals("pending", body.getJSONObject("pending_update").getString("status"))
    }

    @Test
    fun aDeviceThatHasNotEnrolledSendsNothing() {
        val transport = FakeTransport()
        assertEquals(
            ProvenPost.Sent.NotEnrolled,
            ReportClient(transport, FakeIdentity(pem = null)).send(steps, emptyMap()),
        )
        assertTrue(transport.paths.isEmpty())
    }

    @Test
    fun aRefusalIsReportedWithItsStatus() {
        assertEquals(
            ProvenPost.Sent.Refused(429),
            ReportClient(FakeTransport(status = 429), FakeIdentity()).send(steps, emptyMap()),
        )
    }

    @Test
    fun boundsEveryFieldToWhatMusterAccepts() {
        val many = List(40) { index ->
            SyncReport.Step("step-$index", Said(List(40) { "c".repeat(600) }, "o".repeat(600)))
        }
        val transport = FakeTransport()

        ReportClient(transport, FakeIdentity()).send(many, emptyMap())

        val reported = sent(transport).getJSONArray("steps")
        assertTrue(reported.length() <= ReportClient.MAX_STEPS)
        var bytes = 0
        for (i in 0 until reported.length()) {
            val step = reported.getJSONObject(i)
            val concerns = step.getJSONArray("concerns")
            assertTrue(concerns.length() <= ReportClient.MAX_CONCERNS)
            assertTrue(step.getString("outcome").length <= ReportClient.MAX_LINE_CHARS)
            bytes += step.getString("name").length + step.getString("outcome").length
            for (j in 0 until concerns.length()) {
                assertTrue(concerns.getString(j).length <= ReportClient.MAX_LINE_CHARS)
                bytes += concerns.getString(j).length
            }
        }
        assertTrue("$bytes bytes", bytes <= ReportClient.MAX_REPORT_BYTES)
    }

    @Test
    fun concernsAreKeptBeforeOutcomesWhenTheBudgetRunsOut() {
        // The concern is the part a monitor alerts on; the outcome is context.
        // Thirty-one outcomes of 512 characters alone overrun the budget, so
        // filling in order would cut the one concern at the end.
        val cramped = List(ReportClient.MAX_STEPS - 1) { index ->
            SyncReport.Step("step-$index", Said(emptyList(), "o".repeat(512)))
        } + SyncReport.Step("install-apps", Said(listOf(welded), "o".repeat(512)))
        val transport = FakeTransport()

        ReportClient(transport, FakeIdentity()).send(cramped, emptyMap())

        val reported = sent(transport).getJSONArray("steps")
        val last = reported.getJSONObject(reported.length() - 1)
        assertEquals(welded, last.getJSONArray("concerns").getString(0))
    }

    @Test
    fun theBodyCarriesNothingButTheProofAndTheReport() {
        val transport = FakeTransport()
        ReportClient(transport, FakeIdentity()).send(steps, mapOf("app.example.x" to 1L))

        val keys = sent(transport).keys().asSequence().toSet()
        assertEquals(
            setOf("nonce", "signature_b64", "certificate_pem", "steps", "packages"),
            keys,
        )
        assertTrue(sent(transport).get("steps") is JSONArray)
    }
}
