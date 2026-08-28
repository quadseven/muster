package app.muster.agent

import java.io.File
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The device's reading of every answer the server can give.
 *
 * These are refusals, and staging real ones against a real server means
 * arranging the failures the class exists to handle - so the transport is
 * faked. What that CANNOT check is whether the server agrees these codes mean
 * what this client thinks; `writesTheStatusMapForTheCrossLanguageCheck` hands
 * that to CI.
 */
class EnrollmentClientTest {

    private class FakeTransport(
        var reply: EnrollmentClient.Transport.Reply? = null,
        var throwing: Exception? = null,
    ) : EnrollmentClient.Transport {
        var lastPath: String? = null
        var lastBody: String? = null

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            lastPath = path; lastBody = body
            throwing?.let { throw it }
            return reply!!
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply {
            lastPath = path
            throwing?.let { throw it }
            return reply!!
        }
    }

    private fun clientReplying(status: Int, body: String = "{}") =
        FakeTransport(EnrollmentClient.Transport.Reply(status, body)).let {
            it to EnrollmentClient(it)
        }

    // ---- presenting ------------------------------------------------------

    @Test
    fun anAcceptedPresentationCarriesTheFingerprintTheDeviceMustDisplay() {
        // The device shows this so the operator can compare it against the
        // console. Without the display there is nothing to check against, and
        // the vouch degrades to "yes, I did start an enrollment".
        val body = JSONObject()
            .put("request_id", "abc123")
            .put("fingerprint", "1379 A19A 1F30 6D87")
            .toString()
        val (transport, client) = clientReplying(202, body)

        val outcome = client.present("714908", "-----BEGIN CERTIFICATE REQUEST-----", "pixel")
        assertTrue(outcome is EnrollmentClient.Presented.Accepted)
        outcome as EnrollmentClient.Presented.Accepted
        assertEquals("abc123", outcome.requestId)
        assertEquals("1379 A19A 1F30 6D87", outcome.fingerprint)
        assertEquals("/v1/enroll/requests", transport.lastPath)
    }

    @Test
    fun theCodeAndCsrAreSentUnderTheNamesTheServerReads() {
        val (transport, client) = clientReplying(
            202, JSONObject().put("request_id", "x").put("fingerprint", "y").toString()
        )
        client.present("714908", "CSRDATA", "pixel-6a-new")

        val sent = JSONObject(transport.lastBody!!)
        assertEquals("714908", sent.getString("code"))
        assertEquals("CSRDATA", sent.getString("csr_pem"))
        assertEquals("pixel-6a-new", sent.getString("device_name"))
    }

    @Test
    fun aWrongCodeIsDistinctFromAnExpiredOne() {
        // 403 means try again with the same code - a mistype. 410 means that
        // code is dead and the operator must mint a new one. Collapsing them
        // leaves a device retrying something that can never succeed.
        assertTrue(clientReplying(403).second.present("1", "c", "d")
            is EnrollmentClient.Presented.WrongCode)
        assertTrue(clientReplying(410).second.present("1", "c", "d")
            is EnrollmentClient.Presented.CodeExpired)
    }

    @Test
    fun aUsedCodeAndABurnedWindowBothStop() {
        assertTrue(clientReplying(409).second.present("1", "c", "d")
            is EnrollmentClient.Presented.CodeAlreadyUsed)
        assertTrue(clientReplying(429).second.present("1", "c", "d")
            is EnrollmentClient.Presented.TooManyAttempts)
    }

    @Test
    fun aRejectedCsrIsReportedAsOurBugNotTheOperatorsMistake() {
        // 400 means the server could not read the CSR we built. Telling the
        // operator to check the code would send them hunting the wrong thing.
        assertTrue(clientReplying(400).second.present("1", "c", "d")
            is EnrollmentClient.Presented.MalformedRequest)
    }

    @Test
    fun aNetworkFailureIsRetryableAndSaysWhy() {
        val transport = FakeTransport(throwing = java.net.UnknownHostException("muster.invalid"))
        val outcome = EnrollmentClient(transport).present("1", "c", "d")
        assertTrue(outcome is EnrollmentClient.Presented.Unreachable)
        assertTrue((outcome as EnrollmentClient.Presented.Unreachable).detail.contains("muster.invalid"))
    }

    // ---- collecting ------------------------------------------------------

    @Test
    fun waitingIsTheNormalPathAndIsNotAFailure() {
        // A human has to walk to their laptop. A client that reads 202 as
        // failure gives up during the most expected part of the ceremony.
        assertTrue(clientReplying(202).second.collect("abc")
            is EnrollmentClient.Collected.Waiting)
    }

    @Test
    fun anIssuedIdentityCarriesTheCertificateAndTheCaToPin() {
        val body = JSONObject()
            .put("certificate_pem", "CERT")
            .put("ca_pem", "CA")
            .put("not_after", "2026-11-16T00:00:00+00:00")
            .put("renew_after", "2026-09-17T00:00:00+00:00")
            .toString()
        val outcome = clientReplying(200, body).second.collect("abc")

        assertTrue(outcome is EnrollmentClient.Collected.Issued)
        outcome as EnrollmentClient.Collected.Issued
        assertEquals("CERT", outcome.certificatePem)
        assertEquals("CA", outcome.caPem)
        assertEquals("2026-09-17T00:00:00+00:00", outcome.renewAfter)
    }

    @Test
    fun goneMeansStopPollingRatherThanRetryForever() {
        // 404 is unknown-or-already-collected. Both are terminal; the identity
        // is handed over exactly once and no amount of polling brings it back.
        assertTrue(clientReplying(404).second.collect("abc")
            is EnrollmentClient.Collected.Gone)
    }

    @Test
    fun anUnknownStatusIsSurfacedRatherThanGuessedAt() {
        val outcome = clientReplying(503).second.collect("abc")
        assertTrue(outcome is EnrollmentClient.Collected.Unexpected)
        assertEquals(503, (outcome as EnrollmentClient.Collected.Unexpected).status)
    }

    // ---- the seam --------------------------------------------------------

    @Test
    fun writesTheStatusMapForTheCrossLanguageCheck() {
        // Handed to CI, which compares it against the server's own map. The two
        // live in different languages and neither suite can see the other -
        // which is exactly how a device ends up retrying something that will
        // never succeed.
        val json = JSONObject()
        EnrollmentClient.STATUS_MEANINGS.forEach { (code, meaning) ->
            json.put(code.toString(), meaning)
        }
        val out = File("build/cross-language/agent-status-map.json")
        out.parentFile.mkdirs()
        out.writeText(json.toString())
        assertTrue(EnrollmentClient.STATUS_MEANINGS.isNotEmpty())
    }
}
