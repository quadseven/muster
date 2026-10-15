package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticsClientTest {
    private class FakeTransport : EnrollmentClient.Transport {
        val paths = mutableListOf<String>()
        val bodies = mutableListOf<String>()
        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            paths += path
            bodies += body
            return if (path == ProvenPost.CHALLENGE_PATH) {
                EnrollmentClient.Transport.Reply(201, "{\"nonce\":\"challenge\"}")
            } else {
                EnrollmentClient.Transport.Reply(202, "{\"accepted\":true}")
            }
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            error("diagnostics does not make GET requests")
    }

    private class FakeIdentity : ConfigurationClient.Identity {
        val signed = mutableListOf<String>()
        override fun certificatePem() = "public certificate"
        override fun signBase64(nonce: String): String {
            signed += nonce
            return "signature"
        }
    }

    @Test
    fun sendsTheReportAfterSigningTheServerNonceWithNoBearerToken() {
        val transport = FakeTransport()
        val identity = FakeIdentity()
        val report = SyncReport.View("checked", emptyList(), listOf("configuration: healthy"))

        val sent = DiagnosticsClient(transport, identity).send(report)

        assertEquals(ProvenPost.Sent.Accepted, sent)
        assertEquals(
            listOf(ProvenPost.CHALLENGE_PATH, DiagnosticsClient.DIAGNOSTICS_PATH),
            transport.paths,
        )
        assertEquals(listOf("challenge"), identity.signed)
        val body = JSONObject(transport.bodies.last())
        assertEquals("public certificate", body.getString("certificate_pem"))
        assertEquals("signature", body.getString("signature_b64"))
        assertEquals("configuration: healthy", body.getJSONArray("diagnostics").getString(0))
        assertTrue(!body.has("token"))
    }

    @Test
    fun boundsTheReportBeforeSendingIt() {
        val transport = FakeTransport()
        val report = SyncReport.View(
            "checked", emptyList(),
            List(30) { "x".repeat(DiagnosticsClient.MAX_LINE_CHARS) },
        )

        assertEquals(
            ProvenPost.Sent.Accepted,
            DiagnosticsClient(transport, FakeIdentity()).send(report),
        )
        val lines = JSONObject(transport.bodies.last()).getJSONArray("diagnostics")
        assertTrue(lines.length() <= DiagnosticsClient.MAX_LINES)
        val byteCount = (0 until lines.length()).sumOf {
            lines.getString(it).toByteArray(Charsets.UTF_8).size
        }
        assertTrue(byteCount <= DiagnosticsClient.MAX_REPORT_BYTES)
    }
}
