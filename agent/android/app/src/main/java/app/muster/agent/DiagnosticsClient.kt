package app.muster.agent

import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets

/** Sends a bounded check-in report using the device identity muster issued. */
class DiagnosticsClient(
    private val transport: EnrollmentClient.Transport,
    private val identity: ConfigurationClient.Identity,
) {
    sealed interface Sent {
        object Accepted : Sent
        data class Refused(val status: Int) : Sent
        data class Unreachable(val cause: String) : Sent
        object NotEnrolled : Sent
    }

    fun send(report: SyncReport.View): Sent {
        val certificate = try {
            identity.certificatePem() ?: return Sent.NotEnrolled
        } catch (_: Exception) {
            return Sent.Unreachable("identity unavailable")
        }
        val nonceReply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Sent.Unreachable(e.javaClass.simpleName)
        }
        if (nonceReply.status != 201) return Sent.Refused(nonceReply.status)
        val nonce = try {
            JSONObject(nonceReply.body).getString("nonce")
        } catch (_: Exception) {
            return Sent.Unreachable("unreadable challenge")
        }
        val signature = try {
            identity.signBase64(nonce)
        } catch (_: Exception) {
            return Sent.Unreachable("keystore signing failed")
        }
        val lines = boundedLines(report.detail)
        val body = JSONObject()
            .put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
            .put("diagnostics", JSONArray(lines))
            .toString()
        val reply = try {
            transport.post(DIAGNOSTICS_PATH, body)
        } catch (e: Exception) {
            return Sent.Unreachable(e.javaClass.simpleName)
        }
        return if (reply.status == 202) Sent.Accepted else Sent.Refused(reply.status)
    }

    private fun boundedLines(lines: List<String>): List<String> {
        val result = mutableListOf<String>()
        var bytes = 0
        for (line in lines.take(MAX_LINES)) {
            val bounded = line.take(MAX_LINE_CHARS)
            val size = bounded.toByteArray(StandardCharsets.UTF_8).size
            if (bytes + size > MAX_REPORT_BYTES) break
            result += bounded
            bytes += size
        }
        return result
    }

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
        const val DIAGNOSTICS_PATH = "/v1/device/diagnostics"
        const val MAX_LINES = 16
        const val MAX_LINE_CHARS = 512
        const val MAX_REPORT_BYTES = 4096
    }
}
