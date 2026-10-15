package app.muster.agent

import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets

/** Sends a bounded check-in report using the device identity muster issued. */
class DiagnosticsClient(
    transport: EnrollmentClient.Transport,
    identity: ConfigurationClient.Identity,
) {
    private val post = ProvenPost(transport, identity)

    fun send(report: SyncReport.View): ProvenPost.Sent {
        val lines = boundedLines(report.detail)
        return post.send(DIAGNOSTICS_PATH, JSONObject().put("diagnostics", JSONArray(lines)))
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
        const val DIAGNOSTICS_PATH = "/v1/device/diagnostics"
        const val MAX_LINES = 16
        const val MAX_LINE_CHARS = 512
        const val MAX_REPORT_BYTES = 4096
    }
}
