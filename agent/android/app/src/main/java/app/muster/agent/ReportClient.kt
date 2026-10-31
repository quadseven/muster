package app.muster.agent

import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets

/**
 * Tell muster what this check-in did, so whether it worked is a question the
 * console can answer (muster#146).
 *
 * THE GAP THIS CLOSES. `/v1/device/config` is pull-only, and every step's
 * `concerns()` used to end on this phone's own status screen - which needs
 * somebody holding it. An install that failed identically at every check-in was
 * visible only as repeated downloads in the server log. This sends every step's
 * outcome and concerns, and the installed versionCode of each managed package,
 * once per check-in, after the steps have run.
 *
 * ONE POST AFTER THE LAST STEP, NOT ONE PER STEP. Each upload costs a challenge
 * and a signature, and muster keeps one report per device, so per-step posts
 * would be eleven round trips to write the same row eleven times. The one case
 * that ends the process before the post - muster installing ITSELF - is the
 * case that succeeded, and the next check-in reports the new version.
 *
 * BOUNDED HERE so muster never has to refuse it: the server's limits are per
 * field and per row, and a report it refuses is a check-in nobody hears about.
 */
class ReportClient(
    transport: EnrollmentClient.Transport,
    identity: ConfigurationClient.Identity,
) {
    private val post = ProvenPost(transport, identity)

    /**
     * @param versions every managed package to its installed versionCode, null
     *   where it is not installed - which is an answer, not a missing one.
     * @param securityPatch ro.build.version.security_patch or null (muster#191).
     * @param buildId Build.ID or null (muster#191).
     * @param pendingUpdate pending update state object or null (muster#191).
     */
    fun send(
        steps: List<SyncReport.Step>,
        versions: Map<String, Long?>,
        securityPatch: String? = null,
        buildId: String? = null,
        pendingUpdate: Any? = null,
    ): ProvenPost.Sent {
        val fields = JSONObject()
            .put("steps", bounded(steps))
            .put("packages", packages(versions))
        if (securityPatch != null) {
            fields.put("security_patch", securityPatch)
        }
        if (buildId != null) {
            fields.put("build_id", buildId)
        }
        if (pendingUpdate != null) {
            fields.put("pending_update", pendingUpdate)
        }
        return post.send(REPORT_PATH, fields)
    }

    private class Entry(val name: String, val outcome: String, val concerns: List<String>)

    /** What is left of the byte budget, spent one string at a time. */
    private class Budget(var left: Int) {
        /** The whole string if it fits, otherwise nothing. */
        fun whole(text: String): String? {
            val size = bytes(text)
            if (size > left) return null
            left -= size
            return text
        }

        /** As much of the string as fits. */
        fun prefix(text: String): String {
            var cut = text.take(left.coerceAtLeast(0))
            while (bytes(cut) > left) cut = cut.dropLast(1)
            left -= bytes(cut)
            return cut
        }
    }

    /**
     * Every step, CONCERNS BEFORE OUTCOMES. The concern is what an operator or
     * a monitor acts on; the outcome is context. When the budget runs out it is
     * the context that is cut, so a long outcome early in the plan cannot crowd
     * out the one concern at the end of it.
     */
    private fun bounded(steps: List<SyncReport.Step>): JSONArray {
        val entries = steps.take(MAX_STEPS).map { step ->
            Entry(
                name = step.name.take(MAX_NAME_CHARS),
                outcome = step.outcome.toString().take(MAX_LINE_CHARS),
                concerns = step.outcome.concerns().take(MAX_CONCERNS).map { it.take(MAX_LINE_CHARS) },
            )
        }
        val budget = Budget(MAX_REPORT_BYTES - entries.sumOf { bytes(it.name) })
        val concerns = entries.map { entry -> entry.concerns.mapNotNull { budget.whole(it) } }
        val outcomes = entries.map { budget.prefix(it.outcome) }
        return JSONArray(
            entries.indices.map { i ->
                JSONObject()
                    .put("name", entries[i].name)
                    .put("outcome", outcomes[i])
                    .put("concerns", JSONArray(concerns[i]))
            }
        )
    }

    private fun packages(versions: Map<String, Long?>): JSONArray = JSONArray(
        versions.entries.take(MAX_PACKAGES).map { (name, code) ->
            JSONObject().put("package", name).put("version_code", code ?: JSONObject.NULL)
        }
    )

    companion object {
        const val REPORT_PATH = "/v1/device/report"
        const val MAX_STEPS = 32
        const val MAX_CONCERNS = 32
        const val MAX_PACKAGES = 64
        const val MAX_NAME_CHARS = 64
        const val MAX_LINE_CHARS = 512

        /**
         * Below muster's 16384, deliberately. The server bounds what it KEEPS,
         * after redacting credential-shaped text, and a redaction can be longer
         * than what it replaced - so a report sized to the exact limit here
         * could be refused there.
         */
        const val MAX_REPORT_BYTES = 12_288

        private fun bytes(text: String) = text.toByteArray(StandardCharsets.UTF_8).size
    }
}
