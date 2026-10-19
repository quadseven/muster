package app.muster.agent

import android.content.Context
import android.util.Log

/** Builds the same platform-only transport used by the other device clients. */
class DiagnosticsSteward(private val context: Context) {
    fun send(report: SyncReport.View): ProvenPost.Sent {
        return try {
            val baseUrl = KeystoreIdentity.serverBaseUrl(context)
            if (baseUrl.isBlank()) {
                return ProvenPost.Sent.Unreachable("no server configured")
            }
            val client = DiagnosticsClient(
                HttpTransport(baseUrl, connectTimeoutMs = 5_000, readTimeoutMs = 5_000),
                KeystoreIdentity(context),
            )
            client.send(report)
        } catch (e: Exception) {
            Log.e(TAG, "diagnostics steward failed", e)
            ProvenPost.Sent.Unreachable(e.javaClass.simpleName)
        }
    }

    private companion object {
        const val TAG = "muster"
    }
}
