package app.muster.agent

import android.content.Context

/** Builds the same platform-only transport used by the other device clients. */
class DiagnosticsSteward(private val context: Context) {
    fun send(report: SyncReport.View): DiagnosticsClient.Sent {
        return try {
            val baseUrl = KeystoreIdentity.serverBaseUrl(context)
            if (baseUrl.isBlank()) {
                return DiagnosticsClient.Sent.Unreachable("no server configured")
            }
            val client = DiagnosticsClient(
                HttpTransport(baseUrl, connectTimeoutMs = 5_000, readTimeoutMs = 5_000),
                KeystoreIdentity(context),
            )
            client.send(report)
        } catch (e: Exception) {
            DiagnosticsClient.Sent.Unreachable(e.javaClass.simpleName)
        }
    }
}
