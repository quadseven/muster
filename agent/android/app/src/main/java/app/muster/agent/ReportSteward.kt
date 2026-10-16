package app.muster.agent

import android.content.Context

/**
 * Sends the check-in report (muster#146) over the platform transport, with the
 * managed packages' versions read from the platform after the steps ran.
 */
class ReportSteward(private val context: Context) {
    fun send(steps: List<SyncReport.Step>): ProvenPost.Sent {
        return try {
            val baseUrl = KeystoreIdentity.serverBaseUrl(context)
            if (baseUrl.isBlank()) {
                return ProvenPost.Sent.Unreachable("no server configured")
            }
            val client = ReportClient(
                HttpTransport(baseUrl, connectTimeoutMs = 5_000, readTimeoutMs = 5_000),
                KeystoreIdentity(context),
            )
            val installs = AppInstallSteward(context)
            client.send(
                steps,
                installs.visibleInstalledVersions(),
                installs.expectedVersions(),
            )
        } catch (e: Exception) {
            ProvenPost.Sent.Unreachable(e.javaClass.simpleName)
        }
    }
}
