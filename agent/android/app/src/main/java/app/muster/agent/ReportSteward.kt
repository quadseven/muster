package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.Build
import org.json.JSONObject

/**
 * Sends the check-in report (muster#146) over the platform transport, with the
 * managed packages' versions read from the platform after the steps ran, plus
 * OS security patch level, build ID and pending update state (muster#191).
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
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            val admin = ComponentName(context, MusterDeviceAdminReceiver::class.java)
            val pendingUpdate = try {
                if (dpm != null && dpm.isDeviceOwnerApp(context.packageName)) {
                    val update = dpm.getPendingSystemUpdate(admin)
                    if (update != null) {
                        JSONObject().put("pending", true)
                    } else null
                } else null
            } catch (e: Exception) {
                null
            }
            client.send(
                steps = steps,
                versions = AppInstallSteward(context).managedVersions(),
                securityPatch = Build.VERSION.SECURITY_PATCH,
                buildId = Build.ID,
                pendingUpdate = pendingUpdate,
            )
        } catch (e: Exception) {
            ProvenPost.Sent.Unreachable(e.javaClass.simpleName)
        }
    }
}
