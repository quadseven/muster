package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.util.Log
import java.io.File
import org.json.JSONObject

/**
 * Act on a reboot file that ConfigurationSteward wrote, after RebootPolicy said yes.
 *
 * THE SAME SHAPE AS WipeSteward, ONE SEVERITY DOWN (muster#58). The decision
 * lives in RebootPolicy, where a JVM test can break it. This class only
 * performs two platform-adjacent actions that cannot be unit tested and must
 * not be pretended to be:
 *
 *   1. acknowledge the reboot to muster, so `reboot_requested_at` clears;
 *   2. call `DevicePolicyManager.reboot(admin)`.
 *
 * `reboot()` NEEDS HARDWARE. There is no test for that call here, on purpose,
 * for the same reason WipeSteward gives at length: a test that proves the plan
 * and reads as if it proved the reboot is the exact shape this repository has
 * been burned by before.
 *
 * ORDER OF OPERATIONS, IDENTICAL TO WIPE'S ARGUMENT. The acknowledgement is
 * sent BEFORE `reboot()`, because that call is not guaranteed to return
 * control to this process. If the acknowledgement succeeds and the platform
 * call then fails, the device stays reboot-requested only in the sense that
 * nothing acted on it yet is false - the flag already cleared, so a failed
 * reboot leaves the device exactly as an administrator would expect an
 * unactioned instruction to leave it: unchanged and reachable, ready to be
 * asked again. The alternative - rebooting first and acknowledging later -
 * has no later if the call succeeds, and a stuck flag on a device that never
 * actually rebooted if it does not.
 */
class RebootSteward(private val context: Context) {

    data class Outcome(
        val plan: RebootPolicy.Plan,
        val acknowledged: Boolean = false,
        val rebootRequested: Boolean = false,
        val kept: String? = null,
    ) : StepOutcome {
        override fun concerns(): List<String> = buildList {
            // A healthy plan (no instruction on the device at all) is not a
            // concern, same reasoning as WipeSteward.Outcome.
            if (kept != null && !plan.isQuietHealthy) {
                add(kept)
            }
            if (rebootRequested) {
                // Honest, not reassuring. reboot() is the one action that
                // normally does not return because the device restarts.
                add("reboot was requested and this process was still running")
            }
        }
        override fun toString(): String = when {
            rebootRequested -> "reboot requested (device should restart); acknowledged=$acknowledged"
            kept != null -> "kept the device running; no reboot - $kept"
            else -> "plan=$plan acknowledged=$acknowledged"
        }
    }

    fun filesDir(): File = context.createDeviceProtectedStorageContext().filesDir

    fun configFile(): File = File(filesDir(), RebootPolicy.FILE_NAME)

    fun reconcile(): Outcome {
        val plan = RebootPolicy.plan(read(configFile()))
        if (!plan.reboot) return Outcome(plan = plan, kept = plan.reason)

        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        if (dpm == null) {
            return Outcome(plan = plan, kept = "no DevicePolicyManager on this device")
        }
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            // Ownership is asked of the platform, not remembered from a local
            // file, same reasoning as WipeSteward.
            return Outcome(plan = plan, kept = "this app is not Device Owner; refusing to call reboot")
        }

        val baseUrl = KeystoreIdentity.serverBaseUrl(context)
        if (baseUrl.isBlank()) {
            return Outcome(plan = plan, kept = "no muster server configured on this device")
        }

        val acknowledgement = acknowledge(baseUrl)
        if (acknowledgement != null) {
            return Outcome(plan = plan, kept = acknowledgement)
        }

        // THE CALL ITSELF. Deliberately not abstracted behind an interface, for
        // the same reason WipeSteward's wipeData() call is not: a fake reboot()
        // proves only that the code reached a line.
        return try {
            dpm.reboot(MusterDeviceAdminReceiver.component(context))
            Outcome(plan = plan, acknowledged = true, rebootRequested = true)
        } catch (e: Exception) {
            // IllegalStateException is the documented case (an ongoing call),
            // and it is exactly the shape this catch exists for: the class
            // name is the log's diagnostic, and the device stays running and
            // reachable rather than half-acted-on.
            Log.e(TAG, "reboot failed; the device remains running", e)
            Outcome(plan = plan, acknowledged = true, kept = "reboot failed: ${e.javaClass.simpleName}")
        }
    }

    private fun read(file: File): String? = try {
        file.takeIf { it.isFile }?.readText()
    } catch (e: Exception) {
        Log.w(TAG, "could not read ${file.name}; treating it as no reboot instruction", e)
        null
    }

    /**
     * Tell muster this device received the reboot instruction and is acting on it.
     *
     * Returns null when the acknowledgement landed; otherwise a reason to keep
     * the device running and not call reboot(). Same proof shape as
     * WipeSteward.acknowledge: one authentication scheme, one channel.
     */
    private fun acknowledge(baseUrl: String): String? {
        try {
            val transport = HttpTransport(baseUrl, connectTimeoutMs = 5_000, readTimeoutMs = 8_000)
            val challenge = transport.post(ConfigurationClient.CHALLENGE_PATH, "{}")
            if (challenge.status != 201) {
                return "muster refused the reboot challenge: ${challenge.status}"
            }
            val nonce = JSONObject(challenge.body).getString("nonce")
            val identity = KeystoreIdentity(context)
            val certificate = identity.certificatePem()
                ?: return "no identity certificate; cannot acknowledge the reboot"
            val body = JSONObject()
                .put("nonce", nonce)
                .put("signature_b64", identity.signBase64(nonce))
                .put("certificate_pem", certificate)
                .toString()
            val reply = transport.post(REBOOT_ACK_PATH, body)
            if (reply.status != 200) {
                return "muster refused the reboot acknowledgement: ${reply.status}"
            }
            return null
        } catch (e: Exception) {
            // The class name is the log's diagnostic, not the message, same
            // reasoning as WipeSteward.acknowledge.
            return "could not acknowledge the reboot: ${e.javaClass.simpleName}"
        }
    }

    companion object {
        const val REBOOT_ACK_PATH = "/v1/device/reboot"
        private const val TAG = "muster"
    }
}
