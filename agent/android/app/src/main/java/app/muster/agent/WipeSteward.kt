package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.util.Log
import java.io.File
import org.json.JSONObject

/**
 * Act on a wipe file that ConfigurationSteward wrote, after WipePolicy said yes.
 *
 * THE DECISION LIVES IN WipePolicy, where a JVM test can break it. This class
 * only performs two platform-adjacent actions that cannot be unit tested and
 * must not be pretended to be:
 *
 *   1. acknowledge the wipe to muster, so the serving wipe-pending state can
 *      become the refusing revoked state;
 *   2. call `DevicePolicyManager.wipeData(0)`.
 *
 * `wipeData()` NEEDS HARDWARE AND IS NOT A CALL YOU RUN TWICE. There is no test
 * for that call here, on purpose. A test that proves the plan and reads as if
 * it proved the wipe is the exact shape this repository has been burned by with
 * `setApplicationRestrictions`; docs/state-of-play.md says the same thing.
 *
 * ORDER OF OPERATIONS. The acknowledgement is deliberately sent BEFORE
 * `wipeData()`, because after the wipe starts this process has no guaranteed
 * chance to say anything. If the acknowledgement succeeds and the platform call
 * then fails or returns, the device is revoked but not erased; an administrator
 * can request wipe again. The alternative - erasing first and acknowledging
 * later - has no later.
 */
// Spark-authored: deepseek-v4-flash-0731 on an on-prem DGX Spark, 2026-09-04; review pending
class WipeSteward(
    private val context: Context,
    private val exchange: ProvenExchange = DefaultProvenExchange(
        HttpTransport(
            KeystoreIdentity.serverBaseUrl(context),
            connectTimeoutMs = 5_000,
            readTimeoutMs = 8_000
        )
    ),
) {

    data class Outcome(
        val plan: WipePolicy.Plan,
        val acknowledged: Boolean = false,
        val wipeRequested: Boolean = false,
        val kept: String? = null,
    ) : StepOutcome {
        override fun concerns(): List<String> = buildList {
            // A healthy plan (no instruction on the device at all) is not a
            // concern; the steward did exactly what it was told. Every other
            // kept reason is: a wipe blocked before wipeData, or a non-wipe
            // plan whose file is empty or has the wrong content.
            if (kept != null && !plan.isQuietHealthy) {
                add(kept)
            }
            if (wipeRequested) {
                // Honest, not reassuring. wipeData is the one action that
                // normally does not return because the device resets.
                add("wipeData was requested and this process was still running")
            }
        }
        override fun toString(): String = when {
            wipeRequested -> "wipe requested (device should reset); acknowledged=$acknowledged"
            kept != null -> "kept the device; no wipe - $kept"
            else -> "plan=$plan acknowledged=$acknowledged"
        }
    }

    fun filesDir(): File = context.createDeviceProtectedStorageContext().filesDir

    fun configFile(): File = File(filesDir(), WipePolicy.FILE_NAME)

    fun reconcile(): Outcome {
        val plan = WipePolicy.plan(read(configFile()))
        if (!plan.wipe) return Outcome(plan = plan, kept = plan.reason)

        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        if (dpm == null) {
            return Outcome(plan = plan, kept = "no DevicePolicyManager on this device")
        }
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            // Ownership is asked of the platform, not remembered from a local
            // file. A wipe on a device this app does not own is a SecurityException,
            // and the cost of getting that wrong is a wipe nobody asked for.
            return Outcome(plan = plan, kept = "this app is not Device Owner; refusing to call wipeData")
        }

        val baseUrl = KeystoreIdentity.serverBaseUrl(context)
        if (baseUrl.isBlank()) {
            return Outcome(plan = plan, kept = "no muster server configured on this device")
        }

        val acknowledgement = acknowledge(baseUrl)
        if (acknowledgement != null) {
            return Outcome(plan = plan, kept = acknowledgement)
        }

        // THE CALL ITSELF. It is deliberately not abstracted behind an
        // interface so a unit test can fake it: a fake wipeData proves only
        // that the code reached a line, and a test that proves a plan and
        // reads as if it proved the wipe is the failure mode documented in
        // WipePolicy and docs/state-of-play.md.
        return try {
            dpm.wipeData(0)
            Outcome(plan = plan, acknowledged = true, wipeRequested = true)
        } catch (e: Exception) {
            Log.e(TAG, "wipeData failed; the device remains enrolled", e)
            Outcome(plan = plan, acknowledged = true, kept = "wipeData failed: ${e.javaClass.simpleName}")
        }
    }

    private fun read(file: File): String? = try {
        file.takeIf { it.isFile }?.readText()
    } catch (e: Exception) {
        Log.w(TAG, "could not read ${file.name}; treating it as no wipe instruction", e)
        null
    }

    /**
     * Tell muster to move this key from wipe-pending to revoked.
     *
     * Returns null when the acknowledgement landed; otherwise a reason to keep
     * the device and not call wipeData. The proof is the same challenge,
     * signature and certificate as ConfigurationClient: one authentication
     * scheme, one channel.
     */
    private fun acknowledge(baseUrl: String): String? {
        val identity = KeystoreIdentity(context)
        val outcome = exchange.exchange(
            endpoint = baseUrl,
            provePath = "/v1/device/wipe",
            identity = identity,
            keyId = identity.keyId(),
            payload = "{}"
        )

        return when (outcome) {
            is Outcome.Answered -> null
            is Outcome.NotEnrolled -> "no identity certificate; cannot acknowledge the wipe"
            is Outcome.Unrecognized -> "muster does not recognize this device's certificate"
            is Outcome.Revoked -> "muster says this device is revoked"
            is Outcome.Unreachable -> "could not acknowledge the wipe: ${outcome.cause.javaClass.simpleName}"
            is Outcome.Refused -> "muster refused the wipe acknowledgement: ${outcome.status}"
            is Outcome.CannotSign -> "could not sign muster's nonce: ${outcome.cause.javaClass.simpleName}"
        }
    }

    companion object {
        const val WIPE_ACK_PATH = "/v1/device/wipe"
        private const val TAG = "muster"
    }
}