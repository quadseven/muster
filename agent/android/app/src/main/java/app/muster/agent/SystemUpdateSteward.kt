package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.app.admin.SystemUpdatePolicy as AndroidSystemUpdatePolicy
import android.content.ComponentName
import android.content.Context
import android.util.Log

/**
 * Applies the system update policy using DevicePolicyManager when the agent is Device Owner (muster#191).
 */
class SystemUpdateSteward(
    private val context: Context,
    private val dpm: DevicePolicyManager? = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager,
) {
    private val admin = ComponentName(context, MusterDeviceAdminReceiver::class.java)

    data class Outcome(val plan: SystemUpdatePolicy.Plan) : StepOutcome {
        override fun concerns(): List<String> = when (plan) {
            is SystemUpdatePolicy.Plan.Skip -> listOf(plan.reason)
            is SystemUpdatePolicy.Plan.Failed -> listOf(plan.reason)
            else -> emptyList()
        }

        override fun toString(): String = when (plan) {
            is SystemUpdatePolicy.Plan.ApplyAutomatic -> "automatic system update policy applied"
            is SystemUpdatePolicy.Plan.ApplyWindowed -> "windowed system update policy applied (${plan.window.startMinute}-${plan.window.endMinute})"
            is SystemUpdatePolicy.Plan.Skip -> "skipped system update policy: ${plan.reason}"
            is SystemUpdatePolicy.Plan.Failed -> "system update policy refused: ${plan.reason}"
        }
    }

    fun reconcile(): Outcome {
        val isDeviceOwner = dpm != null && dpm.isDeviceOwnerApp(context.packageName)
        val target = object : SystemUpdatePolicy.Target {
            override fun setAutomaticInstallPolicy(): SystemUpdatePolicy.Result =
                set("automatic") { AndroidSystemUpdatePolicy.createAutomaticInstallPolicy() }

            override fun setWindowedInstallPolicy(startMinute: Int, endMinute: Int): SystemUpdatePolicy.Result =
                set("windowed") { AndroidSystemUpdatePolicy.createWindowedInstallPolicy(startMinute, endMinute) }
        }

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = isDeviceOwner,
            target = target,
            log = { msg -> Log.i(TAG, msg) },
        )
        return Outcome(plan)
    }

    /**
     * Builds and sets the policy, and on a platform refusal returns it as a [SystemUpdatePolicy.Result.Refused]
     * naming the exception, so the step outcome and the check-in report carry the failure.
     */
    private fun set(kind: String, policy: () -> AndroidSystemUpdatePolicy): SystemUpdatePolicy.Result {
        val manager = dpm ?: return SystemUpdatePolicy.Result.Refused("no DevicePolicyManager on this device")
        return try {
            manager.setSystemUpdatePolicy(admin, policy())
            SystemUpdatePolicy.Result.Applied
        } catch (e: SecurityException) {
            refused(kind, e)
        } catch (e: IllegalArgumentException) {
            refused(kind, e)
        } catch (e: IllegalStateException) {
            refused(kind, e)
        }
    }

    private fun refused(kind: String, e: RuntimeException): SystemUpdatePolicy.Result.Refused {
        Log.e(TAG, "could not set $kind system update policy", e)
        return SystemUpdatePolicy.Result.Refused(
            "could not set $kind system update policy: ${e.javaClass.simpleName}: ${e.message}",
        )
    }

    companion object {
        private const val TAG = "MusterUpdate"
    }
}
