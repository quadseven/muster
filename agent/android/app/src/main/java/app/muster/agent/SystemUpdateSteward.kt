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
            else -> emptyList()
        }

        override fun toString(): String = when (plan) {
            is SystemUpdatePolicy.Plan.ApplyAutomatic -> "automatic system update policy applied"
            is SystemUpdatePolicy.Plan.ApplyWindowed -> "windowed system update policy applied (${plan.window.startMinute}-${plan.window.endMinute})"
            is SystemUpdatePolicy.Plan.Skip -> "skipped system update policy: ${plan.reason}"
        }
    }

    fun reconcile(): Outcome {
        val isDeviceOwner = dpm != null && dpm.isDeviceOwnerApp(context.packageName)
        val target = object : SystemUpdatePolicy.Target {
            override fun setAutomaticInstallPolicy(): Boolean {
                return try {
                    dpm?.setSystemUpdatePolicy(
                        admin,
                        AndroidSystemUpdatePolicy.createAutomaticInstallPolicy(),
                    )
                    true
                } catch (e: Exception) {
                    Log.e(TAG, "could not set automatic system update policy", e)
                    false
                }
            }

            override fun setWindowedInstallPolicy(startMinute: Int, endMinute: Int): Boolean {
                return try {
                    dpm?.setSystemUpdatePolicy(
                        admin,
                        AndroidSystemUpdatePolicy.createWindowedInstallPolicy(startMinute, endMinute),
                    )
                    true
                } catch (e: Exception) {
                    Log.e(TAG, "could not set windowed system update policy", e)
                    false
                }
            }
        }

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = isDeviceOwner,
            target = target,
            log = { msg -> Log.i(TAG, msg) },
        )
        return Outcome(plan)
    }

    companion object {
        private const val TAG = "MusterUpdate"
    }
}
