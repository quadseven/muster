package app.muster.agent

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.os.Bundle
import android.util.Log

/**
 * Answers the platform's "what kind of provisioning is this?" during setup.
 *
 * NO UI, ON PURPOSE. This runs inside the setup wizard on a phone somebody is
 * standing over, and every screen a DPC adds there is a screen that can hang,
 * render wrongly on a form factor nobody tested, or wait for a tap that never
 * comes. muster has exactly one answer to give, so it gives it and finishes.
 *
 * A REFUSAL IS RESULT_CANCELED, not a crash. Provisioning failure factory-resets
 * the device either way; the difference is that a cancel is the platform being
 * told no, and an exception is the platform finding out by falling over.
 */
class ProvisioningModeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Only populated when the platform is actually offering a choice.
        val allowed = intent
            .getIntegerArrayListExtra(
                DevicePolicyManager.EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES
            )
            ?.toList()
            .orEmpty()

        when (val mode = ProvisioningPolicy.chooseMode(allowed)) {
            is ProvisioningPolicy.Mode.FullyManaged -> {
                Log.i(TAG, "provisioning as a fully managed device: ${mode.reason}")
                setResult(
                    RESULT_OK,
                    Intent().putExtra(
                        DevicePolicyManager.EXTRA_PROVISIONING_MODE,
                        ProvisioningPolicy.FULLY_MANAGED_DEVICE,
                    ),
                )
            }
            is ProvisioningPolicy.Mode.Refuse -> {
                Log.e(TAG, "refusing to provision: ${mode.why}")
                setResult(RESULT_CANCELED)
            }
        }
        finish()
    }

    companion object {
        private const val TAG = "muster"
    }
}
