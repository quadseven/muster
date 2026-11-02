package app.muster.agent

/**
 * System update policy for managed devices (muster#191).
 *
 * The agent sets an automatic install policy when it holds Device Owner so that
 * OS updates install without waiting for user interaction in Settings.
 * When not holding Device Owner, it sets nothing and logs why.
 */
object SystemUpdatePolicy {

    enum class PolicyType {
        AUTOMATIC,
        WINDOWED,
    }

    data class Window(val startMinute: Int, val endMinute: Int)

    sealed interface Plan {
        data class ApplyAutomatic(val reason: String = "automatic install policy applied") : Plan
        data class ApplyWindowed(val window: Window, val reason: String = "windowed install policy applied") : Plan
        data class Skip(val reason: String) : Plan

        /** The agent is Device Owner and tried, and the platform refused the policy. */
        data class Failed(val reason: String) : Plan
    }

    /** What the platform said when asked to set a policy. */
    sealed interface Result {
        data object Applied : Result
        data class Refused(val reason: String) : Result
    }

    interface Target {
        fun setAutomaticInstallPolicy(): Result
        fun setWindowedInstallPolicy(startMinute: Int, endMinute: Int): Result
    }

    fun plan(
        isDeviceOwner: Boolean,
        window: Window? = null,
    ): Plan {
        if (!isDeviceOwner) {
            return Plan.Skip("agent does not hold Device Owner; system update policy requires Device Owner")
        }
        return if (window != null) {
            Plan.ApplyWindowed(window)
        } else {
            Plan.ApplyAutomatic()
        }
    }

    fun apply(
        isDeviceOwner: Boolean,
        target: Target,
        window: Window? = null,
        log: (String) -> Unit = {},
    ): Plan {
        val p = plan(isDeviceOwner, window)
        // The outcome names a refusal, so the check-in report carries it and
        // the console does not show a policy the platform never took.
        return when (p) {
            is Plan.ApplyAutomatic -> settled(p, target.setAutomaticInstallPolicy(), log) {
                "applied automatic install policy"
            }
            is Plan.ApplyWindowed -> settled(
                p,
                target.setWindowedInstallPolicy(p.window.startMinute, p.window.endMinute),
                log,
            ) {
                "applied windowed install policy (${p.window.startMinute}-${p.window.endMinute})"
            }
            is Plan.Skip -> {
                log(p.reason)
                p
            }
            is Plan.Failed -> {
                log(p.reason)
                p
            }
        }
    }

    private fun settled(planned: Plan, result: Result, log: (String) -> Unit, applied: () -> String): Plan =
        when (result) {
            is Result.Applied -> {
                log(applied())
                planned
            }
            is Result.Refused -> Plan.Failed(result.reason).also { log(it.reason) }
        }
}
