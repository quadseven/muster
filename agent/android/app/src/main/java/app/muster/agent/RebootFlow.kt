package app.muster.agent

/**
 * One reboot decision and, only when instructed, one acknowledgement and one platform call.
 *
 * THE STEWARD'S PLAN IS THE SINGLE SOURCE OF TRUTH. This flow does not re-read
 * the file or re-evaluate policy; it calls the steward and maps its outcome to
 * a Move the caller can act on. The steward keeps the unfaked platform call
 * (`reboot`), which is the one action a JVM test cannot reach.
 */
class RebootFlow(
    private val steward: RebootSteward,
) {
    sealed interface Move : StepOutcome {
        /** No reboot instruction on this device. Nothing to do. */
        object NotInstructed : Move {
            override fun concerns(): List<String> = emptyList()
            override fun toString(): String = "not instructed"
        }

        /** Reboot acknowledged and reboot() called. Device should restart. */
        object Rebooted : Move {
            override fun concerns(): List<String> = emptyList()
            override fun toString(): String = "rebooted"
        }

        /** Reboot was blocked before reboot(), or an error occurred. */
        data class Kept(val reason: String) : Move {
            override fun concerns(): List<String> = listOf(reason)
            override fun toString(): String = "kept - $reason"
        }
    }

    fun advance(): Move = when (val outcome = steward.reconcile()) {
        is RebootSteward.Outcome -> when {
            outcome.rebootRequested -> Move.Rebooted
            outcome.kept != null -> Move.Kept(outcome.kept!!)
            else -> Move.Kept("unknown: $outcome")
        }
    }
}