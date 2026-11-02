package app.muster.agent

/**
 * One wipe decision and, only when instructed, one acknowledgement and one platform call.
 *
 * THE STEWARD'S PLAN IS THE SINGLE SOURCE OF TRUTH. This flow does not re-read
 * the file or re-evaluate policy; it calls the steward and maps its outcome to
 * a Move the caller can act on. The steward keeps the unfaked platform call
 * (`wipeData`), which is the one action a JVM test cannot reach.
 */
class WipeFlow(
    private val steward: WipeSteward,
) {
    sealed interface Move : StepOutcome {
        /** No wipe instruction on this device. Nothing to do. */
        object NotInstructed : Move {
            override fun concerns(): List<String> = emptyList()
            override fun toString(): String = "not instructed"
        }

        /** Wipe acknowledged and wipeData called. Device should reset. */
        object Wiped : Move {
            override fun concerns(): List<String> = emptyList()
            override fun toString(): String = "wiped"
        }

        /** Wipe was blocked before wipeData, or an error occurred. */
        data class Kept(val reason: String) : Move {
            override fun concerns(): List<String> = listOf(reason)
            override fun toString(): String = "kept - $reason"
        }
    }

    fun advance(): Move = when (val outcome = steward.reconcile()) {
        is WipeSteward.Outcome -> when {
            outcome.wipeRequested -> Move.Wiped
            outcome.kept != null -> Move.Kept(outcome.kept!!)
            else -> Move.Kept("unknown: $outcome")
        }
    }
}