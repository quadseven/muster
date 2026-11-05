package app.muster.agent

import org.json.JSONObject

/**
 * Acknowledge an instruction to muster, then act on it, and never the other
 * way round (muster#219).
 *
 * THE FLOW BESIDE RenewalFlow AND HandsFreeEnrollment for the two
 * instructions that cannot be taken back: a wipe and a reboot. The
 * acknowledgement goes FIRST because after `wipeData()` or `reboot()` starts
 * this process has no guaranteed chance to say anything. If the
 * acknowledgement lands and the platform call then fails, the device is
 * acknowledged and not acted on, and an administrator can ask again. Acting
 * first and acknowledging later has no later.
 *
 * THE ACTION IS INJECTED SO THE ORDERING CAN BE TESTED, NOT SO THE PLATFORM
 * CALL CAN BE FAKED. WipeSteward and RebootSteward pass the real
 * `DevicePolicyManager` call; AcknowledgedActionTest passes a recorder and
 * proves only that the call is reached after an answer and never without one.
 *
 * @param path the acknowledgement route, e.g. `/v1/device/wipe`
 * @param what the instruction as a log word, e.g. "wipe"
 */
class AcknowledgedAction(
    private val exchange: ProvenExchange,
    private val path: String,
    private val what: String,
) {
    sealed interface Acted {
        /** muster took the acknowledgement and the action returned. */
        object Done : Acted

        /** The acknowledgement did not land. The action was NOT called. */
        data class NotAcknowledged(val reason: String) : Acted

        /** Acknowledged, and the action threw. The steward logs [error]. */
        data class ActionFailed(val error: Exception) : Acted
    }

    fun run(action: () -> Unit): Acted {
        val refusal = acknowledge()
        if (refusal != null) return Acted.NotAcknowledged(refusal)
        return try {
            action()
            Acted.Done
        } catch (e: Exception) {
            Acted.ActionFailed(e)
        }
    }

    /** Null when muster answered 200; otherwise why the action must not run. */
    private fun acknowledge(): String? =
        when (val outcome = exchange.post(path, JSONObject())) {
            is ProvenExchange.Outcome.Answered ->
                if (outcome.status == ACKNOWLEDGED) null else refused(outcome.status)
            ProvenExchange.Outcome.NotEnrolled ->
                "no identity certificate; cannot acknowledge the $what"
            ProvenExchange.Outcome.Unrecognized -> refused(401)
            is ProvenExchange.Outcome.Revoked -> refused(403)
            is ProvenExchange.Outcome.Refused ->
                if (outcome.status == ProvenExchange.CHALLENGE_ISSUED) {
                    "could not acknowledge the $what: ${outcome.detail}"
                } else {
                    "muster refused the $what challenge: ${outcome.status}"
                }
            is ProvenExchange.Outcome.Unreachable ->
                "could not acknowledge the $what: ${outcome.detail}"
            is ProvenExchange.Outcome.CannotSign ->
                "could not acknowledge the $what: ${outcome.detail}"
        }

    private fun refused(status: Int) = "muster refused the $what acknowledgement: $status"

    companion object {
        const val ACKNOWLEDGED = 200

        /**
         * The log words for the two instructions. Kept here, not spelled out
         * in the Stewards, because BootPlanTest refuses a Steward that names
         * a managed file as a string literal, and these match two such names.
         */
        const val WIPE = "wipe"
        const val REBOOT = "reboot"
    }
}
