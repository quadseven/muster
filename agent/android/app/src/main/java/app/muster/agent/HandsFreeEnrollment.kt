package app.muster.agent

/**
 * Enrollment with nobody holding the phone.
 *
 * WHAT THIS IS FOR. A wiped device scans a provisioning QR off a monitor and
 * comes up owned by muster. Until this existed the last step was still manual:
 * somebody opened the agent, read six digits off a console, and typed them in.
 * The QR now carries a pairing code in its admin extras bundle, and this is what
 * spends it.
 *
 * READ enroll.py's MODULE DOCSTRING BEFORE CHANGING ANYTHING HERE. The security
 * question this answers is not on this side of the wire: with nobody looking at
 * the device's screen there is no second copy of the key fingerprint, so the
 * comparison an administrator makes when they vouch cannot catch a stranger who
 * guessed the code. The answer is that a scanned code is 192 bits rather than
 * six digits, so the stranger cannot reach the queue at all. Nothing on this
 * side may loosen that: in particular the code is used ONCE and then forgotten,
 * because a device that kept retrying a spent code would be indistinguishable
 * from something replaying one.
 *
 * A STATE MACHINE, NOT A LOOP WITH A SLEEP IN IT. `advance()` makes exactly one
 * call and says what should happen next, so both callers can drive it the way
 * their own context allows - the provisioning screen polls it while a person
 * waits, and the boot plan nudges it once and returns. Neither owns the clock,
 * which is what lets every branch below be tested with no device.
 */
class HandsFreeEnrollment(
    /**
     * Built ONLY when there is something to send, which is why it is a factory.
     *
     * The common case at boot is a device that is already enrolled, on every
     * boot for the rest of its life, and building a flow costs reading the
     * server address off disk and standing up an HTTP client. A caller that had
     * to avoid that cost itself would have to re-implement the "is there
     * anything to do" decision - which is what the boot plan did until this
     * became a factory, and it got it wrong: it returned before the cleanup
     * below and left a spent code on a device forever.
     */
    private val flow: () -> EnrollmentFlow,
    private val store: Handover,
    private val identity: EnrollmentFlow.IdentityStore,
) {

    /**
     * What provisioning left behind for enrollment to pick up.
     *
     * Separate from `IdentityStore` because these two have opposite lifetimes:
     * the identity is kept for the life of the device, and everything here is
     * deleted the moment it has been used or refused. A single store holding
     * both invites a `clear()` that takes the certificate with it.
     */
    interface Handover {
        /** The code out of the provisioning QR, or null if there was not one. */
        fun pairingCode(): String?

        /** The request already lodged with muster, if this device presented. */
        fun requestId(): String?

        /** Remember which request is waiting on a human, across a reboot. */
        fun rememberRequest(requestId: String)

        /**
         * Drop both. Called when enrollment ENDS, either way.
         *
         * Keeping a spent code would have the device re-present it at every
         * boot forever, which the server answers with CODE_USED - the same
         * refusal it reports for somebody replaying a photographed QR. An
         * appliance in a cupboard would then look exactly like an attack.
         */
        fun forget()
    }

    /** What happened, and what the caller should do about it. */
    sealed interface Move : StepOutcome {
        /** There is already an identity. Nothing to do, and nothing was sent. */
        object AlreadyEnrolled : Move

        /** No code was left behind. The typed path is how this device gets in. */
        object NothingToPresent : Move

        /** Lodged with muster and waiting on an administrator to vouch. */
        data class Presented(val fingerprint: String) : Move

        /** Done. The device has an identity. */
        object Enrolled : Move

        /** Try again in this many seconds - waiting on a human, or on a network. */
        data class Retry(val afterSeconds: Long, val detail: String) : Move

        /** Over, and it will not get better by itself. The handover is forgotten. */
        data class Stopped(val reason: String) : Move

        // AN UNENROLLED DEVICE ENFORCES NOTHING, so every move that is not
        // "this device holds an identity" is worth a person's attention. That
        // includes NothingToPresent, which is what a phone says when the
        // operator has not started a ceremony - quiet, correct, and still the
        // reason none of the steps below it will do anything.
        override fun concerns(): List<String> = when (this) {
            AlreadyEnrolled, Enrolled -> emptyList()
            NothingToPresent -> listOf("not enrolled and nothing to present")
            is Presented -> listOf("presented ${fingerprint}; waiting to be vouched")
            is Retry -> listOf("retrying in ${afterSeconds}s - $detail")
            is Stopped -> listOf("enrollment stopped - $reason")
        }
    }

    /**
     * Advance enrollment by exactly one call, and say what comes next.
     *
     * The order matters. An identity is checked FIRST so a device that is
     * already in the kith never presents again - re-presenting would put a
     * second request in the operator's queue for a phone that is already
     * enrolled, and there is no way for them to tell it is a duplicate.
     */
    fun advance(): Move {
        if (identity.hasIdentity()) {
            // Belt and braces: whatever is left of the handover is dead the
            // moment a certificate exists, and this is the one place that runs
            // on a device which enrolled some other way (typed, or a cable).
            store.forget()
            return Move.AlreadyEnrolled
        }

        val outstanding = store.requestId()
        if (outstanding != null) return collect(outstanding)

        val code = store.pairingCode() ?: return Move.NothingToPresent
        return present(code)
    }

    private fun present(code: String): Move = when (val step = flow().present(code)) {
        is EnrollmentFlow.Step.AwaitingVouch -> {
            // WRITTEN DOWN BEFORE ANYTHING ELSE HAPPENS. The code is spent the
            // instant the server accepts it, so a device that lost this id would
            // have no way back: presenting again answers CODE_USED, and the
            // certificate an administrator vouched for would sit uncollected.
            store.rememberRequest(step.requestId)
            Move.Presented(step.fingerprint)
        }
        // Stale QR, replayed QR, or a burned window. All three are the server
        // refusing this code for good, so the handover goes rather than being
        // retried at every boot for the life of the device.
        is EnrollmentFlow.Step.Stopped -> {
            store.forget()
            Move.Stopped(step.reason)
        }
        is EnrollmentFlow.Step.Retry -> Move.Retry(step.afterSeconds, step.detail)
        is EnrollmentFlow.Step.Enrolled -> {
            store.forget()
            Move.Enrolled
        }
    }

    private fun collect(requestId: String): Move =
        when (val step = flow().collect(requestId)) {
            is EnrollmentFlow.Step.Enrolled -> {
                store.forget()
                Move.Enrolled
            }
            is EnrollmentFlow.Step.Stopped -> {
                store.forget()
                Move.Stopped(step.reason)
            }
            // Covers both "no human has vouched yet" and "the network is gone",
            // which are the same instruction to a caller with no screen: come
            // back later. EnrollmentFlow already chose the interval for each.
            is EnrollmentFlow.Step.Retry -> Move.Retry(step.afterSeconds, step.detail)
            is EnrollmentFlow.Step.AwaitingVouch -> Move.Presented(step.fingerprint)
        }

    /**
     * Keep advancing until enrollment settles or the caller runs out of time.
     *
     * FOR THE PROVISIONING SCREEN, which is the one moment on a hands-free
     * device when something is allowed to wait: the operator has just scanned
     * the QR and is standing at the console the pending request is about to
     * appear on. Everywhere else calls `advance()` once and leaves.
     *
     * `now` and `sleep` are injected for the usual reason - a bounded loop that
     * owns its own clock can only be tested by actually waiting - and the
     * deadline is a WALL CLOCK rather than an iteration count, because the
     * thing that must not happen is a setup wizard sitting on this screen.
     */
    fun runUntil(deadlineMillis: Long, now: () -> Long, sleep: (Long) -> Unit): Move {
        while (true) {
            val move = advance()
            val wait = when (move) {
                is Move.Retry -> move.afterSeconds * 1000
                // Presented is not the end: an administrator is about to vouch,
                // and this is the whole reason the screen waits at all.
                is Move.Presented -> EnrollmentFlow.POLL_INTERVAL_S * 1000
                else -> return move
            }
            // The deadline is checked AFTER advancing, so a caller who arrives
            // already out of time still makes one attempt. A `while (now <
            // deadline)` would make none, and on a device with a valid code that
            // is a phone which provisions, sends nothing, and comes up
            // unenrolled for no reason a log could explain.
            val remaining = deadlineMillis - now()
            if (remaining <= 0 || wait >= remaining) return move
            sleep(wait)
        }
    }
}
