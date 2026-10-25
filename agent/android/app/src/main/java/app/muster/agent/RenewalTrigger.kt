package app.muster.agent

/**
 * What started the pass a renewal happens in, so muster can log it (muster#22).
 *
 * WHY THE SERVER NEEDS TO KNOW. Proving that the scheduled check-in, and not a
 * person pressing sync, reached `POST /v1/device/renew` was only readable from
 * logcat on the handset: every caller runs the same `BootPlan.STEPS`, so the
 * request looked identical whichever one sent it. The renewal now says.
 *
 * A THREAD-LOCAL RATHER THAN A PARAMETER ON EVERY STEP, because only renewal
 * reads it and each caller runs the whole plan on one thread of its own - the
 * job's executor, the sync button's executor, the boot receiver's thread - so
 * two passes running at once cannot see each other's value. A step run outside
 * [during] reports null, and the request then carries no trigger at all.
 */
object RenewalTrigger {
    const val CHECK_IN = "check-in"
    const val CATCH_UP = "catch-up"
    const val BOOT = "boot"
    const val SYNC = "sync"

    private val current = ThreadLocal<String?>()

    fun current(): String? = current.get()

    fun <T> during(trigger: String, work: () -> T): T {
        val prior = current.get()
        current.set(trigger)
        try {
            return work()
        } finally {
            current.set(prior)
        }
    }
}
