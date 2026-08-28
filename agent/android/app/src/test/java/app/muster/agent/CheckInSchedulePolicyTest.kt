package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * How often a device reconciles itself, and when a schedule needs rewriting.
 *
 * muster#58. Configuration was fetched AT BOOT ONLY, so a device that came up
 * wrong stayed wrong until somebody rebooted it or pressed a button - and the
 * failure this fixes is worse than a missed reboot.
 *
 * Two Pixels acting as bond legs drained flat overnight. Their relay starts at
 * LOCKED_BOOT_COMPLETED so a locked phone still relays, but the console write
 * token is deliberately not cached before first unlock - so each came up
 * forwarding bytes and unable to announce itself. No announce, no leg, and the
 * router lost every uplink it had. There is no self-heal path on that side:
 * re-delivering the configuration to the LIVE process is what makes it announce
 * again, and nothing was re-delivering anything.
 *
 * The one that matters is `aScheduleThatIsAlreadyRightIsLeftAlone` - rewriting
 * a periodic job restarts its interval, so a device that rescheduled on every
 * boot-ish event would push its own next check-in away forever.
 */
class CheckInSchedulePolicyTest {

    @Test
    fun theIntervalIsTheOneAndroidWillActuallyHonour() {
        // JobScheduler clamps a periodic job to 15 minutes; asking for less
        // does not fail, it silently becomes 15 - and a constant that lies
        // about what the device does is worse than a slower one that does not.
        assertTrue(CheckInSchedulePolicy.INTERVAL_MS >= 15 * 60_000L)
    }

    @Test
    fun aDeviceWithNoScheduleNeedsOne() {
        assertTrue(CheckInSchedulePolicy.needsScheduling(existingIntervalMs = null))
    }

    @Test
    fun aScheduleThatIsAlreadyRightIsLeftAlone() {
        // THE ONE THAT MATTERS. Rescheduling a periodic job RESTARTS its
        // interval. A device that rewrote its schedule on every boot, every
        // sync press and every supervision pass would push its own next
        // check-in permanently into the future and never run one - which looks
        // exactly like a schedule that is working.
        assertFalse(
            CheckInSchedulePolicy.needsScheduling(
                existingIntervalMs = CheckInSchedulePolicy.INTERVAL_MS
            )
        )
    }

    @Test
    fun aScheduleAtTheWrongIntervalIsRewritten() {
        // An agent that changed its mind about the interval must be able to
        // take effect without a wipe, so a stale interval IS grounds to rewrite.
        assertTrue(CheckInSchedulePolicy.needsScheduling(existingIntervalMs = 60_000L))
        assertTrue(
            CheckInSchedulePolicy.needsScheduling(
                existingIntervalMs = CheckInSchedulePolicy.INTERVAL_MS * 4
            )
        )
    }

    @Test
    fun theJobIdIsStableSoOneDeviceHasOneSchedule() {
        // A job id derived from anything that changes - a timestamp, a hash of
        // config - would leave one orphaned periodic job per change, each still
        // firing, and the device would reconcile N times per interval.
        assertEquals(CheckInSchedulePolicy.JOB_ID, CheckInSchedulePolicy.JOB_ID)
        assertTrue(CheckInSchedulePolicy.JOB_ID > 0)
    }

    @Test
    fun aCheckInIsWorthRunningEvenWithNoNetwork() {
        // MOST OF THE BOOT PLAN IS LOCAL. Restrictions, app visibility and app
        // configuration are reconciled from files already on the device, and
        // those are exactly what a half-started device is missing. Requiring a
        // network would mean a device on a dead router - the case this exists
        // for - never reconciles at all.
        assertFalse(CheckInSchedulePolicy.REQUIRES_NETWORK)
    }

    // ---- catching up after a failed fetch ---------------------------------

    @Test
    fun aCheckInThatCouldNotReachMusterAsksToBeWokenWhenTheNetworkReturNS() {
        // THE PERIODIC JOB IS NOT ENOUGH ON ITS OWN. It carries no network
        // constraint on purpose - the local steps must run on a device sitting
        // on a dead router - which means a fetch that failed waits the FULL
        // interval rather than recovering when connectivity comes back. For a
        // bond leg whose router just returned, that is the difference between
        // seconds and fifteen minutes.
        assertTrue(CheckInSchedulePolicy.needsCatchUp(fetchReachedMuster = false))
    }

    @Test
    fun aCheckInThatReachedMusterAsksForNothingExtra() {
        // Scheduling a catch-up after every successful check-in would mean a
        // device with a perfectly good network waking itself twice per
        // interval, forever, for nothing.
        assertFalse(CheckInSchedulePolicy.needsCatchUp(fetchReachedMuster = true))
    }

    @Test
    fun theCatchUpIsADIFFERENTJobFromThePeriodicOne() {
        // Sharing an id would make scheduling the catch-up REPLACE the periodic
        // job - the device would recover once and then never reconcile again,
        // which is worse than the bug being fixed.
        assertTrue(CheckInSchedulePolicy.CATCH_UP_JOB_ID != CheckInSchedulePolicy.JOB_ID)
    }

    @Test
    fun theCatchUpBacksOffRatherThanSpinning() {
        // A device whose network never returns must not retry in a loop; a
        // device whose network returns in a minute must not wait fifteen.
        assertTrue(CheckInSchedulePolicy.CATCH_UP_BACKOFF_MS in 1_000..60_000)
        assertTrue(CheckInSchedulePolicy.CATCH_UP_BACKOFF_MS < CheckInSchedulePolicy.INTERVAL_MS)
    }
}
