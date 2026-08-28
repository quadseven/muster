package app.muster.agent

import app.muster.agent.IdentityLifecycle.Stance
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The renewal decision, which is where an offline device gets stranded.
 *
 * The two worth reading are `aClockBehindTheCertificateIsNotAnInvalidCertificate`
 * and `renewalStartsWithAWideRunway`. Both encode the same lesson from zippie:
 * these devices are off, or travelling, or wrong about the date, and a policy
 * tuned for a server in a rack fails them in exactly those states.
 */
class IdentityLifecycleTest {

    private val day = 86_400L
    private val notBefore = 1_000_000L
    private val notAfter = notBefore + 90 * day
    private val renewAfter = notBefore + 30 * day

    @Test
    fun aFreshIdentityIsCurrent() {
        val stance = IdentityLifecycle.stance(notBefore, notAfter, renewAfter, notBefore + day)
        assertEquals(Stance.Current, stance)
    }

    @Test
    fun renewalStartsWithAWideRunway() {
        // One second past the server's renewAfter, with 60 days still to run.
        val stance = IdentityLifecycle.stance(notBefore, notAfter, renewAfter, renewAfter + 1)
        assertTrue(stance is Stance.ShouldRenew)
        val remaining = (stance as Stance.ShouldRenew).secondsUntilExpiry
        assertTrue(
            "a device offline for a fortnight must still wake up inside the window",
            remaining > 55 * day,
        )
    }

    @Test
    fun anExpiredIdentityIsLapsedNotUnenrolled() {
        // "Not enrolled" reads as somebody wiped the device. "Lapsed 3 days
        // ago" tells an operator what actually happened.
        val stance = IdentityLifecycle.stance(notBefore, notAfter, renewAfter, notAfter + 3 * day)
        assertTrue(stance is Stance.Lapsed)
        assertEquals(3 * day, (stance as Stance.Lapsed).secondsSinceExpiry)
    }

    @Test
    fun aClockBehindTheCertificateIsNotAnInvalidCertificate() {
        // THE one that matters. The MT3000 has no RTC and can boot in 1970.
        // Concluding "invalid" here means a device deleting a good identity
        // because it does not know the date - unrecoverable without a cable.
        val stance = IdentityLifecycle.stance(notBefore, notAfter, renewAfter, notBefore - 7 * day)
        assertTrue(stance is Stance.ClockBehind)
        assertEquals(7 * day, (stance as Stance.ClockBehind).secondsOfSkew)
    }

    @Test
    fun noCertificateIsUnenrolled() {
        assertEquals(Stance.Unenrolled, IdentityLifecycle.stance(null, null, null, 1))
        assertEquals(Stance.Unenrolled, IdentityLifecycle.stance(notBefore, null, null, 1))
    }

    @Test
    fun aMissingRenewAfterFallsBackToAThirdOfLife() {
        // An older server, or an identity stored before the field existed.
        // Silently never renewing would be the worst possible fallback.
        val third = notBefore + (notAfter - notBefore) / 3
        assertEquals(Stance.Current, IdentityLifecycle.stance(notBefore, notAfter, null, third - 1))
        assertTrue(IdentityLifecycle.stance(notBefore, notAfter, null, third) is Stance.ShouldRenew)
    }

    @Test
    fun expiryIsInclusiveSoTheLastSecondIsNotStillValid() {
        assertTrue(IdentityLifecycle.stance(notBefore, notAfter, renewAfter, notAfter) is Stance.Lapsed)
    }

    // ---- backoff ---------------------------------------------------------

    @Test
    fun theFirstFailureWaitsRatherThanRetryingInstantly() {
        assertEquals(0L, IdentityLifecycle.backoffSeconds(0))
        assertEquals(30L, IdentityLifecycle.backoffSeconds(1))
    }

    @Test
    fun backoffGrowsButIsCapped() {
        assertEquals(60L, IdentityLifecycle.backoffSeconds(2))
        assertEquals(120L, IdentityLifecycle.backoffSeconds(3))
        assertEquals(3600L, IdentityLifecycle.backoffSeconds(12))
    }

    @Test
    fun aDeviceFailingForAWeekStillTriesHourly() {
        // The ceiling matters more than the growth. The usual reason renewal
        // fails is no network; the moment there is one, the device must not be
        // sitting in a day-long backoff.
        assertEquals(3600L, IdentityLifecycle.backoffSeconds(1000))
    }
}
