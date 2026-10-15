package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * muster#146: an install that cannot succeed must stop costing a download.
 *
 * The case that motivated this, in generic form: a 19.5 MB APK signed by a
 * different key than the installed copy was fetched four times in eleven
 * minutes, failing identically each time, because nothing remembered.
 */
class InstallGateTest {

    private val now = 1_000_000L
    private val oldKey = setOf("aa".repeat(32))
    private val newKey = setOf("bb".repeat(32))

    private fun decide(
        replace: Boolean = false,
        installed: Set<String>? = oldKey,
        remembered: Set<String>? = null,
        attempts: InstallGate.Attempts? = null,
        at: Long = now,
    ) = InstallGate.decide(replace, installed, remembered, attempts, at)

    @Test
    fun bytesNobodyHasTriedAreFetched() {
        assertEquals(InstallGate.Decision.Fetch, decide())
    }

    @Test
    fun aFailedInstallWaitsBeforeTheSameBytesAreFetchedAgain() {
        val attempts = InstallGate.failed(null, now)

        val decision = decide(attempts = attempts, at = now + 60)

        assertTrue(decision is InstallGate.Decision.Wait)
        assertEquals(1, (decision as InstallGate.Decision.Wait).attempts.failures)
    }

    @Test
    fun theWaitOutlastsTheFifteenMinuteCheckIn() {
        // A first wait no longer than one check-in would be no wait at all: the
        // next periodic run would find it expired and fetch again.
        val attempts = InstallGate.failed(null, now)
        assertTrue(attempts.retryAtS - now > CheckInSchedulePolicy.INTERVAL_MS / 1000)
    }

    @Test
    fun theWaitDoublesWithEachFailureAndStopsAtADay() {
        var attempts: InstallGate.Attempts? = null
        val waits = (1..10).map {
            attempts = InstallGate.failed(attempts, now)
            attempts!!.retryAtS - now
        }

        assertEquals(waits[0] * 2, waits[1])
        assertEquals(waits[1] * 2, waits[2])
        assertEquals(InstallGate.MAX_BACKOFF_S, waits.last())
        assertEquals(10, attempts!!.failures)
    }

    @Test
    fun onceTheWaitIsOverTheBytesAreFetchedAgain() {
        val attempts = InstallGate.failed(null, now)
        assertEquals(InstallGate.Decision.Fetch, decide(attempts = attempts, at = attempts.retryAtS))
    }

    @Test
    fun aSignerKnownToDifferIsRefusedBeforeDownloading() {
        val decision = decide(installed = oldKey, remembered = newKey)

        assertTrue(decision is InstallGate.Decision.Incompatible)
    }

    @Test
    fun theRefusalIsNotRetriedOnABackoffClock() {
        // Not transient: no number of retries makes a different key acceptable,
        // so an expired wait must not turn this back into a download.
        val attempts = InstallGate.failed(null, now)
        val decision = decide(
            installed = oldKey, remembered = newKey,
            attempts = attempts, at = attempts.retryAtS + 1,
        )
        assertTrue(decision is InstallGate.Decision.Incompatible)
    }

    @Test
    fun theRefusalNamesTheReasonAndroidWouldGive() {
        val line = InstallGate.incompatible("app.example.companion", "companion-152.apk")

        assertTrue(line, line.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE"))
        assertTrue(line, line.startsWith("app.example.companion: "))
        assertTrue(line, line.contains("companion-152.apk"))
    }

    @Test
    fun aRotatedKeyWhoseLineageIncludesTheInstalledSignerIsNotRefused() {
        // v3 rotation: the new APK is signed by the new key and carries a
        // lineage back to the old one, and Android installs it in place.
        val lineage = oldKey + newKey
        assertEquals(InstallGate.Decision.Fetch, decide(installed = oldKey, remembered = lineage))
        assertEquals(true, InstallGate.compatible(oldKey, lineage))
    }

    @Test
    fun withTheReplaceFlagTheMismatchIsLeftForTheStewardToResolve() {
        assertEquals(
            InstallGate.Decision.Fetch,
            decide(replace = true, installed = oldKey, remembered = newKey),
        )
    }

    @Test
    fun anUnreadableSignerIsNotADifference() {
        assertNull(InstallGate.compatible(emptySet(), newKey))
        assertNull(InstallGate.compatible(oldKey, emptySet()))
        assertEquals(InstallGate.Decision.Fetch, decide(installed = emptySet(), remembered = newKey))
    }

    @Test
    fun nothingInstalledCannotBeIncompatible() {
        assertEquals(InstallGate.Decision.Fetch, decide(installed = null, remembered = newKey))
    }

    @Test
    fun theWaitSaysWhenTheNextAttemptIs() {
        val attempts = InstallGate.failed(InstallGate.failed(null, now), now)
        val line = InstallGate.waiting("app.example.companion", attempts, now)

        assertTrue(line, line.startsWith("app.example.companion: "))
        assertTrue(line, line.contains("failed 2 times"))
        assertTrue(line, line.contains("next attempt in 60m"))
    }

    @Test
    fun attemptsSurviveBeingWrittenDownAndReadBack() {
        val attempts = InstallGate.Attempts(failures = 3, retryAtS = 42L)
        assertEquals(attempts, InstallGate.readAttempts(InstallGate.write(attempts)))
    }

    @Test
    fun aDamagedAttemptsRecordReadsAsNoneRatherThanAsAFailure() {
        assertNull(InstallGate.readAttempts(null))
        assertNull(InstallGate.readAttempts("garbage"))
        assertNull(InstallGate.readAttempts("x:1"))
    }

    @Test
    fun signersSurviveBeingWrittenDownAndReadBack() {
        val lineage = oldKey + newKey
        assertEquals(lineage, InstallGate.readSigners(InstallGate.writeSigners(lineage)))
        assertNull(InstallGate.readSigners(null))
        assertNull(InstallGate.readSigners(""))
    }
}
