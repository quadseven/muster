package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The wipe step as the check-in report counts it (muster#161).
 *
 * A handset with no wipe instruction is healthy and must not add to the "N of
 * M steps need attention" count, while a wipe that is pending but blocked must
 * still say so.
 */
class WipeStewardOutcomeTest {

    private fun outcome(file: String?, kept: String? = null) =
        WipeSteward.Outcome(plan = WipePolicy.plan(file), kept = kept)

    @Test
    fun noWipeInstructionIsNotAConcern() {
        val healthy = outcome(null, kept = WipePolicy.plan(null).reason)
        assertTrue(healthy.concerns().isEmpty())
    }

    @Test
    fun aHealthyWipeStepDoesNotInflateTheStepCount() {
        val apps = object : StepOutcome {
            override fun concerns() = listOf("app did not take")
        }
        val view = SyncReport.of(
            listOf(
                SyncReport.Step("wipe", outcome(null, kept = "no wipe instruction")),
                SyncReport.Step("apps", apps),
            ),
        )
        assertEquals("Checked in. 1 of 2 steps need attention.", view.headline)
    }

    @Test
    fun aBlockedWipeIsStillAConcern() {
        val reason = "this app is not Device Owner; refusing to call wipeData"
        assertEquals(listOf(reason), outcome(WipePolicy.COMMAND, kept = reason).concerns())
    }

    @Test
    fun anEmptyWipeFileIsStillAConcern() {
        val reason = WipePolicy.plan("").reason
        assertEquals(listOf(reason), outcome("", kept = reason).concerns())
    }
}
