package app.muster.agent

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The plan that decides whether a reboot file means reboot, with no Android.
 *
 * `DevicePolicyManager.reboot()` is deliberately not tested. It needs
 * hardware, so these tests prove the decision only. RebootSteward's class
 * comment says the same thing at the call site, and so does WipePolicyTest
 * beside it for the same call one severity up.
 */
class RebootPolicyTest {

    @Test
    fun anAbsentRebootFileIsNotAnInstruction() {
        val plan = RebootPolicy.plan(null)
        assertFalse(plan.reboot)
        assertTrue(plan.reason.contains("no reboot instruction"))
    }

    @Test
    fun theExactServerCommandIsAnInstruction() {
        assertTrue(RebootPolicy.plan(RebootPolicy.COMMAND).reboot)
    }

    @Test
    fun anEmptyRebootFileIsNotAnInstruction() {
        // An empty file is the shape of a partial write or a broken fetch, not
        // an instruction - same reasoning as WipePolicy's own empty-file case.
        assertFalse(RebootPolicy.plan("").reboot)
    }

    @Test
    fun aDifferentContentIsNotAnInstruction() {
        assertFalse(RebootPolicy.plan("maybe reboot\n").reboot)
    }

    @Test
    fun noInstructionIsTheQuietHealthyCaseAndNotAConcern() {
        // No file at all means the steward did exactly what it was told, so
        // this must not surface as a concern next to the real ones.
        assertTrue(RebootPolicy.plan(null).isQuietHealthy)
    }

    @Test
    fun aRebootPendingIsNotTheQuietHealthyCase() {
        assertFalse(RebootPolicy.plan(RebootPolicy.COMMAND).isQuietHealthy)
    }

    @Test
    fun anEmptyFileIsAConcernNotTheQuietHealthyCase() {
        assertFalse(RebootPolicy.plan("").isQuietHealthy)
    }

    @Test
    fun aWrongContentFileIsAConcernNotTheQuietHealthyCase() {
        assertFalse(RebootPolicy.plan("maybe reboot\n").isQuietHealthy)
    }
}
