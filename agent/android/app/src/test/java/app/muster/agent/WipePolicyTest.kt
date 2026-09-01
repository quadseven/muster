package app.muster.agent

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The plan that decides whether a wipe file means wipe, with no Android.
 *
 * `DevicePolicyManager.wipeData()` is deliberately not tested. It needs
 * hardware and cannot be run twice, so these tests prove the decision only.
 * WipeSteward's class comment says the same thing at the call site.
 */
class WipePolicyTest {

    @Test
    fun anAbsentWipeFileIsNotAnErase() {
        val plan = WipePolicy.plan(null)
        assertFalse(plan.wipe)
        assertTrue(plan.reason.contains("no wipe instruction"))
    }

    @Test
    fun theExactServerCommandIsAnErase() {
        assertTrue(WipePolicy.plan(WipePolicy.COMMAND).wipe)
    }

    @Test
    fun anEmptyWipeFileIsNotAnErase() {
        // An empty file is the shape of a partial write or a broken fetch, not
        // an instruction. Reading it as wipe would make a failed write the
        // most destructive outcome available in the agent.
        assertFalse(WipePolicy.plan("").wipe)
    }

    @Test
    fun aDifferentContentIsNotAnErase() {
        assertFalse(WipePolicy.plan("maybe wipe\n").wipe)
    }
}
