package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit test for SystemUpdatePolicy (muster#191).
 *
 * Acceptance criteria:
 * A unit test proves the agent sets the automatic-install policy when it is
 * Device Owner, and sets nothing (and logs why) when it is not.
 */
class SystemUpdatePolicyTest {

    private class FakeTarget : SystemUpdatePolicy.Target {
        var automaticSet = false
        var windowedSet: Pair<Int, Int>? = null

        override fun setAutomaticInstallPolicy(): Boolean {
            automaticSet = true
            return true
        }

        override fun setWindowedInstallPolicy(startMinute: Int, endMinute: Int): Boolean {
            windowedSet = startMinute to endMinute
            return true
        }
    }

    @Test
    fun setsAutomaticInstallPolicyWhenDeviceOwner() {
        val target = FakeTarget()
        val logs = mutableListOf<String>()

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = true,
            target = target,
            log = { logs += it },
        )

        assertTrue(plan is SystemUpdatePolicy.Plan.ApplyAutomatic)
        assertTrue(target.automaticSet)
        assertEquals(listOf("applied automatic install policy"), logs)
    }

    @Test
    fun setsNothingAndLogsWhyWhenNotDeviceOwner() {
        val target = FakeTarget()
        val logs = mutableListOf<String>()

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = false,
            target = target,
            log = { logs += it },
        )

        assertTrue(plan is SystemUpdatePolicy.Plan.Skip)
        assertFalse(target.automaticSet)
        assertEquals(
            listOf("agent does not hold Device Owner; system update policy requires Device Owner"),
            logs,
        )
    }

    @Test
    fun setsWindowedPolicyWhenWindowConfigured() {
        val target = FakeTarget()
        val logs = mutableListOf<String>()

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = true,
            target = target,
            window = SystemUpdatePolicy.Window(120, 300),
            log = { logs += it },
        )

        assertTrue(plan is SystemUpdatePolicy.Plan.ApplyWindowed)
        assertFalse(target.automaticSet)
        assertEquals(120 to 300, target.windowedSet)
        assertEquals(listOf("applied windowed install policy (120-300)"), logs)
    }
}
