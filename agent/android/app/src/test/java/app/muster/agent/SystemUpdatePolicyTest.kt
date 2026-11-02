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

    private class FakeTarget(
        private val result: SystemUpdatePolicy.Result = SystemUpdatePolicy.Result.Applied,
    ) : SystemUpdatePolicy.Target {
        var automaticSet = false
        var windowedSet: Pair<Int, Int>? = null

        override fun setAutomaticInstallPolicy(): SystemUpdatePolicy.Result {
            automaticSet = true
            return result
        }

        override fun setWindowedInstallPolicy(startMinute: Int, endMinute: Int): SystemUpdatePolicy.Result {
            windowedSet = startMinute to endMinute
            return result
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

    @Test
    fun aRefusedPolicyComesBackAsFailedNamingWhy() {
        val reason = "could not set automatic system update policy: SecurityException: not owner"
        val target = FakeTarget(SystemUpdatePolicy.Result.Refused(reason))
        val logs = mutableListOf<String>()

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = true,
            target = target,
            log = { logs += it },
        )

        assertTrue(target.automaticSet)
        assertEquals(SystemUpdatePolicy.Plan.Failed(reason), plan)
        assertEquals(listOf(reason), logs)
    }

    @Test
    fun aRefusedWindowedPolicyComesBackAsFailed() {
        val reason = "could not set windowed system update policy: IllegalArgumentException: bad window"
        val target = FakeTarget(SystemUpdatePolicy.Result.Refused(reason))

        val plan = SystemUpdatePolicy.apply(
            isDeviceOwner = true,
            target = target,
            window = SystemUpdatePolicy.Window(120, 300),
        )

        assertEquals(120 to 300, target.windowedSet)
        assertEquals(SystemUpdatePolicy.Plan.Failed(reason), plan)
    }
}
