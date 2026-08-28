package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a device is asked to enforce, and what it is protected from being asked.
 *
 * The two that matter most are `aTypoIsRefusedRatherThanSkipped` - a silently
 * ignored line leaves a phone unrestricted with a config file on it that reads
 * as though it is not - and `aRestrictionRemovedFromTheConfigIsCleared`, which
 * is what stops policy being a ratchet whose only reverse gear is a wipe.
 */
class RestrictionPolicyTest {

    private fun keys(text: String?) = RestrictionPolicy.read(text).keys

    @Test
    fun nothingConfiguredAsksForNothing() {
        assertTrue(keys(null).isEmpty())
        assertTrue(keys("").isEmpty())
        assertTrue(keys("   \n\n  ").isEmpty())
    }

    @Test
    fun aKnownNameBecomesItsPlatformKey() {
        assertEquals(setOf("no_set_wallpaper"), keys("DISALLOW_SET_WALLPAPER"))
    }

    @Test
    fun theIrregularKeyIsDeclaredRatherThanDerived() {
        // DISALLOW_APPS_CONTROL is `no_control_apps`, NOT `no_apps_control`.
        // This single entry is why the table is written out by hand: there is
        // no rule to derive these by, and a key derived wrongly is not an
        // error - the platform stores it and enforces nothing.
        assertEquals(setOf("no_control_apps"), keys("DISALLOW_APPS_CONTROL"))
    }

    @Test
    fun commentsAndBlankLinesAndSpacingAreIgnored() {
        val text = """
            # what this appliance is allowed to do
            
              DISALLOW_SET_WALLPAPER   # it is a display, not a phone
            DISALLOW_SAFE_BOOT
        """.trimIndent()
        assertEquals(setOf("no_set_wallpaper", "no_safe_boot"), keys(text))
    }

    @Test
    fun aTypoIsRefusedRatherThanSkipped() {
        // The failure being prevented: the device comes up with no restriction,
        // and the only evidence is a file that appears to ask for one.
        val desired = RestrictionPolicy.read("DISALLOW_SET_WALLPAPR")
        assertTrue(desired.keys.isEmpty())
        assertEquals(1, desired.refused.size)
        assertTrue(desired.refused.single().line.contains("WALLPAPR"))
    }

    @Test
    fun aStrandingRestrictionIsRefusedUnlessSpelledOut() {
        val desired = RestrictionPolicy.read("DISALLOW_FACTORY_RESET")
        assertTrue(desired.keys.isEmpty())
        assertTrue(desired.refused.single().why.contains(RestrictionPolicy.ACCEPT_STRANDING))
    }

    @Test
    fun aStrandingRestrictionIsAllowedWhenSpelledOut() {
        val desired = RestrictionPolicy.read("DISALLOW_FACTORY_RESET accept-stranding")
        assertEquals(setOf("no_factory_reset"), desired.keys)
        assertTrue(desired.refused.isEmpty())
    }

    @Test
    fun theDebuggingRefusalNamesWhatItWouldCost() {
        // Not generic caution: adb is the ONLY route to the 80% charge cap,
        // which no Device Owner can set by policy at any API level.
        val why = RestrictionPolicy.read("DISALLOW_DEBUGGING_FEATURES").refused.single().why
        assertTrue(why.contains("adb"))
        assertTrue(why.contains("charge cap"))
    }

    // ---- planning --------------------------------------------------------

    @Test
    fun whatIsMissingGetsAdded() {
        val plan = RestrictionPolicy.plan(
            RestrictionPolicy.read("DISALLOW_SET_WALLPAPER"),
            inForce = emptySet(),
            setByUs = emptySet(),
        )
        assertEquals(listOf("no_set_wallpaper"), plan.add)
        assertTrue(plan.clear.isEmpty())
    }

    @Test
    fun reconcilingTwiceChangesNothingTheSecondTime() {
        val plan = RestrictionPolicy.plan(
            RestrictionPolicy.read("DISALLOW_SET_WALLPAPER"),
            inForce = setOf("no_set_wallpaper"),
            setByUs = setOf("no_set_wallpaper"),
        )
        assertTrue(plan.changesNothing)
    }

    @Test
    fun aRestrictionRemovedFromTheConfigIsCleared() {
        val plan = RestrictionPolicy.plan(
            RestrictionPolicy.read(""),
            inForce = setOf("no_set_wallpaper"),
            setByUs = setOf("no_set_wallpaper"),
        )
        assertEquals(listOf("no_set_wallpaper"), plan.clear)
    }

    @Test
    fun somebodyElsesRestrictionIsLeftAlone() {
        // muster is not necessarily the only thing that ever set a restriction,
        // and a reconciler that clears what it does not recognize is one that
        // quietly undoes another admin's deliberate decision.
        val plan = RestrictionPolicy.plan(
            RestrictionPolicy.read(""),
            inForce = setOf("no_outgoing_calls"),
            setByUs = emptySet(),
        )
        assertTrue(plan.clear.isEmpty())
        assertTrue(plan.changesNothing)
    }

    @Test
    fun aStrandingRestrictionIsNeverWithdrawnAutomatically() {
        // Deliberately absent from MANAGED. Taking one of these back off is a
        // decision to make in front of the device, not a side effect of
        // someone deleting a line from a config file.
        val plan = RestrictionPolicy.plan(
            RestrictionPolicy.read(""),
            inForce = setOf("no_factory_reset"),
            setByUs = setOf("no_factory_reset"),
        )
        assertTrue(plan.clear.isEmpty())
    }

    @Test
    fun aRestrictionThatIsNoLongerInForceIsPutBack() {
        // The device says the restriction is gone; muster's own record says it
        // set one. Policy is re-asserted rather than remembered - otherwise a
        // restriction the platform declined, or one cleared out from under us,
        // reads as "already applied" on every boot from then on.
        val plan = RestrictionPolicy.plan(
            RestrictionPolicy.read("DISALLOW_SET_WALLPAPER"),
            inForce = emptySet(),
            setByUs = setOf("no_set_wallpaper"),
        )
        assertEquals(listOf("no_set_wallpaper"), plan.add)
        assertTrue(plan.clear.isEmpty())
    }

    // ---- the table itself ------------------------------------------------

    @Test
    fun noKeyIsDeclaredTwice() {
        val managed = RestrictionPolicy.MANAGED.values.toList()
        assertEquals(managed.toSet().size, managed.size)
        val stranding = RestrictionPolicy.STRANDING.values.map { it.key }.toSet()
        assertTrue(managed.toSet().intersect(stranding).isEmpty())
    }

    @Test
    fun everyKeyLooksLikeAPlatformRestrictionKey() {
        // Cheap guard against a copy-paste that leaves a constant NAME in the
        // value column. It cannot prove a key is real - only a device can do
        // that, which is why RestrictionSteward reads the restrictions back.
        val all = RestrictionPolicy.MANAGED.values +
            RestrictionPolicy.STRANDING.values.map { it.key }
        for (key in all) {
            assertTrue("$key should be lower case", key == key.lowercase())
            assertTrue("$key should start with no_", key.startsWith("no_"))
        }
    }
}
