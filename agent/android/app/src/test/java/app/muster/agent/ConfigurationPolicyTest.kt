package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a device does with a configuration muster served it.
 *
 * Three carry the design. [nothingButARealConfigurationIsEverActedOn] is the
 * one that keeps a device's policy when muster is unreachable, which is
 * CONTEXT.md's second rule. [aFileMusterDoesNotManageIsNeverWritten] is what
 * stops this being a remote write primitive over the agent's own storage. And
 * [aFileTheServerNoLongerServesComesOffTheDevice] is what makes it a reconciler
 * rather than a ratchet.
 *
 * WHAT IS NOT COVERED HERE, stated so it is not mistaken for more than it is:
 * `ConfigurationSteward` does the file IO - the atomic write, the delete, the
 * keystore signature - and has no tests, because it needs a device. It calls
 * [ConfigurationPolicy.instruction] rather than deciding for itself, so the
 * decision is testable even though the doing is not.
 */
class ConfigurationPolicyTest {

    private val empty = ConfigurationPolicy.MANAGED.associateWith { null as String? }

    @Test
    fun nothingButARealConfigurationIsEverActedOn() {
        // THE SINGLE MOST DESTRUCTIVE DECISION IN THIS FEATURE. `plan` removes
        // every managed file a configuration does not mention, so handing it
        // anything other than a real answer from muster wipes the device - and
        // "muster is unreachable" is the ordinary state of a phone on hotel
        // wifi, not an edge case. CONTEXT.md's second rule is that operation
        // must not need the internet.
        //
        // Enumerated one by one rather than in a loop, so adding an outcome to
        // Fetched and forgetting it here is a test that does not compile rather
        // than a case nobody wrote.
        assertNull(ConfigurationPolicy.instruction(ConfigurationClient.Fetched.NotEnrolled))
        assertNull(ConfigurationPolicy.instruction(ConfigurationClient.Fetched.Unrecognized))
        assertNull(ConfigurationPolicy.instruction(ConfigurationClient.Fetched.Revoked))
        assertNull(
            ConfigurationPolicy.instruction(ConfigurationClient.Fetched.Unreachable("dns"))
        )
        assertNull(
            ConfigurationPolicy.instruction(ConfigurationClient.Fetched.Refused(503, "down"))
        )
        assertNull(
            ConfigurationPolicy.instruction(
                ConfigurationClient.Fetched.DeviceCannotAsk("keystore")
            )
        )
    }

    @Test
    fun aRealConfigurationIsActedOn() {
        // The other half. A guard that refused everything would be a device
        // that can never be configured, which passes the test above.
        val answer = ConfigurationClient.Fetched.Configuration(
            revision = "r1",
            files = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
        )
        assertEquals(answer, ConfigurationPolicy.instruction(answer))
    }

    @Test
    fun aFileMusterDoesNotManageIsNeverWritten() {
        // THE ONE THAT MATTERS MOST. `server-url` decides which control plane
        // this device answers to, and a control plane that can rewrite it is
        // one that can hand the device to somebody else. The set is closed on
        // the server too; this is the half a mistaken server cannot talk past.
        val plan = ConfigurationPolicy.plan(
            served = mapOf(
                "server-url" to "https://elsewhere.example",
                "../../../data/local/tmp/x" to "anything",
                "restrictions" to "DISALLOW_SAFE_BOOT\n",
            ),
            onDevice = empty,
        )

        assertEquals(listOf("restrictions"), plan.write.keys.toList())
        assertEquals(
            listOf("../../../data/local/tmp/x", "server-url"),
            plan.refused.map { it.name }.sorted(),
        )
    }

    @Test
    fun aFileTheServerNoLongerServesComesOffTheDevice() {
        // Reconciling goes both ways or it is a ratchet, and the reverse gear
        // on a ratchet a Device Owner is holding is a factory reset. The
        // stewards make this safe in the direction that matters: no
        // restrictions file means "leave the device as it is", not "strip it".
        val plan = ConfigurationPolicy.plan(
            served = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
            onDevice = mapOf(
                "restrictions" to "DISALLOW_SAFE_BOOT\n",
                "visible-apps" to "app.muster.agent\n",
                "app-config" to "set app.zippie.companion homeHost 10.0.0.1\n",
            ),
        )

        assertEquals(listOf("app-config", "visible-apps"), plan.remove.sorted())
        assertEquals(listOf("restrictions"), plan.unchanged)
    }

    @Test
    fun anEmptyFileIsWrittenAndIsNotTheSameAsNoFile() {
        // The distinction the whole agent is built on: an empty restrictions
        // file withdraws everything; an absent one means nobody has configured
        // this device. Collapsing them here would make it impossible to unlock
        // a device the shared policy restricts.
        val plan = ConfigurationPolicy.plan(
            served = mapOf("restrictions" to ""),
            onDevice = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
        )

        assertEquals(mapOf("restrictions" to ""), plan.write)
        assertTrue(plan.remove.isEmpty())
    }

    @Test
    fun aFileThatIsThereButUnreadableIsReplacedRatherThanLeft() {
        // The steward reports such a file as PRESENT with no content, which is
        // why the two are separate parameters. A corrupt local file must not be
        // the thing that blocks the fetch which would fix it.
        val plan = ConfigurationPolicy.plan(
            served = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
            onDevice = mapOf("restrictions" to null),
            present = setOf("restrictions"),
        )

        assertEquals(mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"), plan.write)
        assertTrue(plan.remove.isEmpty())
    }

    @Test
    fun aFileThatIsThereAndUnreadableIsStillRemovableWhenTheServerStopsServingIt() {
        // The half a single content map cannot express: no content and no
        // longer served still has to mean "take it off the device", or a file
        // that went bad becomes one muster can never withdraw.
        val plan = ConfigurationPolicy.plan(
            served = emptyMap(),
            onDevice = mapOf("app-config" to null),
            present = setOf("app-config"),
        )

        assertEquals(listOf("app-config"), plan.remove)
    }

    @Test
    fun aFileThatHasNotChangedIsNotRewritten() {
        // Not tidiness. Rewriting means the stewards behind this reconcile from
        // scratch at every boot, and on the allowlist that is a call per
        // package on a phone that has just come up.
        val plan = ConfigurationPolicy.plan(
            served = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
            onDevice = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
        )

        assertTrue(plan.write.isEmpty())
        assertEquals(listOf("restrictions"), plan.unchanged)
        assertTrue(plan.changesNothing)
    }

    @Test
    fun aServerThatConfiguresNothingWithdrawsWhatItPreviouslySent() {
        // "muster no longer configures this device" has to be sayable, or a
        // device can only ever be un-managed with a cable - which is the thing
        // this whole path exists to stop needing.
        val plan = ConfigurationPolicy.plan(
            served = emptyMap(),
            onDevice = mapOf("restrictions" to "DISALLOW_SAFE_BOOT\n"),
        )

        assertEquals(listOf("restrictions"), plan.remove)
        assertTrue(plan.write.isEmpty())
    }

    @Test
    fun aFileTheServerDoesNotServeAndTheDeviceDoesNotHaveIsNotRemoved() {
        // Otherwise every boot logs a removal of something that was never
        // there, and the log stops being how anybody tells a real change from
        // a quiet one.
        val plan = ConfigurationPolicy.plan(served = emptyMap(), onDevice = empty)
        assertTrue(plan.remove.isEmpty())
        assertTrue(plan.changesNothing)
    }

    @Test
    fun nothingInThePlanPrintsAConfiguredValue() {
        // `app-config` carries write tokens - `announceToken` is one - and
        // BootReceiver logs the outcome of every boot step. A data class prints
        // every field, which is why Plan overrides toString.
        val plan = ConfigurationPolicy.plan(
            served = mapOf(
                "app-config" to "set app.zippie.companion announceToken zk_live_7f3a91c4e08b46d2a5\n",
                "server-url" to "https://elsewhere.example",
            ),
            onDevice = empty,
        )

        assertFalse(plan.toString().contains("zk_live_7f3a91c4e08b46d2a5"))
        assertFalse(plan.toString().contains("elsewhere.example"))
        assertTrue("the names are what a log is for", plan.toString().contains("app-config"))
    }

    @Test
    fun everyManagedNameIsOneAStewardActuallyReads() {
        // A name here that no steward reads is a file this agent downloads,
        // writes and never acts on - which looks identical to a policy that is
        // being enforced, from every angle except the device itself.
        assertEquals(
            // restrictions  -> RestrictionSteward.configFile()
            // visible-apps  -> AppVisibilitySteward.configFile()
            // app-config    -> AppConfigSteward.configFile()
            // wallpaper     -> WallpaperSteward.configFile()
            // install-apps -> AppInstallSteward.configFile(), read by BOTH the
            //                 install-apps and install-self steps (muster#81)
            setOf("restrictions", "visible-apps", "app-config", "wallpaper", "install-apps"),
            ConfigurationPolicy.MANAGED,
        )
    }

    // ---- the seam --------------------------------------------------------

    @Test
    fun writesTheManagedFileNamesForTheCrossLanguageCheck() {
        // Handed to CI, which compares it against `policy.MANAGED_FILES`. The
        // two live in different languages and neither suite can see the other,
        // and the drift is silent in BOTH directions: a name the server serves
        // and this set does not hold is refused at the device and never
        // written, while a name this set holds and the server will not serve is
        // a policy file an operator can write that never travels.
        val json = org.json.JSONArray()
        ConfigurationPolicy.MANAGED.forEach { json.put(it) }
        val out = java.io.File("build/cross-language/agent-managed-files.json")
        out.parentFile.mkdirs()
        out.writeText(json.toString())
        assertTrue(ConfigurationPolicy.MANAGED.isNotEmpty())
    }
}
