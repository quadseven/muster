package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What an appliance shows, and what it is protected from being told to hide.
 *
 * THE FOUR THAT ARE WORTH THE MOST are the ones that cost a handset when they
 * are wrong: `settingsIsNeverHidden`, `musterItselfIsNeverHidden`,
 * `theLauncherThisDeviceActuallyUsesIsNeverHidden` and
 * `theSetupWizardIsNeverHidden`. Every one of them is a device nobody can fix
 * from the sofa, and there is no way to stage any of them on real hardware
 * without wiping a phone to find out.
 *
 * `aPackageAddedBackToTheAllowlistIsUnhidden` is the fifth. Without it the
 * policy is a ratchet, and the only reverse gear on a ratchet a Device Owner is
 * holding is a factory reset.
 */
class AppVisibilityPolicyTest {

    /** One plausible Pixel, as the DEVICE would report it: things with icons. */
    private val onThePhone = setOf(
        "app.muster.agent",
        "app.zippie.companion",
        "com.android.settings",
        "com.android.vending",
        "com.google.android.gm",
        "com.google.android.apps.photos",
    )

    /** What that same Pixel answers when it is asked who does what. */
    private val pixel = AppVisibilityPolicy.Resolved(
        own = "app.muster.agent",
        home = setOf("com.google.android.apps.nexuslauncher"),
        settings = setOf("com.android.settings"),
        setupWizard = setOf("com.google.android.setupwizard"),
    )

    private fun plan(
        text: String?,
        installed: Set<String> = onThePhone,
        hidden: Set<String> = emptySet(),
        resolved: AppVisibilityPolicy.Resolved = pixel,
    ) = AppVisibilityPolicy.plan(
        AppVisibilityPolicy.read(text),
        installed = installed,
        hidden = hidden,
        resolved = resolved,
    )

    // ---- reading the file ------------------------------------------------

    @Test
    fun nothingConfiguredNamesNothing() {
        assertTrue(AppVisibilityPolicy.read(null).visible.isEmpty())
        assertTrue(AppVisibilityPolicy.read("").visible.isEmpty())
        assertTrue(AppVisibilityPolicy.read("   \n\n  ").visible.isEmpty())
    }

    @Test
    fun aPackageNameIsAPackageToKeep() {
        assertEquals(
            setOf("app.zippie.companion"),
            AppVisibilityPolicy.read("app.zippie.companion").visible,
        )
    }

    @Test
    fun commentsAndBlankLinesAndSpacingAreIgnored() {
        val text = """
            # kitchen display - it is an appliance, not a phone

              app.muster.agent   # the status screen
            com.android.settings
        """.trimIndent()
        assertEquals(
            setOf("app.muster.agent", "com.android.settings"),
            AppVisibilityPolicy.read(text).visible,
        )
    }

    @Test
    fun aLineThatIsNotAPackageNameIsRefusedRatherThanSkipped() {
        // The failure being prevented is sharper here than it is for a
        // restriction: a silently dropped line in an allowlist does not leave a
        // device unpoliced, it HIDES the application somebody wrote down.
        val desired = AppVisibilityPolicy.read("Play Store")
        assertTrue(desired.visible.isEmpty())
        assertEquals(1, desired.refused.size)
        assertTrue(desired.refused.single().line.contains("Play Store"))
    }

    @Test
    fun oneBareWordIsNotAPackageName() {
        assertTrue(AppVisibilityPolicy.read("settings").visible.isEmpty())
        assertTrue(AppVisibilityPolicy.read("settings").refused.isNotEmpty())
    }

    // ---- the four that strand a phone ------------------------------------

    @Test
    fun settingsIsNeverHidden() {
        // An allowlist that names one app and forgets Settings is the ordinary
        // way somebody writes this file. It must not be the way somebody loses
        // a handset.
        val plan = plan("app.zippie.companion")
        assertFalse("com.android.settings" in plan.hide)
    }

    @Test
    fun theSettingsRefusalNamesWhatItWouldCost() {
        val kept = plan("app.zippie.companion").keptVisible
            .single { it.packageName == "com.android.settings" }
        assertTrue(kept.why.contains("adb"))
        assertTrue(kept.why.contains("Settings"))
    }

    @Test
    fun aProtectedPackageTheAllowlistNamesIsNotWarnedAbout() {
        // keptVisible is muster overriding the file. A package the operator
        // wrote down is not an override, and warning about it every boot would
        // bury the ones that are.
        val plan = plan("app.muster.agent\ncom.android.settings\n")
        assertTrue(plan.keptVisible.isEmpty())
    }

    @Test
    fun musterItselfIsNeverHidden() {
        // The status screen is how anybody finds out what the device thinks it
        // is. An agent with no icon cannot be opened to be told otherwise.
        val plan = plan("app.zippie.companion")
        assertFalse("app.muster.agent" in plan.hide)
        assertTrue(plan.keptVisible.any { it.packageName == "app.muster.agent" })
    }

    @Test
    fun theLauncherThisDeviceActuallyUsesIsNeverHidden() {
        // Resolved from the device rather than matched against a table: this
        // launcher is one nothing in NEVER_HIDDEN has ever heard of.
        val strange = pixel.copy(home = setOf("com.oem.someones.own.launcher"))
        val plan = plan(
            "app.zippie.companion",
            installed = onThePhone + "com.oem.someones.own.launcher",
            resolved = strange,
        )
        assertFalse("com.oem.someones.own.launcher" in plan.hide)
        assertTrue(
            AppVisibilityPolicy.loadBearing(strange)
                .getValue("com.oem.someones.own.launcher")
                .contains("home"),
        )
    }

    @Test
    fun theSetupWizardIsNeverHidden() {
        // The one whose loss a factory reset does not fix, because a factory
        // reset is what comes back to it.
        val wizard = "com.google.android.setupwizard"
        val plan = plan("app.zippie.companion", installed = onThePhone + wizard)
        assertFalse(wizard in plan.hide)
        val why = plan.keptVisible.single { it.packageName == wizard }.why
        assertTrue(why.contains("factory reset"))
    }

    @Test
    fun aLoadBearingPackageIsProtectedWhenTheDeviceNamedNoSettings() {
        // The SETTINGS query comes back empty on a device where an OEM moved
        // the action. The declared table is what is left when that happens, so
        // it has to hold on its own. The home screen still resolves here, or
        // hiding would be withheld and the test would prove nothing.
        val noSettings = pixel.copy(settings = emptySet(), setupWizard = emptySet())
        val plan = plan("app.zippie.companion", resolved = noSettings)
        assertTrue("hiding should still be running", plan.hide.isNotEmpty())
        assertFalse("com.android.settings" in plan.hide)
    }

    @Test
    fun everyProtectedNameSurvivesBeingOnThePhone() {
        // One test over the whole table rather than four over four names. The
        // failure it guards is an edit to the `keep` union that leaves the four
        // hand-written cases green because they happen to resolve as well.
        for (packageName in AppVisibilityPolicy.NEVER_HIDDEN.keys) {
            val plan = plan("app.zippie.companion", installed = onThePhone + packageName)
            assertFalse("$packageName was hidden", packageName in plan.hide)
        }
    }

    @Test
    fun aBlankOwnPackageNameProtectsNothingByThatName() {
        // Resolved.own comes from context.packageName, which cannot be blank on
        // a real device - but a blank string in a keep-set would protect a
        // package called "" and read as though muster were protected.
        val nameless = pixel.copy(own = "")
        assertFalse("" in AppVisibilityPolicy.loadBearing(nameless).keys)
    }

    @Test
    fun everyProtectedPackageSaysWhatHidingItWouldCost() {
        for ((packageName, why) in AppVisibilityPolicy.loadBearing(pixel)) {
            assertTrue("$packageName has no reason", why.isNotBlank())
            // A reason that is only a name is not a reason. These get logged at
            // boot and are the only thing an operator has to argue with.
            assertTrue("$packageName reads as a label, not a cost", why.length > 40)
        }
    }

    // ---- the allowlist doing its job -------------------------------------

    @Test
    fun everythingNotNamedIsHidden() {
        val plan = plan(
            """
                app.muster.agent
                app.zippie.companion
                com.android.settings
            """.trimIndent()
        )
        assertEquals(
            listOf(
                "com.android.vending",
                "com.google.android.apps.photos",
                "com.google.android.gm",
            ),
            plan.hide,
        )
        assertTrue(plan.unhide.isEmpty())
    }

    @Test
    fun anEmptyAllowlistStillLeavesADeviceSomebodyCanFix() {
        // An empty file is a real instruction - "nothing stays" - and it must
        // still not be a way to lose the handset.
        val plan = plan("")
        assertFalse("com.android.settings" in plan.hide)
        assertFalse("app.muster.agent" in plan.hide)
        assertEquals(
            listOf(
                "app.zippie.companion",
                "com.android.vending",
                "com.google.android.apps.photos",
                "com.google.android.gm",
            ),
            plan.hide,
        )
    }

    @Test
    fun nothingIsHiddenThatTheDeviceDidNotReport() {
        // The plan can only ever name packages the device said it has. Hiding a
        // package by name out of a table is how an MDM acts on a handset it is
        // imagining rather than the one in front of it.
        val plan = plan("app.muster.agent")
        assertTrue(plan.hide.all { it in onThePhone })
        assertTrue(plan.unhide.all { it in onThePhone })
    }

    @Test
    fun reconcilingTwiceChangesNothingTheSecondTime() {
        val file = "app.muster.agent\ncom.android.settings\n"
        val first = plan(file)
        // What the device would look like afterwards. A hidden package is still
        // reported as installed - the steward asks with
        // MATCH_UNINSTALLED_PACKAGES precisely so that stays true.
        val second = plan(file, hidden = first.hide.toSet())
        assertTrue(second.changesNothing)
    }

    @Test
    fun aPackageRemovedFromTheAllowlistIsHidden() {
        val plan = plan(
            "app.muster.agent\ncom.android.settings\n",
            hidden = setOf("com.android.vending"),
        )
        assertTrue("app.zippie.companion" in plan.hide)
        // And the one already hidden is not asked for a second time.
        assertFalse("com.android.vending" in plan.hide)
    }

    @Test
    fun aPackageAddedBackToTheAllowlistIsUnhidden() {
        // Without this the policy is a ratchet whose reverse gear is a wipe.
        val plan = plan(
            "app.muster.agent\napp.zippie.companion\ncom.android.settings\n",
            hidden = setOf("app.zippie.companion", "com.google.android.gm"),
        )
        assertEquals(listOf("app.zippie.companion"), plan.unhide)
        assertFalse("com.google.android.gm" in plan.unhide)
    }

    @Test
    fun aLoadBearingPackageFoundHiddenIsPutBack() {
        // Somebody ran `pm hide com.android.settings`, or an older allowlist
        // did it before this rule existed. Either way the device walks itself
        // back at the next boot, which is the only recovery an appliance in a
        // cupboard is ever going to get.
        val plan = plan("app.zippie.companion", hidden = setOf("com.android.settings"))
        assertEquals(listOf("com.android.settings"), plan.unhide)
    }

    @Test
    fun aNameThatIsNotOnTheDeviceIsRefusedRatherThanIgnored() {
        // A typo in an allowlist does not leave an application visible by
        // accident - it hides it. `app.zippie.compainon` reads exactly like a
        // policy that is working.
        val plan = plan("app.muster.agent\napp.zippie.compainon\n")
        assertTrue(plan.refused.any { it.line == "app.zippie.compainon" })
        // And nothing is hidden while the file still reads that way.
        assertTrue(plan.hide.isEmpty())
        assertTrue("app.zippie.companion" in plan.withheld)
    }

    @Test
    fun bothKindsOfRefusalArriveTogether() {
        // A malformed line and a name that is not on the device are found in
        // different places - one while reading, one while planning - and the
        // steward logs a single list.
        val plan = plan("Play Store\napp.zippie.compainon\napp.muster.agent\n")
        assertEquals(
            setOf("Play Store", "app.zippie.compainon"),
            plan.refused.map { it.line }.toSet(),
        )
    }

    // ---- a file muster could not read in full ----------------------------

    @Test
    fun nothingIsHiddenOffAFileWithALineThatWouldNotParse() {
        // THE ONE THAT COSTS A HANDSET. `adb shell pm list packages >
        // visible-apps` is the obvious way to build this file and every line of
        // its output begins `package:`, which is not a package name. Read
        // line-by-line that file is an allowlist naming NOTHING, which is the
        // strongest instruction this format carries - strip the launcher. An
        // allowlist muster could not read in full is one it must not act on.
        val fromPmList = onThePhone.joinToString("\n") { "package:$it" }
        val plan = plan(fromPmList)

        assertTrue(plan.hide.isEmpty())
        assertEquals(onThePhone.size, plan.refused.size)
        assertTrue(plan.withheldWhy.isNotEmpty())
        // And it says what it would have done, so the log is not just silence.
        assertTrue("app.zippie.companion" in plan.withheld)
    }

    @Test
    fun theWithholdingSaysWhatItWouldHaveCost() {
        val why = plan("Play Store").withheldWhy.single()
        assertTrue(why.contains("hides"))
        assertTrue(why.contains("could not be acted on"))
    }

    @Test
    fun unhidingStillRunsOffAFileThatCouldNotBeRead() {
        // Withholding is one-directional on purpose. Hiding takes something
        // away and can strand a phone; unhiding gives it back and cannot, so a
        // device that is already stranded is not left there by a typo made
        // while trying to un-strand it.
        val plan = plan(
            "Play Store\ncom.android.settings\n",
            hidden = setOf("com.android.settings"),
        )
        assertTrue(plan.hide.isEmpty())
        assertEquals(listOf("com.android.settings"), plan.unhide)
    }

    @Test
    fun nothingIsHiddenWhenTheDeviceNamedNoHomeScreen() {
        // Every Android device has a home app. An empty answer means package
        // visibility is not working or the manifest's queries element does not
        // match what this handset declares - and it arrives as an ABSENCE,
        // which is the one thing nobody spots in a log.
        val blind = AppVisibilityPolicy.Resolved(own = "app.muster.agent")
        val plan = plan("app.muster.agent\ncom.android.settings\n", resolved = blind)

        assertTrue(plan.hide.isEmpty())
        assertTrue(plan.withheld.isNotEmpty())
        assertTrue(plan.withheldWhy.single().contains("no home screen"))
    }

    @Test
    fun aFileOfNothingButCommentsStillMeansNothingStaysVisible() {
        // Deliberate, and pinned because it is a surprise: commenting every
        // line out is NOT how you turn this policy off. It reads as an
        // allowlist naming nothing, exactly like an empty file. Deleting the
        // file is how you turn it off - `policy.md` says so.
        val plan = plan("# turning this off for now\n# app.zippie.companion\n")
        assertTrue(plan.refused.isEmpty())
        assertTrue("app.zippie.companion" in plan.hide)
        assertFalse("com.android.settings" in plan.hide)
    }

    @Test
    fun theSameNameTwiceIsTheSameAsOnce() {
        val plan = plan("app.zippie.companion\napp.zippie.companion\n")
        assertTrue(plan.refused.isEmpty())
        assertFalse("app.zippie.companion" in plan.hide)
    }

    @Test
    fun aPackageIsNeverBothHiddenAndUnhidden() {
        val plan = plan("app.muster.agent", hidden = setOf("com.google.android.gm"))
        assertTrue(plan.hide.intersect(plan.unhide.toSet()).isEmpty())
    }

    @Test
    fun nothingConfiguredAndNothingHiddenChangesNothing() {
        // The state a device is in before anybody writes the file. Reading it
        // as "no file" is the steward's job; if the file IS there and empty
        // that is a different instruction, tested above.
        val plan = plan(onThePhone.joinToString("\n"))
        assertTrue(plan.changesNothing)
    }

    // ---- the table itself ------------------------------------------------

    @Test
    fun everyProtectedNameLooksLikeAPackageName() {
        // Cheap guard against a label landing in the key column. It cannot
        // prove a package exists - only a device can do that, which is why the
        // steward reads back from the platform and why the launcher and
        // Settings are resolved rather than matched.
        for (packageName in AppVisibilityPolicy.NEVER_HIDDEN.keys) {
            assertTrue("$packageName has no dot in it", packageName.contains('.'))
            assertEquals(packageName.lowercase(), packageName)
            assertFalse("$packageName has a space in it", packageName.contains(' '))
        }
    }

    @Test
    fun theThingsThisPolicyExistsToHideAreNotProtected() {
        // The Play Store is the headline item on the issue. A well-meant entry
        // for it, or for Play services, would make this whole object a no-op on
        // the only app anybody complains about.
        assertFalse("com.android.vending" in AppVisibilityPolicy.NEVER_HIDDEN)
        assertFalse("com.google.android.gms" in AppVisibilityPolicy.NEVER_HIDDEN)
    }

    @Test
    fun noProtectedNameIsDeclaredTwice() {
        val names = AppVisibilityPolicy.NEVER_HIDDEN.keys.toList()
        assertEquals(names.toSet().size, names.size)
    }
}
