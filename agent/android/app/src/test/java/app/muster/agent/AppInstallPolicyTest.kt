package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which applications a device is told to carry, and when it acts.
 *
 * muster#67. Until this, muster hid the Play Store and then owned updates it
 * could not perform: the only route from a built APK to a handset was a wipe
 * and a QR scan, which also threw away the identity, the policy and the
 * enrolment.
 *
 * The ones that matter most are `theAgentInstallsItselfLAST` - installing
 * itself kills the process, so anything queued behind it never runs - and
 * `aDeviceAlreadyCarryingTheVersionDoesNothing`, which is what stops a phone
 * reinstalling a 12.7 MB APK on every boot.
 */
class AppInstallPolicyTest {

    private val digestA = "a".repeat(64)
    private val digestB = "b".repeat(64)

    private fun line(pkg: String, asset: String, digest: String, version: Long) =
        "install $pkg $asset sha256 $digest version $version"

    // ---- reading ----------------------------------------------------------

    @Test
    fun nothingConfiguredAsksForNothing() {
        assertTrue(AppInstallPolicy.read(null).wanted.isEmpty())
        assertTrue(AppInstallPolicy.read("").wanted.isEmpty())
        assertTrue(AppInstallPolicy.read("# just a comment\n\n").wanted.isEmpty())
    }

    @Test
    fun anInstallLineNamesAPackageAnAssetADigestAndAVersion() {
        val read = AppInstallPolicy.read(line("app.zippie.companion", "z.apk", digestA, 72))
        assertEquals(1, read.wanted.size)
        val w = read.wanted[0]
        assertEquals("app.zippie.companion", w.packageName)
        assertEquals("z.apk", w.asset)
        assertEquals(digestA, w.digest)
        assertEquals(72L, w.versionCode)
        assertTrue(read.refused.isEmpty())
    }

    @Test
    fun aLineWithoutADigestIsRefusedRatherThanTrusted() {
        // AN AGENT THAT INSTALLS UNVERIFIED BYTES HANDED TO IT OVER THE NETWORK
        // IS WORSE THAN ONE THAT CANNOT INSTALL AT ALL. This is the line that
        // makes that true, so it is not optional-with-a-warning.
        val read = AppInstallPolicy.read("install app.zippie.companion z.apk version 72")
        assertTrue(read.wanted.isEmpty())
        assertEquals(1, read.refused.size)
    }

    @Test
    fun aDigestThatIsNotOneIsRefused() {
        assertEquals(1, AppInstallPolicy.read(line("a.b", "z.apk", "nothex", 1)).refused.size)
        assertEquals(
            1,
            AppInstallPolicy.read(line("a.b", "z.apk", "A".repeat(64), 1)).refused.size,
        )
    }

    @Test
    fun anAssetNameThatCouldWalkOutOfTheStoreIsRefused() {
        assertEquals(1, AppInstallPolicy.read(line("a.b", "../../etc/passwd", digestA, 1)).refused.size)
        assertEquals(1, AppInstallPolicy.read(line("a.b", "a/b.apk", digestA, 1)).refused.size)
    }

    @Test
    fun aVersionThatIsNotANumberIsRefused() {
        val read = AppInstallPolicy.read("install a.b z.apk sha256 $digestA version soon")
        assertTrue(read.wanted.isEmpty())
        assertEquals(1, read.refused.size)
    }

    @Test
    fun aTypoIsRefusedRatherThanSkipped() {
        val read = AppInstallPolicy.read("instal a.b z.apk sha256 $digestA version 1")
        assertEquals(1, read.refused.size)
        assertTrue(read.refused[0].why, read.refused[0].line.contains("instal"))
    }

    @Test
    fun aRefusedLineDoesNotStopTHEOTHERSFromBeingInstalled() {
        // DELIBERATELY DIFFERENT FROM AppVisibilityPolicy, where one bad line
        // withholds the whole plan. Hiding is destructive and a typo there
        // strips a phone; installing is ADDITIVE, and withholding every install
        // because one line is wrong denies a device the software it needs in
        // order to protect it from having extra software.
        val read = AppInstallPolicy.read(
            "instal broken line\n" + line("app.zippie.companion", "z.apk", digestA, 72)
        )
        assertEquals(1, read.refused.size)
        assertEquals(1, read.wanted.size)
    }

    @Test
    fun twoLinesForOnePackageAreRefusedRatherThanTheLastWinning() {
        val read = AppInstallPolicy.read(
            line("a.b", "one.apk", digestA, 1) + "\n" + line("a.b", "two.apk", digestB, 2)
        )
        assertEquals(1, read.wanted.size)
        assertEquals("one.apk", read.wanted[0].asset)
        assertEquals(1, read.refused.size)
    }

    // ---- planning ---------------------------------------------------------

    private fun desired(vararg w: AppInstallPolicy.Wanted) =
        AppInstallPolicy.Desired(w.toList(), emptyList())

    private fun wanted(pkg: String, version: Long, asset: String = "z.apk") =
        AppInstallPolicy.Wanted(pkg, asset, digestA, version)

    @Test
    fun anApplicationThatIsNotThereIsInstalled() {
        val plan = AppInstallPolicy.plan(desired(wanted("a.b", 1)), installed = emptyMap())
        assertEquals(listOf("a.b"), plan.install.map { it.packageName })
        assertTrue(plan.install[0].why.contains("not installed"))
    }

    @Test
    fun anOlderApplicationIsUpgraded() {
        val plan = AppInstallPolicy.plan(desired(wanted("a.b", 5)), installed = mapOf("a.b" to 3L))
        assertEquals(1, plan.install.size)
        // BOTH numbers, and asserted exactly. A looser check passed while the
        // message read "carrying 3, told $5" - a stray dollar from a `$$` that
        // Kotlin does not treat as an escape.
        assertEquals("carrying 3, told 5", plan.install[0].why)
    }

    @Test
    fun aDeviceAlreadyCarryingTheVersionDoesNothing() {
        // Without this a phone re-downloads and reinstalls a 12.7 MB APK on
        // every single boot.
        val plan = AppInstallPolicy.plan(desired(wanted("a.b", 5)), installed = mapOf("a.b" to 5L))
        assertTrue(plan.install.isEmpty())
        assertEquals(listOf("a.b"), plan.current)
    }

    @Test
    fun aNEWERApplicationIsLeftALONE() {
        // Android refuses a downgrade anyway, so attempting one is a guaranteed
        // failure reported every boot. It is also what a hand-installed debug
        // build looks like, and muster stamping on that is a worse surprise
        // than leaving it.
        val plan = AppInstallPolicy.plan(desired(wanted("a.b", 5)), installed = mapOf("a.b" to 9L))
        assertTrue(plan.install.isEmpty())
        assertEquals(listOf("a.b"), plan.current)
    }

    @Test
    fun theAgentInstallsItselfLAST() {
        // THE ORDER IS LOAD-BEARING. Committing muster's own session kills this
        // process, so anything queued behind it never runs - a boot that
        // updated the agent would silently skip every other application, and
        // the next boot would find the agent current and skip them again.
        val plan = AppInstallPolicy.plan(
            desired(wanted(AppInstallPolicy.OWN_PACKAGE, 2), wanted("app.zippie.companion", 1)),
            installed = mapOf(AppInstallPolicy.OWN_PACKAGE to 1L),
        )
        assertEquals(
            listOf("app.zippie.companion", AppInstallPolicy.OWN_PACKAGE),
            plan.install.map { it.packageName },
        )
    }

    @Test
    fun theAgentIsStillInstalledWhenItIsTheOnlyThingNamed() {
        val plan = AppInstallPolicy.plan(
            desired(wanted(AppInstallPolicy.OWN_PACKAGE, 2)),
            installed = mapOf(AppInstallPolicy.OWN_PACKAGE to 1L),
        )
        assertEquals(listOf(AppInstallPolicy.OWN_PACKAGE), plan.install.map { it.packageName })
    }

    @Test
    fun anInstallThatFailedIsSimplyTRIEDAGAIN() {
        // muster#67's fifth criterion: "an update that fails leaves the device
        // running the agent it already had".
        //
        // THE REASON THAT IS TRUE IS THAT NOTHING HERE REMEMBERS TRYING. The
        // plan is computed from what the PLATFORM reports is installed, never
        // from what muster attempted, so a failed install is indistinguishable
        // from one that was never attempted - the device is still on its old
        // version, and the next boot plans the same install again.
        //
        // A steward that recorded "I installed this" would be the version of
        // this that breaks: a failed install would be remembered as done, and
        // the device would sit on the old build forever with nothing retrying.
        val want = wanted("a.b", 5)
        val firstBoot = AppInstallPolicy.plan(desired(want), installed = mapOf("a.b" to 3L))
        assertEquals(1, firstBoot.install.size)

        // The commit failed; the platform still reports 3.
        val secondBoot = AppInstallPolicy.plan(desired(want), installed = mapOf("a.b" to 3L))
        assertEquals(1, secondBoot.install.size)
        assertEquals(firstBoot.install[0].why, secondBoot.install[0].why)

        // And once it takes, it stops.
        val afterItWorked = AppInstallPolicy.plan(desired(want), installed = mapOf("a.b" to 5L))
        assertTrue(afterItWorked.install.isEmpty())
    }

    // ---- installing in two passes (muster#81) -----------------------------
    //
    // Proved on a handset: zippie was installed and its managed configuration
    // was NOT applied in the same check-in, because `app-config` runs before
    // `install-apps` and the package did not exist when it ran. The grant
    // failed with DID_NOT_TAKE and the app sat installed and unconfigured until
    // the next pass fifteen minutes later.
    //
    // Reordering wholesale is not the fix: `install-apps` is last precisely
    // because installing MUSTER kills the process, and anything queued behind
    // that never runs. So the step splits.

    @Test
    fun theOthersPassInstallsEverythingExceptMuster() {
        val plan = AppInstallPolicy.plan(
            desired(wanted(AppInstallPolicy.OWN_PACKAGE, 2), wanted("app.zippie.companion", 1)),
            installed = mapOf(AppInstallPolicy.OWN_PACKAGE to 1L),
            only = AppInstallPolicy.Only.OTHERS,
        )
        assertEquals(listOf("app.zippie.companion"), plan.install.map { it.packageName })
    }

    @Test
    fun theSelfPassInstallsONLYMuster() {
        val plan = AppInstallPolicy.plan(
            desired(wanted(AppInstallPolicy.OWN_PACKAGE, 2), wanted("app.zippie.companion", 1)),
            installed = mapOf(AppInstallPolicy.OWN_PACKAGE to 1L),
            only = AppInstallPolicy.Only.SELF,
        )
        assertEquals(listOf(AppInstallPolicy.OWN_PACKAGE), plan.install.map { it.packageName })
    }

    @Test
    fun theTwoPassesTogetherCoverExactlyWhatOnePassWouldHave() {
        // The split must not LOSE anything. Whatever `ALL` would install, the
        // two scoped passes install between them - no package in both, none in
        // neither.
        val d = desired(
            wanted(AppInstallPolicy.OWN_PACKAGE, 2),
            wanted("app.zippie.companion", 1),
            wanted("app.other.thing", 3),
        )
        val installed = mapOf(AppInstallPolicy.OWN_PACKAGE to 1L)
        val all = AppInstallPolicy.plan(d, installed).install.map { it.packageName }
        val others = AppInstallPolicy.plan(d, installed, AppInstallPolicy.Only.OTHERS)
            .install.map { it.packageName }
        val self = AppInstallPolicy.plan(d, installed, AppInstallPolicy.Only.SELF)
            .install.map { it.packageName }

        assertEquals(all.sorted(), (others + self).sorted())
        assertTrue("no package may be in both passes", (others intersect self.toSet()).isEmpty())
    }

    @Test
    fun aPassThatInstallsNothingStillReportsWhatIsCurrent() {
        // `current` is how the status screen says "nothing to do here" rather
        // than staying silent, and scoping must not empty it.
        val plan = AppInstallPolicy.plan(
            desired(wanted("app.zippie.companion", 1)),
            installed = mapOf("app.zippie.companion" to 1L),
            only = AppInstallPolicy.Only.OTHERS,
        )
        assertTrue(plan.install.isEmpty())
        assertEquals(listOf("app.zippie.companion"), plan.current)
    }

    @Test
    fun `the replace flag is off unless the line says so`() {
        val read = AppInstallPolicy.read(
            "install app.zippie.companion z.apk sha256 ${"a".repeat(64)} version 152"
        )
        assertEquals(1, read.wanted.size)
        assertFalse(
            "removing an app destroys its data; that must never be inferred",
            read.wanted[0].replaceIfSignerDiffers,
        )
    }

    @Test
    fun `the replace flag is read when the line says so`() {
        val read = AppInstallPolicy.read(
            "install app.zippie.companion z.apk sha256 ${"a".repeat(64)} version 152 " +
                "replace-if-signer-differs"
        )
        assertEquals(1, read.wanted.size)
        assertTrue(read.wanted[0].replaceIfSignerDiffers)
    }

    @Test
    fun `a misspelled replace flag is refused, not ignored`() {
        // NOT READ AS ABSENCE. A typo in the flag that authorizes DELETING AN
        // APP'S DATA would otherwise silently withhold the only thing the line
        // was added to do, and the operator would see an install that keeps
        // failing with nothing saying why.
        val read = AppInstallPolicy.read(
            "install app.zippie.companion z.apk sha256 ${"a".repeat(64)} version 152 " +
                "replace-if-signer-differ"
        )
        assertTrue("the line must not install", read.wanted.isEmpty())
        assertEquals(1, read.refused.size)
        assertTrue(
            "the refusal should name the flag, got: ${read.refused[0].why}",
            read.refused[0].why.contains("replace-if-signer-differs"),
        )
    }

    @Test
    fun `a ninth word is still refused`() {
        val read = AppInstallPolicy.read(
            "install app.zippie.companion z.apk sha256 ${"a".repeat(64)} version 152 " +
                "replace-if-signer-differs extra"
        )
        assertTrue(read.wanted.isEmpty())
        assertEquals(1, read.refused.size)
    }

    @Test
    fun `the replace flag is refused on muster itself`() {
        // UNRECOVERABLE, NOT MERELY BAD. Uninstalling muster removes Device
        // Owner, and Device Owner cannot be re-established on a provisioned
        // device - it takes a factory reset, which destroys every other
        // application's data on the way. A line that told muster to replace
        // itself this way would unmanage the handset permanently.
        val read = AppInstallPolicy.read(
            "install app.muster.agent muster.apk sha256 ${"a".repeat(64)} version 81 " +
                "replace-if-signer-differs"
        )
        assertTrue("muster must not install itself this way", read.wanted.isEmpty())
        assertEquals(1, read.refused.size)
        assertTrue(
            "the refusal must say why, got: ${read.refused[0].why}",
            read.refused[0].why.contains("Device Owner"),
        )
    }

    @Test
    fun `muster's own line is still accepted without the flag`() {
        val read = AppInstallPolicy.read(
            "install app.muster.agent muster.apk sha256 ${"a".repeat(64)} version 81"
        )
        assertEquals(1, read.wanted.size)
        assertEquals("app.muster.agent", read.wanted[0].packageName)
    }
}
