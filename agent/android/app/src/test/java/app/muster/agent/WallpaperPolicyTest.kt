package app.muster.agent

import app.muster.agent.WallpaperPolicy.Decision
import app.muster.agent.WallpaperPolicy.Surface
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which image is applied, to which screens, and when the device is left alone.
 *
 * Locking the wallpaper is not tested here because it is not decided here - see
 * RestrictionPolicyTest.
 *
 * The ones that matter most are `noImageConfiguredLeavesTheDeviceAlone` - an
 * MDM that imposes a background nobody asked for is one people uninstall -
 * `theSameImageOnTheSameScreensIsNotReapplied`, which stops a phone decoding a
 * full-resolution bitmap every boot, and
 * `aDeviceThatAppliedToOneScreenAppliesToTheOtherWhenThePolicyChanges`, which
 * is muster#41: recording a digest alone made a device believe it was done.
 */
class WallpaperPolicyTest {

    private val digestA = "a".repeat(64)
    private val digestB = "b".repeat(64)
    private val both = setOf(Surface.SYSTEM, Surface.LOCK)

    private fun desired(digest: String? = digestA, surfaces: Set<Surface> = both) =
        WallpaperPolicy.Desired(
            asset = if (digest == null) null else "wall.png",
            digest = digest,
            surfaces = surfaces,
        )

    // ---- reading the file -------------------------------------------------

    @Test
    fun nothingConfiguredAsksForNothing() {
        assertNull(WallpaperPolicy.read(null).asset)
        assertNull(WallpaperPolicy.read("").asset)
        assertNull(WallpaperPolicy.read("   \n\n # just a comment \n").asset)
    }

    @Test
    fun anImageLineNamesAnAssetAndTheDigestToExpect() {
        val read = WallpaperPolicy.read("image wall.png sha256 $digestA")
        assertEquals("wall.png", read.asset)
        assertEquals(digestA, read.digest)
        assertTrue(read.refused.isEmpty())
    }

    @Test
    fun bothScreensAreTheDefaultWhenTheFileDoesNotSay() {
        assertEquals(both, WallpaperPolicy.read("image wall.png sha256 $digestA").surfaces)
    }

    @Test
    fun whichScreensIsExpressible() {
        // muster#41: "expressible, not hardcoded".
        val read = WallpaperPolicy.read("image wall.png sha256 $digestA\nsurfaces lock")
        assertEquals(setOf(Surface.LOCK), read.surfaces)
    }

    @Test
    fun commentsAndBlankLinesAreNotLines() {
        val read = WallpaperPolicy.read(
            "# the household background\n\n  image wall.png sha256 $digestA  # why\n"
        )
        assertEquals("wall.png", read.asset)
        assertTrue(read.refused.toString(), read.refused.isEmpty())
    }

    @Test
    fun anImageWithNoDigestIsRefusedRatherThanTrusted() {
        // Applying whatever the server hands over is the one property this
        // file exists to provide, so a line without a digest cannot configure.
        val read = WallpaperPolicy.read("image wall.png")
        assertNull(read.asset)
        assertEquals(1, read.refused.size)
    }

    @Test
    fun aDigestThatIsNotOneIsRefused() {
        assertEquals(1, WallpaperPolicy.read("image wall.png sha256 nothex").refused.size)
        // Uppercase is refused too: the device compares strings, and a policy
        // that "looks right" and never matches is worse than one that refuses.
        assertEquals(1, WallpaperPolicy.read("image w.png sha256 ${"A".repeat(64)}").refused.size)
    }

    @Test
    fun anAssetNameThatCouldWalkOutOfTheStoreIsRefused() {
        assertEquals(1, WallpaperPolicy.read("image ../../etc/passwd sha256 $digestA").refused.size)
        assertEquals(1, WallpaperPolicy.read("image a/b.png sha256 $digestA").refused.size)
    }

    @Test
    fun aTypoIsRefusedRatherThanSkipped() {
        // The whole reason refusals exist: `surfacs lock` silently ignored is a
        // device that reads as configured and is not.
        val read = WallpaperPolicy.read("image wall.png sha256 $digestA\nsurfacs lock")
        assertEquals(1, read.refused.size)
        assertTrue(read.refused[0].why, read.refused[0].line.contains("surfacs"))
        assertEquals(both, read.surfaces, )
    }

    @Test
    fun anUnknownSurfaceIsRefusedAndDoesNotNarrowTheSet() {
        val read = WallpaperPolicy.read("image wall.png sha256 $digestA\nsurfaces lock desktop")
        assertEquals(1, read.refused.size)
        // NOT narrowed to {lock}: half of a refused line is not an instruction.
        assertEquals(both, read.surfaces)
    }

    @Test
    fun twoImagesAreRefusedRatherThanTheLastOneWinning() {
        val read = WallpaperPolicy.read(
            "image one.png sha256 $digestA\nimage two.png sha256 $digestB"
        )
        assertEquals("one.png", read.asset)
        assertEquals(1, read.refused.size)
    }

    // ---- deciding ---------------------------------------------------------

    @Test
    fun noImageConfiguredLeavesTheDeviceAlone() {
        assertEquals(Decision.NothingConfigured, WallpaperPolicy.decide(desired(null), null, emptySet()))
        assertEquals(Decision.NothingConfigured, WallpaperPolicy.decide(desired(""), digestA, both))
    }

    @Test
    fun aFirstImageIsAppliedToEveryNamedScreen() {
        val decision = WallpaperPolicy.decide(desired(), null, emptySet())
        assertTrue(decision is Decision.Apply)
        decision as Decision.Apply
        assertTrue(decision.reason.contains("yet"))
        assertEquals(both, decision.surfaces)
    }

    @Test
    fun theSameImageOnTheSameScreensIsNotReapplied() {
        assertEquals(Decision.AlreadyApplied, WallpaperPolicy.decide(desired(), digestA, both))
    }

    @Test
    fun aChangedImageIsAppliedToEveryNamedScreen() {
        val decision = WallpaperPolicy.decide(desired(digestB), digestA, both)
        assertTrue(decision is Decision.Apply)
        decision as Decision.Apply
        assertTrue(decision.reason.contains("changed"))
        // Every screen, not only missing ones: a screen carrying the OLD image
        // is as wrong as one carrying nothing.
        assertEquals(both, decision.surfaces)
    }

    @Test
    fun aDeviceThatAppliedToOneScreenAppliesToTheOtherWhenThePolicyChanges() {
        // muster#41's fourth criterion, and the reason the record has to say
        // which surfaces: with a digest alone this device believes it is done.
        val decision = WallpaperPolicy.decide(desired(), digestA, setOf(Surface.SYSTEM))
        assertTrue(decision is Decision.Apply)
        decision as Decision.Apply
        assertEquals(setOf(Surface.LOCK), decision.surfaces)
        assertTrue(decision.reason, decision.reason.contains("lock"))
    }

    @Test
    fun reconcilingTwiceChangesNothingTheSecondTime() {
        // muster#41's third criterion, spelled out as the loop it describes.
        var appliedDigest: String? = null
        var appliedSurfaces = emptySet<Surface>()
        val first = WallpaperPolicy.decide(desired(), appliedDigest, appliedSurfaces)
        assertTrue(first is Decision.Apply)
        appliedDigest = digestA
        appliedSurfaces = (first as Decision.Apply).surfaces
        assertEquals(
            Decision.AlreadyApplied,
            WallpaperPolicy.decide(desired(), appliedDigest, appliedSurfaces),
        )
    }

    @Test
    fun anEmptyRecordOfWhatWasAppliedCountsAsNeverApplied() {
        // A device-protected read that came back blank must retry, not conclude
        // it is done. Concluding done is how a phone never applies it at all.
        assertTrue(WallpaperPolicy.decide(desired(), "", both) is Decision.Apply)
    }

    @Test
    fun aScreenThePolicyNoLongerNamesIsReportedAndNotCleared() {
        // Clearing is destructive and irreversible from the device's side, and
        // the trigger is a word disappearing from a text file.
        val decision = WallpaperPolicy.decide(desired(surfaces = setOf(Surface.SYSTEM)), digestA, both)
        assertEquals(Decision.NoLongerNamed(setOf(Surface.LOCK)), decision)
    }

    // ---- what a person is told --------------------------------------------

    @Test
    fun aDeviceCarryingTheRightImageOnTheRightScreensSaysNothing() {
        val outcome = WallpaperPolicy.Outcome(
            applied = both,
            decision = Decision.AlreadyApplied,
        )
        assertTrue(outcome.concerns().toString(), outcome.concerns().isEmpty())
    }

    @Test
    fun aWallpaperNobodyConfiguredIsAConcern() {
        // Every muster device reported this until there was an asset store to
        // configure one from, and it reads as the quietest possible success.
        val outcome = WallpaperPolicy.Outcome(decision = Decision.NothingConfigured)
        assertEquals(1, outcome.concerns().size)
        assertTrue(outcome.concerns()[0].contains("no wallpaper configured"))
    }

    @Test
    fun aFetchThatFailedIsNotAlsoReportedAsNothingConfigured() {
        // THE CONTRADICTION THIS TEST EXISTS FOR. The steward reaches this with
        // `NothingConfigured` when it could not get the bytes, so the two lines
        // fired together - telling an operator no wallpaper is configured while
        // they are looking at the file they wrote. A real report read as noise
        // is worse than no report.
        val outcome = WallpaperPolicy.Outcome(
            decision = Decision.NothingConfigured,
            couldNotFetch = "wall.png: Unreachable(detail=UnknownHostException)",
        )
        assertEquals(outcome.concerns().toString(), 1, outcome.concerns().size)
        assertTrue(outcome.concerns()[0].startsWith("COULD_NOT_FETCH"))
    }

    @Test
    fun substitutedBytesAreTheLoudestThingThisStepCanSay() {
        val outcome = WallpaperPolicy.Outcome(
            decision = Decision.NothingConfigured,
            substituted = "wall.png: expected sha256 aaaa, the bytes were bbbb",
        )
        assertEquals(1, outcome.concerns().size)
        assertTrue(outcome.concerns()[0].startsWith("SUBSTITUTED"))
    }

    @Test
    fun aRefusedLineIsNotAlsoReportedAsNothingConfigured() {
        val outcome = WallpaperPolicy.Outcome(
            decision = Decision.NothingConfigured,
            refused = listOf(WallpaperPolicy.Refusal("surfacs lock", "not something...")),
        )
        assertEquals(1, outcome.concerns().size)
        assertTrue(outcome.concerns()[0].startsWith("REFUSED"))
    }

    @Test
    fun aScreenTheDeviceWouldNotSetIsAConcern() {
        val outcome = WallpaperPolicy.Outcome(
            applied = setOf(Surface.SYSTEM),
            decision = Decision.Apply("first time", both),
            didNotTake = listOf("lock"),
        )
        assertEquals(1, outcome.concerns().size)
        assertTrue(outcome.concerns()[0].contains("DID_NOT_TAKE"))
    }

    @Test
    fun aScreenThePolicyDroppedIsReportedRatherThanSilentlyLeft() {
        val outcome = WallpaperPolicy.Outcome(
            decision = Decision.NoLongerNamed(setOf(Surface.LOCK)),
        )
        assertEquals(1, outcome.concerns().size)
        assertTrue(outcome.concerns()[0].contains("lock"))
    }

    @Test
    fun anOutcomeNeverPrintsAnImageOrADigestInFull() {
        val outcome = WallpaperPolicy.Outcome(
            applied = both,
            decision = Decision.Apply("first time", both),
        )
        assertTrue(outcome.toString(), outcome.toString().contains("system"))
    }
}
