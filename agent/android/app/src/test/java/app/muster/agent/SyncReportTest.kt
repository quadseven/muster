package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a person is told after a check-in.
 *
 * This exists because of a device that fetched its policy, reconciled every
 * step, hid nothing, and said "Managed - Current". Every steward had worked out
 * exactly why and written it down; the caller logged the lot at INFO and
 * rendered a screen that never mentioned it. On a phone with no adb - which is
 * every hands-free enrollment - that is indistinguishable from a device nobody
 * ever configured.
 *
 * WHAT THIS FILE DOES NOT TEST, and where that is covered instead. The steward
 * `Outcome` types are nested inside classes that import `android.*`, so they
 * cannot be constructed here. That every one of them implements `StepOutcome`
 * is not left to a test at all: `BootPlan.STEPS` is typed
 * `(Context) -> StepOutcome`, so a steward that does not implement it fails to
 * compile. A type is a better guarantee than an assertion, and it is the reason
 * that signature was tightened from `Any?` rather than the caller being taught
 * to recognise five shapes.
 *
 * The test that matters most is `aStepThatDidNothingIsNotReportedAsSuccess`.
 */
class SyncReportTest {

    /** A step outcome with whatever concerns a case needs. */
    private class Fake(private val says: List<String>) : StepOutcome {
        override fun concerns() = says
        override fun toString() = "fake(${says.size})"
    }

    private fun report(vararg steps: Pair<String, StepOutcome>) =
        SyncReport.of(steps.map { SyncReport.Step(it.first, it.second) })

    @Test
    fun aQuietRunSaysSoWithoutListingEveryStep() {
        val view = report(
            "restrictions" to Fake(emptyList()),
            "apps" to Fake(emptyList()),
        )
        assertTrue(view.concerns.isEmpty())
        assertTrue(view.headline, view.headline.contains("2 steps"))
        assertTrue(view.headline, view.headline.contains("nothing to report"))
    }

    @Test
    fun aStepThatDidNothingIsNotReportedAsSuccess() {
        // The exact shape of the device in hand: policy served, nothing hidden.
        val view = report("apps" to Fake(listOf("WITHHELD hiding [com.android.chrome]")))
        assertEquals(1, view.concerns.size)
        assertTrue(view.concerns[0], view.concerns[0].startsWith("apps: "))
        assertTrue(view.concerns[0], view.concerns[0].contains("WITHHELD"))
        // And the headline must not read as a clean run.
        assertTrue(view.headline, view.headline.contains("need attention"))
    }

    @Test
    fun theHeadlineCountsConcernsRatherThanNamingThem() {
        // A headline that named them would truncate on a narrow phone and read
        // as though there were fewer.
        val view = report(
            "a" to Fake(listOf("one", "two")),
            "b" to Fake(listOf("three")),
            "c" to Fake(emptyList()),
        )
        assertEquals(3, view.concerns.size)
        assertTrue(view.headline, view.headline.contains("3 of 3 steps"))
    }

    @Test
    fun everyConcernNamesTheStepThatRaisedIt() {
        val view = report("restrictions" to Fake(listOf("DID_NOT_TAKE [no_safe_boot]")))
        assertEquals(listOf("restrictions: DID_NOT_TAKE [no_safe_boot]"), view.concerns)
    }

    @Test
    fun aThrownStepIsAConcernAndDoesNotHideTheOnesAroundIt() {
        val view = report(
            "configuration" to SyncReport.Threw("configuration", "timeout"),
            "apps" to Fake(listOf("nothing enforced - no visible-apps file")),
        )
        assertEquals(2, view.concerns.size)
        assertTrue(view.concerns[0], view.concerns[0].contains("timeout"))
        assertTrue(view.concerns[1], view.concerns[1].contains("no visible-apps file"))
    }

    @Test
    fun aThrowWithNoMessageStillSaysSomething() {
        val view = report("apps" to SyncReport.Threw("apps", null))
        assertEquals(1, view.concerns.size)
        assertTrue(view.concerns[0], view.concerns[0].contains("no message"))
    }

    @Test
    fun detailCarriesEveryStepIncludingTheQuietOnes() {
        // The concerns are the exceptions; the detail is the whole story, and
        // a step missing from it would look like a step that never ran.
        val view = report("a" to Fake(emptyList()), "b" to Fake(listOf("x")))
        assertEquals(2, view.detail.size)
        assertTrue(view.detail[0], view.detail[0].startsWith("a: "))
    }

    // The wallpaper's own "nothing configured is a concern" moved to
    // WallpaperSteward.Outcome when muster#45 gave the step a real Outcome like
    // the other four stewards. It cannot be built here - the steward imports
    // android.* - and it is covered by the compiler instead, the same way every
    // other steward's conformance is: see this class's header.

    @Test
    fun anUnenrolledDeviceIsAConcernBecauseNothingBelowItCanWork() {
        val view = report("enroll" to HandsFreeEnrollment.Move.NothingToPresent)
        assertEquals(1, view.concerns.size)
        assertTrue(view.concerns[0], view.concerns[0].contains("not enrolled"))
        assertTrue(report("enroll" to HandsFreeEnrollment.Move.AlreadyEnrolled).concerns.isEmpty())
    }
}
