package app.muster.agent

import app.muster.agent.IdentityLifecycle.Stance
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a person holding the phone is told, for every state it can be in.
 *
 * The state that mattered enough to write this class is
 * `anEnrolledDeviceIsNeverAskedToEnroll`. The agent shipped showing a valid,
 * enrolled Device Owner an empty pairing box and "Enroll this device".
 *
 * Two of these cannot be staged on hardware on demand at all - a lapsed
 * certificate and a clock behind its own identity - which is the reason the
 * decision is a function rather than a branch inside an Activity.
 */
class DeviceStatusTest {

    private fun facts(
        deviceOwner: Boolean = true,
        stance: Stance = Stance.Current,
        lastCheckIn: Long? = 1_000_000L,
        restrictions: List<String> = listOf("no_safe_boot"),
    ) = DeviceStatus.Facts(
        deviceOwner = deviceOwner,
        stance = stance,
        notAfter = 1_795_000_000L,
        renewAfter = 1_792_000_000L,
        serverUrl = "https://enroll.muster.example",
        restrictions = restrictions,
        agentVersion = "0.1.0",
        lastCheckIn = lastCheckIn,
        now = 1_000_060L,
    )

    @Test
    fun anEnrolledDeviceIsNeverAskedToEnroll() {
        // THE bug. An enrolled Device Owner was shown an enrollment form.
        val view = DeviceStatus.render(facts(stance = Stance.Current))
        assertFalse(view.canEnroll)
        assertEquals("Managed and current", view.headline)
    }

    @Test
    fun aDeviceThatIsNotOwnedSaysSoBeforeAnythingElse() {
        // Without ownership nothing else reported here is enforceable, so
        // leading with a certificate would be misleading about the only thing
        // that decides whether policy applies.
        val view = DeviceStatus.render(facts(deviceOwner = false, stance = Stance.Current))
        assertEquals("Not managed", view.headline)
    }

    @Test
    fun anUnenrolledDeviceIsOfferedEnrollment() {
        val view = DeviceStatus.render(facts(stance = Stance.Unenrolled))
        assertTrue(view.canEnroll)
        assertEquals("Not enrolled", view.headline)
    }

    @Test
    fun aLapsedIdentityIsOfferedEnrollmentAgain() {
        // Lapse IS the revocation mechanism, so this is a normal end state and
        // not an error - the device simply has to rejoin the kith.
        val view = DeviceStatus.render(facts(stance = Stance.Lapsed(secondsSinceExpiry = 172_800)))
        assertTrue(view.canEnroll)
        assertEquals("Identity lapsed", view.headline)
        assertTrue(view.detail.contains("2 days"))
    }

    @Test
    fun aClockBehindItsOwnCertificateIsNamedAsSuch() {
        // The diagnosis nothing else on the device will offer. To every other
        // tool this looks like a networking fault.
        val view = DeviceStatus.render(facts(stance = Stance.ClockBehind(secondsOfSkew = 7_200)))
        assertEquals("Clock is wrong", view.headline)
        assertTrue(view.detail.contains("2 hours"))
        assertFalse("a clock fault is not fixed by enrolling again", view.canEnroll)
    }

    @Test
    fun renewalDueIsReassuringRatherThanAlarming() {
        val view = DeviceStatus.render(facts(stance = Stance.ShouldRenew(secondsUntilExpiry = 2_592_000)))
        assertEquals("Renewal due", view.headline)
        assertTrue(view.detail.contains("30 days"))
        assertFalse(view.canEnroll)
    }

    @Test
    fun restrictionsAreShownOrSaidToBeAbsent() {
        val none = DeviceStatus.render(facts(restrictions = emptyList()))
        assertEquals("none", none.rows.single { it.label == "Restrictions in force" }.value)
        val some = DeviceStatus.render(facts(restrictions = listOf("no_safe_boot", "no_add_user")))
        assertTrue(some.rows.single { it.label == "Restrictions in force" }.value.contains("no_add_user"))
    }

    @Test
    fun aDeviceThatHasNeverCheckedInSaysNever() {
        // Not "0 minutes ago", which reads as healthy.
        val view = DeviceStatus.render(facts(lastCheckIn = null))
        assertEquals("never", view.rows.single { it.label == "Last check-in" }.value)
    }

    @Test
    fun theCheckInIsRelativeAndCoarse() {
        val view = DeviceStatus.render(facts(lastCheckIn = 1_000_000L))  // now is +60
        assertEquals("1 minute ago", view.rows.single { it.label == "Last check-in" }.value)
    }

    @Test
    fun durationsReadLikeSomethingAPersonWouldSay() {
        assertEquals("less than a minute", DeviceStatus.humanize(30))
        assertEquals("1 minute", DeviceStatus.humanize(60))
        assertEquals("5 minutes", DeviceStatus.humanize(300))
        assertEquals("1 hour", DeviceStatus.humanize(3600))
        assertEquals("1 day", DeviceStatus.humanize(86_400))
        assertEquals("27 days", DeviceStatus.humanize(86_400 * 27))
    }

    @Test
    fun aNegativeDurationDoesNotRenderAsNonsense() {
        // now comes from the device's own clock, and the whole reason
        // ClockBehind exists is that it cannot be trusted.
        assertEquals("less than a minute", DeviceStatus.humanize(-500))
    }

    @Test
    fun aDateIsRenderedForAPersonRatherThanForTheWire() {
        // The wire format is an ISO instant to microseconds. It is the longest
        // string on the page and the part that matters - roughly when - is the
        // hardest to pull out of it.
        val rendered = DeviceStatus.when_(1_795_000_000L, 1_795_000_000L - 86_400 * 90)
        assertTrue(rendered, rendered.startsWith("18 Nov 2026"))
        assertTrue(rendered, rendered.contains("in 90 days"))
    }

    @Test
    fun aDateInThePastSaysAgoRatherThanNegativeIn() {
        val rendered = DeviceStatus.when_(1_795_000_000L, 1_795_000_000L + 86_400 * 3)
        assertTrue(rendered, rendered.contains("3 days ago"))
    }

    @Test
    fun theOwnerRowIsCapitalised() {
        // It is the product's name, on a phone somebody else is holding.
        val value = DeviceStatus.render(facts()).rows.single { it.label == "Managed by" }.value
        assertEquals("Muster (Device Owner)", value)
    }

    @Test
    fun nothingOnScreenSpellsTheProductWithALowercaseM() {
        // Caught twice by eye and fixed twice by hand, which is the argument
        // for a test rather than a third correction. Strings live in two places
        // - strings.xml and Kotlin - and only one of them got capitalised each
        // time. This walks every stance so a new branch cannot reintroduce it.
        val stances = listOf(
            IdentityLifecycle.Stance.Current,
            IdentityLifecycle.Stance.Unenrolled,
            IdentityLifecycle.Stance.Lapsed(1),
            IdentityLifecycle.Stance.ShouldRenew(1),
            IdentityLifecycle.Stance.ClockBehind(1),
        )
        for (owner in listOf(true, false)) {
            for (stance in stances) {
                val view = DeviceStatus.render(facts(deviceOwner = owner, stance = stance))
                // Prose only. A hostname is not prose: `enroll.muster.example` is
                // lowercase because DNS is, and capitalising it would be wrong
                // in a way a person would have to work around.
                val shown = (listOf(view.headline, view.detail) + view.rows.map { it.value })
                    .filterNot { it.contains("://") }
                for (text in shown) {
                    assertFalse(
                        "\"$text\" spells the product with a lowercase m",
                        Regex("\\bmuster\\b").containsMatchIn(text),
                    )
                }
            }
        }
    }
}
