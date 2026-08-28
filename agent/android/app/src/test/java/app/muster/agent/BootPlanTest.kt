package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * That the things which reconcile a device are actually run when it boots.
 *
 * WHY A TEST THIS SMALL EARNS ITS PLACE. The bug it guards against already
 * happened here: `WallpaperSteward.lock()` was written, documented and covered
 * by three passing unit tests, and no code path could reach it, so the agent
 * enforced nothing while the suite stayed green. Testing a decision function
 * proves the decision is right; it says nothing about whether anything asks.
 *
 * WHAT THIS DOES NOT COVER, stated so it is not mistaken for more than it is:
 * it asserts the boot plan enumerates each steward, not that BootReceiver
 * iterates the plan correctly, and not that the receiver is registered for the
 * right intents. Those need an instrumented device or Robolectric, neither of
 * which is on this project. It catches a steward being added and never wired,
 * or wired and later dropped - which is the failure that actually occurred.
 */
class BootPlanTest {

    private val names = BootPlan.STEPS.map { it.first }

    @Test
    fun configurationIsFetchedAtBootAndBeforeAnythingReconcilesAgainstIt() {
        // Every steward after it is a reconciler over files this one writes, so
        // fetching late would mean every policy change took two boots - on
        // appliances that may not boot for months. It is also the whole answer
        // to muster#46: without this step in this list, a QR-provisioned device
        // enrolls and then sits empty until somebody puts a cable in it.
        assertTrue(
            "configuration must be fetched at boot, not merely implemented",
            names.contains("configuration"),
        )
        assertTrue(
            "the fetch must run before the stewards that read what it writes",
            names.indexOf("configuration") < names.indexOf("wallpaper"),
        )
    }

    @Test
    fun enrollmentIsAdvancedAtBoot() {
        // The RECOVERY half of hands-free enrollment. PolicyComplianceActivity
        // presents while the operator is standing at the console, and gives up
        // after ninety seconds so setup cannot hang - so a vouch that arrives a
        // minute later has nothing to collect it unless something at boot does.
        // Without this step that device comes up provisioned, with a request
        // muster has already signed a certificate for, and waits for a human to
        // open the app: the exact hands-on step the QR exists to remove.
        assertTrue(
            "enrollment must be advanced at boot, not merely implemented",
            names.contains("enroll"),
        )
    }

    @Test
    fun enrollmentIsAdvancedBeforeConfigurationIsFetched() {
        // ORDER, AND THIS ONE IS LOAD-BEARING RATHER THAN TIDY. Configuration is
        // fetched over the identity a device holds (muster#46), so a device that
        // is not in the kith yet has nothing to fetch it with. Enrolling second
        // means the first boot of a QR-provisioned phone fetches nothing, and
        // the operator waits for a second boot to see any policy at all - on an
        // appliance that may not boot again for months.
        assertEquals(0, names.indexOf("enroll"))
        assertTrue(names.indexOf("enroll") < names.indexOf("configuration"))
    }

    @Test
    fun restrictionsAreReconciledAtBoot() {
        assertTrue(
            "restrictions must be run at boot, not merely implemented",
            names.contains("restrictions"),
        )
    }

    @Test
    fun appConfigurationIsReconciledAtBoot() {
        // The whole point of managed app configuration is that nobody has to
        // touch the phone. A steward that is written and never run leaves the
        // configured app exactly where it was before the feature existed:
        // installed, launched, and contributing nothing.
        assertTrue(
            "app configuration must be run at boot, not merely implemented",
            names.contains("app-config"),
        )
    }

    @Test
    fun theWallpaperIsStillReconciledAtBoot() {
        assertTrue(names.contains("wallpaper"))
        // muster#67: installing muster's own package ends the process, so
        // every step that decides whether a device is managed must already
        // have run. Last in the plan, and last within its own step.
        // muster#81: the install step SPLIT. Installing muster ends the process,
        // so that half stays last - but everything else must land BEFORE the
        // steps that configure and reveal it, or a freshly installed app sits
        // unconfigured and hidden for a whole interval. Proved on a handset.
        assertEquals(
            "installing MUSTER must be the last thing a boot does",
            names.size - 1,
            names.indexOf("install-self"),
        )
        assertTrue(
            "other applications must be installed before they are configured",
            names.indexOf("install-apps") < names.indexOf("app-config"),
        )
        assertTrue(
            "other applications must be installed before the launcher is filtered",
            names.indexOf("install-apps") < names.indexOf("apps"),
        )
        // COSMETIC, AND IT MAKES A NETWORK CALL NOW (muster#45), so it must not
        // sit in front of the steps that decide whether a device is managed.
        // Ahead of them, a slow network meant a phone came up unrestricted for
        // as long as an image took to arrive.
        assertTrue(
            "a picture must not delay the restrictions",
            names.indexOf("restrictions") < names.indexOf("wallpaper"),
        )
        assertTrue(
            "a picture must not delay the app configuration",
            names.indexOf("app-config") < names.indexOf("wallpaper"),
        )
    }

    @Test
    fun whichApplicationsAreVisibleIsReconciledAtBoot() {
        // AppVisibilityPolicy has more tests than anything else in the agent
        // and every one of them is over a pure function. Not one of them says
        // that anything ever asks - which is the failure this file exists for,
        // and the failure that already happened once here.
        assertTrue(
            "the allowlist must be reconciled at boot, not merely implemented",
            names.contains("apps"),
        )
    }

    @Test
    fun theBootStepDoesNotDecideForItselfWhetherThereIsAnythingToDo() {
        // A SOURCE-LEVEL GUARD, because what it protects cannot be reached from
        // a JVM test: `BootPlan.enroll` builds a FileIdentityStore from a
        // Context, so there is no way to exercise it without a device. The bug
        // it guards against is not hypothetical - it was here, and review found
        // it rather than anything failing.
        //
        // WHAT WENT WRONG. This step asked `identity.hasIdentity()` itself and
        // returned early, which reads as a cheap short-circuit and was a second
        // copy of a decision HandsFreeEnrollment already makes. So it returned
        // BEFORE that class's cleanup ran, and a device that scanned a
        // hands-free QR, failed to present, and was then enrolled by hand kept
        // its spent pairing code in device-protected storage for the life of the
        // phone - re-presenting it at every boot and being refused CODE_USED,
        // which is the refusal muster reports for somebody replaying a
        // photographed QR.
        //
        // The flow is a factory now, so the cheap path stays cheap without
        // anybody re-implementing the decision to keep it that way;
        // `nothingIsBuiltOnTheBootOfADeviceThatHasNothingToDo` pins that half.
        val code = readSource("BootPlan.kt").lines()
            .filterNot { it.trim().startsWith("//") }
            .joinToString("\n")
        assertFalse(
            "BootPlan is deciding for itself whether this device is enrolled, " +
                "which is how it came to skip HandsFreeEnrollment's cleanup",
            code.contains("hasIdentity"),
        )
    }

    /**
     * A file out of the agent's own sources, found from wherever the runner
     * started.
     *
     * Gradle runs unit tests with the working directory at `app/`; the local
     * no-SDK harness runs from elsewhere in the checkout. Walking up and trying
     * both shapes is what makes one test work under both. It FAILS rather than
     * skipping when the file cannot be found - a guard that quietly does nothing
     * looks exactly like a guard that passes.
     */
    private fun readSource(name: String): String {
        val relative = "src/main/java/app/muster/agent/$name"
        var here: java.io.File? = java.io.File(".").absoluteFile
        repeat(8) {
            val directory = here ?: return@repeat
            for (candidate in listOf(
                java.io.File(directory, relative),
                java.io.File(directory, "agent/android/app/$relative"),
            )) {
                if (candidate.isFile) return candidate.readText()
            }
            here = directory.parentFile
        }
        throw AssertionError(
            "could not find $name from ${java.io.File(".").absolutePath}; this " +
                "guard is not running, which looks exactly like it passing"
        )
    }

    @Test
    fun everyStepIsNamedForTheLog() {
        // The names end up in logcat as "boot (ACTION): <name> <outcome>", which
        // on a device nobody is holding is the entire diagnostic.
        assertTrue(names.all { it.isNotBlank() })
        assertTrue(names.toSet().size == names.size)
    }
}
