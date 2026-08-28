package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import android.util.Log
import java.io.File

/**
 * Put the device's launcher where the allowlist says it should be.
 *
 * WHERE THE CONFIG COMES FROM, and why it is a file. Same reasoning as the
 * restrictions and the wallpaper beside it: this app is Device Owner, so
 * anything baked into the APK can only be changed by a release, and a release
 * eventually costs a factory reset when the signing key moves. A file pushed
 * over adb is the difference between changing policy and shipping one.
 *
 * AN ABSENT FILE IS NOT AN EMPTY ONE. No file at all means nothing has been
 * configured and the device is left exactly as it is. A file that exists and is
 * empty is an allowlist that names nothing, and every application with an icon
 * goes except the ones that cannot go. Collapsing those two would make a first
 * boot on an unconfigured device indistinguishable from a deliberate
 * instruction to strip it.
 *
 * ONLY PACKAGES WITH AN ICON ARE EVER CONSIDERED, and that is the load-bearing
 * safety property of this class rather than an implementation detail. The
 * candidate set comes from ACTION_MAIN + CATEGORY_LAUNCHER, so it is exactly
 * the set of things a person can see and press. A package with no launcher
 * entry - the setup wizard, SystemUI, the permission controller, the media
 * provider - is not a thing this can hide even if somebody puts it nowhere in
 * the allowlist, because it was never a candidate. AppVisibilityPolicy protects
 * several of them by name anyway; this is the reason that table is belt rather
 * than braces.
 *
 * WHAT THIS COSTS A BOOT, written down because it is the one step in BootPlan
 * that scales with what is on the phone. One `queryIntentActivities`, then one
 * `isApplicationHidden` per icon - call it fifty on a stock Pixel - and on the
 * one boot where an allowlist first arrives, a write and a read-back for each
 * package that changes. The budget is
 * `ActivityManagerService.BROADCAST_BG_TIMEOUT`, 60 seconds: BOOT_COMPLETED and
 * LOCKED_BOOT_COMPLETED are background broadcasts, not the 10-second foreground
 * kind. Reads are cheap and writes happen once, so that used to be a
 * comfortable margin.
 *
 * IT IS LESS COMFORTABLE SINCE muster#46. `BootReceiver` now runs the plan on a
 * background thread under `goAsync()`, which was needed for the network step
 * ahead of this one - but `goAsync` does NOT extend the 60 seconds, it only
 * keeps the process alive to use them, and the fetch can spend up to 26 of them
 * before this step starts. The margin here is still thought to be enough and
 * has never been measured on a handset. If it is ever exceeded, the fix is a
 * scheduled job rather than a broadcast, not doing less here.
 *
 * TWO PACKAGE MANAGER FLAGS THAT ARE NOT OPTIONAL, both verified against AOSP
 * on 2026-08-19 and both silent when wrong:
 *
 *   * MATCH_UNINSTALLED_PACKAGES. A hidden package is not "available" to
 *     PackageManager - `PackageUserStateUtils.isAvailable` returns false for
 *     `installed && hidden` unless this flag is set. Without it, hiding an
 *     application removes it from the very query that would find it again, so
 *     putting a package back in the allowlist would unhide nothing and the
 *     reverse gear would be a factory reset after all.
 *   * MATCH_DIRECT_BOOT_AWARE and MATCH_DIRECT_BOOT_UNAWARE, together.
 *     `ComputerEngine.updateFlags` fills these in from the user's unlock state
 *     when the caller expresses no opinion, and at LOCKED_BOOT_COMPLETED - one
 *     of the two broadcasts that gets this far - that means direct-boot-aware
 *     components only. Almost nothing on the launcher is direct-boot aware, so
 *     the query comes back nearly empty and the reconcile does nothing, on
 *     precisely the boot an appliance in a cupboard gets.
 */
class AppVisibilitySteward(private val context: Context) {

    /** Where `muster visible-apps` pushes the file. */
    fun configFile(): File = File(
        // Device-protected, like everything else the boot path reads: this runs
        // at LOCKED_BOOT_COMPLETED, before first unlock, and a credential-
        // protected read there fails in a way that looks like an empty config -
        // which for an allowlist means "hide everything".
        context.createDeviceProtectedStorageContext().filesDir, "visible-apps"
    )

    /**
     * What happened, for the caller to log.
     *
     * THE READ-BACK IS THE REASON THIS RETURNS A SHAPE RATHER THAN A BOOLEAN.
     * `setApplicationHidden` returns a boolean and it is not the verdict.
     * `DevicePolicyManagerService.setApplicationHidden` opens by consulting
     * `listPolicyExemptAppsUnchecked` and returning false without doing
     * anything for a package on it (AOSP, read 2026-08-19); that list is
     * `R.array.policy_exempt_apps` plus a vendor overlay, and an app cannot
     * read it - `getPolicyExemptApps` is `@hide`/`@TestApi` behind
     * MANAGE_DEVICE_ADMINS. Asking the platform afterwards is the only question
     * whose answer is about the device.
     *
     * A DEVICE WITH SUCH A PACKAGE ON ITS LAUNCHER NEVER CONVERGES, and that is
     * an accepted cost rather than an oversight. The package is enumerated,
     * not in the allowlist, not hidden, so it lands in `hide` at every boot;
     * the write no-ops; the read-back disagrees; [didNotHide] names it again.
     * Forever. The alternative is muster remembering which packages the
     * platform refuses, which is a record that goes stale the first time a
     * system update changes the overlay - and a stale record here means
     * quietly giving up on hiding something. Repeating the question every boot
     * is the cheaper wrong answer of the two.
     *
     * [didNotHide] AND [didNotUnhide] ARE SEPARATE, and they are not the same
     * event. A hide that did not take is cosmetic - Play Store is still on the
     * launcher and somebody grumbles. An unhide that did not take is the
     * reverse gear failing: the operator put a package back in the file,
     * rebooted, and it did not come back, which is the state this whole design
     * exists to avoid. One flat list would have rendered them identically.
     */
    data class Outcome(
        val hidden: List<String> = emptyList(),
        val unhidden: List<String> = emptyList(),
        val withheld: List<String> = emptyList(),
        val refused: List<AppVisibilityPolicy.Refusal> = emptyList(),
        val keptVisible: List<AppVisibilityPolicy.LoadBearing> = emptyList(),
        val didNotHide: List<String> = emptyList(),
        val didNotUnhide: List<String> = emptyList(),
        val threw: List<String> = emptyList(),
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            inert?.let { add("nothing enforced - $it") }
            if (withheld.isNotEmpty()) add("WITHHELD hiding $withheld")
            refused.forEach { add("REFUSED '${it.line}' - ${it.why}") }
            keptVisible.forEach { add("KEPT_VISIBLE ${it.packageName} - ${it.why}") }
            if (didNotHide.isNotEmpty()) add("DID_NOT_HIDE $didNotHide")
            if (didNotUnhide.isNotEmpty()) add("DID_NOT_UNHIDE $didNotUnhide")
            if (threw.isNotEmpty()) add("THREW $threw")
        }
        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            else -> buildString {
                append("hid=$hidden unhid=$unhidden")
                if (withheld.isNotEmpty()) append(" WITHHELD=$withheld")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
                if (keptVisible.isNotEmpty()) {
                    append(" KEPT_VISIBLE=${keptVisible.map { it.packageName }}")
                }
                if (didNotHide.isNotEmpty()) append(" DID_NOT_HIDE=$didNotHide")
                if (didNotUnhide.isNotEmpty()) append(" DID_NOT_UNHIDE=$didNotUnhide")
                if (threw.isNotEmpty()) append(" THREW=$threw")
            }
        }
    }

    fun reconcile(): Outcome {
        val file = configFile()
        if (!file.isFile) return Outcome(inert = "no visible-apps file at ${file.absolutePath}")

        // EVERY "NOTHING HAPPENED" FROM HERE ON RAISES ITS OWN VOICE before
        // returning, rather than leaving the severity to whoever logs the
        // Outcome. One caller logs all of this at INFO (BootReceiver) and one
        // logs it and then paints over it (StatusActivity.sync), so "this
        // device is no longer managed" arriving at the same level as "there is
        // no config file" means `logcat -s muster:E` shows nothing at all for
        // an appliance that was quietly never policed. The absent file above is
        // the one genuinely benign case, and it stays quiet.
        //
        // Ownership is checked, not assumed: setApplicationHidden without it
        // throws SecurityException, and at BOOT_COMPLETED that takes the step
        // down with it.
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            val why = "not device owner; applications cannot be hidden"
            Log.w(TAG, "visible-apps: $why")
            return Outcome(inert = why)
        }
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: run {
                Log.e(TAG, "visible-apps: no DevicePolicyManager on this device")
                return Outcome(inert = "no DevicePolicyManager")
            }
        val admin = MusterDeviceAdminReceiver.component(context)
        val packages = context.packageManager

        val installed = launchablePackages(packages)
        // A device that names nothing but muster is not a device with one app
        // on it - it is what a manifest missing its <queries> element looks
        // like, because package visibility filtering leaves an app able to see
        // only itself. Going inert with the cause named beats reporting a plan
        // that changes nothing and letting somebody go and edit the file.
        //
        // This catches total filtering only. The stronger and more general
        // signal is a device that names no HOME screen, which AppVisibilityPolicy
        // treats as grounds to withhold hiding at any size.
        if (installed.size <= 1) {
            val why = "this device named at most one launchable application ($installed), " +
                "which is what a manifest with no <queries> element looks like - an app " +
                "can always see itself - so nothing was hidden or unhidden"
            Log.e(TAG, "visible-apps: $why")
            return Outcome(inert = why)
        }

        val desired = AppVisibilityPolicy.read(file.readText())
        val resolved = AppVisibilityPolicy.Resolved(
            own = context.packageName,
            home = packagesAnswering(
                packages,
                Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),
            ),
            settings = packagesAnswering(packages, Intent(Settings.ACTION_SETTINGS)),
            setupWizard = packagesAnswering(
                packages,
                Intent(Intent.ACTION_MAIN).addCategory(CATEGORY_SETUP_WIZARD),
            ),
        )
        // What the PLATFORM says is hidden, not what muster once did.
        //
        // ASKED ONLY ABOUT PACKAGES THIS DEVICE REPORTED, and that is a
        // constraint rather than a convenience. `isApplicationHidden` ends at
        // `PackageManagerService.getApplicationHiddenSettingAsUser`, which
        // returns TRUE for a package it has never heard of (AOSP, read
        // 2026-08-19: `if (ps == null) return true`). So asking about a name out
        // of AppVisibilityPolicy.NEVER_HIDDEN - half of which are the other
        // vendor's spelling and are not on any one handset - or about a typo in
        // the allowlist, answers "hidden". That package would then be unhidden
        // every boot, the call would return false because there is nothing to
        // unhide, and the read-back below would report DID_NOT_UNHIDE forever
        // against a package that does not exist.
        //
        // EVERY PACKAGE IS ASKED ABOUT SEPARATELY, and one that throws is
        // dropped from the reconcile rather than taking the whole reconcile
        // with it. A single `installed.filter { dpm.isApplicationHidden(...) }`
        // would abort at package 5 of 40, leave nothing hidden, and report the
        // failure only as a stack trace in BootReceiver naming the exception
        // class and not the package - identically, at every boot, forever.
        val threw = mutableListOf<String>()
        val readable = LinkedHashSet<String>()
        val hiddenNow = LinkedHashSet<String>()
        for (packageName in installed) {
            try {
                if (dpm.isApplicationHidden(admin, packageName)) hiddenNow.add(packageName)
                readable.add(packageName)
            } catch (e: Exception) {
                // Not in `readable`, so it is neither hidden nor unhidden. A
                // package muster cannot read the state of is a package muster
                // has no business acting on.
                Log.e(TAG, "visible-apps: cannot read '$packageName'; leaving it alone", e)
                threw.add(packageName)
            }
        }

        // Named, because `installed` and `hidden` are both Set<String> and
        // adjacent: swapping them compiles, inverts the whole policy, and the
        // first thing anybody would notice is a stripped phone. RestrictionSteward
        // names its two for the same reason.
        val plan = AppVisibilityPolicy.plan(
            desired,
            installed = readable,
            hidden = hiddenNow,
            resolved = resolved,
        )
        for (refusal in plan.refused) {
            Log.w(TAG, "visible-apps refused: ${refusal.line} - ${refusal.why}")
        }
        for (kept in plan.keptVisible) {
            Log.w(
                TAG,
                "visible-apps: keeping ${kept.packageName} visible although the " +
                    "allowlist does not name it - ${kept.why}",
            )
        }
        // Louder than the refusals it follows from, because it is the
        // consequence rather than the cause: an appliance that did not get
        // stripped looks exactly like one nobody configured, and this is the
        // only line that tells the two apart.
        for (why in plan.withheldWhy) {
            Log.e(TAG, "visible-apps: HIDING WITHHELD - $why")
        }
        if (plan.withheld.isNotEmpty()) {
            Log.e(TAG, "visible-apps: would have hidden ${plan.withheld}")
        }
        if (plan.changesNothing) {
            return Outcome(
                withheld = plan.withheld,
                refused = plan.refused,
                keptVisible = plan.keptVisible,
                threw = threw,
            )
        }

        // Guarded per package for the same reason the read above is: half a
        // launcher hidden and no record of which half is worse than either
        // outcome on its own.
        fun apply(packageName: String, hide: Boolean) {
            try {
                if (!dpm.setApplicationHidden(admin, packageName, hide)) {
                    // The platform declined outright rather than accepting and
                    // not taking effect - most likely its policy-exempt list.
                    // A different sentence from the read-back below, because it
                    // is a different thing to go and look at.
                    Log.w(
                        TAG,
                        "visible-apps: the platform declined to " +
                            "${if (hide) "hide" else "unhide"} '$packageName'",
                    )
                }
            } catch (e: Exception) {
                Log.e(
                    TAG,
                    "visible-apps: '$packageName' threw while being " +
                        "${if (hide) "hidden" else "unhidden"}",
                    e,
                )
                threw.add(packageName)
            }
        }
        // UNHIDING FIRST, AND THAT ORDER IS LOAD-BEARING. Unhiding is the only
        // recovery an appliance in a cupboard ever gets, and the list is always
        // the short one. Hiding forty packages ahead of it would queue the
        // recovery behind forty policy-engine writes on exactly the boot where
        // it matters most - the first one after somebody put Settings back in
        // the file - and anything that cuts the receiver short from there
        // leaves the device stranded for another whole boot.
        for (packageName in plan.unhide) apply(packageName, false)
        for (packageName in plan.hide) apply(packageName, true)

        // READ BACK. The call returning is not evidence of anything: the
        // platform's own policy-exempt list makes setApplicationHidden a no-op
        // for some packages, and on a device with more than one admin policy
        // the resolved answer is not necessarily the one just written. Asking
        // is what catches both, on the first device rather than the tenth.
        //
        // A read that throws counts as NOT having taken. "Could not prove it
        // worked" and "proved it did not" call for the same look at the device,
        // and the alternative is silence about a package nothing can answer for.
        fun isHidden(packageName: String): Boolean? = try {
            dpm.isApplicationHidden(admin, packageName)
        } catch (e: Exception) {
            Log.e(TAG, "visible-apps: cannot read back '$packageName'", e)
            null
        }
        val didNotHide = plan.hide.filter { isHidden(it) != true }
        val didNotUnhide = plan.unhide.filter { isHidden(it) != false }

        for (packageName in didNotHide) {
            Log.e(
                TAG,
                "visible-apps: '$packageName' was hidden and the platform does " +
                    "not agree it is - it is still on the launcher",
            )
        }
        for (packageName in didNotUnhide) {
            Log.e(
                TAG,
                "visible-apps: '$packageName' was UNHIDDEN and the platform " +
                    "still says it is hidden - the allowlist names it and the " +
                    "device is not giving it back",
            )
        }
        Log.i(TAG, "visible-apps hid=${plan.hide} unhid=${plan.unhide}")

        return Outcome(
            hidden = plan.hide,
            unhidden = plan.unhide,
            withheld = plan.withheld,
            refused = plan.refused,
            keptVisible = plan.keptVisible,
            didNotHide = didNotHide,
            didNotUnhide = didNotUnhide,
            threw = threw,
        )
    }

    /** Every package with an icon on this device, hidden ones included. */
    private fun launchablePackages(packages: PackageManager): Set<String> =
        packagesAnswering(
            packages,
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
        )

    private fun packagesAnswering(packages: PackageManager, intent: Intent): Set<String> =
        // The int overload rather than PackageManager.ResolveInfoFlags, which
        // arrived in API 33 and this agent runs from 29.
        packages.queryIntentActivities(intent, MATCH_FLAGS)
            .mapNotNull { it.activityInfo?.packageName }
            .toCollection(LinkedHashSet<String>())

    companion object {
        private const val TAG = "muster"

        /**
         * `Intent.CATEGORY_SETUP_WIZARD`, written out because it is hidden API.
         *
         * The constant is `@hide` in `frameworks/base/core/java/android/content/
         * Intent.java`, checked there on 2026-08-19; the STRING is not hidden -
         * it is what the AOSP setup wizard declares in its own manifest
         * (`packages/apps/Provision`, ACTION_MAIN + CATEGORY_HOME + DEFAULT +
         * CATEGORY_SETUP_WIZARD, read on the same day). Querying for it is an
         * ordinary intent query, not a private API call.
         */
        private const val CATEGORY_SETUP_WIZARD = "android.intent.category.SETUP_WIZARD"

        /**
         * See the class comment; neither of these is optional.
         *
         * `val` and not `const val`: the right-hand side is built out of Java
         * static fields, which Kotlin does not accept in a compile-time
         * constant.
         */
        private val MATCH_FLAGS =
            PackageManager.MATCH_UNINSTALLED_PACKAGES or
                PackageManager.MATCH_DIRECT_BOOT_AWARE or
                PackageManager.MATCH_DIRECT_BOOT_UNAWARE
    }
}
