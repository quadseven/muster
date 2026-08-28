package app.muster.agent

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.content.Context
import android.os.PowerManager
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import java.io.File

/**
 * Put each managed app's configuration where the config file says it should be.
 *
 * WHERE THE CONFIG COMES FROM, and why it is a file. Same reasoning as the
 * restrictions beside it: this app is Device Owner, so anything baked into the
 * APK can only be changed by a release, and a release eventually costs a
 * factory reset when the signing key moves. It is also the only shape in which
 * a write token can reach a device at all without somebody typing it into the
 * phone.
 *
 * AN ABSENT FILE AND AN EMPTY ONE MEAN THE SAME THING HERE, which is the one
 * place this file deliberately parts company with the restrictions steward
 * beside it. There an empty file is an instruction to withdraw everything;
 * here it does nothing at all, because withdrawing a bundle is not the same as
 * clearing an app's settings. Under the receiving contract an absent key means
 * "keep what you have stored", so taking a bundle away changes nothing an app
 * can observe - it just falls back to values it already has. There is
 * therefore no destructive instruction to distinguish, and nothing worth
 * distinguishing it from. See AppConfigPolicy.plan for the same reasoning
 * applied per app.
 *
 * NO VALUE IS EVER LOGGED. `BootReceiver` logs the outcome of every step, and
 * `announceToken` and `ddClientToken` are credentials. [Outcome] and every
 * type it holds name keys and packages only; `AppConfigPolicy` says why that
 * has to be enforced by the types rather than by remembering.
 *
 * NO NEW MANIFEST PERMISSION. `setApplicationRestrictions` and
 * `setPermissionGrantState` are Device Owner privileges, not permissions, so
 * the four-permission profile that cleared the Play Protect approved-DPC check
 * on 2026-08-19 is untouched. `server/tests/test_agent_manifest.py` pins it.
 */
class AppConfigSteward(private val context: Context) {

    /** Where `muster app-config` pushes the file. */
    fun configFile(): File = File(
        // Device-protected, like everything else the boot path reads: this runs
        // at LOCKED_BOOT_COMPLETED, before first unlock, and a credential-
        // protected read there fails in a way that looks like an empty config.
        context.createDeviceProtectedStorageContext().filesDir, "app-config"
    )

    /**
     * What happened, for the caller to log.
     *
     * [didNotTake] is the one that matters. A key that was written, did not
     * error, and is not in the bundle afterwards - or a permission the platform
     * declined to grant - is the failure this class exists to make visible.
     * Entries are "package key", never a value.
     */
    data class Outcome(
        val configured: List<String> = emptyList(),
        val granted: List<String> = emptyList(),
        val refused: List<AppConfigPolicy.Refusal> = emptyList(),
        val didNotTake: List<String> = emptyList(),
        /** Applications Android may be freezing. Reported, not fixable here. */
        val batteryConcerns: List<String> = emptyList(),
        /** Components poked so a freshly configured app acts on its config. */
        val woken: List<String> = emptyList(),
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            inert?.let { add("nothing enforced - $it") }
            refused.forEach { add("REFUSED '${it.line}' - ${it.why}") }
            if (didNotTake.isNotEmpty()) add("DID_NOT_TAKE $didNotTake")
            // Reported, never fixed here - see AppConfigPolicy.batteryConcerns
            // for why muster states something it has no API to change.
            addAll(batteryConcerns)
        }
        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            else -> buildString {
                append("configured=$configured granted=$granted")
                if (woken.isNotEmpty()) append(" woken=$woken")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
                if (didNotTake.isNotEmpty()) append(" DID_NOT_TAKE=$didNotTake")
            }
        }
    }

    fun reconcile(): Outcome {
        val file = configFile()
        if (!file.isFile) return Outcome(inert = "no app-config file at ${file.absolutePath}")

        // Checked, not assumed. setApplicationRestrictions without ownership
        // throws SecurityException, and at boot that takes the receiver's whole
        // remaining plan down with it.
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            return Outcome(inert = "not device owner; app configuration cannot be set")
        }
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Outcome(inert = "no DevicePolicyManager")
        val admin = MusterDeviceAdminReceiver.component(context)

        val desired = AppConfigPolicy.read(file.readText())
        for (refusal in desired.refused) {
            Log.w(TAG, "app config refused: ${refusal.line} - ${refusal.why}")
        }

        val current = desired.apps.associate { app ->
            app.packageName to carriedBy(dpm, admin, app.packageName)
        }
        val alreadyGranted = desired.apps
            .flatMap { app -> app.grants.map { AppConfigPolicy.Grant(app.packageName, it) } }
            .filter { isInForce(dpm, admin, it) }
            .toSet()

        val plan = AppConfigPolicy.plan(desired, current, alreadyGranted)
        // BATTERY STATE IS REPORTED EVEN WHEN NOTHING CHANGED, and that is the
        // case that matters most: a device in steady state is exactly the one
        // that has been sitting frozen while its configuration looked perfect.
        val battery = AppConfigPolicy.batteryConcerns(exemptionState(desired))
        if (plan.changesNothing) {
            // AND THE WAKES ARE STILL RECONCILED HERE, which is the whole point
            // of the ledger and was very nearly undone by this early return.
            //
            // A missed wake lives exactly in the steady state: the pass that
            // installed the app fired at a package that did not exist yet, and
            // by the next pass the restrictions already match, so the plan
            // changes nothing. Returning here without reconciling wakes would
            // have made the ledger unreachable on the ONE path it was written
            // for - a fix that is correct in isolation and inert in place.
            return Outcome(
                refused = plan.refused,
                batteryConcerns = battery,
                woken = reconcileWakes(desired),
            )
        }

        val configured = mutableListOf<String>()
        val granted = mutableListOf<String>()
        val didNotTake = mutableListOf<String>()

        for (write in plan.writes) {
            // GUARDED PER APP, not once around the loop. An app that is not
            // installed yet - which is zippie's whole situation until #20 lands
            // - must not stop the other apps on the device being configured.
            try {
                dpm.setApplicationRestrictions(admin, write.packageName, toBundle(write.values))
            } catch (e: Exception) {
                // THE CLASS NAME AND NOT THE EXCEPTION, and not its stack
                // trace. This is the one construct in the write path whose text
                // muster does not choose: an exception raised with the bundle in
                // hand may quote any of it, and this file's whole thesis is that
                // it cannot know which values are credentials. The class is what
                // distinguishes the cases that matter anyway - SecurityException
                // is "not device owner", and everything else is worth a bug.
                Log.e(TAG, "app config for ${write.packageName} was refused: ${e.javaClass.simpleName}")
                didNotTake += write.values.keys.map { "${write.packageName} $it" }
                continue
            }

            // READ BACK. setApplicationRestrictions does not tell the caller
            // anything: it returns void, and a bundle that never arrived looks
            // exactly like one that did. Asking the platform what the app now
            // carries is the only question whose answer is not our own guess -
            // the same rule RestrictionSteward follows, and the same rule that
            // caught a config file which was never on the device at all.
            val after = carriedBy(dpm, admin, write.packageName)
            val wrong = write.values.keys.filter { after[it] != write.values[it] }
            val leftOver = after.keys.filter { it !in write.values.keys }

            configured.add("${write.packageName} set=${write.setKeys} dropped=${write.droppedKeys}")
            for (key in wrong) {
                val named = "${write.packageName} $key"
                didNotTake.add(named)
                Log.e(TAG, "app config '$named' was written and the platform does not hold it")
            }
            for (key in leftOver) {
                val named = "${write.packageName} $key"
                didNotTake.add(named)
                Log.e(TAG, "app config '$named' was withdrawn and the platform still holds it")
            }
        }

        for (grant in plan.grants) {
            val named = "${grant.packageName} ${grant.permission}"
            val asked = try {
                dpm.setPermissionGrantState(
                    admin,
                    grant.packageName,
                    grant.permission,
                    DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED,
                )
            } catch (e: Exception) {
                // The class name only, for the same reason as the write above.
                Log.e(TAG, "grant of $named was refused: ${e.javaClass.simpleName}")
                false
            }
            // BOTH HALVES ARE ASKED FOR, and they answer different questions.
            // The grant STATE is muster's policy, which is what makes the
            // permission stick when somebody taps deny; whether the app HOLDS
            // the permission is the outcome the operator actually wanted. A
            // policy of GRANTED over an app that does not hold it is the state
            // that reads as done and is not - `setPermissionGrantState` returns
            // false for a permission the app never declared, and for one that
            // is not a runtime permission on this release.
            if (asked && isInForce(dpm, admin, grant)) {
                granted.add(named)
            } else {
                didNotTake.add(named)
                Log.e(TAG, "'$named' was granted and the app does not hold the permission")
            }
        }

        Log.i(TAG, "app config configured=$configured granted=$granted")

        // THE SAME HELPER the steady-state branch above calls. One
        // implementation, so a wake cannot be reconciled on one path and
        // skipped on the other.
        val woken = reconcileWakes(desired)

        return Outcome(
            woken = woken,
            batteryConcerns = battery,
            configured = configured,
            granted = granted,
            refused = plan.refused,
            didNotTake = didNotTake,
        )
    }

    /**
     * What bundle the platform says this app carries right now.
     *
     * Answering "nothing" for a package the platform will not talk about is
     * deliberate: it makes the next step WRITE, and the write is guarded and
     * reported. Treating it as an error instead would abandon every app after
     * this one in the file.
     */
    private fun carriedBy(
        dpm: DevicePolicyManager,
        admin: ComponentName,
        packageName: String,
    ): Map<String, Any?> = try {
        flatten(dpm.getApplicationRestrictions(admin, packageName))
    } catch (e: Exception) {
        Log.w(TAG, "cannot read the configuration of $packageName: ${e.javaClass.simpleName}")
        emptyMap()
    }

    /** Is this permission both muster's policy and actually held by the app? */
    private fun isInForce(
        dpm: DevicePolicyManager,
        admin: ComponentName,
        grant: AppConfigPolicy.Grant,
    ): Boolean = try {
        dpm.getPermissionGrantState(admin, grant.packageName, grant.permission) ==
            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED &&
            context.packageManager.checkPermission(grant.permission, grant.packageName) ==
            PackageManager.PERMISSION_GRANTED
    } catch (e: Exception) {
        // An app that is not installed answers this way, and that is not an
        // error - it is "no", which is the right answer to "is it granted".
        Log.w(TAG, "cannot read the grant state of ${grant.packageName}: ${e.javaClass.simpleName}")
        false
    }

    /**
     * Poke one component, so a stopped app starts existing.
     *
     * `FLAG_INCLUDE_STOPPED_PACKAGES` IS THE ENTIRE POINT. Without it this
     * broadcast is dropped for exactly the app that needs it: one that has
     * never been launched sits in Android's STOPPED state and receives nothing,
     * which is why a freshly installed application can be perfectly configured
     * and permanently inert.
     *
     * EXPLICIT, via `setComponent`. An implicit broadcast does not reach a
     * stopped app however it is flagged, and the component is named in policy
     * because it is a contract with somebody else's manifest.
     */
    /**
     * Tell any package that has not been told about this configuration.
     *
     * CALLED ON EVERY PATH, including the one where the plan changes nothing.
     * An explicit wake is a one-shot broadcast and Android does not queue it
     * for a component that is not installed yet; the install step commits a
     * PackageInstaller session and returns before installation completes. So
     * the pass that installs an app can fire a wake into nothing, and by the
     * next pass the configuration already matches. Reconciling wakes only when
     * something changed makes that miss permanent.
     */
    private fun reconcileWakes(desired: AppConfigPolicy.Desired): List<String> {
        val installedNow = desired.wakes
            .map { it.packageName }
            .filter { isInstalled(it) }
            .toSet()
        return desired.wakes.mapNotNull { w ->
            val fingerprint = AppConfigPolicy.fingerprintFor(w, desired)
            val should = AppConfigPolicy.shouldWake(
                wake = w,
                installed = installedNow,
                wokenFor = WakeLedger.wokenFor(context, WakeLedger.key(w)),
                fingerprint = fingerprint,
            )
            if (!should) null
            else wake(w)?.also { WakeLedger.record(context, WakeLedger.key(w), fingerprint) }
        }
    }

    /**
     * Does the platform actually have this package RIGHT NOW?
     *
     * Asked of the PackageManager rather than inferred from "we just installed
     * it": the install step commits a session and returns before the
     * installation completes, so believing our own install would reintroduce
     * exactly the race this guards.
     */
    private fun isInstalled(packageName: String): Boolean = try {
        context.packageManager.getPackageInfo(packageName, 0)
        true
    } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
        false
    }

    private fun wake(w: AppConfigPolicy.Wake): String? {
        val component = ComponentName.unflattenFromString(w.component)
        if (component == null) {
            // Refused at read time too; belt and braces, because the platform
            // answers a malformed component with null rather than an exception
            // and the resulting silence is indistinguishable from success.
            Log.e(TAG, "app config: '${w.component}' is not a component; not waking")
            return null
        }
        // RESOLVE THE RECEIVER, not just the string. `unflattenFromString`
        // is a PARSE: it succeeds for any well-formed "pkg/Class" whether or
        // not that class exists. An explicit broadcast to a receiver that was
        // renamed, removed or disabled is dropped by the framework with no
        // exception and no return value - so without this, the ledger would
        // record a delivery that never happened and never try again. That is
        // the permanent miss this whole mechanism exists to prevent,
        // reintroduced one layer down.
        val receiver = try {
            context.packageManager.getReceiverInfo(component, 0)
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            Log.e(TAG, "app config: ${w.component} is not a receiver on this device; not waking")
            return null
        }
        // NOT EXPORTED IS THE FOURTH SILENT DROP. An explicit broadcast from
        // another UID to a receiver declared `android:exported="false"` is
        // filtered by the system with no exception and no return value, exactly
        // like the absent and disabled cases. If this is ever false, the wake
        // has never been deliverable and the ledger would record every send as
        // a success.
        if (!receiver.exported) {
            Log.e(
                TAG,
                "app config: ${w.component} is not exported, so a broadcast from " +
                    "muster cannot reach it; not waking",
            )
            return null
        }
        // THE MANIFEST VALUE IS NOT THE RUNTIME STATE. `ComponentInfo.enabled`
        // is the merged `android:enabled` attribute as DECLARED; it does not
        // reflect `setApplicationEnabledSetting` or `setComponentEnabledSetting`
        // - and `getPackageInfo` succeeds for a disabled app, so nothing above
        // catches it either.
        //
        // ANYTHING THAT IS NOT ENABLED-OR-DEFAULT COUNTS AS OFF. The settings
        // are DEFAULT(0), ENABLED(1), DISABLED(2), DISABLED_USER(3),
        // DISABLED_UNTIL_USED(4). Testing only against DISABLED - as the first
        // version of this check did - lets `pm disable-user` straight through,
        // which is what several admin and OEM flows actually set. The broadcast
        // is dropped, the ledger records a delivery, and it is never retried:
        // the same permanent miss, surviving a fix that enumerated the wrong
        // set of states.
        val pm = context.packageManager
        fun off(setting: Int) = setting !=
            android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED &&
            setting != android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT
        val appOff = !receiver.applicationInfo.enabled ||
            off(pm.getApplicationEnabledSetting(component.packageName))
        val componentOff = off(pm.getComponentEnabledSetting(component))
        if (!receiver.isEnabled || appOff || componentOff) {
            Log.e(TAG, "app config: ${w.component} is disabled; not waking")
            return null
        }
        return try {
            context.sendBroadcast(
                Intent(w.action)
                    .setComponent(component)
                    .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
            )
            Log.i(TAG, "app config: woke ${w.component} with ${w.action}")
            w.component
        } catch (e: Exception) {
            Log.e(TAG, "app config: could not wake ${w.component}", e)
            null
        }
    }

    /**
     * Which configured applications Android is willing to leave alone.
     *
     * READ, NEVER SET. There is no public Device Owner API to grant this - see
     * `AppConfigPolicy.batteryConcerns`. A package this cannot answer for is
     * left OUT of the map rather than reported as either state, because a
     * fabricated answer here would poison the one line meant to be trusted.
     */
    private fun exemptionState(desired: AppConfigPolicy.Desired): Map<String, Boolean> {
        val power = context.getSystemService(PowerManager::class.java) ?: return emptyMap()
        val state = LinkedHashMap<String, Boolean>()
        for (packageName in desired.apps.map { it.packageName }.distinct()) {
            try {
                state[packageName] = power.isIgnoringBatteryOptimizations(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "app config: cannot read battery exemption for '$packageName'", e)
            }
        }
        return state
    }

    companion object {
        private const val TAG = "muster"

        /**
         * A Bundle holding exactly what the config file asked for.
         *
         * String and Boolean are the only two shapes `AppConfigPolicy` can
         * produce, so a third is a programming error rather than anything an
         * operator can cause. It throws rather than skipping the key, because
         * skipping would push a bundle quietly missing a value. The caller's
         * per-app `try` then reports it as a refusal for that app and carries
         * on with the others, which is the right blast radius for a bug that
         * can only affect one app's values.
         */
        private fun toBundle(values: Map<String, Any>): Bundle {
            val bundle = Bundle()
            for ((key, value) in values) {
                when (value) {
                    is String -> bundle.putString(key, value)
                    is Boolean -> bundle.putBoolean(key, value)
                    else -> throw IllegalStateException(
                        // The KEY, never the value: this message can reach a log.
                        "app config key '$key' holds a ${value.javaClass.simpleName}"
                    )
                }
            }
            return bundle
        }

        /**
         * A restrictions Bundle as a plain map, so comparing it is a comparison
         * and not a walk over typed getters.
         *
         * `Bundle.get` is deprecated and there is no replacement that can read
         * a value whose type is not known in advance, which is exactly the
         * situation here: the keys belong to somebody else's app.
         */
        @Suppress("DEPRECATION")
        private fun flatten(bundle: Bundle?): Map<String, Any?> {
            val held = bundle ?: return emptyMap()
            return held.keySet().associateWith { held.get(it) }
        }
    }
}
