package app.muster.agent

/**
 * Which restrictions this device should carry, and which it should not.
 *
 * WHY THIS EXISTS AT ALL. Before it, the agent enforced nothing. The single
 * restriction in the codebase - DISALLOW_SET_WALLPAPER - was added by
 * `WallpaperSteward.lock()`, whose only possible caller was
 * `reconcile(lockAfterwards = false)`, and nothing anywhere passed `true`. The
 * decision function had three passing unit tests over a path production could
 * not reach, so the suite was green across a capability that did not exist. A
 * pure function nothing calls is documentation, not policy.
 *
 * RECONCILING GOES BOTH WAYS, and that is the point of a plan rather than a
 * list of things to turn on. A restriction deleted from the config must come
 * OFF the device. Policy that only ever adds is a ratchet, and the only way to
 * undo a ratchet on a Device Owner is a factory reset - which is a very
 * expensive way to say "actually, let them change the wallpaper".
 *
 * ONLY RESTRICTIONS IN [MANAGED] ARE EVER CLEARED. Anything else found on the
 * device is left exactly as it is. muster is not the only thing that may ever
 * have set a restriction, and a reconciler that clears everything it does not
 * recognize is one that quietly undoes somebody else's deliberate decision.
 */
object RestrictionPolicy {

    /**
     * The word that has to appear beside a stranding restriction to allow it.
     *
     * Deliberately long and unmistakable. The whole purpose is that it cannot
     * be arrived at by a typo, because the restrictions it guards are the ones
     * whose blast radius is a wipe.
     */
    const val ACCEPT_STRANDING = "accept-stranding"

    /**
     * Config name to platform key, for everything muster will manage.
     *
     * The keys on the right are the values of the `UserManager.DISALLOW_*`
     * constants, which is what `addUserRestriction` and the Bundle returned by
     * `getUserRestrictions` both speak. They are written as literals rather
     * than referenced through `UserManager` so that this whole object stays a
     * plain JVM class the unit tests can exercise without a device.
     *
     * A WRONG LITERAL HERE WOULD BE SILENT: `addUserRestriction` does not
     * reject a key it does not recognize, it just stores something nothing
     * enforces. That is why RestrictionSteward reads the restrictions back
     * after writing them instead of trusting that the call returned.
     *
     * Every value below was checked against AOSP
     * `core/java/android/os/UserManager.java` on 2026-08-19. Re-check if a name
     * is added; do not pattern-match a new one from the ones already here.
     */
    val MANAGED: Map<String, String> = linkedMapOf(
        // The one that already existed, now reachable.
        "DISALLOW_SET_WALLPAPER" to "no_set_wallpaper",
        // Keeps zippie on the handset. A managed app somebody can uninstall
        // from Settings is a managed app that will eventually be missing.
        "DISALLOW_UNINSTALL_APPS" to "no_uninstall_apps",
        // Force-stop and clear-data are the other two ways to defeat an app
        // without uninstalling it, and they leave no trace that says why it
        // stopped reporting.
        "DISALLOW_APPS_CONTROL" to "no_control_apps",
        // Nothing sideloads onto an appliance. Note this does NOT block the
        // agent's own installs: a Device Owner installing through
        // PackageInstaller is not "unknown sources".
        "DISALLOW_INSTALL_UNKNOWN_SOURCES" to "no_install_unknown_sources",
        // Safe mode starts the device with device-admin apps disabled, which
        // is a reboot-shaped hole straight through everything else here.
        "DISALLOW_SAFE_BOOT" to "no_safe_boot",
        // A second user is a second place for policy not to apply.
        "DISALLOW_ADD_USER" to "no_add_user",
        // The clock is load-bearing on this device, not cosmetic. The agent
        // decides whether to renew by comparing now against its own
        // certificate's dates, and IdentityLifecycle is tested against exactly
        // the state a wrong clock produces - "clock behind its own
        // certificate". A device whose time can be moved by hand is one that
        // can be talked out of renewing, or into believing it has lapsed.
        "DISALLOW_CONFIG_DATE_TIME" to "no_config_date_time",
    )

    /**
     * Restrictions that are real, useful, and can stand a device up in a corner
     * it cannot be walked out of remotely. Allowed, but never by accident.
     *
     * Both entries are grounded in findings already recorded in this repo
     * rather than in general caution.
     */
    val STRANDING: Map<String, Stranding> = linkedMapOf(
        // docs/android-constraints.md, measured 2026-08-18: a commercial MDM
        // set exactly this on <device-serial>, and the phone "cannot be freed
        // from Settings" as a result. The supported exit was the vendor's own
        // wipe command. muster has no wipe command.
        "DISALLOW_FACTORY_RESET" to Stranding(
            "no_factory_reset",
            "it removes the last local way back into a device; a phone that " +
                "cannot be reset from Settings can only be recovered by " +
                "whatever still has remote control of it",
        ),
        // docs/android-constraints.md: the 80% charge cap is not writable by
        // any Device Owner at any API level, so it stays an adb step. Turning
        // off debugging features remotely removes the only route to it - and
        // removes it in a way that cannot be undone remotely either, because
        // undoing it is itself a settings change on a device nobody can reach.
        "DISALLOW_DEBUGGING_FEATURES" to Stranding(
            "no_debugging_features",
            "adb is the only route to the 80% charge cap, which no Device " +
                "Owner can set by policy; turning this on remotely closes " +
                "the door from the inside",
        ),
    )

    /**
     * A stranding restriction: its platform key, spelled out, and why it bites.
     *
     * The key is DECLARED rather than derived from the constant name. There is
     * no reliable rule to derive it by: DISALLOW_APPS_CONTROL is
     * `no_control_apps` and not `no_apps_control`, confirmed against AOSP
     * `core/java/android/os/UserManager.java` on 2026-08-19. A key derived
     * wrongly is not an error - it is a restriction the platform stores and
     * never enforces.
     */
    data class Stranding(val key: String, val why: String)

    /** A config line that will not be acted on, and the reason, for logging. */
    data class Refusal(val line: String, val why: String)

    /** What muster wants, once the config file has been read. */
    data class Desired(val keys: Set<String>, val refused: List<Refusal>)

    /**
     * What reconciling would do. Add and clear are platform keys.
     *
     * [changesNothing] is what makes a second boot cheap and, more importantly,
     * what makes "nothing happened" distinguishable from "nothing was
     * configured" in the log.
     */
    data class Plan(
        val add: List<String>,
        val clear: List<String>,
        val refused: List<Refusal>,
    ) {
        val changesNothing: Boolean get() = add.isEmpty() && clear.isEmpty()
    }

    /**
     * Read the config file's text into a set of platform keys.
     *
     * One restriction per line, `#` starts a comment, blank lines ignored. Flat
     * text rather than JSON to match `server-url` beside it: this file is
     * written by a person over adb, and a missing brace should not be the
     * difference between a policy and no policy.
     *
     * AN UNRECOGNIZED NAME IS REFUSED, LOUDLY, NOT SKIPPED. A typo in a
     * restriction name is otherwise indistinguishable from not having asked for
     * it, and the device would come up unrestricted with a config file on it
     * that appears to say otherwise.
     */
    fun read(text: String?): Desired {
        if (text.isNullOrBlank()) return Desired(emptySet(), emptyList())

        val keys = LinkedHashSet<String>()
        val refused = mutableListOf<Refusal>()

        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue

            val words = line.split(Regex("\\s+"))
            val name = words[0].uppercase()
            val accepted = words.drop(1).any { it.equals(ACCEPT_STRANDING, ignoreCase = true) }

            val managed = MANAGED[name]
            if (managed != null) {
                keys.add(managed)
                continue
            }

            val stranding = STRANDING[name]
            if (stranding != null) {
                if (accepted) {
                    // Allowed, because it was spelled out. Stranding
                    // restrictions are deliberately not in MANAGED, so muster
                    // will never CLEAR one on its own - taking one of these
                    // back off is a decision to make in front of the device.
                    keys.add(stranding.key)
                } else {
                    refused.add(
                        Refusal(line, "${stranding.why} - add '$ACCEPT_STRANDING' to allow it")
                    )
                }
                continue
            }

            refused.add(
                Refusal(line, "not a restriction muster manages; known names are ${MANAGED.keys}")
            )
        }
        return Desired(keys, refused)
    }

    /**
     * Work out the difference between what is wanted and what the device has.
     *
     * TWO SOURCES, BECAUSE THERE ARE TWO QUESTIONS, and answering both from one
     * of them gets one of them wrong.
     *
     * What to ADD is decided from what is actually IN FORCE. Deciding it from
     * muster's own record instead would mean setting a restriction once and
     * never looking again: anything the platform quietly declined, or anything
     * cleared out from under us, would read as "already applied" on every
     * subsequent boot. Comparing against reality makes every boot re-assert
     * policy rather than remember having asserted it.
     *
     * What to CLEAR is decided from what MUSTER SET. A restriction that is in
     * force but that muster never set is not muster's to withdraw, and the
     * difference between those two only exists in this second set.
     *
     * @param inForce restrictions actually in effect on the device
     * @param setByUs restrictions this admin has recorded as its own
     */
    fun plan(desired: Desired, inForce: Set<String>, setByUs: Set<String>): Plan {
        val add = desired.keys.filterNot { it in inForce }
        // Only ever withdraw from the managed vocabulary, and only what muster
        // itself put there.
        val clear = MANAGED.values.filter { it in setByUs && it !in desired.keys }
        return Plan(add = add, clear = clear, refused = desired.refused)
    }
}
