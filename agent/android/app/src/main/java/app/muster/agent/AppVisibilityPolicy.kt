package app.muster.agent

/**
 * Which applications an appliance shows the person holding it, and which it
 * hides.
 *
 * WHY AN ALLOWLIST AND NOT A BLOCKLIST. A muster-owned Pixel comes up with the
 * whole consumer launcher on it - Play Store, Gmail, Drive, Photos - on a
 * device whose entire purpose is to be a relay. Naming the ones to remove means
 * a list that is wrong the moment Google adds an app; naming the ones to keep
 * means a device that is right by default and gets no worse.
 *
 * HIDDEN, NOT UNINSTALLED. `DevicePolicyManager.setApplicationHidden` is
 * reversible: the package is still on the device, and the same call with
 * `false` puts the icon back. Uninstalling a system app for a user is a
 * different and much less reversible act, and it is deliberately not what this
 * does.
 *
 * RECONCILING GOES BOTH WAYS, for the same reason it does in RestrictionPolicy.
 * A package taken out of the file gets hidden at the next boot; a package put
 * back gets unhidden. Policy that only hides is a ratchet, and the reverse gear
 * on a ratchet held by a Device Owner is a factory reset.
 *
 * WHERE THIS DIFFERS FROM RestrictionPolicy, deliberately. That object will
 * only ever CLEAR a restriction muster itself set, because a restrictions file
 * is a list of things to turn on out of an open vocabulary and muster is not
 * necessarily the only thing that ever set one. An allowlist is not a list of
 * things to turn on - it is a statement about the WHOLE set of applications a
 * person can see and launch. There is nothing outside it for muster to trespass
 * on, so a package found hidden that the policy says must stay visible is
 * unhidden whoever hid it.
 *
 * THAT RECOVERY REACHES EXACTLY THE PACKAGES THIS CAN HIDE, and no further.
 * AppVisibilitySteward only ever enumerates things with a launcher icon, so
 * that is the whole set - which on a Pixel means Settings and muster itself,
 * and nothing else in [NEVER_HIDDEN]. `pm hide com.google.android.apps
 * .nexuslauncher` from a shell is NOT walked back here, because the launcher
 * has no launcher entry of its own to be found by. Stated this way because the
 * first draft of this comment claimed the opposite, and a recovery mechanism
 * somebody believes in and does not have is worse than one they know they
 * lack.
 *
 * NOTHING HERE TOUCHES ANDROID. Every decision below is a pure function over
 * strings, so the ones that can strand a phone are provable on a laptop. The
 * Android calls, and the reading back of what actually happened, are in
 * AppVisibilitySteward.
 */
object AppVisibilityPolicy {

    /** A config line that will not be acted on, and the reason, for logging. */
    data class Refusal(val line: String, val why: String)

    /**
     * A package muster will not hide, and what hiding it would cost.
     *
     * A SEPARATE TYPE FROM [Refusal] ON PURPOSE. A refusal is muster declining
     * to act on something the file said; this is muster overriding what the
     * file did NOT say. An allowlist asks for a hide by omission, so the only
     * way to say "no, not that one" is to say it about the package rather than
     * about a line - and the reason has to name the cost, because there is no
     * line for the operator to go and look at.
     */
    data class LoadBearing(val packageName: String, val why: String)

    /** What the config file asks to keep visible, once it has been read. */
    data class Desired(val visible: Set<String>, val refused: List<Refusal>)

    /**
     * The load-bearing packages THIS DEVICE named when it was asked.
     *
     * ASKED RATHER THAN ASSUMED, because a table of package names is a guess
     * about a handset somebody else is holding. The launcher on a Pixel is
     * `com.google.android.apps.nexuslauncher` and on AOSP it is
     * `com.android.launcher3`, and on the next device it is neither. Resolving
     * the intents finds whatever this device actually uses, including on a
     * build nobody here has ever seen. [NEVER_HIDDEN] is the belt to this
     * braces, not the other way around.
     *
     * @param own muster's own package name
     * @param home packages answering ACTION_MAIN + CATEGORY_HOME
     * @param settings packages answering `android.settings.SETTINGS`
     * @param setupWizard packages answering ACTION_MAIN + CATEGORY_SETUP_WIZARD
     */
    data class Resolved(
        val own: String,
        val home: Set<String> = emptySet(),
        val settings: Set<String> = emptySet(),
        val setupWizard: Set<String> = emptySet(),
    )

    /**
     * What reconciling would do.
     *
     * [changesNothing] saves the WRITES on a steady-state boot, which is the
     * expensive half - forty `setApplicationHidden` calls are forty trips
     * through the policy engine, each doing real work. It does not save the
     * reads: the plan cannot be computed without asking the platform about
     * every launchable package first, so a boot that changes nothing still
     * costs one query per icon. It is also what makes "nothing happened"
     * distinguishable in the log from "nothing was configured".
     *
     * [withheld] IS THE ONE TO READ WHEN AN APPLIANCE DID NOT GET STRIPPED. It
     * holds what would have been hidden and was not, and [withheldWhy] says
     * why. Empty in the ordinary case. See [plan] for when hiding is withheld
     * and why the two directions are not treated alike.
     */
    data class Plan(
        val hide: List<String>,
        val unhide: List<String>,
        val refused: List<Refusal>,
        val keptVisible: List<LoadBearing>,
        val withheld: List<String> = emptyList(),
        val withheldWhy: List<String> = emptyList(),
    ) {
        val changesNothing: Boolean get() = hide.isEmpty() && unhide.isEmpty()
    }

    /**
     * Packages muster will never hide, whatever the file says, and why.
     *
     * READ THE REASONS, NOT THE NAMES. Each entry is here because hiding it
     * takes away a way of fixing the device, and the reason is the argument for
     * the entry. A name that turns out to be wrong on some handset costs
     * nothing - it protects a package that is not there. A name that is MISSING
     * costs a phone.
     *
     * WHAT IS ACTUALLY REACHABLE FROM HERE, stated so this table is not
     * mistaken for the whole defense. AppVisibilitySteward only ever considers
     * packages that answer ACTION_MAIN + CATEGORY_LAUNCHER - that is, packages
     * with an icon a person can see and tap - so of everything below only
     * Settings and muster itself can be reached by the hiding path at all. The
     * rest are here against a later change that widens what gets enumerated,
     * which is exactly the change that would strand a device silently.
     *
     * PROVENANCE, because half of these cannot be checked from a laptop:
     *
     *   * `com.android.settings`, `com.android.systemui`, `com.android.shell`,
     *     `com.android.provision`, `com.android.launcher3` and
     *     `com.android.permissioncontroller` were each read out of the
     *     `package=` attribute of their own AOSP manifest on 2026-08-19.
     *   * The three `com.google.*` names are the Pixel builds of the same
     *     things. They are not in AOSP, they are widely documented, and NOTHING
     *     HERE HAS MEASURED THEM ON A HANDSET. They are declared anyway because
     *     a wrong name here is inert and a missing one is not.
     */
    val NEVER_HIDDEN: Map<String, String> = linkedMapOf(
        // The one that matters most, and the one the hiding path can actually
        // reach: Settings carries a launcher icon.
        "com.android.settings" to
            "Settings is the last local way into a device: developer options, " +
                "and therefore adb, are behind it. A phone with no Settings " +
                "icon and no adb has no route left that does not start with a " +
                "factory reset",
        // Not launcher-visible today. Here because a device with no shell is a
        // device with nothing on the screen to press.
        "com.android.systemui" to
            "the status bar, the navigation bar and the lock screen are all " +
                "this one package; hiding it leaves a screen with nothing on " +
                "it to touch",
        // adb's own package. `run-as`, and therefore every config file the
        // agent reads, arrives through it - including the file that would undo
        // this policy.
        "com.android.shell" to
            "adb's own package: `run-as` runs in it, which is how every muster " +
                "config file gets onto the device, including the one that " +
                "would undo this",
        // The setup wizard is the one whose loss is not recoverable BY a
        // factory reset - it is what a factory reset comes back to.
        "com.android.provision" to
            "the AOSP setup wizard: it is what a factory-reset device comes " +
                "back to, so hiding it turns the last resort into a phone " +
                "stuck on the welcome screen",
        "com.google.android.setupwizard" to
            "the Pixel setup wizard: it is what a factory-reset device comes " +
                "back to, so hiding it turns the last resort into a phone " +
                "stuck on the welcome screen",
        // Both launchers, in case the HOME resolve comes back empty.
        "com.android.launcher3" to
            "the AOSP launcher: hiding the home screen leaves a device that " +
                "boots to nothing and cannot be asked to start anything",
        "com.google.android.apps.nexuslauncher" to
            "the Pixel launcher: hiding the home screen leaves a device that " +
                "boots to nothing and cannot be asked to start anything",
        // Permission dialogs, and on recent releases the roles and safety
        // center behind them.
        "com.android.permissioncontroller" to
            "every runtime permission dialog on the device is drawn by this " +
                "package; without it nothing can ever be granted anything again",
        "com.google.android.permissioncontroller" to
            "every runtime permission dialog on the device is drawn by this " +
                "package; without it nothing can ever be granted anything again",
        // DELIBERATELY ABSENT: com.android.vending and com.google.android.gms.
        // The Play Store is the headline thing this policy exists to take off
        // the launcher, and neither is a route back into a device.
    )

    /**
     * What a package name is allowed to look like.
     *
     * Two segments minimum, each starting with a letter. Not a full Android
     * package grammar - it exists to catch a line that is obviously not a
     * package name, so that [plan] can decline to strip the device off a file
     * it could not read in full.
     */
    private val PACKAGE_NAME =
        Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    /**
     * Read the config file's text into the set of packages that stay visible.
     *
     * One package per line, `#` starts a comment, blank lines ignored. Flat
     * text rather than JSON, matching `restrictions` and `server-url` beside
     * it: this file is written by a person over adb, and a missing brace should
     * not be the difference between a policy and no policy.
     *
     * A LINE THAT IS NOT A PACKAGE NAME IS REFUSED, LOUDLY, NOT SKIPPED - the
     * same rule as RestrictionPolicy and for a sharper reason. A skipped line
     * in an allowlist does not leave a device unpoliced, it leaves an
     * application hidden that somebody wrote down to keep.
     */
    fun read(text: String?): Desired {
        if (text.isNullOrBlank()) return Desired(emptySet(), emptyList())

        val visible = LinkedHashSet<String>()
        val refused = mutableListOf<Refusal>()

        for (raw in text.lineSequence()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue

            if (PACKAGE_NAME.matches(line)) {
                visible.add(line)
            } else {
                // The `package:` prefix is called out by name because the
                // obvious way to build this file is `adb shell pm list packages
                // > visible-apps`, and every line of that output carries one.
                // Before hiding was withheld on a refusal, that file parsed to
                // an allowlist naming nothing - which is the instruction to
                // strip the entire launcher.
                refused.add(
                    Refusal(
                        line,
                        "not a package name; one package per line, like " +
                            "com.android.settings. `pm list packages` prefixes " +
                            "every line with `package:` - that has to come off",
                    )
                )
            }
        }
        return Desired(visible, refused)
    }

    /**
     * Every package this device must keep, mapped to why, most specific first.
     *
     * The resolved answers go in ahead of [NEVER_HIDDEN] so that the reason
     * logged for a package names the role it was found in on THIS device rather
     * than the generic entry from the table.
     */
    fun loadBearing(resolved: Resolved): Map<String, String> {
        val keep = LinkedHashMap<String, String>()

        fun note(packageName: String, why: String) {
            if (packageName.isNotBlank() && packageName !in keep) keep[packageName] = why
        }

        note(
            resolved.own,
            "muster itself: the status screen is how anybody finds out what " +
                "this device thinks it is, and an agent with no icon cannot be " +
                "opened to be told otherwise",
        )
        for (packageName in resolved.home) {
            note(
                packageName,
                "this device's home screen, as it answered ACTION_MAIN + " +
                    "CATEGORY_HOME; hiding it leaves a device that boots to " +
                    "nothing",
            )
        }
        for (packageName in resolved.settings) {
            note(
                packageName,
                "this device's Settings, as it answered android.settings." +
                    "SETTINGS; it is the last local way to reach developer " +
                    "options and therefore adb",
            )
        }
        for (packageName in resolved.setupWizard) {
            note(
                packageName,
                "this device's setup wizard, as it answered ACTION_MAIN + " +
                    "CATEGORY_SETUP_WIZARD; it is what a factory reset comes " +
                    "back to",
            )
        }
        for ((packageName, why) in NEVER_HIDDEN) note(packageName, why)

        return keep
    }

    /**
     * Work out the difference between what is wanted and what the device has.
     *
     * BOTH ARGUMENTS COME FROM THE DEVICE, and that is what makes every boot
     * re-assert the policy rather than remember having asserted it. [installed]
     * is what the device says is launchable, [hidden] is what the platform says
     * is hidden right now. Neither is muster's own record of what it once did:
     * a record cannot notice a package the platform refused to hide, or one
     * that came back, and would read as "already applied" forever.
     *
     * THERE IS NO WAY TO OVERRIDE A LOAD-BEARING PACKAGE, and unlike
     * `RestrictionPolicy.ACCEPT_STRANDING` there is deliberately no word that
     * unlocks one. Two reasons. There is no line to write the word on - an
     * allowlist asks for a hide by staying silent, and a magic word cannot be
     * attached to a silence. And the stranding is worse in kind: a device with
     * DISALLOW_FACTORY_RESET set still has Settings and still has adb, whereas
     * a device with no Settings icon has neither, and no remote command exists
     * here to put it back.
     *
     * THE TWO DIRECTIONS ARE NOT TREATED ALIKE, and that asymmetry is the point
     * of [Plan.withheld]. Hiding takes something away from somebody holding a
     * phone and is the direction that can strand one; unhiding gives it back
     * and cannot. So when this cannot fully trust what it was told, it
     * withholds the hiding and lets the unhiding run - a device that did not
     * get stripped is a device somebody can go and fix, which is the opposite
     * of what the other choice produces.
     *
     * HIDING IS WITHHELD FOR TWO REASONS, both learned rather than imagined.
     *
     * A LINE THE FILE COULD NOT READ. An allowlist is not a list of things to
     * turn on, where a bad line costs one restriction. Every line that fails to
     * parse is a package that gets HIDDEN, and a file where every line fails is
     * the strongest instruction this format can carry - strip the launcher. The
     * concrete route is not hypothetical: `adb shell pm list packages >
     * visible-apps` is the obvious way to build this file and every line of it
     * begins `package:`, which is not a package name. That file used to parse
     * as "keep nothing".
     *
     * A DEVICE THAT NAMED NO HOME SCREEN. `resolved.home` is the primary
     * protection for the launcher and the table is only the fallback. An empty
     * answer means package visibility is not working, or the manifest's
     * `queries` element does not match what this handset declares - and it
     * arrives as an ABSENCE, which is the one thing nobody notices in a log.
     * Every Android device has a home app, so an empty answer is a broken
     * question, and the answer to a broken question is not to start hiding
     * things.
     *
     * @param installed packages the device reports as having a launcher entry,
     *   hidden ones included
     * @param hidden which of those the platform reports hidden right now
     */
    fun plan(
        desired: Desired,
        installed: Set<String>,
        hidden: Set<String>,
        resolved: Resolved,
    ): Plan {
        val loadBearing = loadBearing(resolved)
        val keep = desired.visible + loadBearing.keys

        // A named package that is not on the device is refused rather than
        // ignored, because it is indistinguishable from a typo - and a typo in
        // this file is not a package that stays visible by accident, it is a
        // package that gets hidden. `app.zippie.compainon` reads exactly like
        // an allowlist that is working.
        //
        // The message names the OTHER cause too. If MATCH_UNINSTALLED_PACKAGES
        // ever stops keeping hidden packages in the enumeration - the one
        // assumption the reverse gear rests on, and one nothing here has
        // measured on a handset - then every package muster already hid answers
        // this way, and an operator trying to put Play Store back would be sent
        // off to check their spelling.
        val unknown = desired.visible
            .filterNot { it in installed }
            .map {
                Refusal(
                    it,
                    "nothing by that name has a launcher entry on this " +
                        "device. Either the line is a typo - check it against " +
                        "`adb shell pm list packages` - or this device is not " +
                        "reporting packages muster has already hidden, which " +
                        "would mean nothing can be unhidden either",
                )
            }

        val refused = desired.refused + unknown

        val withheldWhy = mutableListOf<String>()
        if (refused.isNotEmpty()) {
            withheldWhy.add(
                "${refused.size} line(s) of the allowlist could not be acted " +
                    "on, and every line this file loses is an application it " +
                    "hides - so nothing is hidden until the file reads clean"
            )
        }
        if (resolved.home.isEmpty()) {
            withheldWhy.add(
                "this device named no home screen at all, which means the " +
                    "question was not asked properly rather than that it has " +
                    "none - hiding anything on that footing risks the launcher"
            )
        }

        // Sorted so the plan, the log and the tests all read the same way twice
        // running. A Set's iteration order is not something to hang a diff on.
        val wouldHide = installed.filter { it !in keep && it !in hidden }.sorted()
        // Unhiding always runs. It is the direction that gives something back.
        val unhide = installed.filter { it in keep && it in hidden }.sorted()

        // Only for packages actually on the device: a Pixel has no
        // com.android.provision, and logging a refusal about a package that
        // does not exist buries the ones that do.
        val keptVisible = loadBearing
            .filterKeys { it in installed && it !in desired.visible }
            .map { LoadBearing(it.key, it.value) }

        return Plan(
            hide = if (withheldWhy.isEmpty()) wouldHide else emptyList(),
            unhide = unhide,
            refused = refused,
            keptVisible = keptVisible,
            withheld = if (withheldWhy.isEmpty()) emptyList() else wouldHide,
            withheldWhy = withheldWhy,
        )
    }
}
