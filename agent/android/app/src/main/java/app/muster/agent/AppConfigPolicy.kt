package app.muster.agent

/**
 * What configuration each managed app is given, and which permissions it is
 * granted.
 *
 * WHY THIS EXISTS. muster could own a device, restrict it, and not configure a
 * single application on it. Measured on <device-serial> on 2026-08-19:
 * app.zippie.companion was installed, running, and contributing nothing,
 * because announcing itself to its router needs a write token that only a
 * human could type in. Owning a phone and managing one are different things,
 * and this file is the difference.
 *
 * THE RECEIVING CONTRACT IS SOMEBODY ELSE'S AND IT IS NOT OURS TO REDESIGN.
 * The app reads the bundle through `RestrictionsManager` and merges it over
 * what it has stored, by a rule written down in its own source: a key PRESENT
 * and non-blank overrides local storage; a key ABSENT or blank leaves local
 * storage alone. Managed configuration can add and change; it cannot silently
 * subtract - because Android hands an app an empty Bundle in perfectly
 * ordinary situations, and treating absent as "clear" would wipe a working
 * local configuration on every unmanaged phone.
 *
 * muster's whole job here is to deliver the bundle faithfully. It does not
 * reorder, rename, translate or invent keys, and it has no vocabulary of its
 * own for them - the key names in the config file are the app's key names,
 * spelled the app's way. A management plane that "helpfully" normalizes a key
 * is one that silently configures nothing.
 *
 * A BLANK VALUE IS NOT A WAY TO CLEAR A KEY, and this file refuses one rather
 * than writing it. Under the receiving contract a blank is indistinguishable
 * from absent, so a blank line reads to the operator as "clear this" and does
 * nothing at all. Deleting the line is the honest way to stop pushing a key.
 *
 * EVERY VALUE IS TREATED AS A CREDENTIAL. muster cannot know which of an app's
 * settings are secret - `announceToken` and `ddClientToken` are, `ddSite` is
 * not, and the next app will draw that line somewhere else - so no value ever
 * appears in a refusal, a plan, a log line or a `toString` anywhere in this
 * file or its steward. Only key names do. That is why the data classes below
 * override `toString` even though they are data classes: the generated one
 * prints every field, and `BootReceiver` logs the outcome of every step.
 */
object AppConfigPolicy {

    /** Set a string value on an app. `set <package> <key> <value...>` */
    const val SET = "set"

    /** Set a boolean. `set-bool <package> <key> true|false` */
    const val SET_BOOL = "set-bool"

    /** Grant a runtime permission. `grant <package> <permission>` */
    const val GRANT = "grant"

    /**
     * Poke a component so a freshly configured app acts on its configuration.
     * See [Wake] for why this exists at all.
     */
    const val WAKE = "wake"

    /** Printed where a configured value would otherwise appear. */
    const val REDACTED = "<value>"

    /**
     * A package name, roughly: at least two dot-separated segments.
     *
     * This catches a MALFORMED package, not a WRONG one. Nothing here can tell
     * `app.zippie.companion` from `app.zippie.compainon`, and the platform
     * stores restrictions for a package that is not installed without
     * complaining - so a typo is invisible until somebody asks why the app is
     * not configured. `AppConfigSteward` reads the bundle back for that
     * reason, and even that only proves the bundle exists, not that anything
     * is reading it.
     */
    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$")

    /** A config line that will not be acted on, and the reason, for logging. */
    data class Refusal(val line: String, val why: String)

    /**
     * One app's managed configuration.
     *
     * [values] holds Strings and Booleans only, in the order the file named
     * them. Order is kept for the log and for review; the platform Bundle is
     * unordered and the app reads by key, so it changes nothing on the device.
     */
    data class AppConfig(
        val packageName: String,
        val values: Map<String, Any>,
        val grants: List<String>,
    ) {
        override fun toString(): String =
            "$packageName keys=${values.keys.toList()} grants=$grants"
    }

    /** What the config file asked for, once read. */
    data class Desired(
        val apps: List<AppConfig>,
        val refused: List<Refusal>,
        val wakes: List<Wake> = emptyList(),
    ) {
        override fun toString(): String =
            "apps=$apps wakes=${wakes.map { it.packageName }} " +
                "refused=${refused.map { it.line }}"
    }

    /**
     * One `setApplicationRestrictions` call.
     *
     * [values] is the WHOLE bundle to write, not a delta, because that call
     * replaces the bundle rather than merging into it. [setKeys] and
     * [droppedKeys] exist so the log can say what actually changed - "wrote 9
     * keys" on every boot is indistinguishable from a device that is drifting.
     */
    data class Write(
        val packageName: String,
        val values: Map<String, Any>,
        val setKeys: List<String>,
        val droppedKeys: List<String>,
    ) {
        override fun toString(): String = "$packageName set=$setKeys dropped=$droppedKeys"
    }

    /** One runtime permission to grant to one package. */
    data class Grant(val packageName: String, val permission: String)

    /** What reconciling would do. */
    data class Plan(
        val writes: List<Write>,
        val grants: List<Grant>,
        val refused: List<Refusal>,
    ) {
        val changesNothing: Boolean get() = writes.isEmpty() && grants.isEmpty()

        override fun toString(): String =
            "writes=$writes grants=$grants refused=${refused.map { it.line }}"
    }

    /**
     * Read the config file's text.
     *
     * Verb first, then the package, then the key, then the value:
     *
     *     # a LAN-local relay leg
     *     set       app.zippie.companion homeHost       192.168.1.10
     *     set-bool  app.zippie.companion autoStartRelay true
     *     grant     app.zippie.companion android.permission.POST_NOTIFICATIONS
     *
     * THE PACKAGE IS ON EVERY LINE and there is no section header, which is
     * the one place this format is deliberately more verbose than it looks
     * like it should be. A mistyped `[package]` header silently assigns every
     * key beneath it to the wrong app, and the key most likely to be under one
     * is a write token. A wrong package on one line is one wrong line.
     *
     * A COMMENT IS A WHOLE LINE, and a `#` after a value is part of the value.
     * The restrictions file beside this one strips trailing comments; this one
     * must not, because values here are credentials and truncating one at a
     * `#` produces a device that authenticates with something almost right -
     * which looks like a server problem for as long as anybody is willing to
     * look.
     *
     * AN UNRECOGNIZED LINE IS REFUSED, LOUDLY, NOT SKIPPED, exactly as in
     * RestrictionPolicy: a silently ignored line leaves an app unconfigured
     * with a file on the device that reads as though it is not.
     */
    fun read(text: String?): Desired {
        if (text.isNullOrBlank()) return Desired(emptyList(), emptyList())

        val order = LinkedHashSet<String>()
        val values = LinkedHashMap<String, LinkedHashMap<String, Any>>()
        val grants = LinkedHashMap<String, MutableList<String>>()
        val wakes = mutableListOf<Wake>()
        val refused = mutableListOf<Refusal>()

        var number = 0
        for (raw in text.lineSequence()) {
            number += 1
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue

            // limit=4 so the value keeps its own spacing and its own '#'.
            val words = line.split(Regex("\\s+"), limit = 4)
            val at = safeLine(number, words)
            val verb = words[0].lowercase()

            if (verb == WAKE) {
                // `wake <package> <component> <action>`. The package is stated
                // SEPARATELY from the component so muster knows WHEN to send it
                // - after configuring that package - and so one line cannot
                // name one app and poke another.
                val parts = line.split(Regex("\\s+"))
                if (parts.size != 4) {
                    refused.add(Refusal(at, "expected: $WAKE <package> <component> <action>"))
                    continue
                }
                val pkg = parts[1]
                val component = parts[2]
                val action = parts[3]
                if (!component.contains('/')) {
                    // `ComponentName.unflattenFromString` returns NULL rather
                    // than throwing on a string with no slash, so an unrefused
                    // typo here is a wake that silently never happens.
                    refused.add(
                        Refusal(at, "'$component' is not a component: expected package/Class")
                    )
                    continue
                }
                if (component.substringBefore('/') != pkg) {
                    refused.add(Refusal(at, "'$component' does not belong to '$pkg'"))
                    continue
                }
                wakes.add(Wake(pkg, component, action))
                continue
            }

            if (verb != SET && verb != SET_BOOL && verb != GRANT) {
                refused.add(
                    Refusal(
                        at,
                        "not something muster can do; lines start with " +
                            "'$SET', '$SET_BOOL' or '$GRANT'",
                    )
                )
                continue
            }

            if (words.size < 3) {
                refused.add(
                    Refusal(
                        at,
                        "too short: $verb needs a package and " +
                            if (verb == GRANT) "a permission" else "a key",
                    )
                )
                continue
            }

            val packageName = words[1]
            if (!PACKAGE.matches(packageName)) {
                refused.add(Refusal(at, "the second word is not a package name"))
                continue
            }

            if (verb == GRANT) {
                if (words.size > 3) {
                    refused.add(Refusal(at, "$GRANT takes exactly one permission"))
                    continue
                }
                order.add(packageName)
                val held = grants.getOrPut(packageName) { mutableListOf() }
                // A repeated grant is not a disagreement, unlike a repeated
                // key: granting twice asks for exactly the same thing. Kept
                // once so the log does not report it twice.
                if (words[2] !in held) held.add(words[2])
                continue
            }

            val key = words[2]
            if (words.size < 4) {
                refused.add(
                    Refusal(
                        at,
                        // The third word is NOT named here, and that is the same
                        // decision safeLine makes: on a three-word line it is
                        // either a key with its value missing or a value with
                        // its key missing, and nothing can tell which.
                        "no value. The third word is a key with no value after " +
                            "it, or a value with no key before it. Note that a " +
                            "blank value is not a way to clear a key either: the " +
                            "app cannot tell blank from absent and leaves what it " +
                            "has stored alone. Delete the line instead",
                    )
                )
                continue
            }

            val held = values[packageName]
            if (held != null && key in held) {
                refused.add(
                    Refusal(
                        at,
                        "'$key' is already set for $packageName earlier in this " +
                            "file; one of the two lines would be invisible",
                    )
                )
                continue
            }

            val value: Any = if (verb == SET_BOOL) {
                when (words[3].lowercase()) {
                    "true" -> true
                    "false" -> false
                    else -> {
                        refused.add(Refusal(at, "$SET_BOOL takes 'true' or 'false'"))
                        continue
                    }
                }
            } else {
                words[3]
            }

            // Stored only once the line is known good, so a package whose every
            // line was refused never gets an entry at all.
            order.add(packageName)
            values.getOrPut(packageName) { LinkedHashMap() }[key] = value
        }

        val apps = order.map { packageName ->
            AppConfig(
                packageName = packageName,
                values = values[packageName].orEmpty(),
                grants = grants[packageName].orEmpty(),
            )
        }
        return Desired(apps, refused, wakes)
    }

    /**
     * Work out what has to be written, given what each app already carries.
     *
     * THE WHOLE BUNDLE IS REWRITTEN WHEN ANY PART OF IT IS WRONG, because
     * `setApplicationRestrictions` replaces rather than merges. That also
     * settles what happens to a key deleted from the file: it leaves the
     * bundle, the app then sees it absent, and under the receiving contract
     * the app keeps whatever it has stored. muster stops pushing a value; it
     * does not reach in and blank one.
     *
     * NOTHING ELSE ON THE DEVICE CAN WRITE THAT BUNDLE. Application
     * restrictions are settable only by a device or profile owner, and this
     * agent is the device owner, so the bundle is muster's own record and
     * replacing it wholesale tramples nobody. That is the difference from
     * `RestrictionPolicy`, which is careful never to clear a user restriction
     * it did not set, because there a second admin genuinely may have.
     *
     * @param current what `getApplicationRestrictions` returns now, per package
     * @param alreadyGranted grants the device already has in force
     */
    fun plan(
        desired: Desired,
        current: Map<String, Map<String, Any?>>,
        alreadyGranted: Set<Grant>,
    ): Plan {
        val writes = mutableListOf<Write>()
        for (app in desired.apps) {
            // AN APP THE FILE GIVES NO VALUES TO IS NOT CONFIGURED BY MUSTER,
            // and is left exactly as it is - which is what happens to an app
            // the file does not mention at all. Writing an empty bundle here
            // instead would make `grant app.example.thing SOME_PERMISSION` a
            // line that silently withdraws that app's whole configuration, so
            // deleting one line from the file would do less damage than
            // deleting two. There is therefore no way to blank an app's bundle
            // from this file, and nothing is lost by that: under the receiving
            // contract an absent key means "keep what you have stored", so
            // withdrawing a bundle changes nothing an app can observe. Pushing
            // a new value is how a wrong one is corrected.
            if (app.values.isEmpty()) continue

            val now = current[app.packageName].orEmpty()
            val setKeys = app.values.keys.filter { now[it] != app.values[it] }
            val dropped = now.keys.filter { it !in app.values.keys }
            if (setKeys.isEmpty() && dropped.isEmpty()) continue
            writes.add(
                Write(
                    packageName = app.packageName,
                    values = app.values,
                    setKeys = setKeys,
                    droppedKeys = dropped,
                )
            )
        }

        val grants = desired.apps
            .flatMap { app -> app.grants.map { Grant(app.packageName, it) } }
            .filterNot { it in alreadyGranted }

        return Plan(writes = writes, grants = grants, refused = desired.refused)
    }

    /**
     * A line as it may appear in a log, which is a much smaller thing than the
     * line as it was written.
     *
     * THE LINE NUMBER IS WHAT IDENTIFIES A REFUSAL, and the content is only
     * ever added when muster can prove it is not a credential. A line it
     * cannot parse might be a token somebody pasted on its own, and there is
     * no way to tell that from a typo of `set` - quoting it back to explain
     * why it was refused would be a strange way to protect it. So:
     *
     *   the verb     only when it is one of muster's three
     *   the package  only when it is shaped like a package name
     *   the key      only when the verb and the package were both good
     *   the value    never
     *
     * The operator loses nothing they cannot get by opening the file at the
     * line number.
     */
    private fun safeLine(number: Int, words: List<String>): String {
        val shown = mutableListOf<String>()
        val verb = words[0].lowercase()
        if (verb == SET || verb == SET_BOOL || verb == GRANT) {
            shown.add(verb)
            val packageName = words.getOrNull(1)
            if (packageName != null && PACKAGE.matches(packageName)) {
                shown.add(packageName)
                // THE THIRD WORD IS ONLY PROVABLY A KEY WHEN A FOURTH FOLLOWS.
                // Otherwise it may be the value with the key missing -
                // `announceToken=<token>` is the syntax every other config
                // format on earth uses, so it is the likeliest thing an
                // operator types here, and quoting it to explain the refusal
                // would put the token in logcat at every boot from then on.
                //
                // `grant` looks like it deserves an exception, because it takes
                // no value and its third word is always a permission. It does
                // not: a three-word `grant` with a valid package is ACCEPTED,
                // so no refusal can ever carry one. An exception for it would
                // be a branch nothing reaches.
                if (words.size > 3) {
                    words.getOrNull(2)?.let { shown.add(it) }
                    shown.add(REDACTED)
                }
            }
        }
        return if (shown.isEmpty()) "line $number" else "line $number: ${shown.joinToString(" ")}"
    }

    /**
     * What to say about applications Android may be freezing.
     *
     * MUSTER REPORTS THIS AND CANNOT FIX IT, which is worth stating rather than
     * hiding. There is no public Device Owner API to allowlist an app from
     * battery optimization - checked against android-36's own
     * `DevicePolicyManager`, which contains nothing matching "exempt", and
     * `PowerManager` exposes only the READ. Only the app itself can ask, with a
     * dialog a person taps.
     *
     * So why say anything? Because `isIgnoringBatteryOptimizations` is readable
     * by anyone, and the alternative is inference. A zippie bond leg spent a
     * week with its socket bound and nothing servicing it: the relay had
     * started, the token was good, it announced every fifteen seconds, and
     * Android had frozen the process. The only way to know was to probe the UDP
     * port from the router and notice nothing answered.
     *
     * "The app asked for an exemption" and "a grant actually took on THIS
     * handset" are different facts, and they have been indistinguishable. A
     * prompt in the app proves the first. This proves the second.
     *
     * @param exempt package name to whether it is exempt. A package ABSENT from
     *   the map could not be read and is deliberately not reported either way -
     *   a fabricated state here would poison the one line meant to be trusted.
     */
    fun batteryConcerns(exempt: Map<String, Boolean>): List<String> =
        exempt.filterValues { !it }.keys.sorted().map { packageName ->
            "$packageName is NOT exempt from battery optimization, so Android " +
                "may freeze it while it looks configured and running. muster " +
                "cannot grant this - no Device Owner API exists - the app has " +
                "to ask for it."
        }

    /**
     * A component to poke after configuring an application.
     *
     * WHY MUSTER SENDS THIS AT ALL (muster#82). A freshly installed application
     * that has never been launched sits in Android's STOPPED state and receives
     * NO broadcasts - including BOOT_COMPLETED. So an app muster installs and
     * configures can sit there permanently, never starting, with its own boot
     * receiver never firing and nothing in any log to say why. That happened:
     * zippie was installed, correctly configured, and silent across a reboot.
     *
     * An EXPLICIT intent carrying `FLAG_INCLUDE_STOPPED_PACKAGES` reaches a
     * stopped app and takes it out of that state. It is the only mechanism that
     * does - there is no Device Owner API for it, checked against android-36's
     * own DevicePolicyManager.
     *
     * THE COMPONENT IS NAMED IN POLICY RATHER THAN GUESSED, because it is a
     * contract with another application's manifest. A convention muster
     * invented would break silently the first time that app renamed a class,
     * and "silently" is the whole problem this exists to solve.
     */
    data class Wake(
        val packageName: String,
        val component: String,
        val action: String,
    )
    /**
     * Should this package be woken?
     *
     * NOT "did the configuration change". That question produced a permanent
     * failure: an install completes asynchronously, so the wake that follows a
     * configuration write can be aimed at a package that does not exist yet,
     * and Android neither queues it nor reports the miss. The next pass then
     * finds the configuration unchanged, short-circuits, and the app is never
     * told - forever.
     *
     * The question that works is "has THIS package been told about THIS
     * configuration", which is false both when the configuration is new AND
     * when a previous wake could not have landed.
     */
    /**
     * How a ledger entry is stored: the boot it was written on, then the
     * fingerprint it recorded.
     *
     * STAMPED RATHER THAN CLEARED. The obvious way to make a reboot un-tell
     * every app is to wipe the ledger from the boot receiver - and that binds
     * correctness to a broadcast arriving. `BOOT_COMPLETED` can be minutes
     * late under boot pressure, can be preceded by other readers of this
     * ledger, and for a stopped package may not arrive at all; any of those
     * leaves last boot's records being read as current. Stamping moves the
     * question to read time, where it cannot be missed.
     *
     * It also settles the double-delivery problem for free: the receiver runs
     * for both LOCKED_BOOT_COMPLETED and BOOT_COMPLETED, and both share a boot
     * count, so the second pass sees the first pass's records rather than
     * re-waking everything.
     */
    fun ledgerValue(bootCount: Long, fingerprint: String): String = "$bootCount:$fingerprint"

    /**
     * The fingerprint a stored entry attests to, or null if it attests to
     * nothing usable - a malformed entry, or one written before this boot.
     *
     * A record from an earlier boot is not merely stale, it is FALSE: it says
     * an app was told, and telling it exists to get it running, and the reboot
     * stopped it. Returning null is what makes the next pass wake it again.
     */
    fun ledgerFingerprint(stored: String?, bootCount: Long): String? {
        val at = stored?.indexOf(':') ?: return null
        if (at <= 0) return null
        val whenBooted = stored.substring(0, at).toLongOrNull() ?: return null
        if (whenBooted != bootCount) return null
        return stored.substring(at + 1).ifEmpty { null }
    }

    fun shouldWake(
        wake: Wake,
        installed: Set<String>,
        wokenFor: String?,
        fingerprint: String,
    ): Boolean = wake.packageName in installed && wokenFor != fingerprint

    /**
     * A stable identity for what ONE wake target is supposed to have been told.
     *
     * DERIVED FROM `Desired`, NOT `Plan`, and that distinction is load-bearing.
     * `Plan` is a DELTA: `plan()` drops an app whose values already match
     * (`if (setKeys.isEmpty() && dropped.isEmpty()) continue`) and filters out
     * grants already in force. So a fingerprint taken from the plan is one
     * value on the pass that writes and a different one on every steady-state
     * pass afterwards - which would wake the app every fifteen minutes forever,
     * restarting a working relay and spending battery to tell it something it
     * already knows. `Desired` is the full intent and does not move.
     *
     * PER TARGET, not per estate and not per package. An estate-wide value
     * re-woke every managed app whenever any one was edited. A per-PACKAGE
     * value is not enough either: a package may declare more than one wake, and
     * recording under the package name lets a send to one component mark the
     * others as told - including when the other one FAILED. That is the
     * permanent miss this mechanism exists to close.
     *
     * LENGTH-PREFIXED and SHA-256. Managed configuration values are routinely
     * JSON or URLs carrying ',' and '=', so a delimiter-joined encoding renders
     * {"x":"y","z":"w"} and {"x":"y,z=w"} identically - and two configurations
     * sharing a fingerprint means the second reads as already-delivered and is
     * never sent. `hashCode()` is 32 bits, which collides around 65k
     * configurations by the birthday bound; a digest costs nothing here.
     */
    fun fingerprintFor(wake: Wake, desired: Desired): String {
        val app = desired.apps.firstOrNull { it.packageName == wake.packageName }
        val parts = buildList {
            for ((k, v) in (app?.values ?: emptyMap()).entries.sortedBy { e -> e.key }) {
                add("set"); add(k); add(v.toString())
            }
            for (g in (app?.grants ?: emptyList()).sorted()) {
                add("grant"); add(g)
            }
            add("wake"); add(wake.component); add(wake.action)
        }
        val encoded = parts.joinToString("") { "${it.length}:$it" }
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(encoded.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

}
