package app.muster.agent

/**
 * Which applications this device is told to carry, and whether to act.
 *
 * WHY THIS EXISTS (muster#67). muster hid the Play Store because an appliance
 * has no business showing one, and thereby took responsibility for updates it
 * could not perform. The only route from a built APK to a handset was a factory
 * reset and a QR scan - which also threw away the device's identity, its policy
 * and its enrolment, to change a file.
 *
 * WHAT MAKES THIS SAFE IS THE DIGEST, and it is the reason this object refuses
 * a line without one rather than warning about it. An agent that installs
 * unverified bytes handed to it over a network is worse than an agent that
 * cannot install at all: it is a remote code execution primitive with a
 * certificate. The bytes are checked against the digest named HERE, in a policy
 * file the device fetched over its own identity - not against anything the
 * server said while handing them over.
 *
 * The file is line-oriented like every other policy file:
 *
 *     install app.zippie.companion zippie-0.1.0.apk sha256 3f2a... version 72
 *
 * `version` is the `versionCode` the APK declares. It is what makes this
 * idempotent without hashing whatever is already on the device: a phone
 * compares the number it is carrying against the number it is told, and a
 * device already at or past it does nothing at all. Without that, a boot means
 * re-downloading and reinstalling twelve megabytes.
 */
object AppInstallPolicy {

    /** muster's own package, which is the one case that ends this process. */
    const val OWN_PACKAGE = "app.muster.agent"

    private const val INSTALL = "install"

    /**
     * The opt-in that allows muster to UNINSTALL before installing.
     *
     * ONE LINE AT A TIME, AND NEVER INFERRED. Android identifies an app by its
     * signing certificate for as long as it is installed, so an APK signed by a
     * different key cannot replace it - and the only way past that is to remove
     * the installed copy, which destroys its data. Deciding that for an
     * operator because an install failed would be muster choosing data loss on
     * their behalf.
     *
     * It is also narrow by construction: the steward only acts on it when the
     * installed signer ACTUALLY differs from the APK's. On the ordinary upgrade
     * path - same key, higher version - the flag is inert, so leaving it on a
     * line costs nothing and does nothing.
     *
     * What it is for: quadseven/zippie's PR gate signs its APK with a keypair
     * it generates per run and deletes when the job ends. A handset that
     * received one is welded to that exact build FOREVER - the key to sign a
     * successor does not exist anywhere. Without this, the only exit is a
     * factory reset.
     */
    private const val REPLACE = "replace-if-signer-differs"
    private const val SHA256 = "sha256"
    private const val VERSION = "version"

    private val HEX = Regex("^[0-9a-f]{64}$")
    private val ASSET = Regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
    // Android package names: labels separated by dots, each starting with a
    // letter. Deliberately narrower than the platform allows - anything odder
    // than this in a policy file is a typo, and a typo here is a download.
    private val PACKAGE = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

    /** A line muster could not act on, kept with the reason. */
    data class Refusal(val line: String, val why: String)

    /**
     * @param asset what to fetch from muster's asset store
     * @param digest lowercase hex sha256 the fetched bytes must have
     * @param versionCode the versionCode those bytes declare
     */
    data class Wanted(
        val packageName: String,
        val asset: String,
        val digest: String,
        val versionCode: Long,
        /** May muster remove an installed copy signed by a different key? */
        val replaceIfSignerDiffers: Boolean = false,
    )

    data class Desired(val wanted: List<Wanted>, val refused: List<Refusal>)

    data class Install(val wanted: Wanted, val why: String) {
        val packageName: String get() = wanted.packageName
    }

    /**
     * @param install what to fetch and install, IN THE ORDER TO DO IT
     * @param current packages already at or past the version named
     */
    data class Plan(
        val install: List<Install> = emptyList(),
        val current: List<String> = emptyList(),
        val refused: List<Refusal> = emptyList(),
    )

    fun read(text: String?): Desired {
        if (text.isNullOrBlank()) return Desired(emptyList(), emptyList())
        val wanted = LinkedHashMap<String, Wanted>()
        val refused = mutableListOf<Refusal>()

        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val words = line.split(Regex("\\s+"))

            fun refuse(why: String) = refused.add(Refusal(line, why))

            if (words[0].lowercase() != INSTALL) {
                refuse("not something the install file can say; lines start with '$INSTALL'")
                continue
            }
            if (words.size !in 7..8 || words[3] != SHA256 || words[5] != VERSION) {
                refuse(
                    "expected: $INSTALL <package> <asset> $SHA256 <hex> $VERSION <code> " +
                        "[$REPLACE]"
                )
                continue
            }
            if (words.size == 8 && words[7] != REPLACE) {
                // NAMED EXACTLY OR REFUSED. A misspelling of a flag that
                // authorizes DELETING AN APP'S DATA must not be read as its
                // absence: that is the reading where a typo silently withholds
                // the one thing the line was added to do, and the operator sees
                // an install that keeps failing for no stated reason.
                refuse("'${words[7]}' is not $REPLACE")
                continue
            }
            val replace = words.size == 8
            val (pkg, asset, digest, version) = listOf(words[1], words[2], words[4], words[6])
            if (!PACKAGE.matches(pkg)) {
                refuse("'$pkg' is not a package name")
                continue
            }
            if (replace && pkg == OWN_PACKAGE) {
                // THE ONE PACKAGE THIS MAY NEVER APPLY TO, AND IT IS
                // UNRECOVERABLE.
                //
                // Uninstalling muster removes the Device Owner, and Device
                // Owner cannot be re-established on a provisioned device - it
                // takes a factory reset. So a line that told muster to replace
                // ITSELF this way would unmanage the handset permanently and
                // destroy every other application's data on the way back,
                // which is precisely the outcome this flag exists to avoid.
                //
                // Refused at READ time rather than guarded in the steward: the
                // steward is where the decision would be one boolean away from
                // being made, and this is not a decision that should be
                // reachable at all. muster's own line reaching the installer
                // with this flag set should be impossible, not merely handled.
                //
                // A signer change on muster itself is a real situation with a
                // real answer, and the answer is a wipe - which is why
                // docs/signing-ceremony.md exists and why it says to do the
                // ceremony BEFORE a phone is enrolled.
                refuse(
                    "$REPLACE cannot be used on $OWN_PACKAGE: uninstalling muster " +
                        "removes Device Owner, which cannot be restored without a " +
                        "factory reset"
                )
                continue
            }
            if (!ASSET.matches(asset)) {
                refuse("'$asset' is not a name an asset can have")
                continue
            }
            if (!HEX.matches(digest)) {
                refuse("'$digest' is not a lowercase hex sha256")
                continue
            }
            val code = version.toLongOrNull()
            if (code == null || code < 0) {
                refuse("'$version' is not a versionCode")
                continue
            }
            if (wanted.containsKey(pkg)) {
                // REFUSED RATHER THAN LAST-ONE-WINS. Two lines for one package
                // is an operator who edited a file and did not finish, and
                // silently picking one of them installs software nobody chose.
                refuse("'$pkg' was already named on an earlier line")
                continue
            }
            wanted[pkg] = Wanted(pkg, asset, digest, code, replaceIfSignerDiffers = replace)
        }
        return Desired(wanted.values.toList(), refused)
    }

    /**
     * @param installed packageName to the versionCode the device is carrying
     *
     * A REFUSED LINE DOES NOT WITHHOLD THE OTHERS, which is deliberately the
     * opposite of `AppVisibilityPolicy`. Hiding is destructive and a typo there
     * strips a phone, so one bad line withholds the whole plan. Installing is
     * ADDITIVE: withholding every install because one line is wrong denies a
     * device the software it needs in order to protect it from having extra
     * software.
     */
    /**
     * Which half of the install work a pass is doing.
     *
     * WHY THERE ARE TWO PASSES (muster#81). Proved on a handset: zippie was
     * installed and its managed configuration was NOT applied in the same
     * check-in, because `app-config` runs before installing and the package did
     * not exist when it ran. The app sat installed and unconfigured until the
     * next pass.
     *
     * Reordering wholesale is not the fix. Installing MUSTER ends the process,
     * so that has to stay last and anything queued behind it never runs. So the
     * work splits: everything else early, where its configuration and its
     * launcher visibility can be applied in the same breath, and muster alone
     * at the end.
     */
    enum class Only {
        /** Every named package except muster. Safe to run before anything. */
        OTHERS,

        /** Muster alone. Ends the process, so nothing may follow it. */
        SELF,

        /** Both, for a caller that is not splitting the work. */
        ALL,
    }

    fun plan(
        desired: Desired,
        installed: Map<String, Long>,
        only: Only = Only.ALL,
    ): Plan {
        val install = mutableListOf<Install>()
        val current = mutableListOf<String>()

        for (want in desired.wanted) {
            val have = installed[want.packageName]
            when {
                have == null ->
                    install.add(Install(want, "not installed"))
                have < want.versionCode ->
                    install.add(Install(want, "carrying $have, told ${want.versionCode}"))
                // AT OR PAST IT IS LEFT ALONE. Android refuses a downgrade, so
                // attempting one is a guaranteed failure reported at every
                // boot - and a newer version is also what a hand-installed
                // build looks like, which muster stamping on is a worse
                // surprise than leaving it.
                else -> current.add(want.packageName)
            }
        }

        // MUSTER LAST, AND THE ORDER IS LOAD-BEARING. Committing this app's own
        // session ends this process, so anything queued behind it never runs -
        // a boot that updated the agent would silently skip every other
        // application, and the next boot would find the agent current and skip
        // them again. Sorted stably so the rest keep the operator's order.
        //
        // The ordering still matters within Only.ALL, and the SCOPE is what a
        // caller splitting the work uses instead.
        val (mine, theirs) = install.partition { it.packageName == OWN_PACKAGE }
        val scoped = when (only) {
            Only.OTHERS -> theirs
            Only.SELF -> mine
            Only.ALL -> theirs + mine
        }
        return Plan(install = scoped, current = current, refused = desired.refused)
    }
}
