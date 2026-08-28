package app.muster.agent

/**
 * Which image this device should carry, on which surfaces, and whether to act.
 *
 * Whether the operator may then CHANGE it is a restriction, and restrictions
 * are decided in one place - see RestrictionPolicy. This object used to answer
 * both questions and the second answer was never asked for by anything.
 *
 * WHY THIS IS NOT `setWallpaper()` ON EVERY BOOT. Decoding and applying a
 * full-resolution bitmap costs real time and memory on a phone that has just
 * come up, and doing it unconditionally means a device that fights anyone who
 * ever changes it. So the decision is separated from the doing, keyed on a
 * digest of the image, and it is idempotent: same image, same surfaces, already
 * applied, nothing happens.
 *
 * The digest is of the SOURCE BYTES rather than of a filename or a timestamp.
 * A filename says nothing about content, and a device that re-applies because a
 * file was touched is the unconditional version wearing a disguise.
 *
 * WHERE THE CONFIGURATION COMES FROM (muster#45). A managed text file named
 * `wallpaper`, fetched over this device's own identity like every other policy
 * file, which NAMES an asset and the digest to expect:
 *
 *     image wall.png sha256 3f2a...
 *     surfaces system lock
 *
 * The bytes travel separately, over their own route, and are checked against
 * the digest named here. So a substituted asset is caught by a file the device
 * fetched over its identity rather than trusted because it arrived.
 */
object WallpaperPolicy {

    /**
     * A screen a wallpaper can be on.
     *
     * TWO, AND NOT A BOOLEAN, because muster#41 is exactly the bug a boolean
     * caused: `setBitmap(bitmap)` sets FLAG_SYSTEM alone, so a managed
     * appliance carried its own background behind the apps and a stock one on
     * the screen anybody walking past actually sees. On a device that is
     * deliberately not a personal phone, the lock screen is the surface that
     * says whose it is.
     */
    enum class Surface(val configName: String) {
        SYSTEM("system"),
        LOCK("lock"),
    }

    /**
     * Both, when the file does not say.
     *
     * An appliance wants both and that is the ordinary case. It is a DEFAULT
     * rather than a hardcoding because a handset in somebody's pocket and a
     * display on a charger want different things - the same reasoning that made
     * locking the wallpaper opt-in.
     */
    val DEFAULT_SURFACES: Set<Surface> = setOf(Surface.SYSTEM, Surface.LOCK)

    /** A line muster could not act on, kept with the reason. */
    data class Refusal(val line: String, val why: String)

    /**
     * @param asset the name to fetch from muster, or null if none is configured
     * @param digest lowercase hex sha256 the fetched bytes must have
     * @param surfaces which screens to put it on
     */
    data class Desired(
        val asset: String? = null,
        val digest: String? = null,
        val surfaces: Set<Surface> = DEFAULT_SURFACES,
        val refused: List<Refusal> = emptyList(),
    )

    private val HEX = Regex("^[0-9a-f]{64}$")
    private val NAME = Regex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

    /**
     * Read the `wallpaper` file, refusing lines rather than ignoring them.
     *
     * A SILENTLY IGNORED LINE IS THE FAILURE THIS AVOIDS, and it is the same
     * one RestrictionPolicy and AppVisibilityPolicy avoid: an operator who
     * mistypes `surfacs lock` and is told nothing has a device that reads as
     * configured and is not. Every refusal reaches the status screen, because
     * `WallpaperSteward.Outcome` carries them and a concern is shown.
     *
     * A FILE WITH NO `image` LINE CONFIGURES NOTHING, deliberately, even if it
     * names surfaces. Surfaces without an image is an instruction to put
     * nothing somewhere.
     */
    fun read(text: String?): Desired {
        if (text == null) return Desired()
        var asset: String? = null
        var digest: String? = null
        var surfaces: Set<Surface>? = null
        val refused = mutableListOf<Refusal>()

        for (raw in text.lines()) {
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val words = line.split(Regex("\\s+"))
            when (words[0]) {
                "image" -> {
                    // `image <name> sha256 <hex>`. THE DIGEST IS REQUIRED and
                    // not optional-with-a-warning: an image named without one
                    // is an instruction to apply whatever the server hands
                    // over, which is the whole property this file exists to
                    // provide.
                    if (words.size != 4 || words[2] != "sha256") {
                        refused.add(Refusal(line, "expected: image <name> sha256 <hex>"))
                    } else if (!NAME.matches(words[1])) {
                        refused.add(Refusal(line, "'${words[1]}' is not a name an asset can have"))
                    } else if (!HEX.matches(words[3])) {
                        refused.add(Refusal(line, "'${words[3]}' is not a lowercase hex sha256"))
                    } else if (asset != null) {
                        refused.add(Refusal(line, "a device carries one wallpaper; '$asset' was already named"))
                    } else {
                        asset = words[1]
                        digest = words[3]
                    }
                }
                "surfaces" -> {
                    val named = words.drop(1)
                    if (named.isEmpty()) {
                        refused.add(Refusal(line, "name at least one of: system, lock"))
                    } else {
                        val known = Surface.entries.associateBy { it.configName }
                        val unknown = named.filterNot { it in known }
                        if (unknown.isNotEmpty()) {
                            refused.add(Refusal(line, "not a surface: $unknown (known: system, lock)"))
                        } else if (surfaces != null) {
                            refused.add(Refusal(line, "surfaces was already named"))
                        } else {
                            surfaces = named.mapNotNull { known[it] }.toSet()
                        }
                    }
                }
                else -> refused.add(Refusal(line, "not something the wallpaper file can say"))
            }
        }
        return Desired(
            asset = asset,
            digest = digest,
            surfaces = surfaces ?: DEFAULT_SURFACES,
            refused = refused,
        )
    }

    /**
     * What the wallpaper step did, and every reason it might not have.
     *
     * HERE AND NOT IN THE STEWARD (muster#41). It was nested in
     * `WallpaperSteward`, which imports `android.*`, so nothing could build one
     * in a test - and it shipped a first draft that reported a failed fetch as
     * BOTH "COULD_NOT_FETCH" and "no wallpaper configured for this device",
     * which are opposite statements about the same handset. Plain data belongs
     * where a test can reach it.
     */
    data class Outcome(
        val applied: Set<Surface> = emptySet(),
        val decision: Decision = Decision.NothingConfigured,
        val refused: List<Refusal> = emptyList(),
        /** Named an asset and could not get usable bytes for it. */
        val couldNotFetch: String? = null,
        /** The bytes arrived and were not the bytes the policy named. */
        val substituted: String? = null,
        /** Applied to some surfaces and not others. */
        val didNotTake: List<String> = emptyList(),
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            substituted?.let { add("SUBSTITUTED $it") }
            couldNotFetch?.let { add("COULD_NOT_FETCH $it") }
            inert?.let { add("nothing enforced - $it") }
            refused.forEach { add("REFUSED '${it.line}' - ${it.why}") }
            if (didNotTake.isNotEmpty()) add("DID_NOT_TAKE $didNotTake")
            // A wallpaper nobody configured reads as the quietest possible
            // success and is the state of every muster device that was promised
            // one (muster#41, muster#45).
            //
            // ONLY WHEN NOTHING ELSE ALREADY SAID WHY. A device that named an
            // image and could not fetch it reaches this line with the same
            // `NothingConfigured`, and telling somebody a wallpaper is not
            // configured when they can see the file they wrote is how a real
            // report gets read as noise.
            val somethingElseSaidWhy =
                substituted != null || couldNotFetch != null ||
                    inert != null || refused.isNotEmpty()
            if (decision is Decision.NothingConfigured && !somethingElseSaidWhy) {
                add("no wallpaper configured for this device")
            }
            if (decision is Decision.NoLongerNamed) {
                add(
                    "the policy no longer names " +
                        "${decision.surfaces.map { it.configName }} and muster does " +
                        "not clear a wallpaper it cannot put back"
                )
            }
        }

        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            else -> buildString {
                append("applied=${applied.map { it.configName }} decision=$decision")
                if (substituted != null) append(" SUBSTITUTED")
                if (couldNotFetch != null) append(" COULD_NOT_FETCH")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
                if (didNotTake.isNotEmpty()) append(" DID_NOT_TAKE=$didNotTake")
            }
        }
    }

    sealed interface Decision {
        /**
         * Put this image on these surfaces.
         *
         * `surfaces` IS WHAT TO SET NOW, not what the policy names. A device
         * that already carries the image on the home screen and has just been
         * told to carry it on the lock screen sets the lock screen alone.
         */
        data class Apply(val reason: String, val surfaces: Set<Surface>) : Decision

        /** Already carrying this image on these surfaces. Do nothing. */
        object AlreadyApplied : Decision

        /** No image configured. Leave the device's own wallpaper alone. */
        object NothingConfigured : Decision

        /**
         * The policy no longer names a surface this device put the image on.
         *
         * REPORTED RATHER THAN CLEARED, and that is a deliberate refusal to act.
         * Clearing a wallpaper is destructive and irreversible from the device's
         * side - the image it replaced is gone - and the trigger here would be a
         * word disappearing from a text file, which is as easily a typo as an
         * instruction. Every other policy object in this agent refuses rather
         * than acting destructively on input it cannot distinguish from a
         * mistake, and this is that rule.
         */
        data class NoLongerNamed(val surfaces: Set<Surface>) : Decision
    }

    /**
     * @param desired what the `wallpaper` file asked for
     * @param appliedDigest the digest this device recorded applying, or null
     * @param appliedSurfaces the surfaces it recorded applying it to
     *
     * WHY THE RECORD HAS TO SAY WHICH SURFACES (muster#41). Recording a digest
     * alone means a device that applied a wallpaper before the policy gained a
     * lock-screen line believes it is done, and never applies it. The record is
     * "this image, on these screens", because that is what the question is.
     */
    fun decide(
        desired: Desired,
        appliedDigest: String?,
        appliedSurfaces: Set<Surface>,
    ): Decision {
        if (desired.digest.isNullOrBlank() || desired.asset.isNullOrBlank()) {
            return Decision.NothingConfigured
        }
        if (appliedDigest.isNullOrBlank()) {
            return Decision.Apply(
                "no wallpaper has been applied by muster yet", desired.surfaces
            )
        }
        if (appliedDigest != desired.digest) {
            // EVERY NAMED SURFACE, not only the missing ones: the image itself
            // changed, so a surface carrying the old one is as wrong as a
            // surface carrying nothing.
            return Decision.Apply("the configured wallpaper has changed", desired.surfaces)
        }
        val missing = desired.surfaces - appliedSurfaces
        if (missing.isNotEmpty()) {
            return Decision.Apply(
                "already applied, but not on ${missing.map { it.configName }}", missing
            )
        }
        val extra = appliedSurfaces - desired.surfaces
        if (extra.isNotEmpty()) return Decision.NoLongerNamed(extra)
        return Decision.AlreadyApplied
    }
}
