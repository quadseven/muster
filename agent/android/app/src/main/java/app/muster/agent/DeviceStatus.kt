package app.muster.agent

/**
 * What this device should say about itself, in one place a test can reach.
 *
 * WHY THIS EXISTS. The agent used to show an enrolled device an empty pairing
 * box and "Enroll this device", because EnrollActivity built a
 * `FileIdentityStore` and never asked it `hasIdentity()`. On a Device Owner that
 * is not a cosmetic bug: this app is the only thing on the phone representing
 * whatever manages it, and it was telling the person holding it something
 * untrue.
 *
 * THE STANCE VOCABULARY ALREADY EXISTED and nothing showed it. IdentityLifecycle
 * has modelled `Current`, `ShouldRenew`, `Lapsed`, `ClockBehind` and `Unenrolled`
 * since renewal was written, and only the renewal path ever read it. `ClockBehind`
 * especially is a diagnosis nothing else on the device will ever offer - a phone
 * whose clock is behind its own certificate looks, to every other tool, like a
 * phone with a networking problem.
 *
 * Rendering is separated from gathering so the interesting half runs on a JVM.
 * The half that talks to Android is a dozen lines of lookups in StatusActivity;
 * the half that decides what a person is told is all here.
 */
object DeviceStatus {

    /** One labelled line on the screen. */
    data class Row(val label: String, val value: String)

    /**
     * @param headline the one line somebody reads before deciding to care
     * @param detail what it means, and what to do about it if anything
     * @param canEnroll whether to offer enrollment at all
     */
    data class View(
        val headline: String,
        val detail: String,
        val rows: List<Row>,
        val canEnroll: Boolean,
    )

    /**
     * Everything the screen is allowed to know, gathered by the Activity.
     *
     * Passed in rather than looked up so this stays a function of its inputs -
     * every state below is one somebody would otherwise have to arrange on real
     * hardware, and two of them (a lapsed certificate, a clock behind its own
     * identity) cannot be staged on demand at all.
     */
    data class Facts(
        val deviceOwner: Boolean,
        val stance: IdentityLifecycle.Stance,
        val notAfter: Long?,
        val renewAfter: Long?,
        val serverUrl: String?,
        val restrictions: List<String>,
        val agentVersion: String,
        val lastCheckIn: Long?,
        val now: Long,
    )

    fun render(facts: Facts): View {
        val headline: String
        val detail: String
        when {
            // Ownership first. Without it nothing else this app reports is
            // enforceable, so leading with a certificate would be misleading
            // about the only thing that matters.
            !facts.deviceOwner -> {
                headline = "Not managed"
                detail = "Muster does not own this device, so no policy applies. " +
                    "Device Owner is taken once, on a factory-reset device."
            }
            facts.stance is IdentityLifecycle.Stance.Unenrolled -> {
                headline = "Not enrolled"
                detail = "This device is managed but has no identity yet. " +
                    "Enroll it with a pairing code from the console."
            }
            facts.stance is IdentityLifecycle.Stance.ClockBehind -> {
                val skew = facts.stance.secondsOfSkew
                headline = "Clock is wrong"
                detail = "This device thinks it is ${humanize(skew)} before its own " +
                    "certificate was issued. Renewal and enrollment will both fail " +
                    "until the clock is right, and nothing else will say so."
            }
            facts.stance is IdentityLifecycle.Stance.Lapsed -> {
                headline = "Identity lapsed"
                detail = "The certificate expired ${humanize(facts.stance.secondsSinceExpiry)} " +
                    "ago and was not renewed. This device has left the kith and must " +
                    "enroll again."
            }
            facts.stance is IdentityLifecycle.Stance.ShouldRenew -> {
                headline = "Renewal due"
                detail = "The certificate is still valid for " +
                    "${humanize(facts.stance.secondsUntilExpiry)} and renewal has " +
                    "started. Nothing to do unless this persists."
            }
            else -> {
                headline = "Managed and current"
                detail = "This device is owned by Muster and holds a valid identity."
            }
        }

        val rows = mutableListOf<Row>()
        rows += Row("Managed by", if (facts.deviceOwner) "Muster (Device Owner)" else "nothing")
        facts.serverUrl?.takeIf { it.isNotBlank() }?.let { rows += Row("Control plane", it) }
        facts.notAfter?.let { rows += Row("Identity expires", when_(it, facts.now)) }
        facts.renewAfter?.let { rows += Row("Renews after", when_(it, facts.now)) }
        rows += Row(
            "Restrictions in force",
            // Read back from the platform by the caller, never echoed from the
            // config file. A config file says what was asked for; only the
            // device says what is true.
            if (facts.restrictions.isEmpty()) "none" else facts.restrictions.joinToString("\n"),
        )
        rows += Row("Agent version", facts.agentVersion)
        rows += Row(
            "Last check-in",
            facts.lastCheckIn?.let { "${humanize(facts.now - it)} ago" } ?: "never",
        )

        return View(
            headline = headline,
            detail = detail,
            rows = rows,
            // Offered only when there is genuinely nothing to enroll with.
            // Showing it beside a valid identity is what this screen replaced.
            canEnroll = facts.stance is IdentityLifecycle.Stance.Unenrolled ||
                facts.stance is IdentityLifecycle.Stance.Lapsed,
        )
    }

    /**
     * A duration a person can act on.
     *
     * Deliberately coarse. "27 days" and "27 days 4 hours" lead to the same
     * decision, and the second invites reading precision into a number whose
     * inputs are a device clock and a certificate.
     */
    fun humanize(seconds: Long): String {
        val s = if (seconds < 0) 0 else seconds
        return when {
            s < 60 -> "less than a minute"
            s < 3600 -> "${s / 60} minute${plural(s / 60)}"
            s < 86400 -> "${s / 3600} hour${plural(s / 3600)}"
            else -> "${s / 86400} day${plural(s / 86400)}"
        }
    }

    private fun plural(n: Long) = if (n == 1L) "" else "s"

    /**
     * A date somebody can act on, with how far away it is.
     *
     * The wire format is an ISO instant to microseconds
     * (`2026-11-17T15:30:14.400660+00:00`), which is right for a protocol and
     * wrong for a screen: it is the longest string on the page and the part
     * that matters - roughly when - is the hardest to extract from it.
     *
     * UTC deliberately. A certificate's validity is not local to wherever the
     * phone currently is, and rendering it in a shifting local zone invites
     * somebody to compare it against a server log and find a mismatch that is
     * not there.
     */
    fun when_(epochSeconds: Long, now: Long): String {
        val date = java.time.Instant.ofEpochSecond(epochSeconds)
            .atZone(java.time.ZoneOffset.UTC)
            .format(java.time.format.DateTimeFormatter.ofPattern("d MMM yyyy"))
        val delta = epochSeconds - now
        return if (delta >= 0) "$date (in ${humanize(delta)})" else "$date (${humanize(-delta)} ago)"
    }
}
