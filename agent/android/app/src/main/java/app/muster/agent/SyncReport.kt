package app.muster.agent

/**
 * What a check-in has to say for itself, decided without touching Android.
 *
 * THE PROBLEM THIS SOLVES is a device that did nothing and said it was fine.
 * Every steward already works out precisely why it changed nothing - withheld,
 * refused, kept visible, did not take, threw - and every one of those facts
 * used to reach `Log.i` and stop there. An appliance enrolled hands-free has no
 * adb and no cable, so `logcat` is not a place a person can look. The reason
 * has to arrive on the screen of the phone that has the problem.
 *
 * THE RULE, and it is the whole design: a step is a concern unless it did what
 * it was told. "Nothing to do" is not the same as "did what it was told" when
 * nothing-to-do means the config file never arrived, so `inert` counts as a
 * concern even though it is the quietest outcome a steward has.
 */
object SyncReport {

    /** One entry from `BootPlan.STEPS`, paired with what it reported. */
    data class Step(val name: String, val outcome: StepOutcome)

    /**
     * A step that threw rather than returning.
     *
     * An exception is the one outcome no steward can describe, because the
     * steward is not running any more. Wrapping it as a `StepOutcome` keeps the
     * caller from having two shapes to render.
     */
    data class Threw(val step: String, val message: String?) : StepOutcome {
        override fun concerns(): List<String> =
            listOf("failed - ${message ?: "no message"}")

        override fun toString(): String = "failed - ${message ?: "no message"}"
    }

    /**
     * @param headline one line, safe to show when all is well.
     * @param concerns one line per thing a person has to go and look at,
     *   prefixed with the step that raised it. Empty means the device is doing
     *   what it was told - and that claim is now worth something.
     * @param detail every step and its full outcome, for the person who wants
     *   the whole story rather than the exceptions.
     */
    data class View(
        val headline: String,
        val concerns: List<String>,
        val detail: List<String>,
    )

    fun of(steps: List<Step>): View {
        val concerns = steps.flatMap { step ->
            step.outcome.concerns().map { "${step.name}: $it" }
        }
        val headline = if (concerns.isEmpty()) {
            "Checked in. ${steps.size} steps, nothing to report."
        } else {
            // COUNTED, NOT LISTED. The headline has one line and the concerns
            // have their own; a headline that tried to name them would truncate
            // the fifth one on the narrowest phone and read as though there
            // were four.
            "Checked in. ${concerns.size} of ${steps.size} steps need attention."
        }
        return View(
            headline = headline,
            concerns = concerns,
            detail = steps.map { "${it.name}: ${it.outcome}" },
        )
    }
}

/**
 * A steward outcome that can be asked whether anything went wrong.
 *
 * WHY THIS IS A TYPE AND NOT A CONVENTION. Every `Outcome` already marks its
 * bad news by SHOUTING the key in `toString` - WITHHELD, REFUSED, DID_NOT_TAKE
 * - and a caller could read severity back out of the rendered line. That works
 * today and breaks silently the first time a key is renamed or a field is
 * added, which is exactly the class of failure this whole file exists to end.
 *
 * Each steward names its own bad news because only it knows what bad means:
 * `withheld` is a refusal to strip a phone and `unchanged` is a normal Tuesday,
 * and nothing outside `AppVisibilitySteward` can tell those apart.
 */
interface StepOutcome {
    /**
     * One line per thing a person has to go and look at. Empty when the step
     * did what it was told - and an empty list is a claim, so a steward that
     * cannot tell must say something rather than nothing.
     */
    fun concerns(): List<String>
}
