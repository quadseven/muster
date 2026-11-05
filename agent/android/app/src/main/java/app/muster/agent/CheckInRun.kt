package app.muster.agent

/** One Android-free owner of check-in execution and its derived decisions. */
object CheckInRun {
    fun interface Step {
        fun run(): StepOutcome
    }

    data class NamedStep(val name: String, val step: Step)

    data class Report(
        val steps: List<SyncReport.Step>,
        val view: SyncReport.View,
        val needsCatchUp: Boolean,
    )

    /**
     * One plan at a time, across the whole process (muster#229).
     *
     * BootReceiver, CheckInJob and StatusActivity each call run from their own
     * worker thread, and the job can fire at boot beside the receiver. Two
     * plans at once stage the same `<name>.incoming` files and race the
     * rename, and download and commit the same package twice. A later caller
     * waits rather than being dropped: its trigger may carry work the first
     * run did not see, and every caller is already off the main thread.
     */
    private val serial = Any()

    /** Runs each named step once, retaining order and isolating failures. */
    fun run(
        steps: List<NamedStep>,
        onThrow: (String, Exception) -> Unit = { _, _ -> },
    ): Report = synchronized(serial) { runSteps(steps, onThrow) }

    private fun runSteps(
        steps: List<NamedStep>,
        onThrow: (String, Exception) -> Unit,
    ): Report {
        val outcomes = steps.map { step ->
            val outcome = try {
                step.step.run()
            } catch (error: Exception) {
                onThrow(step.name, error)
                SyncReport.Threw(step.name, error.message)
            }
            SyncReport.Step(step.name, outcome)
        }
        val answered = outcomes.firstOrNull { it.name == "configuration" }
            ?.outcome?.musterAnswered == true
        return Report(
            steps = outcomes,
            view = SyncReport.of(outcomes),
            needsCatchUp = CheckInSchedulePolicy.needsCatchUp(answered),
        )
    }
}
