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

    /** Runs each named step once, retaining order and isolating failures. */
    fun run(
        steps: List<NamedStep>,
        onThrow: (String, Exception) -> Unit = { _, _ -> },
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
