package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CheckInRunTest {
    private data class Fake(
        private val messages: List<String> = emptyList(),
        override val musterAnswered: Boolean? = null,
    ) : StepOutcome {
        override fun concerns() = messages
    }

    @Test
    fun throwingStepIsCapturedAndLaterStepsStillRun() {
        val ran = mutableListOf<String>()
        val report = CheckInRun.run(
            listOf(
                CheckInRun.NamedStep("first") { ran.add("first"); Fake() },
                CheckInRun.NamedStep("broken") { ran.add("broken"); error("boom") },
                CheckInRun.NamedStep("last") { ran.add("last"); Fake() },
            ),
        )
        assertEquals(listOf("first", "broken", "last"), ran)
        assertEquals("broken", report.steps[1].name)
        assertEquals(listOf("broken: failed - boom"), report.view.concerns)
    }

    @Test
    fun concernsKeepStepAndWithinStepOrdering() {
        val report = CheckInRun.run(
            listOf(
                CheckInRun.NamedStep("a") { Fake(listOf("one", "two")) },
                CheckInRun.NamedStep("b") { Fake(listOf("three")) },
            ),
        )
        assertEquals(listOf("a: one", "a: two", "b: three"), report.view.concerns)
    }

    @Test
    fun catchUpUsesTypedMusterAnswerFactRatherThanConcernText() {
        val noAnswer = CheckInRun.run(listOf(
            CheckInRun.NamedStep("configuration") { Fake(listOf("reworded message"), false) },
        ))
        val answered = CheckInRun.run(listOf(
            CheckInRun.NamedStep("configuration") { Fake(listOf("no fresh policy wording"), true) },
        ))
        assertTrue(noAnswer.needsCatchUp)
        assertFalse(answered.needsCatchUp)
    }
}
