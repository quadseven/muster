package app.muster.agent

import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
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
    fun concurrentRunsNeverOverlapTheirSteps() {
        // Boot, the scheduled job and the status screen each call run from
        // their own thread (muster#229). Two plans at once race the same
        // staged files and install the same package twice.
        val inside = AtomicInteger(0)
        val widest = AtomicInteger(0)
        val start = CountDownLatch(1)
        val runners = (1..4).map { n ->
            Thread {
                start.await()
                CheckInRun.run(
                    (1..3).map { i ->
                        CheckInRun.NamedStep("r$n-s$i") {
                            widest.accumulateAndGet(inside.incrementAndGet(), ::maxOf)
                            Thread.sleep(20)
                            inside.decrementAndGet()
                            Fake()
                        }
                    },
                )
            }.apply { start() }
        }
        start.countDown()
        runners.forEach { it.join(10_000) }
        assertTrue(runners.none { it.isAlive })
        assertEquals(1, widest.get())
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
