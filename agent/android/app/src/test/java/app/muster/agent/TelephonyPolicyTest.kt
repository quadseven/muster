package app.muster.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a device is asked to enforce about telephony, and what it is protected
 * from being asked.
 *
 * The two that matter most are `aTypoIsRefusedRatherThanSkipped` - a silently
 * ignored line leaves a phone with calls it was meant to block - and
 * `blockIncomingHasNoRestrictionKey`, which is the one line the file can
 * name that no user restriction enforces - the call screener does instead.
 */
class TelephonyPolicyTest {

    private fun read(text: String?) = TelephonyPolicy.read(text)

    @Test
    fun nothingConfiguredAsksForNothing() {
        assertTrue(read(null).keys.isEmpty())
        assertTrue(read("").keys.isEmpty())
        assertTrue(read("   \n\n  ").keys.isEmpty())
        assertFalse(read("").blockIncoming)
    }

    @Test
    fun aKnownNameBecomesItsPlatformKey() {
        assertEquals(setOf("no_outgoing_calls"), read("block-outgoing").keys)
    }

    @Test
    fun documentedTelephonyFileRequestsOutgoingRestrictionAndIncomingOperatorStep() {
        val desired = read("block-outgoing\nblock-incoming\n")
        assertEquals(setOf("no_outgoing_calls"), desired.keys)
        assertTrue(desired.blockIncoming)
        assertTrue(desired.refused.isEmpty())
    }

    @Test
    fun theKeyIsDeclaredRatherThanDerived() {
        // `no_outgoing_calls` is the AOSP value of DISALLOW_OUTGOING_CALLS.
        // There is no rule to derive it, and a key derived wrongly is not an
        // error - the platform stores it and enforces nothing.
        assertEquals("no_outgoing_calls", TelephonyPolicy.MANAGED["BLOCK_OUTGOING"])
    }

    @Test
    fun commentsAndBlankLinesAndSpacingAreIgnored() {
        val text = """
            # what this appliance may do on the cellular leg
            
              block-outgoing   # no dialling from a data-only handset
            block-incoming
        """.trimIndent()
        val desired = read(text)
        assertEquals(setOf("no_outgoing_calls"), desired.keys)
        assertTrue(desired.blockIncoming)
        assertEquals(emptyList<TelephonyPolicy.Refusal>(), desired.refused)
    }

    @Test
    fun blockIncomingHasNoRestrictionKey() {
        // There is no user restriction for refusing an incoming call. The line
        // is recognized and recorded for the call screener, but produces no
        // restriction key.
        val desired = read("block-incoming")
        assertTrue(desired.keys.isEmpty())
        assertTrue(desired.blockIncoming)
    }

    @Test
    fun aTypoIsRefusedRatherThanSkipped() {
        // The failure being prevented: the device comes up unrestricted, and
        // the only evidence is a file that appears to ask for a restriction.
        val desired = read("block-outgoig")
        assertTrue(desired.keys.isEmpty())
        assertFalse(desired.blockIncoming)
        assertEquals(1, desired.refused.size)
        assertEquals("block-outgoig", desired.refused.single().line)
    }

    @Test
    fun unknownInstructionIsRefusedAlongsideKnownOnes() {
        val desired = read("block-outgoing\nbogus-line\n")
        assertEquals(setOf("no_outgoing_calls"), desired.keys)
        assertEquals(1, desired.refused.size)
        assertEquals("bogus-line", desired.refused.single().line)
    }

    @Test
    fun aPlanAddsWhatIsNotInForceAndClearsWhatMusterSet() {
        val desired = read("block-outgoing")
        val plan = TelephonyPolicy.plan(
            desired,
            inForce = emptySet(),
            setByUs = setOf("no_outgoing_calls"),
        )
        assertEquals(listOf("no_outgoing_calls"), plan.add)
        assertTrue(plan.clear.isEmpty())
    }

    @Test
    fun aPlanClearsWhatMusterSetWhenTheFileRemovesIt() {
        val desired = read("")
        val plan = TelephonyPolicy.plan(
            desired,
            inForce = setOf("no_outgoing_calls"),
            setByUs = setOf("no_outgoing_calls"),
        )
        assertTrue(plan.add.isEmpty())
        assertEquals(listOf("no_outgoing_calls"), plan.clear)
    }

    @Test
    fun aPlanDoesNotClearWhatAnotherAdminSet() {
        val desired = read("")
        val plan = TelephonyPolicy.plan(
            desired,
            inForce = setOf("no_outgoing_calls"),
            setByUs = emptySet(),
        )
        assertTrue(plan.add.isEmpty())
        assertTrue(plan.clear.isEmpty())
    }

    @Test
    fun aPlanWithNoChangesIsChangesNothing() {
        val desired = read("block-outgoing")
        val plan = TelephonyPolicy.plan(
            desired,
            inForce = setOf("no_outgoing_calls"),
            setByUs = setOf("no_outgoing_calls"),
        )
        assertTrue(plan.changesNothing)
        assertTrue(plan.add.isEmpty())
        assertTrue(plan.clear.isEmpty())
    }

    @Test
    fun blockIncomingDoesNotMakeAPlanNotNothing() {
        // blockIncoming is enforced by the call screener, not a restriction,
        // so it produces no add or clear for the restriction plan.
        val desired = read("block-incoming")
        val plan = TelephonyPolicy.plan(
            desired,
            inForce = emptySet(),
            setByUs = emptySet(),
        )
        assertTrue(plan.changesNothing)
        assertTrue(plan.blockIncoming)
    }

    @Test
    fun theScreenerRejectsIncomingCallsOnlyWhenTheFileAsksForIt() {
        assertTrue(TelephonyPolicy.rejects(read("block-incoming"), incoming = true))
        assertFalse(TelephonyPolicy.rejects(read("block-outgoing"), incoming = true))
        assertFalse(TelephonyPolicy.rejects(read(""), incoming = true))
    }

    @Test
    fun theScreenerNeverRejectsAnOutgoingCall() {
        // Telecom shows the screener outgoing calls too. Refusing those is
        // no_outgoing_calls' job, which lets emergency calls through; the
        // screener must not get in the way of one.
        assertFalse(TelephonyPolicy.rejects(read("block-incoming"), incoming = false))
    }

    @Test
    fun theDataSiphonKeyCarriesItsAospValue() {
        // A WRONG LITERAL HERE IS SILENT: addUserRestriction stores a key it
        // does not recognise and enforces nothing, so the only thing standing
        // between a typo and a phone that quietly still dials is this
        // assertion. Read out of AOSP UserManager.java on 2026-09-19.
        assertEquals("no_outgoing_calls", TelephonyPolicy.MANAGED["BLOCK_OUTGOING"])
    }
}
