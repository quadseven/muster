package app.muster.agent

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The durable status learned from muster's last deliberate answer. */
class RevocationStatusTest {

    @Test
    fun anExplicitRevocationSetsTheStatus() {
        assertTrue(RevocationStatus.next(false, ConfigurationClient.Fetched.Revoked))
    }

    @Test
    fun aTransportFailureCannotInventARevocation() {
        assertFalse(
            RevocationStatus.next(
                false,
                ConfigurationClient.Fetched.Unreachable("timeout"),
            )
        )
    }

    @Test
    fun aTransportFailureCannotEraseARevocation() {
        assertTrue(
            RevocationStatus.next(
                true,
                ConfigurationClient.Fetched.Unreachable("timeout"),
            )
        )
    }

    @Test
    fun aSuccessfulAnswerClearsTheStatusAfterReadmission() {
        assertFalse(
            RevocationStatus.next(
                true,
                ConfigurationClient.Fetched.Configuration("r2", emptyMap()),
            )
        )
    }
}
