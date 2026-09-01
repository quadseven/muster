package app.muster.agent

/**
 * One renewal decision and, only when due, one exchange and one store write.
 *
 * THE EXISTING KEY IS USED TWICE. It signs the CSR through [DeviceKeys], and
 * [RenewalClient] signs muster's nonce through the same keystore identity used
 * by configuration fetches. There is no key-generation option here. On Android
 * both adapters use `AndroidKeystoreKeys.DEFAULT_ALIAS`, whose `ensure` call is
 * idempotent; changing that alias would change the device's key_id and the
 * server would refuse the CSR rather than rotate it by accident.
 */
class RenewalFlow(
    private val keys: EnrollmentFlow.DeviceKeys,
    private val client: RenewalClient,
    private val store: EnrollmentFlow.IdentityStore,
) {
    sealed interface Move : StepOutcome {
        object NotDue : Move {
            override fun concerns(): List<String> = emptyList()
            override fun toString(): String = "not due"
        }

        object Renewed : Move {
            override fun concerns(): List<String> = emptyList()
            override fun toString(): String = "renewed"
        }

        data class Failed(val detail: String) : Move {
            override fun concerns(): List<String> = listOf(detail)
            override fun toString(): String = detail
        }
    }

    fun advance(stance: IdentityLifecycle.Stance): Move = when (stance) {
        is IdentityLifecycle.Stance.ShouldRenew -> renew()
        IdentityLifecycle.Stance.Current,
        is IdentityLifecycle.Stance.Lapsed,
        is IdentityLifecycle.Stance.ClockBehind,
        IdentityLifecycle.Stance.Unenrolled -> Move.NotDue
    }

    private fun renew(): Move {
        val material = try {
            keys.ensure()
        } catch (e: Exception) {
            return Move.Failed("could not use the enrolled key: ${detail(e)}")
        }
        val csr = try {
            CertificateRequest.toPem(
                CertificateRequest.build("renewal", material.publicKey, material.signer)
            )
        } catch (e: Exception) {
            return Move.Failed("could not build a renewal request: ${detail(e)}")
        }
        return when (val renewed = client.renew(csr)) {
            is RenewalClient.Renewed.Identity -> {
                try {
                    store.save(
                        renewed.certificatePem,
                        renewed.caPem,
                        renewed.notAfter,
                        renewed.renewAfter,
                    )
                } catch (e: Exception) {
                    // The old certificate remains usable until its expiry. Say
                    // that the write failed instead of reporting a renewal the
                    // next check-in cannot observe.
                    return Move.Failed("renewed certificate did not land: ${detail(e)}")
                }
                Move.Renewed
            }
            is RenewalClient.Renewed.NotEnrolled -> Move.Failed("this device has no identity")
            is RenewalClient.Renewed.Unrecognized ->
                Move.Failed("muster does not recognize this device's certificate")
            is RenewalClient.Renewed.Unreachable ->
                Move.Failed("muster is unreachable (${renewed.detail})")
            is RenewalClient.Renewed.Refused ->
                Move.Failed("muster refused renewal: ${renewed.status} ${renewed.detail}")
            is RenewalClient.Renewed.DeviceCannotAsk ->
                Move.Failed("this device could not ask: ${renewed.detail}")
        }
    }

    private fun detail(e: Exception): String = e.javaClass.simpleName
}
