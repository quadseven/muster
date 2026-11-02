package app.muster.agent

import kotlinx.coroutines.withContext

sealed interface Outcome {
    data class Answered(
        val body: String,
        val checkInIntervalS: Long?
    ) : Outcome

    data class NotEnrolled(
        val keyId: String
    ) : Outcome

    data class Unrecognized(
        val keyId: String
    ) : Outcome

    data class Revoked(
        val keyId: String
    ) : Outcome

    data class Unreachable(
        val cause: Throwable
    ) : Outcome

    data class Refused(
        val status: Int,
        val body: String
    ) : Outcome

    data class CannotSign(
        val cause: Throwable
    ) : Outcome
}

interface ProvenExchange {
    suspend fun exchange(
        endpoint: String,
        provePath: String,
        identity: ConfigurationClient.Identity,
        keyId: String,
        payload: String
    ): Outcome
}

class DefaultProvenExchange(
    private val transport: EnrollmentClient.Transport
) : ProvenExchange {

    override suspend fun exchange(
        endpoint: String,
        provePath: String,
        identity: ConfigurationClient.Identity,
        keyId: String,
        payload: String
    ): Outcome = withContext(ProvenPost.IO_DISPATCHER) {
        val certificate = identity.certificatePem() ?: return@withContext Outcome.NotEnrolled(keyId)

        val challengeOutcome = ProvenPost.getChallenge(
            transport = transport,
            endpoint = endpoint,
            keyId = keyId,
            certificatePem = certificate
        )

        when (challengeOutcome) {
            is ProvenPost.ChallengeOutcome.Challenge -> {
                val signed = try {
                    identity.signBase64(challengeOutcome.nonce)
                } catch (e: Exception) {
                    return@withContext Outcome.CannotSign(e)
                }

                val postOutcome = ProvenPost.postProof(
                    transport = transport,
                    endpoint = endpoint,
                    provePath = provePath,
                    keyId = keyId,
                    certificatePem = certificate,
                    challenge = challengeOutcome.nonce,
                    signature = signed,
                    payload = payload
                )

                when (postOutcome) {
                    is ProvenPost.PostOutcome.Proven -> {
                        Outcome.Answered(postOutcome.body, postOutcome.checkInIntervalS)
                    }
                    is ProvenPost.PostOutcome.NotEnrolled -> Outcome.NotEnrolled(postOutcome.keyId)
                    is ProvenPost.PostOutcome.Unrecognized -> Outcome.Unrecognized(postOutcome.keyId)
                    is ProvenPost.PostOutcome.Revoked -> Outcome.Revoked(postOutcome.keyId)
                    is ProvenPost.PostOutcome.Unreachable -> Outcome.Unreachable(postOutcome.cause)
                    is ProvenPost.PostOutcome.Refused -> Outcome.Refused(postOutcome.status, postOutcome.body)
                }
            }
            is ProvenPost.ChallengeOutcome.NotEnrolled -> Outcome.NotEnrolled(challengeOutcome.keyId)
            is ProvenPost.ChallengeOutcome.Unrecognized -> Outcome.Unrecognized(challengeOutcome.keyId)
            is ProvenPost.ChallengeOutcome.Revoked -> Outcome.Revoked(challengeOutcome.keyId)
            is ProvenPost.ChallengeOutcome.Unreachable -> Outcome.Unreachable(challengeOutcome.cause)
            is ProvenPost.ChallengeOutcome.Refused -> Outcome.Refused(challengeOutcome.status, challengeOutcome.body)
        }
    }
}