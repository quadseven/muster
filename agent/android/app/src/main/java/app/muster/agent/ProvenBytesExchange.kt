package app.muster.agent

import kotlinx.coroutines.withContext

sealed interface BytesOutcome {
    data class Proven(
        val bytes: ByteArray,
        val digest: String
    ) : BytesOutcome

    data class NotEnrolled(
        val keyId: String
    ) : BytesOutcome

    data class Unrecognized(
        val keyId: String
    ) : BytesOutcome

    data class Revoked(
        val keyId: String
    ) : BytesOutcome

    data class Unreachable(
        val cause: Throwable
    ) : BytesOutcome

    data class Refused(
        val status: Int,
        val detail: String
    ) : BytesOutcome

    data class CannotSign(
        val cause: Throwable
    ) : BytesOutcome
}

interface ProvenBytesExchange {
    suspend fun exchange(
        endpoint: String,
        provePath: String,
        identity: ConfigurationClient.Identity,
        keyId: String,
        payload: String
    ): BytesOutcome
}

class DefaultProvenBytesExchange(
    private val transport: AssetClient.Transport
) : ProvenBytesExchange {

    override suspend fun exchange(
        endpoint: String,
        provePath: String,
        identity: ConfigurationClient.Identity,
        keyId: String,
        payload: String
    ): BytesOutcome = withContext(ProvenPost.IO_DISPATCHER) {
        val certificate = identity.certificatePem() ?: return@withContext BytesOutcome.NotEnrolled(keyId)

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
                    return@withContext BytesOutcome.CannotSign(e)
                }

                val postOutcome = ProvenPost.postProofForBytes(
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
                    is ProvenPost.BytesPostOutcome.Proven -> {
                        BytesOutcome.Proven(postOutcome.bytes, postOutcome.digest)
                    }
                    is ProvenPost.BytesPostOutcome.NotEnrolled -> BytesOutcome.NotEnrolled(postOutcome.keyId)
                    is ProvenPost.BytesPostOutcome.Unrecognized -> BytesOutcome.Unrecognized(postOutcome.keyId)
                    is ProvenPost.BytesPostOutcome.Revoked -> BytesOutcome.Revoked(postOutcome.keyId)
                    is ProvenPost.BytesPostOutcome.Unreachable -> BytesOutcome.Unreachable(postOutcome.cause)
                    is ProvenPost.BytesPostOutcome.Refused -> BytesOutcome.Refused(postOutcome.status, postOutcome.detail)
                }
            }
            is ProvenPost.ChallengeOutcome.NotEnrolled -> BytesOutcome.NotEnrolled(challengeOutcome.keyId)
            is ProvenPost.ChallengeOutcome.Unrecognized -> BytesOutcome.Unrecognized(challengeOutcome.keyId)
            is ProvenPost.ChallengeOutcome.Revoked -> BytesOutcome.Revoked(challengeOutcome.keyId)
            is ProvenPost.ChallengeOutcome.Unreachable -> BytesOutcome.Unreachable(challengeOutcome.cause)
            is ProvenPost.ChallengeOutcome.Refused -> BytesOutcome.Refused(challengeOutcome.status, challengeOutcome.body)
        }
    }
}