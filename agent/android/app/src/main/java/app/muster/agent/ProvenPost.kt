package app.muster.agent

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * One POST to muster carrying this device's proof: challenge, sign, send.
 *
 * SHARED BY EVERY UPLOAD rather than written into each, because the server
 * authenticates every device route in one place (`_proven_device`) and the
 * client side of that should be one place too. Diagnostics and the check-in
 * report both go up through this; a third upload is a path and a body, not a
 * third copy of the handshake.
 */
class ProvenPost(
    private val transport: EnrollmentClient.Transport,
    private val identity: ConfigurationClient.Identity,
) {
    sealed interface Sent {
        object Accepted : Sent
        data class Refused(val status: Int) : Sent
        data class Unreachable(val cause: String) : Sent
        object NotEnrolled : Sent
    }

    /**
     * Sign a fresh nonce and POST [fields] with the proof added.
     *
     * @param accepted the status muster answers when it took the upload.
     */
    fun send(path: String, fields: JSONObject, accepted: Int = 202): Sent {
        val certificate = try {
            identity.certificatePem() ?: return Sent.NotEnrolled
        } catch (_: Exception) {
            return Sent.Unreachable("identity unavailable")
        }
        val nonce = when (val challenge = challenge()) {
            is Challenge.Nonce -> challenge.value
            is Challenge.Failed -> return challenge.sent
        }
        val signature = try {
            identity.signBase64(nonce)
        } catch (_: Exception) {
            return Sent.Unreachable("keystore signing failed")
        }
        fields.put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
        val reply = try {
            transport.post(path, fields.toString())
        } catch (e: Exception) {
            return Sent.Unreachable(e.javaClass.simpleName)
        }
        return if (reply.status == accepted) Sent.Accepted else Sent.Refused(reply.status)
    }

    private sealed interface Challenge {
        data class Nonce(val value: String) : Challenge
        data class Failed(val sent: Sent) : Challenge
    }

    private fun challenge(): Challenge {
        val reply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Challenge.Failed(Sent.Unreachable(e.javaClass.simpleName))
        }
        if (reply.status != 201) return Challenge.Failed(Sent.Refused(reply.status))
        return try {
            Challenge.Nonce(JSONObject(reply.body).getString("nonce"))
        } catch (_: Exception) {
            Challenge.Failed(Sent.Unreachable("unreadable challenge"))
        }
    }

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
        const val PROVE_PATH = "/v1/device/prove"
        val IO_DISPATCHER = Dispatchers.IO

        sealed interface ChallengeOutcome {
            data class Challenge(val nonce: String) : ChallengeOutcome
            data class NotEnrolled(val keyId: String) : ChallengeOutcome
            data class Unrecognized(val keyId: String) : ChallengeOutcome
            data class Revoked(val keyId: String) : ChallengeOutcome
            data class Unreachable(val keyId: String, val cause: Throwable) : ChallengeOutcome
            data class Refused(val keyId: String, val status: Int, val body: String) : ChallengeOutcome
        }

        sealed interface PostOutcome {
            data class Proven(val keyId: String, val body: String, val checkInIntervalS: Long?) : PostOutcome
            data class NotEnrolled(val keyId: String) : PostOutcome
            data class Unrecognized(val keyId: String) : PostOutcome
            data class Revoked(val keyId: String) : PostOutcome
            data class Unreachable(val keyId: String, val cause: Throwable) : PostOutcome
            data class Refused(val keyId: String, val status: Int, val body: String) : PostOutcome
        }

        sealed interface BytesPostOutcome {
            data class Proven(val keyId: String, val bytes: ByteArray, val digest: String) : BytesPostOutcome
            data class NotEnrolled(val keyId: String) : BytesPostOutcome
            data class Unrecognized(val keyId: String) : BytesPostOutcome
            data class Revoked(val keyId: String) : BytesPostOutcome
            data class Unreachable(val keyId: String, val cause: Throwable) : BytesPostOutcome
            data class Refused(val keyId: String, val status: Int, val detail: String) : BytesPostOutcome
        }

        /**
         * Get a challenge from muster.
         */
        suspend fun getChallenge(
            transport: EnrollmentClient.Transport,
            endpoint: String,
            keyId: String,
            certificatePem: String
        ): ChallengeOutcome = withContext(IO_DISPATCHER) {
            val challengePath = "$endpoint$CHALLENGE_PATH"
            val reply = try {
                transport.post(challengePath, "{}")
            } catch (e: Exception) {
                ChallengeOutcome.Unreachable(keyId, e)
            }
            when (reply.status) {
                201 -> try {
                    val nonce = JSONObject(reply.body).getString("nonce")
                    ChallengeOutcome.Challenge(nonce)
                } catch (e: Exception) {
                    ChallengeOutcome.Refused(keyId, reply.status, "unreadable challenge: ${e.javaClass.simpleName}")
                }
                401 -> ChallengeOutcome.Unrecognized(keyId)
                403 -> ChallengeOutcome.Revoked(keyId)
                404 -> ChallengeOutcome.NotEnrolled(keyId)
                else -> ChallengeOutcome.Refused(keyId, reply.status, reply.body)
            }
        }

        /**
         * Sign a challenge with the private key.
         */
        fun signChallenge(
            challenge: String,
            privateKey: java.security.PrivateKey
        ): String? {
            return try {
                val signature = java.security.Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                signature.update(challenge.toByteArray())
                android.util.Base64.encodeToString(signature.sign(), android.util.Base64.NO_WRAP)
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Post the proof to muster (JSON response).
         *
         * @param provePath the server path to POST the proof to (e.g. "/v1/device/config", "/v1/enroll/renew")
         * @param payload JSON string with additional fields to include in the proof request
         */
        suspend fun postProof(
            transport: EnrollmentClient.Transport,
            endpoint: String,
            provePath: String,
            keyId: String,
            certificatePem: String,
            challenge: String,
            signature: String,
            payload: String
        ): PostOutcome = withContext(IO_DISPATCHER) {
            val fields = try {
                JSONObject(payload).apply {
                    put("nonce", challenge)
                    put("signature_b64", signature)
                    put("certificate_pem", certificatePem)
                }
            } catch (e: Exception) {
                return@withContext PostOutcome.Refused(keyId, 400, "invalid payload: ${e.javaClass.simpleName}")
            }

            val reply = try {
                transport.post("$endpoint$provePath", fields.toString())
            } catch (e: Exception) {
                return@withContext PostOutcome.Unreachable(keyId, e)
            }

            when (reply.status) {
                200, 201 -> {
                    var checkInIntervalS: Long? = null
                    try {
                        val json = JSONObject(reply.body)
                        if (json.has("check_in_interval_s")) {
                            checkInIntervalS = json.getLong("check_in_interval_s")
                        }
                    } catch (_: Exception) {
                        // ignore
                    }
                    PostOutcome.Proven(keyId, reply.body, checkInIntervalS)
                }
                401 -> PostOutcome.Unrecognized(keyId)
                403 -> PostOutcome.Revoked(keyId)
                404 -> PostOutcome.NotEnrolled(keyId)
                else -> PostOutcome.Refused(keyId, reply.status, reply.body)
            }
        }

        /**
         * Post the proof to muster (binary response for assets).
         *
         * @param transport transport that supports postForBytes
         * @param provePath the server path to POST the proof to (e.g. "/v1/device/asset")
         * @param payload JSON string with additional fields to include in the proof request
         */
        suspend fun postProofForBytes(
            transport: AssetClient.Transport,
            endpoint: String,
            provePath: String,
            keyId: String,
            certificatePem: String,
            challenge: String,
            signature: String,
            payload: String
        ): BytesPostOutcome = withContext(IO_DISPATCHER) {
            val fields = try {
                JSONObject(payload).apply {
                    put("nonce", challenge)
                    put("signature_b64", signature)
                    put("certificate_pem", certificatePem)
                }
            } catch (e: Exception) {
                return@withContext BytesPostOutcome.Refused(keyId, 400, "invalid payload: ${e.javaClass.simpleName}")
            }

            val reply = try {
                transport.postForBytes("$endpoint$provePath", fields.toString())
            } catch (e: Exception) {
                return@withContext BytesPostOutcome.Unreachable(keyId, e)
            }

            when (reply.status) {
                200 -> {
                    val digest = sha256(reply.bytes)
                    BytesPostOutcome.Proven(keyId, reply.bytes, digest)
                }
                401 -> BytesPostOutcome.Unrecognized(keyId)
                403 -> BytesPostOutcome.Revoked(keyId)
                404 -> BytesPostOutcome.NotEnrolled(keyId)
                else -> BytesPostOutcome.Refused(keyId, reply.status, reply.detail)
            }
        }

        fun sha256(bytes: ByteArray): String =
            java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
    }
}