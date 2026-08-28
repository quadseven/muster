package app.muster.agent

import java.security.MessageDigest
import org.json.JSONObject

/**
 * Fetching one operator file from muster, over the identity this device holds.
 *
 * WHY THIS EXISTS (muster#45). Everything muster could apply used to travel
 * over a cable, and the wallpaper still came off a travel router. A phone
 * provisioned by QR is on somebody else's network and has neither. This is the
 * route the bytes take; the wallpaper is the first thing through it and an APK
 * is the same route with a bigger file (muster#42).
 *
 * THE SAME TWO-REQUEST PROOF AS ConfigurationClient, and deliberately not a new
 * one. muster issues the nonce, this device signs it with the key in its
 * keystore, and the signature travels WITH the fetch. A second authentication
 * scheme invented for the second thing a device asks for would be a second
 * chance to get it wrong, and the wrong one would be the one nobody tested
 * against a handset.
 *
 * THE DIGEST IS CHECKED HERE AND IT IS THE POINT OF THE CLASS. The device was
 * told what to expect by a policy file it fetched over this same identity, so
 * bytes that do not match are bytes something in the path substituted - and
 * Cloudflare serving a stale APK for hours, while the endpoint describing it
 * stayed current, is not hypothetical in this estate. The `X-Muster-Digest`
 * header the server sends is NOT what is checked: anything that could change
 * the body could change a header beside it.
 */
class AssetClient(
    private val transport: Transport,
    private val identity: ConfigurationClient.Identity,
) {

    /**
     * An answer that is not text.
     *
     * A SEPARATE INTERFACE RATHER THAN A WIDER `EnrollmentClient.Transport`,
     * because every existing fake implements that one and would have to grow a
     * method it has no use for - and the obvious way to do that is a default
     * that throws, which is a trap wearing a convenience.
     */
    interface Transport : EnrollmentClient.Transport {
        fun postForBytes(path: String, body: String): BytesReply

        /**
         * NOT a data class: `ByteArray` gives a generated `equals` that compares
         * references, so two identical replies would be unequal and a test
         * written against that would pass for the wrong reason.
         *
         * @param detail the error body, when there is one. Never the bytes.
         */
        class BytesReply(
            val status: Int,
            val bytes: ByteArray,
            val detail: String = "",
        )
    }

    sealed interface Fetched {
        /** The bytes, and they match the digest that was asked for. */
        class Asset(val bytes: ByteArray) : Fetched {
            override fun toString(): String = "asset (${bytes.size} bytes, verified)"
        }

        /** This device has no identity to fetch with. Not a failure. */
        object NotEnrolled : Fetched

        /** Network, DNS, TLS. The device keeps what it already has. */
        data class Unreachable(val detail: String) : Fetched

        /** A certificate muster did not issue, or a signature that does not match. */
        object Unrecognized : Fetched

        /** muster answered and said no. 404 is "no such asset". */
        data class Refused(val status: Int, val detail: String) : Fetched

        /**
         * The bytes arrived and are not the bytes that were asked for.
         *
         * ITS OWN STATE, NOT AN `Unreachable`, because the two demand opposite
         * responses: a network that is down is retried and a wallpaper that
         * does not match its digest must never be applied and must be LOUD. It
         * is also the only state here that says something about the path
         * between muster and the device rather than about either end.
         */
        data class DigestMismatch(val expected: String, val actual: String) : Fetched

        /** The keystore would not sign. This device's problem, not the server's. */
        data class DeviceCannotAsk(val detail: String) : Fetched
    }

    /**
     * @param name the asset to fetch, as the policy file named it
     * @param expectedDigest lowercase hex sha256 the bytes must have
     */
    fun fetch(name: String, expectedDigest: String): Fetched {
        val certificate = identity.certificatePem() ?: return Fetched.NotEnrolled

        val nonce = when (val challenged = challenge()) {
            is Challenged.Nonce -> challenged.value
            is Challenged.Failed -> return challenged.why
        }

        val signature = try {
            identity.signBase64(nonce)
        } catch (e: Exception) {
            return Fetched.DeviceCannotAsk("could not sign muster's nonce: ${detail(e)}")
        }

        val body = JSONObject()
            .put("nonce", nonce)
            .put("signature_b64", signature)
            .put("certificate_pem", certificate)
            .put("name", name)
            .toString()

        val reply = try {
            transport.postForBytes(ASSET_PATH, body)
        } catch (e: Exception) {
            return Fetched.Unreachable(detail(e))
        }

        if (reply.status == 401) return Fetched.Unrecognized
        if (reply.status != 200) {
            return Fetched.Refused(reply.status, reply.detail.take(REFUSAL_DETAIL_CHARS))
        }

        val actual = sha256(reply.bytes)
        // Compared lowercase because the policy file refuses anything else, and
        // a comparison that could fail on case would be a wallpaper that never
        // applies with no line saying why.
        if (!actual.equals(expectedDigest, ignoreCase = true)) {
            return Fetched.DigestMismatch(expected = expectedDigest, actual = actual)
        }
        return Fetched.Asset(reply.bytes)
    }

    private sealed interface Challenged {
        data class Nonce(val value: String) : Challenged
        data class Failed(val why: Fetched) : Challenged
    }

    private fun challenge(): Challenged {
        val reply = try {
            transport.post(CHALLENGE_PATH, "{}")
        } catch (e: Exception) {
            return Challenged.Failed(Fetched.Unreachable(detail(e)))
        }
        if (reply.status != 201) {
            return Challenged.Failed(
                Fetched.Refused(reply.status, reply.body.take(REFUSAL_DETAIL_CHARS))
            )
        }
        return try {
            Challenged.Nonce(JSONObject(reply.body).getString("nonce"))
        } catch (e: Exception) {
            Challenged.Failed(
                Fetched.Refused(reply.status, "unreadable challenge: ${detail(e)}")
            )
        }
    }

    /**
     * An exception as one word: its class name, and nothing else.
     *
     * The same rule as ConfigurationClient. A message can carry the URL it
     * failed on, and a URL here is one a device signed a nonce for.
     */
    private fun detail(e: Exception): String = e.javaClass.simpleName

    companion object {
        const val CHALLENGE_PATH = "/v1/auth/challenge"
        const val ASSET_PATH = "/v1/device/asset"
        private const val REFUSAL_DETAIL_CHARS = 200

        fun sha256(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
    }
}
