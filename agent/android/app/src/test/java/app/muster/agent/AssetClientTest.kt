package app.muster.agent

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Fetching operator bytes over the identity this device holds.
 *
 * The one that decides whether the feature is safe is
 * `bytesThatDoNotMatchTheDigestAreNotTheAsset`: the digest is the only thing
 * standing between a managed device and whatever an intermediary decided to
 * serve, and this estate has already had a CDN hand a handset a stale APK for
 * four hours while the endpoint describing it stayed current.
 */
class AssetClientTest {

    private val bytes = "a wallpaper, pretend".toByteArray()
    private val digest = AssetClient.sha256(bytes)

    private class FakeIdentity(
        private val certificate: String? = "-----BEGIN CERTIFICATE-----",
        private val signs: Boolean = true,
    ) : ConfigurationClient.Identity {
        override fun certificatePem() = certificate
        override fun signBase64(nonce: String): String {
            if (!signs) throw IllegalStateException("keystore said no")
            return "signature-over-$nonce"
        }
    }

    private class FakeTransport(
        private val challengeStatus: Int = 201,
        private val assetStatus: Int = 200,
        private val bytes: ByteArray = ByteArray(0),
        private val detail: String = "",
        private val throwsOnAsset: Boolean = false,
    ) : AssetClient.Transport {
        val posted = mutableListOf<Pair<String, String>>()

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            posted.add(path to body)
            return EnrollmentClient.Transport.Reply(
                challengeStatus, JSONObject().put("nonce", "n-1").toString()
            )
        }

        override fun get(path: String) = EnrollmentClient.Transport.Reply(404, "")

        override fun postForBytes(path: String, body: String): AssetClient.Transport.BytesReply {
            posted.add(path to body)
            if (throwsOnAsset) throw java.io.IOException("no route to host")
            return AssetClient.Transport.BytesReply(assetStatus, bytes, detail)
        }
    }

    @Test
    fun anAssetThatMatchesItsDigestIsTheAsset() {
        val transport = FakeTransport(bytes = bytes)
        val fetched = AssetClient(transport, FakeIdentity()).fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.Asset)
        assertTrue((fetched as AssetClient.Fetched.Asset).bytes.contentEquals(bytes))
    }

    @Test
    fun bytesThatDoNotMatchTheDigestAreNotTheAsset() {
        // THE TEST THIS CLASS EXISTS FOR. An intermediary served something
        // else; the device must not apply it and must say so distinctly.
        val transport = FakeTransport(bytes = "something else entirely".toByteArray())
        val fetched = AssetClient(transport, FakeIdentity()).fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.DigestMismatch)
        assertEquals(digest, (fetched as AssetClient.Fetched.DigestMismatch).expected)
    }

    @Test
    fun anEmptyBodyWithA200IsAMismatchAndNotAnEmptyAsset() {
        // A truncated response and a captive portal both look like this.
        val fetched = AssetClient(FakeTransport(bytes = ByteArray(0)), FakeIdentity())
            .fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.DigestMismatch)
    }

    @Test
    fun theNonceIsTheServersAndTravelsWithTheFetch() {
        val transport = FakeTransport(bytes = bytes)
        AssetClient(transport, FakeIdentity()).fetch("wall.png", digest)
        assertEquals(AssetClient.CHALLENGE_PATH, transport.posted[0].first)
        assertEquals(AssetClient.ASSET_PATH, transport.posted[1].first)
        val body = JSONObject(transport.posted[1].second)
        assertEquals("wall.png", body.getString("name"))
        assertEquals("signature-over-n-1", body.getString("signature_b64"))
    }

    @Test
    fun aDeviceWithNoIdentityHasNothingToFetchWith() {
        val transport = FakeTransport(bytes = bytes)
        val fetched = AssetClient(transport, FakeIdentity(certificate = null))
            .fetch("wall.png", digest)
        assertEquals(AssetClient.Fetched.NotEnrolled, fetched)
        assertTrue("nothing should have been asked", transport.posted.isEmpty())
    }

    @Test
    fun aKeystoreThatWillNotSignIsThisDevicesProblem() {
        val fetched = AssetClient(FakeTransport(), FakeIdentity(signs = false))
            .fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.DeviceCannotAsk)
    }

    @Test
    fun anUnreachableServerIsNotAMissingAsset() {
        // The device keeps the wallpaper it already has. Collapsing this into
        // "no asset" would strip a device every time its network went away.
        val fetched = AssetClient(FakeTransport(throwsOnAsset = true), FakeIdentity())
            .fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.Unreachable)
    }

    @Test
    fun aStrangerIsToldSoDistinctlyFromBeingRefused() {
        assertEquals(
            AssetClient.Fetched.Unrecognized,
            AssetClient(FakeTransport(assetStatus = 401), FakeIdentity()).fetch("w.png", digest),
        )
    }

    @Test
    fun anAssetMusterDoesNotHaveIsRefusedWithItsStatus() {
        val fetched = AssetClient(FakeTransport(assetStatus = 404, detail = "no such asset"), FakeIdentity())
            .fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.Refused)
        assertEquals(404, (fetched as AssetClient.Fetched.Refused).status)
    }

    @Test
    fun aStoreThatDidNotMountIsRefusedRatherThanTreatedAsMissing() {
        // 503 from the server means "muster has no asset store" - a deployment
        // problem, not a policy one - and the device must not conclude the
        // operator removed the wallpaper.
        val fetched = AssetClient(FakeTransport(assetStatus = 503), FakeIdentity())
            .fetch("wall.png", digest)
        assertEquals(503, (fetched as AssetClient.Fetched.Refused).status)
    }

    @Test
    fun aChallengeThatFailsStopsBeforeAnythingIsSigned() {
        val fetched = AssetClient(FakeTransport(challengeStatus = 500), FakeIdentity())
            .fetch("wall.png", digest)
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.Refused)
    }

    @Test
    fun theDigestComparisonIsNotCaseSensitiveEvenThoughThePolicyIs() {
        val fetched = AssetClient(FakeTransport(bytes = bytes), FakeIdentity())
            .fetch("wall.png", digest.uppercase())
        assertTrue(fetched.toString(), fetched is AssetClient.Fetched.Asset)
    }

    @Test
    fun aFetchedAssetNeverPrintsItsOwnBytes() {
        val fetched = AssetClient(FakeTransport(bytes = bytes), FakeIdentity())
            .fetch("wall.png", digest)
        assertTrue(fetched.toString(), !fetched.toString().contains("wallpaper, pretend"))
    }
}
