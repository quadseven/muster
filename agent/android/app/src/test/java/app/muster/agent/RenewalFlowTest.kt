package app.muster.agent

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.util.io.pem.PemReader
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The existing lifecycle decision reaching an exchange and a durable write. */
class RenewalFlowTest {

    private class Keys : EnrollmentFlow.DeviceKeys {
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        override fun ensure(): EnrollmentFlow.DeviceKeys.Material {
            val signer = Signature.getInstance(CertificateRequest.SIGNATURE_ALGORITHM)
            signer.initSign(pair.private)
            return EnrollmentFlow.DeviceKeys.Material(pair.public, signer)
        }
    }

    private class Transport : EnrollmentClient.Transport {
        var renewalBody: String? = null
        var calls = 0

        override fun post(path: String, body: String): EnrollmentClient.Transport.Reply {
            calls += 1
            return if (path == RenewalClient.CHALLENGE_PATH) {
                EnrollmentClient.Transport.Reply(
                    201, JSONObject().put("nonce", "server-nonce").toString()
                )
            } else {
                renewalBody = body
                EnrollmentClient.Transport.Reply(
                    201,
                    JSONObject()
                        .put("certificate_pem", "new certificate")
                        .put("ca_pem", "authority")
                        .put("not_after", "2026-12-01T00:00:00+00:00")
                        .put("renew_after", "2026-10-01T00:00:00+00:00")
                        .toString(),
                )
            }
        }

        override fun get(path: String): EnrollmentClient.Transport.Reply =
            throw AssertionError("renewal never GETs")
    }

    private class Identity : ConfigurationClient.Identity {
        override fun certificatePem(): String = "certificate"
        override fun signBase64(nonce: String): String = "signature"
    }

    private class Store : EnrollmentFlow.IdentityStore {
        var saved: List<String>? = null

        override fun save(
            certificatePem: String,
            caPem: String,
            notAfter: String,
            renewAfter: String,
        ) {
            saved = listOf(certificatePem, caPem, notAfter, renewAfter)
        }

        override fun hasIdentity(): Boolean = true
    }

    @Test
    fun aDevicePastRenewAfterStoresTheNewCertificateAndRenewAfter() {
        val keys = Keys()
        val transport = Transport()
        val store = Store()
        val flow = RenewalFlow(
            keys,
            RenewalClient(transport, Identity()),
            store,
        )

        val move = flow.advance(IdentityLifecycle.Stance.ShouldRenew(60))

        assertTrue(move is RenewalFlow.Move.Renewed)
        assertEquals(
            listOf(
                "new certificate",
                "authority",
                "2026-12-01T00:00:00+00:00",
                "2026-10-01T00:00:00+00:00",
            ),
            store.saved,
        )
    }

    @Test
    fun renewalCertifiesTheExistingDeviceKey() {
        val keys = Keys()
        val transport = Transport()
        val flow = RenewalFlow(keys, RenewalClient(transport, Identity()), Store())

        flow.advance(IdentityLifecycle.Stance.ShouldRenew(60))

        val pem = JSONObject(transport.renewalBody!!).getString("csr_pem")
        val der = PemReader(pem.reader()).use { it.readPemObject().content }
        val csr = PKCS10CertificationRequest(der)
        assertTrue(
            "renewal generated a different key, which changes key_id",
            csr.subjectPublicKeyInfo.encoded.contentEquals(keys.pair.public.encoded),
        )
    }

    @Test
    fun aCurrentDeviceMakesNoRenewalRequest() {
        val transport = Transport()
        val store = Store()
        val flow = RenewalFlow(Keys(), RenewalClient(transport, Identity()), store)

        val move = flow.advance(IdentityLifecycle.Stance.Current)

        assertTrue(move is RenewalFlow.Move.NotDue)
        assertEquals(0, transport.calls)
        assertEquals(null, store.saved)
    }
}
