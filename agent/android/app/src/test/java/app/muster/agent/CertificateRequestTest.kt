package app.muster.agent

import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The CSR the agent presents, checked twice over.
 *
 * These tests prove it is well-formed and self-consistent. They CANNOT prove
 * muster's CA will accept it - that is a different language, a different
 * library, and the exact seam where two halves written separately disagree. The
 * CI job writes a CSR from `writesACsrForTheCrossLanguageCheck` to disk and
 * feeds it to the Python CA, which is what closes that gap.
 */
class CertificateRequestTest {

    private fun p256() =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    @Test
    fun theRequestIsSignedByTheKeyItCertifies() {
        // The whole claim a CSR makes: "I hold the private half of this public
        // key". muster's CA refuses any request where this does not hold.
        val keys = p256()
        val csr = CertificateRequest.build("whatever", keys.public, keys.private)

        val verifier = JcaContentVerifierProviderBuilder()
            .setProvider(BouncyCastleProvider())
            .build(keys.public)
        assertTrue("the CSR does not verify against its own key", csr.isSignatureValid(verifier))
    }

    @Test
    fun aRequestSignedByADifferentKeyDoesNotVerify() {
        val keys = p256()
        val impostor = p256()
        val signature = Signature.getInstance(CertificateRequest.SIGNATURE_ALGORITHM)
        signature.initSign(impostor.private)

        // Ask for a CSR certifying one key while signing with another.
        val csr = CertificateRequest.build("whatever", keys.public, signature)

        val verifier = JcaContentVerifierProviderBuilder()
            .setProvider(BouncyCastleProvider())
            .build(keys.public)
        assertTrue(
            "a request signed by a key it does not certify must not verify",
            !csr.isSignatureValid(verifier),
        )
    }

    @Test
    fun theSignerIsInjectedSoAnUnextractableKeyWorks() {
        // The Android Keystore never hands out a private key; it hands out a
        // Signature. This is the path a real device takes, exercised with a
        // software key because a JVM test has no keystore.
        val keys = p256()
        val signature = Signature.getInstance(CertificateRequest.SIGNATURE_ALGORITHM)
        signature.initSign(keys.private)

        val csr = CertificateRequest.build("pixel-6a", keys.public, signature)
        val verifier = JcaContentVerifierProviderBuilder()
            .setProvider(BouncyCastleProvider())
            .build(keys.public)
        assertTrue(csr.isSignatureValid(verifier))
    }

    @Test
    fun theEncodedRequestCarriesTheKeyBeingCertified() {
        val keys = p256()
        val csr = CertificateRequest.build("pixel-6a", keys.public, keys.private)
        assertTrue(
            "the CSR does not carry the public key it was built with",
            csr.subjectPublicKeyInfo.encoded.contentEquals(keys.public.encoded),
        )
    }

    @Test
    fun pemIsWhatGoesOverTheWire() {
        // PEM survives a JSON body, a log line and a terminal. Raw DER survives
        // none of the three without another layer of encoding.
        val keys = p256()
        val pem = CertificateRequest.toPem(CertificateRequest.build("x", keys.public, keys.private))
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        assertTrue(pem.trimEnd().endsWith("-----END CERTIFICATE REQUEST-----"))
    }

    @Test
    fun writesACsrForTheCrossLanguageCheck() {
        // Not an assertion so much as a fixture handed to the next CI step.
        // Kotlin+BouncyCastle produced it; Python+cryptography has to accept it,
        // and nothing inside this JVM can tell us whether it will.
        val keys = p256()
        val pem = CertificateRequest.toPem(
            CertificateRequest.build("i-would-like-to-be-admin", keys.public, keys.private)
        )
        val out = File("build/cross-language/agent.csr")
        out.parentFile.mkdirs()
        out.writeText(pem)
        assertEquals("-----BEGIN CERTIFICATE REQUEST-----", pem.lineSequence().first())
    }
}
