package app.muster.agent

import java.io.StringWriter
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter

/**
 * Build the PKCS#10 request a device presents at enrollment.
 *
 * THE PRIVATE KEY IS NEVER HANDED TO THIS CLASS AS BYTES, and that is the whole
 * design. On a real device the key is generated inside the Android Keystore and
 * cannot be extracted at all - what comes out is a `Signature` object that will
 * sign on the key's behalf. So this takes a signer, not a key, and the same
 * code path works for a hardware-backed key it can never see and for a software
 * key in a JVM test.
 *
 * WHY THE SUBJECT HERE BARELY MATTERS. muster's CA discards it: `issue()` reads
 * only the public key out of the request and builds the subject from the name
 * the administrator vouched for. A CSR's subject is written by whoever is
 * enrolling, so trusting it is how a device enrolls itself as CN=admin. This
 * fills one in because PKCS#10 requires the field, not because anything
 * downstream believes it.
 */
object CertificateRequest {

    /** SHA-256 with ECDSA, matching the P-256 keys the agent generates. */
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /**
     * A [ContentSigner] backed by a `Signature` this code did not create.
     *
     * The indirection exists for the Android Keystore: its private keys are
     * unextractable by design, so BouncyCastle cannot be handed one. It can be
     * handed something that signs, which is all a CSR needs.
     */
    private class SignatureContentSigner(
        private val signature: Signature,
        private val algorithmIdentifier: org.bouncycastle.asn1.x509.AlgorithmIdentifier,
    ) : ContentSigner {
        private val buffer = java.io.ByteArrayOutputStream()

        override fun getAlgorithmIdentifier() = algorithmIdentifier

        override fun getOutputStream(): java.io.OutputStream = buffer

        override fun getSignature(): ByteArray {
            signature.update(buffer.toByteArray())
            return signature.sign()
        }
    }

    /**
     * @param subjectCommonName a placeholder; the CA does not trust it (see above)
     * @param publicKey the key being certified
     * @param signer a Signature already initialised for signing with the
     *   matching private key - from the Android Keystore on a device
     */
    fun build(
        subjectCommonName: String,
        publicKey: PublicKey,
        signer: Signature,
    ): PKCS10CertificationRequest {
        val algorithmIdentifier =
            org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder()
                .find(SIGNATURE_ALGORITHM)
        val builder = JcaPKCS10CertificationRequestBuilder(
            X500Name("CN=$subjectCommonName"),
            publicKey,
        )
        return builder.build(SignatureContentSigner(signer, algorithmIdentifier))
    }

    /** Convenience for tests and for any caller holding an extractable key. */
    fun build(
        subjectCommonName: String,
        publicKey: PublicKey,
        privateKey: PrivateKey,
    ): PKCS10CertificationRequest {
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        return build(subjectCommonName, publicKey, signature)
    }

    /**
     * PEM, which is what the enrollment endpoint takes.
     *
     * PEM rather than DER over the wire deliberately: the request travels
     * through a JSON body and, when something goes wrong, through a log and a
     * human's terminal. Base64 with a header survives all three; raw DER does
     * not survive the first one without another layer of encoding.
     */
    fun toPem(csr: PKCS10CertificationRequest): String {
        val out = StringWriter()
        PemWriter(out).use { it.writeObject(PemObject("CERTIFICATE REQUEST", csr.encoded)) }
        return out.toString()
    }
}
