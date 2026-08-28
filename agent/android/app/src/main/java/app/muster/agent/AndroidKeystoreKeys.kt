package app.muster.agent

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * The device's key, generated inside the Android Keystore and never extractable.
 *
 * THIS IS THE POINT OF THE WHOLE DESIGN. muster's rule is that a private key
 * never moves, and here that is not a promise the code makes - it is enforced
 * by the platform. `KeyStore.getEntry` hands back a `PrivateKey` object that is
 * a HANDLE; the bytes live in hardware and there is no API that returns them.
 * A control plane holding every device's private key is one breach away from
 * being every device, and this is what makes that impossible rather than
 * merely against policy.
 *
 * STRONGBOX WHERE THERE IS ONE, and a fallback where there is not. A Pixel 6a
 * has a Titan M2, so the key lives in a separate security chip. Devices without
 * one still get a TEE-backed key, which is weaker but still unextractable.
 * Asking for StrongBox unconditionally throws `StrongBoxUnavailableException`
 * on hardware that lacks it, which would mean an agent that runs on Pixels and
 * mysteriously fails everywhere else.
 *
 * WHAT IS DELIBERATELY NOT SET: no `setUserAuthenticationRequired`. These are
 * appliances that boot unattended in a cupboard, and a key that cannot be used
 * until somebody unlocks the screen is a device that never renews its own
 * certificate. That is a real security trade and it is made on purpose: the key
 * is protected by being unextractable, not by being gated on a human.
 */
class AndroidKeystoreKeys(
    private val context: Context,
    private val alias: String = DEFAULT_ALIAS,
) : EnrollmentFlow.DeviceKeys {

    /**
     * The device's key, generating it only if there is not one already.
     *
     * Idempotent, and that is load-bearing rather than tidy: `EnrollmentFlow`
     * calls this on every retry, and a version that generated each time would
     * change the fingerprint on the screen while the operator is comparing it
     * against the console.
     */
    override fun ensure(): EnrollmentFlow.DeviceKeys.Material {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        val existing = store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        if (existing != null) {
            return material(existing.privateKey, existing.certificate.publicKey)
        }

        Log.i(TAG, "generating a device key in the keystore (alias=$alias)")
        val pair = generate(strongBox = true) ?: generate(strongBox = false)
        ?: error("could not generate a device key in the Android Keystore")
        return material(pair.private, pair.public)
    }

    private fun generate(strongBox: Boolean): java.security.KeyPair? = try {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (strongBox) builder.setIsStrongBoxBacked(true)

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(builder.build()) }
            .generateKeyPair()
    } catch (e: Exception) {
        // Only the StrongBox attempt is allowed to fail quietly - the caller
        // retries without it. A failure on the fallback is returned as null and
        // becomes the error() above, because a device with no key cannot enroll
        // and pretending otherwise produces a confusing failure much later.
        if (strongBox) {
            Log.i(TAG, "no StrongBox on this device; using the TEE-backed keystore")
            null
        } else {
            Log.e(TAG, "keystore key generation failed", e)
            null
        }
    }

    private fun material(
        privateKey: PrivateKey,
        publicKey: java.security.PublicKey,
    ): EnrollmentFlow.DeviceKeys.Material {
        // A Signature initialised against the keystore handle. This is what
        // CertificateRequest signs the CSR with, and it is the only way to use
        // a key whose bytes nothing can read.
        val signer = Signature.getInstance(CertificateRequest.SIGNATURE_ALGORITHM)
        signer.initSign(privateKey)
        return EnrollmentFlow.DeviceKeys.Material(publicKey, signer)
    }

    /** Is there already a key? Asked of the keystore, never cached. */
    fun exists(): Boolean =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(alias)

    companion object {
        private const val TAG = "muster"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        /**
         * The alias is an interface with the device, not a local name.
         *
         * Change it and every already-enrolled device generates a second key,
         * enrolls again as a stranger, and leaves the first one orphaned in
         * hardware where nothing will ever clean it up.
         */
        const val DEFAULT_ALIAS = "muster-device-identity"
    }
}
