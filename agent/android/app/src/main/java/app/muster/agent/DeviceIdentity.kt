package app.muster.agent

import android.content.Context
import java.io.File
import java.security.Signature
import java.util.Base64

/**
 * How this device proves who it is, and where its control plane lives.
 *
 * EXTRACTED SO THERE IS ONE COPY (muster#45). This began inside
 * `ConfigurationSteward` as a private class, and the moment a second thing a
 * device fetches arrived - an asset - the choice was a second copy or this. The
 * Base64 comment below says exactly why a second copy is a bad trade: the
 * encoder is a detail that is wrong in a way nobody sees until a handset gets a
 * 400 that reads like a signature problem.
 *
 * The certificate is PUBLIC and is read off disk; the private key is not here
 * and cannot be - `AndroidKeystoreKeys` hands back a handle to something whose
 * bytes no API returns, which is the whole point of the design (CONTEXT.md: the
 * private key never moves).
 */
class KeystoreIdentity(private val context: Context) : ConfigurationClient.Identity {

    override fun certificatePem(): String? =
        File(File(context.createDeviceProtectedStorageContext().filesDir, "identity"), "device.crt")
            .takeIf { it.isFile }
            ?.readText()
            ?.takeIf { it.isNotBlank() }

    override fun signBase64(nonce: String): String {
        val signer: Signature = AndroidKeystoreKeys(context).ensure().signer
        signer.update(nonce.toByteArray())
        // `getEncoder`, NOT `getMimeEncoder`, and not android.util.Base64 with
        // its default flags. Both of those wrap at 76 characters, and the
        // server decodes with `validate=True`, which rejects a newline -
        // arriving as a 400 that reads like a signature problem rather than
        // like a line break. java.util.Base64 needs API 26 and minSdk here is
        // 29; it also exists on the JVM, so nothing that uses it is untestable
        // off a device.
        return Base64.getEncoder().encodeToString(signer.sign())
    }

    companion object {
        /**
         * Where the control plane lives, for this device.
         *
         * The same file `EnrollActivity` reads, written by the provisioning
         * extras or by `muster provision --server-url`. Read from disk rather
         * than passed in because every caller runs from a broadcast receiver,
         * which has no state to carry.
         */
        fun serverBaseUrl(context: Context): String {
            val file = File(
                context.createDeviceProtectedStorageContext().filesDir, "server-url"
            )
            return if (file.isFile) file.readText().trim() else ""
        }
    }
}
