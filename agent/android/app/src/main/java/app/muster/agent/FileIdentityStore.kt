package app.muster.agent

import android.content.Context
import java.io.File

/**
 * Where the issued certificate lives.
 *
 * Device-protected storage, for the same reason the wallpaper state is: the
 * agent runs before first unlock on an appliance that may sit in a cupboard for
 * days, and credential-protected storage is unreadable then. An identity the
 * device cannot read at boot is an identity it does not have.
 *
 * The PRIVATE key is not here and never will be - it is in the keystore, which
 * is the whole point (AndroidKeystoreKeys). These are public certificates.
 */
class FileIdentityStore(context: Context) : EnrollmentFlow.IdentityStore {

    private val dir = File(
        context.createDeviceProtectedStorageContext().filesDir, "identity"
    ).apply { mkdirs() }

    override fun save(
        certificatePem: String,
        caPem: String,
        notAfter: String,
        renewAfter: String,
    ) {
        File(dir, "device.crt").writeText(certificatePem)
        File(dir, "ca.crt").writeText(caPem)
        // One line each, so a human reading it over adb gets an answer rather
        // than a parsing exercise.
        File(dir, "not-after").writeText(notAfter)
        File(dir, "renew-after").writeText(renewAfter)
    }

    override fun hasIdentity(): Boolean = File(dir, "device.crt").isFile

    fun notAfter(): String? = File(dir, "not-after").takeIf { it.isFile }?.readText()?.trim()

    fun renewAfter(): String? = File(dir, "renew-after").takeIf { it.isFile }?.readText()?.trim()
}
