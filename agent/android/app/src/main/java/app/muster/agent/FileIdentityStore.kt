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
        // Staged and renamed, each one (muster#229). Renewal runs inside a
        // boot broadcast that may run out of time, and a device.crt cut off
        // part way is an identity the server refuses with no way back on the
        // device. A failed write throws and leaves the previous file whole.
        StagedWrite.replace(File(dir, "device.crt"), certificatePem)
        StagedWrite.replace(File(dir, "ca.crt"), caPem)
        // One line each, so a human reading it over adb gets an answer rather
        // than a parsing exercise.
        StagedWrite.replace(File(dir, "not-after"), notAfter)
        StagedWrite.replace(File(dir, "renew-after"), renewAfter)
    }

    override fun hasIdentity(): Boolean = File(dir, "device.crt").isFile

    fun notAfter(): String? = File(dir, "not-after").takeIf { it.isFile }?.readText()?.trim()

    fun renewAfter(): String? = File(dir, "renew-after").takeIf { it.isFile }?.readText()?.trim()

    /**
     * The file a check-in's renew-after replaces (muster#22), or null when
     * there is nothing to replace: no identity yet, or the value is unchanged.
     * The write itself is ConfigurationSteward's, the one staged-and-renamed
     * write the fetch already has, so a reader never sees half a timestamp.
     */
    fun staleRenewAfter(renewAfter: String): File? =
        File(dir, "renew-after").takeIf { hasIdentity() && renewAfter != renewAfter() }
}
