package app.muster.agent

import android.content.Context
import android.util.Log
import java.io.File
import java.security.cert.CertificateFactory
import java.time.OffsetDateTime

/** Renew the identity during the same reconcile that already checks in. */
class RenewalSteward(private val context: Context) {

    fun reconcile(): RenewalFlow.Move {
        val store = FileIdentityStore(context)
        if (!store.hasIdentity()) return RenewalFlow.Move.NotDue
        val certificate = certificateDates()
            ?: return RenewalFlow.Move.Failed("could not read this device's identity certificate")
        val stance = IdentityLifecycle.stance(
            notBefore = certificate.first,
            notAfter = certificate.second,
            renewAfter = epochOf(store.renewAfter()),
            now = System.currentTimeMillis() / 1000,
        )
        if (stance !is IdentityLifecycle.Stance.ShouldRenew) {
            return RenewalFlow.Move.NotDue
        }
        val baseUrl = KeystoreIdentity.serverBaseUrl(context)
        if (baseUrl.isBlank()) {
            return RenewalFlow.Move.Failed("no muster server configured on this device")
        }
        return RenewalFlow(
            keys = AndroidKeystoreKeys(context),
            client = RenewalClient(
                HttpTransport(baseUrl, connectTimeoutMs = 5_000, readTimeoutMs = 8_000),
                KeystoreIdentity(context),
            ),
            store = store,
        ).advance(stance)
    }

    /**
     * Dates come from the certificate being renewed, not a second copy.
     *
     * `renew-after` has no certificate field and must be stored beside it, but
     * not-before and not-after do. Reading those from sidecar files would let a
     * half-written identity decide that a different certificate is due.
     */
    private fun certificateDates(): Pair<Long, Long>? = try {
        val pem = File(
            context.createDeviceProtectedStorageContext().filesDir, "identity/device.crt"
        ).takeIf { it.isFile }?.readBytes() ?: return null
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(pem.inputStream()) as java.security.cert.X509Certificate
        certificate.notBefore.time / 1000 to certificate.notAfter.time / 1000
    } catch (e: Exception) {
        Log.w(TAG, "could not read the identity certificate's dates", e)
        null
    }

    private fun epochOf(iso: String?): Long? = try {
        iso?.takeIf { it.isNotBlank() }?.let { OffsetDateTime.parse(it).toEpochSecond() }
    } catch (e: Exception) {
        Log.w(TAG, "could not read renew-after", e)
        null
    }

    companion object {
        private const val TAG = "muster"
    }
}
