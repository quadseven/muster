package app.muster.agent

import android.content.Context
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import java.io.File
import java.io.IOException

/**
 * Put the device's wifi network where the served `wifi` file says (muster#195).
 *
 * THE THIN HALF. Every decision is WifiPolicy's, where the JVM harness runs it;
 * this class only supplies the platform behind [WifiPolicy.Target] and the
 * applied-digest record behind [WifiPolicy.Ledger].
 *
 * WHY THESE CALLS. `WifiManager.addNetwork` is deprecated and returns -1 for an
 * ordinary app from Android 10, and Device Owner is one of its documented
 * exemptions. With no network id, the platform matches an existing
 * configuration by SSID and security and updates it, so "add" and "update" are
 * the same call. `getCallerConfiguredNetworks` (Android 12) lists the networks
 * this app configured, which is the question asked: did the device forget ours.
 * Below 12 the full list needs a location grant, so an empty answer there is
 * "cannot say" and the network is handed over again.
 *
 * NONE OF THIS IS PROVEN BY A UNIT TEST, and nothing here pretends otherwise.
 * Whether a handset that forgot the network rejoins it is the live check on
 * the ticket.
 */
class WifiSteward(private val context: Context) {

    private fun directory(): File =
        // Device-protected, like every file the boot path reads: this runs at
        // LOCKED_BOOT_COMPLETED, before first unlock.
        context.createDeviceProtectedStorageContext().filesDir

    /** Where ConfigurationSteward writes the served file. */
    fun configFile(): File = File(directory(), WifiPolicy.FILE_NAME)

    fun reconcile(): WifiPolicy.Outcome {
        val file = configFile()
        val served = if (!file.isFile) {
            null
        } else {
            try {
                file.readText()
            } catch (e: IOException) {
                // Refuse rather than read an unreadable file as absent. The
                // message names the file, never its content.
                val outcome = WifiPolicy.Outcome(WifiPolicy.LeaveAlone, inert = "the wifi file could not be read")
                Log.w(TAG, "wifi: $outcome")
                return outcome
            }
        }
        return WifiPolicy.reconcile(served, Ledger(File(directory(), WifiPolicy.APPLIED_FILE)), Platform(context)) {
            Log.i(TAG, it)
        }
    }

    private class Ledger(private val file: File) : WifiPolicy.Ledger {
        override fun lastApplied(): String? = try {
            file.takeIf { it.isFile }?.readText()?.trim()?.ifEmpty { null }
        } catch (e: IOException) {
            null
        }

        override fun record(digest: String) {
            try {
                file.writeText(digest)
            } catch (e: IOException) {
                // A lost record costs one more platform write next check-in,
                // which merges into the same configuration.
                Log.w(TAG, "wifi: the applied record could not be written")
            }
        }
    }

    private class Platform(private val context: Context) : WifiPolicy.Target {

        private val wifi: WifiManager? = context.getSystemService(WifiManager::class.java)

        override val isDeviceOwner: Boolean get() = MusterDeviceAdminReceiver.isDeviceOwner(context)

        @Suppress("DEPRECATION")
        override fun onDevice(ssid: String): Boolean? {
            val manager = wifi ?: return null
            return try {
                val wanted = WifiPolicy.quoted(ssid)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    manager.callerConfiguredNetworks.any { it.SSID == wanted }
                } else {
                    val all = manager.configuredNetworks.orEmpty()
                    if (all.isEmpty()) null else all.any { it.SSID == wanted }
                }
            } catch (e: SecurityException) {
                null
            }
        }

        @Suppress("DEPRECATION")
        override fun save(network: WifiPolicy.Network): Boolean {
            val manager = wifi ?: return false
            return try {
                val id = manager.addNetwork(configuration(network))
                id != -1 && manager.enableNetwork(id, false)
            } catch (e: SecurityException) {
                false
            }
        }

        @Suppress("DEPRECATION")
        private fun configuration(network: WifiPolicy.Network): WifiConfiguration =
            WifiConfiguration().apply {
                SSID = WifiPolicy.quoted(network.ssid)
                val modern = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
                when (network.security) {
                    "WPA" -> {
                        preSharedKey = WifiPolicy.quoted(network.passphrase)
                        if (modern) {
                            setSecurityParams(WifiConfiguration.SECURITY_TYPE_PSK)
                        } else {
                            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK)
                        }
                    }
                    "WEP" -> {
                        wepKeys[0] = WifiPolicy.wepKey(network.passphrase)
                        wepTxKeyIndex = 0
                        if (modern) {
                            setSecurityParams(WifiConfiguration.SECURITY_TYPE_WEP)
                        } else {
                            allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)
                            allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN)
                            allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED)
                        }
                    }
                    else -> if (modern) {
                        setSecurityParams(WifiConfiguration.SECURITY_TYPE_OPEN)
                    } else {
                        allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)
                    }
                }
            }
    }

    companion object {
        private const val TAG = "muster"
    }
}
