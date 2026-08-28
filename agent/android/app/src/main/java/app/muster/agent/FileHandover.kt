package app.muster.agent

import android.content.Context
import android.util.Log
import java.io.File

/**
 * What provisioning left behind, on disk.
 *
 * DEVICE-PROTECTED STORAGE, for the same reason `server-url` and the identity
 * are there: this is read by a device that has just been wiped and may never be
 * unlocked by anybody. Credential-protected storage is unreadable before first
 * unlock, so a code written there would be invisible at exactly the moment it
 * is for.
 *
 * Beside `server-url` and deliberately in the same directory. The two arrive in
 * the same admin extras bundle, are written by the same activity, and are
 * useless apart - a code with nowhere to send it enrolls nothing, and an
 * address with no code is the device that waits to be typed at.
 */
class FileHandover(context: Context) : HandsFreeEnrollment.Handover {

    private val dir = context.createDeviceProtectedStorageContext().filesDir

    override fun pairingCode(): String? =
        ProvisioningPolicy.pairingCode(read(PAIRING_CODE))

    override fun requestId(): String? = read(REQUEST_ID)?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * READ BACK, BECAUSE THIS IS THE ONE FILE WHOSE LOSS IS UNRECOVERABLE.
     *
     * The server address and the pairing code are both replaceable - an operator
     * can re-provision or type a code. This id cannot be: the code was spent the
     * instant muster accepted it, so presenting again answers CODE_USED, and a
     * certificate an administrator vouched for would sit uncollected with
     * nothing on either side able to connect the two. It is verified at least as
     * hard as the two values that do not matter as much.
     *
     * It does not throw. The caller is a boot receiver or a provisioning screen,
     * neither of which may fail over a file, and the id is still in memory for
     * the rest of this run - what is lost is only surviving a reboot. So this
     * says so at ERROR, loudly, naming what it costs.
     */
    override fun rememberRequest(requestId: String) {
        val target = File(dir, REQUEST_ID)
        try {
            target.writeText(requestId)
        } catch (e: Exception) {
            Log.e(TAG, "could not write $REQUEST_ID: a vouch for this device may go uncollected", e)
            return
        }
        if (target.takeIf { it.isFile }?.readText()?.trim() != requestId) {
            Log.e(
                TAG,
                "$REQUEST_ID did not land: this device will re-present a spent " +
                    "code after a reboot and be refused, and the certificate " +
                    "already vouched for will never be collected",
            )
        }
    }

    override fun forget() {
        // Deleted, not blanked. An empty file and an absent one mean the same
        // thing to every reader above, but an operator running `ls` over adb on
        // a device that would not enroll should see nothing there rather than
        // something that looks like a value which failed to write.
        for (name in listOf(PAIRING_CODE, REQUEST_ID)) {
            val file = File(dir, name)
            if (file.exists() && !file.delete()) {
                // Never thrown. This runs inside a boot receiver and inside
                // provisioning, and neither may fail over a file that could not
                // be unlinked - the worst case is a spent code being re-presented
                // once more and refused, which is what the server is for.
                Log.w(TAG, "could not delete $name; it will be re-presented and refused")
            }
        }
    }

    private fun read(name: String): String? =
        File(dir, name).takeIf { it.isFile }?.readText()

    companion object {
        private const val TAG = "muster"

        /**
         * The names are an interface with an operator holding adb, not locals.
         *
         * `docs/provisioning-a-pixel.md` and any future runbook name these when
         * a device will not enroll and somebody has to look at why. Renaming one
         * costs nothing at build time and makes every written instruction wrong.
         */
        const val PAIRING_CODE = "pairing-code"
        const val REQUEST_ID = "enroll-request"
    }
}
