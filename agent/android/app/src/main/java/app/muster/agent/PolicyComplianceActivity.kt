package app.muster.agent

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.util.Log
import android.widget.TextView
import java.io.File
import java.util.concurrent.Executors

/**
 * The last thing the platform runs before handing the device over.
 *
 * WHAT IT IS FOR, AND WHAT MUSTER USES IT FOR. The platform's purpose for this
 * screen is to let an administrator show compliance requirements before setup
 * finishes. muster has none to show, so it does the two things that can only be
 * done here: it reads the admin extras bundle, and - because this is the one
 * moment on a hands-free device when something is allowed to wait - it enrolls.
 *
 * THIS IS WHERE THE SERVER ADDRESS ARRIVES. The provisioning QR has always
 * carried `muster.server_url` in EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, and
 * until this activity existed nothing on the device read it - there was no code
 * anywhere referencing the extras bundle at all. A QR-provisioned phone
 * therefore came up owned, healthy, and with an empty server address, and the
 * enrollment screen had nowhere to send it. The only way to fix it was adb,
 * which is the cable the QR exists to avoid.
 *
 * THE PAIRING CODE ARRIVES THE SAME WAY, and it is what takes the last person
 * off the handset. Both are written to device-protected storage, because
 * anywhere else and the value is unreadable before first unlock, which is
 * exactly when an appliance would try to use it.
 *
 * PROVISIONING MUST FINISH, WHATEVER HAPPENS HERE. AOSP is blunt about the
 * cost: "if provisioning fails, the device is factory reset". So the watchdog
 * below is armed BEFORE anything else runs, every step catches THROWABLE rather
 * than Exception, and the activity finishes with RESULT_OK on every path
 * including the ones where enrollment got nowhere. Throwable and not Exception
 * because an Error on the worker thread kills the process, and a watchdog on the
 * main looper cannot save a path that destroys the looper. The worst case this
 * can produce is a phone that comes up owned and unenrolled, which the boot plan
 * retries and a person can finish by hand - not a wiped one.
 *
 * NOT MEASURED ON A HANDSET. The extras-adoption half was: `server-url` landed
 * during provisioning on <device-serial> on 2026-08-19 with no cable. The
 * enrollment half was written without a device and nobody has watched a phone
 * do it.
 */
class PolicyComplianceActivity : Activity() {

    private val work = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // ARMED FIRST, before a single line that can throw or block. Everything
        // after this point is allowed to fail, hang or be slow; none of it can
        // leave setup sitting on this screen, because this is already queued.
        main.postDelayed({ handOver("enrollment did not finish in time") }, DEADLINE_MS)

        // SOMETHING RATHER THAN A BLANK WINDOW. This screen used to finish
        // instantly; it can now hold setup for up to ninety seconds, and a
        // blank one for that long reads as a phone that has locked up - which
        // is when somebody pulls the battery on a device mid-provisioning.
        //
        // The try/catch is what makes this optional, not the fact that the view
        // is built in code: `getString` is still a resource lookup. Drawing is
        // cosmetic and enrollment is not, so nothing here may stop the rest.
        try {
            setContentView(
                TextView(this).apply {
                    text = getString(R.string.provisioning_enrolling)
                    setPadding(64, 128, 64, 64)
                }
            )
        } catch (e: Throwable) {
            Log.w(TAG, "could not draw the provisioning screen; carrying on without it", e)
        }

        val extras = try {
            adopt()
        } catch (e: Throwable) {
            // Recoverable over adb, or by hand on the phone. A device that
            // factory-reset itself during setup is a wipe and a second attempt.
            Log.e(TAG, "could not adopt the provisioning extras", e)
            false
        }
        if (!extras) {
            handOver("nothing usable in the provisioning extras")
            return
        }
        // THE HAND-OFF ITSELF IS GUARDED, not just what it hands off. Every
        // other line in this method is inside a try for a reason, and this one
        // was the exception: `execute` can reject, and a throw escaping
        // onCreate is a crashed activity, which is a failed provisioning, which
        // is a wiped handset. The catch is what makes the guard above complete
        // rather than nearly complete.
        try {
            startEnrolling()
        } catch (t: Throwable) {
            Log.e(TAG, "could not start enrollment", t)
            handOver("enrollment could not be started")
        }
    }

    private fun startEnrolling() {
        work.execute {
            // THROWABLE, NOT EXCEPTION, and the difference is a factory reset.
            // An Error on this thread - a NoClassDefFoundError out of the
            // keystore or BouncyCastle, an OutOfMemoryError parsing a
            // certificate - reaches the default uncaught handler and kills the
            // PROCESS. That takes the main looper with it, and the watchdog
            // armed above lives on the main looper: it cannot save a path that
            // destroys the thread it is queued on. So provisioning would fail
            // with no result set, and AOSP factory-resets a device whose
            // provisioning fails.
            val outcome = try {
                enroll()
            } catch (t: Throwable) {
                Log.e(TAG, "hands-free enrollment failed", t)
                "failed: ${t.message}"
            }
            main.post { handOver(outcome) }
        }
    }

    /**
     * Take the server address and the pairing code out of the bundle.
     *
     * Returns whether there is an address, which is the one value without which
     * nothing else here can do anything. A code with nowhere to send it enrolls
     * nothing; an address with no code is a device that waits to be typed at,
     * and that is a legitimate QR to have minted.
     */
    private fun adopt(): Boolean {
        @Suppress("DEPRECATION") // The Class-typed overload is API 33; minSdk is 29.
        val extras = intent.getParcelableExtra<PersistableBundle>(
            DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE
        )

        val code = ProvisioningPolicy.pairingCode(
            extras?.getString(ProvisioningPolicy.PAIRING_CODE_KEY)
        )
        if (code == null) {
            // INFO and not a warning: a QR minted to be printed carries no code
            // on purpose, and a line that reads like a fault would send somebody
            // hunting a problem that is a deliberate choice.
            Log.i(TAG, "no pairing code in the provisioning extras; this device enrolls by hand")
        } else {
            // NEVER THE CODE ITSELF, here or anywhere. logcat on a device being
            // provisioned in a room is a screen in that room, and the server
            // side drops the same field for the same reason (telemetry.py).
            write(FileHandover.PAIRING_CODE, code)
            Log.i(TAG, "pairing code adopted from provisioning (${code.length} characters)")
        }

        val url = ProvisioningPolicy.serverUrl(extras?.getString(ProvisioningPolicy.SERVER_URL_KEY))
        if (url == null) {
            Log.w(TAG, "no usable ${ProvisioningPolicy.SERVER_URL_KEY} in the provisioning extras")
            return false
        }
        write("server-url", url)
        Log.i(TAG, "server address adopted from provisioning: $url")
        return true
    }

    /**
     * Write, then read back rather than trust it.
     *
     * These files decide where a freshly wiped phone tries to enroll and with
     * what, and the next things to read them are a different process at boot and
     * a background thread moments from now.
     */
    private fun write(name: String, value: String) {
        val target = File(createDeviceProtectedStorageContext().filesDir, name)
        target.writeText(value)
        val landed = target.takeIf { it.isFile }?.readText()?.trim()
        if (landed != value) {
            Log.e(TAG, "$name did not land: wrote ${value.length} characters, read back ${landed?.length}")
        }
    }

    /** Present and poll until enrolled, refused, or out of time. */
    private fun enroll(): String {
        val flow = EnrollmentFlow(
            keys = AndroidKeystoreKeys(this),
            client = EnrollmentClient(HttpTransport(serverUrl())),
            store = FileIdentityStore(this),
            deviceName = android.os.Build.MODEL ?: "android",
        )
        val hands = HandsFreeEnrollment(
            flow = { flow }, store = FileHandover(this), identity = FileIdentityStore(this),
        )
        // Its own deadline, and a shorter one than the watchdog's. The watchdog
        // is the guarantee that setup finishes; this is the loop noticing first,
        // so the usual path ends by finishing rather than by being cut off.
        //
        // THE GAP HAS TO COVER A WHOLE CALL, not a moment. `runUntil` checks the
        // clock before it advances and cannot know how long the next call will
        // take, so a request started just inside the deadline can still be
        // sitting in HttpTransport's 10s connect plus 20s read. A five-second
        // gap looked right and was not: it would be exceeded on precisely the
        // run that needs it, the one where the network is what failed, and the
        // watchdog would cut the loop off and log a timeout instead of the
        // loop's own verdict.
        val deadline = System.currentTimeMillis() + DEADLINE_MS - WORST_CASE_CALL_MS
        return hands.runUntil(
            deadlineMillis = deadline,
            now = { System.currentTimeMillis() },
            sleep = { Thread.sleep(it) },
        ).toString()
    }

    private fun serverUrl(): String {
        val file = File(createDeviceProtectedStorageContext().filesDir, "server-url")
        return if (file.isFile) file.readText().trim() else ""
    }

    /**
     * Finish provisioning. Idempotent, because two paths race to call it.
     *
     * The watchdog and the enrollment thread can both arrive, and calling
     * `finish()` twice is harmless while logging twice is a runbook reading two
     * contradictory outcomes for one device.
     */
    private fun handOver(outcome: String) {
        if (done) return
        done = true
        Log.i(TAG, "provisioning compliance finished: $outcome")
        setResult(RESULT_OK)
        finish()
    }

    override fun onDestroy() {
        super.onDestroy()
        main.removeCallbacksAndMessages(null)
        // The enrollment thread is left to finish its current call rather than
        // interrupted. It may be mid-POST of a CSR, and abandoning that puts a
        // request in the operator's queue whose id this device never learned.
        work.shutdown()
    }

    companion object {
        private const val TAG = "muster"

        /**
         * How long setup may sit here waiting to be vouched for.
         *
         * A COMPROMISE BETWEEN TWO REAL COSTS, neither of which is theoretical.
         * Too short and the operator, who is walking from the phone to the
         * console they minted the QR on, does not get there in time - the device
         * finishes setup unenrolled and somebody has to touch it after all. Too
         * long and a phone with no network sits on a blank compliance screen for
         * minutes looking broken.
         *
         * Ninety seconds is the walk-to-the-laptop-and-click number. Missing it
         * costs nothing permanent: the request is already lodged and its id is on
         * disk, so the next boot collects the certificate an administrator
         * vouched for while the screen was gone.
         */
        private const val DEADLINE_MS = 90_000L

        /**
         * How long one enrollment call can take at worst, so the loop can stop
         * before the watchdog rather than being cut off by it.
         *
         * COUPLED TO HttpTransport'S OWN TIMEOUTS - 10s connect plus 20s read -
         * with five seconds over. Change either of those and this is the number
         * that has to move with them; the symptom of forgetting is not a
         * failure, it is a log that says "did not finish in time" for every
         * device on a slow network instead of saying what actually happened.
         */
        private const val WORST_CASE_CALL_MS = 35_000L
    }
}
