package app.muster.agent

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.UserManager
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.io.File
import java.security.cert.CertificateFactory
import java.time.OffsetDateTime
import java.util.concurrent.Executors

/**
 * The app's home: what this device is, rather than a form asking it to enroll.
 *
 * This is the LAUNCHER activity now. Enrollment is reached from here and only
 * when there is something to enroll - the previous arrangement showed an
 * enrolled Device Owner an empty pairing box, which is the app telling the
 * person holding the phone something untrue about the thing managing it.
 *
 * All the deciding is in DeviceStatus, which is a plain object with tests. This
 * class gathers facts and draws them, and is deliberately dull: two of the
 * states it can render - a lapsed certificate, a clock behind its own identity -
 * cannot be arranged on hardware on demand, so none of the logic that chooses
 * between them lives here.
 */
class StatusActivity : Activity() {

    private val work = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_status)

        findViewById<Button>(R.id.enroll).setOnClickListener {
            startActivity(Intent(this, EnrollActivity::class.java))
        }
        findViewById<Button>(R.id.sync).setOnClickListener { sync() }
    }

    // Re-read on every return to the screen. Enrollment happens in another
    // activity, and coming back to a stale "Not enrolled" would be the same
    // class of lie this screen was written to remove.
    override fun onResume() {
        super.onResume()
        render()
    }

    /**
     * Reconcile now, rather than at the next boot.
     *
     * The only thing that reconciled a device before this button was a reboot:
     * BOOT_COMPLETED is a protected broadcast, so neither a person holding the
     * phone nor an operator over adb could ask it to check in.
     */
    private fun sync() {
        val button = findViewById<Button>(R.id.sync)
        button.isEnabled = false
        setStatus("Checking in...")
        work.execute {
            val steps = BootPlan.STEPS.map { (name, run) ->
                SyncReport.Step(
                    name,
                    try {
                        run(this)
                    } catch (e: Exception) {
                        Log.e(TAG, "sync: $name failed", e)
                        SyncReport.Threw(name, e.message)
                    },
                )
            }
            val report = SyncReport.of(steps)
            CheckIn.record(this, System.currentTimeMillis() / 1000)
            main.post {
                report.detail.forEach { Log.i(TAG, "sync $it") }
                // ON THE SCREEN, NOT ONLY IN LOGCAT. A phone enrolled by QR has
                // no adb and no cable, so the reason a step enforced nothing has
                // to arrive somewhere the person holding it can read.
                report.concerns.forEach { Log.e(TAG, "sync CONCERN $it") }
                lastReport = report
                button.isEnabled = true
                render()
            }
        }
    }

    private fun setStatus(message: String) {
        findViewById<TextView>(R.id.detail).text = message
    }

    /**
     * The last check-in's report, or null before the first one this launch.
     *
     * NOT PERSISTED, deliberately: a concern from a previous launch that has
     * since been fixed would be worse than no concern at all, and the button
     * that refreshes it is on the same screen.
     */
    private var lastReport: SyncReport.View? = null

    private fun render() {
        val view = DeviceStatus.render(gather())
        findViewById<TextView>(R.id.headline).text = view.headline
        // The identity detail says whether this device is in the kith. The
        // report says whether being in it changed anything, which is a
        // different question and the one that goes unanswered without this.
        val report = lastReport
        findViewById<TextView>(R.id.detail).text = if (report == null) {
            view.detail
        } else {
            listOf(view.detail, report.headline).joinToString("\n\n")
        }

        // CONCERNS GET THEIR OWN VIEWS, and until 2026-09-02 they did not: they
        // were joined onto `detail`, which rendered "2 of 10 steps need
        // attention" in the same dim paragraph as "this device is owned by
        // Muster". Two sentences with opposite urgency, drawn identically, and
        // the urgent one second.
        val concerns = findViewById<LinearLayout>(R.id.concerns)
        concerns.removeAllViews()
        val outstanding = report?.concerns.orEmpty()
        concerns.visibility = if (outstanding.isEmpty()) View.GONE else View.VISIBLE
        for (concern in outstanding) {
            val item = layoutInflater.inflate(R.layout.row_concern, concerns, false)
            item.findViewById<TextView>(R.id.concern).text = concern
            concerns.addView(item)
        }

        findViewById<Button>(R.id.enroll).visibility =
            if (view.canEnroll) View.VISIBLE else View.GONE

        val rows = findViewById<LinearLayout>(R.id.rows)
        rows.removeAllViews()
        for ((index, row) in view.rows.withIndex()) {
            val item = layoutInflater.inflate(R.layout.row_fact, rows, false)
            item.findViewById<TextView>(R.id.label).text = row.label
            item.findViewById<TextView>(R.id.value).apply {
                text = row.value
                // A build stamp or a URL is compared character by character;
                // the mono face is what makes that possible. `machine` is
                // decided in DeviceStatus, where the value comes from.
                if (row.machine) {
                    setTextAppearance(R.style.Muster_RowValue_Mono)
                }
            }
            // The first rule would sit directly under the button block and read
            // as an underline for it rather than as the top of a list.
            if (index == 0) {
                item.findViewById<View>(R.id.rule).visibility = View.GONE
            }
            rows.addView(item)
        }
    }

    private fun gather(): DeviceStatus.Facts {
        val store = FileIdentityStore(this)
        val now = System.currentTimeMillis() / 1000
        val notBefore = certificateNotBefore()
        val notAfter = store.notAfter()
        val renewAfter = store.renewAfter()

        return DeviceStatus.Facts(
            deviceOwner = MusterDeviceAdminReceiver.isDeviceOwner(this),
            stance = IdentityLifecycle.stance(
                notBefore = notBefore,
                notAfter = epochOf(notAfter),
                renewAfter = epochOf(renewAfter),
                now = now,
            ),
            revoked = RevocationStore.current(this),
            notAfter = epochOf(notAfter),
            renewAfter = epochOf(renewAfter),
            serverUrl = serverUrl(),
            restrictions = restrictionsInForce(),
            agentVersion = packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown",
            lastCheckIn = CheckIn.last(this),
            now = now,
        )
    }

    /**
     * Read out of the certificate rather than stored beside it.
     *
     * IdentityLifecycle needs notBefore to tell ClockBehind from Lapsed, and
     * that value only exists inside the certificate - a copy written next to it
     * would be one more thing that can disagree with the thing it describes.
     */
    private fun certificateNotBefore(): Long? = try {
        val pem = File(
            createDeviceProtectedStorageContext().filesDir, "identity/device.crt"
        ).takeIf { it.isFile }?.readBytes()
        pem?.let {
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(it.inputStream())
            cert.let { c ->
                (c as java.security.cert.X509Certificate).notBefore.time / 1000
            }
        }
    } catch (e: Exception) {
        Log.w(TAG, "could not read the certificate's start date", e)
        null
    }

    /** The server states these as ISO instants; a malformed one is not a crash. */
    private fun epochOf(iso: String?): Long? = try {
        iso?.takeIf { it.isNotBlank() }?.let { OffsetDateTime.parse(it).toEpochSecond() }
    } catch (e: Exception) {
        Log.w(TAG, "unparseable timestamp: $iso", e)
        null
    }

    private fun serverUrl(): String? =
        File(createDeviceProtectedStorageContext().filesDir, "server-url")
            .takeIf { it.isFile }?.readText()?.trim()

    /**
     * Asked of the platform, never echoed from the config file.
     *
     * A config file says what was requested. Only the device says what is true,
     * and `addUserRestriction` does not reject a key it does not recognise - it
     * stores something nothing enforces.
     */
    private fun restrictionsInForce(): List<String> {
        if (!MusterDeviceAdminReceiver.isDeviceOwner(this)) return emptyList()
        val dpm = getSystemService(DevicePolicyManager::class.java) ?: return emptyList()
        val ours = dpm.getUserRestrictions(MusterDeviceAdminReceiver.component(this))
        val effective = getSystemService(UserManager::class.java)?.userRestrictions
        return ours.keySet()
            .filter { ours.getBoolean(it, false) && effective?.getBoolean(it, false) != false }
            .sorted()
    }

    companion object {
        private const val TAG = "muster"
    }
}
