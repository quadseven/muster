package app.muster.agent

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.io.File
import java.util.concurrent.Executors

/**
 * The device half of the pairing ceremony.
 *
 * Thin on purpose. Every decision - which key, what the CSR says, what each
 * status means, when to retry - lives in EnrollmentFlow and its collaborators,
 * all of which are tested without a device. This class turns taps into calls
 * and results into text, and nothing else. An Activity that made decisions
 * would be a set of decisions that can only be exercised by hand on hardware.
 *
 * THE FINGERPRINT IS THE PRODUCT of this screen. Everything else is
 * scaffolding around getting that string in front of a person who is also
 * looking at the console.
 */
class EnrollActivity : Activity() {

    private val work = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var flow: EnrollmentFlow
    private var polling = false
    /** Kept so a retry re-presents the SAME code rather than an empty one. */
    private var lastCode: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_enroll)

        flow = EnrollmentFlow(
            keys = AndroidKeystoreKeys(this),
            client = EnrollmentClient(HttpTransport(serverBaseUrl())),
            store = FileIdentityStore(this),
            deviceName = android.os.Build.MODEL ?: "android",
        )

        findViewById<Button>(R.id.enroll).setOnClickListener {
            val code = findViewById<EditText>(R.id.code).text.toString().trim()
            if (code.isEmpty()) return@setOnClickListener
            lastCode = code
            say("Presenting...")
            work.execute { handle(flow.present(code)) }
        }
    }

    /**
     * Where the control plane lives.
     *
     * Read from a file the provisioning tool writes rather than compiled in.
     * A hostname baked into an APK is one that cannot change without a release,
     * and on a Device Owner app a release eventually means a factory reset.
     */
    private fun serverBaseUrl(): String {
        val file = File(createDeviceProtectedStorageContext().filesDir, "server-url")
        return if (file.isFile) file.readText().trim() else ""
    }

    // A BLOCK body, not an expression one. `handle` reaches itself through the
    // Retry branch, and an inferred return type on a recursive function is
    // something Kotlin refuses to work out - but declaring `: Unit` on an
    // expression body does not fix it either, because Handler.post returns
    // Boolean. The block discards that and the recursion resolves.
    private fun handle(step: EnrollmentFlow.Step) {
        main.post {
            when (step) {
            is EnrollmentFlow.Step.AwaitingVouch -> {
                showFingerprint(step.fingerprint)
                say("Waiting for an administrator to approve this device.")
                if (!polling) {
                    polling = true
                    poll(step.requestId)
                }
            }
            is EnrollmentFlow.Step.Enrolled -> {
                polling = false
                say("Enrolled. This device now has an identity.")
            }
            is EnrollmentFlow.Step.Stopped -> {
                polling = false
                say(step.reason)
            }
            is EnrollmentFlow.Step.Retry -> {
                // Re-present the SAME code. An empty one here was a bug: it
                // would burn an attempt against the server on a code the
                // operator never typed, and report their real code as wrong.
                say("${step.detail} - retrying in ${step.afterSeconds}s")
                main.postDelayed(
                    { work.execute { handle(flow.present(lastCode)) } },
                    step.afterSeconds * 1000,
                )
            }
            }
        }
    }

    private fun poll(requestId: String) {
        work.execute {
            val step = flow.collect(requestId)
            main.post {
                when (step) {
                    is EnrollmentFlow.Step.Retry ->
                        main.postDelayed({ poll(requestId) }, step.afterSeconds * 1000)
                    else -> handle(step)
                }
            }
        }
    }

    private fun say(message: String) {
        findViewById<TextView>(R.id.status).text = message
    }

    private fun showFingerprint(fingerprint: String) {
        findViewById<TextView>(R.id.fingerprint_label).visibility = View.VISIBLE
        findViewById<TextView>(R.id.fingerprint).apply {
            text = fingerprint
            visibility = View.VISIBLE
        }
    }
}
