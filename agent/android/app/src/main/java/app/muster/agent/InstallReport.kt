package app.muster.agent

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import android.util.Log

/**
 * Where the platform reports the outcome of an install muster committed.
 *
 * WHY THIS EXISTS AT ALL. `PackageInstaller.Session.commit` REQUIRES an
 * `IntentSender`; there is no form of it that says "I do not care". For a
 * Device Owner there is nothing to approve, so the result is only ever news -
 * but the news has to go somewhere, and a sender pointing at nothing means the
 * outcome of every install is lost.
 *
 * WHAT IT IS NOT is the thing that decides whether an install worked. The next
 * reconcile asks the PLATFORM what version is installed, which is the answer
 * that cannot go stale and cannot be missed because a process died - and for
 * muster's own package this receiver is running inside the app being replaced,
 * so it may never be delivered at all. This is a log line, deliberately, and
 * the comment is here so nobody later builds a decision on top of it.
 */
class InstallReport : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(
            PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE
        )
        val packageName = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME).orEmpty()
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
        when (status) {
            PackageInstaller.STATUS_SUCCESS ->
                Log.i(TAG, "install-apps: platform installed '$packageName'")
            // A Device Owner should never see this: it is what a session gets
            // when it needs a human to tap approve. If it appears, the device is
            // NOT owned the way muster believes it is, and that is worth an
            // error rather than a shrug.
            PackageInstaller.STATUS_PENDING_USER_ACTION ->
                Log.e(
                    TAG,
                    "install-apps: '$packageName' is waiting for somebody to tap " +
                        "approve, which means this device is not owned - nobody " +
                        "is holding it",
                )
            else ->
                Log.e(TAG, "install-apps: '$packageName' failed, status=$status $message")
        }
        // RECORDED, because the reason a platform refused is not recoverable
        // any other way and one caller needs it to decide whether removing an
        // application is justified. Inferring "it refused because the signer
        // differs" from "it refused, and the signers differ" misdiagnoses every
        // OTHER refusal - a full disk, a transient package-manager error - as a
        // signature conflict, and the action that follows deletes the app's
        // data.
        if (packageName.isNotEmpty()) lastStatus[packageName] = status to message
    }

    companion object {
        private const val TAG = "muster"

        /**
         * The most recent platform verdict per package, in this process.
         *
         * IN MEMORY DELIBERATELY. It is read seconds after it is written, by
         * the pass that committed the session, and a value that outlived the
         * process would describe an install nobody is waiting on. Muster's own
         * update ends this process, and that is the one case where no caller
         * survives to read this anyway.
         */
        private val lastStatus = java.util.concurrent.ConcurrentHashMap<String, Pair<Int, String>>()

        /** Forget any previous verdict, so a stale one cannot be read as this one. */
        fun forget(packageName: String) {
            lastStatus.remove(packageName)
        }

        /**
         * Did the platform refuse this because the installed copy is signed by
         * a different key?
         *
         * `STATUS_FAILURE_CONFLICT` is what a signature mismatch surfaces as,
         * and the message carries INSTALL_FAILED_UPDATE_INCOMPATIBLE. Null means
         * no verdict has arrived yet - which is NOT a refusal, and must not be
         * read as one.
         */
        fun refusedForSignature(packageName: String): Boolean? {
            val (status, message) = lastStatus[packageName] ?: return null
            if (status == PackageInstaller.STATUS_SUCCESS) return false
            return status == PackageInstaller.STATUS_FAILURE_CONFLICT ||
                message.contains("UPDATE_INCOMPATIBLE") ||
                message.contains("SIGNATURE")
        }
        const val ACTION = "app.muster.agent.INSTALL_REPORT"

        /**
         * A sender for one install.
         *
         * `FLAG_MUTABLE` because the PLATFORM fills the result extras in; an
         * immutable sender would arrive with none of them and report every
         * install as a failure with no message. `FLAG_UPDATE_CURRENT` plus a
         * per-package request code so two installs in one run do not overwrite
         * each other's sender and both report the same package.
         */
        fun intentSender(context: Context, packageName: String): IntentSender {
            val intent = Intent(ACTION).setPackage(context.packageName)
            return PendingIntent.getBroadcast(
                context,
                packageName.hashCode(),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            ).intentSender
        }
    }
}
