package app.muster.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Reconcile the device to what it is supposed to be, at boot.
 *
 * LOCKED_BOOT_COMPLETED as well as BOOT_COMPLETED, and this is the reason the
 * stewards keep their state in device-protected storage: on a phone with a lock
 * screen, LOCKED_BOOT_COMPLETED fires before first unlock, and an appliance
 * sitting on a charger in a cupboard may not be unlocked for days. A receiver
 * that only listens for BOOT_COMPLETED does nothing on exactly the devices this
 * exists for.
 *
 * Kept deliberately thin. Work here delays boot for everything else on the
 * phone, and a crash takes the receiver down with no way to see why on a device
 * nobody is holding.
 *
 * THE PLAN RUNS OFF THE MAIN THREAD, and it has to since the first step became
 * a network fetch (muster#46). `onReceive` runs on the main thread, and Android
 * throws `NetworkOnMainThreadException` for any socket opened there - which the
 * per-step catch below would have swallowed into one log line, leaving a device
 * that fetches nothing and looks exactly like one whose server is down. That is
 * this codebase's own recurring failure: a capability that is written, wired,
 * green, and cannot run.
 *
 * `goAsync` IS WHAT KEEPS THE PROCESS ALIVE while that happens. Without it the
 * system is free to kill the process the moment `onReceive` returns, and the
 * work would be cut off part way - mid-write, on a phone in a cupboard.
 *
 * IT DOES NOT BUY MORE TIME, AND IT IS EASY TO BELIEVE IT DOES. The broadcast
 * timeout is armed when the broadcast is dispatched and cancelled by
 * `PendingResult.finish()`; deferring the finish defers nothing about the
 * deadline. What `goAsync` buys is process lifetime and priority, not budget.
 * So the whole plan still has to fit in one background broadcast's allowance,
 * which is why the fetch uses shorter HTTP timeouts than enrollment does
 * (ConfigurationSteward) and why `finish()` is in a `finally` - a receiver that
 * never finishes is one the system eventually kills the hard way.
 *
 * NOT MEASURED ON A HANDSET. Two requests at 5s connect plus 8s read is up to
 * 26 seconds before the allowlist step - the longest one - has started, and
 * nothing here has watched that complete on a real boot.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        // ONE RECONCILE AT A TIME, AND THIS IS NOT HOUSEKEEPING. This receiver
        // is registered for BOTH LOCKED_BOOT_COMPLETED and BOOT_COMPLETED, so
        // it fires twice on a phone with a lock screen. While the plan ran on
        // the main thread that cost nothing - broadcasts to one receiver are
        // dispatched in order and the first had finished. Moving it onto a
        // thread removes that, and two plans running at once would have one
        // writing a config file while the other decides whether to delete it,
        // and two stewards asserting user restrictions against each other.
        //
        // The second broadcast is DROPPED rather than queued: it would do
        // exactly the same work, and waiting for the first burns the budget
        // goAsync bought. Said out loud, because "the plan did not run at
        // BOOT_COMPLETED" is otherwise indistinguishable from a receiver that
        // was never called.
        if (!running.compareAndSet(false, true)) {
            Log.i(TAG, "boot ($action): already reconciling; this broadcast is a duplicate")
            return
        }
        val pending = goAsync()
        // A plain Thread rather than an Executor: a receiver instance exists
        // for one broadcast, so an executor created here would have to be shut
        // down here too, and one forgotten path leaks a thread per boot.
        Thread({
            try {
                run(context, action)
            } finally {
                // ALWAYS, and in this order. An unfinished broadcast holds a
                // wake lock and counts against the system's budget for this
                // app; a flag left set means this device never reconciles again
                // until it reboots.
                running.set(false)
                pending.finish()
            }
        }, "muster-boot").start()
    }

    private fun run(context: Context, action: String) {
        // EACH STEP IS GUARDED SEPARATELY, which the single try/catch this
        // replaced did not do. With one block around everything, a wallpaper
        // that failed to decode took the restrictions down with it - and the
        // log said the wallpaper failed, so the missing restrictions looked
        // like they had never been asked for.
        for ((name, step) in BootPlan.STEPS) {
            try {
                val outcome = step(context)
                Log.i(TAG, "boot ($action): $name $outcome")
                // AT ERROR, SEPARATELY FROM THE LINE ABOVE. `logcat -s muster:E`
                // is what somebody runs against a device that is not behaving,
                // and a step that enforced nothing used to be invisible there -
                // its whole outcome arrived at INFO alongside the steps that
                // worked.
                for (concern in outcome.concerns()) {
                    Log.e(TAG, "boot ($action): $name CONCERN $concern")
                }
            } catch (e: Exception) {
                // Never let one of these kill the receiver. A device that fails
                // to apply a picture is cosmetic; a receiver that throws at
                // every boot is a device that never runs anything else added
                // here later.
                Log.e(TAG, "boot ($action): $name failed", e)
            }
        }
        // Recorded even if a step failed. "Last check-in" answers whether the
        // agent ran at all, which is a different question from whether it
        // liked what it found - and the first one somebody asks about a device
        // that is behaving oddly.
        CheckIn.record(context, System.currentTimeMillis() / 1000)
        // AFTER the steps, and unconditionally (muster#58). A persisted job
        // survives a reboot, so this is usually a no-op that logs "already
        // scheduled" - but a device that has never scheduled one, or whose
        // schedule the platform dropped, has nothing to survive, and boot is
        // the one moment guaranteed to come round again. `ensureScheduled` is
        // idempotent precisely so this can be called without thinking.
        CheckInJob.ensureScheduled(context)
    }

    companion object {
        private const val TAG = "muster"

        /**
         * Whether a reconcile is in flight, across every instance of this
         * receiver in this process.
         *
         * On the COMPANION deliberately: Android constructs a new receiver for
         * every broadcast, so an instance field would be a fresh `false` each
         * time and would guard nothing at all - the sort of lock that reads
         * correct and is not.
         */
        private val running = java.util.concurrent.atomic.AtomicBoolean(false)
    }
}
