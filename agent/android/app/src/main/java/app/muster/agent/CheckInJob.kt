package app.muster.agent

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.util.Log

/**
 * Reconcile this device on a timer, not only when it boots.
 *
 * WHY JobScheduler AND NOT WorkManager. WorkManager wraps this and would be one
 * more dependency inside a Device Owner app - a package that cannot easily be
 * taken back off a handset - to schedule one periodic job. The platform already
 * does Doze, backoff and persistence across reboot; the wrapper buys API
 * pleasantness for a call made in one place.
 *
 * `setPersisted` IS WHAT MAKES THIS SURVIVE A REBOOT, and it is also why
 * BootReceiver still schedules: persisted jobs survive, but a device that has
 * never scheduled one - a fresh install, a restore - has nothing to survive.
 * Both paths call the same idempotent `ensureScheduled`.
 *
 * NOTHING HERE DECIDES ANYTHING. It runs `BootPlan.STEPS`, which is the same
 * list a boot runs and the same list the status screen's button runs, so a
 * check-in cannot drift from a boot. A step that is wrong is wrong in all three.
 */
class CheckInJob : JobService() {

    private val work = java.util.concurrent.Executors.newSingleThreadExecutor()

    override fun onStartJob(params: JobParameters?): Boolean {
        work.execute {
            val steps = BootPlan.STEPS.map { (name, run) ->
                SyncReport.Step(
                    name,
                    try {
                        run(this)
                    } catch (e: Exception) {
                        Log.e(TAG, "check-in: $name failed", e)
                        SyncReport.Threw(name, e.message)
                    },
                )
            }
            val report = SyncReport.of(steps)
            report.detail.forEach { Log.i(TAG, "check-in $it") }
            // AT ERROR, so `logcat -s muster:E` on a device that is behaving
            // oddly shows the reason rather than a wall of successful steps.
            report.concerns.forEach { Log.e(TAG, "check-in CONCERN $it") }
            CheckIn.record(this, System.currentTimeMillis() / 1000)
            // A FETCH THAT DID NOT REACH MUSTER ASKS TO BE WOKEN WHEN A NETWORK
            // APPEARS. The periodic job carries no network constraint - the
            // local steps must run on a device sitting on a dead router - so
            // without this a failed fetch waits the whole interval. For a bond
            // leg whose router just came back, that is seconds versus fifteen
            // minutes.
            val reached = steps.none {
                it.name == "configuration" && it.outcome.concerns().any { c ->
                    c.contains("no fresh policy")
                }
            }
            if (CheckInSchedulePolicy.needsCatchUp(reached)) scheduleCatchUp(this)
            // `false`: never reschedule THIS run. The job is periodic, so the
            // next one is already coming; asking for a retry on top of that is
            // how one failing step becomes a device reconciling continuously.
            jobFinished(params, false)
        }
        // `true` = work continues on another thread. Returning false here would
        // tell the platform the job finished before any of it ran.
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        // The platform took the device back - Doze, or the constraints stopped
        // being met. `true` asks for a reschedule, which for a periodic job
        // means the next interval rather than an immediate retry.
        return true
    }

    companion object {
        private const val TAG = "muster"

        /**
         * Schedule the check-in, unless one is already scheduled correctly.
         *
         * IDEMPOTENT BY NECESSITY, not politeness. `schedule()` on an existing
         * periodic job REPLACES it and restarts its interval, so calling this
         * unconditionally from every boot and every supervision pass would push
         * the next check-in permanently into the future - a device that looks
         * scheduled and never runs.
         */
        /**
         * Ask to be run once, soon, as soon as there is a network.
         *
         * A SEPARATE JOB ID FROM THE PERIODIC ONE. Sharing it would make this
         * REPLACE the periodic job: the device would recover once and then
         * never reconcile again - a worse bug than the one being fixed, and one
         * that would look like a success.
         *
         * Scheduling this repeatedly is harmless: a one-shot job replaced by an
         * identical one-shot job is still one pending run.
         */
        fun scheduleCatchUp(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            val job = JobInfo.Builder(
                CheckInSchedulePolicy.CATCH_UP_JOB_ID,
                ComponentName(context, CheckInJob::class.java),
            )
                // THE WHOLE POINT OF THIS JOB, and the one difference from the
                // periodic one: it waits for a network rather than ignoring it.
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setMinimumLatency(CheckInSchedulePolicy.CATCH_UP_BACKOFF_MS)
                .setBackoffCriteria(
                    CheckInSchedulePolicy.CATCH_UP_BACKOFF_MS,
                    JobInfo.BACKOFF_POLICY_EXPONENTIAL,
                )
                .setPersisted(true)
                .build()
            // WRAPPED, BECAUSE A REFUSAL HERE MUST NOT END THE PROCESS.
            //
            // `schedule` does not merely return false when the platform objects
            // to the job's SHAPE - it throws. A missing ACCESS_NETWORK_STATE
            // threw SecurityException from this line on a handset whose
            // enrolment had just been refused, and because this runs on a
            // JobService worker the uncaught exception killed the process, the
            // job rescheduled, and the device crash-looped showing "Muster keeps
            // stopping" to somebody standing over a phone they believed was
            // enrolling.
            //
            // The permission is declared now. This stays because the shape of
            // the failure is the problem: this code path exists to recover from
            // a failed fetch, and a recovery path that can take the process down
            // makes every ordinary failure fatal.
            val outcome = try {
                scheduler.schedule(job)
            } catch (e: Exception) {
                Log.e(TAG, "check-in: the platform refused the catch-up schedule outright", e)
                return
            }
            if (outcome != JobScheduler.RESULT_SUCCESS) {
                Log.e(TAG, "check-in: the platform refused the catch-up schedule")
            } else {
                Log.i(TAG, "check-in: catch-up queued for when a network appears")
            }
        }

        fun ensureScheduled(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: run {
                Log.e(TAG, "check-in: no JobScheduler; this device will not self-reconcile")
                return
            }
            val existing = scheduler.allPendingJobs
                .firstOrNull { it.id == CheckInSchedulePolicy.JOB_ID }
                ?.intervalMillis
            if (!CheckInSchedulePolicy.needsScheduling(existing)) {
                Log.i(TAG, "check-in: already scheduled every ${existing}ms")
                return
            }
            val job = JobInfo.Builder(
                CheckInSchedulePolicy.JOB_ID,
                ComponentName(context, CheckInJob::class.java),
            )
                .setPeriodic(CheckInSchedulePolicy.INTERVAL_MS)
                // Survives reboot. Needs RECEIVE_BOOT_COMPLETED, which this app
                // already holds for its own boot receiver.
                .setPersisted(true)
                .setRequiredNetworkType(
                    if (CheckInSchedulePolicy.REQUIRES_NETWORK) JobInfo.NETWORK_TYPE_ANY
                    else JobInfo.NETWORK_TYPE_NONE
                )
                .build()
            val result = try {
                scheduler.schedule(job)
            } catch (e: Exception) {
                // See scheduleCatchUp. A device that cannot schedule reconciles
                // only at boot; a device whose agent dies trying does not
                // reconcile at all, and takes the status screen with it.
                Log.e(TAG, "check-in: the platform refused the schedule outright", e)
                return
            }
            if (result == JobScheduler.RESULT_SUCCESS) {
                Log.i(TAG, "check-in: scheduled every ${CheckInSchedulePolicy.INTERVAL_MS}ms")
            } else {
                // LOUD. A device that failed to schedule reconciles only at
                // boot, which is the exact state this whole feature exists to
                // end - and it would otherwise be silent.
                Log.e(TAG, "check-in: the platform REFUSED the schedule (result=$result)")
            }
        }
    }
}
