package app.muster.agent

/**
 * How often a device reconciles itself, decided without touching Android.
 *
 * WHY THIS EXISTS (muster#58). Configuration was fetched AT BOOT ONLY, so a
 * device that came up wrong stayed wrong until somebody rebooted it or pressed
 * a button on its screen. The operator asked the right question about that -
 * "why do i have to tap to check in it should check in on its own" - and the
 * outage that made it urgent is worse than a missed reboot.
 *
 * Two Pixels acting as bond legs drained flat overnight and rebooted. Their
 * relay starts at LOCKED_BOOT_COMPLETED, deliberately, so a phone locked in a
 * car still relays - but the console write token is deliberately NOT cached
 * before first unlock, because it is a credential rather than configuration. So
 * each relay came up forwarding bytes and unable to ANNOUNCE itself. No
 * announce, no leg, and the router lost every uplink it had.
 *
 * There is no self-heal path on that side. What fixes it is re-delivering the
 * configuration to the LIVE process: the companion's restrictions-changed
 * receiver assigns the config AND starts announcing, so a device that gets its
 * app-config again starts announcing again with no reboot and no credential
 * cached anywhere. Nothing was re-delivering anything. This is what does.
 */
object CheckInSchedulePolicy {

    /**
     * How long between check-ins.
     *
     * FIFTEEN MINUTES BECAUSE THAT IS THE FLOOR ANDROID HONOURS. JobScheduler
     * clamps a periodic job to fifteen minutes; asking for one minute does not
     * fail, it silently becomes fifteen - and a constant that lies about what
     * the device does is worse than a slower one that does not.
     *
     * Not shorter for another reason: every check-in reconciles the whole boot
     * plan, and one of those steps now fetches over the network. A device in a
     * drawer should cost a request an hour, not a request a minute.
     */
    const val INTERVAL_MS: Long = 15 * 60_000L

    /**
     * One device, one schedule.
     *
     * STABLE, AND DERIVED FROM NOTHING. A job id computed from a timestamp or a
     * hash of the configuration would leave one orphaned periodic job per
     * change - each still firing, none cancelled, and the device reconciling N
     * times per interval with no way to tell from the outside.
     */
    const val JOB_ID: Int = 0x7A1DE

    /**
     * Whether the check-in needs the network to be worth running.
     *
     * FALSE, AND THAT IS THE POINT OF IT. Most of the boot plan is LOCAL:
     * restrictions, app visibility and app configuration are reconciled from
     * files already on the device, and those are exactly what a half-started
     * device is missing. Requiring a network would mean a device sitting on a
     * dead router - the case this exists for - never reconciles at all, which
     * is the failure rather than a saving.
     */
    const val REQUIRES_NETWORK: Boolean = false

    /**
     * Does the schedule need writing, given what is already there?
     *
     * @param existingIntervalMs the interval of a periodic job already
     *   scheduled under [JOB_ID], or null if there is none.
     *
     * RESCHEDULING RESTARTS THE INTERVAL, which is the whole reason this is a
     * decision rather than an unconditional call. A device that rewrote its
     * schedule on every boot, every sync press and every supervision pass would
     * push its own next check-in permanently into the future and never run one -
     * and from the outside that is indistinguishable from a schedule that works.
     */
    fun needsScheduling(existingIntervalMs: Long?): Boolean =
        existingIntervalMs != INTERVAL_MS

    /**
     * A second job id, for the catch-up. NEVER the same as [JOB_ID].
     *
     * Sharing one would make scheduling the catch-up REPLACE the periodic job:
     * the device would recover once and then never reconcile again, which is a
     * worse bug than the one being fixed and would look like a success.
     */
    const val CATCH_UP_JOB_ID: Int = 0x7A1DF

    /**
     * How long the catch-up waits before its first attempt, and the unit it
     * backs off by.
     *
     * SHORT, BECAUSE THE POINT IS RECOVERY SPEED. A leg whose router just came
     * back should reconcile in seconds, not at the next quarter hour. Backed
     * off rather than fixed, because a device whose network never returns must
     * not spin - JobScheduler doubles this on each failure.
     */
    const val CATCH_UP_BACKOFF_MS: Long = 30_000L

    /**
     * Should a one-shot, network-gated catch-up be scheduled?
     *
     * WHY THE PERIODIC JOB IS NOT ENOUGH BY ITSELF. It deliberately carries NO
     * network constraint, so that the local steps - restrictions, app
     * visibility, app configuration - still run on a device sitting on a dead
     * router. The cost of that choice is that a FETCH which failed waits the
     * full interval rather than recovering when connectivity returns.
     *
     * So the two jobs split the work honestly: the periodic one guarantees a
     * device reconciles at all, and this one guarantees it reconciles SOON
     * after the network comes back. Scheduled only on failure, because a
     * catch-up after every healthy check-in is a device waking itself twice per
     * interval forever for nothing.
     */
    fun needsCatchUp(fetchReachedMuster: Boolean): Boolean = !fetchReachedMuster
}
