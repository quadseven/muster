package app.muster.agent

/**
 * When should this device replace its certificate, and what may it do meanwhile?
 *
 * WHY THIS IS NOT `if (now > notAfter) renew()`. The devices muster manages are
 * routers in hotels and phones in drawers. Three things follow that a naive
 * expiry check gets wrong, and each one strands a device that was working:
 *
 *  1. **Renewal must start long before expiry**, because the device may be
 *     offline for the whole window. Waiting until the last day means a phone
 *     switched off for a fortnight comes back with a dead identity and no way
 *     to get a new one except the cable it was enrolled with.
 *
 *  2. **An expired identity is not the same as no identity.** A device whose
 *     certificate lapsed while it was in a drawer should say so precisely, so
 *     an operator sees "expired 3 days ago" rather than "not enrolled" - which
 *     reads as somebody having wiped it.
 *
 *  3. **The clock may be wrong.** The GL-MT3000 has no RTC and can boot in
 *     1970. A device that believes it is before its own certificate's
 *     not-before must not conclude the certificate is invalid and delete it -
 *     that is a device destroying its identity because it does not know what
 *     day it is. It reports the skew and keeps the certificate.
 */
object IdentityLifecycle {

    /** What the agent should do about its identity right now. */
    sealed interface Stance {
        /** Healthy and well inside its life. Do nothing. */
        object Current : Stance

        /** Past the renewal point. Try to renew; the identity still works. */
        data class ShouldRenew(val secondsUntilExpiry: Long) : Stance

        /** Expired. Renewal is the only path back, and mTLS will now fail. */
        data class Lapsed(val secondsSinceExpiry: Long) : Stance

        /**
         * The device's clock is before the certificate's own not-before.
         *
         * NOT treated as invalid, deliberately. See the class docstring: this
         * is a device that does not know the date, and deleting a good
         * certificate over it is unrecoverable without a cable.
         */
        data class ClockBehind(val secondsOfSkew: Long) : Stance

        /** No certificate at all. Enrollment, not renewal. */
        object Unenrolled : Stance
    }

    /**
     * @param notBefore  epoch seconds from the certificate
     * @param notAfter   epoch seconds from the certificate
     * @param renewAfter epoch seconds the server said to start renewing at
     * @param now        epoch seconds by this device's own clock
     */
    fun stance(
        notBefore: Long?,
        notAfter: Long?,
        renewAfter: Long?,
        now: Long,
    ): Stance {
        if (notBefore == null || notAfter == null) return Stance.Unenrolled

        if (now < notBefore) return Stance.ClockBehind(notBefore - now)
        if (now >= notAfter) return Stance.Lapsed(now - notAfter)

        // renewAfter missing is not an error: an older server, or an identity
        // stored before the field existed. Fall back to a third of life, which
        // is what the server would have said anyway.
        val threshold = renewAfter ?: (notBefore + (notAfter - notBefore) / 3)
        return if (now >= threshold) Stance.ShouldRenew(notAfter - now) else Stance.Current
    }

    /**
     * How long to wait before the next renewal attempt, in seconds.
     *
     * Exponential with a ceiling, and the CEILING matters more than the growth:
     * a device that has been failing for a week must still try roughly hourly,
     * because the usual reason it is failing is that it has no network - and
     * the moment it gets one it must not be sitting in a day-long backoff.
     *
     * The floor matters too. A device retrying instantly against a server that
     * is refusing it is a device hammering an endpoint it cannot use.
     */
    fun backoffSeconds(consecutiveFailures: Int): Long {
        if (consecutiveFailures <= 0) return 0
        val floor = 30L
        val ceiling = 3600L
        var wait = floor
        repeat(minOf(consecutiveFailures - 1, 20)) {
            wait *= 2
            if (wait >= ceiling) return ceiling
        }
        return minOf(wait, ceiling)
    }
}
