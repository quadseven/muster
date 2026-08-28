package app.muster.agent

import java.security.PublicKey
import java.security.Signature

/**
 * Enrollment from the device's side, end to end: key, CSR, present, poll, store.
 *
 * THE BUG THIS IS SHAPED TO AVOID. The obvious implementation generates a key
 * pair at the start of `enroll()`. Retry after a wrong code and it generates
 * another - so the fingerprint on the device's screen CHANGES while the
 * operator is looking at it, and the one they eventually compare against the
 * console is not the one they were shown. Worse, on hardware-backed storage
 * every discarded key is one more entry the device can never clean up.
 *
 * So the key is created once, on first need, and reused for the life of the
 * device. `DeviceKeys.ensure()` is idempotent by contract, and there is
 * deliberately no way to ask this class to regenerate: a key that changes is a
 * device that loses its identity, and the recovery for that is a cable.
 *
 * WHAT IS NOT HERE. No threading, no timers, no lifecycle. `step()` is called
 * by whatever is driving - a WorkManager job, a foreground service, a test -
 * and returns what to do next. A state machine that owns its own clock cannot
 * be tested at the states that matter.
 */
class EnrollmentFlow(
    private val keys: DeviceKeys,
    private val client: EnrollmentClient,
    private val store: IdentityStore,
    private val deviceName: String,
) {

    /** The device's key material. Generated once, never exported. */
    interface DeviceKeys {
        /**
         * The key for this device, creating it only if absent.
         *
         * MUST be idempotent. Called on every retry, and a version that
         * generates each time changes the fingerprint under the operator.
         */
        fun ensure(): Material

        data class Material(val publicKey: PublicKey, val signer: Signature)
    }

    /** Where the issued identity is kept. */
    interface IdentityStore {
        fun save(certificatePem: String, caPem: String, notAfter: String, renewAfter: String)
        fun hasIdentity(): Boolean
    }

    sealed interface Step {
        /** Show this to the operator; they must compare it with the console. */
        data class AwaitingVouch(val requestId: String, val fingerprint: String) : Step
        /** Enrolled. The device has an identity. */
        object Enrolled : Step
        /** Tell the operator, in these words. Enrollment has stopped. */
        data class Stopped(val reason: String) : Step
        /** Try again after this many seconds. */
        data class Retry(val afterSeconds: Long, val detail: String) : Step
    }

    private var failures = 0

    /**
     * Present this device against a pairing code.
     *
     * Returns what the caller should do next. Note that a refusal which the
     * operator can fix - a mistyped code - is `Stopped` rather than `Retry`,
     * because retrying the SAME wrong code achieves nothing; the operator has
     * to act, and telling them so is more useful than a spinner.
     */
    fun present(code: String): Step {
        val material = keys.ensure()
        val csr = CertificateRequest.toPem(
            CertificateRequest.build(deviceName, material.publicKey, material.signer)
        )

        return when (val outcome = client.present(code, csr, deviceName)) {
            is EnrollmentClient.Presented.Accepted -> {
                failures = 0
                Step.AwaitingVouch(outcome.requestId, outcome.fingerprint)
            }
            is EnrollmentClient.Presented.WrongCode ->
                Step.Stopped("That code was not recognized. Check it and try again.")
            is EnrollmentClient.Presented.CodeExpired ->
                Step.Stopped("That code has expired. Generate a new one and try again.")
            is EnrollmentClient.Presented.CodeAlreadyUsed ->
                Step.Stopped("That code has already been used. Generate a new one.")
            is EnrollmentClient.Presented.TooManyAttempts ->
                Step.Stopped("Too many attempts on that code. Generate a new one.")
            is EnrollmentClient.Presented.MalformedRequest ->
                // Our CSR, our bug. Saying "check the code" would send the
                // operator hunting something that is not wrong.
                Step.Stopped("This device built a request the server could not read.")
            is EnrollmentClient.Presented.Unreachable -> {
                failures += 1
                Step.Retry(IdentityLifecycle.backoffSeconds(failures), outcome.detail)
            }
            is EnrollmentClient.Presented.Unexpected -> {
                failures += 1
                Step.Retry(
                    IdentityLifecycle.backoffSeconds(failures),
                    "unexpected status ${outcome.status}",
                )
            }
        }
    }

    /**
     * Poll for the administrator's vouch.
     *
     * `Waiting` is the expected answer for as long as it takes a human to walk
     * to a laptop, so it does not count as a failure and does not grow the
     * backoff. Counting it would push the poll interval out to an hour while
     * the operator is standing there wondering why nothing happens.
     */
    fun collect(requestId: String): Step =
        when (val outcome = client.collect(requestId)) {
            is EnrollmentClient.Collected.Issued -> {
                store.save(
                    outcome.certificatePem,
                    outcome.caPem,
                    outcome.notAfter,
                    outcome.renewAfter,
                )
                failures = 0
                Step.Enrolled
            }
            is EnrollmentClient.Collected.Waiting ->
                Step.Retry(POLL_INTERVAL_S, "waiting for an administrator to vouch")
            is EnrollmentClient.Collected.Gone ->
                Step.Stopped("This enrollment is no longer available. Start again with a new code.")
            is EnrollmentClient.Collected.Unreachable -> {
                failures += 1
                Step.Retry(IdentityLifecycle.backoffSeconds(failures), outcome.detail)
            }
            is EnrollmentClient.Collected.Unexpected -> {
                failures += 1
                Step.Retry(
                    IdentityLifecycle.backoffSeconds(failures),
                    "unexpected status ${outcome.status}",
                )
            }
        }

    companion object {
        /**
         * How often to ask whether a human has vouched yet.
         *
         * Short, because someone is standing there watching, and this is the
         * one part of the ceremony where a person is actively waiting on the
         * device rather than the other way round.
         */
        const val POLL_INTERVAL_S = 3L
    }
}
