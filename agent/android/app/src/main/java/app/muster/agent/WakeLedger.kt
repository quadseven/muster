package app.muster.agent

import android.content.Context

/**
 * Which packages have been told about which configuration.
 *
 * WHY THIS EXISTS AT ALL. An explicit wake is a one-shot broadcast, and Android
 * does not queue it for a component that is not installed yet. `sendBroadcast`
 * reports nothing either way, so a wake aimed at a package whose installation
 * has not finished is indistinguishable from one that arrived.
 *
 * That race is not hypothetical - it is the ordinary case. The install step
 * COMMITS a PackageInstaller session; the installation completes
 * asynchronously, some time after the step returns. So the configuration step
 * that follows can write restrictions and fire a wake at a component that does
 * not exist for another second or two.
 *
 * Gating the wake on "did the configuration change this pass" made that
 * permanent: the next reconciliation finds the configuration already matching,
 * short-circuits, and never wakes anything again. A freshly enrolled handset on
 * 2026-08-23 sat exactly there - zippie 152 installed, correctly configured,
 * process alive, relay never started, and nothing that would ever retry.
 *
 * The ledger replaces "has the configuration changed" with "has THIS package
 * been told about THIS configuration", which is the question that actually
 * needs answering. A fingerprint is recorded only after a wake is sent to a
 * package the platform confirms is installed, so a wake that could not have
 * landed is not remembered as delivered, and the next pass tries again.
 */
object WakeLedger {

    /**
     * The ledger key for a wake target: component AND action.
     *
     * THE KEY MUST BE AS SPECIFIC AS THE FINGERPRINT. The fingerprint includes
     * the action, so two wakes sharing a component but differing in action
     * produce two different fingerprints - and a component-only key means each
     * send overwrites the other's record. Neither ever matches, so both fire on
     * every pass forever: the fifteen-minute battery burn this mechanism exists
     * to avoid, arriving through an aliasing collision between the key and the
     * value.
     */
    fun key(wake: AppConfigPolicy.Wake): String = "${wake.component}#${wake.action}"

    private const val PREFS = "muster-wake-ledger"

    private fun prefs(context: Context) =
        context.createDeviceProtectedStorageContext()
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * The configuration fingerprint this TARGET was last successfully told about.
     *
     * KEYED BY COMPONENT AND ACTION, NOT PACKAGE. A package may declare more than one wake
     * target, and a package-keyed ledger lets a send to one component mark the
     * others as told. Worse in the failure interleaving: if the first wake fails
     * and the second succeeds, recording under the shared package name asserts
     * that the failed one was delivered, and it is never retried. The component
     * is globally unique and is the thing the send actually targeted.
     */
    fun wokenFor(context: Context, component: String): String? =
        AppConfigPolicy.ledgerFingerprint(
            prefs(context).getString(component, null),
            bootCount(context),
        )

    /**
     * Remember that this package was woken for this configuration.
     *
     * ONLY CALL THIS AFTER A SEND TO A RESOLVED, ENABLED RECEIVER. Recording a
     * wake that went nowhere is how the ledger would come to assert a delivery
     * that never happened - the same lie, one layer further in.
     */
    fun record(context: Context, component: String, fingerprint: String) {
        prefs(context).edit()
            .putString(component, AppConfigPolicy.ledgerValue(bootCount(context), fingerprint))
            .apply()
    }

    /**
     * Which boot this is, from the platform.
     *
     * `Settings.Global.BOOT_COUNT` increments on every boot and is readable
     * during direct boot, which is where this ledger lives. On the impossible
     * reading it returns -1, and every entry then fails to match - so the
     * failure mode is waking an app that did not need it, not leaving one
     * asleep that did.
     */
    private fun bootCount(context: Context): Long =
        android.provider.Settings.Global.getLong(
            context.contentResolver,
            android.provider.Settings.Global.BOOT_COUNT,
            -1L,
        )
}
