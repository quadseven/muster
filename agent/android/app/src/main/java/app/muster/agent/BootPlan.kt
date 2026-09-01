package app.muster.agent

import android.content.Context

/**
 * Everything reconciled at boot, in order.
 *
 * A LIST RATHER THAN A RUN OF STATEMENTS, so that a test can assert what boot
 * actually does. This is not decoration. Restriction support existed in this
 * codebase for a while as a steward nothing ever called - `WallpaperSteward`
 * carried a `lock()` whose only possible caller defaulted the flag off - with
 * passing unit tests over a decision function production could not reach. A
 * capability is not wired because it compiles. It is wired because something
 * enumerates it, and enumerating it here is what lets a test say so.
 *
 * KEPT OUT OF BootReceiver ON PURPOSE. The receiver extends an Android class,
 * and reading a value off its companion from a JVM unit test means class-
 * loading a BroadcastReceiver against the stub android.jar. This object has no
 * Android supertype, so the test that guards the wiring costs nothing and
 * cannot fail for reasons that have nothing to do with the wiring.
 */
object BootPlan {

    /**
     * Name for the log, and the work. Order is the order they run in.
     *
     * TYPED `StepOutcome` RATHER THAN `Any?`, which is what it was while a
     * check-in could report success on a device that had enforced nothing.
     * `Any?` left the caller no question it could ask, so the caller printed
     * `toString` and rendered a screen from somewhere else entirely. A step
     * added here now cannot compile until it can say what went wrong.
     */
    val STEPS: List<Pair<String, (Context) -> StepOutcome>> = listOf(
        // FIRST, AND BEFORE THE FETCH BELOW, WHICH IS THE ORDER THAT MATTERS.
        // Configuration is fetched over the identity a device holds, so a device
        // that is not in the kith yet has nothing to fetch it with - putting
        // enrollment second would mean the first boot of a QR-provisioned phone
        // fetches nothing, and the operator waits for a second boot to see any
        // policy at all. This is also the only step that can change what the
        // others are allowed to do: everything after it reconciles a device
        // muster owns, and this is what finishes making it one.
        //
        // It is the RECOVERY half of hands-free enrollment.
        // PolicyComplianceActivity presents while the operator is standing
        // there; if the vouch arrives after that screen has gone, this is what
        // collects the certificate.
        //
        // EXACTLY ONE CALL, NO POLLING, and that is still true now that
        // BootReceiver runs this off the main thread. `goAsync` buys a budget,
        // not an unbounded one, and it is shared with every step after this -
        // so a step that waited here for a human to vouch would spend the whole
        // of it and the device would come up with no configuration fetched and
        // nothing reconciled. Waiting for a human is what the provisioning
        // screen is for; this one advances by a move and leaves.
        "enroll" to { context: Context -> enroll(context) },
        // BEFORE CONFIGURATION, so the rest of this check-in proves with the
        // certificate just written rather than spending one final request on
        // the old one. This is driven by the same fifteen-minute reconcile as
        // every other step: adding a renewal scheduler would create another
        // clock and another path BootPlan cannot prove is wired.
        "renew" to { context: Context -> RenewalSteward(context).reconcile() },
        // Then the fetch, and the order is the point here too. Every step after
        // this one is a reconciler over files in the agent's own directory, so
        // fetching before them means ONE boot both collects a policy change and
        // applies it. Fetching last would make every change take two boots, on
        // appliances that may not boot for months.
        "configuration" to { context: Context -> ConfigurationSteward(context).reconcile() },
        // AFTER CONFIGURATION AND BEFORE THE OTHER STEWARDS, because the wipe
        // instruction arrives as a managed file and this is the step that acts
        // on it. A wipe is terminal; anything that ran before it would not
        // matter, and anything after it may never run. Placed before the
        // restrictions deliberately: a device that has been told to erase
        // itself must not spend its remaining time reconciling less important
        // policy.
        "wipe" to { context: Context -> WipeSteward(context).reconcile() },
        "restrictions" to { context: Context -> RestrictionSteward(context).reconcile() },
        // After restrictions, because the restrictions are what keep a managed
        // app on the handset at all - there is no point configuring an app
        // somebody can still uninstall from Settings.
        // BEFORE app-config AND BEFORE apps, and that is the whole point of the
        // split (muster#81). Proved on a handset: zippie was installed and its
        // managed configuration was NOT applied in the same check-in, because
        // this ran after them and the package did not exist when they did. The
        // grant failed with DID_NOT_TAKE and the app sat installed,
        // unconfigured and hidden until the next pass.
        //
        // Everything EXCEPT muster, because installing muster ends the process
        // - see the last step.
        "install-apps" to { context: Context ->
            AppInstallSteward(context).reconcile(AppInstallPolicy.Only.OTHERS)
        },
        "app-config" to { context: Context -> AppConfigSteward(context).reconcile() },
        // MOVED DOWN HERE FROM AHEAD OF THE RESTRICTIONS (muster#45), because it
        // stopped being a local step. The image now arrives over the air, so
        // this makes a second network round trip inside the same `goAsync`
        // budget the fetch above already spent some of - and it is the only
        // COSMETIC step in the plan. Ahead of the restrictions it meant a phone
        // whose network was slow came up unrestricted for as long as a picture
        // took, which is trading the thing that matters for the thing that does
        // not. A device that never gets its wallpaper is a device that looks
        // wrong; a device that never gets its restrictions is unmanaged.
        "wallpaper" to { context: Context -> WallpaperSteward(context).reconcile() },
        // Last, and deliberately. It is the only step that makes a call per
        // package rather than a call per policy, so on the first boot after an
        // allowlist arrives it is much the longest - and a step that runs long
        // must not be one the others are queued behind.
        "apps" to { context: Context -> AppVisibilitySteward(context).reconcile() },
        // LAST, AND THE ORDER IS LOAD-BEARING TWICE OVER (muster#67).
        //
        // Last in the plan because installing muster's OWN package ends this
        // process - `AppInstallPolicy` already puts the agent last WITHIN the
        // step for the same reason, and putting the step anywhere but the end
        // would mean an update to the agent silently skipped every step behind
        // it. A boot that updates the agent must still have applied the
        // restrictions, the app configuration and the app visibility first.
        //
        // Last also because it is by far the most expensive: one twelve
        // megabyte download per application that needs one, against a `goAsync`
        // budget shared with everything above it.
        "install-self" to { context: Context ->
            AppInstallSteward(context).reconcile(AppInstallPolicy.Only.SELF)
        },
    )

    /**
     * One move of hands-free enrollment, or nothing at all.
     *
     * A FUNCTION RATHER THAN A LAMBDA because it is the only step that has to
     * build a client, and burying that in the list above would make the list
     * unreadable for the sake of symmetry. The decision itself is in
     * HandsFreeEnrollment, which is tested with no device.
     *
     * Returns AlreadyEnrolled on every boot of every enrolled device, which is
     * almost all of them, and does so without touching the network: the check is
     * a file on disk. This step must stay cheap, because it runs before the four
     * that actually reconcile the device.
     */
    private fun enroll(context: Context): HandsFreeEnrollment.Move {
        val identity = FileIdentityStore(context)
        // NO SHORT-CIRCUIT HERE, and there used to be one. This asked
        // `identity.hasIdentity()` itself before building anything, which read
        // as a cheap early exit and was a second copy of a decision
        // HandsFreeEnrollment already makes - so it returned before that class's
        // cleanup ran, and a device that scanned a hands-free QR, failed to
        // present, and was then enrolled by hand kept its spent pairing code in
        // device-protected storage for the life of the phone.
        //
        // The flow is a factory instead, so nothing is built on the common path
        // and there is exactly one place that decides whether there is anything
        // to do. Building one costs a file read and an HTTP client; deciding
        // twice costs a bug nothing on the device would ever report.
        return HandsFreeEnrollment(
            flow = { flowFor(context, identity) },
            store = FileHandover(context),
            identity = identity,
        ).advance()
    }

    private fun flowFor(
        context: Context,
        identity: FileIdentityStore,
    ): EnrollmentFlow {
        val serverUrl = java.io.File(
            context.createDeviceProtectedStorageContext().filesDir, "server-url"
        ).takeIf { it.isFile }?.readText()?.trim().orEmpty()
        return EnrollmentFlow(
            keys = AndroidKeystoreKeys(context),
            client = EnrollmentClient(HttpTransport(serverUrl)),
            store = identity,
            deviceName = android.os.Build.MODEL ?: "android",
        )
    }
}
