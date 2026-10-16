package app.muster.agent

import android.content.Context
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.util.Log
import java.io.File

/**
 * Fetch the applications this device is told to carry, and install them.
 *
 * WHY A DEVICE OWNER CAN DO THIS AT ALL. muster is Device Owner, so a
 * `PackageInstaller` session it commits is approved without a person tapping
 * anything - which is the whole point, because the phones this manages are
 * appliances with nobody holding them. It is NOT "unknown sources": that
 * restriction governs other apps installing packages, and is one muster sets
 * (see RestrictionPolicy).
 *
 * NOTHING IS INSTALLED THAT DID NOT MATCH ITS DIGEST. The bytes come from
 * muster's asset store over this device's own identity, and are checked against
 * a digest named in a policy file fetched the same way. An agent that installed
 * whatever a server handed it would be a remote code execution primitive
 * carrying a certificate.
 *
 * INSTALLING MUSTER ITSELF ENDS THIS PROCESS, which is why `AppInstallPolicy`
 * puts it last and why nothing here assumes the loop finishes. Everything is
 * driven from state on disk and from what the platform reports, so an
 * interrupted run resumes at the next boot: a package already at the version
 * named is simply not in the plan.
 */
class AppInstallSteward(
    private val context: Context,
    private val clientFactory: () -> AssetClient? = { defaultClient(context) },
    private val ledgerFactory: () -> InstallLedger = { InstallLedger(context) },
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {

    data class Outcome(
        val installed: List<String> = emptyList(),
        val current: List<String> = emptyList(),
        val refused: List<AppInstallPolicy.Refusal> = emptyList(),
        /** Named an application and could not get usable bytes for it. */
        val couldNotFetch: List<String> = emptyList(),
        /** The bytes arrived and were not the bytes the policy named. */
        val substituted: List<String> = emptyList(),
        /** The platform refused the install. */
        val didNotTake: List<String> = emptyList(),
        /** Removed before installing, because the installed copy had a different signer. */
        val replaced: List<String> = emptyList(),
        /** A signer mismatch the policy did not authorize muster to resolve. */
        val weldedShut: List<String> = emptyList(),
        /** Failed recently, so not downloaded again yet (muster#146). */
        val backingOff: List<String> = emptyList(),
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            substituted.forEach { add("SUBSTITUTED $it") }
            weldedShut.forEach { add("WELDED $it") }
            couldNotFetch.forEach { add("COULD_NOT_FETCH $it") }
            didNotTake.forEach { add("DID_NOT_TAKE $it") }
            backingOff.forEach { add("BACKING_OFF $it") }
            inert?.let { add("nothing enforced - $it") }
            refused.forEach { add("REFUSED '${it.line}' - ${it.why}") }
        }

        override fun toString(): String = when {
            inert != null -> "nothing done: $inert"
            else -> buildString {
                append("installed=$installed current=${current.size}")
                if (substituted.isNotEmpty()) append(" SUBSTITUTED=$substituted")
                if (couldNotFetch.isNotEmpty()) append(" COULD_NOT_FETCH=$couldNotFetch")
                if (didNotTake.isNotEmpty()) append(" DID_NOT_TAKE=$didNotTake")
                if (backingOff.isNotEmpty()) append(" BACKING_OFF=${backingOff.size}")
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
            }
        }
    }

    /** What one pass found, collected package by package. */
    private class Tally {
        val installed = mutableListOf<String>()
        val couldNotFetch = mutableListOf<String>()
        val substituted = mutableListOf<String>()
        val didNotTake = mutableListOf<String>()
        val replaced = mutableListOf<String>()
        val weldedShut = mutableListOf<String>()
        val backingOff = mutableListOf<String>()
    }

    /** The `install-apps` policy file, written by ConfigurationSteward. */
    fun configFile(): File = File(
        context.createDeviceProtectedStorageContext().filesDir, AppInstallPolicy.FILE_NAME
    )

    fun reconcile(only: AppInstallPolicy.Only = AppInstallPolicy.Only.ALL): Outcome {
        val configured = configFile().takeIf { it.isFile }?.readText()
        val desired = AppInstallPolicy.read(configured)
        if (desired.wanted.isEmpty() && desired.refused.isEmpty()) {
            return Outcome()
        }
        // Ownership checked, not assumed: a session commit without it needs a
        // person to tap approve, which on an appliance nobody is holding means
        // a dialog nothing will ever answer.
        if (!MusterDeviceAdminReceiver.isDeviceOwner(context)) {
            val why = "not device owner; applications cannot be installed silently"
            Log.w(TAG, "install-apps: $why")
            return Outcome(inert = why, refused = desired.refused)
        }

        val plan = AppInstallPolicy.plan(desired, installedVersions(desired), only)
        for (refusal in plan.refused) {
            Log.w(TAG, "install-apps refused: ${refusal.line} - ${refusal.why}")
        }

        val ledger = ledgerFactory()
        ledger.keepOnly(desired.wanted.map { it.digest }.toSet())
        val tally = Tally()
        for (step in plan.install) attempt(step, ledger, tally)

        return Outcome(
            installed = tally.installed,
            current = plan.current,
            refused = plan.refused,
            couldNotFetch = tally.couldNotFetch,
            substituted = tally.substituted,
            didNotTake = tally.didNotTake,
            replaced = tally.replaced,
            weldedShut = tally.weldedShut,
            backingOff = tally.backingOff,
        )
    }

    /**
     * Every package the install file names, at the version the platform
     * reports NOW, null where it is not installed.
     *
     * For the check-in report (muster#146), and read after the install steps
     * rather than taken from their outcomes: the platform is the answer that
     * cannot be stale, and an install that landed after its step gave up
     * waiting is still an install.
     */
    fun managedVersions(): Map<String, Long?> {
        val desired = AppInstallPolicy.read(configFile().takeIf { it.isFile }?.readText())
        val have = installedVersions(desired)
        return desired.wanted.associate { it.packageName to have[it.packageName] }
    }

    /** Expected versionCode for each package named by the active install policy. */
    fun expectedVersions(): Map<String, Long> =
        AppInstallPolicy.read(configFile().takeIf { it.isFile }?.readText())
            .wanted.associate { it.packageName to it.versionCode }

    /** Installed packages visible through the launchable-app query in the manifest. */
    fun visibleInstalledVersions(): Map<String, Long?> {
        val packages = context.packageManager
        val managed = managedVersions()
        val result = LinkedHashMap<String, Long?>().apply { putAll(managed) }
        val names = packages.queryIntentActivities(
            android.content.Intent(android.content.Intent.ACTION_MAIN)
                .addCategory(android.content.Intent.CATEGORY_LAUNCHER),
            0,
        ).mapNotNull { it.activityInfo?.packageName }.toSortedSet()
        for (name in names) {
            if (result.size >= MAX_REPORTED_PACKAGES) break
            if (name in result) continue
            try {
                result[name] = packages.getPackageInfo(name, 0).longVersionCode
            } catch (e: PackageManager.NameNotFoundException) {
                // Visibility changed between the launcher query and lookup.
                Log.d(TAG, "check-in: $name disappeared after launcher query")
            } catch (e: Exception) {
                Log.e(TAG, "check-in: cannot read installed version for $name", e)
            }
        }
        // Managed packages come first, including those without a launcher icon.
        return result
    }

    /**
     * One package: decide whether to download it at all, then do.
     *
     * DECIDED BEFORE THE DOWNLOAD (muster#146). The same bytes failing at every
     * check-in cost a full download each time; `InstallGate` refuses bytes
     * already shown to carry an incompatible signer, and waits out a backoff
     * on bytes that failed for any other reason.
     */
    private fun attempt(step: AppInstallPolicy.Install, ledger: InstallLedger, tally: Tally) {
        val want = step.wanted
        val now = clock()
        val decision = InstallGate.decide(
            want.replaceIfSignerDiffers,
            installedSigners(want.packageName),
            ledger.signers(want.digest),
            ledger.attempts(want.digest),
            now,
        )
        when (decision) {
            InstallGate.Decision.Incompatible -> {
                Log.w(
                    TAG,
                    "install-apps: ${want.packageName} refused before downloading - " +
                        InstallGate.INCOMPATIBLE,
                )
                tally.weldedShut.add(InstallGate.incompatible(want.packageName, want.asset))
            }
            is InstallGate.Decision.Wait ->
                tally.backingOff.add(InstallGate.waiting(want.packageName, decision.attempts, now))
            InstallGate.Decision.Fetch -> fetchAndInstall(step, ledger, tally)
        }
    }

    private fun fetchAndInstall(step: AppInstallPolicy.Install, ledger: InstallLedger, tally: Tally) {
        val want = step.wanted
        when (val fetched = fetch(want.asset, want.digest)) {
            is AssetClient.Fetched.Asset -> install(step, fetched.bytes, ledger, tally)
            is AssetClient.Fetched.DigestMismatch -> {
                // LOUD, AND NOTHING IS INSTALLED. Something in the path
                // served bytes the policy did not name, and this is the
                // one place where acting anyway would be catastrophic.
                Log.e(
                    TAG,
                    "install-apps: SUBSTITUTED ${want.asset} - expected " +
                        "${fetched.expected}, got ${fetched.actual}",
                )
                tally.substituted.add(
                    "${want.packageName}: ${want.asset} expected sha256 " +
                        "${fetched.expected.take(12)}, bytes were ${fetched.actual.take(12)}"
                )
                // BACKED OFF like a failed install: the bytes were downloaded
                // in full, and the same path will most likely serve the same
                // wrong ones next time.
                ledger.failed(want.digest, clock())
            }
            else -> {
                // Unreachable, refused, not enrolled. The device keeps what
                // it already has, which is CONTEXT.md's second rule. NOT
                // backed off: nothing was downloaded, and a network that comes
                // back should be used at once.
                Log.w(TAG, "install-apps: could not fetch ${want.asset}: $fetched")
                tally.couldNotFetch.add("${want.packageName}: $fetched")
            }
        }
    }

    private fun install(
        step: AppInstallPolicy.Install,
        bytes: ByteArray,
        ledger: InstallLedger,
        tally: Tally,
    ) {
        val want = step.wanted
        // THE PLATFORM DECIDES, AND IT SAYS WHY.
        //
        // Deciding "this cannot install" ourselves reimplements Android's
        // signature logic and gets v3 key rotation wrong, where a rotated key
        // carries a lineage proving continuity and installs in place. And
        // inferring "it refused because of the signer" from "it refused, and
        // the signers differ" misdiagnoses every OTHER refusal - a full disk, a
        // transient package-manager error - as a signature conflict. The action
        // that follows deletes an application's data, so the diagnosis has to
        // come from the platform rather than from a guess that fits.
        InstallReport.forget(want.packageName)
        if (commitAndWait(want, bytes)) return succeeded(step, ledger, tally)

        // ASKED HERE, not before the commit. An earlier reading would be up to
        // a minute stale by now, and anything else on the device - Play, a
        // system update - may have replaced the package in between. Removing
        // on a stale reading deletes an app whose data was preservable.
        val reading = signerCheck(want.packageName, bytes)
        // REMEMBERED, so the next check-in can refuse these bytes without
        // downloading them again (muster#146). The digest pins the bytes, so
        // their signer cannot change under it.
        if (reading.signer == Signer.DIFFERS) ledger.rememberSigners(want.digest, reading.incoming)
        val platformSaysSignature = InstallReport.refusedForSignature(want.packageName) == true
        if (want.replaceIfSignerDiffers && reading.signer == Signer.DIFFERS && platformSaysSignature) {
            return replace(step, bytes, ledger, tally)
        }
        ledger.failed(want.digest, clock())
        when {
            reading.signer != Signer.DIFFERS -> tally.didNotTake.add(want.packageName)
            // The flag is already on the line and the platform did not name the
            // signer as its reason, so nothing was removed - and the advice in
            // the refusal below, to add the flag, would be wrong here.
            want.replaceIfSignerDiffers -> tally.didNotTake.add(
                "${want.packageName}: signed by a different key, but the platform " +
                    "did not give that as its reason, so the installed copy was kept"
            )
            else -> tally.weldedShut.add(InstallGate.incompatible(want.packageName, want.asset))
        }
    }

    /** Remove the installed copy and install again. Reached only by the opt-in. */
    private fun replace(
        step: AppInstallPolicy.Install,
        bytes: ByteArray,
        ledger: InstallLedger,
        tally: Tally,
    ) {
        val name = step.packageName
        if (!uninstall(name)) {
            ledger.failed(step.wanted.digest, clock())
            tally.didNotTake.add("$name: could not be removed")
            return
        }
        InstallReport.forget(name)
        if (commitAndWait(step.wanted, bytes)) {
            tally.replaced.add(name)
            return succeeded(step, ledger, tally)
        }
        ledger.failed(step.wanted.digest, clock())
        tally.didNotTake.add("$name: removed and would still not install")
    }

    private fun succeeded(step: AppInstallPolicy.Install, ledger: InstallLedger, tally: Tally) {
        ledger.succeeded(step.wanted.digest)
        tally.installed.add(step.packageName)
        Log.i(TAG, "install-apps: ${step.packageName} installed (${step.why})")
    }

    private fun commitAndWait(want: AppInstallPolicy.Wanted, bytes: ByteArray): Boolean =
        commit(want.packageName, bytes) && installTook(want.packageName, want.versionCode)

    /**
     * What comparing the installed signer to the fetched one established.
     *
     * FOUR STATES, NOT A BOOLEAN, because one of these authorizes deleting an
     * application's data and "I could not tell" must never be mistaken for
     * "they are different". A boolean forces every failure to pick a side, and
     * the safe side depends on which downstream action reads it: with the
     * replace flag off, guessing DIFFERS costs a spurious message; with it on,
     * it costs the app.
     */
    private enum class Signer { SAME, DIFFERS, UNKNOWN, NOTHING_INSTALLED }

    /** The verdict, and the fetched bytes' signer lineage it was reached with. */
    private data class SignerReading(val signer: Signer, val incoming: Set<String>)

    /**
     * Did the install actually land, at the version asked for?
     *
     * `commit` returning true means the SESSION was committed, not that the
     * package changed - installation is asynchronous and a refusal arrives
     * later, through a broadcast this process is not listening for. Asking the
     * platform what it now carries is the answer that cannot be stale, and it
     * is what tells a refusal apart from a success.
     */
    private fun installTook(packageName: String, wanted: Long): Boolean {
        for (attempt in 1..240) {
            Thread.sleep(250)
            val at = try {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(packageName, 0).longVersionCode
            } catch (e: PackageManager.NameNotFoundException) {
                continue
            }
            if (at >= wanted) return true
        }
        return false
    }

    /**
     * Does the installed copy carry a signer these bytes cannot update?
     *
     * THE DIGEST OF THE CERTIFICATE, not the certificate object. Two `Signature`
     * instances for identical bytes are not equal by identity, and comparing
     * `toCharsString()` works but moves megabytes through a string. The
     * comparison itself is `InstallGate.compatible`, which reads the fetched
     * bytes' whole lineage so a rotated key is not taken for a different one.
     */
    private fun signerCheck(packageName: String, bytes: ByteArray): SignerReading {
        val installed = installedSigners(packageName)
            ?: return SignerReading(Signer.NOTHING_INSTALLED, emptySet())
        val incoming = archiveLineage(packageName, bytes)
        val signer = when (InstallGate.compatible(installed, incoming)) {
            null -> Signer.UNKNOWN.also {
                Log.e(TAG, "install-apps: $packageName has no readable signer on one side")
            }
            true -> Signer.SAME
            false -> Signer.DIFFERS.also {
                Log.e(
                    TAG,
                    "install-apps: $packageName installed signer ${installed.first().take(12)} " +
                        "is not in the lineage of ${incoming.first().take(12)}",
                )
            }
        }
        return SignerReading(signer, incoming)
    }

    /** The installed copy's signer digests: null if not installed, empty if unreadable. */
    private fun installedSigners(packageName: String): Set<String>? {
        val installed = try {
            context.packageManager.getPackageInfo(
                packageName, PackageManager.GET_SIGNING_CERTIFICATES
            )
        } catch (e: PackageManager.NameNotFoundException) {
            return null
        } catch (e: Exception) {
            // UNREADABLE, NOT ABSENT. This now runs before every download, and
            // throwing here would end the whole step - every other package's
            // install with it - over a question whose honest answer is
            // "could not tell", which `InstallGate` never reads as a refusal.
            Log.e(TAG, "install-apps: cannot read the installed signer of $packageName", e)
            return emptySet()
        }
        return digests(installed.signingInfo?.apkContentsSigners)
    }

    /** The signer lineage of fetched bytes, or empty when it cannot be read. */
    private fun archiveLineage(packageName: String, bytes: ByteArray): Set<String> {
        // A UNIQUE FILE. A fixed name is overwritten by a second package's
        // check running in the same pass, and both then read bytes belonging to
        // neither - which resolves to UNKNOWN and silently withholds an install.
        val staged = File.createTempFile("signer-check-", ".apk", context.cacheDir)
        return try {
            staged.writeBytes(bytes)
            val incoming = context.packageManager.getPackageArchiveInfo(
                staged.absolutePath,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
            // UNREADABLE IS NOT "THE SAME". An empty answer makes the
            // comparison UNKNOWN rather than letting it pass as one that ran.
            if (incoming == null) {
                Log.e(TAG, "install-apps: could not read the signer of the fetched $packageName")
                emptySet()
            } else {
                lineage(incoming)
            }
        } catch (e: Exception) {
            // UNKNOWN, NOT DIFFERS, AND THE DIFFERENCE IS AN APP'S DATA.
            // `writeBytes` throws on a full disk, which these handsets reach -
            // and DIFFERS is not merely informational here, it is the signal
            // that authorizes deletion. Failing towards DIFFERS would remove an
            // app on no evidence that anything differed at all.
            Log.e(TAG, "install-apps: comparing signers for $packageName failed", e)
            emptySet()
        } finally {
            staged.delete()
        }
    }

    /**
     * Every key these bytes can claim continuity from: the rotation history
     * for a single signer, or the signer set itself when there are several
     * (which cannot rotate).
     */
    private fun lineage(info: android.content.pm.PackageInfo): Set<String> {
        val signing = info.signingInfo ?: return emptySet()
        return digests(
            if (signing.hasMultipleSigners()) signing.apkContentsSigners
            else signing.signingCertificateHistory
        )
    }

    private fun digests(signers: Array<android.content.pm.Signature>?): Set<String> {
        if (signers == null) return emptySet()
        val sha = java.security.MessageDigest.getInstance("SHA-256")
        return signers.map { s ->
            sha.digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
    }

    /**
     * Remove an installed package, AND THIS DESTROYS ITS DATA.
     *
     * Reached only from a policy line that opted in by name, and only when the
     * installed signer actually differs - because at that point the alternative
     * is not "keep the data", it is "this device can never be updated again
     * without a factory reset, which destroys the data anyway along with
     * everything else on the phone".
     */
    private fun uninstall(packageName: String): Boolean {
        Log.w(TAG, "install-apps: REMOVING $packageName - its data will be lost")
        return try {
            // THE SAME SENDER THE INSTALL USES. A Device Owner uninstall needs
            // no approval, so the result is only ever news - and the loop below
            // asks the platform directly rather than trusting a broadcast this
            // process may not live to receive.
            context.packageManager.packageInstaller.uninstall(
                packageName,
                InstallReport.intentSender(context, packageName),
            )
            // THE CALL IS ASYNCHRONOUS, so this waits for the package to go
            // rather than assuming it did. Committing an install over a package
            // that is still present fails exactly as before, and would read as
            // the uninstall having been pointless.
            for (attempt in 1..120) {
                Thread.sleep(250)
                try {
                    context.packageManager.getPackageInfo(packageName, 0)
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.i(TAG, "install-apps: $packageName removed")
                    return true
                }
            }
            Log.e(TAG, "install-apps: $packageName was still installed after thirty seconds")
            false
        } catch (e: Exception) {
            Log.e(TAG, "install-apps: removing $packageName failed", e)
            false
        }
    }

    /**
     * What each named package is at now, or absent if it is not installed.
     *
     * ASKED ONLY ABOUT PACKAGES THE POLICY NAMES, rather than enumerating
     * everything. `getPackageInfo` on a name this device cannot see throws
     * NameNotFoundException, which is the same answer as "not installed" and is
     * what the plan wants; enumerating would additionally run into package
     * visibility filtering, which a Device Owner is NOT exempt from.
     */
    private fun installedVersions(desired: AppInstallPolicy.Desired): Map<String, Long> {
        val packages = context.packageManager
        val versions = LinkedHashMap<String, Long>()
        for (want in desired.wanted) {
            try {
                // `longVersionCode` UNCONDITIONALLY. It needs API 28 and this
                // app's minSdk is 29, so a version check here would be dead
                // code guarding against a platform the agent cannot run on -
                // and it would drag in a DEPRECATION suppression for a branch
                // that can never execute.
                versions[want.packageName] =
                    packages.getPackageInfo(want.packageName, 0).longVersionCode
            } catch (_: PackageManager.NameNotFoundException) {
                // Not installed. Deliberately not an entry: `plan` reads an
                // absent key as "install", and a 0 would read as "downgrade".
            } catch (e: Exception) {
                Log.e(TAG, "install-apps: cannot read ${want.packageName}", e)
            }
        }
        return versions
    }

    /**
     * Write the bytes into a session and commit it.
     *
     * COMMITTING MUSTER'S OWN SESSION ENDS THIS PROCESS. There is deliberately
     * nothing after the commit that this class depends on: the return value is
     * "the platform accepted the session", not "the install finished", because
     * for one package in the list this method never returns at all.
     */
    private fun commit(packageName: String, bytes: ByteArray): Boolean {
        val installer = context.packageManager.packageInstaller
        var sessionId = -1
        return try {
            val params = PackageInstaller.SessionParams(
                PackageInstaller.SessionParams.MODE_FULL_INSTALL
            )
            params.setAppPackageName(packageName)
            sessionId = installer.createSession(params)
            installer.openSession(sessionId).use { session ->
                session.openWrite("muster", 0, bytes.size.toLong()).use { out ->
                    out.write(bytes)
                    session.fsync(out)
                }
                // A BROADCAST NOBODY LISTENS FOR, and that is not an oversight.
                // `commit` requires an IntentSender; a Device Owner install
                // needs no approval, so the result is only ever news. Reading
                // it would mean a receiver that has to survive this process
                // being killed by its own update - and the next boot's
                // reconcile answers the same question by asking the platform
                // what is installed, which is the answer that cannot go stale.
                session.commit(InstallReport.intentSender(context, packageName))
            }
            true
        } catch (e: Exception) {
            Log.e(TAG, "install-apps: '$packageName' would not install", e)
            if (sessionId >= 0) {
                // Abandoned, or the session's staged bytes sit in /data until
                // the platform decides to clean them - which for a 12.7 MB APK
                // retried every boot is a disk that fills up quietly.
                runCatching { installer.abandonSession(sessionId) }
            }
            false
        }
    }

    private fun fetch(name: String, digest: String): AssetClient.Fetched {
        val client = clientFactory()
            ?: return AssetClient.Fetched.Unreachable("no muster server configured")
        return client.fetch(name, digest)
    }

    companion object {
        private const val TAG = "muster"
        private const val MAX_REPORTED_PACKAGES = 64

        private fun defaultClient(context: Context): AssetClient? {
            val serverUrl = KeystoreIdentity.serverBaseUrl(context)
            if (serverUrl.isBlank()) return null
            // A LONGER READ BUDGET THAN THE WALLPAPER'S. An APK is an order of
            // magnitude bigger, and a boot that gives up halfway through one
            // has spent the bytes and gained nothing.
            return AssetClient(
                HttpTransport(serverUrl, connectTimeoutMs = 10_000, readTimeoutMs = 120_000),
                KeystoreIdentity(context),
            )
        }
    }
}
