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
        val inert: String? = null,
    ) : StepOutcome {

        override fun concerns(): List<String> = buildList {
            substituted.forEach { add("SUBSTITUTED $it") }
            weldedShut.forEach { add("WELDED $it") }
            couldNotFetch.forEach { add("COULD_NOT_FETCH $it") }
            didNotTake.forEach { add("DID_NOT_TAKE $it") }
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
                if (refused.isNotEmpty()) append(" REFUSED=${refused.map { it.line }}")
            }
        }
    }

    /** The `install-apps` policy file, written by ConfigurationSteward. */
    fun configFile(): File = File(
        context.createDeviceProtectedStorageContext().filesDir, "install-apps"
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

        val installed = mutableListOf<String>()
        val couldNotFetch = mutableListOf<String>()
        val substituted = mutableListOf<String>()
        val didNotTake = mutableListOf<String>()
        val replaced = mutableListOf<String>()
        val weldedShut = mutableListOf<String>()

        for (step in plan.install) {
            val want = step.wanted
            when (val fetched = fetch(want.asset, want.digest)) {
                is AssetClient.Fetched.Asset -> {
                    // THE PLATFORM DECIDES, AND IT SAYS WHY.
                    //
                    // Deciding "this cannot install" ourselves reimplements
                    // Android's signature logic and gets v3 key rotation wrong,
                    // where a rotated key carries a lineage proving continuity
                    // and installs in place. And inferring "it refused because
                    // of the signer" from "it refused, and the signers differ"
                    // misdiagnoses every OTHER refusal - a full disk, a
                    // transient package-manager error - as a signature
                    // conflict. The action that follows deletes an
                    // application's data, so the diagnosis has to come from the
                    // platform rather than from a guess that fits.
                    InstallReport.forget(want.packageName)
                    var took = commit(want.packageName, fetched.bytes) &&
                        installTook(want.packageName, want.versionCode)

                    var signer = Signer.UNKNOWN
                    if (!took && want.replaceIfSignerDiffers) {
                        // ASKED AGAIN HERE, not before the commit. The earlier
                        // reading would be up to a minute stale by now, and
                        // anything else on the device - Play, a system update -
                        // may have replaced the package in between. Removing on
                        // a stale reading deletes an app whose data was
                        // preservable.
                        signer = signerCheck(want.packageName, fetched.bytes)
                        val platformSaysSignature = InstallReport.refusedForSignature(want.packageName)
                        if (signer == Signer.DIFFERS && platformSaysSignature == true) {
                            if (uninstall(want.packageName)) {
                                InstallReport.forget(want.packageName)
                                took = commit(want.packageName, fetched.bytes) &&
                                    installTook(want.packageName, want.versionCode)
                                if (took) replaced.add(want.packageName)
                                else didNotTake.add(
                                    "${want.packageName}: removed and would still not install"
                                )
                            } else {
                                didNotTake.add("${want.packageName}: could not be removed")
                            }
                        }
                    } else if (!took) {
                        signer = signerCheck(want.packageName, fetched.bytes)
                    }

                    if (took) {
                        installed.add(want.packageName)
                        Log.i(TAG, "install-apps: ${want.packageName} installed (${step.why})")
                    } else if (didNotTake.none { it.startsWith("${want.packageName}:") }) {
                        if (signer == Signer.DIFFERS) {
                            weldedShut.add(
                                "${want.packageName}: the installed copy is signed by a " +
                                    "different key, so ${want.asset} cannot install over it. " +
                                    "Add 'replace-if-signer-differs' to the policy line to " +
                                    "remove it first - THAT DELETES ITS DATA - or wipe the device."
                            )
                        } else {
                            didNotTake.add(want.packageName)
                        }
                    }
                }
                is AssetClient.Fetched.DigestMismatch -> {
                    // LOUD, AND NOTHING IS INSTALLED. Something in the path
                    // served bytes the policy did not name, and this is the
                    // one place where acting anyway would be catastrophic.
                    Log.e(
                        TAG,
                        "install-apps: SUBSTITUTED ${want.asset} - expected " +
                            "${fetched.expected}, got ${fetched.actual}",
                    )
                    substituted.add(
                        "${want.packageName}: ${want.asset} expected sha256 " +
                            "${fetched.expected.take(12)}, bytes were ${fetched.actual.take(12)}"
                    )
                }
                else -> {
                    // Unreachable, refused, not enrolled. The device keeps what
                    // it already has, which is CONTEXT.md's second rule.
                    Log.w(TAG, "install-apps: could not fetch ${want.asset}: $fetched")
                    couldNotFetch.add("${want.packageName}: $fetched")
                }
            }
        }

        return Outcome(
            installed = installed,
            current = plan.current,
            refused = plan.refused,
            couldNotFetch = couldNotFetch,
            substituted = substituted,
            didNotTake = didNotTake,
            replaced = replaced,
            weldedShut = weldedShut,
        )
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
    /**
     * Does the installed copy carry a different signing certificate than these
     * bytes? Null when there is nothing installed to compare against.
     *
     * THE DIGEST OF THE CERTIFICATE, not the certificate object. Two `Signature`
     * instances for identical bytes are not equal by identity, and comparing
     * `toCharsString()` works but moves megabytes through a string.
     *
     * This is the check that turns an impossible install into a stated refusal.
     * INSTALL_FAILED_UPDATE_INCOMPATIBLE is not transient - no number of
     * retries makes a different key acceptable - so knowing BEFORE committing
     * is the difference between a clear message and a download loop.
     */
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

    private fun signerCheck(packageName: String, bytes: ByteArray): Signer {
        val pm = context.packageManager
        val installed = try {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } catch (e: PackageManager.NameNotFoundException) {
            return Signer.NOTHING_INSTALLED
        }
        // A UNIQUE FILE. A fixed name is overwritten by a second package's
        // check running in the same pass, and both then read bytes belonging to
        // neither - which resolves to UNKNOWN and silently withholds an install.
        val staged = File.createTempFile("signer-check-", ".apk", context.cacheDir)
        return try {
            staged.writeBytes(bytes)
            val incoming = pm.getPackageArchiveInfo(
                staged.absolutePath,
                PackageManager.GET_SIGNING_CERTIFICATES,
            ) ?: run {
                // UNREADABLE IS NOT "THE SAME". Returning false here would let
                // an install proceed on the assumption that a comparison
                // succeeded when it never ran.
                Log.e(TAG, "install-apps: could not read the signer of the fetched $packageName")
                return Signer.UNKNOWN
            }
            fun digests(info: android.content.pm.PackageInfo): Set<String> {
                val signers = info.signingInfo?.apkContentsSigners ?: return emptySet()
                val sha = java.security.MessageDigest.getInstance("SHA-256")
                return signers.map { s ->
                    sha.digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
                }.toSet()
            }
            val here = digests(installed)
            val there = digests(incoming)
            if (here.isEmpty() || there.isEmpty()) {
                Log.e(TAG, "install-apps: $packageName has no readable signer on one side")
                return Signer.UNKNOWN
            }
            if (here == there) Signer.SAME else Signer.DIFFERS.also {
                Log.e(
                    TAG,
                    "install-apps: $packageName installed signer ${here.first().take(12)} " +
                        "does not match ${there.first().take(12)}",
                )
            }
        } catch (e: Exception) {
            // UNKNOWN, NOT DIFFERS, AND THE DIFFERENCE IS AN APP'S DATA.
            // `writeBytes` throws on a full disk, which these handsets reach -
            // and DIFFERS is not merely informational here, it is the signal
            // that authorizes deletion. Failing towards DIFFERS would remove an
            // app on no evidence that anything differed at all.
            Log.e(TAG, "install-apps: comparing signers for $packageName failed", e)
            Signer.UNKNOWN
        } finally {
            staged.delete()
        }
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
