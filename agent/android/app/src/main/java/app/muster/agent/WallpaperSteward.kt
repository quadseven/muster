package app.muster.agent

import android.app.WallpaperManager
import android.content.Context
import android.graphics.BitmapFactory
import android.util.Log
import java.io.File
import java.security.MessageDigest

/**
 * Put the configured image on the screens the policy names.
 *
 * WHERE THE IMAGE COMES FROM, and why it is not bundled. Baking a picture into
 * the APK means every change to it is a rebuild, a reinstall and - because this
 * app is Device Owner - eventually a factory reset when the signing key moves.
 *
 * IT NOW ARRIVES OVER THE AIR (muster#45). The `wallpaper` policy file names an
 * asset and the digest to expect; `AssetClient` fetches the bytes over this
 * device's own identity and refuses anything that does not match. Before that,
 * the only route was `adb push` while a cable was attached - which a phone
 * provisioned by QR on somebody else's network never has. A file already on the
 * device is still used if it matches, so the cable case keeps working and a
 * device that has already fetched does not fetch again.
 *
 * LOCKING THE WALLPAPER LIVES IN RestrictionPolicy, not here.
 *
 * NOTHING HERE RUNS WITHOUT AN IMAGE. A device with no wallpaper configured
 * keeps whatever it has. An MDM that imposes a default background on a phone
 * nobody asked it to is the kind of thing that makes people uninstall the MDM.
 */
class WallpaperSteward(
    private val context: Context,
    private val clientFactory: () -> AssetClient? = { defaultClient(context) },
) {

    // `Outcome` lives in WallpaperPolicy, not here. It is plain data with no
    // Android in it, and nested in this class no test could construct one -
    // which is how it shipped saying both COULD_NOT_FETCH and "no wallpaper
    // configured" about the same device.

    private val state by lazy {
        // Device-protected storage: this runs at BOOT_COMPLETED, which on a
        // phone with a lock screen fires BEFORE first unlock. Credential-
        // protected storage is not readable then, and the read fails in a way
        // that looks like "no wallpaper has ever been applied" - so the device
        // would re-apply on every single boot.
        context.createDeviceProtectedStorageContext()
            .getSharedPreferences("muster-wallpaper", Context.MODE_PRIVATE)
    }

    /** The `wallpaper` policy file, written by ConfigurationSteward. */
    fun configFile(): File = File(
        context.createDeviceProtectedStorageContext().filesDir, "wallpaper"
    )

    /** Where the bytes are kept once fetched, or pushed by `muster` over adb. */
    fun imageFile(): File = File(
        context.createDeviceProtectedStorageContext().filesDir, "wallpaper.png"
    )

    private fun hashOf(file: File): String? {
        if (!file.isFile) return null
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun appliedSurfaces(): Set<WallpaperPolicy.Surface> {
        val recorded = state.getStringSet(APPLIED_SURFACES, null) ?: return emptySet()
        return recorded.mapNotNull { name ->
            WallpaperPolicy.Surface.entries.firstOrNull { it.configName == name }
        }.toSet()
    }

    fun reconcile(): WallpaperPolicy.Outcome {
        val configured = configFile().takeIf { it.isFile }?.readText()
        val desired = WallpaperPolicy.read(configured)

        // A file that names nothing usable configures nothing, and the refusals
        // are what says so - returning early without them would report "no
        // wallpaper configured" to an operator who wrote one.
        if (desired.asset == null || desired.digest == null) {
            return WallpaperPolicy.Outcome(
                decision = WallpaperPolicy.Decision.NothingConfigured,
                refused = desired.refused,
            )
        }

        // THE BYTES ARE MADE TO MATCH BEFORE ANYTHING IS DECIDED. The local file
        // may be from a previous policy, from `adb push`, or absent.
        val onDisk = hashOf(imageFile())
        if (!onDisk.equals(desired.digest, ignoreCase = true)) {
            when (val fetched = fetch(desired.asset, desired.digest)) {
                is AssetClient.Fetched.Asset -> {
                    if (!place(fetched.bytes)) {
                        return WallpaperPolicy.Outcome(
                            decision = WallpaperPolicy.Decision.NothingConfigured,
                            refused = desired.refused,
                            couldNotFetch = "${desired.asset} arrived and could not be stored",
                        )
                    }
                }
                is AssetClient.Fetched.DigestMismatch -> {
                    // LOUD, AND NOTHING IS APPLIED. Something in the path served
                    // bytes the policy did not name.
                    Log.e(TAG, "wallpaper: SUBSTITUTED - expected ${fetched.expected}, got ${fetched.actual}")
                    return WallpaperPolicy.Outcome(
                        decision = WallpaperPolicy.Decision.NothingConfigured,
                        refused = desired.refused,
                        substituted = "${desired.asset}: expected sha256 " +
                            "${fetched.expected.take(12)}, the bytes were ${fetched.actual.take(12)}",
                    )
                }
                else -> {
                    // Unreachable, refused, not enrolled. The device keeps
                    // whatever it already has - CONTEXT.md's second rule.
                    Log.w(TAG, "wallpaper: could not fetch ${desired.asset}: $fetched")
                    return WallpaperPolicy.Outcome(
                        decision = WallpaperPolicy.Decision.NothingConfigured,
                        refused = desired.refused,
                        couldNotFetch = "${desired.asset}: $fetched",
                    )
                }
            }
        }

        val decision = WallpaperPolicy.decide(desired, state.getString(APPLIED_DIGEST, null), appliedSurfaces())
        if (decision !is WallpaperPolicy.Decision.Apply) {
            return WallpaperPolicy.Outcome(decision = decision, refused = desired.refused)
        }

        val bitmap = BitmapFactory.decodeFile(imageFile().absolutePath)
        if (bitmap == null) {
            // Present and not an image. Do NOT record a digest: recording one
            // would mean this never retries, and the operator would be left
            // with a device that silently ignored their picture.
            Log.w(TAG, "wallpaper file is not a decodable image: ${imageFile().absolutePath}")
            return WallpaperPolicy.Outcome(
                decision = WallpaperPolicy.Decision.NothingConfigured,
                refused = desired.refused,
                couldNotFetch = "${desired.asset} is not a decodable image",
            )
        }

        val manager = WallpaperManager.getInstance(context)
        val took = mutableSetOf<WallpaperPolicy.Surface>()
        val didNotTake = mutableListOf<String>()
        for (surface in decision.surfaces) {
            // ONE CALL PER SURFACE, not one call with both flags. A single call
            // that half-fails cannot say which half, and the lock screen is the
            // one the operator cannot check without locking the phone.
            try {
                manager.setBitmap(bitmap, null, true, flagFor(surface))
                took.add(surface)
            } catch (e: Exception) {
                Log.e(TAG, "wallpaper: ${surface.configName} would not take", e)
                didNotTake.add(surface.configName)
            }
        }

        // RECORDED AS THE UNION of what was already carried and what just took,
        // and only for this digest. Recording `decision.surfaces` would claim
        // the ones that threw; recording only `took` would lose the home screen
        // on the boot that added the lock screen.
        val carried = if (state.getString(APPLIED_DIGEST, null) == desired.digest) {
            appliedSurfaces() + took
        } else {
            took
        }
        state.edit()
            .putString(APPLIED_DIGEST, desired.digest)
            .putStringSet(APPLIED_SURFACES, carried.map { it.configName }.toSet())
            .apply()
        Log.i(TAG, "wallpaper applied to ${took.map { it.configName }}: ${decision.reason}")

        return WallpaperPolicy.Outcome(
            applied = took,
            decision = decision,
            refused = desired.refused,
            didNotTake = didNotTake,
        )
    }

    private fun flagFor(surface: WallpaperPolicy.Surface): Int = when (surface) {
        WallpaperPolicy.Surface.SYSTEM -> WallpaperManager.FLAG_SYSTEM
        WallpaperPolicy.Surface.LOCK -> WallpaperManager.FLAG_LOCK
    }

    private fun fetch(name: String, digest: String): AssetClient.Fetched {
        val client = clientFactory()
            ?: return AssetClient.Fetched.Unreachable("no muster server configured")
        return client.fetch(name, digest)
    }

    /** Write the bytes beside the policy that named them, or say it failed. */
    private fun place(bytes: ByteArray): Boolean = try {
        val target = imageFile()
        val staged = File(target.parentFile, "${target.name}.incoming")
        staged.writeBytes(bytes)
        // Renamed rather than written in place, so a boot that is cut short
        // cannot leave half an image where a whole one was.
        staged.renameTo(target) || run { staged.delete(); false }
    } catch (e: Exception) {
        Log.e(TAG, "wallpaper: could not store fetched bytes", e)
        false
    }

    companion object {
        private const val TAG = "muster"
        private const val APPLIED_DIGEST = "applied-hash"
        private const val APPLIED_SURFACES = "applied-surfaces"

        /**
         * The client this step uses on a handset.
         *
         * A FACTORY RATHER THAN A CONSTRUCTED CLIENT, so that a device with no
         * server configured does not build an `HttpTransport` that throws on
         * every call - and so that this class has a seam a test can hold.
         *
         * The timeouts are shorter than enrollment's for the reason
         * `HttpTransport` gives: this runs inside a broadcast receiver at boot,
         * where the budget belongs to the whole boot plan, and an image is the
         * least urgent thing in it.
         */
        private fun defaultClient(context: Context): AssetClient? {
            val serverUrl = KeystoreIdentity.serverBaseUrl(context)
            if (serverUrl.isBlank()) return null
            return AssetClient(
                HttpTransport(serverUrl, connectTimeoutMs = 8_000, readTimeoutMs = 20_000),
                KeystoreIdentity(context),
            )
        }
    }
}
