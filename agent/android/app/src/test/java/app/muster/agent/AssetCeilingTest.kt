package app.muster.agent

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The device's asset ceiling, and the seam it shares with the server.
 *
 * These two numbers are one contract in two languages, and they drifted the
 * first time: the server went to 32 MiB so the store could carry an APK and the
 * agent stayed at 8, so a handset refused a 16.9 MB install with `413 asset is
 * larger than this device will hold` while the server served it happily.
 */
class AssetCeilingTest {

    @Test
    fun theCeilingFitsTheThingsMusterActuallyServes() {
        // The agent APK is ~13 MB and zippie's is ~17 MB. A ceiling below
        // either is a device that refuses the only payloads there are.
        assertTrue(
            "the ceiling must hold a real APK",
            AssetCeiling.MAX_BYTES > 20 * 1024 * 1024,
        )
    }

    @Test
    fun theDeviceAgreesWithTheSERVERAboutHowBigAnAssetMayBe() {
        // READ OUT OF THE SERVER'S OWN SOURCE. A constant restated in a comment
        // is a constant that drifts; this fails the moment somebody changes one
        // side, which is exactly what happened and was only caught on a phone.
        // SEARCHED UPWARD, NOT A FIXED RELATIVE PATH. The working directory
        // differs between Gradle (agent/android/app) and the local harness
        // (the repo root), and the first version of this test used one fixed
        // path, silently found nothing, and PASSED - so it reported agreement
        // while the two numbers were 8 MiB apart. A test that cannot find its
        // subject must fail, not shrug.
        var dir: File? = File(".").absoluteFile
        var server: File? = null
        while (dir != null && server == null) {
            val candidate = File(dir, "server/muster/assets.py")
            if (candidate.isFile) server = candidate
            dir = dir.parentFile
        }
        requireNotNull(server) {
            "could not find server/muster/assets.py from ${File(".").absolutePath} - " +
                "this test compares the agent's ceiling against the server's and " +
                "cannot be allowed to pass without reading it"
        }
        val line = server.readLines().firstOrNull { it.startsWith("MAX_BYTES") }
            ?: throw AssertionError("could not find MAX_BYTES in ${server.path}")
        val expression = line.substringAfter("=").trim()
        val bytes = expression.split("*").map { it.trim().toInt() }.reduce(Int::times)
        assertEquals(
            "the agent and the server disagree about the asset ceiling",
            bytes,
            AssetCeiling.MAX_BYTES,
        )
    }
}
