package app.muster.agent

import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

/**
 * The write FileIdentityStore uses for device.crt (muster#229).
 *
 * A certificate written in place and cut off part way is a device the server
 * answers 401 forever, with no way back short of a factory reset. The staged
 * write is what makes a failure leave the previous identity standing.
 */
class StagedWriteTest {

    private fun dir(): File = Files.createTempDirectory("staged-write").toFile()

    @Test
    fun aSuccessfulWriteReplacesTheFileAndLeavesNoStage() {
        val dir = dir()
        val target = File(dir, "device.crt").apply { writeText("OLD") }

        StagedWrite.replace(target, "NEW")

        assertEquals("NEW", target.readText())
        assertFalse(File(dir, "device.crt.incoming").exists())
    }

    @Test
    fun aFailedStageLeavesTheOldCertificateReadable() {
        val dir = dir()
        val target = File(dir, "device.crt").apply { writeText("OLD") }
        // A directory where the stage file goes makes the stage write fail,
        // which stands in for a broadcast cut off part way through.
        File(dir, "device.crt.incoming").mkdirs()

        try {
            StagedWrite.replace(target, "NEW")
            fail("a stage that could not be written must be reported")
        } catch (expected: IOException) {
        }

        assertEquals("OLD", target.readText())
    }

    @Test
    fun aFirstWriteNeedsNoPreviousFile() {
        val dir = dir()
        val target = File(dir, "device.crt")

        StagedWrite.replace(target, "FIRST")

        assertEquals("FIRST", target.readText())
    }
}
