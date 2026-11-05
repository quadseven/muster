package app.muster.agent

import java.io.File
import java.io.IOException

/**
 * Replace a file by writing a stage beside it and renaming it into place.
 *
 * A rename within one filesystem is atomic, so a reader gets the old file or
 * the new one and never half of either. The same shape as
 * ConfigurationSteward.write, kept here without Android imports so the JVM
 * harness can prove it (muster#229).
 *
 * Throws rather than returning false: the caller of an identity write has to
 * know it did not land, and the previous file is still in place when it does.
 */
object StagedWrite {
    fun replace(target: File, content: String) {
        val staged = File(target.parentFile, "${target.name}.incoming")
        try {
            staged.writeText(content)
        } catch (e: IOException) {
            if (staged.isFile) staged.delete()
            throw IOException("could not stage ${target.name}", e)
        }
        if (!staged.renameTo(target)) {
            staged.delete()
            throw IOException("could not replace ${target.name}; it still holds the previous contents")
        }
    }
}
