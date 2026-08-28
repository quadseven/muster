package app.muster.agent

/**
 * The most an operator asset may be, on the device side.
 *
 * WHY THIS IS ITS OWN OBJECT rather than a literal in `HttpTransport`. It is
 * one half of a two-sided contract - `assets.MAX_BYTES` in the server is the
 * other - and the two are different languages in different processes, so
 * nothing the compiler does can hold them together.
 *
 * They drifted the first time, immediately, and it cost a device: the server's
 * ceiling went to 32 MiB when the asset store moved to a share so it could
 * carry a 12.7 MB APK, and the agent's stayed at 8 MiB. The handset refused a
 * 16.9 MB install with `413 asset is larger than this device will hold` while
 * the server served the same bytes without complaint. Nothing was wrong on
 * either side alone.
 *
 * So the number lives in one named place per side, and CI compares them - the
 * same shape as the managed-file vocabulary check, and for the same reason.
 */
object AssetCeiling {

    /**
     * 32 MiB, matching `muster.assets.MAX_BYTES`.
     *
     * Room for an APK to grow without room for a mistake: the agent is ~13 MB
     * and zippie's is ~17 MB, so this is roughly double the largest real asset
     * and far below anything that would trouble a phone reading it into memory.
     */
    const val MAX_BYTES: Int = 32 * 1024 * 1024
}
