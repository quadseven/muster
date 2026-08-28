package app.muster.agent

import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * HttpURLConnection, which is enough and ships with the platform.
 *
 * No OkHttp, no Retrofit: this makes a handful of request shapes to one host,
 * and every dependency added to a Device Owner app is one that has to be
 * trusted with a device somebody cannot easily take back.
 *
 * The error stream is read on failure, not discarded. The server's refusals
 * carry the reason a human needs - "that code has expired" - and reading only
 * the success stream throws it away, leaving a status code and a shrug.
 *
 * THE TIMEOUTS ARE A PARAMETER BECAUSE THE CALLERS HAVE DIFFERENT BUDGETS.
 * Enrollment can wait: a person is standing in front of the device watching a
 * fingerprint. A configuration fetch runs inside a broadcast receiver at boot,
 * where the budget belongs to the whole boot plan and a request that takes
 * thirty seconds is thirty seconds the restrictions have not been applied for.
 * The defaults are enrollment's, so no existing call site changed.
 */
class HttpTransport(
    private val baseUrl: String,
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 20_000,
    /**
     * The most an asset may be.
     *
     * MUST MATCH `assets.MAX_BYTES` ON THE SERVER, and this is the second time
     * that has been written down because the first time did not hold: the
     * server's ceiling was raised to 32 MiB when the asset store moved to a
     * share so it could carry an APK, and THIS was left at 8. The result was a
     * handset refusing a 16.9 MB install with `413 asset is larger than this
     * device will hold` while the server served it happily - a drift between
     * two numbers that are one contract, discovered on a real phone.
     *
     * Kept as a device-side ceiling rather than deferring to the server's,
     * because a device that only works when the other end is well-behaved is
     * not the property that matters. But the number is the same number, and
     * `AssetCeiling` is what stops it drifting again.
     */
    private val maxAssetBytes: Int = AssetCeiling.MAX_BYTES,
) : AssetClient.Transport {

    override fun post(path: String, body: String): EnrollmentClient.Transport.Reply =
        request(path, "POST", body)

    override fun get(path: String): EnrollmentClient.Transport.Reply =
        request(path, "GET", null)

    /**
     * A reply that is not text: an operator asset (muster#45).
     *
     * READ WITH A CEILING. Without one this reads whatever arrives into the
     * heap of an app running at BOOT_COMPLETED, and the size is decided by the
     * other end of a connection - a captive portal, a proxy, or a file an
     * operator put in the store by mistake. The server caps what it will serve;
     * this caps what the device will hold, because a device that only works
     * when the server is well-behaved is not the property that matters.
     *
     * The ERROR body is read as text and kept short: muster's refusals say the
     * reason, and a 404 body is worth having in the log.
     */
    override fun postForBytes(path: String, body: String): AssetClient.Transport.BytesReply {
        require(baseUrl.isNotBlank()) { "no muster server configured on this device" }
        val connection = (URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection)
        connection.requestMethod = "POST"
        connection.connectTimeout = connectTimeoutMs
        connection.readTimeout = readTimeoutMs
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.outputStream.use { it.write(body.toByteArray()) }
        return try {
            val status = connection.responseCode
            if (status !in 200..299) {
                val detail = connection.errorStream?.bufferedReader()
                    ?.use(BufferedReader::readText).orEmpty()
                AssetClient.Transport.BytesReply(status, ByteArray(0), detail.take(REFUSAL_CHARS))
            } else {
                val buffer = ByteArrayOutputStream()
                val chunk = ByteArray(16 * 1024)
                connection.inputStream.use { input ->
                    while (true) {
                        val read = input.read(chunk)
                        if (read <= 0) break
                        buffer.write(chunk, 0, read)
                        if (buffer.size() > maxAssetBytes) {
                            // Reported as a REFUSAL rather than a truncated
                            // body: a short read would fail the digest check
                            // and be reported as a substituted asset, which
                            // would send somebody looking for an attacker.
                            return AssetClient.Transport.BytesReply(
                                HTTP_TOO_LARGE,
                                ByteArray(0),
                                "asset is larger than this device will hold ($maxAssetBytes bytes)",
                            )
                        }
                    }
                }
                AssetClient.Transport.BytesReply(status, buffer.toByteArray())
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun request(path: String, method: String, body: String?):
        EnrollmentClient.Transport.Reply {
        require(baseUrl.isNotBlank()) {
            "no muster server configured on this device"
        }
        val connection = (URL(baseUrl.trimEnd('/') + path).openConnection() as HttpURLConnection)
        connection.requestMethod = method
        connection.connectTimeout = connectTimeoutMs
        connection.readTimeout = readTimeoutMs
        if (body != null) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body.toByteArray()) }
        }
        return try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use(BufferedReader::readText).orEmpty()
            EnrollmentClient.Transport.Reply(status, text)
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val REFUSAL_CHARS = 500

        /**
         * 413, said by the DEVICE about a body it declined to finish reading.
         * Not a status muster sent - it is how "I stopped" reaches the caller
         * as a refusal rather than as bytes that fail their digest.
         */
        private const val HTTP_TOO_LARGE = 413
    }
}
