package com.antivirusalai

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

data class CloudUrlCheckResult(
    val level: String,
    val signals: List<String>,
    val reputationClassification: String?,
    val reputationSource: String?,
    val disclaimer: String?
)

/**
 * HTTPS-only API client. Only explicitly submitted URLs are sent; file contents
 * and local file hashes are never uploaded by this client.
 */
object CloudThreatApi {
    private const val MAX_RESPONSE_BYTES = 64 * 1024

    fun health(): String {
        val base = BuildConfig.ALAI_API_BASE_URL.trimEnd('/')
        require(base.startsWith("https://")) { "Cloud API must use HTTPS." }
        val connection = (URL("$base/v1/health").openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 8_000
            readTimeout = 8_000
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
        }
        return try {
            val status = connection.responseCode
            if (status !in 200..299) {
                throw IllegalStateException("Cloud API returned HTTP $status.")
            }
            val body = readBounded(connection.inputStream)
            if (!body.contains("\"ok\":true") || !body.contains("ANTIVIRUS AL AI API")) {
                throw IllegalStateException("Cloud API returned an unexpected response.")
            }
            "اتصال امن به API ابری برقرار است. | Cloud API connected securely."
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Checks a user-submitted URL against the server's structural rules and
     * curated reputation data. A missing reputation record is UNKNOWN, not clean.
     */
    fun checkUrl(value: String): CloudUrlCheckResult {
        val base = BuildConfig.ALAI_API_BASE_URL.trimEnd('/')
        require(base.startsWith("https://")) { "Cloud API must use HTTPS." }
        require(value.length in 1..2_048) { "URL length is invalid." }

        val payload = JSONObject().put("url", value).toString().toByteArray(Charsets.UTF_8)
        val connection = (URL("$base/v1/url/check").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 8_000
            readTimeout = 10_000
            instanceFollowRedirects = false
            doOutput = true
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setFixedLengthStreamingMode(payload.size)
        }

        return try {
            connection.outputStream.use { it.write(payload) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.let(::readBounded).orEmpty()
            if (status !in 200..299) {
                throw IllegalStateException("Cloud URL check returned HTTP $status.")
            }
            val root = JSONObject(body)
            check(root.optBoolean("ok", false)) { "Cloud URL check did not return a valid assessment." }
            val assessment = root.optJSONObject("assessment")
                ?: error("Cloud URL check response is missing its assessment.")
            val reputation = assessment.optJSONObject("reputation")
            val rawSignals = assessment.optJSONArray("signals")
            val signals = buildList {
                if (rawSignals != null) {
                    for (index in 0 until rawSignals.length()) {
                        rawSignals.optString(index).takeIf { it.isNotBlank() }?.let(::add)
                    }
                }
            }
            CloudUrlCheckResult(
                level = assessment.optString("level", "UNKNOWN"),
                signals = signals,
                reputationClassification = reputation?.optString("classification")?.takeIf { !it.isNullOrBlank() },
                reputationSource = reputation?.optString("source")?.takeIf { !it.isNullOrBlank() },
                disclaimer = root.optString("disclaimer").takeIf { it.isNotBlank() }
            )
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream): String {
        input.use { source ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(4_096)
            var total = 0
            while (true) {
                val count = source.read(buffer)
                if (count < 0) break
                total += count
                require(total <= MAX_RESPONSE_BYTES) { "Cloud API response exceeds its size limit." }
                output.write(buffer, 0, count)
            }
            return output.toString(Charsets.UTF_8.name())
        }
    }
}
