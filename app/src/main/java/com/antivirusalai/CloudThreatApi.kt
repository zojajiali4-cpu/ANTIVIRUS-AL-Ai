package com.antivirusalai

import java.net.HttpURLConnection
import java.net.URL

/**
 * Minimal HTTPS-only connectivity client. No file, hash, or personal data is sent.
 */
object CloudThreatApi {
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
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            if (!body.contains("\\"ok\\":true") || !body.contains("ANTIVIRUS AL AI API")) {
                throw IllegalStateException("Cloud API returned an unexpected response.")
            }
            "اتصال امن به API ابری برقرار است. | Cloud API connected securely."
        } finally {
            connection.disconnect()
        }
    }
}
