package com.antivirusalai

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

data class BazaarBillingReadiness(
    val checkoutReady: Boolean,
    val monthlySku: String,
    val annualSku: String
)

data class BazaarSubscriptionEntitlement(
    val entitled: Boolean,
    val productId: String,
    val expiresAtEpochMillis: Long,
    val cloudAccessToken: String?
)

/**
 * HTTPS client for the first-party Worker. Purchase tokens are sent only to the
 * Worker for server-side Cafe Bazaar validation and are never persisted locally.
 */
object BazaarBillingApi {
    private const val MAX_RESPONSE_BYTES = 32 * 1024
    private const val MAX_PURCHASE_TOKEN_LENGTH = 4096

    fun billingStatus(): BazaarBillingReadiness {
        val root = requestJson("/v1/billing/bazaar/status", null)
        require(root.optBoolean("ok", false)) {
            "The Cafe Bazaar billing service returned an invalid readiness response."
        }
        val monthlySku = root.optString("monthlySku", "")
        val annualSku = root.optString("annualSku", "")
        val configuredSkusMatch = monthlySku == BuildConfig.ALAI_BAZAAR_MONTHLY_SKU &&
            annualSku == BuildConfig.ALAI_BAZAAR_ANNUAL_SKU
        return BazaarBillingReadiness(
            checkoutReady = root.optBoolean("checkoutReady", false) && configuredSkusMatch,
            monthlySku = monthlySku,
            annualSku = annualSku
        )
    }

    fun verifySubscription(productId: String, purchaseToken: String): BazaarSubscriptionEntitlement {
        require(productId == BuildConfig.ALAI_BAZAAR_MONTHLY_SKU ||
            productId == BuildConfig.ALAI_BAZAAR_ANNUAL_SKU) {
            "This Cafe Bazaar subscription product is not supported."
        }
        val token = validatePurchaseToken(purchaseToken)
        val payload = JSONObject()
            .put("subscriptionId", productId)
            .put("purchaseToken", token)
        val root = requestJson("/v1/billing/bazaar/verify", payload)
        require(root.optBoolean("ok", false)) {
            when (root.optString("error")) {
                "PURCHASE_NOT_ENTITLED" -> "This Cafe Bazaar subscription is not currently active."
                "PURCHASE_TOKEN_INVALID" -> "Cafe Bazaar could not validate this purchase."
                else -> "Secure subscription verification is unavailable."
            }
        }
        val verifiedProduct = root.optString("subscriptionId", "")
        require(verifiedProduct == productId) {
            "The verified subscription belongs to a different product."
        }
        val expiry = root.optLong("expiresAtEpochMillis", 0L)
        require(expiry > 0L) { "The verified subscription expiry is missing." }
        val entitled = root.optBoolean("entitled", false) &&
            expiry > System.currentTimeMillis()
        val accessToken = if (entitled) {
            validateCloudAccessToken(root.optString("cloudAccessToken", ""))
        } else null
        return BazaarSubscriptionEntitlement(
            entitled = entitled,
            productId = verifiedProduct,
            expiresAtEpochMillis = expiry,
            cloudAccessToken = accessToken
        )
    }

    internal fun validatePurchaseToken(value: String): String {
        require(value.isNotBlank() && value.length in 20..MAX_PURCHASE_TOKEN_LENGTH &&
            value.none { it.isWhitespace() || it.code < 0x20 || it.code == 0x7f }) {
            "The Cafe Bazaar purchase token is malformed."
        }
        return value
    }

    internal fun validateCloudAccessToken(value: String): String {
        require(value.length in 64..4096 &&
            value.matches(Regex("[A-Za-z0-9_-]{20,2048}\\.[A-Za-z0-9_-]{40,128}"))) {
            "The server did not issue a valid PLUS access token."
        }
        return value
    }

    private fun requestJson(path: String, payload: JSONObject?): JSONObject {
        val base = BuildConfig.ALAI_API_BASE_URL.trimEnd('/')
        require(base.startsWith("https://")) { "Cafe Bazaar verification requires HTTPS." }
        val bytes = payload?.toString()?.toByteArray(Charsets.UTF_8)
        val connection = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = if (bytes == null) "GET" else "POST"
            connectTimeout = 8_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
            if (bytes != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setFixedLengthStreamingMode(bytes.size)
            }
        }
        return try {
            if (bytes != null) connection.outputStream.use { it.write(bytes) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.let(::readBounded).orEmpty()
            if (status == 503) {
                throw IllegalStateException("Cafe Bazaar verification is not configured or temporarily unavailable.")
            }
            if (status == 401 || status == 403) {
                throw IllegalStateException("Cafe Bazaar purchase verification was rejected.")
            }
            if (status !in 200..299) {
                throw IllegalStateException("Cafe Bazaar service returned HTTP $status.")
            }
            runCatching { JSONObject(text) }.getOrElse {
                throw IllegalStateException("Cafe Bazaar service returned invalid JSON.")
            }
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
                require(total <= MAX_RESPONSE_BYTES) {
                    "Cafe Bazaar response exceeds its size limit."
                }
                output.write(buffer, 0, count)
            }
            return output.toString(Charsets.UTF_8.name())
        }
    }
}
