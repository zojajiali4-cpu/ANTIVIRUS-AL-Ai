package com.antivirusalai

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

data class CloudBillingStatus(val checkoutReady: Boolean, val activeBasePlans: Set<String>)
data class CloudSubscriptionEntitlement(
    val entitled: Boolean, val subscriptionState: String, val productId: String,
    val basePlanId: String, val isTrial: Boolean, val expiresAtEpochMillis: Long,
    val cloudAccessToken: String? = null
)

/** Cafe Bazaar purchase verifier. Raw tokens are sent only to the HTTPS Worker and never persisted by the app. */
object CloudBillingApi {
    private const val MAX_RESPONSE_BYTES = 32 * 1024
    private const val MAX_TOKEN_LENGTH = 4096
    private val allowedProducts = mapOf(
        BuildConfig.ALAI_MONTHLY_PRODUCT_ID to "monthly",
        BuildConfig.ALAI_ANNUAL_PRODUCT_ID to "annual"
    )

    fun billingStatus(): CloudBillingStatus {
        val connection = openConnection("/v1/bazaar/status", "GET")
        return try {
            val status = connection.responseCode
            val responseText = responseText(connection, status)
            if (status !in 200..299) throw IllegalStateException("Cafe Bazaar billing readiness is unavailable.")
            parseBillingStatusPayload(responseText)
        } finally { connection.disconnect() }
    }

    fun verifySubscription(productId: String, purchaseToken: String): CloudSubscriptionEntitlement {
        require(productId in allowedProducts) { "Unsupported Cafe Bazaar subscription product." }
        val token = validatePurchaseToken(purchaseToken)
        val payload = JSONObject().put("productId", productId).put("purchaseToken", token)
            .toString().toByteArray(Charsets.UTF_8)
        val connection = openConnection("/v1/bazaar/subscription/verify", "POST").apply {
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setFixedLengthStreamingMode(payload.size)
        }
        return try {
            connection.outputStream.use { it.write(payload) }
            val status = connection.responseCode
            val responseText = responseText(connection, status)
            if (status == 503) throw IllegalStateException("Cafe Bazaar purchase verification is not configured or temporarily unavailable.")
            if (status !in 200..299) throw IllegalStateException("Cafe Bazaar could not verify this subscription.")
            parseSubscriptionEntitlementPayload(responseText)
        } finally { connection.disconnect() }
    }

    internal fun parseSubscriptionEntitlementPayload(responseText: String): CloudSubscriptionEntitlement {
        val root = runCatching { JSONObject(responseText) }.getOrElse {
            throw IllegalArgumentException("The billing service returned an invalid response.")
        }
        require(root.optBoolean("ok", false)) {
            when (root.optString("error")) {
                "PURCHASE_NOT_ENTITLED" -> "This Cafe Bazaar subscription is not currently active."
                "INVALID_PURCHASE_TOKEN" -> "Cafe Bazaar returned an invalid purchase token."
                else -> "This subscription could not be verified."
            }
        }
        val productId = root.optString("productId", "")
        val basePlanId = allowedProducts[productId]
        require(basePlanId != null && root.optString("basePlanId") == basePlanId) {
            "The verified Cafe Bazaar subscription product does not match this app."
        }
        val expiresAt = root.optLong("expiresAtEpochMillis", 0L)
        require(expiresAt > 0L) { "The verified subscription expiry is missing." }
        val state = root.optString("subscriptionState", "SUBSCRIPTION_STATE_UNSPECIFIED")
        val entitled = root.optBoolean("entitled", false) &&
            state == "SUBSCRIPTION_STATE_ACTIVE" && expiresAt > System.currentTimeMillis()
        val accessToken = if (entitled) validatePlusAccessToken(root.optString("cloudAccessToken", "")) else null
        return CloudSubscriptionEntitlement(entitled, state, productId, basePlanId,
            root.optBoolean("isTrial", false) && entitled, expiresAt, accessToken)
    }

    internal fun parseBillingStatusPayload(responseText: String): CloudBillingStatus {
        val root = JSONObject(responseText)
        require(root.optBoolean("ok", false)) { "Cafe Bazaar billing readiness returned an invalid response." }
        val products = root.optJSONArray("activeProducts")
        val plans = buildSet {
            if (products != null) for (index in 0 until products.length()) {
                allowedProducts[products.optString(index)]?.let(::add)
            }
        }
        val ready = root.optBoolean("checkoutReady", false) && plans.isNotEmpty()
        return CloudBillingStatus(ready, if (ready) plans else emptySet())
    }

    internal fun validatePlusAccessToken(value: String): String {
        require(value.length in 64..4096 &&
            value.matches(Regex("[A-Za-z0-9_-]{20,2048}\\.[A-Za-z0-9_-]{40,128}"))) {
            "A valid server-issued PLUS access token is required."
        }
        return value
    }

    internal fun validatePurchaseToken(value: String): String {
        require(value.length in 20..MAX_TOKEN_LENGTH) { "The Cafe Bazaar purchase token has an invalid length." }
        require(value.none { it.isWhitespace() || it.code < 0x20 || it.code == 0x7f }) {
            "The Cafe Bazaar purchase token contains invalid characters."
        }
        return value
    }

    private fun openConnection(path: String, method: String): HttpURLConnection {
        val base = BuildConfig.ALAI_API_BASE_URL.trimEnd('/')
        require(base.startsWith("https://")) { "Billing verification requires HTTPS." }
        return (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 8_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
        }
    }

    private fun responseText(connection: HttpURLConnection, status: Int): String {
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        return stream?.let(::readBounded).orEmpty()
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
                require(total <= MAX_RESPONSE_BYTES) { "The billing service response exceeds its size limit." }
                output.write(buffer, 0, count)
            }
            return output.toString(Charsets.UTF_8.name())
        }
    }
}
