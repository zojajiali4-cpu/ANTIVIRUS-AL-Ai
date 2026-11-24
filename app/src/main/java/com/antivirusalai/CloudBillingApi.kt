package com.antivirusalai

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

data class CloudBillingStatus(
    val checkoutReady: Boolean,
    val activeBasePlans: Set<String>
)

data class CloudSubscriptionEntitlement(
    val entitled: Boolean,
    val subscriptionState: String,
    val productId: String,
    val basePlanId: String,
    val isTrial: Boolean,
    val expiresAtEpochMillis: Long,
    val cloudAccessToken: String? = null
)

object CloudBillingApi {
    private const val MAX_RESPONSE_BYTES = 32 * 1024
    private const val MAX_TOKEN_LENGTH = 4096

    fun billingStatus(): CloudBillingStatus {
        val base = BuildConfig.ALAI_API_BASE_URL.trimEnd('/')
        require(base.startsWith("https://")) { "Billing status requires HTTPS." }
        val connection = (URL(base + "/v1/billing/status").openConnection()
            as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 8_000
            readTimeout = 12_000
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/json")
        }
        return try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val responseText = stream?.let(::readBounded).orEmpty()
            if (status !in 200..299) {
                throw IllegalStateException("Secure billing readiness check is unavailable.")
            }
            parseBillingStatusPayload(responseText)
        } finally {
            connection.disconnect()
        }
    }

    fun verifySubscription(purchaseToken: String): CloudSubscriptionEntitlement {
        val token = validatePurchaseToken(purchaseToken)
        val productId = BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID
        require(productId.matches(Regex("[A-Za-z0-9._-]{3,100}"))) {
            "The subscription product configuration is invalid."
        }
        val base = BuildConfig.ALAI_API_BASE_URL.trimEnd('/')
        require(base.startsWith("https://")) { "Billing verification requires HTTPS." }
        val payload = JSONObject().put("productId", productId).put("purchaseToken", token)
            .toString().toByteArray(Charsets.UTF_8)
        val connection = (URL(base + "/v1/billing/subscription/verify").openConnection()
            as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 8_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            doOutput = true
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setFixedLengthStreamingMode(payload.size)
        }
        return try {
            connection.outputStream.use { it.write(payload) }
            val status = connection.responseCode
            val responseStream = if (status in 200..299) connection.inputStream else connection.errorStream
            val responseText = responseStream?.let(::readBounded).orEmpty()
            if (status == 503) {
                throw IllegalStateException("Purchase verification is not configured or temporarily unavailable.")
            }
            if (status !in 200..299) throw IllegalStateException("Google Play could not verify this purchase.")
            parseSubscriptionEntitlementPayload(responseText)
        } finally { connection.disconnect() }
    }

    internal fun parseSubscriptionEntitlementPayload(responseText: String): CloudSubscriptionEntitlement {
        val root = runCatching { JSONObject(responseText) }.getOrElse {
            throw IllegalArgumentException("The billing service returned an invalid response.")
        }
        require(root.optBoolean("ok", false)) {
            when (root.optString("error")) {
                "PURCHASE_NOT_ENTITLED" -> "This subscription does not currently grant access."
                "PURCHASE_ACKNOWLEDGEMENT_PENDING" -> "Google Play confirmation is pending. Restore purchases to retry."
                else -> "This purchase could not be verified."
            }
        }
        val basePlanId = root.optString("basePlanId", "")
        require(basePlanId in setOf("monthly", "annual")) {
            "The verified subscription base plan is not supported."
        }
        val expiresAt = root.optLong("expiresAtEpochMillis", 0L)
        require(expiresAt > 0L) { "The verified subscription expiry is missing." }
        val productId = BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID
        val verifiedProductId = root.optString("productId", "")
        require(verifiedProductId == productId) {
            "The verified purchase belongs to a different subscription product."
        }
        val state = root.optString("subscriptionState", "SUBSCRIPTION_STATE_UNSPECIFIED")
        val stateAllowsAccess = state in setOf(
            "SUBSCRIPTION_STATE_ACTIVE",
            "SUBSCRIPTION_STATE_IN_GRACE_PERIOD",
            "SUBSCRIPTION_STATE_CANCELED"
        )
        val isCurrentlyEntitled = root.optBoolean("entitled", false) &&
            stateAllowsAccess && expiresAt > System.currentTimeMillis()
        val cloudAccessToken = if (isCurrentlyEntitled) {
            validatePlusAccessToken(root.optString("cloudAccessToken", ""))
        } else null
        return CloudSubscriptionEntitlement(
            entitled = isCurrentlyEntitled,
            subscriptionState = state,
            productId = verifiedProductId,
            basePlanId = basePlanId,
            isTrial = root.optBoolean("isTrial", false) && isCurrentlyEntitled,
            expiresAtEpochMillis = expiresAt,
            cloudAccessToken = cloudAccessToken
        )
    }

    internal fun validatePlusAccessToken(value: String): String {
        require(value.length in 64..4096 &&
            value.matches(Regex("[A-Za-z0-9_-]{20,2048}\\.[A-Za-z0-9_-]{40,128}"))) {
            "A valid server-issued PLUS access token is required."
        }
        return value
    }

    internal fun parseBillingStatusPayload(responseText: String): CloudBillingStatus {
        val root = JSONObject(responseText)
        require(root.optBoolean("ok", false)) {
            "Secure billing readiness check returned an invalid response."
        }
        val allowedPlans = setOf("monthly", "annual")
        val values = root.optJSONArray("activeBasePlans")
        val activePlans = buildSet {
            if (values != null) {
                for (index in 0 until values.length()) {
                    values.optString(index).takeIf { it in allowedPlans }?.let(::add)
                }
            }
        }
        val productMatches = root.optString("productId", "") ==
            BuildConfig.ALAI_SUBSCRIPTION_PRODUCT_ID
        val checkoutReady = root.optBoolean("checkoutReady", false) &&
            productMatches && activePlans.isNotEmpty()
        return CloudBillingStatus(
            checkoutReady = checkoutReady,
            activeBasePlans = if (checkoutReady) activePlans else emptySet()
        )
    }

    internal fun validatePurchaseToken(value: String): String {
        require(value.length in 20..MAX_TOKEN_LENGTH) { "The Google Play purchase token has an invalid length." }
        require(value.none { it.isWhitespace() || it.code < 0x20 || it.code == 0x7f }) {
            "The Google Play purchase token contains invalid characters."
        }
        return value
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
