package com.antivirusalai

import org.junit.Assert.assertEquals
import org.junit.Test

class CloudBillingApiTest {
    @Test
    fun acceptsOpaqueGooglePurchaseTokenWithoutModifyingIt() {
        val token = "purchase-token-from-google-play-123456"
        assertEquals(token, CloudBillingApi.validatePurchaseToken(token))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsShortPurchaseToken() {
        CloudBillingApi.validatePurchaseToken("short")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsWhitespaceInPurchaseToken() {
        CloudBillingApi.validatePurchaseToken("purchase token from google play")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsControlCharactersInPurchaseToken() {
        CloudBillingApi.validatePurchaseToken("purchase-token-from-google-play-123456\n")
    }
    @Test
    fun acceptsWellFormedServerIssuedPlusAccessToken() {
        val token = "eyJ2IjoxLCJhdWQiOiJhbGFpIn0." + "A".repeat(43)
        assertEquals(token, CloudBillingApi.validatePlusAccessToken(token))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMalformedServerIssuedPlusAccessToken() {
        CloudBillingApi.validatePlusAccessToken("tampered.or-invalid")
    }

    @Test
    fun grantsCloudEntitlementOnlyWhenServerAlsoProvidesAccessToken() {
        val expiry = System.currentTimeMillis() + 60_000L
        val token = "eyJ2IjoxLCJhdWQiOiJhbGFpIn0." + "A".repeat(43)
        val payload = """{"ok":true,"entitled":true,"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","productId":"alai_plus","basePlanId":"monthly","isTrial":true,"expiresAtEpochMillis":$expiry,"cloudAccessToken":"$token"}"""
        val result = CloudBillingApi.parseSubscriptionEntitlementPayload(payload)
        assertEquals(true, result.entitled)
        assertEquals(token, result.cloudAccessToken)
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesActiveEntitlementWithoutServerIssuedCloudToken() {
        val expiry = System.currentTimeMillis() + 60_000L
        val payload = """{"ok":true,"entitled":true,"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","productId":"alai_plus","basePlanId":"monthly","expiresAtEpochMillis":$expiry}"""
        CloudBillingApi.parseSubscriptionEntitlementPayload(payload)
    }

    @Test
    fun doesNotGrantCloudEntitlementForNonEntitledSubscription() {
        val expiry = System.currentTimeMillis() + 60_000L
        val payload = """{"ok":true,"entitled":false,"subscriptionState":"SUBSCRIPTION_STATE_ON_HOLD","productId":"alai_plus","basePlanId":"monthly","expiresAtEpochMillis":$expiry}"""
        val result = CloudBillingApi.parseSubscriptionEntitlementPayload(payload)
        assertEquals(false, result.entitled)
        assertEquals(null, result.cloudAccessToken)
    }

    @Test
    fun billingStatusAcceptsOnlyKnownActivePlansForTheExpectedProduct() {
        val result = CloudBillingApi.parseBillingStatusPayload(
            """{"ok":true,"checkoutReady":true,"productId":"alai_plus","activeBasePlans":["monthly","annual","unknown"]}"""
        )
        assertEquals(true, result.checkoutReady)
        assertEquals(setOf("monthly", "annual"), result.activeBasePlans)
    }

    @Test
    fun billingStatusRemainsClosedWhenServerReportsNotReady() {
        val result = CloudBillingApi.parseBillingStatusPayload(
            """{"ok":true,"checkoutReady":false,"productId":null,"activeBasePlans":[]}"""
        )
        assertEquals(false, result.checkoutReady)
        assertEquals(emptySet<String>(), result.activeBasePlans)
    }

    @Test
    fun billingStatusRejectsUnexpectedProductEvenWhenServerSaysReady() {
        val result = CloudBillingApi.parseBillingStatusPayload(
            """{"ok":true,"checkoutReady":true,"productId":"another-product","activeBasePlans":["monthly"]}"""
        )
        assertEquals(false, result.checkoutReady)
        assertEquals(emptySet<String>(), result.activeBasePlans)
    }

    @Test(expected = IllegalArgumentException::class)
    fun billingStatusRejectsMalformedOrUnsuccessfulServerResponse() {
        CloudBillingApi.parseBillingStatusPayload("""{"ok":false}""")
    }
}
