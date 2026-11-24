package com.antivirusalai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudBillingApiTest {
    @Test fun acceptsOpaqueBazaarPurchaseTokenWithoutModifyingIt() {
        val token = "bazaar-purchase-token-123456789012345"
        assertEquals(token, CloudBillingApi.validatePurchaseToken(token))
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsShortPurchaseToken() { CloudBillingApi.validatePurchaseToken("short") }
    @Test(expected = IllegalArgumentException::class) fun rejectsWhitespaceInPurchaseToken() { CloudBillingApi.validatePurchaseToken("bazaar purchase token") }
    @Test(expected = IllegalArgumentException::class) fun rejectsControlCharactersInPurchaseToken() { CloudBillingApi.validatePurchaseToken("bazaar-purchase-token-123456789\n") }
    @Test fun acceptsWellFormedServerIssuedPlusAccessToken() {
        val token = "eyJ2IjoxLCJhdWQiOiJhbGFpIn0." + "A".repeat(43)
        assertEquals(token, CloudBillingApi.validatePlusAccessToken(token))
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsMalformedServerIssuedPlusAccessToken() { CloudBillingApi.validatePlusAccessToken("tampered.or-invalid") }
    @Test fun grantsEntitlementOnlyForServerVerifiedActiveBazaarSubscription() {
        val expiry = System.currentTimeMillis() + 60_000L
        val token = "eyJ2IjoxLCJhdWQiOiJhbGFpIn0." + "A".repeat(43)
        val payload = """{"ok":true,"entitled":true,"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","productId":"alai_plus_monthly","basePlanId":"monthly","expiresAtEpochMillis":$expiry,"cloudAccessToken":"$token"}"""
        val result = CloudBillingApi.parseSubscriptionEntitlementPayload(payload)
        assertTrue(result.entitled); assertEquals(token, result.cloudAccessToken); assertEquals("monthly", result.basePlanId)
    }
    @Test(expected = IllegalArgumentException::class) fun refusesActiveEntitlementWithoutServerIssuedCloudToken() {
        val expiry = System.currentTimeMillis() + 60_000L
        CloudBillingApi.parseSubscriptionEntitlementPayload("""{"ok":true,"entitled":true,"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","productId":"alai_plus_monthly","basePlanId":"monthly","expiresAtEpochMillis":$expiry}""")
    }
    @Test fun doesNotGrantCloudEntitlementForExpiredSubscription() {
        val expiry = System.currentTimeMillis() - 60_000L
        val result = CloudBillingApi.parseSubscriptionEntitlementPayload("""{"ok":true,"entitled":true,"subscriptionState":"SUBSCRIPTION_STATE_ACTIVE","productId":"alai_plus_monthly","basePlanId":"monthly","expiresAtEpochMillis":$expiry}""")
        assertFalse(result.entitled); assertNull(result.cloudAccessToken)
    }
    @Test fun billingStatusAcceptsOnlyKnownConfiguredBazaarProducts() {
        val result = CloudBillingApi.parseBillingStatusPayload("""{"ok":true,"checkoutReady":true,"activeProducts":["alai_plus_monthly","alai_plus_annual","unknown"]}""")
        assertTrue(result.checkoutReady); assertEquals(setOf("monthly", "annual"), result.activeBasePlans)
    }
    @Test fun billingStatusRemainsClosedWhenServerReportsNotReady() {
        val result = CloudBillingApi.parseBillingStatusPayload("""{"ok":true,"checkoutReady":false,"activeProducts":[]}""")
        assertFalse(result.checkoutReady); assertTrue(result.activeBasePlans.isEmpty())
    }
    @Test fun billingStatusRejectsUnrecognizedProductsEvenWhenServerSaysReady() {
        val result = CloudBillingApi.parseBillingStatusPayload("""{"ok":true,"checkoutReady":true,"activeProducts":["another-product"]}""")
        assertFalse(result.checkoutReady); assertTrue(result.activeBasePlans.isEmpty())
    }
    @Test(expected = IllegalArgumentException::class) fun billingStatusRejectsMalformedOrUnsuccessfulServerResponse() {
        CloudBillingApi.parseBillingStatusPayload("""{"ok":false}""")
    }
}
