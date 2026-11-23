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
