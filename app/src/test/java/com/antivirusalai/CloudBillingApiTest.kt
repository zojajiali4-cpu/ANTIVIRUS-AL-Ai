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
}
