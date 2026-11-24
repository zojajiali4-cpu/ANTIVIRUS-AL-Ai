package com.antivirusalai

import org.junit.Assert.assertEquals
import org.junit.Test

class BazaarBillingApiTest {
    @Test
    fun acceptsOpaqueBazaarPurchaseTokenWithoutChangingIt() {
        val token = "bazaar-purchase-token-123456789"
        assertEquals(token, BazaarBillingApi.validatePurchaseToken(token))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsShortBazaarPurchaseToken() {
        BazaarBillingApi.validatePurchaseToken("short")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsWhitespaceInBazaarPurchaseToken() {
        BazaarBillingApi.validatePurchaseToken("bazaar purchase token 123456789")
    }

    @Test
    fun acceptsServerIssuedPlusAccessTokenShape() {
        val token = "eyJ2IjoxLCJhdWQiOiJhbGFpLWhhc2gifQ." + "A".repeat(43)
        assertEquals(token, BazaarBillingApi.validateCloudAccessToken(token))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsMalformedPlusAccessToken() {
        BazaarBillingApi.validateCloudAccessToken("forged.invalid")
    }
}
