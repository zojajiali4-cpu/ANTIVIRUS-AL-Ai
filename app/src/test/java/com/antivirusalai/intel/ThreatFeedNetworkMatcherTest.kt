package com.antivirusalai.intel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ThreatFeedNetworkMatcherTest {
    private fun indicator(type: ThreatIndicatorType, value: String) = ThreatNetworkIndicator(
        type = type,
        value = value,
        familyId = "TEST.FAMILY",
        classification = ThreatClassification.SUSPICIOUS,
        sources = setOf("THREATFOX"),
        confidence = 90,
        firstSeenAtEpochSeconds = 1_800_000_000L,
        expiresAtEpochSeconds = 1_800_086_400L
    )

    @Test
    fun exactDomainMatchIsReturned() {
        val expected = indicator(ThreatIndicatorType.DOMAIN, "bad.example")
        val found = ThreatFeedNetworkMatcher.find(
            "https://bad.example/login",
            mapOf("DOMAIN|bad.example" to expected)
        )
        assertEquals(expected, found)
    }

    @Test
    fun subdomainDoesNotInheritParentDomainReputation() {
        val parent = indicator(ThreatIndicatorType.DOMAIN, "example")
        assertNull(
            ThreatFeedNetworkMatcher.find(
                "https://bad.example/login",
                mapOf("DOMAIN|example" to parent)
            )
        )
    }

    @Test
    fun exactUrlWithPortCanMatch() {
        val expected = indicator(ThreatIndicatorType.URL, "http://bad.example:8080/payload")
        val found = ThreatFeedNetworkMatcher.find(
            "http://bad.example:8080/payload",
            mapOf("URL|http://bad.example:8080/payload" to expected)
        )
        assertEquals(expected, found)
    }

    @Test
    fun credentialsAndFragmentsAreNotMatched() {
        val expected = indicator(ThreatIndicatorType.DOMAIN, "bad.example")
        assertNull(
            ThreatFeedNetworkMatcher.find(
                "https://user@bad.example/path",
                mapOf("DOMAIN|bad.example" to expected)
            )
        )
        assertNull(
            ThreatFeedNetworkMatcher.find(
                "https://bad.example/path#fragment",
                mapOf("DOMAIN|bad.example" to expected)
            )
        )
    }
}
