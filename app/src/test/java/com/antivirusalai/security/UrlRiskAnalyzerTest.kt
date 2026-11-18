package com.antivirusalai.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlRiskAnalyzerTest {
    @Test fun rejectsNonWebSchemes() {
        val result = UrlRiskAnalyzer.analyze("javascript:alert(1)")
        assertEquals(UrlRiskLevel.INVALID, result.level)
        assertEquals("UNSUPPORTED_SCHEME", result.signals.single().code)
    }

    @Test fun flagsEmbeddedCredentials() {
        val result = UrlRiskAnalyzer.analyze("https://trusted.example@evil.example/login")
        assertEquals(UrlRiskLevel.HIGH_RISK_STRUCTURE, result.level)
        assertEquals("EMBEDDED_CREDENTIALS", result.signals.single().code)
    }

    @Test fun flagsPlainHttpWithoutCallingItMalware() {
        val result = UrlRiskAnalyzer.analyze("http://example.com/")
        assertEquals(UrlRiskLevel.CAUTION, result.level)
        assertTrue(result.signals.any { it.code == "UNENCRYPTED_HTTP" })
    }

    @Test fun flagsKnownShortenerAsUnresolved() {
        val result = UrlRiskAnalyzer.analyze("https://bit.ly/abc123")
        assertTrue(result.signals.any { it.code == "URL_SHORTENER" })
        assertNotNull(result.normalizedUrl)
    }

    @Test fun reportsNoStructuralWarningForOrdinaryHttps() {
        val result = UrlRiskAnalyzer.analyze("https://example.com/help")
        assertEquals(UrlRiskLevel.NO_STRUCTURAL_WARNING, result.level)
        assertTrue(result.signals.isEmpty())
    }

    @Test fun rejectsWhitespaceAndMalformedHost() {
        assertEquals(UrlRiskLevel.INVALID, UrlRiskAnalyzer.analyze("https://exa mple.com").level)
        assertNull(UrlRiskAnalyzer.analyze("https:///missing-host").normalizedUrl)
    }

    @Test fun flagsIpLiteralAndPunycodeDomains() {
        assertTrue(UrlRiskAnalyzer.analyze("https://192.0.2.1/login").signals.any { it.code == "IP_LITERAL_HOST" })
        assertTrue(UrlRiskAnalyzer.analyze("https://xn--e1afmkfd.example/").signals.any { it.code == "PUNYCODE_HOST" })
    }
}
