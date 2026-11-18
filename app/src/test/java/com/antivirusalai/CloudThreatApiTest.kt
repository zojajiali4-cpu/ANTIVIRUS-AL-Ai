package com.antivirusalai

import org.junit.Assert.assertEquals
import org.junit.Test

class CloudThreatApiTest {
    @Test
    fun acceptsAndNormalizesUppercaseSha256() {
        assertEquals("a".repeat(64), CloudThreatApi.validateSha256("A".repeat(64)))
    }

    @Test
    fun trimsSurroundingWhitespaceBeforeValidation() {
        val digest = "b".repeat(64)
        assertEquals(digest, CloudThreatApi.validateSha256("  $digest\n"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsWrongLength() {
        CloudThreatApi.validateSha256("a".repeat(63))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonHexadecimalCharacters() {
        CloudThreatApi.validateSha256("g".repeat(64))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsEmptyDigest() {
        CloudThreatApi.validateSha256("")
    }
}
