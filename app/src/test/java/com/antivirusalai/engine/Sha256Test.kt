package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Sha256Test {
    @Test
    fun hashesKnownUtf8Input() {
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Sha256.digest("abc".toByteArray(Charsets.UTF_8))
        )
    }

    @Test
    fun outputIsLowercaseHex() {
        val actual = Sha256.digest(byteArrayOf(0, 1, 15, 16, -1))
        assertEquals(64, actual.length)
        assertEquals(actual.lowercase(), actual)
        assertTrue(actual.all { it in "0123456789abcdef" })
    }

    @Test
    fun hexEncodingPreservesLeadingZeroAndUnsignedBytes() {
        assertEquals("000f80ff", Sha256.hex(byteArrayOf(0x00, 0x0f, 0x80.toByte(), 0xff.toByte())))
    }

    @Test
    fun streamingDigestMatchesKnownVectorAcrossChunks() {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update("a".toByteArray(Charsets.UTF_8))
        digest.update("bc".toByteArray(Charsets.UTF_8))
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            Sha256.hex(digest.digest())
        )
    }
}
