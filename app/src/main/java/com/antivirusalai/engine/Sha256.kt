package com.antivirusalai.engine

import java.security.MessageDigest

object Sha256 {
    fun digest(bytes: ByteArray): String =
        hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    /** Canonical lowercase hex encoding shared by in-memory and streaming digests. */
    fun hex(bytes: ByteArray): String = bytes.joinToString("") { byte ->
        "%02x".format(byte.toInt() and 0xff)
    }
}
