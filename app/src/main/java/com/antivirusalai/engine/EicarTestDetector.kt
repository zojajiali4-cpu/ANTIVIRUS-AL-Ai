package com.antivirusalai.engine

import java.io.File
import java.io.InputStream

/**
 * Recognizes the harmless EICAR antivirus test string.
 *
 * This is a regression-test marker only. It is not a production malware signature
 * and must never be presented as evidence of real-world malware detection.
 */
object EicarTestDetector {
    private val pattern: ByteArray = buildString {
        append("X5O!P%@AP[4\\PZX54(P^)7CC)7}")
        append('$')
        append("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!")
        append('$')
        append("H+H*")
    }.toByteArray(Charsets.US_ASCII)

    private val prefix: IntArray = IntArray(pattern.size).also { table ->
        var matched = 0
        for (i in 1 until pattern.size) {
            while (matched > 0 && pattern[i] != pattern[matched]) {
                matched = table[matched - 1]
            }
            if (pattern[i] == pattern[matched]) matched++
            table[i] = matched
        }
    }

    /** Incremental matcher used by the main scan pass; it retains only KMP state. */
    class StreamingMatcher {
        private var matched = 0
        var found: Boolean = false
            private set

        fun update(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size - offset) {
            require(offset >= 0 && length >= 0 && offset <= buffer.size - length)
            if (found) return
            val end = offset + length
            for (i in offset until end) {
                val value = buffer[i]
                while (matched > 0 && value != pattern[matched]) {
                    matched = prefix[matched - 1]
                }
                if (value == pattern[matched]) matched++
                if (matched == pattern.size) {
                    found = true
                    return
                }
            }
        }
    }

    fun contains(file: File): Boolean = file.inputStream().use(::contains)

    /** Streaming KMP matcher; memory use is constant regardless of file size. */
    fun contains(input: InputStream): Boolean {
        val matcher = StreamingMatcher()
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) return matcher.found
            if (count == 0) continue
            matcher.update(buffer, 0, count)
            if (matcher.found) return true
        }
    }
}
