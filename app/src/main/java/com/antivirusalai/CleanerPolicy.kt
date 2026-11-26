package com.antivirusalai

import java.util.Locale

internal object CleanerPolicy {
    private val temporaryExtensions = setOf("tmp", "temp", "log", "bak", "old", "part", "crdownload", "cache")

    fun isTemporaryName(name: String): Boolean {
        val extension = name.substringAfterLast('.', "").lowercase(Locale.ROOT)
        return extension in temporaryExtensions
    }
}
