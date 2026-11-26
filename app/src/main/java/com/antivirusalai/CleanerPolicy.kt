package com.antivirusalai

import java.io.File
import java.util.Locale

/**
 * Conservative storage-cleaner classification. These rules only create review
 * candidates; they never authorize deletion by themselves.
 */
internal object CleanerPolicy {
    private val temporaryExtensions = setOf(
        "tmp", "temp", "part", "crdownload", "cache", "download"
    )
    private val reviewOnlyExtensions = setOf("log", "bak", "old")

    fun isLikelyTemporaryName(name: String): Boolean =
        extensionOf(name) in temporaryExtensions

    fun needsManualReviewName(name: String): Boolean =
        extensionOf(name) in reviewOnlyExtensions

    fun extensionOf(name: String): String =
        name.substringAfterLast('.', "").lowercase(Locale.ROOT)

    /**
     * Android/data and Android/obb are protected by scoped-storage rules.
     * Within Android/, only Android/media is traversed by this cleaner.
     */
    fun isProtectedRelativePath(relativePath: String): Boolean {
        val segments = relativePath
            .replace('\\', '/')
            .split('/')
            .filter { it.isNotBlank() }
        if (segments.isEmpty() || !segments.first().equals("Android", ignoreCase = true)) {
            return false
        }
        return segments.size >= 2 && !segments[1].equals("media", ignoreCase = true)
    }

    fun isWithinRoot(candidate: File, root: File): Boolean {
        val candidatePath = runCatching { candidate.canonicalPath }.getOrNull() ?: return false
        val rootPath = runCatching { root.canonicalPath }.getOrNull() ?: return false
        return candidatePath == rootPath || candidatePath.startsWith(rootPath + File.separator)
    }

    fun saturatedAdd(total: Long, value: Long): Long =
        if (value > 0L && total > Long.MAX_VALUE - value) Long.MAX_VALUE
        else total + value
}
