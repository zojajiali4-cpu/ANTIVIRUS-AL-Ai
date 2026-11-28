package com.antivirusalai.engine

import java.io.File
import java.util.Locale

internal object QuickScanPolicy {
    private val topLevelPriority = mapOf(
        "downloads" to 0, "download" to 1, "documents" to 2,
        "bluetooth" to 3, "android" to 4
    )
    private val executableAndArchiveExtensions = setOf(
        "apk", "apks", "xapk", "aab", "dex", "jar", "zip", "rar", "7z",
        "tar", "gz", "so", "elf", "js", "mjs", "html", "htm"
    )
    private val documentExtensions = setOf(
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "xml"
    )

    fun shouldVisitDirectory(storageRoot: File, directory: File): Boolean {
        val parts = relativeParts(storageRoot, directory) ?: return false
        if (parts.isEmpty()) return true
        return when (parts[0].lowercase(Locale.ROOT)) {
            "download", "downloads", "documents", "bluetooth" -> true
            "android" -> parts.size == 1 ||
                (parts.size >= 2 && parts[1].equals("media", ignoreCase = true))
            else -> false
        }
    }

    fun orderChildren(storageRoot: File, directory: File, children: Array<File>): List<File> =
        children.asSequence()
            .filter { child -> !child.isDirectory || shouldVisitDirectory(storageRoot, child) }
            .sortedWith(
                compareBy<File> { priority(storageRoot, it) }
                    .thenByDescending { if (it.isFile) it.lastModified() else Long.MIN_VALUE }
                    .thenBy { it.name.lowercase(Locale.ROOT) }
            )
            .toList()

    fun priority(storageRoot: File, entry: File): Int {
        if (entry.isDirectory) {
            val parts = relativeParts(storageRoot, entry) ?: return Int.MAX_VALUE
            if (parts.isEmpty()) return 0
            val first = parts[0].lowercase(Locale.ROOT)
            if (first == "android") {
                return if (parts.size == 1) 4
                else if (parts[1].equals("media", ignoreCase = true)) 5
                else Int.MAX_VALUE
            }
            return topLevelPriority[first] ?: 20
        }
        val extension = entry.name.substringAfterLast('.', "").lowercase(Locale.ROOT)
        return when {
            extension in executableAndArchiveExtensions -> 6
            extension in documentExtensions -> 7
            else -> 8
        }
    }

    private fun relativeParts(root: File, child: File): List<String>? = try {
        val rootPath = root.canonicalPath.trimEnd(File.separatorChar)
        val childPath = child.canonicalPath
        if (childPath == rootPath) emptyList()
        else if (!childPath.startsWith(rootPath + File.separator)) null
        else childPath.removePrefix(rootPath + File.separator)
            .split(File.separatorChar)
            .filter { it.isNotBlank() }
    } catch (_: Exception) {
        null
    }
}
