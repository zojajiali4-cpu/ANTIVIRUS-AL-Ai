package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.util.Locale

enum class FolderScanMode { ALL_FILES, APK_ONLY }

data class FolderScanItem(val uri: Uri, val result: ScanResult)

data class FolderScanFailure(val name: String, val reason: String)

data class ScanCoverageCell(
    val format: String,
    val verdict: ScanVerdict,
    val count: Int
)

/**
 * Aggregates only normalized format/verdict counts. It never retains file names,
 * paths, hashes, or file bytes, and bounds attacker-controlled format cardinality.
 */
internal class ScanCoverageAccumulator {
    private val formats = mutableSetOf<String>()
    private val counts = mutableMapOf<Pair<String, ScanVerdict>, Int>()

    fun record(result: ScanResult) {
        val structuralFormat = result.staticAnalysis?.format
            ?.trim()
            ?.uppercase(Locale.ROOT)
            ?.takeIf { format ->
                format.isNotEmpty() && format.length <= 32 &&
                    format.all { character -> character.isLetterOrDigit() || character in "_+.-" }
            }
        val mimeType = result.mimeType
            ?.substringBefore(';')
            ?.trim()
            ?.lowercase(Locale.ROOT)
            ?.takeIf { mime ->
                mime.length <= 64 && '/' in mime &&
                    mime.all { character -> character.isLetterOrDigit() || character in "/-+._!#$&^" }
            }
        val candidate = structuralFormat ?: mimeType ?: "UNKNOWN"
        val format = when {
            candidate in formats -> candidate
            formats.size < MAX_FORMATS - 1 -> candidate.also { formats += it }
            else -> "OTHER".also { formats += it }
        }
        val key = format to result.verdict
        counts[key] = (counts[key] ?: 0) + 1
    }

    fun snapshot(): List<ScanCoverageCell> = counts.map { (key, count) ->
        ScanCoverageCell(format = key.first, verdict = key.second, count = count)
    }.sortedWith(compareBy<ScanCoverageCell> { it.format }.thenBy { it.verdict.name })

    companion object {
        const val MAX_FORMATS = 32
        const val MAX_CELLS = 256
    }
}

data class FolderScanReport(
    val items: List<FolderScanItem>,
    val failures: List<FolderScanFailure>,
    val discoveredFiles: Int,
    val skippedFiles: Int,
    val truncated: Boolean,
    val scannedCountOverride: Int? = null,
    val suspiciousCountOverride: Int? = null,
    val unknownCountOverride: Int? = null,
    val matchedCountOverride: Int? = null,
    val coverageMatrix: List<ScanCoverageCell> = emptyList()
) {
    val scannedCount: Int get() = scannedCountOverride ?: items.size
    val suspiciousCount: Int get() = suspiciousCountOverride ?: items.count { it.result.verdict in setOf(ScanVerdict.KNOWN_MALWARE, ScanVerdict.POTENTIALLY_UNWANTED, ScanVerdict.SUSPICIOUS) }
    val unknownCount: Int get() = unknownCountOverride ?: items.count {
        it.result.verdict == ScanVerdict.UNKNOWN_APK ||
            it.result.verdict == ScanVerdict.UNSUPPORTED_FILE ||
            it.result.verdict == ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE
    }
    val matchedCount: Int get() = matchedCountOverride ?: items.count { it.result.verdict == ScanVerdict.TEST_MARKER_MATCH }

    /** Actual analysis ratio; files skipped by the engine remain visible in this value. */
    val scanCoveragePercent: Int get() =
        if (discoveredFiles == 0) {
            if (!truncated) 100 else 0
        } else ((scannedCount * 100L) / discoveredFiles).toInt().coerceIn(0, 100)

    /** Number of discovered files with a final analyzed-or-not-analyzed disposition. */
    val accountedFiles: Int get() =
        (scannedCount + skippedFiles).coerceAtMost(discoveredFiles)

    /** Completion of the accessible inventory, not the percentage successfully analyzed. */
    val completionPercent: Int get() =
        if (discoveredFiles == 0) {
            if (fullScanCoverage) 100 else 0
        } else {
            val accountedPercent = ((accountedFiles * 100L) / discoveredFiles).toInt().coerceIn(0, 100)
            if (fullScanCoverage) accountedPercent else accountedPercent.coerceAtMost(99)
        }

    /** Exact known-malware count across all scanner results, not only the UI preview. */
    val knownMalwareCount: Int get() =
        coverageMatrix.filter { it.verdict == ScanVerdict.KNOWN_MALWARE }.sumOf { it.count }
            .takeIf { it > 0 }
            ?: items.count { it.result.verdict == ScanVerdict.KNOWN_MALWARE }

    /** Files with no scanned result and no explicit skip/failure disposition. */
    val unaccountedFiles: Int get() =
        (discoveredFiles - scannedCount - skippedFiles).coerceAtLeast(0)

    val allDiscoveredFilesAccounted: Boolean get() = unaccountedFiles == 0

    /**
     * Full scope completion means every Android-accessible path in this scan scope
     * was enumerated and every discovered file has a final disposition. Skips
     * remain visible in their own counter and do not hold the progress below 100%.
     */
    val fullScanCoverage: Boolean get() =
        allDiscoveredFilesAccounted && !truncated
}

/**
 * Scans files under one user-authorized SAF folder.
 * It never walks arbitrary device storage and never installs or executes files.
 */
object FolderScanEngine {
    const val MAX_FILES = ScanLimits.FOLDER_FILE_LIMIT
    const val MAX_DEPTH = 64
    const val MAX_TOTAL_BYTES = ScanLimits.FOLDER_TOTAL_BYTES
    private const val MAX_DIRECTORY_VISITS = ScanLimits.MAX_FOLDER_DIRECTORY_VISITS
    private const val MAX_PENDING_DIRECTORIES = ScanLimits.MAX_PENDING_DIRECTORIES

    private data class Candidate(
        val uri: Uri,
        val name: String,
        val declaredSize: Long
    )

    suspend fun scanFolder(
        context: Context,
        treeUri: Uri,
        mode: FolderScanMode,
        onProgress: suspend (current: Int, total: Int, name: String) -> Unit
    ): FolderScanReport = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        val candidates = mutableListOf<Candidate>()
        val failures = mutableListOf<FolderScanFailure>()
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<Pair<String, Int>>()
        queue.add(DocumentsContract.getTreeDocumentId(treeUri) to 0)
        var truncated = false
        var discoverySkipped = 0
        var directoryVisits = 0

        while (queue.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            directoryVisits++
            if (directoryVisits > MAX_DIRECTORY_VISITS) {
                failures += FolderScanFailure(
                    "Folder traversal",
                    "Stopped after the 2,000-directory safety limit."
                )
                truncated = true
                break
            }
            val (directoryId, depth) = queue.removeFirst()
            if (depth > MAX_DEPTH) {
                failures += FolderScanFailure(directoryId, "Maximum folder depth reached.")
                truncated = true
                continue
            }
            if (!visited.add(directoryId)) continue

            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, directoryId)
            try {
                resolver.query(
                    childrenUri,
                    arrayOf(
                        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                        DocumentsContract.Document.COLUMN_MIME_TYPE,
                        DocumentsContract.Document.COLUMN_SIZE
                    ),
                    null,
                    null,
                    null
                )?.use { cursor ->
                    val idColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    val sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                    while (cursor.moveToNext()) {
                        val mime = if (mimeColumn >= 0) cursor.getString(mimeColumn) else null
                        val fallbackName = if (nameColumn >= 0) cursor.getString(nameColumn).orEmpty() else "Unnamed file"
                        if (idColumn < 0) {
                            // Without document IDs no SAF child URI can be constructed;
                            // this provider listing cannot be treated as complete.
                            truncated = true
                            if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                                failures += FolderScanFailure(fallbackName, "Directory identifier was unavailable; its contents could not be enumerated.")
                                truncated = true
                            } else {
                                discoverySkipped++
                                failures += FolderScanFailure(fallbackName, "Document identifier was unavailable; this file could not be opened for scanning.")
                            }
                            continue
                        }
                        val documentId = cursor.getString(idColumn)
                        if (documentId.isNullOrBlank()) {
                            if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                                failures += FolderScanFailure(fallbackName, "Directory identifier was empty; its contents could not be enumerated.")
                                truncated = true
                            } else {
                                discoverySkipped++
                                failures += FolderScanFailure(fallbackName, "Document identifier was empty; this file could not be opened for scanning.")
                            }
                            continue
                        }
                        val name = if (fallbackName.isNotBlank()) fallbackName else documentId
                        val size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) cursor.getLong(sizeColumn) else -1L

                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            if (queue.size < MAX_PENDING_DIRECTORIES) {
                                queue.add(documentId to depth + 1)
                            } else {
                                failures += FolderScanFailure(
                                    name.ifBlank { documentId },
                                    "Directory queue reached the 30,000-entry safety limit."
                                )
                                truncated = true
                            }
                        } else {
                            val isApk = name.endsWith(".apk", ignoreCase = true) ||
                                mime == "application/vnd.android.package-archive"
                            if (mode == FolderScanMode.ALL_FILES || isApk) {
                                if (candidates.size >= MAX_FILES) {
                                    truncated = true
                                    break
                                }
                                candidates += Candidate(
                                    uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId),
                                    name = name.ifBlank { "Unnamed file" },
                                    declaredSize = size
                                )
                            }
                        }
                    }
                } ?: run {
                    failures.add(FolderScanFailure(directoryId, "Folder contents could not be listed."))
                    truncated = true
                }
            } catch (error: SecurityException) {
                failures += FolderScanFailure(directoryId, "Access denied by the document provider.")
                truncated = true
            } catch (error: Exception) {
                failures += FolderScanFailure(directoryId, error.message ?: "Folder could not be read.")
                truncated = true
            }
            if (truncated) break
        }

        // Count every result but keep only a bounded preview; retain detections first.
        val findingItems = mutableListOf<FolderScanItem>()
        val previewItems = mutableListOf<FolderScanItem>()
        var skipped = discoverySkipped
        var totalBytes = 0L
        var scannedCount = 0
        var suspiciousCount = 0
        var unknownCount = 0
        var matchedCount = 0
        val coverage = ScanCoverageAccumulator()
        for ((index, candidate) in candidates.withIndex()) {
            currentCoroutineContext().ensureActive()
            if (candidate.declaredSize > ScanEngine.MAX_FILE_SIZE_BYTES) {
                skipped++
                failures += FolderScanFailure(candidate.name, "File exceeds the 200 MB per-file limit.")
                continue
            }
            if (candidate.declaredSize > 0L &&
                totalBytes + candidate.declaredSize > MAX_TOTAL_BYTES
            ) {
                skipped++
                failures += FolderScanFailure(candidate.name, "Folder scan reached the 25 GB total data limit.")
                // The file is explicitly counted as not analyzed; discovery itself is complete.
                continue
            }

            withContext(Dispatchers.Main.immediate) {
                onProgress(index + 1, candidates.size, candidate.name)
            }
            try {
                val result = ScanEngine.scan(context.applicationContext, candidate.uri)
                totalBytes += result.sizeBytes
                scannedCount++
                coverage.record(result)
                when (result.verdict) {
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.POTENTIALLY_UNWANTED,
                    ScanVerdict.SUSPICIOUS -> suspiciousCount++
                    ScanVerdict.UNKNOWN_APK,
                    ScanVerdict.UNSUPPORTED_FILE,
                    ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE -> unknownCount++
                    ScanVerdict.TEST_MARKER_MATCH -> matchedCount++
                    ScanVerdict.NO_KNOWN_INDICATOR -> Unit
                }
                val reportItem = FolderScanItem(candidate.uri, result)
                val isPriorityFinding = result.verdict in setOf(
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.POTENTIALLY_UNWANTED,
                    ScanVerdict.SUSPICIOUS
                )
                if (isPriorityFinding) {
                    if (findingItems.size < ScanLimits.MAX_RESULT_DETAILS) findingItems += reportItem
                } else if (previewItems.size < ScanLimits.MAX_RESULT_DETAILS) {
                    previewItems += reportItem
                }
                if (totalBytes >= MAX_TOTAL_BYTES) {
                    val remaining = candidates.size - index - 1
                    if (remaining > 0) {
                        // These files were already enumerated, so record them as skipped
                        // without marking the directory traversal itself as incomplete.
                        skipped += remaining
                        failures += FolderScanFailure(
                            "Remaining files",
                            "Stopped analyzing after the 25 GB total data limit; $remaining file(s) were recorded as not scanned."
                        )
                    }
                    break
                }
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (error: Exception) {
                skipped++
                failures += FolderScanFailure(candidate.name, error.message ?: "File scan failed.")
            }
        }

        val report = FolderScanReport(
            items = if (findingItems.isNotEmpty()) findingItems else previewItems,
            failures = failures,
            discoveredFiles = candidates.size + discoverySkipped,
            skippedFiles = skipped,
            // Skipped candidates have an explicit final disposition. Only traversal
            // gaps or an enumeration safety limit make the accessible scope incomplete.
            truncated = truncated,
            scannedCountOverride = scannedCount,
            suspiciousCountOverride = suspiciousCount,
            unknownCountOverride = unknownCount,
            matchedCountOverride = matchedCount,
            coverageMatrix = coverage.snapshot()
        )
        val finalProgress = if (report.fullScanCoverage) {
            report.discoveredFiles
        } else {
            (report.discoveredFiles - 1).coerceAtLeast(0)
        }
        withContext(Dispatchers.Main.immediate) {
            onProgress(
                finalProgress,
                report.discoveredFiles,
                if (report.fullScanCoverage) "Accessible folder scope completed"
                else "Accessible folder scope is incomplete; see skipped-file details"
            )
        }
        report
    }
}
