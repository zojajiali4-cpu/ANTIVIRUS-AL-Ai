package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

enum class FolderScanMode { ALL_FILES, APK_ONLY }

data class FolderScanItem(val uri: Uri, val result: ScanResult)

data class FolderScanFailure(val name: String, val reason: String)

data class FolderScanSummary(
    val scanned: Int,
    val threats: Int,
    val unknown: Int,
    val noKnownIndicator: Int,
    val testMatches: Int
) {
    companion object {
        fun fromVerdicts(verdicts: Iterable<ScanVerdict>): FolderScanSummary {
            var scanned = 0
            var threats = 0
            var unknown = 0
            var noKnown = 0
            var tests = 0
            for (verdict in verdicts) {
                scanned++
                when (verdict) {
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.KNOWN_PUA,
                    ScanVerdict.KNOWN_SUSPICIOUS,
                    ScanVerdict.SUSPICIOUS -> threats++
                    ScanVerdict.UNKNOWN_APK,
                    ScanVerdict.UNSUPPORTED_FILE -> unknown++
                    ScanVerdict.NO_KNOWN_INDICATOR -> noKnown++
                    ScanVerdict.TEST_MARKER_MATCH -> tests++
                }
            }
            return FolderScanSummary(scanned, threats, unknown, noKnown, tests)
        }
    }
}

data class FolderScanReport(
    val items: List<FolderScanItem>,
    val failures: List<FolderScanFailure>,
    val discoveredFiles: Int,
    val skippedFiles: Int,
    val totalBytes: Long,
    val durationMillis: Long,
    val truncated: Boolean
) {
    val summary: FolderScanSummary
        get() = FolderScanSummary.fromVerdicts(items.map { it.result.verdict })
}

/**
 * Scans only a SAF tree explicitly selected by the user.
 * Never traverses arbitrary device storage or other apps' private data.
 */
object FolderScanEngine {
    const val MAX_FILES = 300
    const val MAX_DEPTH = 20
    const val MAX_TOTAL_BYTES = 1024L * 1024L * 1024L
    private const val MAX_DIRECTORY_VISITS = 2_000
    private const val MAX_PENDING_DIRECTORIES = 3_000

    private data class Candidate(val uri: Uri, val name: String, val declaredSize: Long)

    suspend fun scanFolder(
        context: Context,
        treeUri: Uri,
        mode: FolderScanMode = FolderScanMode.ALL_FILES,
        onProgress: suspend (current: Int, total: Int, name: String) -> Unit
    ): FolderScanReport = withContext(Dispatchers.IO) {
        val startedAt = System.nanoTime()
        val resolver = context.contentResolver
        val candidates = mutableListOf<Candidate>()
        val failures = mutableListOf<FolderScanFailure>()
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<Pair<String, Int>>()
        queue.add(DocumentsContract.getTreeDocumentId(treeUri) to 0)
        var truncated = false
        var directoryVisits = 0

        while (queue.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            directoryVisits++
            if (directoryVisits > MAX_DIRECTORY_VISITS) {
                failures += FolderScanFailure("Folder traversal", "Stopped at the 2,000-directory safety limit.")
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
                    null, null, null
                )?.use { cursor ->
                    val idColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    val sizeColumn = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                    while (cursor.moveToNext()) {
                        currentCoroutineContext().ensureActive()
                        if (idColumn < 0) continue
                        val documentId = cursor.getString(idColumn) ?: continue
                        val name = if (nameColumn >= 0) cursor.getString(nameColumn).orEmpty() else documentId
                        val mime = if (mimeColumn >= 0) cursor.getString(mimeColumn) else null
                        val size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) cursor.getLong(sizeColumn) else -1L

                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            if (queue.size < MAX_PENDING_DIRECTORIES) queue.add(documentId to depth + 1)
                            else {
                                failures += FolderScanFailure(name.ifBlank { documentId }, "Directory queue safety limit reached.")
                                truncated = true
                            }
                        } else {
                            val apk = name.endsWith(".apk", ignoreCase = true) ||
                                mime == "application/vnd.android.package-archive"
                            if (mode == FolderScanMode.ALL_FILES || apk) {
                                if (candidates.size >= MAX_FILES) {
                                    truncated = true
                                    break
                                }
                                candidates += Candidate(
                                    DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId),
                                    name.ifBlank { "Unnamed file" },
                                    size
                                )
                            }
                        }
                    }
                } ?: failures.add(FolderScanFailure(directoryId, "Folder contents could not be listed."))
            } catch (_: SecurityException) {
                failures += FolderScanFailure(directoryId, "Access denied by the document provider.")
                truncated = true
            } catch (error: Exception) {
                failures += FolderScanFailure(directoryId, error.message ?: "Folder could not be read.")
                truncated = true
            }
            if (truncated) break
        }

        val items = mutableListOf<FolderScanItem>()
        var skipped = 0
        var totalBytes = 0L
        for ((index, candidate) in candidates.withIndex()) {
            currentCoroutineContext().ensureActive()
            if (candidate.declaredSize > ScanEngine.MAX_FILE_SIZE_BYTES) {
                skipped++
                failures += FolderScanFailure(candidate.name, "File exceeds the 200 MB per-file limit.")
                continue
            }
            if (candidate.declaredSize > 0L && totalBytes + candidate.declaredSize > MAX_TOTAL_BYTES) {
                skipped++
                failures += FolderScanFailure(candidate.name, "Folder scan reached the 1 GB total data limit.")
                truncated = true
                continue
            }

            withContext(Dispatchers.Main.immediate) {
                onProgress(index + 1, candidates.size, candidate.name)
            }
            try {
                val result = ScanEngine.scan(context.applicationContext, candidate.uri)
                totalBytes += result.sizeBytes
                items += FolderScanItem(candidate.uri, result)
                if (totalBytes >= MAX_TOTAL_BYTES) {
                    truncated = index < candidates.lastIndex
                    if (truncated) {
                        skipped += candidates.size - index - 1
                        failures += FolderScanFailure("Remaining files", "Stopped after reaching the 1 GB total data limit.")
                    }
                    break
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                skipped++
                failures += FolderScanFailure(candidate.name, error.message ?: "File scan failed.")
            }
        }

        FolderScanReport(
            items = items,
            failures = failures,
            discoveredFiles = candidates.size,
            skippedFiles = skipped,
            totalBytes = totalBytes,
            durationMillis = (System.nanoTime() - startedAt) / 1_000_000L,
            truncated = truncated || skipped > 0
        )
    }
}
