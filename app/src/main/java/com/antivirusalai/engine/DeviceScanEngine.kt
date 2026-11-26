package com.antivirusalai.engine

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Device-wide shared-storage scanner.
 *
 * Android still protects other apps' private data and parts of /Android.
 * On Android 11+, broad shared-storage traversal requires the user to grant
 * MANAGE_EXTERNAL_STORAGE in system settings.
 */
object DeviceScanEngine {
    private const val QUICK_FILE_LIMIT = ScanLimits.QUICK_FILE_LIMIT
    private const val QUICK_TOTAL_BYTES = ScanLimits.QUICK_TOTAL_BYTES
    private const val DEEP_FILE_LIMIT = ScanLimits.DEEP_FILE_LIMIT
    private const val DEEP_TOTAL_BYTES = ScanLimits.DEEP_TOTAL_BYTES
    private const val MAX_DEPTH = ScanLimits.MAX_FILE_DEPTH
    private const val MAX_DIRECTORY_VISITS = ScanLimits.MAX_DIRECTORY_VISITS

    fun hasBroadStorageAccess(context: Context): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            context.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        }

    suspend fun scanDevice(
        context: Context,
        deep: Boolean,
        onProgress: suspend (current: Int, total: Int, name: String) -> Unit
    ): FolderScanReport = withContext(Dispatchers.IO) {
        // Never bypass Android's special-access gate. If the user declines it,
        // continue with the readable installed APK components instead of aborting.
        val hasStorageAccess = hasBroadStorageAccess(context)
        val roots = if (hasStorageAccess) findStorageRoots(context) else emptyList()
        val failures = mutableListOf<FolderScanFailure>()
        if (!hasStorageAccess) {
            failures += FolderScanFailure(
                "Shared storage",
                "All files access was not granted. Installed application APK components are checked only where Android exposes readable paths; shared-storage folders are not included."
            )
        }
        val candidates = linkedMapOf<String, File>()
        val maxFiles = if (deep) DEEP_FILE_LIMIT else QUICK_FILE_LIMIT
        var traversalLimitReached = !hasStorageAccess
        var discoverySkipped = 0

        fun addCandidate(file: File, allowedRoot: File) {
            if (candidates.size >= maxFiles || !file.isFile) return
            if (!file.canRead()) {
                discoverySkipped++
                failures += FolderScanFailure(file.name, "File is not readable by this app.")
                return
            }
            val canonical = try {
                file.canonicalFile
            } catch (error: Exception) {
                discoverySkipped++
                traversalLimitReached = true
                failures += FolderScanFailure(file.name, "Could not resolve the file's canonical path.")
                return
            }
            val rootPath = allowedRoot.canonicalPath
            if (canonical.path != rootPath &&
                !canonical.path.startsWith(rootPath + File.separator)
            ) {
                discoverySkipped++
                traversalLimitReached = true
                failures += FolderScanFailure(file.name, "A file path outside the selected storage root was skipped.")
                return
            }
            candidates.putIfAbsent(canonical.path, canonical)
        }

        // Quick and deep scans enumerate the same Android-accessible shared-storage scope.
        // Files that cannot be analyzed remain in the final count as not-scanned items.
        val packageDiscovery = addInstalledApplicationPackages(context, candidates, failures, maxFiles)
        discoverySkipped += packageDiscovery.skippedComponents
        if (packageDiscovery.incomplete) traversalLimitReached = true

        if (hasStorageAccess && roots.isEmpty()) {
            failures += FolderScanFailure("Shared storage", "No readable shared-storage root was available.")
            traversalLimitReached = true
        }

        roots.forEach { root ->
            if (candidates.size >= maxFiles) {
                traversalLimitReached = true
                return@forEach
            }
            val rootCanonical = runCatching { root.canonicalFile }.getOrNull()
            if (rootCanonical == null || !rootCanonical.isDirectory) {
                failures += FolderScanFailure(root.name, "Storage root could not be resolved or listed.")
                traversalLimitReached = true
                return@forEach
            }
            val queue = ArrayDeque<Pair<File, Int>>()
            queue.add(rootCanonical to 0)
            val visited = mutableSetOf<String>()
            var directoryVisits = 0
            while (queue.isNotEmpty() && candidates.size < maxFiles) {
                currentCoroutineContext().ensureActive()
                directoryVisits++
                if (directoryVisits > MAX_DIRECTORY_VISITS) {
                    failures += FolderScanFailure(
                        rootCanonical.name,
                        "Device scan stopped after the 20,000-directory safety limit."
                    )
                    traversalLimitReached = true
                    break
                }
                val (directory, depth) = queue.removeFirst()
                if (depth > MAX_DEPTH) {
                    failures += FolderScanFailure(directory.name, "Maximum directory depth reached.")
                    traversalLimitReached = true
                    continue
                }
                val canonical = try {
                    directory.canonicalFile
                } catch (_: Exception) {
                    failures += FolderScanFailure(directory.name, "Could not resolve directory path.")
                    traversalLimitReached = true
                    continue
                }
                if (!canonical.path.startsWith(rootCanonical.path + File.separator) &&
                    canonical.path != rootCanonical.path
                ) {
                    failures += FolderScanFailure(directory.name, "A path outside the selected storage root was skipped.")
                    traversalLimitReached = true
                    continue
                }
                if (!visited.add(canonical.path)) continue
                if (isProtectedDirectory(rootCanonical, canonical)) continue
                var listingFailure: String? = null
                val children = try {
                    canonical.listFiles()
                } catch (_: SecurityException) {
                    listingFailure = "Access denied by Android."
                    null
                }
                if (children == null) {
                    failures += FolderScanFailure(
                        canonical.name,
                        listingFailure ?: "Android did not return a directory listing."
                    )
                    traversalLimitReached = true
                    continue
                }
                children.forEach { child ->
                    if (candidates.size >= maxFiles) return@forEach
                    if (child.isDirectory) {
                        if (!isProtectedDirectory(rootCanonical, child)) {
                            if (queue.size < ScanLimits.MAX_PENDING_DIRECTORIES) {
                                queue.add(child to depth + 1)
                            } else {
                                failures += FolderScanFailure(
                                    child.name,
                                    "Pending-directory safety limit reached; this part of the tree was not enumerated."
                                )
                                traversalLimitReached = true
                            }
                        }
                    } else {
                        addCandidate(child, rootCanonical)
                    }
                }
            }
            if (candidates.size >= maxFiles) {
                traversalLimitReached = true
                failures += FolderScanFailure(
                    "Scan limit",
                    "The $maxFiles-file device scan safety limit was reached; additional paths may remain."
                )
            }
        }

        // Keep a bounded result preview, but prefer actual detections over early clean/unknown files.
        val findingItems = mutableListOf<FolderScanItem>()
        val previewItems = mutableListOf<FolderScanItem>()
        var skipped = discoverySkipped
        var totalBytes = 0L
        var scannedCount = 0
        var suspiciousCount = 0
        var unknownCount = 0
        var matchedCount = 0
        val coverage = ScanCoverageAccumulator()
        val list = candidates.values.toList()
        val discoveredFiles = list.size + discoverySkipped
        val totalByteLimit = if (deep) DEEP_TOTAL_BYTES else QUICK_TOTAL_BYTES
        var budgetExhausted = false

        for ((index, file) in list.withIndex()) {
            currentCoroutineContext().ensureActive()
            val declaredSize = file.length()

            if (budgetExhausted) {
                skipped++
            } else if (declaredSize > ScanEngine.MAX_FILE_SIZE_BYTES) {
                skipped++
                failures += FolderScanFailure(file.name, "File exceeds the 200 MB per-file analysis limit.")
            } else if (declaredSize > 0 && declaredSize > totalByteLimit - totalBytes) {
                skipped++
                failures += FolderScanFailure(
                    file.name,
                    if (deep) "The 25 GB deep-scan data budget was reached; this file was recorded as not scanned."
                    else "The 25 GB quick-scan data budget was reached; this file was recorded as not scanned."
                )
                if (totalBytes >= totalByteLimit) budgetExhausted = true
            } else {
                try {
                    val result = ScanEngine.scan(context.applicationContext, Uri.fromFile(file))
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
                    val reportItem = FolderScanItem(Uri.fromFile(file), result)
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
                } catch (cancelled: kotlinx.coroutines.CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    skipped++
                    failures += FolderScanFailure(file.name, error.message ?: "File scan failed.")
                }
            }

            // Discovery-time skips were already accounted for. Do not show 100%
            // until the final directory traversal status is known.
            val accountedSoFar = discoverySkipped + index + 1
            if (index == 0 || (index + 1) % 5 == 0 || index == list.lastIndex) {
                val liveCurrent = if (discoveredFiles > 0) {
                    accountedSoFar.coerceAtMost(discoveredFiles - 1)
                } else 0
                withContext(Dispatchers.Main.immediate) {
                    onProgress(liveCurrent, discoveredFiles, file.name)
                }
            }

            if (totalBytes >= totalByteLimit && index < list.lastIndex) {
                val remaining = list.size - index - 1
                skipped += remaining
                failures += FolderScanFailure(
                    "Remaining files",
                    if (deep) "The remaining $remaining file(s) were recorded as not scanned after the 25 GB deep-scan data budget."
                    else "The remaining $remaining file(s) were recorded as not scanned after the 25 GB quick-scan data budget."
                )
                break
            }
        }

        // A per-file or aggregate analysis limit is disclosed as not-scanned data,
        // not mistaken for a missing directory listing. Traversal gaps are different.
        val truncated = traversalLimitReached || candidates.size >= maxFiles
        val report = FolderScanReport(
            items = if (findingItems.isNotEmpty()) findingItems else previewItems,
            failures = failures,
            discoveredFiles = discoveredFiles,
            skippedFiles = skipped,
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
                if (report.fullScanCoverage) "Accessible scan scope completed"
                else "Accessible scan scope is incomplete; see skipped-path details"
            )
        }
        report
    }

    private fun findStorageRoots(context: Context): List<File> {
        val roots = linkedMapOf<String, File>()
        val candidates = mutableListOf<File>()
        candidates += Environment.getExternalStorageDirectory()
        context.getExternalFilesDirs(null).filterNotNull().forEach { appFiles ->
            val path = appFiles.absolutePath
            val marker = path.indexOf("/Android/data/")
            if (marker > 0) candidates += File(path.substring(0, marker))
        }
        candidates.forEach { candidate ->
            val root = runCatching { candidate.canonicalFile }.getOrNull() ?: return@forEach
            if (root.isDirectory && root.canRead()) roots[root.path] = root
        }
        return roots.values.toList()
    }

    private fun isProtectedDirectory(root: File, directory: File): Boolean {
        val relative = runCatching {
            directory.canonicalPath.removePrefix(root.canonicalPath).trimStart(File.separatorChar)
        }.getOrDefault("")
        val parts = relative.split(File.separatorChar)
        return parts.size >= 2 && parts[0].equals("Android", true) &&
            (parts[1].equals("data", true) || parts[1].equals("obb", true))
    }

    private data class PackageDiscoveryResult(
        val skippedComponents: Int,
        val incomplete: Boolean
    )

    private fun addInstalledApplicationPackages(
        context: Context,
        output: LinkedHashMap<String, File>,
        failures: MutableList<FolderScanFailure>,
        maxFiles: Int
    ): PackageDiscoveryResult {
        // QUERY_ALL_PACKAGES visibility is a sensitive inventory. Do not query
        // installed applications until the user has separately consented in-app.
        if (!com.antivirusalai.InstalledAppInventoryConsent.isGranted(context)) {
            failures += FolderScanFailure(
                "Installed app inventory",
                "Installed-app inspection was skipped because the user has not granted in-app consent. Shared-storage scanning may continue independently."
            )
            // Without explicit app-inventory consent, installed APKs are outside
            // the authorized scan scope; shared-storage scanning may still finish.
            return PackageDiscoveryResult(skippedComponents = 0, incomplete = false)
        }

        val pm = context.packageManager
        val apps = try {
            if (Build.VERSION.SDK_INT >= 33) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
        } catch (error: Exception) {
            failures += FolderScanFailure("Installed apps", error.message ?: "App inventory unavailable.")
            return PackageDiscoveryResult(skippedComponents = 1, incomplete = true)
        }

        var skippedComponents = 0
        for (app in apps) {
            // Consent may be revoked while a large package inventory is being
            // enumerated. Stop before reading the next package's metadata.
            if (!com.antivirusalai.InstalledAppInventoryConsent.isGranted(context)) {
                failures += FolderScanFailure(
                    "Installed app inventory",
                    "Installed-app inspection was stopped because the user revoked consent during the scan."
                )
                skippedComponents++
                break
            }
            if (output.size >= maxFiles) break

            // Keep null base paths visible as an unverified component rather than
            // dropping them with listOfNotNull(). Each split must be accounted for.
            val componentPaths: List<String?> =
                listOf(app.sourceDir) + app.splitSourceDirs.orEmpty().map { it }
            val collected = InstalledPackageArchiveCollector.collect(
                componentPaths,
                output,
                maxFiles
            )
            skippedComponents += collected.skippedComponents
            if (collected.skippedComponents > 0) {
                failures += FolderScanFailure(
                    app.packageName,
                    "${collected.skippedComponents} installed APK component(s) could not be read or resolved; the package is not fully verified."
                )
            }
        }
        return PackageDiscoveryResult(
            skippedComponents = skippedComponents,
            incomplete = skippedComponents > 0
        )
    }
}
