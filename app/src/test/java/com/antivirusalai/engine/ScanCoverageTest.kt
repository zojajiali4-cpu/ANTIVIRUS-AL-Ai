package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanCoverageTest {
    private fun result(
        format: String?,
        mimeType: String?,
        verdict: ScanVerdict
    ) = ScanResult(
        displayName = "sample.bin",
        mimeType = mimeType,
        sizeBytes = 1L,
        sha256 = "a".repeat(64),
        verdict = verdict,
        evidence = emptyList(),
        apkMetadata = null,
        durationMillis = 1L,
        staticAnalysis = format?.let {
            StaticAnalysisSummary(it, true, true, 0, 0L, emptySet())
        }
    )

    @Test
    fun separatesScannedCoverageFromExplicitlyAccountedFiles() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = listOf(
                FolderScanFailure("large.bin", "File exceeds the analysis limit."),
                FolderScanFailure("locked.bin", "Access denied.")
            ),
            discoveredFiles = 10,
            skippedFiles = 3,
            truncated = false,
            scannedCountOverride = 7
        )

        assertEquals(7, report.scannedCount)
        assertEquals(3, report.skippedFiles)
        assertEquals(70, report.scanCoveragePercent)
        assertEquals(100, report.completionPercent)
        assertEquals(0, report.unaccountedFiles)
        assertTrue(report.allDiscoveredFilesAccounted)
        assertTrue(report.fullScanCoverage)
    }

    @Test
    fun exposesAnyCandidateWithoutATerminalDisposition() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = emptyList(),
            discoveredFiles = 10,
            skippedFiles = 2,
            truncated = true,
            scannedCountOverride = 4
        )

        assertEquals(40, report.scanCoveragePercent)
        assertEquals(60, report.completionPercent)
        assertEquals(4, report.unaccountedFiles)
        assertFalse(report.allDiscoveredFilesAccounted)
        assertFalse(report.fullScanCoverage)
    }

    @Test
    fun traversalGapNeverReportsFullScopeCompletionEvenWhenListedFilesWereAccounted() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = listOf(FolderScanFailure("Download", "Directory listing was blocked")),
            discoveredFiles = 10,
            skippedFiles = 0,
            truncated = true,
            scannedCountOverride = 10
        )

        assertEquals(100, report.scanCoveragePercent)
        assertEquals(99, report.completionPercent)
        assertFalse(report.fullScanCoverage)
    }

    @Test
    fun knownMalwareCountUsesAllAggregatedResultsInsteadOfTheVisiblePreview() {
        val report = FolderScanReport(
            items = emptyList(),
            failures = emptyList(),
            discoveredFiles = 4,
            skippedFiles = 0,
            truncated = false,
            scannedCountOverride = 4,
            coverageMatrix = listOf(
                ScanCoverageCell("APK", ScanVerdict.KNOWN_MALWARE, 2),
                ScanCoverageCell("ZIP", ScanVerdict.NO_KNOWN_INDICATOR, 2)
            )
        )

        assertEquals(2, report.knownMalwareCount)
    }

    @Test
    fun emptySuccessfulScopeHasFullCoverageButUnavailableScopeDoesNot() {
        val empty = FolderScanReport(emptyList(), emptyList(), 0, 0, false)
        val unavailable = FolderScanReport(
            emptyList(),
            listOf(FolderScanFailure("Shared storage", "Permission not granted")),
            0,
            0,
            true
        )

        assertEquals(100, empty.scanCoveragePercent)
        assertEquals(100, empty.completionPercent)
        assertTrue(empty.fullScanCoverage)
        assertEquals(0, unavailable.scanCoveragePercent)
        assertEquals(0, unavailable.completionPercent)
        assertFalse(unavailable.fullScanCoverage)
    }
    @Test
    fun aggregatesEveryScannedResultByNormalizedFormatAndVerdict() {
        val accumulator = ScanCoverageAccumulator()
        accumulator.record(result("apk", "application/vnd.android.package-archive", ScanVerdict.KNOWN_MALWARE))
        accumulator.record(result("APK", "application/vnd.android.package-archive", ScanVerdict.KNOWN_MALWARE))
        accumulator.record(result("ZIP", "application/zip", ScanVerdict.NO_KNOWN_INDICATOR))

        val matrix = accumulator.snapshot()
        assertEquals(
            listOf(
                ScanCoverageCell("APK", ScanVerdict.KNOWN_MALWARE, 2),
                ScanCoverageCell("ZIP", ScanVerdict.NO_KNOWN_INDICATOR, 1)
            ),
            matrix
        )
        assertEquals(3, matrix.sumOf { it.count })
    }

    @Test
    fun usesMimeFallbackUnknownBucketAndBoundedFormatCardinality() {
        val accumulator = ScanCoverageAccumulator()
        accumulator.record(result(null, "application/pdf; charset=binary", ScanVerdict.UNSUPPORTED_FILE))
        accumulator.record(result(null, null, ScanVerdict.UNKNOWN_APK))
        repeat(40) { index ->
            accumulator.record(result(null, "application/x-sample-$index", ScanVerdict.NO_KNOWN_INDICATOR))
        }

        val matrix = accumulator.snapshot()
        assertTrue(matrix.any { it.format == "application/pdf" && it.verdict == ScanVerdict.UNSUPPORTED_FILE })
        assertTrue(matrix.any { it.format == "UNKNOWN" && it.verdict == ScanVerdict.UNKNOWN_APK })
        assertTrue(matrix.any { it.format == "OTHER" && it.count > 0 })
        assertTrue(matrix.size <= ScanCoverageAccumulator.MAX_CELLS)
    }
}
