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
            failures = emptyList(),
            discoveredFiles = 10,
            skippedFiles = 3,
            truncated = false,
            scannedCountOverride = 7
        )

        assertEquals(7, report.scannedCount)
        assertEquals(70, report.scanCoveragePercent)
        assertEquals(0, report.unaccountedFiles)
        assertTrue(report.allDiscoveredFilesAccounted)
        assertFalse(report.fullScanCoverage)
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
        assertEquals(4, report.unaccountedFiles)
        assertFalse(report.allDiscoveredFilesAccounted)
        assertFalse(report.fullScanCoverage)
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
        assertTrue(empty.fullScanCoverage)
        assertEquals(0, unavailable.scanCoveragePercent)
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
