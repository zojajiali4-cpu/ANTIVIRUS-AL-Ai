package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class FolderScanSummaryTest {
    @Test
    fun verdictsAreGroupedWithoutCallingUnknownFilesClean() {
        val summary = FolderScanSummary.fromVerdicts(
            listOf(
                ScanVerdict.KNOWN_MALWARE,
                ScanVerdict.SUSPICIOUS,
                ScanVerdict.UNSUPPORTED_FILE,
                ScanVerdict.UNKNOWN_APK,
                ScanVerdict.NO_KNOWN_INDICATOR,
                ScanVerdict.TEST_MARKER_MATCH
            )
        )
        assertEquals(6, summary.scanned)
        assertEquals(2, summary.threats)
        assertEquals(2, summary.unknown)
        assertEquals(1, summary.noKnownIndicator)
        assertEquals(1, summary.testMatches)
    }

    @Test
    fun emptyBatchHasZeroCounts() {
        assertEquals(FolderScanSummary(0, 0, 0, 0, 0), FolderScanSummary.fromVerdicts(emptyList()))
    }
}
