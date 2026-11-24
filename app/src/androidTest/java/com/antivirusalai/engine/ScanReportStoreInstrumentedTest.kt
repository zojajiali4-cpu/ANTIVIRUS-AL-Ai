package com.antivirusalai.engine

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ScanReportStoreInstrumentedTest {
    @Test
    fun roundTripPreservesStructuredEngineAndAiFields() {
        val original = ScanResult(
            displayName = "sample.apk",
            mimeType = "application/vnd.android.package-archive",
            sizeBytes = 123_456L,
            sha256 = "a".repeat(64),
            verdict = ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE,
            evidence = listOf(
                ScanEvidence("STATIC_ANALYSIS_INCOMPLETE", "Static analysis incomplete", "Coverage was partial.", EvidenceSeverity.INFO)
            ),
            apkMetadata = null,
            durationMillis = 987L,
            contentEngineState = ContentEngineState.COMPLETE,
            contentRuleSetId = "ruleset-test-v4",
            contentRuleMatches = listOf("rule.alpha", "rule.beta"),
            contentEngineErrorCode = null,
            contentRuleBundleVersion = 12L,
            staticAnalysis = StaticAnalysisSummary(
                format = "APK",
                supported = true,
                complete = false,
                entryCount = 42,
                expandedBytes = 8192L,
                signalCategories = setOf("ARCHIVE_ANOMALY", "DEX_CAPABILITY")
            ),
            mlModelState = MlModelState.NOT_CONFIGURED,
            mlFeatureCount = 37,
            mlRiskScore = null,
            mlModelVersion = null,
            mlTopFeatures = listOf("permission_count", "dex_network_api"),
            behavioralAnalysisState = BehavioralAnalysisState.STATIC_INDICATORS_ONLY,
            unknownFileCase = UnknownFileCase(
                sha256 = "a".repeat(64),
                sizeBytes = 123_456L,
                mimeType = "application/vnd.android.package-archive",
                detectedFormat = "APK",
                verdict = ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE,
                analysisComplete = false,
                evidenceCodes = listOf("STATIC_ANALYSIS_INCOMPLETE", "THREAT_FEED_UNAVAILABLE"),
                createdAtMillis = 1_800_000_000_000L
            )
        )

        val restored = ScanReportStore.decodeResult(ScanReportStore.encodeResult(original))
        assertNotNull(restored)
        restored ?: return

        assertEquals(original.contentEngineState, restored.contentEngineState)
        assertEquals(original.contentRuleSetId, restored.contentRuleSetId)
        assertEquals(original.contentRuleMatches, restored.contentRuleMatches)
        assertEquals(original.contentRuleBundleVersion, restored.contentRuleBundleVersion)
        assertEquals(original.staticAnalysis, restored.staticAnalysis)
        assertEquals(original.mlModelState, restored.mlModelState)
        assertEquals(original.mlFeatureCount, restored.mlFeatureCount)
        assertEquals(original.mlRiskScore, restored.mlRiskScore)
        assertEquals(original.mlModelVersion, restored.mlModelVersion)
        assertEquals(original.mlTopFeatures, restored.mlTopFeatures)
        assertEquals(original.behavioralAnalysisState, restored.behavioralAnalysisState)
        assertEquals(original.unknownFileCase, restored.unknownFileCase)
        assertEquals(original.evidence, restored.evidence)
    }

    @Test
    fun legacyReportsLoadWithSafeDefaultsForNewFields() {
        val legacy = JSONObject()
            .put("displayName", "old.apk")
            .put("mimeType", JSONObject.NULL)
            .put("sizeBytes", 10L)
            .put("sha256", "b".repeat(64))
            .put("verdict", ScanVerdict.UNSUPPORTED_FILE.name)
            .put("evidence", JSONArray())
            .put("apkMetadata", JSONObject.NULL)
            .put("durationMillis", 10L)

        val restored = ScanReportStore.decodeResult(legacy)
        assertNotNull(restored)
        restored ?: return

        assertEquals(ContentEngineState.UNAVAILABLE, restored.contentEngineState)
        assertEquals(MlModelState.NOT_CONFIGURED, restored.mlModelState)
        assertEquals(BehavioralAnalysisState.NOT_APPLICABLE, restored.behavioralAnalysisState)
        assertEquals(emptyList<String>(), restored.contentRuleMatches)
        assertEquals(emptyList<String>(), restored.mlTopFeatures)
        assertNull(restored.staticAnalysis)
        assertNull(restored.unknownFileCase)
    }
    @Test
    fun scanReportRoundTripPreservesAggregateCoverageMatrix() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ScanReportStore.clear(context)
        val expected = listOf(
            ScanCoverageCell("APK", ScanVerdict.KNOWN_MALWARE, 2),
            ScanCoverageCell("application/pdf", ScanVerdict.UNSUPPORTED_FILE, 1)
        )
        val report = FolderScanReport(
            items = emptyList(),
            failures = emptyList(),
            discoveredFiles = 3,
            skippedFiles = 0,
            truncated = false,
            scannedCountOverride = 3,
            coverageMatrix = expected
        )

        ScanReportStore.save(context, deep = true, report = report)
        val restored = ScanReportStore.load(context)

        assertNotNull(restored)
        assertEquals(expected, restored!!.report.coverageMatrix)
        ScanReportStore.clear(context)
    }
}
