package com.antivirusalai.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanVerdictPolicyTest {
    private val fullyCovered = ScanVerdictReadiness(
        threatFeedAvailable = true,
        threatFeedFresh = true,
        threatFeedNotTruncated = true,
        signedContentRulesAvailable = true,
        nativeContentEngineComplete = true,
        staticAnalysisSupported = true,
        staticAnalysisComplete = true,
        requiredStagesCompleted = true,
        noKnownThreatMatches = true
    )

    @Test
    fun permitsNoKnownIndicatorOnlyWhenEveryRequiredLayerIsComplete() {
        assertTrue(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered))
    }

    @Test
    fun unavailableOrStaleOrTruncatedThreatFeedNeverProducesNegativeVerdict() {
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(threatFeedAvailable = false)))
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(threatFeedFresh = false)))
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(threatFeedNotTruncated = false)))
    }

    @Test
    fun missingRulesOrIncompleteEnginesNeverProducesNegativeVerdict() {
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(signedContentRulesAvailable = false)))
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(nativeContentEngineComplete = false)))
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(staticAnalysisSupported = false)))
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(staticAnalysisComplete = false)))
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(requiredStagesCompleted = false)))
    }

    @Test
    fun anyKnownOrPartialThreatSignalBlocksNegativeVerdict() {
        assertFalse(ScanVerdictPolicy.canDeclareNoKnownIndicator(fullyCovered.copy(noKnownThreatMatches = false)))
    }
}
