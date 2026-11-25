package com.antivirusalai.engine

/**
 * A negative result is permitted only when every required detection layer has
 * completed against current, authenticated, non-truncated intelligence.
 * This is a "no known indicator" result, not a guarantee that a file is safe.
 */
internal data class ScanVerdictReadiness(
    val threatFeedAvailable: Boolean,
    val threatFeedFresh: Boolean,
    val threatFeedNotTruncated: Boolean,
    val signedContentRulesAvailable: Boolean,
    val nativeContentEngineComplete: Boolean,
    val staticAnalysisSupported: Boolean,
    val staticAnalysisComplete: Boolean,
    val requiredStagesCompleted: Boolean,
    val noKnownThreatMatches: Boolean
)

internal object ScanVerdictPolicy {
    fun canDeclareNoKnownIndicator(readiness: ScanVerdictReadiness): Boolean =
        readiness.threatFeedAvailable &&
            readiness.threatFeedFresh &&
            readiness.threatFeedNotTruncated &&
            readiness.signedContentRulesAvailable &&
            readiness.nativeContentEngineComplete &&
            readiness.staticAnalysisSupported &&
            readiness.staticAnalysisComplete &&
            readiness.requiredStagesCompleted &&
            readiness.noKnownThreatMatches
}
