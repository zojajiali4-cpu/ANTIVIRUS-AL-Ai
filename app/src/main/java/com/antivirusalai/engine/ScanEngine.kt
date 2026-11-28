package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.antivirusalai.intel.ContentRuleBundleRuntime
import com.antivirusalai.intel.ContentRuleBundleState
import com.antivirusalai.intel.ThreatClassification
import com.antivirusalai.intel.ThreatFeedFreshness
import com.antivirusalai.intel.ThreatFeedRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

data class ScanBatchContext internal constructor(
    val contentBundle: com.antivirusalai.intel.SignedContentRuleBundle?,
    val contentRuleState: ContentRuleBundleState,
    val threatFeed: com.antivirusalai.intel.SignedThreatFeed?,
    val threatFeedStatus: com.antivirusalai.intel.ThreatFeedStatus
)

class ScanTooLargeException(message: String) : Exception(message)

object ScanEngine {
    const val MAX_FILE_SIZE_BYTES = 200L * 1024L * 1024L

    /** Capture one verified intelligence snapshot for an entire multi-file run. */
    fun prepareBatchContext(context: Context): ScanBatchContext {
        val appContext = context.applicationContext
        val bundle = runCatching { ContentRuleBundleRuntime.current(appContext) }.getOrNull()
        val ruleState = if (bundle != null) ContentRuleBundleState.CURRENT
        else runCatching { ContentRuleBundleRuntime.state(appContext) }.getOrDefault(ContentRuleBundleState.INVALID)
        val feed = runCatching { ThreatFeedRuntime.currentFeed(appContext) }.getOrNull()
        val feedStatus = runCatching { ThreatFeedRuntime.status(appContext) }.getOrElse {
            com.antivirusalai.intel.ThreatFeedStatus(ThreatFeedFreshness.UNAVAILABLE, "STATUS_READ_FAILED")
        }
        return ScanBatchContext(bundle, ruleState, feed, feedStatus)
    }

    suspend fun scan(
        context: Context,
        uri: Uri,
        persistUnknownCase: Boolean = true,
        batchContext: ScanBatchContext? = null
    ): ScanResult = withContext(Dispatchers.IO) {
        val resolver = context.contentResolver
        val localFile = if (uri.scheme == "file") uri.path?.let(::File) else null
        val metadata = if (localFile != null) {
            localFile.name to localFile.length()
        } else {
            resolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null
            )?.use { cursor ->
                if (!cursor.moveToFirst()) null else {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    val name = if (nameIndex >= 0) cursor.getString(nameIndex) else null
                    val size = if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) cursor.getLong(sizeIndex) else -1L
                    name to size
                }
            }
        }

        val displayName = metadata?.first?.takeIf { it.isNotBlank() } ?: "Selected file"
        val declaredSize = metadata?.second ?: -1L
        if (declaredSize > MAX_FILE_SIZE_BYTES) {
            throw ScanTooLargeException("File exceeds the 200 MB MVP scan limit.")
        }

        val mimeType = resolver.getType(uri)
        val captureByMetadata = listOf(".apk", ".zip", ".jar", ".aab", ".apks", ".xapk", ".dex", ".so", ".elf")
            .any { displayName.endsWith(it, ignoreCase = true) } ||
            mimeType == "application/vnd.android.package-archive"
        var temp: File? = null
        var tempSink: FileOutputStream? = null
        val headerPrefix = ByteArray(4)
        var headerPrefixSize = 0
        var headerDecisionMade = captureByMetadata
        val eicarMatcher = EicarTestDetector.StreamingMatcher()
        val digest = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L
        val startedAt = System.nanoTime()
        val preparedContentBundle = if (batchContext == null) null else {
            batchContext.contentBundle?.takeIf { it.expiresAtEpochSeconds > System.currentTimeMillis() / 1000L }
        }
        val effectiveContentRuleState = if (
            batchContext != null && batchContext.contentBundle != null && preparedContentBundle == null
        ) ContentRuleBundleState.EXPIRED else batchContext?.contentRuleState
        val contentBundleStage = if (batchContext == null) {
            ScanStageRunner.execute("CONTENT_RULE_BUNDLE") {
                ContentRuleBundleRuntime.current(context.applicationContext)
            }
        } else {
            ScanStageExecution("CONTENT_RULE_BUNDLE", ScanStageState.COMPLETED, preparedContentBundle)
        }
        val contentBundle = contentBundleStage.value
        val nativeInitStage = ScanStageRunner.execute("NATIVE_ENGINE_INIT") {
            NativeContentEngine.openSession(contentBundle?.rules.orEmpty())
        }
        var nativeSession = nativeInitStage.value
        var contentEngineState = if (nativeSession == null) ContentEngineState.UNAVAILABLE else ContentEngineState.INCOMPLETE
        var contentEngineErrorCode: String? =
            if (nativeSession == null) "NATIVE_LIBRARY_UNAVAILABLE" else null
        var nativeMatches = emptySet<String>()

        try {
            if (captureByMetadata) {
                temp = File.createTempFile("alai-scan-", ".bin", context.cacheDir)
                tempSink = FileOutputStream(temp!!)
            }
            val input = resolver.openInputStream(uri)
                ?: throw IllegalStateException("Android could not open the selected file.")
            input.use { source ->
                // The native scanner accepts chunks up to 64 KiB. Matching that
                // boundary reduces read/JNI calls without exceeding its contract.
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    currentCoroutineContext().ensureActive()
                    val count = source.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    totalBytes += count
                    if (totalBytes > MAX_FILE_SIZE_BYTES) {
                        throw ScanTooLargeException("File exceeds the 200 MB MVP scan limit.")
                    }
                    digest.update(buffer, 0, count)
                    eicarMatcher.update(buffer, 0, count)
                    if (nativeSession != null && contentEngineErrorCode == null) {
                        try {
                            nativeSession?.update(buffer, count)
                        } catch (_: Exception) {
                            runCatching { nativeSession?.close() }
                            nativeSession = null
                            contentEngineState = ContentEngineState.INCOMPLETE
                            contentEngineErrorCode = "NATIVE_UPDATE_FAILED"
                        } catch (_: LinkageError) {
                            runCatching { nativeSession?.close() }
                            nativeSession = null
                            contentEngineState = ContentEngineState.INCOMPLETE
                            contentEngineErrorCode = "NATIVE_LINKAGE_FAILED"
                        }
                    }

                    val sink = tempSink
                    if (sink != null) {
                        sink.write(buffer, 0, count)
                    } else if (!headerDecisionMade) {
                        val prefixBytesFromChunk = minOf(4 - headerPrefixSize, count)
                        System.arraycopy(buffer, 0, headerPrefix, headerPrefixSize, prefixBytesFromChunk)
                        headerPrefixSize += prefixBytesFromChunk
                        if (headerPrefixSize == headerPrefix.size) {
                            headerDecisionMade = true
                            val zipContainer = headerPrefix[0] == 'P'.code.toByte() &&
                                headerPrefix[1] == 'K'.code.toByte()
                            val elfBinary = headerPrefix[0] == 0x7f.toByte() &&
                                headerPrefix[1] == 'E'.code.toByte() &&
                                headerPrefix[2] == 'L'.code.toByte() &&
                                headerPrefix[3] == 'F'.code.toByte()
                            if (zipContainer || elfBinary) {
                                temp = File.createTempFile("alai-scan-", ".bin", context.cacheDir)
                                tempSink = FileOutputStream(temp!!)
                                tempSink!!.write(headerPrefix)
                                if (count > prefixBytesFromChunk) {
                                    tempSink!!.write(
                                        buffer,
                                        prefixBytesFromChunk,
                                        count - prefixBytesFromChunk
                                    )
                                }
                            }
                        }
                    }
                }
            }
            tempSink?.close()
            tempSink = null

            if (nativeSession != null && contentEngineErrorCode == null) {
                try {
                    nativeMatches = nativeSession!!.finish()
                    contentEngineState = ContentEngineState.COMPLETE
                } catch (_: Exception) {
                    contentEngineState = ContentEngineState.INCOMPLETE
                    contentEngineErrorCode = "NATIVE_FINISH_FAILED"
                } catch (_: LinkageError) {
                    contentEngineState = ContentEngineState.INCOMPLETE
                    contentEngineErrorCode = "NATIVE_LINKAGE_FAILED"
                }
            }

            val hash = Sha256.hex(digest.digest())
            val evidence = mutableListOf<ScanEvidence>()
            ScanStageRunner.failureEvidence(contentBundleStage)?.let(evidence::add)
            ScanStageRunner.failureEvidence(nativeInitStage)?.let(evidence::add)
            if (contentEngineState != ContentEngineState.COMPLETE) {
                evidence += ScanEvidence(
                    "NATIVE_CONTENT_ENGINE_INCOMPLETE",
                    "Native content analysis is unavailable or incomplete",
                    "The local C++ signature matcher did not complete. Its result is not used as evidence of a clean file.",
                    EvidenceSeverity.INFO
                )
            }
            if (contentBundle == null) {
                val stateStage = if (batchContext == null) {
                    ScanStageRunner.execute("CONTENT_RULE_BUNDLE_STATE") {
                        ContentRuleBundleRuntime.state(context.applicationContext)
                    }
                } else {
                    ScanStageExecution(
                        "CONTENT_RULE_BUNDLE_STATE",
                        ScanStageState.COMPLETED,
                        effectiveContentRuleState ?: ContentRuleBundleState.INVALID
                    )
                }
                ScanStageRunner.failureEvidence(stateStage)?.let(evidence::add)
                val state = stateStage.value ?: ContentRuleBundleState.INVALID
                evidence += ScanEvidence(
                    "SIGNED_CONTENT_RULES_${state.name}",
                    "Production content rules are not currently available",
                    when (state) {
                        ContentRuleBundleState.MISSING -> "No signed offline content-rule bundle is installed. Only built-in harmless self-tests are active."
                        ContentRuleBundleState.EXPIRED -> "The installed signed content-rule bundle has expired and is not used."
                        ContentRuleBundleState.INVALID -> "The installed content-rule bundle failed validation and is not used."
                        ContentRuleBundleState.CURRENT -> "A current bundle was reported, but could not be loaded for this scan."
                    },
                    EvidenceSeverity.INFO
                )
            }

            val selfTestMatch = NativeContentEngine.SELF_TEST_RULE_ID in nativeMatches
            val allContentRules = contentBundle?.rules.orEmpty()
            val qualifiedRulesStage = ScanStageRunner.execute("CONTENT_RULE_GROUPING") {
                ContentRuleGroupEvaluator.qualifiedMatches(allContentRules, nativeMatches)
            }
            ScanStageRunner.failureEvidence(qualifiedRulesStage)?.let(evidence::add)
            val matchedContentRules = qualifiedRulesStage.value.orEmpty()
            val partialRulesStage = ScanStageRunner.execute("CONTENT_RULE_PARTIAL_MATCHES") {
                ContentRuleGroupEvaluator.partialMatches(allContentRules, nativeMatches)
            }
            ScanStageRunner.failureEvidence(partialRulesStage)?.let(evidence::add)
            partialRulesStage.value.orEmpty().forEach { partial ->
                evidence += ScanEvidence(
                    "CONTENT_RULE_GROUP_PARTIAL_${partial.groupId}",
                    "Partial match for ${partial.familyId}",
                    "${partial.matchedCount} of ${partial.requiredCount} indicators matched. The group threshold was not reached, so this is informational only and does not affect the verdict.",
                    EvidenceSeverity.LOW
                )
            }
            matchedContentRules.forEach { rule ->
                evidence += ScanEvidence(
                    "CONTENT_SIGNATURE_${rule.id}",
                    "Content signature matched: ${rule.familyId}",
                    rule.description + " Confidence: ${rule.confidence}%. Source: ${rule.sourceId}. License: ${rule.licenseId}.",
                    when {
                        rule.classification == ThreatClassification.MALWARE && rule.confidence >= 90 -> EvidenceSeverity.HIGH
                        else -> EvidenceSeverity.MEDIUM
                    }
                )
            }
            if (selfTestMatch) {
                evidence += ScanEvidence(
                    "NATIVE_ENGINE_SELF_TEST_MARKER",
                    "Harmless native-engine self-test marker matched",
                    "The C++ matcher recognized its dedicated harmless integration fixture. This is not a malware detection.",
                    EvidenceSeverity.INFO
                )
            }

            val localReputationStage = ScanStageRunner.execute("LOCAL_HASH_REPUTATION") {
                LocalIndicatorDatabase.lookup(hash)
            }
            ScanStageRunner.failureEvidence(localReputationStage)?.let(evidence::add)
            val localMatch = localReputationStage.value

            val eicarStage = ScanStageRunner.execute("EICAR_SELF_TEST") {
                eicarMatcher.found
            }
            ScanStageRunner.failureEvidence(eicarStage)?.let(evidence::add)
            val eicarMatch = eicarStage.value == true

            val preparedThreatFeed = if (batchContext == null) null else {
                batchContext.threatFeed?.takeIf { it.expiresAtEpochSeconds > System.currentTimeMillis() / 1000L }
            }
            val effectiveThreatFeedStatus = when {
                batchContext == null -> null
                batchContext.threatFeed != null && preparedThreatFeed == null ->
                    com.antivirusalai.intel.ThreatFeedStatus(ThreatFeedFreshness.STALE, "FEED_EXPIRED_DURING_SCAN")
                else -> batchContext.threatFeedStatus
            }
            val threatFeedStage = if (batchContext == null) {
                ScanStageRunner.execute("SIGNED_THREAT_FEED_READ") {
                    ThreatFeedRuntime.currentFeed(context.applicationContext)
                }
            } else {
                ScanStageExecution("SIGNED_THREAT_FEED_READ", ScanStageState.COMPLETED, preparedThreatFeed)
            }
            ScanStageRunner.failureEvidence(threatFeedStage)?.let(evidence::add)
            val currentThreatFeed = threatFeedStage.value
            val threatFeedStatusStage = if (batchContext == null) {
                ScanStageRunner.execute("SIGNED_THREAT_FEED_STATUS") {
                    ThreatFeedRuntime.status(context.applicationContext)
                }
            } else {
                ScanStageExecution("SIGNED_THREAT_FEED_STATUS", ScanStageState.COMPLETED, effectiveThreatFeedStatus)
            }
            ScanStageRunner.failureEvidence(threatFeedStatusStage)?.let(evidence::add)
            val threatFeedStatus = threatFeedStatusStage.value
                ?: com.antivirusalai.intel.ThreatFeedStatus(ThreatFeedFreshness.UNAVAILABLE, "STATUS_READ_FAILED")
            val threatMatch = currentThreatFeed?.indicators?.get(hash.lowercase())
            if (threatMatch != null) {
                val label = when (threatMatch.classification) {
                    ThreatClassification.MALWARE -> "Known malware"
                    ThreatClassification.PUA -> "Potentially unwanted file"
                    ThreatClassification.SUSPICIOUS -> "Suspicious file"
                }
                evidence += ScanEvidence(
                    "SIGNED_FEED_${threatMatch.classification.name}",
                    label,
                    "Exact SHA-256 match in the authenticated feed. Family: ${threatMatch.familyId}. Sources: ${threatMatch.sources.sorted().joinToString()}.",
                    when (threatMatch.classification) {
                        ThreatClassification.MALWARE -> EvidenceSeverity.HIGH
                        ThreatClassification.PUA, ThreatClassification.SUSPICIOUS -> EvidenceSeverity.MEDIUM
                    }
                )
            }
            if (currentThreatFeed?.truncated == true) {
                evidence += ScanEvidence(
                    "THREAT_FEED_TRUNCATED",
                    "Threat intelligence snapshot is capped",
                    "The signed feed reports that per-type indicator limits excluded some otherwise valid entries. A non-match is therefore not exhaustive.",
                    EvidenceSeverity.INFO
                )
            }
            if (threatFeedStatus.freshness != ThreatFeedFreshness.UP_TO_DATE) {
                val stale = threatFeedStatus.freshness == ThreatFeedFreshness.STALE
                evidence += ScanEvidence(
                    if (stale) "THREAT_FEED_STALE" else "THREAT_FEED_UNAVAILABLE",
                    "Current threat intelligence is not available",
                    if (stale) "The last authenticated threat feed has expired. A current feed no-match result is unavailable."
                    else "No valid current authenticated threat feed is available. A current feed no-match result is unavailable.",
                    EvidenceSeverity.INFO
                )
            }

            val looksLikeApk = temp?.let(ApkFileDetector::isApkArchive) == true ||
                displayName.endsWith(".apk", ignoreCase = true) ||
                mimeType == "application/vnd.android.package-archive"
            val apkStage = ScanStageRunner.execute("APK_METADATA_ANALYSIS") {
                if (looksLikeApk && temp != null) ApkMetadataInspector.inspect(context, temp!!) else null
            }
            ScanStageRunner.failureEvidence(apkStage)?.let(evidence::add)
            val apk = apkStage.value

            val staticStage = ScanStageRunner.execute("FORMAT_STATIC_ANALYSIS") {
                // Ordinary documents/media are inspected in the streaming pass.
                // Materialize only APK/ZIP/ELF-like inputs that need random-access
                // structural parsing; do not write and reread every file.
                temp?.let(FormatStaticAnalyzer::analyze) ?: StaticAnalysisReport(
                    format = null,
                    supported = false,
                    complete = true,
                    entryCount = 0,
                    expandedBytes = 0L,
                    evidence = emptyList(),
                    signalCategories = emptySet(),
                    riskPoints = 0
                )
            }
            ScanStageRunner.failureEvidence(staticStage)?.let(evidence::add)
            val staticReport = staticStage.value ?: StaticAnalysisReport(
                format = null,
                supported = false,
                complete = false,
                entryCount = 0,
                expandedBytes = 0L,
                evidence = emptyList(),
                signalCategories = setOf("ANALYZER_FAILURE"),
                riskPoints = 0
            )

            val permissionStage = ScanStageRunner.execute("APK_PERMISSION_ANALYSIS") {
                apk?.let(PermissionRiskAnalyzer::analyze)
            }
            ScanStageRunner.failureEvidence(permissionStage)?.let(evidence::add)
            val permissionAssessment = permissionStage.value

            val fusionStage = ScanStageRunner.execute("MULTI_SIGNAL_RISK_FUSION") {
                MultiSignalRiskScorer.assess(permissionAssessment, staticReport)
            }
            ScanStageRunner.failureEvidence(fusionStage)?.let(evidence::add)
            val combinedRisk = fusionStage.value ?: CombinedRiskAssessment(
                score = 0,
                suspicious = false,
                evidence = emptyList(),
                independentSignalGroups = emptySet()
            )
            evidence += combinedRisk.evidence

            if (!staticStage.completed) {
                evidence += ScanEvidence(
                    "STATIC_ANALYZER_FALLBACK_ONLY",
                    "Static parser failed; independent checks continued",
                    "The structured file parser failed. Hash reputation, the streaming content engine, and other independent checks still ran where available; structural coverage for this file is incomplete.",
                    EvidenceSeverity.INFO
                )
            }
            if (!staticReport.complete) {
                evidence += ScanEvidence(
                    "STATIC_ANALYSIS_INCOMPLETE",
                    "Static format analysis was incomplete",
                    "One or more archive, DEX, or native-code limits were reached. No clean conclusion is drawn.",
                    EvidenceSeverity.INFO
                )
            }
            if (!staticReport.supported) {
                evidence += ScanEvidence(
                    "FORMAT_NOT_SUPPORTED",
                    "File format is not structurally covered",
                    "No configured APK/ZIP/ELF structural parser recognized this format.",
                    EvidenceSeverity.INFO
                )
            }

            val mlFeatures = OnDeviceMlScorer.extractFeatures(
                apk = apk,
                static = staticReport,
                fileSizeBytes = totalBytes,
                contentEngineState = contentEngineState
            )
            // The trained model is currently scoped to structurally parsed APK files.
            // ZIP/ELF/unknown inputs are not silently interpreted as APKs.
            val mlStage = ScanStageRunner.execute("ON_DEVICE_MODEL_INFERENCE") {
                if (apk != null && staticReport.format == "APK") {
                    OnDeviceMlScorer.score(context.applicationContext, mlFeatures)
                } else {
                    MlScoringResult(MlModelState.NOT_APPLICABLE)
                }
            }
            ScanStageRunner.failureEvidence(mlStage)?.let(evidence::add)
            val mlResult = mlStage.value
                ?: MlScoringResult(MlModelState.ERROR, errorCode = "MODEL_STAGE_FAILED")
            val behavioralState = if (staticReport.supported) {
                BehavioralAnalysisState.STATIC_INDICATORS_ONLY
            } else {
                BehavioralAnalysisState.NOT_APPLICABLE
            }
            if (staticReport.supported) {
                evidence += ScanEvidence(
                    "DYNAMIC_BEHAVIORAL_SANDBOX_NOT_CONFIGURED",
                    "Dynamic behavioral sandbox was not run",
                    "This report contains static DEX/API and ELF symbol indicators only. The selected application was not executed, and other apps' private processes were not instrumented.",
                    EvidenceSeverity.INFO
                )
            }
            when (mlResult.state) {
                MlModelState.READY -> {
                    evidence += ScanEvidence(
                        "ON_DEVICE_AI_RISK_SCORE",
                        "AI multi-view risk score: ${mlResult.riskScore}/100",
                        "Model ${mlResult.modelVersion} produced a review-level risk index. Top contributing features: ${mlResult.topFeatures.joinToString()}. Threshold: ${((mlResult.threshold ?: 1f) * 100f).toInt()}/100. This score is not proof of malware.",
                        if (mlResult.highRisk) EvidenceSeverity.MEDIUM else EvidenceSeverity.INFO
                    )
                }
                MlModelState.NOT_CONFIGURED -> if (apk != null) {
                    evidence += ScanEvidence(
                        "ON_DEVICE_ML_MODEL_NOT_INSTALLED",
                        "Validated on-device AI model is not packaged",
                        "The feature pipeline is active, but no trained and independently evaluated model artifact is installed. AI does not affect this file's verdict.",
                        EvidenceSeverity.INFO
                    )
                }
                MlModelState.ERROR -> evidence += ScanEvidence(
                    "ON_DEVICE_ML_MODEL_INVALID",
                    "On-device AI model could not be loaded",
                    "The model artifact failed integrity or schema validation and was not used in the verdict. Code: ${mlResult.errorCode ?: "MODEL_ERROR"}.",
                    EvidenceSeverity.MEDIUM
                )
                MlModelState.NOT_APPLICABLE -> Unit
            }
            val topContentRule = matchedContentRules.maxByOrNull {
                when {
                    it.classification == ThreatClassification.MALWARE && it.confidence >= 90 -> 3
                    it.classification == ThreatClassification.PUA && it.confidence >= 70 -> 2
                    else -> 1
                }
            }
            val contentRuleVerdict = topContentRule?.let { rule ->
                when (rule.classification) {
                    ThreatClassification.MALWARE ->
                        if (rule.confidence >= 90) ScanVerdict.KNOWN_MALWARE else ScanVerdict.SUSPICIOUS
                    ThreatClassification.PUA ->
                        if (rule.confidence >= 70) ScanVerdict.POTENTIALLY_UNWANTED else ScanVerdict.SUSPICIOUS
                    ThreatClassification.SUSPICIOUS -> ScanVerdict.SUSPICIOUS
                }
            }

            val noKnownIndicatorReady = ScanVerdictPolicy.canDeclareNoKnownIndicator(
                ScanVerdictReadiness(
                    threatFeedAvailable = threatFeedStage.completed && currentThreatFeed != null,
                    threatFeedFresh = threatFeedStatusStage.completed &&
                        threatFeedStatus.freshness == ThreatFeedFreshness.UP_TO_DATE,
                    threatFeedNotTruncated = currentThreatFeed?.truncated != true,
                    signedContentRulesAvailable = contentBundleStage.completed && contentBundle != null,
                    nativeContentEngineComplete = nativeInitStage.completed &&
                        contentEngineState == ContentEngineState.COMPLETE,
                    staticAnalysisSupported = staticStage.completed && staticReport.supported,
                    staticAnalysisComplete = staticReport.complete,
                    requiredStagesCompleted = localReputationStage.completed &&
                        eicarStage.completed && apkStage.completed &&
                        permissionStage.completed && fusionStage.completed &&
                        qualifiedRulesStage.completed && partialRulesStage.completed &&
                        mlStage.completed && mlResult.state != MlModelState.ERROR,
                    noKnownThreatMatches = threatMatch == null && localMatch == null &&
                        !eicarMatch && !selfTestMatch && matchedContentRules.isEmpty() &&
                        partialRulesStage.value.isNullOrEmpty() && !mlResult.highRisk &&
                        !combinedRisk.suspicious
                )
            )

            val verdict = when {
                threatMatch?.classification == ThreatClassification.MALWARE -> ScanVerdict.KNOWN_MALWARE
                contentRuleVerdict == ScanVerdict.KNOWN_MALWARE -> ScanVerdict.KNOWN_MALWARE
                threatMatch?.classification == ThreatClassification.PUA ||
                    contentRuleVerdict == ScanVerdict.POTENTIALLY_UNWANTED -> ScanVerdict.POTENTIALLY_UNWANTED
                threatMatch?.classification == ThreatClassification.SUSPICIOUS ||
                    contentRuleVerdict == ScanVerdict.SUSPICIOUS -> ScanVerdict.SUSPICIOUS
                eicarMatch -> {
                    evidence += ScanEvidence(
                        "EICAR_TEST_FILE", "Harmless EICAR test string detected",
                        "The standard EICAR antivirus test string was detected. It is intentionally harmless and is used only to test scanner reporting.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.TEST_MARKER_MATCH
                }
                selfTestMatch -> ScanVerdict.TEST_MARKER_MATCH
                localMatch != null -> {
                    evidence += ScanEvidence(
                        "BENIGN_PROJECT_TEST_MARKER", "Benign project test marker matched",
                        "This is a harmless ANTIVIRUS AL AI test fixture. It is not malware.",
                        EvidenceSeverity.INFO
                    )
                    ScanVerdict.TEST_MARKER_MATCH
                }
                looksLikeApk && apk == null -> {
                    evidence += ScanEvidence(
                        "APK_PARSE_UNAVAILABLE", "APK metadata could not be parsed",
                        "The selected file looks like an APK, but Android's package parser could not read its metadata. The result is unknown, not clean.",
                        EvidenceSeverity.MEDIUM
                    )
                    ScanVerdict.UNKNOWN_APK
                }
                mlResult.highRisk -> ScanVerdict.SUSPICIOUS
                combinedRisk.suspicious -> ScanVerdict.SUSPICIOUS
                noKnownIndicatorReady -> ScanVerdict.NO_KNOWN_INDICATOR
                staticReport.supported || apk != null -> ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE
                else -> ScanVerdict.UNSUPPORTED_FILE
            }

            if (UnknownFileInvestigator.shouldInvestigate(verdict)) {
                evidence += ScanEvidence(
                    "UNKNOWN_FILE_INVESTIGATION_QUEUED",
                    "Unknown file added to local investigation queue",
                    "A privacy-minimal case was created from the SHA-256 and local analysis metadata. No file bytes, filename, or path were uploaded. Online hash lookup is not configured, so the result remains unknown.",
                    EvidenceSeverity.INFO
                )
            }
            val baseResult = ScanResult(
                displayName = displayName,
                mimeType = mimeType,
                sizeBytes = totalBytes,
                sha256 = hash,
                verdict = verdict,
                evidence = evidence.toList(),
                apkMetadata = apk,
                durationMillis = (System.nanoTime() - startedAt) / 1_000_000L,
                contentEngineState = contentEngineState,
                contentRuleSetId = contentBundle?.let { "signed-content-rules-v${it.version}" }
                    ?: NativeContentEngine.RULE_SET_ID,
                contentRuleMatches = matchedContentRules.map { it.id },
                contentEngineErrorCode = contentEngineErrorCode,
                contentRuleBundleVersion = contentBundle?.version,
                staticAnalysis = StaticAnalysisSummary(
                    staticReport.format,
                    staticReport.supported,
                    staticReport.complete,
                    staticReport.entryCount,
                    staticReport.expandedBytes,
                    staticReport.signalCategories
                ),
                mlModelState = mlResult.state,
                mlFeatureCount = mlFeatures.featureCount,
                mlRiskScore = mlResult.riskScore,
                mlModelVersion = mlResult.modelVersion,
                mlTopFeatures = mlResult.topFeatures,
                behavioralAnalysisState = behavioralState
            )
            val unknownCase = UnknownFileInvestigator.createCase(baseResult)
            if (unknownCase != null) {
                if (persistUnknownCase) {
                    runCatching {
                        UnknownFileInvestigationStore.record(context.applicationContext, unknownCase)
                    }
                }
                baseResult.copy(unknownFileCase = unknownCase)
            } else {
                baseResult
            }
        } finally {
            runCatching { tempSink?.close() }
            runCatching { nativeSession?.close() }
            temp?.delete()
        }
    }
}
