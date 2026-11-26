package com.antivirusalai.engine

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject

data class StoredDeviceScan(val deep: Boolean, val report: FolderScanReport)

object ScanReportStore {
    private const val PREFS = "device-scan-report"
    private const val REPORT_KEY = "latest_report"

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(REPORT_KEY).apply()
    }

    fun save(context: Context, deep: Boolean, report: FolderScanReport) {
        val root = JSONObject()
            .put("deep", deep)
            .put("discoveredFiles", report.discoveredFiles)
            .put("skippedFiles", report.skippedFiles)
            .put("truncated", report.truncated)
            .put("scannedCountOverride", report.scannedCountOverride ?: JSONObject.NULL)
            .put("suspiciousCountOverride", report.suspiciousCountOverride ?: JSONObject.NULL)
            .put("unknownCountOverride", report.unknownCountOverride ?: JSONObject.NULL)
            .put("matchedCountOverride", report.matchedCountOverride ?: JSONObject.NULL)
        val items = JSONArray()
        report.items.take(60).forEach { item ->
            items.put(JSONObject().put("uri", item.uri.toString()).put("result", encodeResult(item.result)))
        }
        val failures = JSONArray()
        report.failures.take(100).forEach { failure ->
            failures.put(JSONObject().put("name", failure.name).put("reason", failure.reason))
        }
        root.put("items", items).put("failures", failures)
        check(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(REPORT_KEY, root.toString()).commit()) { "The scan report could not be saved." }
    }

    fun load(context: Context): StoredDeviceScan? = runCatching {
        val encoded = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(REPORT_KEY, null) ?: return null
        val root = JSONObject(encoded)
        val items = mutableListOf<FolderScanItem>()
        val itemArray = root.optJSONArray("items") ?: JSONArray()
        for (index in 0 until itemArray.length()) {
            val item = itemArray.optJSONObject(index) ?: continue
            val uri = item.optString("uri").takeIf { it.isNotBlank() } ?: continue
            val resultObject = item.optJSONObject("result") ?: continue
            val result = decodeResult(resultObject) ?: continue
            items += FolderScanItem(Uri.parse(uri), result)
        }
        val failures = mutableListOf<FolderScanFailure>()
        val failureArray = root.optJSONArray("failures") ?: JSONArray()
        for (index in 0 until failureArray.length()) {
            val item = failureArray.optJSONObject(index) ?: continue
            failures += FolderScanFailure(item.optString("name"), item.optString("reason"))
        }
        StoredDeviceScan(
            deep = root.optBoolean("deep", false),
            report = FolderScanReport(
                items = items, failures = failures,
                discoveredFiles = root.optInt("discoveredFiles"),
                skippedFiles = root.optInt("skippedFiles"),
                truncated = root.optBoolean("truncated"),
                scannedCountOverride = root.nullableInt("scannedCountOverride"),
                suspiciousCountOverride = root.nullableInt("suspiciousCountOverride"),
                unknownCountOverride = root.nullableInt("unknownCountOverride"),
                matchedCountOverride = root.nullableInt("matchedCountOverride")
            )
        )
    }.getOrNull()

    internal fun encodeResult(result: ScanResult): JSONObject {
        val evidence = JSONArray()
        result.evidence.forEach { item ->
            evidence.put(JSONObject().put("code", item.code).put("title", item.title)
                .put("detail", item.detail).put("severity", item.severity.name))
        }
        val apk = result.apkMetadata?.let { metadata ->
            val permissions = JSONArray()
            metadata.requestedPermissions.sorted().forEach { permissions.put(it) }
            JSONObject().put("packageName", metadata.packageName)
                .put("versionName", metadata.versionName ?: JSONObject.NULL)
                .put("targetSdk", metadata.targetSdk)
                .put("requestedPermissions", permissions)
                .put("debuggable", metadata.debuggable)
                .put("signingCertificateSha256", metadata.signingCertificateSha256 ?: JSONObject.NULL)
                .put("exportedComponentCount", metadata.exportedComponentCount)
                .put("declaredAccessibilityServiceCount", metadata.declaredAccessibilityServiceCount)
        }
        val contentMatches = JSONArray()
        result.contentRuleMatches.take(512).forEach { contentMatches.put(it.take(96)) }
        val staticAnalysis = result.staticAnalysis?.let { summary ->
            val categories = JSONArray()
            summary.signalCategories.sorted().take(64).forEach { categories.put(it.take(96)) }
            JSONObject()
                .put("format", summary.format ?: JSONObject.NULL)
                .put("supported", summary.supported)
                .put("complete", summary.complete)
                .put("entryCount", summary.entryCount.coerceAtLeast(0))
                .put("expandedBytes", summary.expandedBytes.coerceAtLeast(0L))
                .put("signalCategories", categories)
        }
        val mlTopFeatures = JSONArray()
        result.mlTopFeatures.take(16).forEach { mlTopFeatures.put(it.take(96)) }
        val unknownCase = result.unknownFileCase?.let { item ->
            val codes = JSONArray()
            item.evidenceCodes.take(64).forEach { codes.put(it.take(96)) }
            JSONObject()
                .put("sha256", item.sha256)
                .put("sizeBytes", item.sizeBytes.coerceAtLeast(0L))
                .put("mimeType", item.mimeType ?: JSONObject.NULL)
                .put("detectedFormat", item.detectedFormat ?: JSONObject.NULL)
                .put("verdict", item.verdict.name)
                .put("analysisComplete", item.analysisComplete)
                .put("evidenceCodes", codes)
                .put("createdAtMillis", item.createdAtMillis)
                .put("remoteLookupState", item.remoteLookupState.take(48))
        }

        return JSONObject().put("displayName", result.displayName)
            .put("mimeType", result.mimeType ?: JSONObject.NULL)
            .put("sizeBytes", result.sizeBytes).put("sha256", result.sha256)
            .put("verdict", result.verdict.name).put("evidence", evidence)
            .put("apkMetadata", apk ?: JSONObject.NULL).put("durationMillis", result.durationMillis)
            .put("contentEngineState", result.contentEngineState.name)
            .put("contentRuleSetId", result.contentRuleSetId ?: JSONObject.NULL)
            .put("contentRuleMatches", contentMatches)
            .put("contentEngineErrorCode", result.contentEngineErrorCode ?: JSONObject.NULL)
            .put("contentRuleBundleVersion", result.contentRuleBundleVersion ?: JSONObject.NULL)
            .put("staticAnalysis", staticAnalysis ?: JSONObject.NULL)
            .put("mlModelState", result.mlModelState.name)
            .put("mlFeatureCount", result.mlFeatureCount.coerceAtLeast(0))
            .put("mlRiskScore", result.mlRiskScore ?: JSONObject.NULL)
            .put("mlModelVersion", result.mlModelVersion ?: JSONObject.NULL)
            .put("mlTopFeatures", mlTopFeatures)
            .put("behavioralAnalysisState", result.behavioralAnalysisState.name)
            .put("unknownFileCase", unknownCase ?: JSONObject.NULL)
    }

    internal fun decodeResult(value: JSONObject): ScanResult? = runCatching {
        val verdict = runCatching { ScanVerdict.valueOf(value.getString("verdict")) }
            .getOrDefault(ScanVerdict.UNSUPPORTED_FILE)
        val evidence = mutableListOf<ScanEvidence>()
        val evidenceArray = value.optJSONArray("evidence") ?: JSONArray()
        for (index in 0 until evidenceArray.length()) {
            val item = evidenceArray.optJSONObject(index) ?: continue
            val severity = runCatching { EvidenceSeverity.valueOf(item.getString("severity")) }
                .getOrDefault(EvidenceSeverity.INFO)
            evidence += ScanEvidence(item.optString("code"), item.optString("title"),
                item.optString("detail"), severity)
        }
        val apkValue = value.opt("apkMetadata")
        val apk = if (apkValue is JSONObject) {
            val permissions = apkValue.optJSONArray("requestedPermissions") ?: JSONArray()
            val permissionSet = buildSet {
                for (index in 0 until permissions.length()) {
                    permissions.optString(index).takeIf { it.isNotBlank() }?.let { add(it) }
                }
            }
            ApkMetadata(
                packageName = apkValue.optString("packageName"),
                versionName = apkValue.nullableString("versionName"),
                targetSdk = apkValue.optInt("targetSdk"),
                requestedPermissions = permissionSet,
                debuggable = apkValue.optBoolean("debuggable"),
                signingCertificateSha256 = apkValue.nullableString("signingCertificateSha256"),
                exportedComponentCount = apkValue.optInt("exportedComponentCount"),
                declaredAccessibilityServiceCount = apkValue.optInt("declaredAccessibilityServiceCount")
            )
        } else null
        val contentEngineState = runCatching {
            ContentEngineState.valueOf(value.optString("contentEngineState"))
        }.getOrDefault(ContentEngineState.UNAVAILABLE)
        val mlModelState = runCatching {
            MlModelState.valueOf(value.optString("mlModelState"))
        }.getOrDefault(MlModelState.NOT_CONFIGURED)
        val behavioralState = runCatching {
            BehavioralAnalysisState.valueOf(value.optString("behavioralAnalysisState"))
        }.getOrDefault(BehavioralAnalysisState.NOT_APPLICABLE)
        val contentMatches = value.optJSONArray("contentRuleMatches").boundedStrings(512, 96)
        val topFeatures = value.optJSONArray("mlTopFeatures").boundedStrings(16, 96)
        val staticValue = value.optJSONObject("staticAnalysis")
        val staticSummary = staticValue?.let { item ->
            StaticAnalysisSummary(
                format = item.nullableString("format"),
                supported = item.optBoolean("supported", false),
                complete = item.optBoolean("complete", false),
                entryCount = item.optInt("entryCount").coerceAtLeast(0),
                expandedBytes = item.optLong("expandedBytes").coerceAtLeast(0L),
                signalCategories = item.optJSONArray("signalCategories").boundedStrings(64, 96).toSet()
            )
        }
        val unknownValue = value.optJSONObject("unknownFileCase")
        val unknownCase = unknownValue?.let { item ->
            runCatching {
                val hash = item.optString("sha256").lowercase()
                require(hash.matches(Regex("^[a-f0-9]{64}$")))
                val caseVerdict = runCatching {
                    ScanVerdict.valueOf(item.optString("verdict"))
                }.getOrDefault(verdict)
                UnknownFileCase(
                    sha256 = hash,
                    sizeBytes = item.optLong("sizeBytes").coerceAtLeast(0L),
                    mimeType = item.nullableString("mimeType")?.take(128),
                    detectedFormat = item.nullableString("detectedFormat")?.take(32),
                    verdict = caseVerdict,
                    analysisComplete = item.optBoolean("analysisComplete", false),
                    evidenceCodes = item.optJSONArray("evidenceCodes").boundedStrings(64, 96),
                    createdAtMillis = item.optLong("createdAtMillis").coerceAtLeast(0L),
                    remoteLookupState = item.optString(
                        "remoteLookupState",
                        UnknownFileCase.REMOTE_LOOKUP_NOT_CONFIGURED
                    ).take(48)
                )
            }.getOrNull()
        }

        ScanResult(
            displayName = value.optString("displayName"), mimeType = value.nullableString("mimeType"),
            sizeBytes = value.optLong("sizeBytes"), sha256 = value.optString("sha256"),
            verdict = verdict, evidence = evidence, apkMetadata = apk,
            durationMillis = value.optLong("durationMillis"),
            contentEngineState = contentEngineState,
            contentRuleSetId = value.nullableString("contentRuleSetId"),
            contentRuleMatches = contentMatches,
            contentEngineErrorCode = value.nullableString("contentEngineErrorCode"),
            contentRuleBundleVersion = value.nullableLong("contentRuleBundleVersion"),
            staticAnalysis = staticSummary,
            mlModelState = mlModelState,
            mlFeatureCount = value.optInt("mlFeatureCount").coerceAtLeast(0),
            mlRiskScore = value.nullableInt("mlRiskScore"),
            mlModelVersion = value.nullableString("mlModelVersion"),
            mlTopFeatures = topFeatures,
            behavioralAnalysisState = behavioralState,
            unknownFileCase = unknownCase
        )
    }.getOrNull()

    private fun JSONArray?.boundedStrings(limit: Int, maxLength: Int): List<String> {
        if (this == null) return emptyList()
        return (0 until minOf(length(), limit)).mapNotNull { index ->
            optString(index).takeIf { it.isNotBlank() && it != "null" }?.take(maxLength)
        }
    }

    private fun JSONObject.nullableString(key: String): String? {
        val value = opt(key)
        return if (value == null || value == JSONObject.NULL) null else value as? String
    }
    private fun JSONObject.nullableInt(key: String): Int? {
        val value = opt(key)
        return if (value == null || value == JSONObject.NULL) null else (value as? Number)?.toInt()
    }
    private fun JSONObject.nullableLong(key: String): Long? {
        val value = opt(key)
        return if (value == null || value == JSONObject.NULL) null else (value as? Number)?.toLong()
    }
}
