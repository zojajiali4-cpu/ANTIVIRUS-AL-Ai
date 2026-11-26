package com.antivirusalai.engine

import android.content.Context
import org.json.JSONArray
import java.util.LinkedHashMap
import org.json.JSONObject

/**
 * Creates a privacy-minimal local investigation record for files that the
 * scanner cannot confidently classify. This does not execute or upload files.
 */
data class UnknownFileCase(
    val sha256: String,
    val sizeBytes: Long,
    val mimeType: String?,
    val detectedFormat: String?,
    val verdict: ScanVerdict,
    val analysisComplete: Boolean,
    val evidenceCodes: List<String>,
    val createdAtMillis: Long,
    val remoteLookupState: String = REMOTE_LOOKUP_NOT_CONFIGURED
) {
    companion object {
        const val REMOTE_LOOKUP_NOT_CONFIGURED = "NOT_CONFIGURED"
    }
}

object UnknownFileInvestigator {
    private val eligibleVerdicts = setOf(
        ScanVerdict.UNKNOWN_APK,
        ScanVerdict.UNSUPPORTED_FILE,
        ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE
    )

    fun shouldInvestigate(verdict: ScanVerdict): Boolean = verdict in eligibleVerdicts

    fun createCase(result: ScanResult, nowMillis: Long = System.currentTimeMillis()): UnknownFileCase? {
        if (!shouldInvestigate(result.verdict)) return null
        val hash = result.sha256.lowercase()
        if (!hash.matches(Regex("^[a-f0-9]{64}$"))) return null

        return UnknownFileCase(
            sha256 = hash,
            sizeBytes = result.sizeBytes.coerceAtLeast(0L),
            mimeType = result.mimeType?.take(128),
            detectedFormat = result.staticAnalysis?.format?.take(32),
            verdict = result.verdict,
            analysisComplete = result.staticAnalysis?.complete == true,
            evidenceCodes = result.evidence
                .map { it.code.take(96) }
                .distinct()
                .take(64),
            createdAtMillis = nowMillis
        )
    }
}

/**
 * Bounded local queue. Only hashes and analysis metadata are persisted;
 * file paths, names, bytes, and private content are deliberately excluded.
 */
object UnknownFileInvestigationStore {
    private const val PREFS = "unknown_file_investigations"
    private const val KEY_CASES = "cases"
    private const val MAX_CASES = 100

    fun record(context: Context, item: UnknownFileCase) = recordBatch(context, listOf(item))

    /**
     * Merge a scan batch with one read and one preference write. Device/folder
     * scans call this in bounded batches instead of rewriting the same JSON
     * preference once for every unknown file.
     */
    fun recordBatch(context: Context, items: List<UnknownFileCase>) {
        if (items.isEmpty()) return
        val incoming = LinkedHashMap<String, UnknownFileCase>()
        items.forEach { item ->
            val hash = item.sha256.lowercase()
            if (hash.matches(Regex("^[a-f0-9]{64}$"))) incoming[hash] = item
        }
        if (incoming.isEmpty()) return

        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val current = runCatching {
            JSONArray(prefs.getString(KEY_CASES, "[]") ?: "[]")
        }.getOrDefault(JSONArray())
        val incomingHashes = incoming.keys
        val merged = ArrayList<JSONObject>(current.length() + incoming.size)

        for (index in 0 until current.length()) {
            val existing = current.optJSONObject(index) ?: continue
            if (existing.optString("sha256").lowercase() !in incomingHashes) {
                merged += existing
            }
        }

        incoming.values.forEach { item ->
            merged += JSONObject()
                .put("sha256", item.sha256.lowercase())
                .put("size_bytes", item.sizeBytes)
                .put("mime_type", item.mimeType)
                .put("detected_format", item.detectedFormat)
                .put("verdict", item.verdict.name)
                .put("analysis_complete", item.analysisComplete)
                .put("created_at_ms", item.createdAtMillis)
                .put("remote_lookup_state", item.remoteLookupState)
                .put("evidence_codes", JSONArray(item.evidenceCodes))
        }

        val start = (merged.size - MAX_CASES).coerceAtLeast(0)
        val bounded = JSONArray()
        for (index in start until merged.size) bounded.put(merged[index])
        prefs.edit().putString(KEY_CASES, bounded.toString()).apply()
    }

    fun read(context: Context): List<JSONObject> {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val array = runCatching { JSONArray(prefs.getString(KEY_CASES, "[]") ?: "[]") }
            .getOrDefault(JSONArray())
        return (0 until array.length()).mapNotNull { array.optJSONObject(it) }
    }
}
