package com.antivirusalai.intel

import android.content.Context
import com.antivirusalai.BuildConfig
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.PublicKey

sealed interface ThreatFeedRefreshResult {
    data object NotConfigured : ThreatFeedRefreshResult
    data class Updated(val version: Long, val indicatorCount: Int) : ThreatFeedRefreshResult
    data class Failed(val reason: String) : ThreatFeedRefreshResult
}

/**
 * Runtime boundary for the signed offline threat feed.
 *
 * The app contains only a pinned public key. The signing private key must stay
 * outside Android and outside this repository. Until both URL and key are
 * provisioned by a release pipeline, refresh is deliberately disabled.
 */
object ThreatFeedRuntime {
    private const val CONNECT_TIMEOUT_MS = 8_000
    private const val READ_TIMEOUT_MS = 12_000

    @Volatile
    private var cachedVerifier: EcdsaP256KeyringVerifier? = null

    private fun configuredVerifier(): EcdsaP256KeyringVerifier? {
        val encoded = BuildConfig.ALAI_THREAT_FEED_PUBLIC_KEY_B64.trim()
        if (encoded.isEmpty()) return null
        cachedVerifier?.let { return it }
        return synchronized(this) {
            cachedVerifier ?: run {
                val key: PublicKey = EcdsaP256KeyringVerifier.decodeX509PublicKey(encoded)
                EcdsaP256KeyringVerifier(mapOf(BuildConfig.ALAI_THREAT_FEED_KEY_ID to key))
                    .also { cachedVerifier = it }
            }
        }
    }

    private fun store(context: Context): SignedThreatFeedStore? {
        val verifier = configuredVerifier() ?: return null
        return SignedThreatFeedStore(
            directory = java.io.File(context.applicationContext.filesDir, "threat-intelligence"),
            verifier = verifier
        )
    }

    /** Returns a verified local match only. An absent or expired feed is never treated as clean. */
    fun lookup(context: Context, sha256: String): ThreatIndicator? =
        store(context)?.lookup(sha256)

    /** Downloads only the signed feed bytes; it never uploads files or hashes. */
    suspend fun refresh(context: Context): ThreatFeedRefreshResult {
        val endpoint = BuildConfig.ALAI_THREAT_FEED_URL.trim()
        val feedStore = try {
            store(context)
        } catch (_: Exception) {
            return ThreatFeedRefreshResult.Failed("Pinned threat-feed public key configuration is invalid.")
        } ?: return ThreatFeedRefreshResult.NotConfigured
        if (endpoint.isEmpty()) return ThreatFeedRefreshResult.NotConfigured

        val connection = try {
            val parsed = URL(endpoint)
            if (parsed.protocol != "https" || parsed.host.isBlank() || parsed.userInfo != null) {
                return ThreatFeedRefreshResult.Failed("Threat feed endpoint must be a valid HTTPS URL.")
            }
            (parsed.openConnection() as? HttpURLConnection)
                ?: return ThreatFeedRefreshResult.Failed("Unsupported threat feed connection.")
        } catch (_: Exception) {
            return ThreatFeedRefreshResult.Failed("Threat feed endpoint is invalid.")
        }

        return try {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/vnd.alai.threat-feed")
            connection.setRequestProperty("Cache-Control", "no-cache")
            val status = connection.responseCode
            if (status != HttpURLConnection.HTTP_OK) {
                return ThreatFeedRefreshResult.Failed("Threat feed server returned HTTP $status.")
            }
            val declaredLength = connection.contentLengthLong
            if (declaredLength > SignedThreatFeedParser.MAX_FEED_BYTES) {
                return ThreatFeedRefreshResult.Failed("Threat feed exceeds the 4 MiB safety limit.")
            }
            val bytes = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > SignedThreatFeedParser.MAX_FEED_BYTES) {
                        return ThreatFeedRefreshResult.Failed("Threat feed exceeds the 2 MiB safety limit.")
                    }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
            val installed = feedStore.install(bytes)
            ThreatFeedRefreshResult.Updated(installed.version, installed.indicators.size + installed.networkIndicators.size)
        } catch (error: FeedValidationException) {
            ThreatFeedRefreshResult.Failed("Threat feed rejected: ${error.code}.")
        } catch (_: Exception) {
            ThreatFeedRefreshResult.Failed("Threat feed could not be downloaded or stored.")
        } finally {
            connection.disconnect()
        }
    }
}
