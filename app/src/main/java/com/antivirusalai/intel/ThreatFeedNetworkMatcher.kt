package com.antivirusalai.intel

import java.net.IDN
import java.net.URI
import java.util.Locale

/** Matches a manually submitted URL against exact indicators in a verified feed. */
object ThreatFeedNetworkMatcher {
    fun find(
        rawUrl: String,
        indicators: Map<String, ThreatNetworkIndicator>
    ): ThreatNetworkIndicator? {
        val uri = runCatching { URI(rawUrl) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        if (scheme != "http" && scheme != "https") return null
        if (uri.rawUserInfo != null || uri.rawFragment != null) return null
        val rawHost = uri.host?.trimEnd('.') ?: return null
        val host = runCatching { IDN.toASCII(rawHost, IDN.USE_STD3_ASCII_RULES) }
            .getOrNull()?.lowercase(Locale.ROOT) ?: return null
        val port = uri.port
        if (port !in -1..65535) return null

        val authorityHost = if (host.contains(':')) "[$host]" else host
        val authority = authorityHost + if (port >= 0) ":$port" else ""
        val path = uri.rawPath.orEmpty().ifEmpty { "/" }
        val normalized = "$scheme://$authority$path" +
            (uri.rawQuery?.let { "?$it" } ?: "")

        indicators["URL|$normalized"]?.let { return it }
        if (port >= 0) indicators["IP_PORT|$host:$port"]?.let { return it }
        indicators["IPV4|$host"]?.let { return it }
        return indicators["DOMAIN|$host"]
    }
}
