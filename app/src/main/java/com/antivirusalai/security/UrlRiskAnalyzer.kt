package com.antivirusalai.security

import java.net.IDN
import java.net.InetAddress
import java.net.URI
import java.util.Locale

enum class UrlRiskLevel { NO_STRUCTURAL_WARNING, CAUTION, HIGH_RISK_STRUCTURE, INVALID }

data class UrlRiskSignal(val code: String, val explanation: String)
data class UrlRiskAssessment(val level: UrlRiskLevel, val normalizedUrl: String?, val signals: List<UrlRiskSignal>)

/**
 * Offline URL structure checks only. This is not a phishing verdict or a reputation service.
 * It never opens, resolves, or contacts the supplied URL.
 */
object UrlRiskAnalyzer {
    private val knownShorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"
    )
    private val suspiciousTerms = setOf(
        "login", "verify", "account", "secure", "wallet", "password", "support", "update"
    )

    fun analyze(input: String): UrlRiskAssessment {
        val candidate = input.trim()
        if (candidate.isEmpty() || candidate.length > 2_048 || candidate.any { it.isWhitespace() || it.isISOControl() }) {
            return invalid("INVALID_INPUT", "The address is empty, too long, or contains whitespace/control characters.")
        }

        val uri = try { URI(candidate) } catch (_: Exception) {
            return invalid("MALFORMED_URL", "The address could not be parsed safely.")
        }
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        if (scheme != "https" && scheme != "http") {
            return invalid("UNSUPPORTED_SCHEME", "Only explicit HTTP or HTTPS web addresses can be assessed.")
        }
        if (uri.rawUserInfo != null) {
            return UrlRiskAssessment(
                UrlRiskLevel.HIGH_RISK_STRUCTURE, null,
                listOf(UrlRiskSignal("EMBEDDED_CREDENTIALS", "The address contains user-information before the host, a common deception pattern."))
            )
        }
        val rawHost = uri.host?.trimEnd('.')?.lowercase(Locale.ROOT)
            ?: return invalid("MISSING_OR_INVALID_HOST", "The address has no valid hostname.")
        val host = try { IDN.toASCII(rawHost, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT) } catch (_: Exception) {
            return invalid("INVALID_HOST", "The hostname contains invalid internationalized-domain characters.")
        }
        if (host.isBlank() || host.length > 253 || host.split('.').any { it.isBlank() || it.length > 63 }) {
            return invalid("INVALID_HOST", "The hostname is outside accepted DNS label limits.")
        }

        val signals = mutableListOf<UrlRiskSignal>()
        if (scheme == "http") signals += UrlRiskSignal("UNENCRYPTED_HTTP", "The connection does not use HTTPS; this alone does not prove the site is malicious.")
        if (host.startsWith("xn--") || host.split('.').any { it.startsWith("xn--") }) {
            signals += UrlRiskSignal("PUNYCODE_HOST", "The hostname uses internationalized punycode; inspect for look-alike characters.")
        }
        if (isIpLiteral(host)) signals += UrlRiskSignal("IP_LITERAL_HOST", "The address uses an IP literal instead of a normal domain name.")
        if (host.count { it == '.' } >= 4) signals += UrlRiskSignal("MANY_SUBDOMAINS", "The hostname contains an unusually deep subdomain chain.")
        if (uri.port !in listOf(-1, 80, 443)) signals += UrlRiskSignal("UNUSUAL_PORT", "The URL specifies a non-standard web port.")
        if (host in knownShorteners) signals += UrlRiskSignal("URL_SHORTENER", "This is a known link-shortening domain; the final destination is not checked offline.")
        val hostAndPath = (host + (uri.rawPath ?: "") + (uri.rawQuery ?: "")).lowercase(Locale.ROOT)
        if (suspiciousTerms.any { term -> hostAndPath.split(Regex("[^a-z0-9]+" )).any { it == term } }) {
            signals += UrlRiskSignal("SENSITIVE_KEYWORD", "The address contains a term often used in account or credential prompts; context is required.")
        }

        val normalized = try {
            URI(scheme, null, host, uri.port, uri.rawPath, uri.rawQuery, null).toASCIIString()
        } catch (_: Exception) { candidate }
        val level = when {
            signals.any { it.code in setOf("EMBEDDED_CREDENTIALS", "IP_LITERAL_HOST", "PUNYCODE_HOST") } -> UrlRiskLevel.HIGH_RISK_STRUCTURE
            signals.isNotEmpty() -> UrlRiskLevel.CAUTION
            else -> UrlRiskLevel.NO_STRUCTURAL_WARNING
        }
        return UrlRiskAssessment(level, normalized, signals)
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(':')) return true
        val parts = host.split('.')
        return parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
    }

    private fun invalid(code: String, explanation: String) =
        UrlRiskAssessment(UrlRiskLevel.INVALID, null, listOf(UrlRiskSignal(code, explanation)))
}
