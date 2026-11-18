package com.antivirusalai

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.antivirusalai.security.UrlRiskAnalyzer
import com.antivirusalai.security.UrlRiskAssessment
import com.antivirusalai.security.UrlRiskLevel

/**
 * On-device URL structure inspection.
 *
 * The URL is parsed locally only. This component does not resolve DNS, open a
 * connection, follow redirects, query cloud reputation or read messages.
 */
@Composable
fun LocalUrlRiskCard(fa: Boolean) {
    var address by rememberSaveable { mutableStateOf("") }
    var assessment by rememberSaveable { mutableStateOf<UrlRiskAssessment?>(null) }

    val result = assessment
    val accent = when (result?.level) {
        UrlRiskLevel.INVALID, UrlRiskLevel.HIGH_RISK_STRUCTURE -> MaterialTheme.colorScheme.error
        UrlRiskLevel.CAUTION -> MaterialTheme.colorScheme.tertiary
        UrlRiskLevel.NO_STRUCTURAL_WARNING -> MaterialTheme.colorScheme.primary
        null -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Text(
                text = if (fa) "بررسی آفلاین لینک" else "Offline link inspection",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = if (fa) {
                    "ساختار نشانی را روی خود گوشی بررسی کن. لینک باز یا به اینترنت ارسال نمی‌شود."
                } else {
                    "Inspect the address structure on this device. The link is not opened or sent to the internet."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = address,
                onValueChange = {
                    address = it
                    assessment = null
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text(if (fa) "نشانی کامل وب" else "Full web address") },
                placeholder = { Text("https://example.com") }
            )
            Button(
                modifier = Modifier.fillMaxWidth(),
                enabled = address.isNotBlank(),
                onClick = { assessment = UrlRiskAnalyzer.analyze(address) }
            ) {
                Text(if (fa) "بررسی آفلاین" else "Inspect offline")
            }

            result?.let { report ->
                val title = when (report.level) {
                    UrlRiskLevel.INVALID -> if (fa) "نشانی نامعتبر" else "Invalid address"
                    UrlRiskLevel.HIGH_RISK_STRUCTURE -> if (fa) "ساختار پرخطر" else "High-risk structure"
                    UrlRiskLevel.CAUTION -> if (fa) "نیازمند احتیاط" else "Use caution"
                    UrlRiskLevel.NO_STRUCTURAL_WARNING -> if (fa) "هشدار ساختاری پیدا نشد" else "No structural warning found"
                }
                Text(
                    text = title,
                    color = accent,
                    style = MaterialTheme.typography.titleSmall
                )
                when (report.level) {
                    UrlRiskLevel.NO_STRUCTURAL_WARNING -> Text(
                        if (fa) "این فقط یعنی نشانه ساختاری شناخته‌شده‌ای پیدا نشد؛ سالم بودن سایت را تضمین نمی‌کند."
                        else "This only means no known structural warning was found; it does not prove the site is safe."
                    )
                    UrlRiskLevel.HIGH_RISK_STRUCTURE -> Text(
                        if (fa) "پیش از باز کردن، نشانی را دقیق بررسی کن. این نتیجه تحلیل ساختار است، نه حکم قطعی بدافزار."
                        else "Check the address carefully before opening it. This is a structural assessment, not a definitive malware verdict."
                    )
                    UrlRiskLevel.CAUTION -> Text(
                        if (fa) "برخی ویژگی‌ها نیازمند بررسی بیشتر هستند؛ این نشانه‌ها به‌تنهایی اثبات فیشینگ نیستند."
                        else "Some characteristics deserve a closer look; these signals alone do not prove phishing."
                    )
                    UrlRiskLevel.INVALID -> Unit
                }

                report.normalizedUrl?.let { normalized ->
                    Text(
                        text = (if (fa) "نشانی نرمال‌شده: " else "Normalized: ") + normalized,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                report.signals.forEach { signal ->
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(signal.code, color = accent, style = MaterialTheme.typography.labelMedium)
                        Text(
                            signal.explanation,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                Text(
                    if (fa) "این بررسی کاملاً محلی است؛ اعتبار آنلاین دامنه، مقصد لینک کوتاه‌شده و محتوای صفحه بررسی نمی‌شود."
                    else "This inspection is fully local. It does not check online domain reputation, resolve shortened links or inspect page content.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
    }
}
