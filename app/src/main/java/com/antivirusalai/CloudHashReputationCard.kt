package com.antivirusalai

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.antivirusalai.engine.ScanResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Optional, explicit-consent cloud reputation lookup.
 *
 * Only the SHA-256 digest is sent. This card never uploads file bytes, names,
 * content URIs or filesystem paths and never changes the local scan verdict.
 */
@Composable
fun CloudHashReputationCard(
    result: ScanResult,
    fa: Boolean,
    premiumAccess: Boolean,
    onOpenStore: () -> Unit
) {
    if (!premiumAccess) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = if (fa) "اعتبارسنجی آنلاین هش — قابلیت PLUS" else "Online hash reputation — PLUS",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = if (fa) {
                        "اسکن و گزارش محلی رایگان است. استعلام ابری اختیاری فقط پس از Trial یا اشتراک تأییدشده و با اجازه جداگانه شما انجام می‌شود."
                    } else {
                        "Local scanning and reports remain free. Optional cloud lookup requires a verified trial or subscription and separate consent."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Button(onClick = onOpenStore) {
                    Text(if (fa) "مشاهده دوره آزمایشی" else "View free-trial offers")
                }
            }
        }
        return
    }
    val digest = result.sha256
    val validDigest = digest.matches(Regex("[0-9a-fA-F]{64}"))
    val scope = rememberCoroutineScope()

    var showConsent by remember(digest) { mutableStateOf(false) }
    var loading by remember(digest) { mutableStateOf(false) }
    var assessment by remember(digest) { mutableStateOf<CloudHashReputationResult?>(null) }
    var error by remember(digest) { mutableStateOf<String?>(null) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = if (fa) "استعلام اختیاری اعتبار آنلاین" else "Optional online reputation",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = if (fa) {
                    "برای بررسی تکمیلی، فقط اثر انگشت SHA-256 فایل ارسال می‌شود؛ خود فایل، نام و مسیر آن ارسال نمی‌شوند."
                } else {
                    "For an optional second opinion, only the file's SHA-256 digest is sent. The file, filename and path are never uploaded."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Button(
                onClick = { showConsent = true },
                enabled = validDigest && !loading
            ) {
                Text(
                    when {
                        loading -> if (fa) "در حال بررسی..." else "Checking..."
                        assessment != null -> if (fa) "استعلام دوباره" else "Check again"
                        else -> if (fa) "درخواست استعلام آنلاین" else "Request online lookup"
                    }
                )
            }

            if (loading) {
                Text(
                    text = if (fa) "نتیجه محلی دست‌نخورده باقی می‌ماند." else "Your local scan result remains unchanged.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            assessment?.let { remote ->
                val classification = remote.classification.uppercase()
                val resultText = when {
                    !remote.found || classification == "UNKNOWN" ->
                        if (fa) {
                            "در بانک فعلی موردی برای این هش پیدا نشد؛ این موضوع به معنی سالم بودن فایل نیست."
                        } else {
                            "No record was found in the current database. This does not prove the file is safe."
                        }
                    classification == "MALWARE" ->
                        if (fa) "بانک آنلاین این هش را بدافزار طبقه‌بندی کرده است." else "The online database classifies this hash as malware."
                    classification == "PUA" ->
                        if (fa) "بانک آنلاین این هش را به‌عنوان برنامه بالقوه ناخواسته ثبت کرده است." else "The online database classifies this hash as a potentially unwanted application."
                    else ->
                        if (fa) "بانک آنلاین برای این هش نشانه مشکوک ثبت کرده است." else "The online database has a suspicious indicator for this hash."
                }
                Text(
                    text = resultText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (remote.found && classification != "UNKNOWN") {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    }
                )
                remote.source?.let {
                    Text(
                        text = (if (fa) "منبع: " else "Source: ") + it,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                remote.familyId?.let {
                    Text(
                        text = (if (fa) "شناسه خانواده: " else "Family: ") + it,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            error?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }

    if (showConsent) {
        AlertDialog(
            onDismissRequest = { showConsent = false },
            title = {
                Text(if (fa) "اجازه استعلام آنلاین؟" else "Allow online reputation lookup?")
            },
            text = {
                Text(
                    if (fa) {
                        "فقط مقدار SHA-256 این فایل به سرویس ابری فرستاده می‌شود. محتوای فایل، نام، مسیر و URI ارسال نمی‌شوند. سرویس ممکن است فراداده معمول اتصال، مانند نشانی IP، را برای محدودسازی درخواست‌ها پردازش کند. عدم وجود نتیجه، تضمین سالم بودن فایل نیست. آیا موافقی؟"
                    } else {
                        "Only this file's SHA-256 digest will be sent to the cloud service. File contents, filename, path and URI are not sent. The service may process normal connection metadata, such as IP address, for rate limiting. No match is not proof of safety. Do you consent?"
                    }
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showConsent = false
                        loading = true
                        error = null
                        assessment = null
                        scope.launch {
                            try {
                                assessment = withContext(Dispatchers.IO) {
                                    CloudThreatApi.checkSha256(digest)
                                }
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (_: Exception) {
                                error = if (fa) {
                                    "استعلام آنلاین در دسترس نیست؛ نتیجه اسکن محلی تغییری نکرد."
                                } else {
                                    "Online lookup is unavailable. Your local scan verdict has not changed."
                                }
                            } finally {
                                loading = false
                            }
                        }
                    }
                ) {
                    Text(if (fa) "تأیید و ارسال هش" else "Consent and send hash")
                }
            },
            dismissButton = {
                TextButton(onClick = { showConsent = false }) {
                    Text(if (fa) "انصراف" else "Cancel")
                }
            }
        )
    }
}
