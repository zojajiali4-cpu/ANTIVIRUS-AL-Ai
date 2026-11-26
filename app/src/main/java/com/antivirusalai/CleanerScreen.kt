package com.antivirusalai

import android.Manifest
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.documentfile.provider.DocumentFile
import com.antivirusalai.engine.DeviceScanEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Locale

private val CleanerTextPrimary = Color(0xFFF3F7FC)
private val CleanerTextSecondary = Color(0xFFB9ADC9)
private val CleanerSurface = Color(0xFF211437)
private val CleanerSurfaceSoft = Color(0xFF2B1948)
private val CleanerSuccess = Color(0xFF58D99A)
private val CleanerWarning = Color(0xFFF2C66D)
private val CleanerAccent = Color(0xFFB98BFF)
private val CleanerDanger = Color(0xFFFF718C)

private const val CLEANER_MAX_FILES = 50_000
private const val CLEANER_MAX_DIRECTORIES = 15_000
private const val CLEANER_MAX_DEPTH = 32
private const val CLEANER_MAX_CANDIDATES = 1_500
private const val CLEANER_HASH_BUDGET_BYTES = 256L * 1024L * 1024L
private const val CLEANER_MAX_HASH_FILE_BYTES = 32L * 1024L * 1024L
private const val CLEANER_LARGE_FILE_BYTES = 100L * 1024L * 1024L
private const val CLEANER_PREVIEW_COUNT = 60

private fun cleanerTr(fa: Boolean, persian: String, english: String) =
    if (fa) persian else english

private enum class CleanerReason {
    TEMPORARY, DUPLICATE, LARGE, REVIEW
}

private data class CleanerItem(
    val id: String,
    val name: String,
    val location: String,
    val size: Long,
    val reasons: Set<CleanerReason>,
    val filePath: String? = null,
    val uri: Uri? = null
)

private data class CleanerScannableFile(
    val id: String,
    val name: String,
    val location: String,
    val size: Long,
    val file: File? = null,
    val uri: Uri? = null
)

private data class CleanerScanResult(
    val filesScanned: Int,
    val directoriesScanned: Int,
    val totalBytes: Long,
    val candidates: List<CleanerItem>,
    val truncated: Boolean,
    val issues: Int,
    val duplicateBytesChecked: Long
)

private data class CleanerStorageStats(
    val totalBytes: Long,
    val availableBytes: Long
)

@Composable
fun CleanerScreen(fa: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var hasBroadAccess by remember { mutableStateOf(DeviceScanEngine.hasBroadStorageAccess(context)) }
    var selectedTreeUri by remember { mutableStateOf<Uri?>(null) }
    var scanResult by remember { mutableStateOf<CleanerScanResult?>(null) }
    var selectedIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var scanning by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    var showDeleteConfirmation by remember { mutableStateOf(false) }
    var cacheBytesCleared by remember { mutableStateOf<Long?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var visibleLimit by remember { mutableStateOf(CLEANER_PREVIEW_COUNT) }

    val settingsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        hasBroadAccess = DeviceScanEngine.hasBroadStorageAccess(context)
        message = if (hasBroadAccess) {
            cleanerTr(fa, "دسترسی حافظه فعال شد. اکنون می‌توانی حافظهٔ مشترک را بررسی کنی.",
                "Storage access granted. Shared storage can now be inspected.")
        } else {
            cleanerTr(fa, "دسترسی فعال نشد؛ می‌توانی یک پوشه را جداگانه انتخاب کنی.",
                "Access was not granted. You can still choose an individual folder.")
        }
    }

    val legacyPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasBroadAccess = DeviceScanEngine.hasBroadStorageAccess(context)
        message = if (granted) {
            cleanerTr(fa, "مجوز خواندن حافظه فعال شد.", "Shared-storage read permission granted.")
        } else {
            cleanerTr(fa, "مجوز داده نشد؛ از انتخاب پوشه استفاده کن.", "Permission denied; use the folder picker instead.")
        }
    }

    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            val persisted = runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }.isSuccess
            selectedTreeUri = uri
            scanResult = null
            selectedIds = emptySet()
            message = if (persisted) {
                cleanerTr(fa, "پوشه انتخاب شد. با اسکن، فایل‌های داخل آن بررسی می‌شوند.",
                    "Folder selected. Start a scan to inspect its files.")
            } else {
                cleanerTr(fa, "پوشه انتخاب شد، اما نگه‌داشتن دسترسی پایدار ممکن نشد. اسکن را همین حالا اجرا کن.",
                    "Folder selected, but persistent access could not be retained. Run the scan now.")
            }
        }
    }

    val selectedBytes = scanResult?.candidates
        ?.filter { selectedIds.contains(it.id) }
        ?.fold(0L) { total, item -> CleanerPolicy.saturatedAdd(total, item.size } ?: 0L
    val storageStats = remember(hasBroadAccess) {
        if (hasBroadAccess) readCleanerStorageStats() else null
    }

    fun startScan() {
        if (scanning || deleting) return
        scope.launch {
            scanning = true
            message = null
            scanResult = null
            selectedIds = emptySet()
            visibleLimit = CLEANER_PREVIEW_COUNT
            try {
                val result = withContext(Dispatchers.IO) {
                    if (hasBroadAccess) scanSharedStorage(context)
                    else {
                        val tree = selectedTreeUri
                        if (tree != null) scanSelectedTree(context, tree)
                        else CleanerScanResult(0, 0, 0L, emptyList(), false, 0, 0L)
                    }
                }
                scanResult = result
                // Deliberately select nothing automatically. Every deletion is an explicit user choice.
                selectedIds = emptySet()
                message = if (result.truncated) {
                    cleanerTr(fa,
                        "بررسی به سقف ایمنی رسید؛ نتیجه ناقص است و همه فایل‌ها بررسی نشده‌اند.",
                        "The safety limit was reached; this result is partial and not every file was inspected.")
                } else {
                    cleanerTr(fa, "بررسی کامل شد. موارد پیشنهادی را بازبینی کن.",
                        "Inspection completed. Review the suggested items.")
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                message = error.message ?: cleanerTr(fa, "اسکن حافظه انجام نشد.", "Storage inspection failed.")
            } finally {
                scanning = false
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(13.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            CleanerHeroIcon()
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(cleanerTr(fa, "پاک‌سازی هوشمند حافظه", "Smart Storage Cleaner"),
                    color = CleanerTextPrimary, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                Text(cleanerTr(fa, "بررسی فضای ذخیره‌سازی و پیشنهاد موارد قابل بازبینی",
                    "Inspect storage and review cleanup candidates"),
                    color = CleanerTextSecondary, fontSize = 11.sp)
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = CleanerSurface)) {
            Column(
                Modifier.fillMaxWidth().padding(15.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(cleanerTr(fa, "دسترسی حافظهٔ مشترک", "Shared storage access"),
                        color = CleanerTextPrimary, fontWeight = FontWeight.SemiBold)
                    Surface(
                        color = if (hasBroadAccess) CleanerSuccess.copy(alpha = 0.16f)
                        else CleanerWarning.copy(alpha = 0.16f),
                        shape = RoundedCornerShape(30.dp)
                    ) {
                        Text(
                            if (hasBroadAccess) cleanerTr(fa, "فعال", "GRANTED")
                            else cleanerTr(fa, "محدود", "LIMITED"),
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
                            color = if (hasBroadAccess) CleanerSuccess else CleanerWarning,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
                Text(
                    if (hasBroadAccess) cleanerTr(
                        fa,
                        "دسترسی همهٔ فایل‌ها فعال است. برنامه می‌تواند فایل‌های قابل‌دسترسی در حافظهٔ مشترک و رسانه‌های ذخیره‌سازی را بررسی کند.",
                        "All files access is enabled. The app can inspect accessible files on shared storage and storage volumes."
                    ) else cleanerTr(
                        fa,
                        "برای بررسی گستردهٔ حافظه، دسترسی ویژهٔ «مدیریت همهٔ فایل‌ها» را از تنظیمات Android فعال کن. این مجوز به داده‌های خصوصی برنامه‌های دیگر دسترسی نمی‌دهد.",
                        "For a wider storage scan, enable Android's special All files access. This does not expose other apps' private data."
                    ),
                    color = CleanerTextSecondary, fontSize = 11.sp, lineHeight = 16.sp
                )
                if (!hasBroadAccess) {
                    Button(
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                val appSettings = Intent(
                                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                    Uri.parse("package:${context.packageName}")
                                )
                                try {
                                    settingsLauncher.launch(appSettings)
                                } catch (_: Exception) {
                                    settingsLauncher.launch(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                                }
                            } else {
                                legacyPermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(cleanerTr(fa, "فعال‌سازی دسترسی حافظه", "Enable storage access"))
                    }
                } else {
                    Button(
                        onClick = { startScan() },
                        enabled = !scanning && !deleting,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(cleanerTr(fa, "اسکن گستردهٔ حافظه", "Scan shared storage"))
                    }
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && hasBroadAccess) {
                    TextButton(
                        onClick = {
                            val intent = Intent(
                                Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                Uri.parse("package:${context.packageName}")
                            )
                            runCatching { settingsLauncher.launch(intent) }
                        },
                        modifier = Modifier.align(Alignment.End)
                    ) { Text(cleanerTr(fa, "مدیریت مجوز", "Manage access"), color = CleanerAccent) }
                }
                if (storageStats != null) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CleanerMetric(
                            Modifier.weight(1f),
                            cleanerTr(fa, "کل حافظه", "Total"),
                            formatCleanerBytes(storageStats.totalBytes)
                        )
                        CleanerMetric(
                            Modifier.weight(1f),
                            cleanerTr(fa, "فضای آزاد", "Available"),
                            formatCleanerBytes(storageStats.availableBytes)
                        )
                    }
                }
            }
        }

        if (!hasBroadAccess) {
            Card(colors = CardDefaults.cardColors(containerColor = CleanerSurfaceSoft)) {
                Column(
                    Modifier.fillMaxWidth().padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(cleanerTr(fa, "بررسی یک پوشه بدون دسترسی گسترده",
                        "Inspect a folder without broad access"),
                        color = CleanerTextPrimary, fontWeight = FontWeight.SemiBold)
                    Text(
                        selectedTreeUri?.lastPathSegment
                            ?: cleanerTr(fa, "می‌توانی Downloads، تصاویر یا پوشهٔ دلخواه را انتخاب کنی.",
                                "Choose Downloads, Pictures, or another folder."),
                        color = CleanerTextSecondary, fontSize = 11.sp
                    )
                    OutlinedButton(
                        onClick = { folderPicker.launch(null) },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(cleanerTr(fa, "انتخاب پوشه", "Choose folder")) }
                    Button(
                        onClick = { startScan() },
                        enabled = selectedTreeUri != null && !scanning && !deleting,
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(cleanerTr(fa, "اسکن پوشهٔ انتخابی", "Scan selected folder")) }
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = CleanerSurface)) {
            Column(
                Modifier.fillMaxWidth().padding(15.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(cleanerTr(fa, "حافظهٔ موقت برنامه", "App temporary cache"),
                    color = CleanerTextPrimary, fontWeight = FontWeight.SemiBold)
                Text(
                    cleanerTr(fa,
                        "این گزینه فقط Cache خود ANTIVIRUS AL AI را پاک می‌کند؛ تنظیمات، قرنطینه و گزارش‌ها حفظ می‌شوند.",
                        "This clears only ANTIVIRUS AL AI's own cache. Settings, quarantine and scan reports are preserved."),
                    color = CleanerTextSecondary, fontSize = 11.sp, lineHeight = 16.sp
                )
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            val deletedBytes = withContext(Dispatchers.IO) {
                                clearOwnAppCache(context)
                            }
                            cacheBytesCleared = deletedBytes
                            message = cleanerTr(fa, "پاک‌سازی Cache برنامه انجام شد.",
                                "The app cache cleanup finished.")
                        }
                    },
                    enabled = !scanning && !deleting,
                    modifier = Modifier.fillMaxWidth()
                ) { Text(cleanerTr(fa, "پاک‌سازی Cache برنامه", "Clear app cache")) }
                cacheBytesCleared?.let {
                    Text(
                        cleanerTr(fa, "حجم پاک‌شده: ${formatCleanerBytes(it)}",
                            "Estimated cleared: ${formatCleanerBytes(it)}"),
                        color = CleanerSuccess, fontSize = 11.sp
                    )
                }
            }
        }

        if (scanning) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Text(cleanerTr(fa, "در حال بررسی فایل‌های قابل‌دسترسی…",
                "Inspecting accessible files…"), color = CleanerAccent, fontSize = 11.sp)
        }

        scanResult?.let { result ->
            Card(colors = CardDefaults.cardColors(containerColor = CleanerSurface)) {
                Column(
                    Modifier.fillMaxWidth().padding(15.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)
                ) {
                    Text(cleanerTr(fa, "گزارش بررسی حافظه", "Storage inspection report"),
                        color = CleanerTextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CleanerMetric(
                            Modifier.weight(1f),
                            cleanerTr(fa, "فایل بررسی‌شده", "Files inspected"),
                            result.filesScanned.toString()
                        )
                        CleanerMetric(
                            Modifier.weight(1f),
                            cleanerTr(fa, "پوشه بررسی‌شده", "Folders inspected"),
                            result.directoriesScanned.toString()
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CleanerMetric(
                            Modifier.weight(1f),
                            cleanerTr(fa, "حجم فایل‌ها", "Inspected size"),
                            formatCleanerBytes(result.totalBytes)
                        )
                        CleanerMetric(
                            Modifier.weight(1f),
                            cleanerTr(fa, "موارد پیشنهادی", "Candidates"),
                            result.candidates.size.toString()
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        CleanerReasonBadge(
                            cleanerTr(fa, "موقت: ${result.candidates.count { CleanerReason.TEMPORARY in it.reasons }}",
                                "Temporary: ${result.candidates.count { CleanerReason.TEMPORARY in it.reasons }}"),
                            CleanerAccent
                        )
                        CleanerReasonBadge(
                            cleanerTr(fa, "تکراری: ${result.candidates.count { CleanerReason.DUPLICATE in it.reasons }}",
                                "Duplicates: ${result.candidates.count { CleanerReason.DUPLICATE in it.reasons }}"),
                            CleanerSuccess
                        )
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                        CleanerReasonBadge(
                            cleanerTr(fa, "حجیم: ${result.candidates.count { CleanerReason.LARGE in it.reasons }}",
                                "Large: ${result.candidates.count { CleanerReason.LARGE in it.reasons }}"),
                            CleanerWarning
                        )
                        CleanerReasonBadge(
                            cleanerTr(fa, "نیازمند بررسی: ${result.candidates.count { CleanerReason.REVIEW in it.reasons }}",
                                "Review: ${result.candidates.count { CleanerReason.REVIEW in it.reasons }}"),
                            CleanerDanger
                        )
                    }
                    if (result.issues > 0 || result.truncated) {
                        Text(
                            cleanerTr(fa,
                                "موارد ردشده/غیرقابل‌دسترسی: ${result.issues} · محدودیت اعمال‌شده: ${if (result.truncated) "بله" else "خیر"}",
                                "Skipped/inaccessible entries: ${result.issues} · Safety limit reached: ${result.truncated}"),
                            color = CleanerWarning, fontSize = 10.sp
                        )
                    }
                    Text(
                        cleanerTr(fa,
                            "فایل‌های بزرگ فقط برای بازبینی معرفی می‌شوند. فایل‌های .log، .bak و .old نیز زبالهٔ قطعی محسوب نمی‌شوند. هیچ موردی خودکار انتخاب نشده است.",
                            "Large files are shown for review only. .log, .bak and .old files are not assumed to be junk. Nothing is preselected."),
                        color = CleanerTextSecondary, fontSize = 10.sp, lineHeight = 15.sp
                    )
                }
            }

            if (result.candidates.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        cleanerTr(fa, "موارد قابل بازبینی", "Review candidates"),
                        color = CleanerTextPrimary, fontWeight = FontWeight.Bold
                    )
                    TextButton(onClick = {
                        selectedIds = if (selectedIds.size == result.candidates.size) emptySet()
                        else result.candidates.map { it.id }.toSet()
                    }) {
                        Text(
                            if (selectedIds.size == result.candidates.size)
                                cleanerTr(fa, "لغو انتخاب همه", "Clear selection")
                            else cleanerTr(fa, "انتخاب همه", "Select all"),
                            color = CleanerAccent, fontSize = 11.sp
                        )
                    }
                }
                Text(
                    cleanerTr(fa, "انتخاب‌شده: ${selectedIds.size} مورد · ${formatCleanerBytes(selectedBytes)}",
                        "Selected: ${selectedIds.size} items · ${formatCleanerBytes(selectedBytes)}"),
                    color = CleanerTextSecondary, fontSize = 11.sp
                )
                Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    result.candidates.take(visibleLimit).forEach { item ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = selectedIds.contains(item.id),
                                onCheckedChange = { checked ->
                                    selectedIds = if (checked) selectedIds + item.id else selectedIds - item.id
                                }
                            )
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(item.name, color = CleanerTextPrimary, fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold)
                                Text(item.location, color = CleanerTextSecondary, fontSize = 9.sp,
                                    maxLines = 2)
                                Text(
                                    "${cleanerReasonLabel(item.reasons, fa)} · ${formatCleanerBytes(item.size)}",
                                    color = CleanerWarning, fontSize = 9.sp
                                )
                            }
                        }
                    }
                }
                if (result.candidates.size > visibleLimit) {
                    TextButton(onClick = {
                        visibleLimit = (visibleLimit + CLEANER_PREVIEW_COUNT).coerceAtMost(result.candidates.size)
                    }, modifier = Modifier.align(Alignment.End)) {
                        Text(cleanerTr(fa, "نمایش موارد بیشتر", "Show more"), color = CleanerAccent)
                    }
                }
                Button(
                    onClick = { showDeleteConfirmation = true },
                    enabled = selectedIds.isNotEmpty() && !deleting && !scanning,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(if (deleting) cleanerTr(fa, "در حال حذف…", "Deleting…")
                    else cleanerTr(fa, "حذف موارد انتخاب‌شده", "Delete selected files"))
                }
            } else if (!scanning) {
                Text(
                    cleanerTr(fa, "مورد پیشنهادی برای پاکسازی پیدا نشد. این به معنی اسکن امنیتی یا تأیید سالم‌بودن همه فایل‌ها نیست.",
                        "No cleanup candidates were found. This is not a malware scan or a guarantee that every file is safe."),
                    color = CleanerSuccess, fontSize = 11.sp, lineHeight = 16.sp
                )
            }
        }

        message?.let {
            Text(it, color = CleanerTextSecondary, fontSize = 11.sp, lineHeight = 16.sp)
        }
        TextButton(onClick = onBack, modifier = Modifier.align(Alignment.End)) {
            Text(cleanerTr(fa, "بازگشت", "Back"), color = CleanerAccent)
        }
    }

    if (showDeleteConfirmation) {
        val chosen = scanResult?.candidates?.filter { selectedIds.contains(it.id) }.orEmpty()
        AlertDialog(
            onDismissRequest = { showDeleteConfirmation = false },
            title = { Text(cleanerTr(fa, "تأیید نهایی حذف", "Confirm file deletion")) },
            text = {
                Text(
                    cleanerTr(fa,
                        "${chosen.size} فایل با حجم تقریبی ${formatCleanerBytes(selectedBytes)} حذف شود؟ این کار قابل بازگشت نیست. فایل‌های سیستمی و داده‌های خصوصی سایر برنامه‌ها در این فهرست قرار نمی‌گیرند.",
                        "Delete ${chosen.size} files totaling about ${formatCleanerBytes(selectedBytes)}? This cannot be undone. System files and other apps' private data are not included.")
                )
            },
            confirmButton = {
                TextButton(
                    enabled = !deleting,
                    onClick = {
                        showDeleteConfirmation = false
                        scope.launch {
                            deleting = true
                            val results = withContext(Dispatchers.IO) {
                                val roots = if (DeviceScanEngine.hasBroadStorageAccess(context))
                                    findCleanerStorageRoots(context) else emptyList()
                                chosen.map { item ->
                                    val deleted = when {
                                        item.filePath != null && roots.isNotEmpty() ->
                                            deleteSharedStorageFile(context, item.filePath, roots)
                                        item.uri != null ->
                                            runCatching { DocumentFile.fromSingleUri(context, item.uri)?.delete() == true }
                                                .getOrDefault(false)
                                        else -> false
                                    }
                                    item.id to deleted
                                }
                            }
                            val deletedIds = results.filter { it.second }.map { it.first }.toSet()
                            val failed = results.size - deletedIds.size
                            scanResult = scanResult?.let { old ->
                                old.copy(candidates = old.candidates.filterNot { deletedIds.contains(it.id) })
                            }
                            selectedIds = selectedIds - deletedIds
                            deleting = false
                            message = cleanerTr(fa,
                                "${deletedIds.size} فایل حذف شد؛ ${failed} مورد حذف نشد. حجم آزادشده برآوردی است.",
                                "${deletedIds.size} files deleted; ${failed} could not be deleted. Reclaimed size is an estimate.")
                        }
                    }
                ) { Text(cleanerTr(fa, "حذف فایل‌ها", "Delete files")) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirmation = false }) {
                    Text(cleanerTr(fa, "انصراف", "Cancel"))
                }
            }
        )
    }
}

@Composable
private fun CleanerHeroIcon() {
    Box(
        modifier = Modifier
            .size(72.dp)
            .background(
                Brush.linearGradient(listOf(Color(0xFF6F35B8), Color(0xFF291B50), Color(0xFF176A68))),
                RoundedCornerShape(20.dp)
            ),
        contentAlignment = Alignment.Center
    ) {
        Canvas(Modifier.size(45.dp)) {
            val w = size.width
            val h = size.height
            drawLine(Color(0xFFFFE6A6), Offset(w * 0.68f, h * 0.12f),
                Offset(w * 0.36f, h * 0.70f), strokeWidth = w * 0.085f, cap = StrokeCap.Round)
            drawRoundRect(
                Color(0xFFC8A0FF),
                topLeft = Offset(w * 0.20f, h * 0.65f),
                size = Size(w * 0.40f, h * 0.15f),
                cornerRadius = CornerRadius(w * 0.06f)
            )
            for (index in 0..3) {
                val x = w * (0.24f + index * 0.09f)
                drawLine(Color(0xFFEEDFFF), Offset(x, h * 0.78f),
                    Offset(x - w * 0.035f, h * 0.91f), strokeWidth = w * 0.035f,
                    cap = StrokeCap.Round)
            }
            val sparkle = Path().apply {
                moveTo(w * 0.78f, h * 0.22f)
                lineTo(w * 0.83f, h * 0.36f)
                lineTo(w * 0.96f, h * 0.41f)
                lineTo(w * 0.83f, h * 0.46f)
                lineTo(w * 0.78f, h * 0.60f)
                lineTo(w * 0.73f, h * 0.46f)
                lineTo(w * 0.60f, h * 0.41f)
                lineTo(w * 0.73f, h * 0.36f)
                close()
            }
            drawPath(sparkle, Color(0xFF9FFFE2))
            drawCircle(Color.White, radius = w * 0.035f, center = Offset(w * 0.17f, h * 0.23f))
            drawCircle(Color.White, radius = w * 0.025f, center = Offset(w * 0.88f, h * 0.76f))
        }
    }
}

@Composable
private fun CleanerMetric(modifier: Modifier, label: String, value: String) {
    Surface(
        modifier = modifier,
        color = CleanerSurfaceSoft,
        shape = RoundedCornerShape(13.dp)
    ) {
        Column(Modifier.padding(11.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(label, color = CleanerTextSecondary, fontSize = 9.sp)
            Text(value, color = CleanerTextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun CleanerReasonBadge(text: String, tint: Color) {
    Surface(color = tint.copy(alpha = 0.13f), shape = RoundedCornerShape(30.dp)) {
        Text(text, Modifier.padding(horizontal = 9.dp, vertical = 5.dp),
            color = tint, fontSize = 9.sp, fontWeight = FontWeight.SemiBold)
    }
}

private fun cleanerReasonLabel(reasons: Set<CleanerReason>, fa: Boolean): String =
    reasons.sortedBy { it.ordinal }.joinToString(" · ") {
        when (it) {
            CleanerReason.TEMPORARY -> cleanerTr(fa, "احتمالاً موقت", "Possible temporary file")
            CleanerReason.DUPLICATE -> cleanerTr(fa, "تکراری با SHA-256", "Duplicate by SHA-256")
            CleanerReason.LARGE -> cleanerTr(fa, "فایل حجیم؛ بازبینی کن", "Large file; review")
            CleanerReason.REVIEW -> cleanerTr(fa, "نیازمند بررسی دستی", "Manual review")
        }
    }

private suspend fun scanSharedStorage(context: Context): CleanerScanResult {
    val roots = findCleanerStorageRoots(context)
    if (roots.isEmpty()) {
        return CleanerScanResult(0, 0, 0L, emptyList(), true, 1, 0L)
    }

    val files = ArrayList<CleanerScannableFile>()
    val failures = 0
    var visitedDirectories = 0
    var truncated = false

    for (root in roots) {
        val queue = ArrayDeque<Pair<File, Int>>()
        val visitedPaths = HashSet<String>()
        queue.add(root to 0)
        while (queue.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            if (files.size >= CLEANER_MAX_FILES || visitedDirectories >= CLEANER_MAX_DIRECTORIES) {
                truncated = true
                break
            }
            val (directory, depth) = queue.removeFirst()
            if (depth > CLEANER_MAX_DEPTH) {
                truncated = true
                continue
            }
            val canonicalDirectory = runCatching { directory.canonicalFile }.getOrNull()
            if (canonicalDirectory == null || !CleanerPolicy.isWithinRoot(canonicalDirectory, root)) {
                truncated = true
                continue
            }
            if (!visitedPaths.add(canonicalDirectory.path)) continue
            val relativeDirectory = canonicalDirectory.relativeTo(root).invariantSeparatorsPath
            if (CleanerPolicy.isProtectedRelativePath(relativeDirectory)) continue

            visitedDirectories++
            val children = try {
                canonicalDirectory.listFiles()
            } catch (_: SecurityException) {
                null
            }
            if (children == null) {
                truncated = true
                continue
            }
            for (child in children) {
                currentCoroutineContext().ensureActive()
                val canonicalChild = runCatching { child.canonicalFile }.getOrNull()
                if (canonicalChild == null || !CleanerPolicy.isWithinRoot(canonicalChild, root)) {
                    truncated = true
                    continue
                }
                if (child.isDirectory) {
                    val relative = canonicalChild.relativeTo(root).invariantSeparatorsPath
                    if (!CleanerPolicy.isProtectedRelativePath(relative)) {
                        queue.add(canonicalChild to depth + 1)
                    }
                } else if (child.isFile) {
                    if (!child.canRead()) {
                        truncated = true
                        continue
                    }
                    val path = canonicalChild.path
                    files.add(
                        CleanerScannableFile(
                            id = path,
                            name = canonicalChild.name,
                            location = relativePathForDisplay(root, canonicalChild),
                            size = canonicalChild.length().coerceAtLeast(0L),
                            file = canonicalChild
                        )
                    )
                    if (files.size >= CLEANER_MAX_FILES) {
                        truncated = true
                        break
                    }
                }
            }
            if (truncated && (files.size >= CLEANER_MAX_FILES ||
                    visitedDirectories >= CLEANER_MAX_DIRECTORIES)) break
        }
        if (files.size >= CLEANER_MAX_FILES || visitedDirectories >= CLEANER_MAX_DIRECTORIES) {
            truncated = true
            break
        }
    }

    return analyzeCleanerFiles(
        context = context,
        files = files,
        directoriesScanned = visitedDirectories,
        truncated = truncated,
        issues = failures
    )
}

private suspend fun scanSelectedTree(context: Context, rootUri: Uri): CleanerScanResult {
    val root = DocumentFile.fromTreeUri(context, rootUri)
        ?: return CleanerScanResult(0, 0, 0L, emptyList(), false, 1, 0L)
    val queue = ArrayDeque<Pair<DocumentFile, Int>>()
    queue.add(root to 0)
    val files = ArrayList<CleanerScannableFile>()
    var directories = 0
    var issues = 0
    var truncated = false
    while (queue.isNotEmpty()) {
        currentCoroutineContext().ensureActive()
        if (files.size >= CLEANER_MAX_FILES || directories >= CLEANER_MAX_DIRECTORIES) {
            truncated = true
            break
        }
        val (folder, depth) = queue.removeFirst()
        if (depth > CLEANER_MAX_DEPTH) {
            truncated = true
            continue
        }
        directories++
        val children = runCatching { folder.listFiles() }.getOrElse {
            issues++
            emptyArray()
        }
        for (child in children) {
            currentCoroutineContext().ensureActive()
            if (child.isDirectory) {
                queue.add(child to depth + 1)
            } else if (child.isFile) {
                val name = child.name ?: continue
                val size = runCatching { child.length() }.getOrDefault(0L).coerceAtLeast(0L)
                files.add(
                    CleanerScannableFile(
                        id = child.uri.toString(),
                        name = name,
                        location = child.uri.lastPathSegment ?: name,
                        size = size,
                        uri = child.uri
                    )
                )
                if (files.size >= CLEANER_MAX_FILES) {
                    truncated = true
                    break
                }
            }
        }
    }
    return analyzeCleanerFiles(context, files, directories, truncated, issues)
}

private suspend fun analyzeCleanerFiles(
    context: Context,
    files: List<CleanerScannableFile>,
    directoriesScanned: Int,
    truncated: Boolean,
    issues: Int
): CleanerScanResult {
    val candidates = LinkedHashMap<String, CleanerItem>()
    var totalBytes = 0L

    fun addReason(file: CleanerScannableFile, reason: CleanerReason) {
        val existing = candidates[file.id]
        if (existing != null) {
            candidates[file.id] = existing.copy(reasons = existing.reasons + reason)
        } else if (candidates.size < CLEANER_MAX_CANDIDATES) {
            candidates[file.id] = CleanerItem(
                id = file.id,
                name = file.name,
                location = file.location,
                size = file.size,
                reasons = setOf(reason),
                filePath = file.file?.path,
                uri = file.uri
            )
        }
    }

    files.forEach { file ->
        totalBytes = CleanerPolicy.saturatedAdd(totalBytes, file.size)
        if (CleanerPolicy.isLikelyTemporaryName(file.name)) {
            addReason(file, CleanerReason.TEMPORARY)
        }
        if (CleanerPolicy.needsManualReviewName(file.name)) {
            addReason(file, CleanerReason.REVIEW)
        }
        if (file.size >= CLEANER_LARGE_FILE_BYTES) {
            addReason(file, CleanerReason.LARGE)
        }
    }

    var hashedBytes = 0L
    val sameSizeGroups = files
        .filter { it.size >= 1_024L && it.size <= CLEANER_MAX_HASH_FILE_BYTES }
        .groupBy { it.size }
        .values
        .filter { it.size > 1 }

    for (group in sameSizeGroups) {
        currentCoroutineContext().ensureActive()
        val firstByHash = HashMap<String, CleanerScannableFile>()
        for (file in group) {
            currentCoroutineContext().ensureActive()
            val remainingBudget = CLEANER_HASH_BUDGET_BYTES - hashedBytes
            if (remainingBudget <= 0L || file.size > remainingBudget) continue
            val hash = try {
                hashCleanerFile(context, file)
            } catch (_: Exception) {
                null
            }
            if (hash != null) {
                hashedBytes = CleanerPolicy.saturatedAdd(hashedBytes, file.size)
                if (firstByHash.putIfAbsent(hash, file) != null) {
                    addReason(file, CleanerReason.DUPLICATE)
                }
            }
        }
    }

    return CleanerScanResult(
        filesScanned = files.size,
        directoriesScanned = directoriesScanned,
        totalBytes = totalBytes,
        candidates = candidates.values.toList(),
        truncated = truncated || candidates.size >= CLEANER_MAX_CANDIDATES,
        issues = issues,
        duplicateBytesChecked = hashedBytes
    )
}

private fun hashCleanerFile(context: Context, candidate: CleanerScannableFile): String? {
    val stream: InputStream = when {
        candidate.file != null -> candidate.file.inputStream()
        candidate.uri != null -> context.contentResolver.openInputStream(candidate.uri) ?: return null
        else -> return null
    }
    val digest = MessageDigest.getInstance("SHA-256")
    stream.buffered().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

private fun findCleanerStorageRoots(context: Context): List<File> {
    val roots = LinkedHashMap<String, File>()
    val candidates = ArrayList<File>()
    candidates.add(Environment.getExternalStorageDirectory())
    context.getExternalFilesDirs(null).filterNotNull().forEach { appFiles ->
        val marker = "/Android/data/"
        val index = appFiles.absolutePath.indexOf(marker)
        if (index > 0) candidates.add(File(appFiles.absolutePath.substring(0, index)))
    }
    candidates.forEach { candidate ->
        val root = runCatching { candidate.canonicalFile }.getOrNull() ?: return@forEach
        if (root.isDirectory && root.canRead()) roots[root.path] = root
    }
    return roots.values.toList()
}

private fun deleteSharedStorageFile(context: Context, path: String, roots: List<File>): Boolean {
    if (!DeviceScanEngine.hasBroadStorageAccess(context)) return false
    val candidate = runCatching { File(path).canonicalFile }.getOrNull() ?: return false
    val allowedRoot = roots.firstOrNull { CleanerPolicy.isWithinRoot(candidate, it) } ?: return false
    val relative = runCatching { candidate.relativeTo(allowedRoot).invariantSeparatorsPath }.getOrNull()
        ?: return false
    if (CleanerPolicy.isProtectedRelativePath(relative)) return false
    if (!candidate.exists() || !candidate.isFile || !candidate.canWrite()) return false
    return runCatching { candidate.delete() }.getOrDefault(false)
}

private fun relativePathForDisplay(root: File, file: File): String =
    runCatching { file.relativeTo(root).invariantSeparatorsPath }
        .getOrDefault(file.name)
        .take(180)

private fun clearOwnAppCache(context: Context): Long {
    val roots = listOfNotNull(context.cacheDir, context.externalCacheDir)
        .distinctBy { runCatching { it.canonicalPath }.getOrDefault(it.absolutePath) }
    var bytes = 0L
    roots.forEach { root ->
        val children = root.listFiles() ?: return@forEach
        children.forEach { child ->
            val before = if (child.isFile) child.length()
                else child.walkTopDown().filter { it.isFile }.fold(0L) { total, file ->
                    CleanerPolicy.saturatedAdd(total, file.length())
                }
            val deleted = runCatching { child.deleteRecursively() }.getOrDefault(false)
            if (deleted) bytes = CleanerPolicy.saturatedAdd(bytes, before)
        }
    }
    return bytes
}

private fun readCleanerStorageStats(): CleanerStorageStats? {
    val root = runCatching { Environment.getExternalStorageDirectory() }.getOrNull() ?: return null
    return runCatching {
        val stats = StatFs(root.path)
        val blockSize = stats.blockSizeLong
        CleanerStorageStats(
            totalBytes = stats.blockCountLong * blockSize,
            availableBytes = stats.availableBlocksLong * blockSize
        )
    }.getOrNull()
}

private fun formatCleanerBytes(bytes: Long): String {
    if (bytes < 1_024L) return "${bytes} B"
    val kb = bytes / 1_024.0
    if (kb < 1_024.0) return String.format(Locale.ROOT, "%.1f KB", kb)
    val mb = kb / 1_024.0
    if (mb < 1_024.0) return String.format(Locale.ROOT, "%.1f MB", mb)
    return String.format(Locale.ROOT, "%.2f GB", mb / 1_024.0)
}
