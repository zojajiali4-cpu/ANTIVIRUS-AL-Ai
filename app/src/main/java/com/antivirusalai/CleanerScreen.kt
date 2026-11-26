package com.antivirusalai

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.weight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.Locale

private val CleanerTextPrimary = androidx.compose.ui.graphics.Color(0xFFF3F7FC)
private val CleanerTextSecondary = androidx.compose.ui.graphics.Color(0xFFB9ADC9)
private val CleanerSurface = androidx.compose.ui.graphics.Color(0xFF211437)
private val CleanerSuccess = androidx.compose.ui.graphics.Color(0xFF58D99A)
private val CleanerWarning = androidx.compose.ui.graphics.Color(0xFFF2C66D)

private fun cleanerTr(fa: Boolean, persian: String, english: String) = if (fa) persian else english

private data class CleanerItem(
    val uri: Uri,
    val name: String,
    val size: Long,
    val reason: String
)

@Composable
fun CleanerScreen(fa: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var treeUri by remember { mutableStateOf<Uri?>(null) }
    var items by remember { mutableStateOf<List<CleanerItem>>(emptyList()) }
    var selected by remember { mutableStateOf<Set<String>>(emptySet()) }
    var scanning by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var cacheBytes by remember { mutableStateOf<Long?>(null) }

    val folderPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            treeUri = uri
            items = emptyList()
            selected = emptySet()
            message = cleanerTr(fa, "پوشه انتخاب شد. برای بررسی، اسکن را شروع کن.", "Folder selected. Start the scan to inspect it.")
        }
    }

    val selectedBytes = items.filter { selected.contains(it.uri.toString()) }.sumOf { it.size }

    Column(verticalArrangement = Arrangement.spacedBy(13.dp)) {
        Text(cleanerTr(fa, "پاک‌سازی حافظه", "Storage Cleaner"), color = CleanerTextPrimary, fontSize = 24.sp)
        Text(
            cleanerTr(fa, "فقط فایل‌های داخل پوشه‌ای که خودت انتخاب می‌کنی بررسی می‌شوند. هیچ فایلی بدون تأیید تو حذف نمی‌شود.",
                "Only files inside a folder you choose are inspected. Nothing is deleted without your confirmation."),
            color = CleanerTextSecondary, fontSize = 12.sp
        )

        Card(colors = CardDefaults.cardColors(containerColor = CleanerSurface)) {
            Column(Modifier.fillMaxWidth().padding(15.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text(cleanerTr(fa, "حافظه موقت ANTIVIRUS AL AI", "ANTIVIRUS AL AI temporary cache"), color = CleanerTextPrimary)
                Text(cleanerTr(fa, "فقط فایل‌های موقت خود برنامه پاک می‌شوند؛ تنظیمات، قرنطینه و گزارش‌های اسکن دست‌نخورده می‌مانند.",
                    "Only this app's temporary cache is cleared; settings, quarantine and scan reports are preserved."),
                    color = CleanerTextSecondary, fontSize = 11.sp)
                Button(
                    onClick = {
                        scope.launch {
                            cacheBytes = withContext(Dispatchers.IO) {
                                val roots = listOfNotNull(context.cacheDir, context.externalCacheDir)
                                roots.sumOf { root ->
                                    val before = root.walkTopDown().filter { it.isFile }.sumOf { it.length() }
                                    val cleared = root.listFiles()?.all { it.deleteRecursively() } ?: true
                                    if (cleared) before else 0L
                                }
                            }
                            message = cleanerTr(fa, "پاک‌سازی حافظه موقت برنامه انجام شد.", "App temporary cache cleared.")
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(cleanerTr(fa, "پاک‌سازی Cache برنامه", "Clear app cache")) }
                cacheBytes?.let {
                    Text(cleanerTr(fa, "حجم پاک‌شده: ${formatCleanerBytes(it)}", "Cleared: ${formatCleanerBytes(it)}"),
                        color = CleanerSuccess, fontSize = 12.sp)
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = CleanerSurface)) {
            Column(Modifier.fillMaxWidth().padding(15.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text(cleanerTr(fa, "بررسی پوشه انتخابی", "Inspect a selected folder"), color = CleanerTextPrimary)
                Text(
                    treeUri?.lastPathSegment ?: cleanerTr(fa, "هنوز پوشه‌ای انتخاب نشده است.", "No folder selected yet."),
                    color = CleanerTextSecondary, fontSize = 11.sp
                )
                OutlinedButton(onClick = { folderPicker.launch(null) }, modifier = Modifier.fillMaxWidth()) {
                    Text(cleanerTr(fa, "انتخاب پوشه", "Choose folder"))
                }
                Button(
                    enabled = treeUri != null && !scanning,
                    onClick = {
                        val uri = treeUri ?: return@Button
                        scope.launch {
                            scanning = true
                            message = null
                            val result = withContext(Dispatchers.IO) { scanCleanerTree(context, uri) }
                            items = result
                            selected = result.map { it.uri.toString() }.toSet()
                            scanning = false
                            message = cleanerTr(fa, "بررسی تمام شد؛ موارد پیشنهادی را بازبینی کن.", "Inspection complete; review the suggested items.")
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (scanning) cleanerTr(fa, "در حال بررسی…", "Scanning…") else cleanerTr(fa, "اسکن فایل‌های اضافی و تکراری", "Scan temporary and duplicate files")) }
            }
        }

        if (items.isNotEmpty()) {
            Text(cleanerTr(fa, "${items.size} مورد پیشنهادی · ${formatCleanerBytes(items.sumOf { it.size })}",
                "${items.size} suggested items · ${formatCleanerBytes(items.sumOf { it.size })}"),
                color = CleanerWarning, fontSize = 13.sp)
            Text(cleanerTr(fa, "موارد انتخاب‌شده: ${formatCleanerBytes(selectedBytes)}", "Selected: ${formatCleanerBytes(selectedBytes)}"),
                color = CleanerTextSecondary, fontSize = 12.sp)
            Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                items.take(40).forEach { item ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = selected.contains(item.uri.toString()),
                            onCheckedChange = { checked ->
                                selected = if (checked) selected + item.uri.toString() else selected - item.uri.toString()
                            }
                        )
                        Column(Modifier.weight(1f)) {
                            Text(item.name, color = CleanerTextPrimary, fontSize = 12.sp)
                            Text("${item.reason} · ${formatCleanerBytes(item.size)}", color = CleanerTextSecondary, fontSize = 10.sp)
                        }
                    }
                }
                if (items.size > 40) {
                    Text(cleanerTr(fa, "۴۰ مورد اول نمایش داده شده‌اند؛ انتخاب گروهی شامل همه موارد است.", "Showing first 40 items; bulk selection includes all results."),
                        color = CleanerTextSecondary, fontSize = 10.sp)
                }
            }
            Button(
                enabled = selected.isNotEmpty() && !deleting,
                onClick = { showDeleteConfirm = true },
                modifier = Modifier.fillMaxWidth()
            ) { Text(cleanerTr(fa, "حذف موارد انتخاب‌شده", "Delete selected items")) }
        }

        message?.let { Text(it, color = CleanerTextSecondary, fontSize = 11.sp) }
        TextButton(onClick = onBack, modifier = Modifier.align(Alignment.End)) {
            Text(cleanerTr(fa, "بازگشت", "Back"))
        }
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text(cleanerTr(fa, "تأیید حذف", "Confirm deletion")) },
            text = { Text(cleanerTr(fa, "تعداد ${selected.size} فایل با حجم ${formatCleanerBytes(selectedBytes)} حذف شود؟ این کار قابل بازگشت نیست.",
                "Delete ${selected.size} files totaling ${formatCleanerBytes(selectedBytes)}? This cannot be undone.")) },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteConfirm = false
                    scope.launch {
                        deleting = true
                        val chosen = items.filter { selected.contains(it.uri.toString()) }
                        val deletedUris = withContext(Dispatchers.IO) {
                            chosen.filter { DocumentFile.fromSingleUri(context, it.uri)?.delete() == true }
                                .map { it.uri.toString() }.toSet()
                        }
                        items = items.filterNot { deletedUris.contains(it.uri.toString()) }
                        selected = selected - deletedUris
                        deleting = false
                        message = cleanerTr(fa, "${deletedUris.size} فایل با موفقیت حذف شد.", "${deletedUris.size} files deleted successfully.")
                    }
                }) { Text(cleanerTr(fa, "حذف", "Delete")) }
            },
            dismissButton = { TextButton(onClick = { showDeleteConfirm = false }) { Text(cleanerTr(fa, "انصراف", "Cancel")) } }
        )
    }
}

private suspend fun scanCleanerTree(context: android.content.Context, rootUri: Uri): List<CleanerItem> {
    val root = DocumentFile.fromTreeUri(context, rootUri) ?: return emptyList()
    val queue = ArrayDeque<Pair<DocumentFile, Int>>()
    queue.add(root to 0)
    val files = ArrayList<DocumentFile>()
    var visited = 0
    while (queue.isNotEmpty() && visited < 5000) {
        val (folder, depth) = queue.removeFirst()
        if (depth > 12) continue
        val children = runCatching { folder.listFiles() }.getOrDefault(emptyArray())
        for (child in children) {
            visited++
            if (visited >= 5000) break
            if (child.isDirectory) queue.add(child to depth + 1)
            else if (child.isFile && child.length() > 0L) files.add(child)
        }
    }

    val candidates = LinkedHashMap<String, CleanerItem>()
    files.forEach { file ->
        val name = file.name ?: return@forEach
        if (CleanerPolicy.isTemporaryName(name)) {
            candidates[file.uri.toString()] = CleanerItem(file.uri, name, file.length(),
                "Temporary-file extension")
        }
    }

    val bySize = files.filter { it.length() >= 1024L }.groupBy { it.length() }.values.filter { it.size > 1 }
    var hashedBytes = 0L
    for (group in bySize) {
        val hashes = HashMap<String, DocumentFile>()
        for (file in group) {
            if (hashedBytes >= 256L * 1024L * 1024L) break
            val digest = runCatching {
                val md = MessageDigest.getInstance("SHA-256")
                var exceededBudget = false
                context.contentResolver.openInputStream(file.uri)?.use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        hashedBytes += count
                        if (hashedBytes > 256L * 1024L * 1024L) {
                            exceededBudget = true
                            break
                        }
                        md.update(buffer, 0, count)
                    }
                } ?: return@runCatching null
                if (exceededBudget) null else md.digest().joinToString("") { "%02x".format(it) }
            }.getOrNull()
            if (digest != null) {
                val previous = hashes.putIfAbsent(digest, file)
                if (previous != null) {
                    candidates[file.uri.toString()] = CleanerItem(file.uri, file.name ?: "file", file.length(),
                        "Duplicate content (SHA-256)")
                }
            }
        }
    }
    return candidates.values.toList()
}

private fun formatCleanerBytes(bytes: Long): String {
    if (bytes < 1024L) return "${bytes} B"
    val kb = bytes / 1024.0
    if (kb < 1024.0) return String.format(Locale.ROOT, "%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024.0) return String.format(Locale.ROOT, "%.1f MB", mb)
    return String.format(Locale.ROOT, "%.2f GB", mb / 1024.0)
}
