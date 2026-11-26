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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
            message = tr(fa, "پوشه انتخاب شد. برای بررسی، اسکن را شروع کن.", "Folder selected. Start the scan to inspect it.")
        }
    }

    val selectedBytes = items.filter { selected.contains(it.uri.toString()) }.sumOf { it.size }

    Column(verticalArrangement = Arrangement.spacedBy(13.dp)) {
        Text(tr(fa, "پاک‌سازی حافظه", "Storage Cleaner"), color = TextPrimary, fontSize = 24.sp)
        Text(
            tr(fa, "فقط فایل‌های داخل پوشه‌ای که خودت انتخاب می‌کنی بررسی می‌شوند. هیچ فایلی بدون تأیید تو حذف نمی‌شود.",
                "Only files inside a folder you choose are inspected. Nothing is deleted without your confirmation."),
            color = TextSecondary, fontSize = 12.sp
        )

        Card(colors = CardDefaults.cardColors(containerColor = SurfaceRaised)) {
            Column(Modifier.fillMaxWidth().padding(15.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text(tr(fa, "حافظه موقت ANTIVIRUS AL AI", "ANTIVIRUS AL AI temporary cache"), color = TextPrimary)
                Text(tr(fa, "فقط فایل‌های موقت خود برنامه پاک می‌شوند؛ تنظیمات، قرنطینه و گزارش‌های اسکن دست‌نخورده می‌مانند.",
                    "Only this app's temporary cache is cleared; settings, quarantine and scan reports are preserved."),
                    color = TextSecondary, fontSize = 11.sp)
                Button(
                    onClick = {
                        scope.launch {
                            cacheBytes = withContext(Dispatchers.IO) {
                                val roots = listOfNotNull(context.cacheDir, context.externalCacheDir)
                                roots.sumOf { root ->
                                    val before = root.walkTopDown().filter { it.isFile }.sumOf { it.length() }
                                    root.listFiles()?.forEach { it.deleteRecursively() }
                                    before
                                }
                            }
                            message = tr(fa, "پاک‌سازی حافظه موقت برنامه انجام شد.", "App temporary cache cleared.")
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(tr(fa, "پاک‌سازی Cache برنامه", "Clear app cache")) }
                cacheBytes?.let {
                    Text(tr(fa, "حجم پاک‌شده: ${formatCleanerBytes(it)}", "Cleared: ${formatCleanerBytes(it)}"),
                        color = ColorSuccess, fontSize = 12.sp)
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = SurfaceRaised)) {
            Column(Modifier.fillMaxWidth().padding(15.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text(tr(fa, "بررسی پوشه انتخابی", "Inspect a selected folder"), color = TextPrimary)
                Text(
                    treeUri?.lastPathSegment ?: tr(fa, "هنوز پوشه‌ای انتخاب نشده است.", "No folder selected yet."),
                    color = TextSecondary, fontSize = 11.sp
                )
                OutlinedButton(onClick = { folderPicker.launch(null) }, modifier = Modifier.fillMaxWidth()) {
                    Text(tr(fa, "انتخاب پوشه", "Choose folder"))
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
                            message = tr(fa, "بررسی تمام شد؛ موارد پیشنهادی را بازبینی کن.", "Inspection complete; review the suggested items.")
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(if (scanning) tr(fa, "در حال بررسی…", "Scanning…") else tr(fa, "اسکن فایل‌های اضافی و تکراری", "Scan temporary and duplicate files")) }
            }
        }

        if (items.isNotEmpty()) {
            Text(tr(fa, "${items.size} مورد پیشنهادی · ${formatCleanerBytes(items.sumOf { it.size })}",
                "${items.size} suggested items · ${formatCleanerBytes(items.sumOf { it.size })}"),
                color = ColorWarning, fontSize = 13.sp)
            Text(tr(fa, "موارد انتخاب‌شده: ${formatCleanerBytes(selectedBytes)}", "Selected: ${formatCleanerBytes(selectedBytes)}"),
                color = TextSecondary, fontSize = 12.sp)
            LazyColumn(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                items(items, key = { it.uri.toString() }) { item ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = selected.contains(item.uri.toString()),
                            onCheckedChange = { checked ->
                                selected = if (checked) selected + item.uri.toString() else selected - item.uri.toString()
                            }
                        )
                        Column(Modifier.weight(1f)) {
                            Text(item.name, color = TextPrimary, fontSize = 12.sp)
                            Text("${item.reason} · ${formatCleanerBytes(item.size)}", color = TextSecondary, fontSize = 10.sp)
                        }
                    }
                }
            }
            Button(
                enabled = selected.isNotEmpty() && !deleting,
                onClick = { showDeleteConfirm = true },
                modifier = Modifier.fillMaxWidth()
            ) { Text(tr(fa, "حذف موارد انتخاب‌شده", "Delete selected items")) }
        }

        message?.let { Text(it, color = TextSecondary, fontSize = 11.sp) }
        TextButton(onClick = onBack, modifier = Modifier.align(Alignment.End)) {
            Text(tr(fa, "بازگشت", "Back"))
        }
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text(tr(fa, "تأیید حذف", "Confirm deletion")) },
            text = { Text(tr(fa, "تعداد ${selected.size} فایل با حجم ${formatCleanerBytes(selectedBytes)} حذف شود؟ این کار قابل بازگشت نیست.",
                "Delete ${selected.size} files totaling ${formatCleanerBytes(selectedBytes)}? This cannot be undone.")) },
            confirmButton = {
                TextButton(onClick = {
                    showDeleteConfirm = false
                    scope.launch {
                        deleting = true
                        val chosen = items.filter { selected.contains(it.uri.toString()) }
                        val deleted = withContext(Dispatchers.IO) {
                            chosen.count { DocumentFile.fromSingleUri(context, it.uri)?.delete() == true }
                        }
                        items = items.filterNot { selected.contains(it.uri.toString()) }
                        selected = emptySet()
                        deleting = false
                        message = tr(fa, "$deleted فایل با موفقیت حذف شد.", "$deleted files deleted successfully.")
                    }
                }) { Text(tr(fa, "حذف", "Delete")) }
            },
            dismissButton = { TextButton(onClick = { showDeleteConfirm = false }) { Text(tr(fa, "انصراف", "Cancel")) } }
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

    val tempExtensions = setOf("tmp", "temp", "log", "bak", "old", "part", "crdownload", "cache")
    val candidates = LinkedHashMap<String, CleanerItem>()
    files.forEach { file ->
        val name = file.name ?: return@forEach
        val ext = name.substringAfterLast('.', "").lowercase(Locale.ROOT)
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
                context.contentResolver.openInputStream(file.uri)?.use { input ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        hashedBytes += count
                        if (hashedBytes > 256L * 1024L * 1024L) break
                        md.update(buffer, 0, count)
                    }
                } ?: return@runCatching null
                md.digest().joinToString("") { "%02x".format(it) }
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
