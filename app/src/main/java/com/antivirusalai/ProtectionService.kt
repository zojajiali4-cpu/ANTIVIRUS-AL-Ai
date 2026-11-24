package com.antivirusalai

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.antivirusalai.engine.DeviceScanEngine
import com.antivirusalai.engine.ScanEngine
import com.antivirusalai.engine.ScanVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * User-enabled, visible protection monitor.
 *
 * It watches accessible shared-storage folders for completed writes/moves and
 * checks newly installed packages while this service is running. Android does
 * not expose other apps' private data or a system-wide process/network hook.
 */
object ProtectionRuntime {
    private const val PREFS = "alai-protection-state"
    private const val KEY_ENABLED = "enabled"

    fun isEnabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_ENABLED, enabled).apply()
    }
}

private data class PendingFileScan(val file: File, val allowedRoot: File, val canonicalPath: String)

class ProtectionService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val observers = CopyOnWriteArrayList<FileObserver>()
    private val activeWatcherCount = AtomicInteger(0)
    private val watchedPaths = mutableSetOf<String>()
    private val pendingScans = PendingScanRegistry(MAX_PENDING_SCANS)
    private val scanQueue = Channel<PendingFileScan>(capacity = MAX_PENDING_SCANS)
    private val overflowAlertPosted = AtomicBoolean(false)
    private var scanWorkerStarted = false
    private var packageReceiverRegistered = false

    private val packageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            // Re-check consent before even reading the package identifier from
            // a system install event; consent may have been revoked while active.
            if (!InstalledAppInventoryConsent.isGranted(this@ProtectionService)) return
            val packageName = intent?.data?.schemeSpecificPart ?: return
            if (packageName == packageNameForSelf()) return
            serviceScope.launch {
                delay(1_200L)
                scanInstalledPackage(packageName)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        startAsForeground()
        startFileScanWorker()
        registerPackageMonitor()
        startFileMonitoring()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            ProtectionRuntime.setEnabled(this, false)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!ProtectionRuntime.isEnabled(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Re-evaluate revocable app-inventory consent and storage access whenever
        // the activity asks the existing service to refresh its coverage.
        registerPackageMonitor()
        startFileMonitoring()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        observers.toList().forEach { observer ->
            runCatching { observer.stopWatching() }
            if (observers.remove(observer)) releaseWatcherSlot()
        }
        observers.clear()
        if (packageReceiverRegistered) {
            runCatching { unregisterReceiver(packageReceiver) }
            packageReceiverRegistered = false
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun buildProtectionNotification(status: String): android.app.Notification {
        val stopIntent = Intent(this, ProtectionService::class.java).setAction(ACTION_STOP)
        val stopPendingIntent = PendingIntent.getService(
            this, 4109, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("ANTIVIRUS AL AI · وضعیت محافظت")
            .setContentText(status)
            .setStyle(NotificationCompat.BigTextStyle().bigText(status))
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "توقف محافظت", stopPendingIntent)
            .build()
    }

    private fun startAsForeground() {
        val notification = buildProtectionNotification("سرویس محافظت در حال بررسی دسترسی‌ها و محدوده پایش است.")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateProtectionNotification(status: String) {
        runCatching {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, buildProtectionNotification(status))
        }
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "محافظت بلادرنگ", NotificationManager.IMPORTANCE_LOW).apply {
                description = "اعلان دائمی هنگام فعال بودن محافظت دستگاه"
                setShowBadge(false)
            }
        )
        manager.createNotificationChannel(
            NotificationChannel(ALERT_CHANNEL_ID, "هشدار تهدید", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "هشدار هنگام شناسایی فایل دارای شاخص تهدید"
            }
        )
        manager.createNotificationChannel(
            NotificationChannel(UNVERIFIED_CHANNEL_ID, "نتیجه نامشخص", NotificationManager.IMPORTANCE_DEFAULT).apply {
                description = "مواردی که به علت محدودیت دسترسی، اندازه یا پوشش موتور کامل بررسی نشده‌اند"
            }
        )
    }

    private fun registerPackageMonitor() {
        // Package inventory is a sensitive signal: registering package-change
        // monitoring is gated by the same explicit, revocable in-app consent.
        if (!InstalledAppInventoryConsent.isGranted(this)) {
            if (packageReceiverRegistered) {
                runCatching { unregisterReceiver(packageReceiver) }
                packageReceiverRegistered = false
            }
            return
        }
        if (packageReceiverRegistered) return

        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(packageReceiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(packageReceiver, filter)
            }
            packageReceiverRegistered = true
        } catch (_: Exception) {
            packageReceiverRegistered = false
        }
    }

    private fun startFileMonitoring() {
        if (!DeviceScanEngine.hasBroadStorageAccess(this)) {
            stopFileMonitoring()
            val status = when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && packageReceiverRegistered ->
                    "پایش فایل‌های حافظه مشترک فعال نیست؛ دسترسی «مدیریت همه فایل‌ها» داده نشده است. فقط رویداد نصب برنامه‌ها، با رضایت قبلی، پایش می‌شود."
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ->
                    "پایش فایل‌ها فعال نیست؛ دسترسی «مدیریت همه فایل‌ها» و رضایت فهرست برنامه‌ها در دسترس نیست."
                packageReceiverRegistered ->
                    "پایش فایل‌های حافظه فعال نیست؛ مجوز خواندن حافظه داده نشده است. فقط رویداد نصب برنامه‌ها با رضایت قبلی پایش می‌شود."
                else ->
                    "پایش فایل‌ها و برنامه‌های تازه نصب‌شده فعال نیست؛ مجوز حافظه یا رضایت فهرست برنامه‌ها موجود نیست."
            }
            updateProtectionNotification(status)
            return
        }

        val storage = Environment.getExternalStorageDirectory()
        val storageRoot = runCatching { storage.canonicalFile }.getOrNull()
        if (storageRoot == null) {
            updateProtectionNotification("مسیر حافظه مشترک قابل‌اعتبارسنجی نیست؛ پایش فایل‌ها شروع نشد.")
            return
        }
        val targets = listOf(
            File(storage, "Download"),
            File(storage, "Downloads"),
            File(storage, "Documents"),
            File(storage, "Bluetooth"),
            File(storage, "DCIM"),
            File(storage, "Pictures"),
            File(storage, "Movies"),
            File(storage, "Android/media")
        )
        val visited = ConcurrentHashMap.newKeySet<String>()
        targets.forEach { directory ->
            val monitorRoot = runCatching { directory.canonicalFile }.getOrNull() ?: return@forEach
            if (monitorRoot.isDirectory && SharedStoragePathPolicy.isWithinRoot(monitorRoot, storageRoot)) {
                watchTree(monitorRoot, monitorRoot, depth = 0, visited = visited)
            }
        }

        val status = when {
            observers.isNotEmpty() && packageReceiverRegistered ->
                "پایش محدود فعال است: ${observers.size} ناظر پوشه و رویدادهای نصب برنامه‌ها. داده خصوصی برنامه‌ها و ترافیک شبکه پایش نمی‌شود."
            observers.isNotEmpty() ->
                "پایش محدود فعال است: ${observers.size} ناظر پوشه. فهرست برنامه‌های نصب‌شده تحت رضایت کاربر فعال نیست و ترافیک شبکه پایش نمی‌شود."
            packageReceiverRegistered ->
                "پایش فایل حافظه مشترک فعال نیست؛ فقط رویدادهای نصب یا به‌روزرسانی برنامه‌ها پایش می‌شوند."
            else ->
                "در این نشست هیچ پوشه فایل یا رویداد نصب برنامه‌ای تحت پایش نیست."
        }
        updateProtectionNotification(status)
    }

    /**
     * Immediately detach every watcher when Android storage access is revoked.
     * The pending scan queue is still bounded; scanFile also re-checks access
     * before opening a queued path, so stale events cannot continue scanning.
     */
    private fun stopFileMonitoring() {
        observers.toList().forEach { observer ->
            runCatching { observer.stopWatching() }
            if (observers.remove(observer)) releaseWatcherSlot()
        }
        observers.clear()
        synchronized(watchedPaths) { watchedPaths.clear() }
    }

    private fun watchTree(directory: File, allowedRoot: File, depth: Int, visited: MutableSet<String>) {
        if (depth > MAX_WATCH_DEPTH || activeWatcherCount.get() >= MAX_WATCHERS) return
        val canonical = runCatching { directory.canonicalFile }.getOrNull() ?: return
        if (!canonical.isDirectory || !SharedStoragePathPolicy.isWithinRoot(canonical, allowedRoot) ||
            !synchronized(visited) { visited.add(canonical.path) }
        ) return
        synchronized(watchedPaths) {
            if (!watchedPaths.add(canonical.path)) return
        }

        val mask = FileObserver.CLOSE_WRITE or
            FileObserver.MOVED_TO or
            FileObserver.CREATE or
            FileObserver.DELETE_SELF or
            FileObserver.MOVE_SELF
        var observer: FileObserver? = null
        if (!reserveWatcherSlot()) {
            synchronized(watchedPaths) { watchedPaths.remove(canonical.path) }
            visited.remove(canonical.path)
            return
        }
        try {
            observer = object : FileObserver(canonical.absolutePath, mask) {
                override fun onEvent(event: Int, path: String?) {
                    if ((event and (FileObserver.DELETE_SELF or FileObserver.MOVE_SELF)) != 0) {
                        synchronized(watchedPaths) { watchedPaths.remove(canonical.path) }
                        visited.remove(canonical.path)
                        if (observers.remove(this)) releaseWatcherSlot()
                        runCatching { stopWatching() }
                        return
                    }

                    val relative = path ?: return
                    val target = File(canonical, relative)
                    if (!SharedStoragePathPolicy.isWithinRoot(target, allowedRoot)) return
                    val isDirectory = target.isDirectory
                    if (isDirectory &&
                        ((event and FileObserver.CREATE) != 0 || (event and FileObserver.MOVED_TO) != 0)
                    ) {
                        serviceScope.launch { watchTree(target, allowedRoot, depth + 1, visited) }
                    } else if (!isDirectory &&
                        ((event and FileObserver.CLOSE_WRITE) != 0 || (event and FileObserver.MOVED_TO) != 0)
                    ) {
                        enqueueFileScan(target, allowedRoot)
                    }
                }
            }
            observers += observer
            observer.startWatching()
        } catch (_: Exception) {
            observer?.let {
                if (observers.remove(it)) releaseWatcherSlot()
            } ?: releaseWatcherSlot()
            synchronized(watchedPaths) { watchedPaths.remove(canonical.path) }
            visited.remove(canonical.path)
            // One inaccessible directory must not stop the remaining watchers.
        }

        if (depth < MAX_WATCH_DEPTH && observers.size < MAX_WATCHERS) {
            runCatching { canonical.listFiles() }.getOrNull()
                ?.filter { it.isDirectory && !it.name.startsWith(".") }
                ?.forEach { watchTree(it, allowedRoot, depth + 1, visited) }
        }
    }

    /**
     * FileObserver callbacks must stay cheap. A bounded channel and one consumer
     * keep bursts of file events from creating an unbounded number of scan jobs.
     */
    private fun reserveWatcherSlot(): Boolean {
        while (true) {
            val current = activeWatcherCount.get()
            if (current >= MAX_WATCHERS) return false
            if (activeWatcherCount.compareAndSet(current, current + 1)) return true
        }
    }

    private fun releaseWatcherSlot() {
        activeWatcherCount.updateAndGet { current -> (current - 1).coerceAtLeast(0) }
    }

    private fun startFileScanWorker() {
        if (scanWorkerStarted) return
        scanWorkerStarted = true
        serviceScope.launch {
            for (request in scanQueue) {
                try {
                    // Coalesce close/move notifications long enough for writers to settle.
                    delay(SCAN_EVENT_SETTLE_MS)
                    scanFile(request.file, request.allowedRoot)
                } finally {
                    pendingScans.release(request.canonicalPath)
                    if (pendingScans.size() == 0) {
                        overflowAlertPosted.set(false)
                    }
                }
            }
        }
    }

    private fun enqueueFileScan(file: File, allowedRoot: File) {
        val canonical = runCatching { file.canonicalFile }.getOrNull() ?: return
        if (!canonical.isFile || !SharedStoragePathPolicy.isWithinRoot(canonical, allowedRoot)) return

        val path = canonical.path
        when (pendingScans.reserve(path)) {
            PendingScanReservation.DUPLICATE -> return
            PendingScanReservation.FULL -> {
                reportScanQueueOverflow()
                return
            }
            PendingScanReservation.RESERVED -> {
                if (scanQueue.trySend(PendingFileScan(canonical, allowedRoot, path)).isFailure) {
                    pendingScans.release(path)
                    reportScanQueueOverflow()
                }
            }
        }
    }

    private fun reportScanQueueOverflow() {
        if (overflowAlertPosted.compareAndSet(false, true)) {
            postUnverifiedAlert(
                "پایش فایل‌ها",
                "صف محدود بررسی پر شد. دست‌کم یک رویداد فایل برای جلوگیری از مصرف بیش از حد منابع وارد صف نشد؛ آن فایل بررسی‌شده محسوب نمی‌شود."
            )
        }
    }

    private suspend fun scanInstalledPackage(packageName: String) {
        if (!InstalledAppInventoryConsent.isGranted(this)) return
        try {
            val info = if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getApplicationInfo(
                    packageName,
                    PackageManager.ApplicationInfoFlags.of(0L)
                )
            } else {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(packageName, 0)
            }
            // Modern Android apps may consist of a base APK plus split APKs.
            // Check every readable component instead of silently checking only the base.
            val hasBaseApkPath = !info.sourceDir.isNullOrBlank()
            val apkPaths = (listOfNotNull(info.sourceDir) + info.splitSourceDirs.orEmpty())
                .distinct()
            if (apkPaths.isEmpty()) {
                postUnverifiedAlert(packageName, "Android did not expose an APK path for this installed app.")
                return
            }

            var checkedComponents = 0
            // A readable split cannot hide a missing/unreadable base APK component.
            var incomplete = !hasBaseApkPath
            for (path in apkPaths) {
                if (!InstalledAppInventoryConsent.isGranted(this)) {
                    incomplete = true
                    break
                }
                val apk = File(path)
                if (!apk.isFile || !apk.canRead() || apk.length() <= 0L ||
                    apk.length() > ScanEngine.MAX_FILE_SIZE_BYTES
                ) {
                    incomplete = true
                    continue
                }
                checkedComponents++
                val result = ScanEngine.scan(applicationContext, Uri.fromFile(apk))
                when (result.verdict) {
                    ScanVerdict.KNOWN_MALWARE,
                    ScanVerdict.POTENTIALLY_UNWANTED,
                    ScanVerdict.SUSPICIOUS -> postThreatAlert(packageName, result.verdict)
                    ScanVerdict.UNKNOWN_APK,
                    ScanVerdict.UNSUPPORTED_FILE,
                    ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE -> incomplete = true
                    else -> Unit
                }
            }
            if (checkedComponents == 0 || incomplete) {
                postUnverifiedAlert(
                    packageName,
                    if (checkedComponents == 0) {
                        "No installed APK component could be read and checked."
                    } else {
                        "One or more APK components could not be fully checked."
                    }
                )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            // An inaccessible package is unknown, never silently marked clean.
            postUnverifiedAlert(
                packageName,
                error.message ?: "Android did not allow the installed app to be checked."
            )
        }
    }

    private suspend fun scanFile(file: File, allowedRoot: File, displayName: String = file.name) {
        try {
            if (!DeviceScanEngine.hasBroadStorageAccess(this)) {
                postUnverifiedAlert(displayName, "Shared-storage access was revoked before this queued file could be scanned.")
                return
            }
            // Re-resolve immediately before opening: a queued path may have been
            // replaced with a symbolic link or redirected outside the monitored root.
            val canonical = runCatching { file.canonicalFile }.getOrNull()
            if (canonical == null || !SharedStoragePathPolicy.isWithinRoot(canonical, allowedRoot)) {
                postUnverifiedAlert(displayName, "The file path changed or escaped the monitored folder; it was not scanned.")
                return
            }
            if (!canonical.isFile) return
            if (!canonical.canRead()) {
                postUnverifiedAlert(displayName, "The file is not readable by this app; no content scan was completed.")
                return
            }
            val size = canonical.length()
            if (size > ScanEngine.MAX_FILE_SIZE_BYTES) {
                postUnverifiedAlert(
                    displayName,
                    "The file exceeds the configured ${ScanEngine.MAX_FILE_SIZE_BYTES}-byte scan limit and was not scanned."
                )
                return
            }

            val result = ScanEngine.scan(applicationContext, Uri.fromFile(canonical))
            when (result.verdict) {
                ScanVerdict.KNOWN_MALWARE,
                ScanVerdict.POTENTIALLY_UNWANTED,
                ScanVerdict.SUSPICIOUS -> postThreatAlert(displayName, result.verdict)
                ScanVerdict.UNKNOWN_APK -> postUnverifiedAlert(
                    displayName,
                    "APK metadata could not be fully analyzed; this file is not declared clean."
                )
                ScanVerdict.UNSUPPORTED_FILE -> postUnverifiedAlert(
                    displayName,
                    "This file format has no content-aware analyzer in the current build."
                )
                ScanVerdict.INCOMPLETE_THREAT_INTELLIGENCE -> postUnverifiedAlert(
                    displayName,
                    "A current authenticated threat-intelligence feed is unavailable or expired."
                )
                else -> Unit
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            postUnverifiedAlert(
                displayName,
                error.message ?: "The scan failed before a complete result could be produced."
            )
        }
    }

    private fun postThreatAlert(name: String, verdict: ScanVerdict) {
        val manager = getSystemService(NotificationManager::class.java)
        val label = when (verdict) {
            ScanVerdict.KNOWN_MALWARE -> "بدافزار شناخته‌شده"
            ScanVerdict.POTENTIALLY_UNWANTED -> "برنامه یا فایل ناخواسته"
            else -> "فایل مشکوک"
        }
        val notification = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("ANTIVIRUS AL AI · $label")
            .setContentText(name)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$label شناسایی شد: $name. برای بررسی و تصمیم درباره قرنطینه، برنامه را باز کنید."))
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        runCatching {
            manager.notify((name.hashCode() and 0x7fffffff).coerceAtLeast(1), notification)
        }
    }

    private fun postUnverifiedAlert(name: String, reason: String) {
        val manager = getSystemService(NotificationManager::class.java)
        val notification = NotificationCompat.Builder(this, UNVERIFIED_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("ANTIVIRUS AL AI · نتیجه نامشخص")
            .setContentText(name)
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    "بررسی کامل این برنامه ممکن نشد: $name. این نتیجه به معنی پاک بودن برنامه نیست. $reason"
                )
            )
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        // Unverified results share one low-priority notification to avoid
        // generating dozens of alerts when a folder contains unsupported files.
        runCatching {
            manager.notify(UNVERIFIED_NOTIFICATION_ID, notification)
        }
    }

    private fun packageNameForSelf(): String = applicationContext.packageName

    companion object {
        const val ACTION_STOP = "com.antivirusalai.action.STOP_PROTECTION"
        private const val CHANNEL_ID = "alai-protection-service"
        private const val ALERT_CHANNEL_ID = "alai-protection-alerts"
        private const val UNVERIFIED_CHANNEL_ID = "alai-protection-unverified"
        private const val NOTIFICATION_ID = 4108
        private const val UNVERIFIED_NOTIFICATION_ID = 4110
        private const val MAX_WATCH_DEPTH = 2
        private const val MAX_WATCHERS = 96
        private const val MAX_PENDING_SCANS = 64
        private const val SCAN_EVENT_SETTLE_MS = 350L
    }
}
