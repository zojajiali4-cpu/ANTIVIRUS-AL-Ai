package com.antivirusalai.engine

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuickScanPolicyTest {
    private val root = File("/storage/emulated/0")

    @Test
    fun quickScanIncludesPriorityIngressFoldersAndAndroidMedia() {
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Download")))
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Downloads")))
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Documents")))
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Bluetooth")))
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Android")))
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Android/media")))
        assertTrue(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Android/media/com.example.app")))
    }

    @Test
    fun quickScanDoesNotDescendIntoBulkMediaOrProtectedAndroidFolders() {
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "DCIM")))
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Pictures")))
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Movies")))
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Music")))
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Android/data")))
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Android/obb")))
        assertFalse(QuickScanPolicy.shouldVisitDirectory(root, File(root, "Android/other")))
    }

    @Test
    fun executableAndArchiveFilesArePrioritizedBeforeOrdinaryFiles() {
        val apk = File(root, "Download/update.apk")
        val document = File(root, "Download/notes.pdf")
        val image = File(root, "Download/photo.jpg")
        assertTrue(QuickScanPolicy.priority(root, apk) < QuickScanPolicy.priority(root, document))
        assertTrue(QuickScanPolicy.priority(root, document) < QuickScanPolicy.priority(root, image))
    }

    @Test
    fun childOrderingKeepsHighRiskFilesAheadOfOrdinaryFiles() {
        val apk = File(root, "Download/update.apk")
        val image = File(root, "Download/photo.jpg")
        val ordered = QuickScanPolicy.orderChildren(root, File(root, "Download"), arrayOf(image, apk))
        assertEquals(apk, ordered.first())
    }
}
