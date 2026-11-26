package com.antivirusalai

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CleanerPolicyTest {
    @Test
    fun recognizesOnlyNarrowTemporaryExtensions() {
        assertTrue(CleanerPolicy.isLikelyTemporaryName("download.part"))
        assertTrue(CleanerPolicy.isLikelyTemporaryName("video.crdownload"))
        assertTrue(CleanerPolicy.isLikelyTemporaryName("session.tmp"))
        assertTrue(CleanerPolicy.isLikelyTemporaryName("item.cache"))
        assertFalse(CleanerPolicy.isLikelyTemporaryName("family-photo.jpg"))
        assertFalse(CleanerPolicy.isLikelyTemporaryName("invoice.pdf"))
    }

    @Test
    fun marksPotentiallyImportantExtensionsForReviewInsteadOfJunk() {
        assertTrue(CleanerPolicy.needsManualReviewName("diagnostic.log"))
        assertTrue(CleanerPolicy.needsManualReviewName("backup.old"))
        assertTrue(CleanerPolicy.needsManualReviewName("profile.bak"))
        assertFalse(CleanerPolicy.isLikelyTemporaryName("diagnostic.log"))
    }

    @Test
    fun protectsAndroidPrivateAndObbFoldersButAllowsMedia() {
        assertTrue(CleanerPolicy.isProtectedRelativePath("Android/data/com.example"))
        assertTrue(CleanerPolicy.isProtectedRelativePath("Android/obb/com.example"))
        assertTrue(CleanerPolicy.isProtectedRelativePath("Android/cache"))
        assertFalse(CleanerPolicy.isProtectedRelativePath("Android"))
        assertFalse(CleanerPolicy.isProtectedRelativePath("Android/media/com.example"))
        assertFalse(CleanerPolicy.isProtectedRelativePath("Download"))
    }

    @Test
    fun pathMustRemainInsideStorageRoot() {
        val root = File("/storage/emulated/0")
        assertTrue(CleanerPolicy.isWithinRoot(File("/storage/emulated/0/Download/file.tmp"), root))
        assertFalse(CleanerPolicy.isWithinRoot(File("/storage/emulated/0-backup/file.tmp"), root))
        assertFalse(CleanerPolicy.isWithinRoot(File("/data/user/0/com.example/files"), root))
    }

    @Test
    fun byteTotalsSaturateInsteadOfOverflowing() {
        assertEquals(Long.MAX_VALUE, CleanerPolicy.saturatedAdd(Long.MAX_VALUE - 2, 10))
        assertEquals(17L, CleanerPolicy.saturatedAdd(10L, 7L))
    }
}
