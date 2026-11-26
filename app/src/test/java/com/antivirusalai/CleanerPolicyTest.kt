package com.antivirusalai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CleanerPolicyTest {
    @Test
    fun recognizesOnlyExplicitTemporaryExtensions() {
        assertTrue(CleanerPolicy.isTemporaryName("download.part"))
        assertTrue(CleanerPolicy.isTemporaryName("old-cache.tmp"))
        assertEquals(false, CleanerPolicy.isTemporaryName("family-photo.jpg"))
        assertEquals(false, CleanerPolicy.isTemporaryName("invoice.pdf"))
    }

    @Test
    fun doesNotClassifyDirectoriesOrUnknownNamesAsTemporary() {
        assertEquals(false, CleanerPolicy.isTemporaryName("folder"))
        assertEquals(false, CleanerPolicy.isTemporaryName("archive.zip"))
    }
}
