package com.antivirusalai

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Test
import java.nio.file.Files

class SharedStoragePathPolicyTest {
    @Test
    fun acceptsOnlyTheAllowedRootAndItsDescendants() {
        val base = Files.createTempDirectory("alai-path-policy-").toFile()
        try {
            val root = java.io.File(base, "Downloads").apply { mkdirs() }
            val nested = java.io.File(root, "nested").apply { mkdirs() }
            val outside = java.io.File(base, "Documents").apply { mkdirs() }

            assertTrue(SharedStoragePathPolicy.isWithinRoot(root, root))
            assertTrue(SharedStoragePathPolicy.isWithinRoot(java.io.File(nested, "sample.apk"), root))
            assertFalse(SharedStoragePathPolicy.isWithinRoot(outside, root))
        } finally {
            base.deleteRecursively()
        }
    }

    @Test
    fun rejectsSymlinkThatEscapesTheMonitoredFolder() {
        val base = Files.createTempDirectory("alai-symlink-policy-").toFile()
        try {
            val root = java.io.File(base, "Downloads").apply { mkdirs() }
            val outside = java.io.File(base, "Private").apply { mkdirs() }
            val outsideFile = java.io.File(outside, "private.dat").apply { writeText("fixture") }
            val link = java.io.File(root, "redirect")

            try {
                Files.createSymbolicLink(link.toPath(), outside.toPath())
            } catch (error: Exception) {
                Assume.assumeNoException("Symbolic links are unavailable on this test host.", error)
            }

            assertFalse(
                SharedStoragePathPolicy.isWithinRoot(java.io.File(link, outsideFile.name), root)
            )
        } finally {
            base.deleteRecursively()
        }
    }
}
