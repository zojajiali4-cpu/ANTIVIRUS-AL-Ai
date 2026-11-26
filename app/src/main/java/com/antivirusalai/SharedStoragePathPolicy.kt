package com.antivirusalai

import java.io.File

/**
 * Enforces the directory boundary for real-time file monitoring.
 *
 * Both paths are canonicalized so symbolic links and ".." components cannot
 * make a monitored file escape the folder tree that the user-enabled watcher
 * was created for. Any path that cannot be resolved is rejected.
 */
internal object SharedStoragePathPolicy {
    fun isWithinRoot(candidate: File, allowedRoot: File): Boolean {
        return try {
            val rootPath = allowedRoot.canonicalFile.toPath().normalize()
            val candidatePath = candidate.canonicalFile.toPath().normalize()
            candidatePath == rootPath || candidatePath.startsWith(rootPath)
        } catch (_: Exception) {
            false
        }
    }
}
