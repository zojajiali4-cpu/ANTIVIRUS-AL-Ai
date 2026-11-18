package com.antivirusalai.remediation

import android.content.Context
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Properties
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class QuarantineReceipt(val id: String, val sizeBytes: Long, val sha256: String)

data class QuarantineEntry(
    val id: String,
    val sizeBytes: Long,
    val sha256: String,
    val savedAtEpochSeconds: Long
)

object QuarantineManager {
    private const val KEY_ALIAS = "antivirus_al_ai_quarantine_v1"
    private val MAGIC = "ALAIQ1".toByteArray(Charsets.US_ASCII)
    private const val MAX_SIZE = 200L * 1024L * 1024L
    private const val IV_SIZE = 12
    private const val TAG_BITS = 128
    private val idPattern = Regex("[0-9a-fA-F-]{36}")
    private val hashPattern = Regex("[0-9a-f]{64}")

    /**
     * Writes an AES-GCM encrypted copy in app-private storage and verifies the
     * plaintext SHA-256. The selected source is intentionally not deleted.
     */
    suspend fun saveEncryptedCopy(
        context: Context,
        source: Uri,
        expectedSha256: String
    ): QuarantineReceipt = withContext(Dispatchers.IO) {
        require(hashPattern.matches(expectedSha256.lowercase())) {
            "Expected SHA-256 is invalid."
        }
        val directory = directory(context)
        val id = UUID.randomUUID().toString()
        val temporary = File.createTempFile("incoming-", ".part", directory)
        val destination = File(directory, "$id.alaiq")
        val metadata = File(directory, "$id.meta")
        val digest = MessageDigest.getInstance("SHA-256")
        var totalBytes = 0L

        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())

            val input = openSource(context, source)
            input.use { sourceStream ->
                FileOutputStream(temporary).use { fileStream ->
                    fileStream.write(MAGIC)
                    fileStream.write(cipher.iv.size)
                    fileStream.write(cipher.iv)

                    val buffer = ByteArray(8192)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = sourceStream.read(buffer)
                        if (count < 0) break
                        totalBytes += count
                        require(totalBytes <= MAX_SIZE) {
                            "File exceeds the 200 MB quarantine limit."
                        }
                        digest.update(buffer, 0, count)
                        cipher.update(buffer, 0, count)?.let(fileStream::write)
                    }

                    fileStream.write(cipher.doFinal())
                    fileStream.fd.sync()
                }
            }

            val actualHash = digest.digest().toHex()
            check(actualHash == expectedSha256.lowercase()) {
                "The source file changed after scanning. The quarantine copy was discarded."
            }

            atomicMove(temporary, destination)
            writeMetadata(
                metadata,
                QuarantineEntry(
                    id = id,
                    sizeBytes = totalBytes,
                    sha256 = actualHash,
                    savedAtEpochSeconds = System.currentTimeMillis() / 1000L
                )
            )
            QuarantineReceipt(id = id, sizeBytes = totalBytes, sha256 = actualHash)
        } catch (error: Exception) {
            temporary.delete()
            destination.delete()
            metadata.delete()
            throw error
        }
    }

    /** Returns only entries with a valid metadata receipt and encrypted payload. */
    fun list(context: Context): List<QuarantineEntry> {
        val dir = directory(context)
        return dir.listFiles { file -> file.isFile && file.name.endsWith(".meta") }
            .orEmpty()
            .mapNotNull { metadata ->
                val id = metadata.name.removeSuffix(".meta")
                if (!idPattern.matches(id)) return@mapNotNull null
                readEntry(dir, id)
            }
            .sortedByDescending { it.savedAtEpochSeconds }
    }

    /**
     * Decrypts and authenticates into a private temporary file first.
     * The user-selected destination is written only after tag, size and hash
     * validation all pass.
     */
    suspend fun restoreTo(
        context: Context,
        id: String,
        destination: Uri
    ): QuarantineEntry = withContext(Dispatchers.IO) {
        require(idPattern.matches(id)) { "Quarantine identifier is invalid." }
        val dir = directory(context)
        val entry = readEntry(dir, id) ?: error("Quarantine item was not found.")
        val encrypted = File(dir, "$id.alaiq")
        val temporary = File.createTempFile("alai-restore-", ".tmp", context.cacheDir)
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L

        try {
            DataInputStream(FileInputStream(encrypted).buffered()).use { input ->
                val magic = ByteArray(MAGIC.size)
                input.readFully(magic)
                check(magic.contentEquals(MAGIC)) { "Quarantine header is invalid." }
                val ivLength = input.readUnsignedByte()
                check(ivLength == IV_SIZE) { "Quarantine IV is invalid." }
                val iv = ByteArray(ivLength)
                input.readFully(iv)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    getOrCreateKey(),
                    GCMParameterSpec(TAG_BITS, iv)
                )

                FileOutputStream(temporary).use { output ->
                    val buffer = ByteArray(8192)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = input.read(buffer)
                        if (count < 0) break
                        val plain = cipher.update(buffer, 0, count)
                        if (plain != null && plain.isNotEmpty()) {
                            total += plain.size
                            require(total <= MAX_SIZE) { "Quarantine item exceeds restore limit." }
                            digest.update(plain)
                            output.write(plain)
                        }
                    }
                    val tail = cipher.doFinal()
                    if (tail.isNotEmpty()) {
                        total += tail.size
                        require(total <= MAX_SIZE) { "Quarantine item exceeds restore limit." }
                        digest.update(tail)
                        output.write(tail)
                    }
                    output.fd.sync()
                }
            }

            check(total == entry.sizeBytes && digest.digest().toHex() == entry.sha256) {
                "Quarantine integrity check failed. Nothing was restored."
            }

            val output = context.contentResolver.openOutputStream(destination, "wt")
                ?: error("Android could not open the selected restore destination.")
            output.use { target ->
                temporary.inputStream().use { source -> source.copyTo(target) }
                target.flush()
            }
            entry
        } finally {
            temporary.delete()
        }
    }

    /** Removes only the selected encrypted copy and metadata, never the original source. */
    fun deleteCopy(context: Context, id: String): Boolean {
        require(idPattern.matches(id)) { "Quarantine identifier is invalid." }
        val dir = directory(context)
        val encrypted = File(dir, "$id.alaiq")
        val metadata = File(dir, "$id.meta")
        if (!encrypted.exists() && !metadata.exists()) return false
        val encryptedDeleted = !encrypted.exists() || encrypted.delete()
        val metadataDeleted = !metadata.exists() || metadata.delete()
        return encryptedDeleted && metadataDeleted
    }

    private fun directory(context: Context): File =
        File(context.applicationContext.filesDir, "quarantine").also {
            check(it.exists() || it.mkdirs()) { "Could not create the private quarantine directory." }
        }

    private fun writeMetadata(file: File, entry: QuarantineEntry) {
        val temporary = File.createTempFile("meta-", ".part", file.parentFile)
        try {
            val properties = Properties().apply {
                setProperty("sizeBytes", entry.sizeBytes.toString())
                setProperty("sha256", entry.sha256)
                setProperty("savedAtEpochSeconds", entry.savedAtEpochSeconds.toString())
            }
            FileOutputStream(temporary).use { output ->
                properties.store(output, "ANTIVIRUS AL AI quarantine receipt")
                output.fd.sync()
            }
            atomicMove(temporary, file)
        } finally {
            temporary.delete()
        }
    }

    private fun readEntry(directory: File, id: String): QuarantineEntry? {
        val metadata = File(directory, "$id.meta")
        val encrypted = File(directory, "$id.alaiq")
        if (!metadata.isFile || !encrypted.isFile) return null
        return runCatching {
            val properties = Properties().apply { metadata.inputStream().use(::load) }
            val size = properties.getProperty("sizeBytes")?.toLongOrNull() ?: return null
            val hash = properties.getProperty("sha256") ?: return null
            val savedAt = properties.getProperty("savedAtEpochSeconds")?.toLongOrNull() ?: return null
            if (size < 0 || size > MAX_SIZE || !hashPattern.matches(hash) || savedAt <= 0) return null
            QuarantineEntry(id, size, hash, savedAt)
        }.getOrNull()
    }

    private fun openSource(context: Context, source: Uri) =
        if (source.scheme == "file") {
            FileInputStream(File(source.path ?: error("Source path is invalid.")))
        } else {
            context.contentResolver.openInputStream(source)
                ?: error("Android could not open the source file.")
        }

    private fun atomicMove(source: File, destination: File) {
        try {
            java.nio.file.Files.move(
                source.toPath(),
                destination.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING
            )
        } catch (_: Exception) {
            check(source.renameTo(destination)) { "Could not finalize quarantine file." }
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun ByteArray.toHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}
