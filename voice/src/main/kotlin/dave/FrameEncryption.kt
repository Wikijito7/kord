package dev.kord.voice.dave

import dev.kord.common.entity.Snowflake
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Implements frame encryption and decryption for the DAVE protocol using AES128-GCM.
 * 
 * Media frames are encrypted for E2EE using AES128-GCM with truncated authentication tags
 * and variable-length ULEB128 encoded nonces.
 */
public class FrameEncryption {
    
    companion object {
        private const val AES_KEY_LENGTH = 16 // AES128
        private const val GCM_NONCE_LENGTH = 12 // Full AES-GCM nonce length
        private const val TRUNCATED_NONCE_LENGTH = 4 // Protocol uses up to 4 bytes
        private const val TRUNCATED_TAG_LENGTH = 8 // 8-byte truncated auth tag
        private const val MAGIC_MARKER = 0xFAFA.toShort()
    }
    
    /**
     * Encrypts an OPUS audio frame using the DAVE protocol format.
     * 
     * @param frame The raw OPUS frame to encrypt
     * @param senderKey The AES key for the sender
     * @param truncatedNonce The 4-byte truncated nonce
     * @return The encrypted protocol frame
     */
    public fun encryptFrame(frame: ByteArray, senderKey: ByteArray, truncatedNonce: Int): ByteArray {
        require(senderKey.size == AES_KEY_LENGTH) { "Sender key must be $AES_KEY_LENGTH bytes" }
        
        // For OPUS frames, the entire frame is encrypted (no unencrypted ranges)
        val fullNonce = expandNonce(truncatedNonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(senderKey, "AES")
        val gcmSpec = GCMParameterSpec(96, fullNonce) // 96-bit tag (will be truncated)
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        
        // Encrypt the frame - this returns ciphertext + full 12-byte auth tag
        val encryptedData = cipher.doFinal(frame)
        
        // Split ciphertext and authentication tag
        val ciphertext = encryptedData.copyOf(encryptedData.size - 12)
        val fullAuthTag = encryptedData.copyOfRange(encryptedData.size - 12, encryptedData.size)
        val truncatedAuthTag = fullAuthTag.copyOf(TRUNCATED_TAG_LENGTH)
        
        // Encode nonce and unencrypted ranges using ULEB128
        val encodedNonce = encodeULEB128(truncatedNonce)
        val encodedUnencryptedRanges = encodeULEB128(0) // Empty for OPUS frames
        
        // Calculate supplemental data size
        val supplementalDataSize = (TRUNCATED_TAG_LENGTH + encodedNonce.size + 
                                   encodedUnencryptedRanges.size + 1 + 2).toByte()
        
        // Build the protocol frame
        return ByteBuffer.allocate(
            ciphertext.size + TRUNCATED_TAG_LENGTH + encodedNonce.size + 
            encodedUnencryptedRanges.size + 1 + 2
        ).apply {
            put(ciphertext)
            put(truncatedAuthTag)
            put(encodedNonce)
            put(encodedUnencryptedRanges)
            put(supplementalDataSize)
            putShort(MAGIC_MARKER)
        }.array()
    }
    
    /**
     * Decrypts a DAVE protocol frame.
     * 
     * @param protocolFrame The encrypted protocol frame
     * @param senderKey The AES key for the sender
     * @return The decrypted OPUS frame, or null if decryption fails
     */
    public fun decryptFrame(protocolFrame: ByteArray, senderKey: ByteArray): ByteArray? {
        require(senderKey.size == AES_KEY_LENGTH) { "Sender key must be $AES_KEY_LENGTH bytes" }
        
        if (!isValidProtocolFrame(protocolFrame)) {
            return null
        }
        
        try {
            // Parse protocol frame from the end
            val buffer = ByteBuffer.wrap(protocolFrame).order(ByteOrder.BIG_ENDIAN)
            
            // Read magic marker (last 2 bytes)
            val magicMarker = buffer.getShort(protocolFrame.size - 2)
            if (magicMarker != MAGIC_MARKER) {
                return null
            }
            
            // Read supplemental data size (1 byte before magic marker)
            val supplementalDataSize = protocolFrame[protocolFrame.size - 3].toInt() and 0xFF
            
            // Calculate positions
            val supplementalDataStart = protocolFrame.size - supplementalDataSize
            val ciphertextLength = supplementalDataStart - TRUNCATED_TAG_LENGTH
            
            if (ciphertextLength <= 0) {
                return null
            }
            
            // Extract components
            val ciphertext = protocolFrame.copyOf(ciphertextLength)
            val truncatedAuthTag = protocolFrame.copyOfRange(ciphertextLength, supplementalDataStart)
            
            // Parse supplemental data to get nonce
            val supplementalData = protocolFrame.copyOfRange(supplementalDataStart, protocolFrame.size - 3)
            var offset = 0
            
            // Skip auth tag (already extracted)
            offset += TRUNCATED_TAG_LENGTH
            
            // Decode nonce
            val (truncatedNonce, nonceLength) = decodeULEB128(supplementalData, offset - TRUNCATED_TAG_LENGTH)
            if (truncatedNonce == -1) {
                return null
            }
            
            val fullNonce = expandNonce(truncatedNonce)
            
            // Reconstruct full auth tag by padding with zeros
            val fullAuthTag = ByteArray(12)
            System.arraycopy(truncatedAuthTag, 0, fullAuthTag, 0, TRUNCATED_TAG_LENGTH)
            
            // Decrypt using AES-GCM
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(senderKey, "AES")
            val gcmSpec = GCMParameterSpec(96, fullNonce)
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            
            // Combine ciphertext and full auth tag for decryption
            val encryptedData = ByteArray(ciphertext.size + 12)
            System.arraycopy(ciphertext, 0, encryptedData, 0, ciphertext.size)
            System.arraycopy(fullAuthTag, 0, encryptedData, ciphertext.size, 12)
            
            return cipher.doFinal(encryptedData)
            
        } catch (e: Exception) {
            return null
        }
    }
    
    /**
     * Checks if a frame is a valid DAVE protocol frame.
     */
    public fun isValidProtocolFrame(frame: ByteArray): Boolean {
        if (frame.size < 13) { // Minimum size: 1 byte ciphertext + 8 auth tag + 1 nonce + 1 ranges + 1 size + 2 magic
            return false
        }
        
        // Check magic marker
        val magicMarker = ByteBuffer.wrap(frame).getShort(frame.size - 2)
        if (magicMarker != MAGIC_MARKER) {
            return false
        }
        
        // Check supplemental data size
        val supplementalDataSize = frame[frame.size - 3].toInt() and 0xFF
        if (supplementalDataSize < 12 || supplementalDataSize >= frame.size) { // Min: 8 tag + 1 nonce + 1 ranges + 1 size + 2 magic
            return false
        }
        
        return true
    }
    
    /**
     * Generates the generation number from a truncated nonce (most significant byte).
     */
    public fun getGenerationFromNonce(truncatedNonce: Int): Int {
        return (truncatedNonce ushr 24) and 0xFF
    }
    
    /**
     * Expands a 4-byte truncated nonce to a full 12-byte GCM nonce.
     */
    private fun expandNonce(truncatedNonce: Int): ByteArray {
        val fullNonce = ByteArray(GCM_NONCE_LENGTH)
        // Write truncated nonce to the 4 least significant bytes
        ByteBuffer.wrap(fullNonce).order(ByteOrder.BIG_ENDIAN).putInt(8, truncatedNonce)
        return fullNonce
    }
    
    /**
     * Encodes an integer using ULEB128 (Unsigned Little Endian Base 128).
     */
    private fun encodeULEB128(value: Int): ByteArray {
        val result = mutableListOf<Byte>()
        var remaining = value
        
        while (remaining >= 0x80) {
            result.add((0x80 or (remaining and 0x7F)).toByte())
            remaining = remaining ushr 7
        }
        result.add(remaining.toByte())
        
        return result.toByteArray()
    }
    
    /**
     * Decodes a ULEB128 encoded integer.
     * 
     * @param data The byte array containing the encoded value
     * @param offset The offset to start reading from
     * @return Pair of (decoded value, bytes consumed), or (-1, 0) on error
     */
    private fun decodeULEB128(data: ByteArray, offset: Int): Pair<Int, Int> {
        var result = 0
        var shift = 0
        var bytesRead = 0
        
        while (offset + bytesRead < data.size) {
            val byte = data[offset + bytesRead].toInt() and 0xFF
            bytesRead++
            
            result = result or ((byte and 0x7F) shl shift)
            
            if ((byte and 0x80) == 0) {
                return Pair(result, bytesRead)
            }
            
            shift += 7
            if (shift >= 32) { // Prevent overflow
                return Pair(-1, 0)
            }
        }
        
        return Pair(-1, 0) // Incomplete encoding
    }
}
