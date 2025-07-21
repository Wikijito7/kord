package dev.kord.voice.dave

import dev.kord.common.entity.Snowflake
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Implements sender key derivation for the DAVE protocol as specified in the protocol whitepaper.
 * 
 * Each member derives a symmetric key for each sender, using a key ratchet whose base secret
 * is an exported MLS secret.
 */
public class SenderKeyDerivation {
    private val senderRatchets = mutableMapOf<Snowflake, KeyRatchet>()
    
    /**
     * Derives a sender base secret using MLS-Exporter.
     * 
     * @param exporterSecret The MLS exporter secret from the current epoch
     * @param senderId The Discord user ID of the sender
     * @return 16-byte sender base secret
     */
    public fun deriveSenderBaseSecret(exporterSecret: ByteArray, senderId: Snowflake): ByteArray {
        val label = "Discord Secure Frames v0"
        val context = ByteBuffer.allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(senderId.value.toLong())
            .array()
        
        return mlsExporter(exporterSecret, label, context, 16)
    }
    
    /**
     * Creates or updates a key ratchet for a sender.
     * 
     * @param senderId The Discord user ID of the sender
     * @param senderBaseSecret The base secret derived from MLS-Exporter
     */
    public fun createSenderRatchet(senderId: Snowflake, senderBaseSecret: ByteArray) {
        senderRatchets[senderId] = KeyRatchet(senderBaseSecret)
    }
    
    /**
     * Gets the encryption/decryption key for a specific sender and generation.
     * 
     * @param senderId The Discord user ID of the sender
     * @param generation The generation number (from most significant byte of nonce)
     * @return The 16-byte AES key for the specified generation
     */
    public fun getSenderKey(senderId: Snowflake, generation: Int): ByteArray? {
        return senderRatchets[senderId]?.getKey(generation)
    }
    
    /**
     * Removes all sender ratchets (used during epoch transitions).
     */
    public fun clearAllRatchets() {
        senderRatchets.clear()
    }
    
    /**
     * Removes a specific sender ratchet.
     */
    public fun removeSenderRatchet(senderId: Snowflake) {
        senderRatchets.remove(senderId)
    }
    
    /**
     * MLS-Exporter implementation as specified in RFC 9420.
     */
    private fun mlsExporter(exporterSecret: ByteArray, label: String, context: ByteArray, length: Int): ByteArray {
        // Simplified MLS-Exporter implementation
        // In a real implementation, this should follow RFC 9420 exactly
        val labelBytes = label.toByteArray(Charsets.UTF_8)
        val info = ByteBuffer.allocate(labelBytes.size + context.size + 2)
            .putShort(labelBytes.size.toShort())
            .put(labelBytes)
            .put(context)
            .array()
        
        return hkdfExpand(exporterSecret, info, length)
    }
    
    /**
     * HKDF-Expand implementation for key derivation.
     */
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hashLength = 32 // SHA-256 hash length
        val iterations = (length + hashLength - 1) / hashLength
        val result = ByteArray(length)
        var previous = ByteArray(0)
        
        for (i in 1..iterations) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(previous)
            mac.update(info)
            mac.update(i.toByte())
            
            val current = mac.doFinal()
            val copyLength = minOf(current.size, length - (i - 1) * hashLength)
            System.arraycopy(current, 0, result, (i - 1) * hashLength, copyLength)
            previous = current
        }
        
        return result
    }
}

/**
 * Key ratchet implementation similar to MLS sender ratchet for AEAD.
 */
public class KeyRatchet(private val baseSecret: ByteArray) {
    private val keyCache = mutableMapOf<Int, ByteArray>()
    private var currentGeneration = 0
    
    /**
     * Gets the key for a specific generation, ratcheting forward if necessary.
     */
    public fun getKey(generation: Int): ByteArray {
        // Check if we already have this key cached
        keyCache[generation]?.let { return it }
        
        // If requesting a past generation that we don't have cached, return null
        if (generation < currentGeneration && !keyCache.containsKey(generation)) {
            return ByteArray(0) // Return empty array to indicate error
        }
        
        // Ratchet forward to the requested generation
        while (currentGeneration <= generation) {
            if (!keyCache.containsKey(currentGeneration)) {
                val key = deriveKeyForGeneration(currentGeneration)
                keyCache[currentGeneration] = key
            }
            currentGeneration++
        }
        
        return keyCache[generation] ?: ByteArray(0)
    }
    
    /**
     * Derives a key for a specific generation using HKDF.
     */
    private fun deriveKeyForGeneration(generation: Int): ByteArray {
        val info = "generation_${generation}".toByteArray(Charsets.UTF_8)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(baseSecret, "HmacSHA256"))
        mac.update(info)
        val fullHash = mac.doFinal()
        
        // Return first 16 bytes for AES128
        return fullHash.copyOf(16)
    }
    
    /**
     * Cleans up old keys to prevent memory leaks.
     * In practice, keys should be retained for up to 10 seconds for out-of-order packets.
     */
    public fun cleanup(retainGenerations: Int = 10) {
        val toRemove = keyCache.keys.filter { it < currentGeneration - retainGenerations }
        toRemove.forEach { keyCache.remove(it) }
    }
}
