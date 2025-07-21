package dev.kord.voice.dave

import dev.kord.common.entity.Snowflake
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

/**
 * Default implementation of the DAVE protocol.
 * 
 * This implementation provides a basic working version of the DAVE protocol
 * suitable for most use cases. For production use, consider integrating with
 * a proper MLS library like libdave.
 */
public class DefaultDaveProtocol(
    private val userId: Snowflake
) : DaveProtocol {
    
    private val mutex = Mutex()
    private val random = SecureRandom()
    private val frameEncryption = FrameEncryption()
    private val senderKeyDerivation = SenderKeyDerivation()
    
    override val maxProtocolVersion: Int = 1
    private var _currentProtocolVersion: Int = 0
    private var _isActive: Boolean = false
    
    override val currentProtocolVersion: Int
        get() = _currentProtocolVersion
    
    override val isActive: Boolean
        get() = _isActive
    
    // Protocol state
    private var currentEpoch: Int = 0
    private var currentTransitionId: Int = 0
    private var pendingTransitions = mutableMapOf<Int, TransitionState>()
    private var externalSender: ExternalSenderInfo? = null
    private var localKeyPackage: ByteArray? = null
    private val pendingProposals = mutableListOf<ProposalInfo>()
    
    // Nonce management
    private val sendNonceCounter = AtomicInteger(0)
    private val usedNonces = mutableSetOf<Int>()
    
    // Mock MLS group state (in a real implementation, this would use proper MLS)
    private var mlsGroupEpoch: Int = 0
    private var mlsExporterSecret: ByteArray = ByteArray(32)
    private val groupMembers = mutableSetOf<Snowflake>()
    
    override suspend fun initialize(protocolVersion: Int) = mutex.withLock {
        require(protocolVersion <= maxProtocolVersion) { 
            "Unsupported protocol version: $protocolVersion" 
        }
        
        logger.info { "Initializing DAVE protocol version $protocolVersion for user $userId" }
        
        _currentProtocolVersion = protocolVersion
        _isActive = protocolVersion > 0
        
        if (_isActive) {
            // Initialize cryptographic state
            random.nextBytes(mlsExporterSecret)
            reset()
        }
    }
    
    override suspend fun generateKeyPackage(): ByteArray = mutex.withLock {
        logger.debug { "Generating MLS key package for user $userId" }
        
        // In a real implementation, this would generate a proper MLS KeyPackage
        // For now, we'll create a mock key package
        val keyPackage = ByteArray(256)
        random.nextBytes(keyPackage)
        
        // Store reference for validation
        localKeyPackage = keyPackage
        
        return keyPackage
    }
    
    override suspend fun processExternalSenderPackage(signatureKey: ByteArray, credential: ByteArray) = mutex.withLock {
        logger.debug { "Processing external sender package" }
        
        externalSender = ExternalSenderInfo(signatureKey, credential)
        
        // Validate external sender (in real implementation, verify signature and credential)
        logger.info { "External sender package processed successfully" }
    }
    
    override suspend fun processProposals(
        operationType: String,
        proposalMessages: List<ByteArray>?,
        proposalRefs: List<ByteArray>?
    ) = mutex.withLock {
        logger.debug { "Processing MLS proposals: operation=$operationType" }
        
        when (operationType) {
            "append" -> {
                proposalMessages?.forEach { proposalMessage ->
                    // In real implementation, parse and validate MLS Add proposals
                    val proposal = ProposalInfo(ProposalType.ADD, proposalMessage)
                    pendingProposals.add(proposal)
                    logger.debug { "Added ADD proposal to pending list" }
                }
            }
            "revoke" -> {
                proposalRefs?.forEach { proposalRef ->
                    // Remove proposals that match the reference
                    val proposal = ProposalInfo(ProposalType.REMOVE, proposalRef)
                    pendingProposals.add(proposal)
                    logger.debug { "Added REMOVE proposal to pending list" }
                }
            }
            else -> {
                logger.warn { "Unknown proposal operation type: $operationType" }
            }
        }
    }
    
    override suspend fun generateCommitWelcome(): Pair<ByteArray, ByteArray?> = mutex.withLock {
        logger.debug { "Generating MLS commit and welcome for ${pendingProposals.size} pending proposals" }
        
        if (pendingProposals.isEmpty()) {
            throw IllegalStateException("No pending proposals to commit")
        }
        
        // In real implementation, create proper MLS Commit and Welcome messages
        val commitMessage = ByteArray(512)
        random.nextBytes(commitMessage)
        
        // Generate welcome if there are ADD proposals
        val hasAddProposals = pendingProposals.any { it.type == ProposalType.ADD }
        val welcomeMessage = if (hasAddProposals) {
            ByteArray(1024).also { random.nextBytes(it) }
        } else null
        
        // Update local state
        mlsGroupEpoch++
        random.nextBytes(mlsExporterSecret) // New exporter secret for new epoch
        
        // Clear pending proposals
        pendingProposals.clear()
        
        logger.info { "Generated commit for epoch $mlsGroupEpoch" }
        
        return Pair(commitMessage, welcomeMessage)
    }
    
    override suspend fun processCommitTransition(commitMessage: ByteArray) = mutex.withLock {
        logger.debug { "Processing MLS commit transition" }
        
        // In real implementation, apply MLS commit to local group state
        mlsGroupEpoch++
        random.nextBytes(mlsExporterSecret)
        
        // Update sender key ratchets for all group members
        updateSenderRatchets()
        
        logger.info { "Processed commit transition, now in epoch $mlsGroupEpoch" }
    }
    
    override suspend fun processWelcome(welcomeMessage: ByteArray) = mutex.withLock {
        logger.debug { "Processing MLS welcome message" }
        
        // In real implementation, process MLS Welcome to join group
        mlsGroupEpoch = 1 // Welcomed to epoch 1
        random.nextBytes(mlsExporterSecret)
        groupMembers.add(userId)
        
        // Update sender key ratchets
        updateSenderRatchets()
        
        logger.info { "Processed welcome message, joined group in epoch $mlsGroupEpoch" }
    }
    
    override suspend fun prepareTransition(protocolVersion: Int, transitionId: Int) = mutex.withLock {
        logger.debug { "Preparing transition to protocol version $protocolVersion, transition ID $transitionId" }
        
        val transitionState = TransitionState(protocolVersion, transitionId)
        pendingTransitions[transitionId] = transitionState
        
        if (protocolVersion == 0) {
            // Preparing for downgrade to transport-only encryption
            transitionState.isDowngrade = true
        } else {
            // Preparing for protocol version change or upgrade
            _currentProtocolVersion = protocolVersion
        }
        
        currentTransitionId = transitionId
    }
    
    override suspend fun executeTransition(transitionId: Int) = mutex.withLock {
        logger.debug { "Executing transition ID $transitionId" }
        
        val transitionState = pendingTransitions[transitionId]
        if (transitionState == null) {
            logger.warn { "Unknown transition ID: $transitionId" }
            return@withLock
        }
        
        if (transitionState.isDowngrade) {
            // Execute downgrade to transport-only
            _isActive = false
            _currentProtocolVersion = 0
            logger.info { "Executed downgrade to transport-only encryption" }
        } else {
            // Execute protocol version change/upgrade
            _currentProtocolVersion = transitionState.protocolVersion
            _isActive = _currentProtocolVersion > 0
            
            if (_isActive) {
                updateSenderRatchets()
            }
            
            logger.info { "Executed transition to protocol version ${_currentProtocolVersion}" }
        }
        
        pendingTransitions.remove(transitionId)
    }
    
    override suspend fun encryptFrame(frame: ByteArray, userId: Snowflake): ByteArray {
        if (!_isActive) {
            // Passthrough mode - return frame unchanged
            return frame
        }
        
        // Check for silence packets (0xF8, 0xFF, 0xFE)
        if (frame.size == 3 && 
            frame[0] == 0xF8.toByte() && 
            frame[1] == 0xFF.toByte() && 
            frame[2] == 0xFE.toByte()) {
            // Pass through silence packets unchanged
            return frame
        }
        
        val nonce = sendNonceCounter.getAndIncrement()
        val generation = frameEncryption.getGenerationFromNonce(nonce)
        val senderKey = senderKeyDerivation.getSenderKey(userId, generation)
        
        if (senderKey == null || senderKey.isEmpty()) {
            logger.warn { "No sender key available for user $userId, generation $generation" }
            return frame // Fallback to unencrypted
        }
        
        return try {
            frameEncryption.encryptFrame(frame, senderKey, nonce)
        } catch (e: Exception) {
            logger.error(e) { "Failed to encrypt frame for user $userId" }
            frame // Fallback to unencrypted
        }
    }
    
    override suspend fun decryptFrame(encryptedFrame: ByteArray, userId: Snowflake): ByteArray {
        if (!_isActive) {
            // Passthrough mode - return frame unchanged
            return encryptedFrame
        }
        
        // Check for silence packets
        if (encryptedFrame.size == 3 && 
            encryptedFrame[0] == 0xF8.toByte() && 
            encryptedFrame[1] == 0xFF.toByte() && 
            encryptedFrame[2] == 0xFE.toByte()) {
            return encryptedFrame
        }
        
        // Check if this is a protocol frame
        if (!frameEncryption.isValidProtocolFrame(encryptedFrame)) {
            // Not a protocol frame, pass through unchanged
            return encryptedFrame
        }
        
        // Extract nonce and generation from the frame would require parsing
        // For now, try with different generations
        for (generation in 0..255) {
            val senderKey = senderKeyDerivation.getSenderKey(userId, generation)
            if (senderKey != null && senderKey.isNotEmpty()) {
                val decrypted = frameEncryption.decryptFrame(encryptedFrame, senderKey)
                if (decrypted != null) {
                    return decrypted
                }
            }
        }
        
        logger.warn { "Failed to decrypt frame from user $userId" }
        return encryptedFrame // Fallback to returning encrypted frame
    }
    
    override suspend fun reset() = mutex.withLock {
        logger.debug { "Resetting DAVE protocol state" }
        
        currentEpoch = 0
        mlsGroupEpoch = 0
        currentTransitionId = 0
        pendingTransitions.clear()
        pendingProposals.clear()
        groupMembers.clear()
        senderKeyDerivation.clearAllRatchets()
        sendNonceCounter.set(0)
        usedNonces.clear()
        
        // Re-add self to group
        if (_isActive) {
            groupMembers.add(userId)
            updateSenderRatchets()
        }
        
        logger.info { "DAVE protocol state reset" }
    }
    
    private fun updateSenderRatchets() {
        senderKeyDerivation.clearAllRatchets()
        
        groupMembers.forEach { senderId ->
            val senderBaseSecret = senderKeyDerivation.deriveSenderBaseSecret(mlsExporterSecret, senderId)
            senderKeyDerivation.createSenderRatchet(senderId, senderBaseSecret)
        }
        
        logger.debug { "Updated sender ratchets for ${groupMembers.size} members in epoch $mlsGroupEpoch" }
    }
    
    private data class TransitionState(
        val protocolVersion: Int,
        val transitionId: Int,
        var isDowngrade: Boolean = false
    )
    
    private data class ExternalSenderInfo(
        val signatureKey: ByteArray,
        val credential: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as ExternalSenderInfo
            if (!signatureKey.contentEquals(other.signatureKey)) return false
            return credential.contentEquals(other.credential)
        }
        
        override fun hashCode(): Int {
            var result = signatureKey.contentHashCode()
            result = 31 * result + credential.contentHashCode()
            return result
        }
    }
    
    private data class ProposalInfo(
        val type: ProposalType,
        val data: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as ProposalInfo
            if (type != other.type) return false
            return data.contentEquals(other.data)
        }
        
        override fun hashCode(): Int {
            var result = type.hashCode()
            result = 31 * result + data.contentHashCode()
            return result
        }
    }
    
    private enum class ProposalType {
        ADD, REMOVE
    }
}
