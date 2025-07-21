package dev.kord.voice.dave

import dev.kord.common.entity.Snowflake

/**
 * DAVE (Discord Audio & Video End-to-End Encryption) Protocol implementation.
 * 
 * This protocol provides end-to-end encryption for voice and video communications
 * using MLS (Messaging Layer Security) for group key exchange and AES128-GCM for
 * media frame encryption.
 */
public interface DaveProtocol {
    /**
     * The maximum DAVE protocol version supported by this implementation.
     */
    public val maxProtocolVersion: Int
    
    /**
     * The current protocol version being used for the session.
     */
    public val currentProtocolVersion: Int
    
    /**
     * Indicates if the protocol is currently active (E2EE enabled).
     */
    public val isActive: Boolean
    
    /**
     * Initialize the DAVE protocol with the specified version.
     */
    public suspend fun initialize(protocolVersion: Int)
    
    /**
     * Generate and return an MLS key package for joining a group.
     */
    public suspend fun generateKeyPackage(): ByteArray
    
    /**
     * Process an MLS external sender package from the voice gateway.
     */
    public suspend fun processExternalSenderPackage(signatureKey: ByteArray, credential: ByteArray)
    
    /**
     * Process MLS proposals from the voice gateway.
     */
    public suspend fun processProposals(operationType: String, proposalMessages: List<ByteArray>?, proposalRefs: List<ByteArray>?)
    
    /**
     * Generate an MLS commit and optional welcome message for pending proposals.
     */
    public suspend fun generateCommitWelcome(): Pair<ByteArray, ByteArray?>
    
    /**
     * Process an MLS commit transition message.
     */
    public suspend fun processCommitTransition(commitMessage: ByteArray)
    
    /**
     * Process an MLS welcome message.
     */
    public suspend fun processWelcome(welcomeMessage: ByteArray)
    
    /**
     * Prepare for a protocol transition.
     */
    public suspend fun prepareTransition(protocolVersion: Int, transitionId: Int)
    
    /**
     * Execute a protocol transition.
     */
    public suspend fun executeTransition(transitionId: Int)
    
    /**
     * Encrypt an audio frame using the DAVE protocol.
     */
    public suspend fun encryptFrame(frame: ByteArray, userId: Snowflake): ByteArray
    
    /**
     * Decrypt an audio frame using the DAVE protocol.
     */
    public suspend fun decryptFrame(encryptedFrame: ByteArray, userId: Snowflake): ByteArray
    
    /**
     * Reset the protocol state (used for sole member reset or error recovery).
     */
    public suspend fun reset()
}
