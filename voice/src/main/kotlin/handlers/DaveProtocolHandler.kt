package dev.kord.voice.handlers

import dev.kord.voice.VoiceConnection
import dev.kord.voice.dave.DaveProtocol
import dev.kord.voice.gateway.*
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

private val logger = KotlinLogging.logger {}

/**
 * Handler for DAVE protocol events from the voice gateway.
 * 
 * This handler processes all DAVE-related opcodes and coordinates with the
 * DaveProtocol implementation to handle end-to-end encryption.
 */
public class DaveProtocolHandler(
    private val events: Flow<VoiceEvent>,
    private val voiceConnection: VoiceConnection,
    private val daveProtocol: DaveProtocol
) {
    
    public suspend fun start() {
        logger.info { "Starting DAVE protocol handler for guild ${voiceConnection.data.guildId}" }
        
        // Handle clients connecting events
        events.filterIsInstance<ClientsConnect>()
            .onEach { event ->
                logger.debug { "Clients connected: ${event.userIds}" }
                // This could be used to track expected group members
            }
            .launchIn(voiceConnection.scope)
        
        // Handle protocol transition preparation
        events.filterIsInstance<DaveProtocolPrepareTransition>()
            .onEach { event ->
                logger.debug { "Preparing protocol transition: version=${event.protocolVersion}, transitionId=${event.transitionId}" }
                try {
                    daveProtocol.prepareTransition(event.protocolVersion, event.transitionId)
                    
                    // Send ready for transition
                    val command = DaveProtocolReadyForTransition(event.transitionId)
                    voiceConnection.voiceGateway.send(command)
                    
                } catch (e: Exception) {
                    logger.error(e) { "Failed to prepare protocol transition" }
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle protocol transition execution
        events.filterIsInstance<DaveProtocolExecuteTransition>()
            .onEach { event ->
                logger.debug { "Executing protocol transition: transitionId=${event.transitionId}" }
                try {
                    daveProtocol.executeTransition(event.transitionId)
                } catch (e: Exception) {
                    logger.error(e) { "Failed to execute protocol transition" }
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle protocol epoch preparation
        events.filterIsInstance<DaveProtocolPrepareEpoch>()
            .onEach { event ->
                logger.debug { "Preparing epoch: version=${event.protocolVersion}, epoch=${event.epoch}, transitionId=${event.transitionId}" }
                try {
                    daveProtocol.prepareTransition(event.protocolVersion, event.transitionId)
                    
                    // Generate and send key package if creating new group (epoch = 1)
                    if (event.epoch == 1) {
                        val keyPackage = daveProtocol.generateKeyPackage()
                        val command = DaveMlsKeyPackage(keyPackage)
                        voiceConnection.voiceGateway.send(command)
                    }
                    
                    // Send ready for transition
                    val readyCommand = DaveProtocolReadyForTransition(event.transitionId)
                    voiceConnection.voiceGateway.send(readyCommand)
                    
                } catch (e: Exception) {
                    logger.error(e) { "Failed to prepare epoch transition" }
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle external sender package
        events.filterIsInstance<DaveMlsExternalSenderPackage>()
            .onEach { event ->
                logger.debug { "Processing external sender package" }
                try {
                    daveProtocol.processExternalSenderPackage(event.signatureKey, event.credential)
                } catch (e: Exception) {
                    logger.error(e) { "Failed to process external sender package" }
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle MLS proposals
        events.filterIsInstance<DaveMlsProposals>()
            .onEach { event ->
                logger.debug { "Processing MLS proposals: operationType=${event.operationType}" }
                try {
                    daveProtocol.processProposals(event.operationType, event.proposalMessages, event.proposalRefs)
                    
                    // Generate commit and welcome if we have pending proposals
                    try {
                        val (commitMessage, welcomeMessage) = daveProtocol.generateCommitWelcome()
                        val command = DaveMlsCommitWelcome(commitMessage, welcomeMessage)
                        voiceConnection.voiceGateway.send(command)
                    } catch (e: IllegalStateException) {
                        // No pending proposals to commit, this is expected sometimes
                        logger.debug { "No pending proposals to commit" }
                    }
                    
                } catch (e: Exception) {
                    logger.error(e) { "Failed to process MLS proposals" }
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle MLS commit transition announcements
        events.filterIsInstance<DaveMlsAnnounceCommitTransition>()
            .onEach { event ->
                logger.debug { "Processing commit transition: transitionId=${event.transitionId}" }
                try {
                    daveProtocol.processCommitTransition(event.commitMessage)
                    
                    // Send ready for transition
                    val command = DaveProtocolReadyForTransition(event.transitionId)
                    voiceConnection.voiceGateway.send(command)
                    
                } catch (e: Exception) {
                    logger.error(e) { "Failed to process commit transition" }
                    
                    // Report invalid commit
                    val invalidCommand = DaveMlsInvalidCommitWelcome(event.transitionId)
                    voiceConnection.voiceGateway.send(invalidCommand)
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle MLS welcome messages
        events.filterIsInstance<DaveMlsWelcome>()
            .onEach { event ->
                logger.debug { "Processing welcome message: transitionId=${event.transitionId}" }
                try {
                    daveProtocol.processWelcome(event.welcomeMessage)
                    
                    // Send ready for transition
                    val command = DaveProtocolReadyForTransition(event.transitionId)
                    voiceConnection.voiceGateway.send(command)
                    
                } catch (e: Exception) {
                    logger.error(e) { "Failed to process welcome message" }
                    
                    // Report invalid welcome
                    val invalidCommand = DaveMlsInvalidCommitWelcome(event.transitionId)
                    voiceConnection.voiceGateway.send(invalidCommand)
                }
            }
            .launchIn(voiceConnection.scope)
        
        // Handle session description updates (includes DAVE protocol version)
        events.filterIsInstance<SessionDescription>()
            .onEach { event ->
                if (event.daveProtocolVersion > 0) {
                    logger.info { "Received session description with DAVE protocol version ${event.daveProtocolVersion}" }
                    try {
                        daveProtocol.initialize(event.daveProtocolVersion)
                    } catch (e: Exception) {
                        logger.error(e) { "Failed to initialize DAVE protocol" }
                    }
                }
            }
            .launchIn(voiceConnection.scope)
        
        logger.info { "DAVE protocol handler started successfully" }
    }
}
