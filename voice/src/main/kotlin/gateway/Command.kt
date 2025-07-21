package dev.kord.voice.gateway

import dev.kord.common.annotation.KordVoice
import dev.kord.common.entity.Snowflake
import dev.kord.voice.EncryptionMode
import dev.kord.voice.SpeakingFlags
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.SerializationStrategy as KSerializationStrategy

public sealed class Command {
    public object SerializationStrategy : KSerializationStrategy<Command> {
        override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Command") {
            element("op", OpCode.serializer().descriptor)
            element("d", JsonObject.serializer().descriptor)
        }

        override fun serialize(encoder: Encoder, value: Command) {
            val composite = encoder.beginStructure(descriptor)

            when (value) {
                is Identify -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.Identify)
                    composite.encodeSerializableElement(descriptor, 1, Identify.serializer(), value)
                }
                is Heartbeat -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.Heartbeat)
                    composite.encodeLongElement(descriptor, 1, value.nonce)
                }
                is SendSpeaking -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.Speaking)
                    composite.encodeSerializableElement(descriptor, 1, SendSpeaking.serializer(), value)
                }
                is SelectProtocol -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.SelectProtocol)
                    composite.encodeSerializableElement(descriptor, 1, SelectProtocol.serializer(), value)
                }
                is Resume -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.Resume)
                    composite.encodeSerializableElement(descriptor, 1, Resume.serializer(), value)
                }
                is DaveProtocolReadyForTransition -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.DaveProtocolReadyForTransition)
                    composite.encodeSerializableElement(descriptor, 1, DaveProtocolReadyForTransition.serializer(), value)
                }
                is DaveMlsKeyPackage -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.DaveMlsKeyPackage)
                    composite.encodeSerializableElement(descriptor, 1, DaveMlsKeyPackage.serializer(), value)
                }
                is DaveMlsCommitWelcome -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.DaveMlsCommitWelcome)
                    composite.encodeSerializableElement(descriptor, 1, DaveMlsCommitWelcome.serializer(), value)
                }
                is DaveMlsInvalidCommitWelcome -> {
                    composite.encodeSerializableElement(descriptor, 0, OpCode.serializer(), OpCode.DaveMlsInvalidCommitWelcome)
                    composite.encodeSerializableElement(descriptor, 1, DaveMlsInvalidCommitWelcome.serializer(), value)
                }
            }

            composite.endStructure(descriptor)
        }
    }
}

@Serializable
public data class Identify(
    @SerialName("server_id")
    val serverId: Snowflake,
    @SerialName("user_id")
    val userId: Snowflake,
    @SerialName("session_id")
    val sessionId: String,
    val token: String,
    @SerialName("max_dave_protocol_version")
    val maxDaveProtocolVersion: Int = 0
) : Command()

@Serializable
public data class Heartbeat(val nonce: Long) : Command()

@KordVoice
@Serializable
public data class SendSpeaking(
    val speaking: SpeakingFlags,
    val delay: Int,
    val ssrc: UInt
) : Command()

@KordVoice
@Serializable
public data class SelectProtocol(
    val protocol: String,
    val data: Data
) : Command() {
    @KordVoice
    @Serializable
    public data class Data(
        val address: String,
        val port: Int,
        val mode: EncryptionMode
    )
}

@Serializable
public data class Resume(
    val serverId: Snowflake,
    val sessionId: String,
    val token: String
) : Command()

@KordVoice
@Serializable
public data class DaveProtocolReadyForTransition(
    @SerialName("transition_id")
    val transitionId: Int
) : Command()

@KordVoice
@Serializable
public data class DaveMlsKeyPackage(
    @SerialName("key_package")
    val keyPackage: ByteArray
) : Command() {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DaveMlsKeyPackage
        return keyPackage.contentEquals(other.keyPackage)
    }

    override fun hashCode(): Int = keyPackage.contentHashCode()
}

@KordVoice
@Serializable
public data class DaveMlsCommitWelcome(
    @SerialName("commit_message")
    val commitMessage: ByteArray,
    @SerialName("welcome_message")
    val welcomeMessage: ByteArray?
) : Command() {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as DaveMlsCommitWelcome
        if (!commitMessage.contentEquals(other.commitMessage)) return false
        if (welcomeMessage != null) {
            if (other.welcomeMessage == null) return false
            if (!welcomeMessage.contentEquals(other.welcomeMessage)) return false
        } else if (other.welcomeMessage != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = commitMessage.contentHashCode()
        result = 31 * result + (welcomeMessage?.contentHashCode() ?: 0)
        return result
    }
}

@KordVoice
@Serializable
public data class DaveMlsInvalidCommitWelcome(
    @SerialName("transition_id")
    val transitionId: Int
) : Command()
