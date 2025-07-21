# DAVE Protocol Support in Kord Voice

Kord Voice now supports Discord's Audio and Video End-to-End Encryption (DAVE) protocol, which provides end-to-end encryption for voice and video communications using MLS (Messaging Layer Security) for group key exchange and AES128-GCM for media frame encryption.

## Overview

The DAVE protocol implementation includes:

- **MLS Group Key Exchange**: Using the Messaging Layer Security protocol for secure group key management
- **Per-Sender Key Derivation**: Each sender has a ratcheted symmetric key derived from MLS exported secrets
- **AES128-GCM Frame Encryption**: Media frames are encrypted using truncated authentication tags and ULEB128 encoded nonces
- **Displayable Codes**: For epoch authenticators and pairwise verification fingerprints
- **Protocol Version Negotiation**: Support for upgrading/downgrading between transport-only and E2EE modes

## Usage

DAVE protocol support is enabled by default when creating a voice connection:

```kotlin
val connection = channel.connect {
    // DAVE protocol is automatically enabled
    // The connection will negotiate E2EE with Discord if supported
    
    audioProvider { 
        // Your audio frames will be automatically encrypted when E2EE is active
        AudioFrame.fromData(yourOpusData)
    }
}
```

### Customizing DAVE Protocol

You can customize the DAVE protocol implementation:

```kotlin
val connection = channel.connect {
    // Disable DAVE protocol if needed
    enableDaveProtocol = false
    
    // Or provide your own implementation
    daveProtocol(MyCustomDaveProtocol(userId))
}
```

### Checking E2EE Status

You can check if end-to-end encryption is currently active:

```kotlin
// Note: This would require extending the VoiceConnection API
// to expose the DAVE protocol status
```

## Implementation Details

### Key Components

- **DaveProtocol Interface**: Main interface for DAVE protocol implementations
- **DefaultDaveProtocol**: Basic working implementation suitable for most use cases
- **SenderKeyDerivation**: Implements the key ratcheting mechanism as specified in the DAVE protocol
- **FrameEncryption**: Handles AES128-GCM encryption/decryption of media frames with DAVE format
- **DisplayableCodes**: Generates human-readable codes for verification
- **DaveProtocolHandler**: Manages DAVE protocol events from the voice gateway

### Protocol Flow

1. **Connection Establishment**: Client announces max supported DAVE protocol version in Identify
2. **Protocol Negotiation**: Voice gateway selects appropriate protocol version for the session
3. **MLS Group Setup**: External sender package is received and MLS group is created
4. **Key Exchange**: Participants exchange MLS key packages and establish the group
5. **Media Encryption**: Audio frames are encrypted using per-sender keys derived from MLS
6. **Transitions**: Protocol handles upgrades/downgrades and group member changes

### Security Features

- **Forward Secrecy**: Keys are ratcheted for long-lived sessions
- **Authentication**: Frames include truncated authentication tags
- **Protocol Frame Detection**: Magic markers prevent confusion with unencrypted frames
- **Passthrough Mode**: Graceful handling of mixed E2EE/non-E2EE sessions

## Production Considerations

The default implementation provides basic DAVE protocol support. For production use, consider:

- Integrating with Discord's official [libdave](https://github.com/discord/libdave) library
- Implementing proper MLS message validation
- Adding persistent identity key support for verification
- Optimizing key caching and cleanup strategies

## Migration Timeline

- **September 2024**: DAVE protocol support is optional, calls auto-upgrade/downgrade
- **2025**: All official Discord clients will support DAVE protocol
- **Future**: Non-E2EE connections will be deprecated and discontinued (with 6+ months notice)

## References

- [DAVE Protocol Whitepaper](https://daveprotocol.com/)
- [Discord's DAVE Blog Post](https://discord.com/blog/meet-dave-e2ee-for-audio-video)
- [libdave Open Source Library](https://github.com/discord/libdave)
- [Discord Voice Connections Documentation](https://discord.com/developers/docs/topics/voice-connections#endtoend-encryption-dave-protocol)
