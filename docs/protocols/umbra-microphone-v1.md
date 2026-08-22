# Umbra → Lumen client microphone protocol, version 1

This document is the normative client API and wire specification for forwarding a microphone captured by Umbra to Lumen. The direction is always client to host. Version 1 uses the existing GameStream RTSP session for negotiation and a dedicated reverse UDP flow for authenticated, encrypted Opus packets.

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## Fixed version-one media format

Version one has one media format:

- Codec: Opus.
- Sample rate and RTP-compatible timestamp clock: 48,000 Hz.
- Channels: one.
- Packet duration: 20 milliseconds, or 960 samples.
- Opus in-band FEC: supported and negotiated per session.
- Maximum encoded Opus packet/ciphertext: 1,275 bytes, the maximum packet size defined by RFC 6716.
- Authenticated encryption: AES-256-GCM with a 16-byte tag.

Umbra MUST capture or resample microphone audio to the negotiated format before encoding. It MUST NOT fragment an Opus packet across LMC1 datagrams.

## RTSP capability and setup

The normative handshake order is `DESCRIBE` → optional microphone `SETUP` → `ANNOUNCE`, matching the existing Moonlight RTSP flow.

### Lumen `DESCRIBE` capability

Lumen advertises this exact SDP capability block in its RTSP `DESCRIBE` response only when `client_microphone` is enabled and the platform virtual microphone backend passes its availability probe:

```sdp
a=x-lumen-mic.version:1
a=x-lumen-mic.codec:opus
a=x-lumen-mic.sampleRate:48000
a=x-lumen-mic.channels:1
a=x-lumen-mic.packetDurationMs:20
a=x-lumen-mic.crypto:aes-256-gcm
a=x-lumen-mic.fec:opus-inband
```

Umbra MUST treat the extension as unsupported unless every required value is understood. Lack of support MUST NOT prevent the normal GameStream session from starting.

### Umbra `ANNOUNCE` selection

After microphone `SETUP` succeeds, Umbra includes this exact selection in its RTSP `ANNOUNCE` SDP:

```sdp
a=x-lumen-mic.enabled:1
a=x-lumen-mic.version:1
a=x-lumen-mic.codec:opus
a=x-lumen-mic.sampleRate:48000
a=x-lumen-mic.channels:1
a=x-lumen-mic.packetDurationMs:20
a=x-lumen-mic.fec:opus-inband
```

Every field and value above is required and exact. Omitting a field, offering a different value, or adding an unsupported `x-lumen-mic.*` field is a malformed selection. Lumen MUST reject an explicit but malformed microphone selection without affecting clients that do not announce the extension.

### Microphone `SETUP`

After accepting the `DESCRIBE` capability and before sending `ANNOUNCE`, Umbra sends RTSP `SETUP` to the media control URI whose stream identifier is exactly:

```text
streamid=lumen-mic/1/0
```

The request uses the same Moonlight UDP transport syntax as the existing GameStream flows:

```http
Transport: unicast;X-GS-ClientPort=<port>-<port+1>
```

Lumen allocates the input flow at the session's mapped UDP base port plus 12 and returns:

```http
Transport: unicast;server_port=<mapped-base-port+12>
X-Lumen-Mic-Session: <32 lowercase hexadecimal digits>
X-Lumen-Mic-Salt: <32 lowercase hexadecimal digits>
```

The session and salt headers each encode 16 independently random bytes. Umbra MUST reject missing, duplicated, non-lowercase, non-hexadecimal, or incorrectly sized values. Umbra MUST NOT send microphone UDP traffic before a successful microphone `SETUP`.

Only one microphone `SETUP` is permitted per RTSP session. Lumen returns RTSP 409 for a repeated request. Umbra creates a new GameStream/RTSP session when it needs new microphone key material. `TEARDOWN`, loss of the RTSP session, or an authenticated `END` closes the generation.

## Key derivation

Version one derives a dedicated microphone key and nonce prefix using HKDF-SHA-256 as specified by RFC 5869:

- Input keying material (`IKM`): the raw 16-byte `rikey` for the enclosing GameStream session.
- Salt: the exact 16 decoded bytes from `X-Lumen-Mic-Salt`.
- Info: the 41 ASCII bytes `lumen/client-microphone/client-to-host/v1`, with no trailing NUL.
- Output length: 36 bytes.
- Bytes 0–31: the AES-256-GCM key.
- Bytes 32–35: the four-byte nonce prefix.

Derivation inputs and output are binary bytes. Implementations MUST NOT pass hexadecimal text, append a NUL to `info`, or apply another text encoding.

## LMC1 UDP datagram

Every multi-byte integer is unsigned and encoded in network byte order (big-endian). The fixed header is exactly 40 bytes and is immediately followed by the declared 0–1,275 bytes of AES-GCM ciphertext and a 16-byte authentication tag. A complete datagram is therefore 56–1,331 bytes.

| Offset | Size | Field | Version-one requirement |
| ---: | ---: | --- | --- |
| 0 | 4 | Magic | ASCII `LMC1` (`4c 4d 43 31`) |
| 4 | 1 | Type | `1` HELLO, `2` AUDIO, `3` RESET, or `4` END |
| 5 | 1 | Flags | `0` or AUDIO-only `SILENCE` bit `0x01` |
| 6 | 2 | Header length | `40` |
| 8 | 16 | Session ID | Exact bytes decoded from `X-Lumen-Mic-Session` |
| 24 | 8 | Packet sequence | Strictly increasing generation-local counter |
| 32 | 4 | Timestamp | 48 kHz audio timeline, modulo 2^32 |
| 36 | 2 | Ciphertext length | Exact ciphertext size, 0–1,275 |
| 38 | 2 | Reserved | Zero |
| 40 | 0–1,275 | Ciphertext | AES-GCM ciphertext; same length as the plaintext |
| variable | 16 | Authentication tag | AES-256-GCM tag |

The packet sequence MUST begin at zero and increase by exactly one for every transmitted datagram, including HELLO, RESET, SILENCE, and END. It MUST NOT wrap within a microphone generation.

### Type and payload rules

| Type | Flags | Ciphertext | Receiver action after authentication |
| --- | --- | --- | --- |
| HELLO (`1`) | `0` | Empty | Start the generation and initialize decoder/timeline state |
| AUDIO (`2`) | `0` | One encrypted Opus packet | Decode and render/inject 20 ms of microphone audio |
| AUDIO (`2`) | `SILENCE` (`0x01`) | Empty | Advance the timeline by 960 samples without decoding |
| RESET (`3`) | `0` | Empty | Reset Opus decoder and jitter/timeline state |
| END (`4`) | `0` | Empty | Close the microphone generation |

Bits `0x02` through `0x80` are reserved and MUST be zero. `SILENCE` is invalid on any non-AUDIO type. A non-SILENCE AUDIO packet MUST contain ciphertext. HELLO, RESET, END, and SILENCE packets MUST have an empty ciphertext. The authentication tag remains REQUIRED for every empty-ciphertext packet.

The timestamp names the first sample represented by an AUDIO packet. After any AUDIO packet, including SILENCE, the sender advances it by exactly 960 modulo 2^32. HELLO, RESET, and END do not advance it.

## Authenticated encryption

Each packet uses AES-256-GCM with the derived key. Its 12-byte nonce is the four-byte derived nonce prefix followed by the packet's eight-byte big-endian packet sequence. The complete fixed 40-byte header, exactly as transmitted, is the additional authenticated data (AAD). The encoded Opus packet is the plaintext, and the 16-byte tag is appended after the ciphertext.

The session identifier is public routing data, not a secret. A sender MUST NOT reuse a packet sequence with the same derived key and nonce prefix. A receiver MUST authenticate the header and ciphertext before acting on the type, flags, timestamp, or payload. This means even HELLO, RESET, SILENCE, and END take effect only after successful GCM authentication.

## Receiver validation and replay handling

Lumen validates a datagram in this order:

1. Require the complete 40-byte fixed header.
2. Require the exact magic, known type, valid type/flag combination, header length, ciphertext ceiling, and zero reserved field.
3. Require the datagram length to equal `40 + ciphertext_length + 16` exactly.
4. Enforce the type-specific empty/non-empty ciphertext rule.
5. Select the active generation by the complete 16-byte session identifier.
6. Reject a packet sequence already authenticated for that generation. A bounded replay window MAY accept authenticated reordering, but duplicate packets MUST never reach the decoder.
7. Construct the nonce, authenticate/decrypt with the fixed header as AAD, and discard the datagram on any GCM failure.
8. Apply the authenticated packet semantics.

RESET and END are sequence barriers. Lumen applies them only when they advance the authenticated sequence high-water mark. After RESET sequence `N`, any delayed AUDIO packet with a sequence lower than `N` is discarded even if it is otherwise authentic.

Malformed, unauthenticated, unknown-session, duplicate, and excessively late datagrams MUST be silently discarded on the media path. They MUST NOT terminate the main GameStream session. Implementations SHOULD rate-limit diagnostics so malformed UDP traffic cannot flood logs.

## Umbra implementation checklist

- Parse the complete `DESCRIBE` capability block when microphone forwarding is enabled.
- Perform `SETUP` for `streamid=lumen-mic/1/0`; strictly decode the returned session and salt.
- Include the exact microphone selection in the subsequent `ANNOUNCE` request.
- Derive exactly 36 bytes with HKDF-SHA-256 from the raw 16-byte session `rikey`.
- Reset packet sequence and timestamp state for every successful microphone `SETUP`.
- Send authenticated HELLO before AUDIO, RESET when capture/encoder discontinuity invalidates decoder state, and END before a graceful stop.
- Serialize every integer in big-endian order and authenticate the exact 40 transmitted header bytes.
- Send one 20 ms mono 48 kHz Opus packet per AUDIO datagram, never exceeding 1,275 ciphertext bytes.
- Use AUDIO|SILENCE with empty ciphertext to preserve the 20 ms timeline while muted or during DTX; always advance the timestamp by 960.
- Destroy derived key material when the microphone generation ends.
