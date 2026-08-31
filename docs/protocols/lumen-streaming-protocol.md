# Lumen Streaming Protocol

Status: normative specification with verified portable primitives and product
integration in progress. Wire version: `1`.

The portable C++23 core currently implements and tests the frozen input
wire/state primitives in section 15, the media packetization and bounded
frame-pipeline primitives in sections 12 through 14, and the RTCP, repair,
congestion, DPLPMTUD, and generation-fence state described in sections 7, 13,
17, and 19.
Lumen additionally wires host capture and Opus encoding to a fresh
generation-scoped audio SSRC only after authenticated `AUDIO_CONFIG_ACK`, then
uses the production libSRTP and single-socket path for RTP and sender reports.
That host-side boundary does not claim a live cross-product stream: Umbra audio
receive/playout, video capture/decoder/renderer integration, and hardware
qualification remain in progress.

The Lumen Streaming Protocol (LSP) is the native, single-port protocol between
Lumen and its clients. It is optimized for competitive game streaming on a
controlled wired network while retaining secure operation and congestion-safe
behavior on ordinary IP networks.

LSP is a complete replacement for the experimental QUIC protocol. It has no
wire compatibility with that protocol and does not reuse its record formats,
state machines, transport semantics, queue behavior, or recovery policy.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Protocol objectives

LSP has five primary objectives:

1. minimize input-to-host and capture-to-client tail latency;
2. sustain the requested frame rate without periodic transport-induced stalls;
3. move hundreds of megabits per second with bounded CPU and allocation cost;
4. recover from packet loss without repeated full keyframes; and
5. carry every application flow on one UDP port.

LSP does not guarantee a physical input-to-photon latency. Display scanout,
panel behavior, game timing, driver queues, encoder behavior, and the network
remain external variables. Implementations report measured stages separately.

## 2. Scope

Wire version 1 defines:

- discovery and pairing invitations;
- DTLS peer authentication and client authorization;
- deterministic reliable control over DTLS datagrams;
- application enumeration, start, attach, stop, and teardown;
- negotiated SRTP/SRTCP streams for video, audio, input, microphone, repair,
  feedback, and telemetry;
- codec configuration generations;
- packet pacing and aggregate congestion feedback;
- frame-aware loss recovery;
- datagram path-MTU discovery; and
- bounded resource and abuse handling.

Wire version 1 does not define:

- a QUIC compatibility mode;
- silent fallback to legacy GameStream;
- browser or WebRTC interoperability;
- multiparty conferencing;
- relay or TURN operation;
- seamless connection migration while streaming;
- unencrypted operation; or
- simultaneous use of multiple application ports.

## 3. Protocol stack

```text
LSP deterministic control             Codec and input semantics
            |                                     |
       DTLS records                     SRTP / SRTCP packets
            |                                     |
            +----------- one UDP socket ----------+
                                |
                         one server port
```

The stack is:

| Concern | LSP/1 requirement |
| --- | --- |
| Network transport | UDP |
| Session security | DTLS 1.3, RFC 9147 |
| Media security | SRTP/SRTCP AEAD AES-128-GCM, RFC 7714 |
| Key export | DTLS-SRTP `use_srtp`, RFC 5764 |
| Media framing | RTP/RTCP, RFC 3550 |
| RTP/RTCP port sharing | RFC 5761 |
| Single-socket classification | RFC 7983 |
| Control encoding | deterministic CBOR, RFC 8949 section 4.2.1 |
| Congestion feedback | RFC 8888 SRTCP feedback |
| Video repair | RFC 8627 FlexFEC and deadline-eligible RFC 4588 RTX |
| Path MTU | RFC 8899 DPLPMTUD |

LSP uses out-of-band deterministic CBOR negotiation and does not use SDP.

## 4. Naming and versioning

- Protocol name: `Lumen Streaming Protocol`.
- Abbreviation: `LSP` within Lumen and Umbra documentation.
- Wire version: unsigned integer `1`.
- DTLS ALPN: exact ASCII `lumen-stream/1`.
- Default UDP port: `48030`.
- mDNS service type: `_lumen-stream._udp`.
- Invitation URI: `umbra://pair/lsp1#<base64url>`.

Every control message contains the wire version. RTP and RTCP formats are
selected only by an authenticated version-1 control negotiation. Unknown
versions, message types, payload types, SSRCs, header-extension IDs, or control
fields are rejected unless explicitly declared extensible.

An authentication or version failure MUST NOT trigger legacy or old-protocol
fallback. A different protocol requires an explicit new connection selected by
the user.

## 5. One-port transport

The host binds one configured UDP port number. It may use separate IPv4 and
IPv6 sockets only where required by the operating system, but both use the same
numeric port. No control response returns another port.

Pairing, authentication, application browsing, start, media, input,
microphone, feedback, path probes, stop, and teardown all use that port.

System mDNS uses the operating system's discovery service and is not an LSP
application listener. Legacy Moonlight listeners remain separate when enabled.

### 5.1 First-byte demultiplexing

The receiver follows RFC 7983:

| First-byte range | Meaning in LSP/1 |
| ---: | --- |
| `0...3` | reserved for future STUN; rejected in phase one |
| `16...19` | reserved; rejected |
| `20...63` | DTLS |
| `64...79` | reserved for future TURN channels; rejected in phase one |
| `128...191` | SRTP or SRTCP |
| all others | invalid |

RTP and RTCP are distinguished according to RFC 5761. Dynamic RTP payload type
assignments MUST avoid the RTCP conflict ranges required by that RFC.

DTLS records and SRTP/SRTCP packets MUST NOT be coalesced into one UDP
datagram. A UDP datagram may contain only DTLS records for one association or
one complete protected RTP/RTCP packet.

### 5.2 Peer identification

Before DTLS authentication, a candidate peer is identified by its network
five-tuple and stateless-cookie transcript. The server MUST validate return
routability before allocating durable connection state.

After authentication, the connection is bound to:

- remote address and port;
- DTLS association;
- host and client identities;
- connection generation;
- negotiated SSRC registry; and
- active stream-session generation, if any.

An address or port change requires a fresh DTLS association in version 1. An
authenticated `ATTACH` may transfer an existing stream after held input is
neutralized. Packets from the old association are then rejected.

## 6. Security

### 6.1 DTLS profile

LSP/1 requires DTLS 1.3. Endpoints MUST NOT negotiate DTLS 1.2 or earlier.

Required properties are:

- TLS cipher suite `TLS_AES_128_GCM_SHA256`;
- X25519 key agreement;
- server certificate authentication;
- stateless cookie validation before expensive server state;
- ALPN `lumen-stream/1`;
- no early application data;
- no anonymous cipher suite;
- no application data before certificate and host-pin validation; and
- no renegotiation semantics inherited from older DTLS versions.

Session resumption is disabled in the first implementation. A later extension
may enable it only when the ticket is bound to the paired host ID, client ID,
certificate SPKI, application identity keys, protocol version, expiry, and
revocation generation.

### 6.2 Host and client identities

The host owns:

- a stable random 128-bit host ID;
- an Ed25519 application identity key;
- a DTLS certificate and private key; and
- a monotonically increasing trust-revocation generation.

The client owns a stable random 128-bit client ID and Ed25519 application
identity key.

The DTLS certificate may be self-signed. Pairing stores the SHA-256 digest of
the certificate's DER SubjectPublicKeyInfo and the host Ed25519 public key.
Every later connection verifies both identities. Certificate rotation is a
signed, acknowledged control operation and never follows an untrusted network
hint.

### 6.3 Pairing invitation

The base64url invitation body is deterministic CBOR containing exactly:

| Key | Value |
| ---: | --- |
| 1 | wire version `1` |
| 2 | host ID, 16 bytes |
| 3 | host Ed25519 public key, 32 bytes |
| 4 | DTLS leaf SPKI SHA-256, 32 bytes |
| 5 | nonzero UDP port |
| 6 | hostname or IP literal |
| 7 | random invitation ID, 16 bytes |
| 8 | random single-use invitation secret, 32 bytes |
| 9 | expiration, whole UTC seconds |
| 10 | offered permission mask |

The fragment portion of the URI prevents normal HTTP referral leakage. The
invitation secret is accepted once, expires, and is stored only as a salted
verifier on the host. Pairing signs the complete client and server nonce
transcript with both application identity keys.

### 6.4 SRTP profile

The DTLS ClientHello offers `SRTP_AEAD_AES_128_GCM`. The server MUST select it
or fail the connection. No MKI is used in the initial implementation.

DTLS exports independent client-write and server-write SRTP master keys and
salts using the RFC 5764 `EXTRACTOR-dtls_srtp` exporter. RTP and RTCP packets
are then protected by SRTP/SRTCP, not by DTLS records.

Each SSRC has independent sequence, rollover, replay, and statistics state.
Authentication failure, replay failure, unknown SSRC, or invalid payload type
causes a silent packet drop and a bounded counter update. It does not expose
parser details to the network.

Custom RTP header extensions carrying input or timing metadata MUST use RFC
6904 encrypted header-extension processing. Frame marking may remain visible
because deadline/recovery classification needs it before payload inspection and
it contains no user data.

### 6.5 Rekey and lifetime

LSP/1 does not perform an in-place SRTP key transition. Before any SRTP
profile's packet or time lifetime is approached, the endpoints create a fresh
DTLS association and use authenticated `ATTACH` to transfer the session.

Input authority moves only after the new association is fully authenticated
and the old authority has been neutralized. A failed rekey attempt leaves the
old association authoritative until its safe lifetime or explicit teardown.

### 6.6 Authorization

Pairing grants an explicit LSP permission mask. Unknown bits are rejected.

| Bit | Permission |
| ---: | --- |
| 0 | browse applications |
| 1 | start or attach own stream |
| 2 | send raw device input and text |
| 3 | send client microphone |
| 4 | stop own stream |
| 5 | quit the hosted application |
| 6 | receive controller output/haptics |

Authentication returns the currently effective subset and its revocation
generation. Raw input packets, input rate changes, text, microphone, stop,
quit, and controller feedback are accepted only with their exact permission
and live session ownership. Permission loss neutralizes affected input before
the revocation response is acknowledged.

## 7. Connection and session state

```text
idle
  -> cookie validation
  -> DTLS handshake
  -> host pin verified
  -> application authentication
  -> ready
  -> starting
  -> streaming
  -> stopping
  -> ready
  -> closed
```

Every transition is driven by an authenticated control request and exact
response. A timeout cannot infer success. Duplicate requests return the cached
outcome for their request ID.

A connection may own at most one active streaming session. A host may impose a
smaller connection limit than its hardware session limit.

### 7.1 Generations

The following independent nonzero 32-bit generations are negotiated:

- connection authority;
- stream session;
- video configuration;
- audio configuration;
- microphone configuration;
- input authority; and
- controller instance for each controller slot.

Generation values never wrap within a connection. Exhaustion requires a new
connection. A packet or control message with a stale generation is ignored and
counted.

### 7.2 Attach

An accepted `START` returns a random 256-bit attach token. On transport loss,
the host immediately neutralizes pressed inputs and holds the process/capture
session for a bounded grace interval.

A fresh authenticated connection may send `ATTACH` with the session ID, token,
and a fresh intent ID. Success advances connection and input generations,
installs new SSRCs and keys, and requires a complete input baseline before
edges are accepted. The prior association cannot regain authority.

## 8. Reliable control over DTLS

DTLS application records are protected but not made reliably ordered by UDP.
LSP therefore defines a small bounded selective-repeat control protocol.

### 8.1 LSPC frame

All integers are unsigned network byte order.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `LSPC` |
| 4 | 1 | wire version `1` |
| 5 | 1 | flags |
| 6 | 2 | message type |
| 8 | 4 | connection generation |
| 12 | 4 | payload length |
| 16 | 8 | message ID |
| 24 | 8 | request ID, or zero for events/ACK-only |
| 32 | 8 | largest received peer message ID |
| 40 | 8 | selective ACK bitmap for the preceding 64 IDs |
| 48 | variable | deterministic CBOR payload |

Flags are:

| Bit | Meaning |
| ---: | --- |
| 0 | acknowledgement required |
| 1 | response |
| 2 | error response |
| 3 | ACK-only, requiring zero type/request/payload |
| 4 | final chunk of a bounded object |
| 5...7 | zero |

Each direction starts message IDs at one and increments once per new logical
frame. Retransmission uses the same message ID and byte-identical LSPC frame in
a new DTLS record.

The receiver accepts a new message ID only within the next 64 values after its
largest authenticated ID. Reordered IDs inside the retained window are allowed;
zero, wrap, reuse with different bytes, or a forward jump beyond the window is
malformed. The sender cannot have more than 64 distinct unacknowledged frames,
so no valid peer requires a larger jump.

The ACK base is itself acknowledged. Bitmap bit zero acknowledges `base - 1`,
bit 63 acknowledges `base - 64`. A sender retains no more than 64 unacknowledged
control frames. Values outside the live window cannot consume memory.

### 8.2 Reliability timing

- Urgent control is acknowledged immediately or within 1 ms.
- Normal control may be acknowledged within 5 ms and SHOULD piggyback an ACK.
- Out-of-order control is acknowledged immediately.
- Initial retransmission timeout is 20 ms on a directly connected or local
  path and 100 ms otherwise.
- After RTT samples exist, RTO is `max(5 ms, 1.5*SRTT + 4*RTTVAR)`, capped at
  250 ms.
- Retransmission backs off by two and never exceeds the message deadline.
- Five unsuccessful transmissions or deadline expiry returns an explicit
  timeout and closes security-sensitive operations.

No control retry blocks input, audio, or already-admitted video.

### 8.3 Idempotence

Request IDs are random nonzero 64-bit values within one connection generation.
The receiver caches the terminal response digest and response bytes until the
request retention deadline. A duplicate request returns the same response and
does not repeat side effects.

Transactional requests include pairing, application start, attach, stop,
permission changes, configuration changes, and certificate rotation.

### 8.4 Large objects

Artwork, application snapshots, and diagnostics use bounded control chunks.
Each chunk fits one path-MTU-safe DTLS datagram and includes object ID, offset,
total length, and final SHA-256 in its CBOR payload.

Large-object transfer:

- has at most 16 chunks outstanding;
- is the lowest scheduler class;
- pauses while a latency stream is active unless explicitly needed for that
  stream;
- never shares storage with media packet slabs; and
- is limited to 16 MiB per object and 32 MiB per connection.

## 9. Control message registry

Exact CBOR schemas MUST be frozen with golden vectors before the corresponding
product control operation is enabled. The top-level message types are reserved:

| Type | Name | Direction |
| ---: | --- | --- |
| `0x0001` | `CLIENT_HELLO` | client to host |
| `0x0002` | `SERVER_HELLO` | host to client |
| `0x0010` | `PAIR_REQUEST` | client to host |
| `0x0011` | `PAIR_RESPONSE` | host to client |
| `0x0020` | `AUTH_REQUEST` | client to host |
| `0x0021` | `AUTH_RESPONSE` | host to client |
| `0x0100` | `LIST_APPLICATIONS` | client to host |
| `0x0101` | `APPLICATIONS` | host to client |
| `0x0200` | `START` | client to host |
| `0x0201` | `START_RESPONSE` | host to client |
| `0x0202` | `ATTACH` | client to host |
| `0x0203` | `ATTACH_RESPONSE` | host to client |
| `0x0204` | `STOP` | either direction |
| `0x0205` | `STOP_RESPONSE` | opposite direction |
| `0x0210` | `VIDEO_CONFIG` | host to client |
| `0x0211` | `VIDEO_CONFIG_ACK` | client to host |
| `0x0212` | `AUDIO_CONFIG` | host to client |
| `0x0213` | `AUDIO_CONFIG_ACK` | client to host |
| `0x0214` | `MICROPHONE_CONFIG` | host to client |
| `0x0215` | `MICROPHONE_CONFIG_ACK` | client to host |
| `0x0216` | `TEXT_INPUT` | client to host |
| `0x0217` | `TEXT_INPUT_RESPONSE` | host to client |
| `0x0218` | `INPUT_RATE_REQUEST` | client to host |
| `0x0219` | `INPUT_RATE_RESPONSE` | host to client |
| `0x0220` | `STREAM_ENDED` | host to client |
| `0x0300` | `PATH_PROBE` | either direction |
| `0x0301` | `PATH_PROBE_ACK` | opposite direction |
| `0x0400` | `OBJECT_CHUNK` | either direction |

Configuration-dependent SRTP packets MUST NOT be transmitted until the
corresponding configuration ACK is authenticated.

## 10. START negotiation

`START` offers:

- application and resume intent;
- competition or adaptive-low-latency network profile;
- exact resolution and rational refresh rate;
- maximum and preferred encoded bitrate;
- ordered codec profiles and pixel formats;
- HDR and chroma capabilities;
- Opus layouts and frame durations;
- microphone capabilities;
- presentation modes;
- DPLPMTUD maximum;
- FlexFEC and RTX support;
- input capture sources, per-device capture-rate observations, requested
  pointer/controller/sensor report-rate ranges, maximum input wire budget, and
  device capabilities;
- client receive-batch capacity, maximum in-flight hardware-decode surfaces,
  and render-mailbox capacity;
- complete-access-unit or bounded-incremental encoder delivery.

`START_RESPONSE` selects one exact tuple and returns:

- session ID and attach token;
- selected scalar and codec values;
- every configuration generation;
- every SSRC and dynamic RTP payload type;
- RTP header-extension ID mapping;
- repair associations;
- initial pacing and congestion parameters;
- selected pointer, controller-state, controller-sensor, and input-refresh
  rates plus reserved input wire budget;
- initial UDP payload size; and
- capture-path status.

The host may select a lower bitrate, resolution, or refresh rate only within an
offered range. Strict offers fail instead of being adjusted.

## 11. RTP session and lane registry

All real-time lanes form one RTP session on the LSP five-tuple. Every active
source has a random nonzero SSRC. The authenticated control mapping, not packet
guessing, assigns semantics.

| Lane | Direction | RTP/SRTCP form |
| --- | --- | --- |
| video primary | host to client | SRTP, H.264/HEVC/AV1 payload |
| video repair | host to client | SRTP FlexFEC SSRC |
| video RTX | host to client | SRTP RTX SSRC, optional |
| audio | host to client | SRTP Opus SSRC |
| input state/edges | client to host | SRTP LSP input SSRC |
| input acknowledgement | host to client | SRTCP APP |
| controller feedback | host to client | SRTCP APP |
| microphone | client to host | SRTP Opus SSRC |
| congestion feedback | receiver to sender | SRTCP RFC 8888 |
| media loss/recovery | receiver to sender | SRTCP AVPF |
| LSP frame status | client to host | SRTCP APP |
| timing and source reports | both | SRTCP SR/RR/XR |

Payload types are dynamically selected from the valid RTP/RTCP-mux range.
Changing codec or payload type requires a new acknowledged generation.

Every negotiated SSRC is unique within the bundled RTP session and nonzero.
The endpoint generating the registry checks collisions before sending the
configuration; the peer independently rejects duplicate SSRC or conflicting
payload-type assignments. An unexpected SSRC never creates state. An SSRC
collision discovered after activation ends the affected media generation and
requires a new authenticated configuration rather than guessing ownership.

## 12. Common RTP profile

### 12.1 Clocks

- Video uses a 90 kHz RTP clock.
- Audio and microphone use a 48 kHz RTP clock.
- Input uses a 1 MHz RTP clock derived from the client monotonic clock.
- RTP sequence numbers follow RFC 3550 and SRTP rollover processing.
- Random initial sequence numbers, timestamps, and SSRCs are mandatory.

RTP timestamps describe media sampling time, not packet send time. RTCP sender
reports and capture-time extensions establish timing relationships.

### 12.2 Header extensions

LSP negotiates RFC 8285 one-byte header-extension IDs. Middle packets of an
ordinary video frame carry no RTP header extension unless a negotiated repair
or scalable-codec rule requires one. Keeping the high-rate middle packets
extension-free increases codec payload per datagram and avoids header-extension
encryption work on every packet.

| Extension | Size | Transmission |
| --- | ---: | --- |
| RFC 9626 frame marking | short form | first two and final video packets |
| RFC 8872 absolute capture time | 8 bytes | first two packets of a video frame |
| `urn:lumen:rtp-hdrext:frame-id` | 8 bytes | first two and final video packets |
| `urn:lumen:rtp-hdrext:input-watermark` | 16 bytes | first two packets of a video frame |
| `urn:lumen:rtp-hdrext:encoder-timing` | 8 bytes | first two packets of a video frame |

Frame ID is a nonzero 64-bit encoder access-unit counter. The input watermark
contains the last completely applied input state sequence and edge ID, each as
64-bit network-order values. Encoder timing contains capture-to-submit and
capture-to-complete microseconds as two saturated 32-bit values.

The receiver keys provisional frame assembly by SSRC plus extended RTP
timestamp, so it does not require an LSP extension on every fragment. Frame ID
binds to that assembly when any repeated metadata packet arrives. FlexFEC
recovers the original RTP header and extensions when it repairs such a packet.

The custom extensions are encrypted under RFC 6904. Missing all repeated
timing metadata does not prevent codec-level frame reassembly, but makes that
frame ineligible for the corresponding telemetry sample. The packetizer MUST
fill extension-free middle packets to the current path payload maximum before
creating another fragment.

### 12.3 Packet size

The initial maximum UDP payload is 1,200 bytes. The endpoint may increase it
only after authenticated RFC 8899-style probe acknowledgement.

Before high-rate video begins, the endpoints perform a two-RTT fast search at
1,400 bytes and then the configured IPv4/IPv6 ceiling. Failure leaves 1,200 as
the safe value and does not block input or control. Later probing runs in the
background. This makes full Ethernet-MTU payloads the expected wired-LAN state
rather than an optional optimization that may never occur.

Normal packets MUST NOT exceed the current discovered UDP payload size and
MUST NOT rely on IPv4 or IPv6 fragmentation. A path reduction applies at the
next packet boundary; video repacketizes only at a frame boundary.

The configured upper probe bound is the smallest of:

- the sender interface limit;
- the receiver-advertised limit;
- the operator-configured limit; and
- 1,472 bytes for IPv4 or 1,452 bytes for IPv6 on a standard 1,500-byte path.

Jumbo frames are outside LSP/1 conformance even when a private network supports
them.

## 13. Video

### 13.1 Codec payloads

- H.264 packetization follows RFC 6184 non-interleaved mode.
- HEVC packetization follows RFC 7798 single-stream mode.
- AV1 packetization follows AOM RTP Payload Format For AV1 v1.0.0.
- RTP marker is set on the last packet of the encoded frame or temporal unit as
  required by the payload format.
- Frame-marking start/end/independent/discardable bits must agree with the
  codec payload and encoder dependency state.

The portable packetizers further freeze these LSP/1 policies:

- H.264 accepts Annex-B-prefix-free source NAL types `1...23`, emits single
  NAL packets, STAP-A type `24`, or FU-A type `28`, and never emits STAP-B,
  MTAP, FU-B, interleaved mode, or cross-frame aggregation.
- HEVC accepts complete Annex-B-prefix-free source NAL types `0...47`, emits
  single NAL packets, aggregation packets of type `48`, or fragmentation units
  of type `49`, and never emits PACI, DONL, or cross-frame aggregation.
- AV1 accepts normalized OBU types `1`, `3...7`, and `15` with the OBU
  size-field and reserved bits clear. It omits temporal delimiters, uses the
  AOM `Z`, `Y`, `W`, and `N` aggregation-header semantics, and sets `N` only
  on the first packet of an explicitly identified coded-video-sequence start.
- Every packetizer accepts only dynamic payload types `96...127` and a nonzero
  negotiated SSRC. It sets the RTP marker only on the last packet of the access
  unit or temporal unit.

Within one already available encoded frame or incremental encoder chunk, the
packetizer aggregates small NAL units or OBUs when the codec payload format
permits and the result fits the current path maximum. It never aggregates
across frame boundaries and never waits for a future encoder chunk merely to
fill a packet.

Codec configuration is sent over `VIDEO_CONFIG`, acknowledged, installed in
the decoder, and repeated in-band at the codec's recovery boundary.

### 13.2 Encoder profile

Competition mode requires:

- hardware encoding;
- no B-frame reordering;
- no lookahead;
- one capture-to-encoder admission slot;
- the lowest-latency verified encoder preset;
- bounded VBV sized from the selected network profile;
- runtime bitrate reconfiguration at frame boundaries; and
- reference invalidation, intra refresh, or explicit capability reporting.

Competition mode SHOULD select bounded-incremental slice, tile, or OBU delivery
when the encoder exposes all of:

- a trustworthy maximum protected byte bound for the access unit before its
  first network packet;
- final reference/independence metadata before admission;
- stable chunk lifetime through packet construction; and
- a callback path that does not poll or copy the partial frame repeatedly.

This fast path overlaps the latter part of encoding with network transmission.
An encoder lacking any required property uses complete-access-unit delivery;
the protocol never guesses a remaining frame size.

An encoder without a verified low-delay mode is rejected for competition mode.

### 13.3 Frame admission

Before the first packet of a frame is submitted, the sender estimates whether
the complete protected frame plus selected repair can leave the pacer before
its network deadline. Complete-access-unit mode uses the exact encoded size.
Bounded-incremental mode reserves byte credit using the encoder's declared
maximum access-unit size plus worst-case selected repair.

If the estimate fails:

- the frame is dropped before partial network submission;
- the drop is reported to the encoder dependency controller;
- the encoder target rate is reduced;
- no IDR is requested solely because of this admission failure; and
- a later dependent frame is admitted only if the encoder confirms a valid
  reference path.

Once a frame begins network submission, the pacer attempts to complete it
within the same deadline. An unexpected mid-frame failure marks the frame
locally incomplete, prevents known-invalid dependents from being emitted, and
enters one recovery epoch.

In bounded-incremental mode, each completed encoder chunk is packetized and
made eligible immediately within the already reserved frame budget. Unused
reservation is returned when the access unit ends. Exceeding the declared
bound is an encoder-contract failure: the sender cancels the frame, enters one
recovery epoch, and disables incremental delivery for the remainder of the
session rather than overrunning the pacer.

At most one unsent encoded frame and one actively packetized frame are retained
in competition mode. Already submitted packet storage may remain until its
repair deadline.

### 13.4 Deadlines

The host computes:

```text
network_deadline = capture_time
                 + selected maximum capture-to-client budget
                 - measured encode/decode/render reserves
```

The deadline is clamped no later than the next selected presentation
opportunity for competition mode. Packets that cannot leave before this
deadline are not sent.

Deadline expiration is a media event, not a connection error.

### 13.5 FlexFEC

Both endpoints implement RFC 8627 single-stream FlexFEC. The selected repair
SSRC protects only its associated primary video SSRC.

Competition defaults are:

- zero active parity on a clean path;
- small frame-local protection groups;
- no group spans two encoded frames;
- repair is emitted before the protected frame deadline;
- independent/configuration frames may receive stronger protection; and
- parity increase follows measured burst loss, not RTT variation alone.

Repair packets consume the same aggregate congestion and pacing credit as
primary packets. The receiver attempts repair immediately when sufficient
packets exist and never delays a complete primary frame waiting for optional
repair.

FEC and SRTP use the default RFC 3711 section 10 `FEC-SRTP` order. The sender
updates an incremental plaintext RTP parity accumulator as each final source
packet is constructed, then protects the source and repair RTP packets in
place under their respective SRTP contexts. It does not retain a second
plaintext copy of every source packet.

The receiver authenticates and decrypts received source and repair packets
before FEC decoding. A recovered plaintext source packet is constructed in a
packet slab, marked as authenticated-by-repair, passed through the same RTP
parser and generation checks, and entered into the source sequence/replay
state so that a later original copy is discarded. FEC state never bypasses
SSRC, payload-type, size, generation, or frame-deadline validation.

The portable FlexFEC group state enforces this exact transition order:

```text
idle
  -> accumulating plaintext source RTP
  -> sealed plaintext repair parity
  -> constructed plaintext repair RTP
  -> repair ready for SRTP
  -> complete
```

A group is frame-local, protects one primary SSRC with one distinct repair
SSRC, and represents at most 64 source sequence numbers in one 64-bit mask.
The accumulator stores only the zero-padded plaintext XOR, the XOR of source
packet lengths, and group metadata. It does not retain source-packet pointers.

### 13.6 RTX

RTX follows RFC 4588 and is negotiated with a separate SSRC and payload type.
Competition mode enables it whenever the measured path and frame budget can
return a packet in time. It is inactive, without negotiation churn, when the
deadline test fails.

The receiver confirms a sequence gap after either two later primary packets
arrive or a path-adaptive reorder delay expires. On a validated wired
competition path that delay is at most 100 microseconds and may be zero when
reordering has not been observed. Eligible Generic NACK is emitted immediately
and does not wait for the periodic congestion-feedback report.

If authenticated repair already received for the group makes recovery
deterministic, the receiver performs FEC instead of sending NACK. It does not
wait beyond the same reorder delay for repair that has not arrived, so enabling
FEC cannot silently add a frame of latency.

A NACK is eligible only when:

```text
now + estimated reverse feedback delay
    + retransmission serialization delay
    + estimated forward delay
    + decode safety reserve
  < frame deadline
```

The receiver suppresses ineligible NACKs. The sender independently repeats the
deadline test. A retransmission is paced and counted against congestion credit.

The sender retains the immutable final source-packet slab only until the
earlier of the frame repair deadline or one measured RTT, with a maximum of two
frame generations and 16 MiB per connection. Retention creates no second copy
in steady state. An actual RTX packet is constructed once in a new final slab
only after an eligible NACK.

The portable retention state stores an opaque nonzero slab token and bounded
metadata. Lookup requires the active video generation, primary SSRC, original
sequence number, unexpired retention, and the same strict reverse-feedback,
serialization, forward-delivery, and decode-reserve deadline test used by the
receiver. Whole older frames are evicted when the two-frame or 16 MiB bound
would otherwise be exceeded.

### 13.7 Recovery state machine

Recovery is scoped to a monotonically increasing recovery epoch:

1. repair an isolated loss with FlexFEC when possible;
2. use deadline-eligible RTX when negotiated;
3. report the exact lost RTP sequence range and affected frame ID;
4. invalidate damaged references or request bounded intra refresh;
5. send PLI/FIR and produce one independent frame only when reference repair
   is unavailable or the decoder reports unrecoverable state; and
6. leave recovery only after the client reports successful decode of the
   recovery frame.

Only one independent recovery frame may be outstanding. Repeated feedback for
the same epoch does not create more keyframes. A new IDR retry requires expiry
of the prior recovery deadline and evidence that it did not decode.

The sender recovery state is exactly `healthy`, `repairing-references`,
`recovery-frame-outstanding`, or `retry-permitted`. An epoch opens only for an
unrecoverable reference loss, an explicit unrecoverable decoder report, or an
unexpected partial frame after network admission. It advances monotonically
without wrapping to zero and returns to `healthy` only when protected feedback
confirms that the one outstanding independent recovery frame decoded.

Sender queue pressure, an expired non-reference frame, and a presentation drop
do not by themselves trigger PLI/FIR.

### 13.8 Video feedback

The client uses:

- RFC 4585 Generic NACK for eligible missing RTP packets;
- RFC 4585 PLI and RFC 5104 FIR for independent-frame recovery;
- RFC 8888 congestion feedback;
- receiver reports for loss and jitter; and
- protected RTCP APP name `LSPV` for decoded/presented frame state.

`LSPV` carries session generation, video generation, recovery epoch, largest
complete frame ID, largest decoded frame ID, largest Metal-committed frame ID,
deadline miss, decoder status, current in-flight decode submissions, maximum
decode submissions, and current render-mailbox occupancy. The client sends it
on each decode completion or capacity transition, subject to one coalesced
packet per 500 microseconds. It is observation, decoder credit, and recovery
input, never an unauthenticated encoder command.

The host's complete-frame admission includes the client's most recent decoder
credit and measured decode-completion rate. Credit is a freshness-bounded hint,
not a reliable token: the receiver remains authoritative and drops before
decoder submission when no hardware surface is available.

The portable RTCP layer currently verifies compound and RFC 5506 reduced-size
datagrams and serializes bounded RFC 4585 Generic NACK and PLI plus RFC 5104
FIR packets. Its RFC 8888 state retains disjoint authenticated packet reports
and makes feedback due at the earlier of 2 ms or 128 packets, subject to the
500-microsecond hard floor. Its `LSPV` state validates generation, frame-order,
decoder-credit, and mailbox invariants and coalesces decode/capacity updates at
the same 500-microsecond minimum. Protection and live SRTCP submission remain
product-integration work.

## 14. Audio and microphone

Audio and microphone use RFC 7587 Opus RTP payloads on independent SSRCs.

The negotiation supports 2.5, 5, 10, and 20 ms frames where the complete packet
fits the path maximum. Competition mode prefers 5 ms and may select 2.5 ms only
after end-to-end device and CPU validation.

- One Opus packet occupies one RTP packet.
- Audio is never fragmented at the application layer.
- No audio or microphone RTX is used.
- Opus packet-loss concealment handles isolated loss.
- Optional in-band Opus FEC may be enabled only when its added algorithmic
  delay improves measured results.
- Silence uses DTX or valid silence packets without tearing down devices.
- The audio jitter buffer starts at one packet and continuously shrinks toward
  the minimum stable preroll. A validated competition path may select
  zero-extra-preroll only when measured arrival variation and audio-device
  callback headroom prove that direct playout does not underrun.
- Audio discontinuity resets sample continuity explicitly.
- Audio never blocks video or input queues.

SRTCP sender reports relate the 48 kHz RTP timeline to the sender clock.

## 15. Input protocol

Input is a new LSP SRTP payload and does not reuse the old protocol's input
record.

### 15.1 Independent clocks and rate negotiation

Input has no dependency on video capture, encoding, frame delivery, display
refresh, V-Sync, audio cadence, or statistics publication. No implementation
may schedule input from a video-frame callback.

LSP distinguishes three rates:

- **capture rate:** physical reports actually delivered by the local OS/device;
- **network report rate:** state packets emitted by the client; and
- **host apply rate:** reports the host input backend can consume.

Each is measured and reported separately. The selected network rate is bounded
by client capability, host apply capability, and the reserved input wire
budget, not by stream FPS.

Wire version 1 supports:

| Input class | Negotiated rate |
| --- | ---: |
| key/button/touch lifecycle edges | event-driven, immediate |
| pointer motion | `125...16000` reports/s |
| controller sticks and analog triggers | `125...2000` reports/s |
| controller gyro/accelerometer | `125...4000` reports/s |
| core/device reconciliation refresh | `50...1000` reports/s |

All competition implementations MUST sustain 1,000 pointer reports/s and
SHOULD sustain 8,000. A client MAY offer 16,000 after a real or synthetic local
capture probe. Advertising a rate does not claim the device or OS actually
delivers it; the effective capture distribution is telemetry.

A device arriving after START sends `INPUT_RATE_REQUEST` with input generation,
device type/ID, instance generation, observed capture distribution, supported
state/sensor rates, and worst-case packet sizes. Until the authenticated
response, physical edges are still immediate while pointer/controller state is
limited to the already admitted 1,000/250 reports/s safe rate. The response
selects per-device rates within the existing 32 Mbps aggregate input budget or
explicitly lowers other replaceable device rates. A rate change neither resets
cumulative state nor advances device generation.

When physical capture exceeds the selected network rate, the client combines
samples without losing state: relative pointer data uses cumulative counters,
absolute axes use the newest value, and physical edges remain individually
ordered. When the network rate exceeds current device activity, no empty
packet is sent merely to meet a nominal frequency.

A high keyboard polling rate reduces the time until a physical transition is
observed; it does not require thousands of empty keyboard packets per second.
The client sends the transition immediately as an edge, then relies on edge
acknowledgement plus bounded core-state reconciliation. Operating-system key-
repeat callbacks do not create new physical down edges.

### 15.2 Delivery model

Input combines:

- a multipart complete baseline sent only when input authority is established;
- a compact high-rate pointer-motion state;
- a small replaceable keyboard/mouse core state;
- independently replaceable controller state, controller sensors, touch, and
  pen state; and
- small ordered non-replaceable edge packets retained until acknowledged.

The client sends an edge packet immediately. While edges remain unacknowledged
it repeats them in later edge packets in ascending order. Edge packets never
carry the complete device snapshot and never wait for a controller/touch state
packet to fill.

Pointer, controller, sensor, core, and device state packets are sent only when
changed or when their bounded refresh deadline expires. The scheduler
coalesces only packets with the same `(input generation, kind, device type,
device ID, instance generation)` supersession key. The host applies each edge
ID exactly once and may replace an older state object with a newer value after
all intervening edges for that object are accounted for.

### 15.3 Input payload

All integers use network byte order.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | input generation |
| 4 | 1 | kind |
| 5 | 1 | flags |
| 6 | 2 | payload length |
| 8 | 8 | state sequence |
| 16 | 8 | client monotonic sample time, microseconds |
| 24 | 8 | kind-specific object ID |
| 32 | 8 | greatest edge ID observed before this state sample |
| 40 | variable | kind payload |

Every complete input RTP packet fits the current path maximum. Input never uses
IP or application fragmentation.

All parts of the initial baseline carry state sequence one. After baseline
commit, state sequence starts at two and increments once per new logical
replaceable pointer/core/controller/sensor/device sample. Edge-batch repetition
does not advance it; an edge packet carries the latest sampled state sequence.
A packet retransmission is byte-identical at the LSP input layer but receives a
new RTP/SRTP sequence number.

State sequence and physical-sample ordinals are nonzero and never wrap. Payload
length equals the bytes remaining after the 40-byte input header exactly.
Unknown kinds, nonzero reserved flag bits, kind-invalid object IDs, oversized
records, or trailing bytes are malformed and discarded before state mutation.

The edge watermark binds replaceable state to ordered physical changes. The
host may authenticate and retain the newest state for a supersession key, but
does not apply it until its greatest contiguous applied edge ID reaches the
watermark. Waiting retains only the newest state per key, never a FIFO of
intermediate analog/motion samples.

Kinds are:

| Kind | Name | Object ID | Scheduling behavior |
| ---: | --- | --- | --- |
| 1 | pointer motion | pointer device ID | latest cumulative sample wins |
| 2 | core state | zero | latest keyboard/mouse state wins |
| 3 | controller/device state | encoded device type and ID | latest matching state wins |
| 4 | controller sensor state | encoded controller and sensor | latest matching sample wins |
| 5 | edge batch | newest edge ID | urgent, retained until ACK |
| 6 | baseline part | random baseline ID | retained until baseline ACK |

Pointer-motion payload is exactly 56 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | pointer instance generation |
| 4 | 2 | flags: relative or absolute; exactly one |
| 6 | 2 | physical reports represented, `1...65535` |
| 8 | 8 | newest physical-sample ordinal |
| 16 | 8 | cumulative relative X, signed |
| 24 | 8 | cumulative relative Y, signed |
| 32 | 8 | cumulative vertical scroll, signed |
| 40 | 8 | cumulative horizontal scroll, signed |
| 48 | 4 | absolute X Q0.32, zero in relative mode |
| 52 | 4 | absolute Y Q0.32, zero in relative mode |

The host stores the last applied cumulative values and injects their difference.
Loss of an intermediate replaceable motion packet therefore loses timing
resolution but not pointer distance or scroll. The common input timestamp is
the newest represented physical sample time. A packet whose physical ordinal
or state sequence is not newer than the accepted value for that pointer is
ignored. Cumulative counters reset only with a committed baseline or new input
generation and never wrap; approaching signed 64-bit exhaustion forces a new
generation. A platform API with a smaller delta field receives bounded chunks
whose sum equals the full cumulative difference.

Core state contains the keyboard HID bitmap, mouse buttons, pointer mode,
cumulative relative pointer/wheel values, and absolute coordinates. It has a
fixed maximum size of 128 bytes.

Controller/device state begins with device type, device ID, nonzero instance
generation, physical-sample ordinal, represented-sample count, and record
length. A controller record carries the newest sticks, analog triggers,
battery, and non-edge state. A packet otherwise carries one pen or a bounded
group of touch coordinates that fits one path-sized packet.

Device classes are frozen as keyboard `1`, pointer `2`, controller `3`, touch
`4`, and pen `5`. Controller sensor classes are gyroscope `1` and
accelerometer `2`.

For a normal device-state object ID, bits `63...56` carry the device class,
bits `55...32` are zero, and bits `31...0` carry a nonzero device ID. For a
controller-sensor object ID, bits `63...56` carry controller class `3`, bits
`55...48` carry the sensor class, bits `47...32` are zero, and bits `31...0`
carry the nonzero controller ID. Pointer-motion object IDs are the pointer ID
`1...4`; core-state object ID is zero; edge-batch object ID is its newest edge
ID; and baseline-part object ID is the nonzero random baseline ID.

Every device-state and sensor-state kind payload begins with this exact 24-byte
prefix:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | device class |
| 1 | 1 | zero for device state; sensor class for sensor state |
| 2 | 2 | physical reports represented, nonzero |
| 4 | 4 | nonzero device ID |
| 8 | 4 | nonzero instance generation |
| 12 | 2 | exact complete kind-payload length |
| 14 | 2 | zero |
| 16 | 8 | nonzero newest physical-sample ordinal |

Kind-specific state bytes follow this prefix. The common object ID and prefix
MUST identify the same device and, for sensor state, the same sensor.

Controller sensor state independently carries timestamped gyro or
accelerometer vectors. Sticks, analog triggers, sensors, and touch coordinates
may be coalesced only under their exact controller/device supersession key.
Controller arrival/removal, framework-reported digital button changes, and
touch/pen lifecycle changes are edges rather than replaceable state. Up to 16
controllers retain independent instance generations and rate selections.

An edge batch carries `1...16` exact 32-byte records with contiguous IDs. The
same edge may appear in multiple packets until acknowledged. Repetition does
not create a new edge or state sequence.

Each edge record has this exact layout:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | nonzero edge ID |
| 8 | 8 | nonzero client monotonic physical time, microseconds |
| 16 | 1 | edge kind |
| 17 | 1 | device class |
| 18 | 2 | HID usage, button, contact, pen control, or lifecycle control ID |
| 20 | 4 | nonzero device ID |
| 24 | 4 | nonzero instance generation |
| 28 | 4 | signed kind-specific scalar, slot, or lifecycle value |

The edge-kind registry is:

| Value | Kind | Required device class |
| ---: | --- | --- |
| 1 | key down | keyboard |
| 2 | key up | keyboard |
| 3 | pointer button down | pointer |
| 4 | pointer button up | pointer |
| 5 | controller arrival | controller |
| 6 | controller removal | controller |
| 7 | controller button down | controller |
| 8 | controller button up | controller |
| 9 | touch begin | touch |
| 10 | touch end | touch |
| 11 | touch cancel | touch |
| 12 | pen begin | pen |
| 13 | pen end | pen |
| 14 | pen cancel | pen |

A complete baseline is a deterministic byte string containing core state plus
every active device and contact. It is split into at most 32 path-sized baseline
parts. Each part carries part index, part count, total length, and a SHA-256
digest. The total is at most 32 KiB. The host buffers one baseline ID and
atomically installs it only after every authenticated part and the digest are
valid. Normal state and edges are not applied until baseline ACK. Missing parts
are retransmitted without changing the baseline ID or state sequence.

The exact 48-byte baseline metadata preceding each part range is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | zero-based part index |
| 1 | 1 | part count, `1...32` |
| 2 | 2 | zero |
| 4 | 4 | complete baseline length, `1...32768` |
| 8 | 4 | exact part byte offset |
| 12 | 4 | exact nonzero part byte length |
| 16 | 32 | SHA-256 of the complete deterministic baseline |
| 48 | variable | exact part bytes |

The common input-header flags are zero in LSP/1. The pointer, device prefix,
edge, and baseline-part layouts above are frozen and implemented. The portable
codec does not yet define the device-specific state bodies following the
24-byte prefix or the deterministic complete-baseline body. Those body schemas
and their product integration remain in progress and are not counted as a
completed wire primitive.

### 15.4 Input acknowledgements

Protected SRTCP APP name `LSPI` acknowledges:

- input generation;
- accepted baseline ID, or zero before baseline commit;
- highest accepted replaceable-state sequence;
- highest applied replaceable-state sequence;
- highest applied pointer physical-sample ordinal for each active pointer;
- greatest contiguous edge ID applied;
- 64-bit edge reception bitmap;
- host monotonic receive and apply times; and
- first captured video frame ID carrying the applied watermark.

The bytes following the SRTCP APP name have an exact fixed 72-byte prefix and
zero through four 16-byte pointer records:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | nonzero input generation |
| 4 | 1 | pointer record count, `0...4` |
| 5 | 1 | flags; bit 0 requests a baseline, all other bits zero |
| 6 | 2 | zero |
| 8 | 8 | accepted baseline ID, or zero |
| 16 | 8 | highest accepted replaceable-state sequence |
| 24 | 8 | highest platform-applied replaceable-state sequence |
| 32 | 8 | greatest contiguously applied edge ID |
| 40 | 8 | forward edge-reception bitmap; bit 0 names the next edge ID |
| 48 | 8 | host monotonic receive time, microseconds |
| 56 | 8 | host monotonic apply-completion time, microseconds |
| 64 | 8 | first captured video frame ID carrying the watermark |
| 72 | `16*n` | active-pointer records |

Each pointer record contains a pointer ID `1...4`, its nonzero instance
generation, and its nonzero greatest applied physical ordinal as `4`, `4`, and
`8` bytes respectively. Pointer IDs in one ACK are unique, applied state never
exceeds accepted state, and the payload length is exactly `72 + 16*n` bytes.

The host sends an ACK immediately after baseline commit or an edge is applied.
While high-rate input is active it also sends at the earlier of 1 ms or eight
newly applied input records, with a hard minimum interval of 125 microseconds.
The client removes only explicitly acknowledged edges and stops baseline-part
retransmission only after the matching baseline ID is acknowledged.

An unacknowledged edge is retried after `clamp(SRTT / 2, 250 microseconds,
2 ms)`. Retry uses the same edge ID and physical timestamp. Replaceable motion,
stick, trigger, sensor, touch-coordinate, and core state are not retransmitted;
a newer cumulative/latest state supersedes them.

If the retained edge window cannot represent a gap, the host requests a new
baseline with an expected next edge ID. The client does not invent continuity.

### 15.5 Input scheduling and safety

Input edges and teardown neutralization are the highest scheduler class.
Pointer motion and input ACK are next, followed by controller state/sensors and
reconciliation state. Input packets are small, never FEC-protected, and never
wait for a video pacing quantum. A new edge wakes the transmit worker
immediately.

`START_RESPONSE` reserves the complete estimated IP/UDP/SRTP/RTP input wire
rate in the client-to-host controller before microphone, client feedback, or
bulk credit. At the maximum 16 kHz pointer rate, the fixed 56-byte motion
payload is approximately 19.5 Mbps including IPv4 and UDP headers; the exact
IPv4/IPv6 negotiated budget is computed rather than guessed.

Host-to-client video and client-to-host input have independent congestion and
pacing state. LSP does not subtract reverse input bytes from a forward video
window. On an explicitly characterized Wi-Fi, wireless, or other shared/
half-duplex medium, a session-level coordinator MAY reduce optional forward
video when reverse input shows queueing or loss; it never delays input to
protect video. If the client-to-host path cannot sustain selected input plus
mandatory control minima, the endpoints explicitly renegotiate the input rate
or end the session; they never build an input queue.

Each replaceable input packet expires after one selected report interval.
Queued motion or analog state is overwritten in place by the newer cumulative
or latest sample before SRTP protection. Once protected/submitted, a packet is
immutable and a later sample receives a new RTP sequence number.

An edge is never silently discarded as stale. Competition mode gives each
edge a 2 ms client-sample-to-host-apply budget. If network retry or the platform
injector cannot satisfy the budget, the host reports input pressure,
neutralizes ambiguous held state, and requests a baseline or ends input
authority. It does not preserve correctness by accumulating a late edge FIFO.

On disconnect, authentication loss, generation replacement, timeout, or input
parser failure, the host atomically releases all held keys, buttons, touches,
pens, and controllers before another authority is accepted.

Controller output uses protected SRTCP APP name `LSPG` and includes input plus
controller-instance generations. Rumble amplitudes and LED color are
replaceable latest state. Adaptive-trigger programs, haptic waveform changes,
motion-sensor enable/disable, and player-slot changes are acknowledged edges.
Feedback for a removed or rebound controller generation is ignored.

The LSPG application data begins with this exact 28-byte envelope:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `LSPG` |
| 4 | 1 | wire version `1` |
| 5 | 1 | subtype: latest state `1`, command `2`, or acknowledgement `3` |
| 6 | 2 | exact subtype-payload length |
| 8 | 4 | nonzero input generation |
| 12 | 4 | nonzero controller ID |
| 16 | 4 | nonzero controller instance generation |
| 20 | 8 | nonzero direction-wide output sequence |
| 28 | variable | subtype payload |

Latest state has an exact eight-byte payload: low-frequency rumble `uint16`,
high-frequency rumble `uint16`, red, green, and blue LED bytes, then one zero
byte. A command payload contains command kind, one zero byte, a two-byte
parameter length, and `0...224` parameter bytes. Command kinds are adaptive
trigger `1`, haptic waveform `2`, motion sensor `3`, and player slot `4`. An
acknowledgement payload is four bytes: status followed by three zero bytes.
Statuses are success `0`, unsupported `1`, stale generation `2`, failed `3`,
and expired `4`. Complete LSPG application data is at most 256 bytes.

Each controller-output direction has a nonzero 64-bit command sequence.
Replaceable rumble/LED state may skip obsolete sequences. An acknowledged
command is retained and retried with the same sequence after
`clamp(SRTT / 2, 250 microseconds, 5 ms)` until the client returns an `LSPG`
ACK subtype or its bounded deadline expires. The ACK contains input generation,
controller ID, controller instance generation, command sequence, and status.
A stale-generation command is not applied but receives a stale status so the
host can retire it without retrying against a rebound device.

An `LSPG` packet is at most 256 bytes and aggregate controller output is capped
at 1,000 packets/s per connection. Haptic or adaptive-trigger commands name
negotiated device primitives and bounded parameters; arbitrary waveform/file
streaming is not part of LSP/1. Output traffic has its own small host-to-client
reserve and cannot consume the input receive/ACK reserve.

### 15.6 Umbra capture and Lumen apply requirements

Umbra's preferred keyboard and pointer path uses public IOHID input-value or
timestamped input-report callbacks on a dedicated native queue. It preserves
the `IOHIDValue` OS-absolute timestamp and converts it once into the client
monotonic clock domain. The callback updates a preallocated SPSC ring or
cumulative pointer state and performs no Swift allocation, `Task`, main-actor
hop, logging, or network call.

Raw capture is active only while an authenticated session owns input authority
and the user's focus/background-input policy permits it. Focus or permission
loss emits release/cancel edges, stops native device callbacks, and completes
input neutralization before the UI reports capture released. Raw HID values,
key usages, controller samples, and text are never written to normal logs or
telemetry payloads.

When raw HID access is unavailable, focused-window AppKit input is the
fallback. Umbra disables `NSEvent.mouseCoalescingEnabled` for the captured
stream lifetime and restores the prior process setting on release. The
fallback reports its observed event frequency and MUST NOT advertise an 8 kHz
capture capability unless measured callbacks sustain it.

Controllers use GameController change handlers and the profile's
`lastEventTimestamp`; they are not polled from the render loop. A native
Objective-C++ adapter may terminate the Apple framework callback and write a
plain C++ state record directly. If a Swift adapter is temporarily retained,
it must call one synchronous allocation-free C function and must not publish
each controller event through actors, async streams, or the UI.

The client calibrates each Apple input API timestamp into one monotonic clock
domain and records mapping uncertainty. It does not assume IOHID, AppKit, and
GameController timestamp units or epochs are interchangeable. When an API does
not provide a usable event timestamp, native callback entry is the sample time
and the missing device-to-callback component is reported as unknown.

The host authenticates input on the socket worker, then submits it to one
ordered high-priority platform-input owner. Key/button/touch lifecycle edges
retain strict ID order. Replaceable motion, sticks, triggers, and sensors may
skip obsolete intermediate states. The Windows virtual-HID backend reports its
measured apply capacity; the negotiation cannot select a higher host apply rate
merely because the client captures it.

The input hot path has these timestamp points:

- physical HID or GameController event;
- native callback entry;
- state composition;
- SRTP protection complete;
- socket submission;
- host kernel receive;
- SRTP authentication complete;
- platform injection submit; and
- platform injection completion when the backend exposes it.

Exactly one capture source owns each physical device generation. Enabling the
IOHID path suppresses duplicate AppKit keyboard/pointer delivery for that
device. Fallback begins only after the native owner is closed and its final
state is reconciled. Device removal emits release/cancel edges before its
instance generation is retired.

### 15.7 Text and IME input

UTF-8 text/IME commit is a reliable `TEXT_INPUT` control request, not a series
of synthetic high-frequency key edges. Its payload contains input generation,
greatest preceding edge ID, UTF-8 byte length, and bounded text. The host waits
until that edge ID is contiguously applied, injects the text once, and returns
the cached idempotent response. Later pointer, controller, or keyboard packets
continue normally and do not wait for text completion.

Inline text must fit one current path-safe LSPC payload. Larger text is uploaded
first through the bounded `OBJECT_CHUNK` mechanism and `TEXT_INPUT` references
its object ID, length, and SHA-256; total text remains limited to 16 KiB. The
host injects only after the complete object and edge barrier validate. Text is
valid Unicode scalar sequences, cannot carry platform commands or alter input
authority, and never consumes the urgent input packet reserve. Clipboard
synchronization, if later enabled, uses a separate permission and control type.

## 16. Scheduler and pacer

Each direction has one aggregate deadline-aware scheduler and one byte pacer.

### 16.1 Scheduler classes

| Priority | Class |
| ---: | --- |
| 0 | input edges, teardown neutralization, and urgent stop authority |
| 1 | pointer motion, controller state/sensors, input ACK/controller feedback, and urgent control |
| 2 | input baseline/reconciliation, audio/microphone, and congestion/recovery feedback |
| 3 | video configuration and recovery packets that can complete the current frame |
| 4 | primary video and remaining deadline-eligible repair |
| 5 | periodic reports and telemetry |
| 6 | large-object chunks |

Priority does not imply starvation. Audio receives reserved cadence credit.
Control and input have bounded byte reserves. Bulk has no reserved credit while
streaming. Within a class, earliest deadline wins. An eligible RTX packet may
preempt newer ordinary video when it can complete an earlier still-useful
frame. A FlexFEC repair packet is never scheduled before every source packet in
the group that it protects has been submitted.

### 16.2 Pacing

The pacer uses bytes, not packet count. It:

- submits the first admitted video packet immediately when credit exists;
- spaces the remainder at the current serialization rate;
- forms a competition-mode pacing quantum of at most 100 microseconds;
- limits one microbatch to the byte credit earned during that quantum, clamped
  to one through eight path-sized packets;
- may submit that microbatch with a public platform batching or UDP
  segmentation API only when every datagram boundary and the quantum deadline
  are preserved;
- charges the complete IP/UDP datagram size, including SRTP tags, RTP headers,
  extensions, FEC, RTX, and DTLS, to the same aggregate rate; and
- drops expired queued media before selecting the next packet.

The competition shaper additionally accounts for configured link framing
overhead when calculating physical serialization time. Congestion control uses
IP-layer delivered bytes so its rate remains comparable across link types.

Input uses a dedicated sub-pacer and protected byte reserve inside the same
aggregate controller. A newly captured edge or due motion report wakes the
transmit worker and may consume its existing input credit immediately; it does
not wait for the next video quantum or frame boundary.

This adaptive microbatch avoids one timer wake per packet at very high rates
without permitting millisecond video bursts. Input, urgent control, and audio
can preempt between datagrams within a batch that has not yet entered the
kernel. Competition mode MAY use a dedicated-core spin tail of at most 50
microseconds after a timer wait; it is disabled by default on battery-powered
or thermally constrained clients.

The pacer submits no more than two future pacing quanta, and never more than
200 microseconds of earned byte credit, into the kernel or NIC at once. A UDP
segmentation request contains at most one quantum. API completion that only
means "copied into the kernel" is not recorded as wire transmission; the
implementation uses the latest public transmit timestamp available and reports
the remaining uncertainty. Kernel backpressure or `ENOBUFS` immediately stops
new video admission instead of expanding a user-space or kernel queue.

The pacer is awakened by a high-resolution monotonic deadline, socket
completion, new urgent work, or congestion-credit change. It never uses a
millisecond polling loop or an unbounded retry loop.

## 17. Congestion control

### 17.1 Feedback

The media receiver sends RFC 8888 congestion feedback at the earlier of:

- 2 ms since the prior feedback; or
- 128 newly received media packets.

Feedback reports every active received SSRC, packet reception, arrival offset,
and ECN mark. Consecutive reports cover disjoint ranges except when a small
overlap is required for reorder correction. A 500-microsecond hard minimum
between reports prevents a feedback storm. The negotiated interval may become
longer when feedback exceeds 0.5 percent of reverse-path delivered bytes, but
never longer than one video frame interval in competition mode. Feedback is
reduced-size protected RTCP under RFC 5506 and is charged to the reverse-path
pacer.

### 17.2 Adaptive low-latency profile

The adaptive controller maintains:

- delivered and lost bytes;
- smoothed RTT and variation;
- one-way delay trend without assuming synchronized clocks;
- ECN-CE fraction;
- aggregate bytes in flight;
- current pacing rate;
- encoder target rate; and
- FEC/RTX overhead separately from source-media rate.

It targets a maximum network queue delay negotiated in `START`, initially 2 ms
on a wired LAN and 10 ms on an unclassified path.

Loss, ECN-CE, or positive delay trend reduces pacing and encoder targets within
one feedback interval. Rate increase is paced and bounded. The encoder target
never exceeds pacing rate minus measured protocol, audio, input, and repair
overhead.

### 17.3 Competition-LAN profile

Competition-LAN is allowed only when the user or managed deployment explicitly
provides:

- a maximum aggregate rate;
- expected wired interface class;
- maximum RTT and queue-delay budget; and
- failure behavior.

It starts at the selected provisioned media rate without slow start. It still
uses the aggregate pacer and feedback. Sustained ECN, loss, RTT violation, or
queue-delay violation triggers immediate rate reduction. Failure to sustain the
minimum viable stream ends the session rather than building latency.

LSP never infers that an arbitrary private IP address is a provisioned path.

### 17.4 Encoder adaptation order

When capacity falls, LSP responds in this order:

1. stop bulk and nonessential telemetry;
2. remove optional RTX and reduce delta-frame FEC;
3. reduce video quantizer/bitrate at the next frame boundary;
4. drop a not-yet-submitted video frame and invalidate its reference use;
5. reduce resolution or refresh only if the client offered adaptation; and
6. terminate if input and audio minima cannot coexist with a valid video mode.

It does not repeatedly request IDR as a congestion response.

### 17.5 ECN and QoS

ECT(0) may be enabled after ECN capability is validated. ECT(1)/L4S is disabled
unless both endpoints implement RFC 9331 behavior and the deployment validates
the path.

All packets on the five-tuple use one DSCP by default. Per-lane DSCP is avoided
because RFC 7657 documents reordering and transport interactions when one
flow receives multiple differentiated treatments. Product correctness never
depends on DSCP preservation.

## 18. Receiver pipeline

The receiver's steady-state path is:

```text
socket batch
  -> first-byte classifier
  -> SRTP authenticate/decrypt in packet slab
  -> SSRC/lane parser
  -> lane-specific bounded queue
  -> video reassembly / audio decode / input apply
```

Required implementation properties:

- preallocated fixed-size packet slabs;
- no `Data` construction or equivalent payload copy per packet;
- sender construction directly into the final packet slab, followed by
  in-place SRTP protection;
- receiver in-place SRTP authentication/decryption and retained payload slices
  through reassembly;
- at most one final frame coalescing copy when the decoder API cannot consume a
  chained block buffer;
- one video reassembly owner, not a chain of serial dispatch queues;
- direct decoder submission from the completed-frame boundary;
- at most two incomplete video frames in competition mode to tolerate packet
  reordering without creating a frame queue;
- a negotiated hardware-decoder submission capacity, normally two through four
  in-flight surfaces, with no separate compressed-frame software queue;
- latest-frame render mailbox of depth one; and
- no network event routed through the main actor or UI run loop.

The socket worker reads a bounded batch, scans fixed plaintext headers to form
a tentative lane order, and authenticates DTLS control, input, input ACK, and
audio ahead of video within that batch. No side effect occurs until packet
authentication succeeds.
The worker drains the socket before invoking decoder, renderer, UI, logging, or
control business logic. Batch size starts at 64 datagrams and is runtime-tuned
only within a hard `32...256` bound.

The kernel receive buffer is sized for measured scheduler jitter and the
largest legal paced burst rather than for seconds of media. Buffer occupancy,
kernel drop counters, batch drain time, and oldest receive timestamp are live
telemetry. Increasing the socket buffer never relaxes packet or frame age
deadlines; stale video is discarded after authentication instead of being
played late.

An incomplete frame expires at its network/decode deadline. The next frame is
not held merely to preserve presentation order when its reference metadata says
it can be decoded independently.

## 19. DPLPMTUD

LSP probes use authenticated DTLS control messages padded to the candidate UDP
payload size. Probe ACK names the random probe ID and exact received size.

- Probes carry no application data.
- Only one probe is outstanding.
- Probe loss does not by itself trigger congestion reduction.
- Probe frequency is at most once per RTT outside initial search.
- A confirmed black hole immediately reduces the current maximum.
- Increasing packet size does not increase the byte pacing rate.
- Video changes packetization only on a frame boundary.

## 20. Timing and telemetry

Each endpoint records monotonic timestamps at:

- input hardware event and LSP enqueue;
- input socket send, host receive, validation, and platform apply;
- capture acquire, conversion end, encoder submit, and encoder completion;
- first and last video packet pacer submission;
- client kernel receive, SRTP completion, frame completion, decoder submit, and
  decoder completion;
- Metal encode, commit, command completion, and best available presentation
  proxy; and
- audio receive, decode, render enqueue, callback, underrun, and rebuffer.

Distributions report count, p50, p95, p99, maximum, drops, active generations,
and clock domain. Cross-machine one-way results include offset uncertainty.

Input telemetry additionally reports, per device and instance generation:

- observed physical callback rate and timestamp spacing;
- physical reports represented per network motion/state packet;
- selected and achieved network report rate;
- host authenticated and applied report rate;
- edge retry and acknowledgement counts;
- superseded replaceable states;
- input wire bitrate including IP/UDP/SRTP/RTP overhead; and
- capture-source type (`IOHID`, `GameController`, or fallback).

No rate is inferred from video frame count. A client exposing only coalesced
AppKit events reports that observed rate instead of the device's advertised USB
polling rate.

RTT is not subtracted from an end-to-end measurement to manufacture a local
latency value. Forward and reverse paths may be asymmetric.

No high-rate telemetry formatting or UI publication executes on the packet
workers. Hot counters are thread-owned, cache-line separated, and updated
without a contended global atomic per packet. A snapshot epoch or equivalent
bounded mechanism aggregates them at no more than 4 Hz for presentation.

## 21. Resource bounds

Initial hard bounds are:

| Resource | Bound |
| --- | ---: |
| authenticated connections | 64 host-wide |
| connections per source prefix | 8 |
| active stream per connection | 1 |
| control frames outstanding per direction | 64 |
| cached terminal control responses | 64 per connection |
| control payload | one current path-safe DTLS datagram; padded DPLPMTUD probe only exception |
| large object | 16 MiB |
| buffered large-object data | 32 MiB per connection |
| active video frame size | 16 MiB competition, 64 MiB absolute parser limit |
| incomplete video frames, competition | 2 |
| RTX source retention | 2 frame generations, 16 MiB per connection |
| in-flight video decode submissions | negotiated `2...4` |
| render mailbox | 1 frame |
| receive batch | `32...256` datagrams |
| pending input baseline | 1 object, 32 parts, 32 KiB |
| input unacknowledged edges | 256 |
| aggregate input wire budget | 32 Mbps per connection |
| urgent packet-slab reserve | 64 maximum input/control packets |
| pointer devices | 4 |
| controllers | 16 |
| controller sensor streams | 2 per controller |
| touches | 16 |
| pens | 4 |
| malformed authenticated packets | 32 per rolling 10 seconds before close |

Packet slabs, FEC storage, RTX retention, and decoder surfaces have separate
host-wide budgets. One connection cannot consume another connection's urgent
input/control reserve. Each endpoint keeps an urgent packet-slab reserve sized
for at least 64 maximum input/control packets; video allocation cannot consume
it. Pool pressure discards expired or oldest unsubmitted video before rejecting
urgent traffic.

## 22. Error handling

Control responses use stable status classes:

| Code | Meaning |
| ---: | --- |
| 0 | success |
| 1 | malformed |
| 2 | unsupported version/capability |
| 3 | authentication failed |
| 4 | permission denied |
| 5 | busy/resource unavailable |
| 6 | unsupported media tuple |
| 7 | stale generation |
| 8 | timeout |
| 9 | path capacity insufficient |
| 10 | internal failure |

Malformed unauthenticated datagrams are silently dropped. Authenticated media
parse failures are dropped and counted. An isolated media failure does not
close control authority. Security, generation, repeated-abuse, or resource
integrity failure closes the relevant association.

## 23. Compatibility boundary

LSP and legacy GameStream are separate protocols. A host may offer both, but a
client connection selects one explicitly.

The retired native transport is not a compatibility target and has been
removed from the current product baselines. LSP does not multiplex it, reuse
its trust or identity state, or expose a compatibility switch.

## 24. Competition acceptance targets

These are gates, not current claims. The exact hardware matrix is recorded with
each result.

On a direct or managed 2.5 GbE path with no injected loss:

- sustain 1080p240 and 1440p240 at their selected bitrate for 30 minutes;
- delivered/presented frame cadence at least 99.9% of submitted source frames;
- no repeating half-second or recovery-cadence hitch;
- p99 inter-present gap no greater than 1.5 frame intervals, excluding an
  identified game/capture stall;
- client kernel-receive to Metal-commit p99 below 3 ms;
- host capture-acquire to first packet submission p99 below 4 ms;
- raw-HID pointer sample to host platform-apply p50 below 500 microseconds and
  p99 below 1 ms at the selected 8 kHz competition rate;
- physical key/button edge to client socket submission p99 below 125
  microseconds and to host platform-apply p99 below 1 ms;
- measured pointer network-report frequency at least 99 percent of the selected
  8 kHz rate during continuous motion, with physical-sample coalescing reported
  rather than hidden;
- unchanged input rate and input latency distributions at 60, 120, and 240
  video FPS;
- generation-correct controller buttons, sticks, triggers, gyro,
  accelerometer, touchpad, rumble, LED, and adaptive-trigger feedback without a
  render-loop dependency;
- pacer scheduled-to-actual submission error p99 below 100 microseconds;
- authenticated urgent-lane delay behind an already received video batch p99
  below 100 microseconds;
- zero decoder recoveries, IDRs requested by transport pressure, audio
  rebuffers, decoder-credit drops, input gaps, and unbounded queue growth; and
- steady-state packet processing below one fully occupied performance core on
  each documented endpoint at 250 Mbps.

A transport-only full-duplex run must sustain at least 100,000 aggregate
authenticated packets/s per endpoint, including 500 Mbps video-sized traffic
in one direction and the negotiated small-packet input budget in the reverse,
without allocation growth, packet-worker starvation, input-rate collapse, or
scheduler deadline drift. It is a transport-capacity gate, not a required
video bitrate.

With controlled loss and reordering:

- isolated recoverable loss uses FEC or eligible RTX without IDR;
- an unrecoverable reference loss creates at most one outstanding recovery
  frame per epoch;
- latency returns to the pre-loss bound without an accumulating queue; and
- input and audio remain within their independent bounds.

Physical input-to-photon qualification uses a high-speed camera or photodiode,
not software timestamps alone.

## 25. Conformance artifacts required before interoperability freeze

The implemented portable primitives require independent vectors before the
interoperability freeze. Product integration must additionally freeze:

- deterministic CBOR schemas for every control type;
- complete LSPC positive and hostile vectors;
- invitation and pairing transcripts;
- DTLS-SRTP exporter vectors;
- SSRC and payload-type negotiation examples;
- RTP packets for every codec and header-extension combination;
- input state and edge vectors;
- SRTCP APP feedback vectors;
- FlexFEC/RTX association examples;
- sequence wrap and replay cases;
- DPLPMTUD probes; and
- teardown and authority-transfer transcripts.

Vectors protect wire interoperability and security boundaries. They do not
substitute for the live functional and performance gates in section 24.

## 26. Reserved future work

The following require a later wire-version or capability extension:

- DTLS connection IDs and seamless path migration;
- STUN/TURN traversal;
- L4S competition profile;
- scalable-video layer switching;
- multi-display streaming;
- more than one client receiver;
- alternative SRTP protection profiles; and
- jumbo-frame conformance.

None may be inferred from an unknown field in version 1.

## 27. References

The research basis and linked standards are collected in
[Lumen Streaming Protocol architecture rationale](lumen-streaming-protocol-rationale.md).
