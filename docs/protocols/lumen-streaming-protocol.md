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
Its reverse direction selects a microphone only with explicit client offer,
paired permission, and a successful Windows virtual-microphone probe; SRTP
admission begins only after the matching generation-qualified
`MICROPHONE_CONFIG_ACK`.
Lumen now also freezes the sixteen-key `START`, 31/32-key START/ATTACH
responses, exact 30-key video selection, and video-schema-revision-three
`VIDEO_CONFIG/ACK` maps for H.264, HEVC, and AV1. The host prepares and owns the
exact Windows virtual display when enabled, proves the requested codec,
profile, pixel class, and color tuple on the named hardware encoder, and starts
its bounded RTP/SRTP sender only after the matching authenticated video
acknowledgement. Fixed extension IDs 1 through 5
carry visible frame marking and capture time plus RFC 6904-encrypted frame
ID/recovery epoch, input watermark, and encoder timing. The selection carries
nullable exact FlexFEC and RTX associations; unsupported hardware/color tuples
fail closed instead of being approximated.
ATTACH uses a client-selected successor token and an idempotent intent. Lumen
commits that exact token only after all fallible replacement resources pass
preflight, retains every prior-session SSRC as a replay-namespace fence, and
does not close retiring associations until the successor has a committed
neutral input baseline whose urgent LSPI acknowledgement entered aggregate
output, mandatory audio, terminal microphone policy, and an acknowledged,
activated video generation.
Umbra now has the matching native receive/depacketization/reassembly,
retained-frame ABI, VideoToolbox, Metal, and protected `LSPV` path. These
implemented product boundaries do not claim a live cross-product stream or
hardware qualification until the Windows host and macOS client run the exact
negotiated slice together.

The client allocates both bounded incomplete-frame byte regions, fragment
tables, ordered slice views, and decoder-transfer frame pool at authenticated
video configuration. Authenticated packet insertion, reorder, completion, and
slot recycling then perform no heap allocation. The retained compatibility
helper remains outside the live receiver path.

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

- discovery and numeric-PIN SPAKE2 pairing;
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
- Wire version: unsigned integer `1`; nested video offers/selections and
  `VIDEO_CONFIG/ACK` use dedicated video schema revision `3`.
- DTLS ALPN: exact ASCII `lumen-stream/1`.
- Default UDP port: `48030`.
- mDNS service type: `_lumen-stream._udp`.
- Pairing discovery: TXT `pair=pin1` plus lowercase `spki=<sha256>`.
- Pairing schema: unsigned integer `1` within PIN control maps.

Every control message contains its assigned version discriminator. LSP/1 maps
use wire version one except that nested video offers and selections and
`VIDEO_CONFIG`/`VIDEO_CONFIG_ACK` use their dedicated schema revision three at
key one. RTP and RTCP formats are
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

### 6.3 Numeric PIN pairing

Discovery advertises `pair=pin1` and the lowercase SHA-256 SPKI digest in TXT
key `spki`. No URI, QR code, bearer invitation, or migrated trust participates
in LSP pairing. Umbra selects a discovered host and displays a random six-digit
PIN. The user enters those exact digits in the authenticated Lumen
administration surface.

Pairing uses RFC 9382 SPAKE2-P256 with scrypt `N=32768`, `r=8`, `p=1`, a
client-selected 16-byte salt, uncompressed 65-byte SEC1 points, full 32-byte
HMAC-SHA-256 confirmations, and Ed25519 identity signatures. Lumen performs
scrypt and host-point work on a dedicated worker, never the UDP socket or HTTP
thread. It retains at most four sessions host-wide, one per source address and
association, for exactly 120 seconds. Each session permits at most three
approval generations with a retry cooldown. Pending client IDs and Ed25519
keys are independently unique. PIN administration names one non-secret session
ID in `X-LSP-Pairing-Session`, while the `text/plain` body remains exactly six
ASCII digits. The host validates `Content-Length: 6` before allocating or
reading the body, never logs or echoes it, and unrelated pending clients
consume no challenge attempt.

POLL starts with a 20 ms floor and doubles to at most one second. Four
consecutive early POLLs trigger a one-second cooldown; accepted POLLs reset the
early-abuse counter. The administration API publishes the proposed client ID,
SHA-256 key fingerprint, effective permissions, and explicitly unverified
client-supplied name without any PIN, point, confirmation, nonce, AAD, or
exporter material.

PIN-to-scalar derivation is frozen as follows; implementations MUST NOT apply
Unicode normalization, decimal conversion, a terminating NUL, a protocol
label, or either identity to these inputs:

1. `password` is exactly the six ASCII digit bytes as displayed and entered,
   in left-to-right order. Every byte must be `0x30...0x39`.
2. `salt_input` is exactly the 16 bytes of the `PAIR_BEGIN` `scrypt_salt`
   value, in unchanged wire order.
3. `dk = scrypt(password, salt_input, N=32768, r=8, p=1, dkLen=32)`.
4. `integer = OS2IP(dk)`, interpreting `dk` as one unsigned big-endian
   integer.
5. `w = integer mod q`, where the P-256 subgroup order is
   `q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`.
6. `w` is encoded in TT as exactly 32 unsigned big-endian bytes. A zero result
   is rejected, all derived state is cleared, and the pairing attempt is
   restarted with a fresh random `scrypt_salt`; the same zero scalar is never
   used or silently changed to one.

The fixed PIN-to-w vector is:

| Value | Hexadecimal bytes |
| --- | --- |
| PIN ASCII | `313233343536` (`123456`) |
| `salt_input` | `000102030405060708090a0b0c0d0e0f` |
| 32-byte scrypt output | `2c96fb20f5af7503bd94936a79d3e5e0a068ee179925f84628b9ca753cb0199d` |
| 32-byte `w` | `2c96fb20f5af7503bd94936a79d3e5e0a068ee179925f84628b9ca753cb0199d` |

The request/response-only registry freezes these maps:

- `PAIR_BEGIN` exact nine keys: wire/schema, client ID, client Ed25519 key,
  UTF-8 name, client pairing nonce, scrypt salt, `pA`, requested permissions;
- `PAIR_PENDING` exact six keys: wire/status/schema, host session ID, absolute
  expiry, effective permissions;
- `PAIR_POLL` exact three keys: wire/schema/session ID;
- `PAIR_CHALLENGE` exact seven keys: wire/schema/session ID, approval
  generation, `pB`, effective permissions, unchanged expiry;
- `PAIR_FINISH` exact six keys: wire/schema/session ID, approval generation,
  `cA`, client Ed25519 signature; and
- `PAIR_RESULT` exact nine keys: wire/status/schema/session ID, approval
  generation, permissions, persisted revocation generation, `cB`, host
  Ed25519 signature.

SPAKE confirmation AAD is exact deterministic CBOR with 18 ordered fields:
label, pairing schema, host ID/key/SPKI, client ID/key, host pairing session,
client pairing nonce, connection and approval generations, both 32-byte hello
nonces, scrypt salt, requested and effective permissions, expiry, and the
dedicated 32-byte TLS exporter from label
`EXPORTER-Lumen-LSP-Pairing-v1` with empty context. It never reuses the
DTLS-SRTP exporter. SPAKE TT independently binds both identities and points.
Trust is persisted before success is sent. Failure never falls back to legacy
pairing and never creates partial LSP trust. Persistence uses atomic
insert-if-absent semantics: it cannot overwrite or reset an existing client.
An identical ID/key recovery preserves the existing permissions and revocation
generation. BEGIN must request every stored permission, and PENDING,
confirmation AAD, CHALLENGE, and RESULT all bind the stored effective mask; a
concurrent permission change fails the attempt instead of changing its result.
The host retains four exact completed RESULT payloads keyed by
session, identity, and association so duplicate FINISH can recover a lost
response independently of the request-ID cache. After association loss, the
same identity may repeat PIN pairing safely and receive the unchanged trust
record.

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

A fresh authenticated connection sends the exact five-key `ATTACH` map
`{1: version, 2: session_id, 3: current_attach_token, 4: intent_id,
5: successor_attach_token}`. Both tokens and the intent ID are nonzero, and
the successor token differs from the current token. Success advances every
connection-scoped media and input generation, installs fresh SSRCs and keys,
echoes the exact successor token at `ATTACH_RESPONSE` key 4, and requires a
complete neutral input baseline before edges are accepted. The host installs
the successor token atomically with authority transfer; it never substitutes
host-selected token material.

An exact duplicate intent on the same association returns its cached terminal
response without repeating side effects. If success is ambiguous because the
association is lost before the response arrives, the client opens another
authenticated association and moves forward: it presents the previously
selected successor as the current token, supplies a new intent ID, and selects
another distinct successor. Repeating the old intent on a different
connection generation is stale. A definite rejection before commit leaves the
prior association and token authoritative. After commit, the prior association
cannot regain authority.

Retiring associations remain bounded and deduplicated. The host closes them
only after the successor's complete neutral baseline is committed and its
urgent LSPI acknowledgement enters aggregate output, mandatory host audio
reaches successful terminal configuration, an absent or optional microphone
reaches terminal policy (a required microphone must be active), and video is
both acknowledged and capture/sender activated. A newer forward-recovery
ATTACH may supersede an incomplete successor without overwriting older
retiring peers.

Fresh authentication is re-evaluated at every ATTACH. Loss of optional
microphone permission omits the replacement microphone generation and retires
the old receiver; loss of required microphone permission rejects before
commit. Controller output is independently carried in the replacement input
mapping, so haptics and LED commands stop immediately when that permission is
absent even though client-to-host input remains authorized.

The committed readiness barrier expires after three seconds. Expiry is a
forward-terminal failure: the host closes the successor and every retiring
association, terminates the held stream, and never revives the predecessor
token, generation, input authority, SRTP context, or media runtime. Retiring
associations pause DPLPMTUD; outstanding host probes are cancelled from
reliable control and rolled back locally, and a late authenticated probe ACK
is acknowledged without changing path state.

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
| `0x0010` | `PAIR_BEGIN` | client to host |
| `0x0011` | `PAIR_PENDING` | host to client |
| `0x0012` | `PAIR_POLL` | client to host |
| `0x0013` | `PAIR_CHALLENGE` | host to client |
| `0x0014` | `PAIR_FINISH` | client to host |
| `0x0015` | `PAIR_RESULT` | host to client |
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

### 9.1 Product operation maps

The following deterministic-CBOR maps are frozen for wire version 1. Keys are
consecutive integers starting at one; no omitted or additional keys are valid.

- `APPLICATIONS` is the exact three-key response: wire version, status, and
  at most 64 application entries. Each entry is the exact six-key map: stable
  application ID, display name, artwork reference (empty when absent), running
  boolean, resume-available boolean, and process generation. A running entry
  has a nonzero generation; a stopped entry has generation zero and cannot be
  resumed. A running application may be unavailable for resume, for example
  when its process is owned by legacy streaming. Clients preserve these fields
  when publishing their application catalog; local session memory is not a
  substitute for the authenticated host process state.
- `CERT_ROTATE` (six keys): wire version, host ID, connection generation,
  rotation generation, replacement SPKI SHA-256, and the old host-identity
  signature. `CERT_ROTATE_ACK` success (five keys) returns wire version,
  status, host ID, connection generation, and rotation generation. A failure
  uses the response/error flags and the generic two-key error map.
- `QUIT_APPLICATION` (three keys): wire version, session ID, and stable
  application ID. Its response has wire version, status, and session ID.
- `TEXT_INPUT` (eight keys): wire version, session ID, input generation,
  preceding edge ID, UTF-8 byte length, nullable inline bytes, nullable object
  ID, and nullable SHA-256. Exactly one of inline bytes or the object reference
  is present. Its response has five keys through the preceding edge ID.
- `INPUT_RATE_REQUEST` (thirteen keys): wire version, session and input
  generations, device type/ID/generation, observed capture rate, state and
  sensor minimum/maximum rates, and state/sensor packet bounds.
  `INPUT_RATE_RESPONSE` has fourteen keys: wire version, status, the six
  generation/device identity fields, selected device state/sensor rates, the
  updated aggregate pointer/controller/sensor/reconciliation rates, and the
  aggregate reserved input wire bits per second.
- `STREAM_ENDED` (four keys): wire version, session ID, stream generation, and
  terminal reason. It is a reliable request-ID-zero notification.
- An `OBJECT_CHUNK` request has six keys: wire version, object ID, contiguous
  offset, total length, nonempty bytes, and complete-object SHA-256. A
  response-flagged successful acknowledgement has five keys: wire version,
  status, object ID, next contiguous offset, and total length. Failure uses the
  generic two-key error map.

Lumen exposes authenticated administration at `POST /api/lsp/identity/rotate`.
The transaction generates a fresh certificate/private-key pair while retaining
the stable host and application identity, sends old-identity-signed
`CERT_ROTATE` to every authenticated client, waits for every atomic-persistence
ACK, atomically replaces the identity file, and only then swaps the server
context used by new associations. Existing associations retain their old
wolfSSL contexts and traffic keys until reconnect. Any generation, client,
persistence, or provider-swap failure keeps or restores the prior identity.

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

`ATTACH_RESPONSE` has the same retained session selection plus advanced
connection/input/audio/microphone/video generations, fresh SSRCs for every
selected lane, and the exact client-selected successor token. All replacement
SSRCs are excluded from every SSRC previously assigned during the live
session, not only the immediately preceding generation.

The host may select a lower bitrate, resolution, or refresh rate only within an
offered range. Strict offers fail instead of being adjusted.

### 10.1 Frozen video control schema revision three

`START` remains exactly sixteen keys. Keys 1 through 10 retain their input,
audio, path, and nullable microphone meanings. Key 11 is network profile zero
for adaptive-low-latency or one for competition. Key 12 is an ordered array of
one through eight exact 18-key video offers:

| Key | Value |
| ---: | --- |
| 1 | video schema revision `3` |
| 2...3 | codec and profile |
| 4...5 | width and height |
| 6...7 | rational refresh numerator and denominator |
| 8...9 | preferred and maximum source bitrate, each at least 1,000 bits/s |
| 10 | pixel class |
| 11...13 | H.273 color primaries, transfer characteristic, and matrix coefficients |
| 14 | full-range boolean |
| 15 | delivery mode |
| 16...17 | FlexFEC and RTX receive support booleans |
| 18 | positive maximum complete-access-unit bytes, at most 16 MiB |

Codec values are H.264 `1`, HEVC `2`, and AV1 `3`. Profiles are H.264 High
`1`, H.264 High 4:4:4 Predictive `2`, HEVC Main `3`, HEVC Main10 `4`, HEVC
Range Extensions `5`, AV1 Main `6`, and AV1 High `7`. Pixel classes are 4:2:0
8-bit/NV12 `1`, 4:2:0 10-bit/P010 `2`, 4:4:4 8-bit `3`, and 4:4:4 10-bit `4`.
Profile and pixel class must be a valid codec tuple. SDR uses H.273 BT.709
primaries/transfer/matrix `1/1/1`. HDR10 uses BT.2020 primaries, SMPTE ST 2084
PQ transfer, and BT.2020 non-constant-luminance matrix `9/16/9`. HLG uses
`9/18/9`. HDR10 and HLG require a 10-bit HEVC or AV1 tuple and limited range.
Keys 13 through 16 of the outer START map carry receive-batch capacity
`1...64`, decoder surfaces `2...4`, render mailbox one, and a maximum
capture-to-present budget of `1...1,000,000` microseconds.

`START_RESPONSE` has exactly 31 keys and `ATTACH_RESPONSE` exactly 32. Their
last key is the same exact 30-key video selection. Selection key 1 is video
schema revision three. Keys 2 through 26 contain video generation, primary
SSRC/PT, 90 kHz clock, the selected codec/profile/dimensions/refresh/bitrate,
pixel and H.273 tuple, range, initial 1,200-byte UDP payload, decoder surfaces,
mailbox one, delivery, and extension IDs `1...5`. Key 27 is null or exact
FlexFEC map `{1: repair_ssrc, 2: repair_pt, 3: window_us,
4: max_group_packets}` with maximum group packets exactly 15. Key 28 is null or
exact RTX map `{1: rtx_ssrc, 2: rtx_pt, 3: apt}` whose `apt` equals the primary
payload type. Keys 29 and 30 are the positive maximum frame age and maximum
complete-access-unit bytes. Frame age and FlexFEC window are each at most
1,000,000 microseconds, and the repair window cannot exceed frame age. Every
SSRC is nonzero and distinct; repair payload types are dynamic, distinct from the primary and every different payload
semantic, and generation-bound. Extension IDs 1 and 2 are visible frame
marking and absolute capture time. IDs 3, 4, and 5 are RFC 6904-encrypted frame
ID, input watermark, and encoder timing.

`VIDEO_CONFIG` is an exact eight-key host request: video schema revision `3`,
session ID, stream generation, the selected 30-key video map, codec
configuration, nonzero frame-ID origin, nonzero recovery epoch, and nullable
HDR metadata. Codec configuration is the exact map `{1: kind, 2: units}` where
kind is H.264 `1`, HEVC `2`, or AV1 `3`; units are exactly prefix-free SPS/PPS,
VPS/SPS/PPS, or one canonical low-overhead AV1 sequence-header OBU. HDR10/PQ
requires the exact 13-key unsigned map containing RGB primary xy at keys 1...6,
white xy at 7...8, maximum/minimum mastering luminance at 9...10, MaxCLL and
MaxFALL at 11...12, and maximum full-frame luminance at 13. SDR and HLG require
null because neither uses HDR10 static mastering metadata. `VIDEO_CONFIG_ACK`
is an exact five-key response containing video schema revision `3`, status,
session ID, video generation, and decoder credit `2...4`.

The Windows host selects only a tuple proven by its current named capture and
hardware-encoder generation. The current VDD/configuration boundary proves SDR
8-bit BT.709 and HDR10/PQ 10-bit modes plus validated 4:4:4 where the active
hardware-encoder probe reports it. HLG remains a valid wire tuple but fails
host selection closed until the active Windows color pipeline can explicitly
prove HLG output; it is never silently encoded as PQ. The LSPC error-response flag and
non-success status must agree. No primary or repair video SRTP packet is legal
before a successful matching acknowledgement.
Before START commits authority or returns success, the host deterministically
encodes the complete `VIDEO_CONFIG`, including canonical codec units and HDR
metadata, under the 1,152-byte control limit. Failure unwinds the launched
application generation and prepared display lease. ATTACH repeats this
preflight after rotating generation and SSRC values but before authority moves.

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
ATTACH allocates every replacement SSRC outside both the new-generation set
and every prior-generation input, acknowledgement, audio, microphone, primary,
FlexFEC, and RTX SSRC, even after transport loss has retired the old live
registry.

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
| `urn:lumen:rtp-hdrext:frame-id` | 12 bytes | first two and final video packets |
| `urn:lumen:rtp-hdrext:input-watermark` | 16 bytes | first two packets of a video frame |
| `urn:lumen:rtp-hdrext:encoder-timing` | 8 bytes | first two packets of a video frame |

The encrypted frame-identity value is the nonzero 64-bit encoder access-unit
counter followed by the nonzero 32-bit recovery epoch, both in network byte
order. It is repeated unchanged on the first two and final packets of the
frame. The input watermark
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

The sender initializes its recovery controller from the nonzero epoch in
`VIDEO_CONFIG`. It writes the controller's current epoch beside every repeated
frame ID. When recovery requires an independent frame, that frame reserves the
sole outstanding slot before its first RTP packet is committed. A second
independent frame is not admitted while the slot remains outstanding; its
unsent encoder dependency is invalidated before later dependent frames may be
admitted.

Each host encoder reference-invalidation request carries a nonzero local
generation and an exact inclusive frame range, both echoed by its terminal
result. The replaceable capture mailbox has exactly one published invalidation
generation. Requests arriving concurrently are retained as one coalesced next
range and published only after the active generation completes. A stale
generation or changed range cannot complete another request. Rejection during
an active recovery epoch falls back to its permitted independent frame;
rejection of pressure-only invalidation fails closed rather than creating an
IDR loop. The accepted generation is carried with the encoder's first repaired
output into the host packet owner. Only an IDR or repaired output matching the
latest dependency generation and frame-index fence may restore reference
validity; older frame completion or `LSPV` confirmation cannot erase a newer
local break. Recovery-phase transitions and dependency break/restore state are
committed under one sender-owned critical section, so no dependent admission
can observe a new recovery epoch with the prior reference validity. A dependent
frame reserves that dependency generation before submission and revalidates it
at every packet commit boundary. A newer break cancels an uncommitted frame or
stops a partially committed frame at the next boundary and enters the existing
partial-frame recovery path. Protecting a packet consumes its SRTP sequence and
creates a local feedback tombstone, but does not make the frame partially
network-visible. If the first protected packet cannot commit, the sender uses
exact pre-submit dependency invalidation rather than opening unexpected-partial
recovery or requesting an IDR for local queue pressure.

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

After SRTCP authentication and session/video generation validation, a status
whose epoch equals the sender's current outstanding epoch confirms recovery
when its decoded watermark reaches or passes the reserved recovery frame. A
same-epoch decoder error is retained as failure evidence, but another recovery
attempt is permitted only after the reserved frame deadline. A decoder error
while recovery is healthy opens the next epoch and requests one independent
frame. Surface exhaustion and deadline-miss observation without decoder error
update capacity and telemetry only; neither opens a recovery epoch nor ends
the session.

The frozen plaintext `LSPV` packet is a 56-byte SRTCP APP packet: version two,
subtype zero, PT 204, RTCP length 13, sender SSRC equal to the negotiated client
input SSRC, and name `LSPV`. Offsets 12 through 15 contain LSP version one,
deadline-miss bit zero, decoder status `0...3`, and maximum decoder credit
`2...4`. Offsets 16, 20, and 24 contain session generation, video generation,
and recovery epoch. Offsets 28, 36, and 44 contain the three largest frame IDs.
Offsets 52 and 53 contain in-flight decode submissions and mailbox occupancy;
offsets 54 through 55 are zero. Generation, ordering, credit, and capacity are
validated only after SRTCP authentication.

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

The host retains a bounded ledger keyed by device class, device ID, instance
generation, and state/sensor stream. Each entry freezes its worst-case packet
size and selected rate. Every renegotiation reclaims the prior exact entry,
selects against all simultaneous device reservations, and returns the complete
four-class aggregate schedule plus exact reserved wire bits, never above the
original START ceiling or 32 Mbps.

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

Controller device state is exactly 88 bytes. Bytes `24...27` contain battery
state (`0` unknown, `1` discharging, `2` charging, `3` full), charge percent
(`0...100`, or `255` only when unknown), active touchpad-contact count
(`0...2`), and zero. Bytes `28...35` are the digital-button bitmap. Bits
`0...19` name south, east, west, north, left/right shoulder, left/right stick,
menu, view, guide, D-pad up/down/left/right, paddles one through four, and
touchpad click; remaining bits are zero. Bytes `36...51` are signed Q1.15 left
X/Y, right X/Y, D-pad X/Y, and auxiliary X/Y axes, with positive Y up. Bytes
`52...59` are unsigned Q0.16 left, right, auxiliary-left, and auxiliary-right
triggers. Bytes `60...87` are two packed 14-byte touchpad contacts: ID, active
byte, normalized Q0.32 X/Y, Q0.16 pressure, and two zero bytes. Inactive
contacts are all-zero; active IDs are nonzero and unique.

Controller sensor state is exactly 36 bytes. Bytes `24...35` are signed
right-handed X, Y, and Z in Q16.16. Gyroscope values are radians per second;
accelerometer values are metres per second squared.

Touch state is a 28-byte header followed by `0...16` packed 32-byte active
contacts sorted by strictly increasing nonzero contact ID. Header byte 24 is
the count and bytes `25...27` are zero. Each contact contains its ID and active
bit, normalized Q0.32 X/Y, Q0.16 pressure, normalized Q0.16 major and minor
surface axes, clockwise radians from +X in signed Q3.12, its nonzero physical
ordinal, and four zero bytes. Contact ordinals do not exceed the device ordinal.

Pen state is exactly 56 bytes. Byte 24 contains in-range, contact, and eraser
bits and byte 25 is zero. Remaining fields are the 16-bit button bitmap,
normalized Q0.32 X/Y, Q0.16 tip pressure, signed Q1.15 tangential pressure,
signed Q3.12 X/Y tilt and clockwise barrel rotation in radians, normalized
Q0.16 hover distance, contact ID, and six zero bytes. Contact implies in-range;
an in-range pen has a nonzero contact ID. A neutral pen has every flag, button,
coordinate, pressure, tilt, rotation, distance, and contact ID zero.

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

The deterministic body begins with a 32-byte header: ASCII `LSPB`, version one,
a neutral-state bit, 16-bit record count `1...128`, exact 32-bit total length,
four zero bytes, the represented edge watermark, and the text/IME barrier edge
ID. The barrier does not exceed the watermark. Each record has a 32-byte header
containing record kind, subtype, two zero bytes, payload length, device ID,
instance generation, per-key state sequence, and per-key physical ordinal,
followed by its exact frozen body. Records are strictly sorted and unique by
`(kind, subtype, device ID)`. Kinds are core, device lifecycle, pointer,
controller, controller sensor, touch, and pen. Lifecycle bodies are four bytes:
device class, active/removal state, and two zero bytes. Every active
pointer/controller/touch/pen lifecycle has one complete matching
same-generation main-state record; controller sensor records additionally
belong to that active controller. A removal tombstone has no same-generation
state. The core record carries the same text barrier as the body header. Every
record has a nonzero sequence and ordinal and installs with the body watermark.

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

The common input-header flags are zero in LSP/1. The pointer, core, controller,
sensor, touch, pen, device-lifecycle, complete-baseline, edge, and baseline-part
layouts above are frozen and implemented by the portable core.

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

The wait is owned by a bounded asynchronous control worker. The receive/retry
dispatcher records the request as pending and remains nonblocking; exact
duplicates receive acknowledgement-only progress until the worker publishes the
terminal cached response at the original request deadline.

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

Established DTLS application records use a one-record completion fence per
association. This preserves DTLS record order even when `OBJECT_CHUNK` records
enter the bulk lane and later urgent control records use the control lane; only
the head record is admitted to the aggregate scheduler at a time.

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

The frozen congestion-control feedback packet is RTPFB PT `205`, FMT `11`.
After the RTCP sender SSRC, each stream block contains media SSRC, 16-bit
`begin_seq`, 16-bit `num_reports`, and exactly `num_reports` 16-bit
`R:1 | ECN:2 | ATO:13` metrics for the half-open range
`[begin_seq, begin_seq + num_reports)`. An odd metric count is followed by one
zero 16-bit alignment word. The packet ends with the middle 32 bits of an NTP
timestamp. One packet contains at most 16,384 metrics. Later bounded overlap
may correct lost to received and may upgrade a duplicate reception to ECN-CE;
it cannot regress received to lost or account the same bytes twice.
ATO uses exact 1/1024-second units: ordinary values end at `0x1FFD`,
`0x1FFE` reports an over-range offset, and `0x1FFF` reports an unavailable
timestamp or arrival after the report instant.

Reduced-size feedback is admitted only after a fresh regular compound RTCP
packet beginning with SR/RR and containing the feedback sender's SDES CNAME.
Video SR and authenticated RR LSR/DLSR fields establish media SRTT and RTTVAR.
Zero-report and fully duplicate reports refresh neither capacity nor pacing,
and accepted feedback observes the 500-microsecond hard floor. The host does
not enable ECT marking until its socket path records real ancillary ECN state;
it never manufactures ECN observations.

During the first live host integration, one packet may contain the active
primary-video and host-audio SSRC blocks in either order. Lumen validates both
blocks completely but feeds only video-ledger bytes into the video-owned
controller. A structurally valid audio-only packet advances the common
feedback cadence and report timestamp but performs no video-ledger or
controller update. It does not fabricate audio delivery or loss bytes. Actual audio,
control, and video accounting moves together into the shared `HostForwardPath`
aggregate egress owner.

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

LSP probes establish intent with reliable authenticated `PATH_PROBE` control,
then send one exact-size protected SRTCP APP packet named `LSPP`. The control
map is exactly `{1: version, 2: nonzero probe_id, 3: UDP payload size}`;
`PATH_PROBE_ACK` repeats the exact map. `LSPP` uses the primary video SSRC in
the host-to-client direction and the negotiated client input SSRC in reverse.
Its plaintext offsets are sender SSRC at 4, name at 8, version at 12, zero at
13, declared protected size at 14, probe ID at 16, and zero probe padding from
24 onward. The RTCP length covers the complete plaintext APP packet. The
sender queries libSRTP's SRTCP trailer length so the protected UDP datagram is
exactly the declared candidate size. Any APP or RFC 3550 padding byte is
validated.

- Probes carry no application data.
- The active-family socket disables local IP fragmentation before bind; the
  listener fails closed if that policy cannot be installed. Windows uses
  protocol-owned PMTU discovery for both IPv4 and IPv6 on the dual-stack
  socket, while Darwin validates `IPV6_DONTFRAG` for native and mapped-v4
  output.
- Only one probe is outstanding.
- The conservative LSP `PROBE_TIMER` is at least 15 seconds and permits three
  fresh SRTCP-index transmissions.
- Authenticated control intent remains live for 60 seconds so it cannot expire
  before the complete three-attempt data-probe budget.
- A local would-block retry reuses the exact protected bytes; a PROBE_TIMER
  retry freshly protects the same logical ID and size with a new SRTCP index.
- Probe loss does not by itself trigger congestion reduction.
- Probe frequency is at most once per RTT outside initial search.
- A confirmed black hole immediately reduces the current maximum.
- A kernel `EMSGSIZE` on a payload above 1,200 bytes is independent black-hole
  evidence: the current frame is abandoned with reference recovery, 1,200 is
  applied at the next frame boundary, and congestion capacity is unchanged.
- A protected video packet rejected with transient would-block is retained and
  retried byte-identically until its frame deadline; the consumed SRTP index is
  never reused or reprotected.
- Silent downstream MTU reduction is confirmed separately from congestion by
  sustained absence of authenticated large-packet delivery while at least
  eight large packets were sent and fresh smaller RTP or SR/RR delivery proves
  the path remains live. This also reconfirms 1,200 at the next frame boundary.
- A failed candidate or black-hole fallback starts a 600-second PMTU raise
  timer. Bounded upward search reopens after it elapses, even when an
  intervening smaller binary-search candidate succeeded.
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

Reconnect telemetry contains no token, intent, identity, certificate, peer
address, or key material. The host administration snapshot reports attempt,
pre-commit rejection, commit, full-readiness, and post-commit failure counts;
the latest connection generation and outcome; and request-to-commit,
commit-to-ready, and request-to-terminal durations.

## 21. Resource bounds

Initial hard bounds are:

| Resource | Bound |
| --- | ---: |
| authenticated connections | 64 host-wide |
| connections per source prefix | 8 |
| active stream per connection | 1 |
| control frames outstanding per direction | 64 |
| cached terminal control responses | 64 per connection |
| pending PIN pairing sessions | 4 host-wide, one per source and association |
| completed PIN RESULT replay | 4 exact session/identity/association entries |
| PIN session lifetime | 120 seconds |
| PIN challenge attempts | 3 per session with cooldown |
| PIN poll interval | 20 ms exponential floor, 1-second ceiling |
| cached successful ATTACH intents | 64 per live session |
| retiring ATTACH associations | 64 per live session |
| live-session SSRC history | 512 nonzero unique assignments |
| committed ATTACH readiness | 1 successor, 3-second deadline |
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

A security provider's ordinary drop disposition remains silent. Its fatal
disposition is acted on only after any synchronous DTLS output scope ends: the
socket owner defers closure and input neutralization of that exact association
without affecting another peer.

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
- PIN/SPAKE pairing maps, AAD, confirmations, and identity-signature transcripts;
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
