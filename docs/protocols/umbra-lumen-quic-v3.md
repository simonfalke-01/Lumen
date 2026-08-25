# Umbra / Lumen direct QUIC protocol version 3

Status: implemented and linked in Umbra and Lumen; cross-machine transport
acceptance and performance validation remain pending.

Version 3 is the direct Umbra/Lumen transport. It uses one QUIC listener on one
UDP port, keeps the existing deterministic control semantics, and removes the
second application cryptographic transport previously layered over TLS. The
exact ALPN is `lumen/3`; legacy compatibility remains a separate profile.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are interpreted as described by RFC 2119 and RFC 8174.

## 1. Scope and non-goals

Version 3 defines:

- QR invitation pairing and paired-client authentication;
- a single-port QUIC connection carrying reliable control streams and QUIC
  DATAGRAM media/input records;
- a fixed 44-byte semantic envelope for all unreliable records;
- application browsing, transactional start/stop, permissions, input, video,
  audio, microphone, telemetry, and configuration generations;
- explicit `LATENCY` and `QUALITY` transport policies; and
- bounded scheduling, queues, loss recovery, migration, and instrumentation.

Version 3 does not define a second secure channel inside QUIC. It has no
application AEAD, X25519 exchange, HKDF schedule, epochs, custom rekey, TLS
exporter, application path challenge, or negotiated media UDP port. QUIC/TLS
provides confidentiality, integrity, replay protection, key updates, loss and
congestion control, connection IDs, and path validation.

The protocol does not claim a hard physical input-to-photon latency. Software
telemetry ends at host capture and client Metal commit. Optical latency requires
a synchronized high-speed camera or photodiode rig. RTT also cannot simply be
subtracted from an end-to-end sample: forward and reverse path delays can be
asymmetric. Section 15 reports network and local pipeline components separately.

## 2. Compatibility and deployment boundary

Version 3 is additive.

- Lumen MUST retain its legacy GameStream/RTSP/ENet endpoints for vanilla
  Moonlight clients.
- Legacy clients MUST NOT receive `ULC3` or `ULM3` data and are never expected
  to advertise `lumen/3`.
- A version-3 connection MUST NOT enter the legacy launch sequence or reuse
  legacy keys, request IDs, sockets, packet headers, or fallback decisions.
- A paired version-3 client MUST NOT silently downgrade after an authentication
  or negotiation failure. Legacy use requires an explicit per-host user choice.
- Host capture, VDD, encoder, audio, and input implementations MAY be shared
  behind a typed session boundary. Wire parsing and security state are isolated.

An Umbra-only deployment exposes one version-3 UDP port. Supporting arbitrary
vanilla Moonlight clients still requires the legacy ports those clients use;
version 3 cannot collapse an unmodified legacy protocol onto one port.

No version-2 artifact or implementation is changed by this specification.

## 3. Standards and connection profile

| Concern | Requirement |
| --- | --- |
| Transport | QUIC version 1, RFC 9000 and RFC 9001 |
| QUIC DATAGRAM | RFC 9221, negotiated with a nonzero maximum |
| TLS | TLS 1.3 only, RFC 8446 |
| ALPN | exact ASCII `lumen/3` |
| TLS server identity | SHA-256 pin of the live leaf certificate DER SPKI |
| Application identities | Ed25519, RFC 8032 |
| Control encoding | restricted deterministic CBOR, RFC 8949 section 4.2.1 |
| Address migration | QUIC connection migration and path validation only |
| Key update | QUIC/TLS key update only |

The host binds exactly one application UDP socket for version 3. After optional
system mDNS discovery, pairing, control, stream startup, media, input,
microphone, stop, and telemetry all use the resulting QUIC connection. A
session never returns another application port.

TLS early data (`0-RTT`), PSK resumption, and session tickets MUST be disabled
in phase one at both endpoints, so every connection presents a live Certificate
whose leaf SPKI can be pinned. Pairing always uses a full handshake. A client MUST NOT
send application bytes until the TLS handshake has completed and the live leaf
SPKI matches its invitation or stored pairing pin. A future resumption extension
must bind the ticket to the previously validated host ID, SPKI, and Ed25519 key
with expiry/invalidation rules; it cannot silently change this phase-one rule.

The implementation MUST expose RFC 9221 DATAGRAM support. If either peer omits
it, `START` fails as unsupported; silently tunnelling live media through a
reliable stream would introduce head-of-line latency and is forbidden.

QUIC libraries handle packet-number protection, ACK generation, retransmission,
anti-amplification, congestion control, PMTU discovery, key update, and path
validation. Application code MUST NOT duplicate those mechanisms.

## 4. Discovery and invitation

Lumen advertises `_lumen-v3._udp` with:

| TXT key | Value |
| --- | --- |
| `v` | exact `3` |
| `id` | 32 lowercase hexadecimal characters encoding the 16-byte host ID |
| `port` | decimal QUIC UDP port |
| `caps` | 16 lowercase hexadecimal characters encoding the capability mask |

The default port is 48030, but clients use the advertised, entered, or invited
port and do not infer it from a legacy port. Direct IP entry uses the same
`host:port` endpoint. Discovery is advisory and never overrides a stored SPKI
pin.

The exact URI is:

```text
umbra://pair/v3#<base64url-without-padding(invitation_bytes)>
```

`invitation_bytes` has this exact layout:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `ULI3` |
| 4 | 1 | invitation format, `1` |
| 5 | 1 | flags: bit 0 hostname is an IP literal; all others zero |
| 6 | 2 | fixed header length, `172` |
| 8 | 2 | total length, `172 + hostname_length` |
| 10 | 2 | nonzero QUIC UDP port |
| 12 | 2 | protocol minimum, `3` |
| 14 | 2 | protocol maximum, `3` |
| 16 | 16 | random invitation ID |
| 32 | 32 | random single-use invitation token |
| 64 | 16 | host ID |
| 80 | 32 | SHA-256 of TLS leaf DER SPKI |
| 112 | 32 | host Ed25519 public key |
| 144 | 8 | issue time, Unix seconds |
| 152 | 8 | expiry time, Unix seconds |
| 160 | 8 | capability snapshot |
| 168 | 2 | hostname length, `1...253` |
| 170 | 2 | zero |
| 172 | variable | normalized ASCII hostname/IP, no NUL |

DNS names are lowercase IDNA A-labels without a trailing dot. IPv4 is dotted
decimal without leading zeroes; IPv6 is RFC 5952 text without brackets. The
token and ID are generated together, the expiry is no more than five minutes
after issue, and the complete bytes are stored host-side by
`SHA-256(invitation_bytes)`. `PAIR_REQUEST` carries that digest. Thus any QR
field mutation fails the stored digest even if it happens to route to the same
host. Address or SPKI mutation also fails pinned TLS before application data.

On every hello and pair response, the advertised host Ed25519 key MUST equal
offset 112 byte-for-byte and its derived host ID MUST equal offset 64. Umbra
verifies the host confirmation signature with that invited key before storing
trust. TLS/WebPKI fallback is forbidden when an invitation pin is present.

The secret is transmitted only after the pinned TLS handshake. Invitations are
consumed atomically and rate-limited before any expensive signature or database
operation. Logs redact invitation IDs/tokens, URI fragments, complete frames,
signatures, and tickets.

There is no short PIN flow. Adding one requires a separately specified and
audited PAKE; hashing or encrypting four decimal digits is not acceptable.

## 5. Encoding

Multi-byte integers are unsigned big-endian. Identifiers are opaque bytes, not
textual UUIDs. Text is valid UTF-8 and display names are NFC-normalized.

Control CBOR preserves the version-2 restrictions:

- shortest integer and length forms, definite lengths, and deterministic map
  key order;
- unsigned integer map keys only;
- no floats, tags, indefinite lengths, duplicate keys, invalid UTF-8, or
  trailing data;
- at most eight active containers, 128 map entries, 4096 array elements,
  65,535 bytes of text, and 1,048,576 bytes per byte string/control payload;
- unknown non-critical keys may be ignored; a frame marked `CRITICAL` fails on
  any unknown key.

Length/count products are checked for overflow before allocation.

## 6. Reliable control stream and idempotency

The client opens the first client-initiated bidirectional QUIC stream (stream
ID 0) immediately after TLS. It is the long-lived control stream. The peer
opening a second control stream is a protocol error. A replacement control
stream is not allowed inside the same connection; loss is handled by QUIC.

Control frames retain the 24-byte version-2 shape with a new namespace:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `ULC3` |
| 4 | 1 | version, exactly `3` |
| 5 | 1 | flags: bit 0 response, bit 1 error, bit 2 critical |
| 6 | 2 | message type |
| 8 | 8 | request ID |
| 16 | 4 | payload length |
| 20 | 4 | zero |
| 24 | variable | deterministic CBOR payload |

Requests have a nonzero request ID. Client-issued request IDs are odd and start
at 1; host-issued request IDs are even and start at 2. Each issuer increments
its own namespace by two. Responses echo the request ID, so response direction
determines the original issuer. Events have request ID zero and neither RESPONSE
nor ERROR. Request IDs are scoped to one QUIC connection authority generation,
never wrap, and are never reused on that connection. A new connection
starts a new request-ID namespace. Each connection permits 32 outstanding
requests and caches 128 completed responses. A byte-identical duplicate on the
same connection returns the byte-identical response; conflicting reuse closes
with `REQUEST_ID_CONFLICT`. Side effects commit before the response enters the
cache, and the cache write occurs before transport send. Cross-connection
idempotency uses operation identifiers (`pair_attempt_id`, `start_intent_id`,
`attach_intent_id`, and `stop_token`), never a recycled request ID.

Application list cursors, permissions, status values, `START` intent IDs,
`STOP` tokens, text-composition phases, and input reset semantics remain those
defined by version 2. A v3 implementation must reproduce the existing
deterministic CBOR vectors before adding v3 transport wiring.

### 6.1 Reliable bulk streams

Large application assets never block stream 0. Each is
one unidirectional QUIC stream with a 64-byte `ULB3` header, exact payload, then
FIN:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `ULB3` |
| 4 | 1 | version, `3` |
| 5 | 1 | object kind |
| 6 | 2 | flags, zero |
| 8 | 8 | originating connection-scoped request ID |
| 16 | 8 | object ID |
| 24 | 8 | payload length |
| 32 | 32 | SHA-256 of exact payload |

Phase-one kind is only `1` host-to-client application asset. Telemetry remains
bounded control batches; kind 2 is reserved. Other kinds/directions are
rejected. Asset length is at most 16 MiB, four concurrent bulk streams and 32
MiB buffered per connection. The matching control response carries kind, object ID, length, and
digest before the stream is accepted. Truncation, extra bytes, digest mismatch,
unknown request, duplicate object ID, wrong direction, reset, or missing FIN
discards the object without partial consumption.

### 6.2 Version-3 control types

Version 3 retains the version-2 type IDs for equivalent operations. The hello,
pair, auth, browse, start/attach, input reset/text, stop, video configuration,
and telemetry meanings are unchanged except where this document explicitly
replaces transport fields.

`START_REQUEST` no longer contains a client X25519 public key, key salt, AEAD
suite selection, media-port proposal, or application rekey interval.
`START_RESPONSE` no longer contains a host X25519 public key, exporter salt,
media UDP port, AEAD suite, epoch, packet-limit, or application rekey interval.
Any of those fields in a critical frame is rejected. Their replacements are:

- selected `LATENCY` or `QUALITY` profile;
- selected codec, chroma, bit depth, HDR transfer and metadata capabilities;
- resolution and rational refresh rate;
- selected semantic DATAGRAM record maximum;
- audio and microphone tuples;
- video, audio, microphone, and input configuration generations; and
- session ID, intent ID, trace ID, and synchronized telemetry anchors.

The selected semantic DATAGRAM maximum MUST NOT exceed the exact maximum the
QUIC stack reports at handshake. Phase one advertises exactly 1,152 bytes as
the immutable receiver acceptance upper bound including the 44-byte envelope;
neither peer advertises a larger value and migration does not change that
receiver bound. Each send is additionally capped by the sender QUIC stack's
current usable DATAGRAM size. A smaller live send cap does not close authenticated
control: video refragments at the next frame, and audio/microphone selects and
ACKs a fitting tuple or ends only the media session. Application code never
requests IP fragmentation.

### 6.3 Exact altered CBOR maps

All keys below are REQUIRED unless marked nullable. No other key is sent in a
phase-one critical frame.

`CLIENT_HELLO` (`0x0001`): 1 minimum version (`3`), 2 maximum version (`3`),
3 fresh nonce bstr32, 4 capability uint64, 5 offered profile array (`1`
LATENCY, `2` QUALITY), 6 paired client ID bstr16 or null, 7 invitation ID bstr16
or null, 8 connection/pair attempt ID bstr16. Exactly one of keys 6 and 7 is
non-null.

`SERVER_HELLO` (`0x0002`): 1 selected version (`3`), 2 fresh nonce bstr32,
3 host ID bstr16, 4 host Ed25519 public key bstr32, 5 live TLS leaf SPKI hash
bstr32, 6 capability uint64, 7 semantic DATAGRAM cap (`1152`), 8 exact attempt
ID echoed from the client hello.

`PAIR_REQUEST` (`0x0010`): 1 invitation ID bstr16, 2 token bstr32, 3 complete
invitation SHA-256 bstr32, 4 stable pair-attempt ID bstr16, 5 derived client ID
bstr16, 6 client Ed25519 public key bstr32, 7 NFC display name text <=64 bytes,
8 requested permission mask, 9 Ed25519 signature bstr64. The unsigned form used
in the transcript is the same map without key 9.

`PAIR_RESPONSE` (`0x0011`): 1 status, 2 host ID, 3 host Ed25519 public key,
4 client ID, 5 granted permissions, 6 minimum protocol (`3`), 7 pair-attempt
ID, 8 monotonic pairing-record generation, 9 host signature bstr64. The
unsigned form omits key 9.

`CLIENT_AUTH` (`0x0003`): 1 client ID bstr16, 2 connection-attempt ID bstr16,
3 replace-existing bool, 4 client signature bstr64. The unsigned form omits key
4. `AUTH_RESPONSE` (`0x0004`): 1 status, 2 client ID, 3 granted permissions,
4 connection-authority generation uint64, 5 owned active session ID or null,
6 connection-attempt ID, 7 host signature bstr64; unsigned omits key 7.

`START_REQUEST` (`0x0100`): 1 start-intent ID bstr16, 2 application ID uint32,
3 profile, 4 width, 5 height, 6 refresh numerator, 7 denominator, 8 bitrate
kbps, 9 codec-offer array, 10 audio-tuple array, 11 microphone tuple or null,
12 semantic DATAGRAM cap (`1152`), 13 trace ID bstr16, 14 HDR-offer array,
15 presentation-offer array, 16 resume bool, 17 quality-requirements map, and
18 play-audio-on-host bool. Key 18 is mandatory and controls whether host audio
continues locally while the selected audio tuple is captured; missing, null,
integer, or other non-boolean values are malformed. FEC is implicitly scheme
zero and has no offer key.

`START_RESPONSE` (`0x0101`): 1 status, 2 start-intent ID, 3 session ID bstr16,
4 selected profile, 5 codec tuple, 6 width, 7 height, 8 refresh numerator,
9 denominator, 10 bitrate kbps, 11 semantic cap (`1152`), 12 audio tuple,
13 microphone tuple/null, 14 video generation, 15 audio generation,
16 microphone generation, 17 input generation, 18 selected presentation map,
19 adjustment array, 20 trace ID, 21 attach token bstr32, 22 session-authority
generation, 23 selected HDR map/null. A failed response makes keys 3...23 null
except key 19 (`[]`).

`ATTACH_REQUEST` (`0x0102`): 1 session ID, 2 attach token bstr32, 3 stable
attach-intent ID bstr16, 4 last input generation, 5 map whose keys 1/2/3 are
last video/audio/microphone generations. `ATTACH_RESPONSE` (`0x0103`): 1
status, 2 session ID, 3 connection-authority generation, 4 new session-authority
generation, 5 input-reset-required bool, 6 current generation map with keys
1/2/3 video/audio/microphone.

The codec tuple keys are: 1 codec (`1` H.264, `2` HEVC, `3` AV1), 2 profile,
3 bit depth, 4 pixel layout (`1` YCbCr 4:2:0, `2` YCbCr 4:4:4, `3` RGB),
5 primaries, 6 transfer, 7 matrix (`0` identity for RGB), 8 range (`0` limited,
`1` full), 9 flags (bit 0 RFI, bit 1 hardware lossless), 10 fidelity (`1`
lossy, `2` visually lossless target, `3` mathematically lossless).
Audio/microphone tuple keys are: 1 codec (`1` Opus), 2 sample rate, 3 channels,
4 frame samples, 5 layout, 6 streams, 7 coupled streams, 8 exact channel map,
9 bitrate bps. Phase one permits at most eight channels and key 8 is exactly
`channels` bytes; 7.1.4/12-channel audio requires a later payload version.

Quality-requirements keys are: 1 minimum fidelity, 2 require RGB, 3 require
4:4:4, 4 require 10-bit, 5 require HDR, 6 allow adjustment. If key 6 is false,
failure of any requirement returns unsupported rather than silently selecting a
weaker tuple. Fidelity 3 requires codec flag bit 1, RGB or lossless-capable exact
layout, and a host encoder result explicitly classified lossless; bitrate alone
never proves it.

HDR offer and selected maps are direction-specific. Both use: 1 transfer
(`1` SDR, `2` PQ, `3` HLG), 2 H.273 primaries, 3 matrix, 4 range, and 5 bit
depth. In `START_REQUEST`, key 6 is the client capability map: 1 static metadata
supported bool, 2 maximum mastering luminance uint32 in 0.0001 nit, 3 maximum
content light uint16 nit, and 4 maximum frame-average light uint16 nit. Key 7
is the supported dynamic-metadata ID array. PQ and HLG pair with codec-tuple
H.273 transfer codes 16 and 18 respectively.

In `START_RESPONSE` and `VIDEO_CONFIG`, key 6 is the authoritative host
mastering map/null and key 7 is the selected dynamic-metadata ID array.
Mastering keys are: 1 six primary x/y
uint16 values in CTA order, 2 white-point x/y uint16, 3 max mastering luminance
uint32 in 0.0001 nit, 4 min mastering luminance same unit, 5 MaxCLL uint16 nit,
6 MaxFALL uint16 nit. Lumen reads these values from the active host
display/capture generation; it never echoes client content metadata or
synthesizes values from per-frame pixels.

Presentation maps use: 1 mode (`1` immediate/VRR, `2` latest-frame fixed-refresh
mailbox, `3` paced quality), 2 maximum queued frames (`1...2`), 3 VRR bool,
4 tear-free-required bool, 5 maximum present age microseconds. Adjustment maps
use: 1 field ID (`1` dimensions, `2` refresh, `3` bitrate, `4` codec,
`5` fidelity, `6` HDR, `7` presentation, `8` audio), 2 requested value,
3 selected value of the same CBOR type, 4 reason (`1` host unsupported,
`2` client limit, `3` profile policy, `4` network bound, `5` resource pressure).

`VIDEO_CONFIG` (`0x0140`, host request with a nonzero even ID): 1 session ID, 2 strictly
increasing generation, 3 selected codec tuple, 4 codec initialization bytes
<=1 MiB, 5 exact HDR metadata map/null, 6 width, 7 height, 8 refresh numerator,
9 denominator. `VIDEO_CONFIG_ACK` (`0x0141`): 1 status, 2 session ID,
3 generation, 4 decoder-capacity frames (`1` or `2`). No dependent video is
sent before this ACK.

`AUDIO_CONFIG` (`0x0142`) and `MICROPHONE_CONFIG` (`0x0144`) are host requests with:
1 session ID, 2 strictly increasing generation, 3 exact selected tuple, 4
discontinuity sample position. Their ACKs (`0x0143`/`0x0145`) contain 1 status,
2 session ID, 3 generation. Each ACK has RESPONSE set and echoes the host
request ID. No dependent record is emitted before ACK. A null
microphone tuple disables channel 4 and still advances generation.

`TELEMETRY_BATCH` (`0x0200`, event): 1 schema (`2`), 2 session ID, 3 trace ID,
4 source (`1` host, `2` client), 5 clock domain (`1` monotonic ns), 6 estimated
peer offset signed ns, 7 uncertainty ns, 8 sample array <=256. Each sample map is
1 stage ID, 2 object/sequence ID, 3 monotonic timestamp ns, 4 signed value, 5
flags. Larger snapshots are split into bounded batches; phase one does not open
an event-owned bulk stream.

## 7. Pairing and authentication transcripts

Every hello contains a fresh 32-byte random nonce. Nonces are generated per
connection and are never restored from a ticket. `CLIENT_HELLO` and
`SERVER_HELLO` include the exact protocol range, capabilities, mode offer,
identity (or null while pairing), host identity, host Ed25519 public key, and
the TLS leaf SPKI SHA-256. The SPKI in `SERVER_HELLO` MUST equal the live TLS
leaf and the invitation/stored pin.

Signatures cover complete encoded frames, not reconstructed CBOR maps. The
signed transcript function is:

```text
T(domain, spki, frames...) =
    domain || spki_sha256 ||
    uint32be(len(frame_1)) || frame_1 ||
    ... ||
    uint32be(len(frame_n)) || frame_n
```

The domain strings, including their terminating zero byte, are:

```text
lumen/3 pair client\0
lumen/3 pair host\0
lumen/3 auth client\0
lumen/3 auth host\0
```

### 7.1 Pairing

After pinned TLS:

1. Umbra sends `CLIENT_HELLO` with a fresh nonce and invitation ID.
2. Lumen sends `SERVER_HELLO` with a fresh nonce.
3. Umbra constructs a complete `PAIR_REQUEST` without its signature. It signs
   `T(pair-client, spki, CLIENT_HELLO, SERVER_HELLO,
   unsigned_PAIR_REQUEST)` with its new Ed25519 identity and sends the complete
   request containing the signature and 32-byte invitation secret.
4. Lumen validates invitation state/digest, invited host-key equality, rate
   limits, client ID derivation, full transcript, and permission bounds before
   one atomic consume-and-store.
5. Lumen signs `T(pair-host, spki, CLIENT_HELLO, SERVER_HELLO,
   complete_PAIR_REQUEST, unsigned_PAIR_RESPONSE)` with its application
   identity and sends the complete response.
6. Umbra verifies the response before storing the host identity, TLS SPKI pin,
   granted permissions, and `minimum_protocol = 3` with legacy fallback off.

The client and host IDs are the first 16 bytes of SHA-256 over the raw Ed25519
public key. Atomic consume creates a ten-minute cross-connection tombstone with
invitation ID, token SHA-256, complete invitation SHA-256, pair-attempt ID,
client public key/ID/name, requested and granted permissions, pairing-record
generation, and terminal status. A retry on a new pinned connection must carry
the same token and byte-identical semantic fields but fresh hello nonces and a
fresh valid transcript signature. Lumen returns the same stored outcome signed
over the new complete frames. A mismatch receives the same generic consumed/
unauthenticated status as an unknown secret and cannot mutate the pairing. The
tombstone is non-evicting until its deadline within the bounded 16-record pool;
when full, creation of a new invitation is refused. This recovers a lost
response without consuming twice or treating connection-scoped request IDs as
durable identifiers.

### 7.2 Paired authentication

After pinned TLS, the peers exchange fresh hello frames. The client signs
`T(auth-client, spki, CLIENT_HELLO, SERVER_HELLO,
unsigned_CLIENT_AUTH)`. The host validates the stored key, permissions, nonce
freshness, live connection, and complete frames. The host then signs
`T(auth-host, spki, CLIENT_HELLO, SERVER_HELLO,
complete_CLIENT_AUTH, unsigned_AUTH_RESPONSE)`.

No browse, start, input, media, microphone, or detailed telemetry operation is
accepted until both application-authentication signatures succeed. Signature
verification and final connection lookup occur under one lifecycle guard so a
validated request cannot be applied to a replaced connection.

For one client, successful authentication atomically increments
`connection_authority_generation`, installs `(connection, generation,
permissions)` as current, and revokes the old connection before the new
`AUTH_RESPONSE` can be sent. Every subsequent control mutation and DATAGRAM
lookup rechecks that tuple under the same lifecycle guard. The replaced
connection can neither inject input nor stop/attach a session and is closed with
`CONNECTION_REPLACED`. Its held input is neutralized.

An existing stream is not implicitly attached. `ATTACH_REQUEST` verifies the
stored attach token and current connection generation, then atomically advances
the session-authority generation, transfers the session to the new tuple,
invalidates the old tuple, and requires `INPUT_RESET` before accepting input.
If response send is ambiguous, the attach-intent tombstone returns the same
generation/outcome on retry. No interval exists where two generations may
mutate one session.

## 8. ULM3 semantic DATAGRAM envelope

Every QUIC DATAGRAM application payload is one complete ULM3 record:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `ULM3` |
| 4 | 1 | version, exactly `3` |
| 5 | 1 | channel |
| 6 | 1 | kind |
| 7 | 1 | flags |
| 8 | 2 | header length, exactly `44` |
| 10 | 2 | payload length |
| 12 | 16 | active session ID |
| 28 | 8 | semantic sequence |
| 36 | 8 | object ID |
| 44 | variable | kind-specific plaintext semantic payload |

"Plaintext" describes the application record before QUIC protection. It MUST
never be sent as an ordinary UDP datagram. QUIC encrypts and authenticates the
whole record.

For video data, flags are bit 0 key frame, bit 1 reserved (codec configuration
is reliable `VIDEO_CONFIG` and this bit is rejected), bit 2
final fragment, bit 3 repair (forbidden phase one), bit 4 discardable, and bit
5 static HDR metadata applies. Bits 6-7 are zero. All non-video records use
zero. A video repair record requires bit 3, but repair/FEC is disabled in phase
one and therefore such a record is rejected.

Payload length MUST equal the remaining record exactly. The session must be
active on that authenticated connection. The record must fit the negotiated
semantic maximum. A malformed, stale-session, reserved, misrouted, or oversized
record is silently dropped and counted; it does not tear down a healthy stream
unless a bounded abuse threshold is exceeded.

Sequence numbers start at one independently for each `(connection, direction,
channel)`, increase by exactly one per emitted record, and never wrap. Receiver
keeps a 1024-bit bounded reorder/deduplication window per tuple: a new high
sequence advances/zeroes the bitmap, an unseen in-window sequence is accepted,
and duplicates or values older than the window are dropped. Gaps are telemetry,
not a cryptographic replay mechanism. At `2^64-1024` the sender ends the session
and opens a new connection rather than risk exhaustion. A connection change
resets namespaces; a QUIC path migration does not. Video fragments may arrive
out of order inside this window and the separate frame bound. `object_id` means
input generation, video frame ID, audio sample position, microphone sample
position, or transport-telemetry generation according to channel.
The receiver DATAGRAM cap is immutable `1152` for the connection; `header_len +
payload_len` must equal the QUIC DATAGRAM application length and payload length
is consequently at most 1108.

## 9. Direction and channel registry

Unlisted triples are reserved and rejected.

| Direction | Channel | Kind | Meaning |
| --- | ---: | ---: | --- |
| client to host | 1 | 1 | complete input state/edge batch |
| host to client | 1 | 2 | input generation/edge acknowledgement |
| host to client | 1 | 3 | input resynchronization request |
| host to client | 1 | 4 | controller feedback and motion-rate control |
| host to client | 2 | 1 | encoded video data fragment |
| host to client | 2 | 2 | reserved video repair; always rejected phase one |
| client to host | 2 | 3 | video loss/keyframe/decode feedback |
| host to client | 3 | 1 | encoded audio packet |
| client to host | 4 | 1 | encoded microphone packet |
| host to client | 5 | 1 | live QUIC RTT telemetry |

There is no application path channel. QUIC migration/path validation owns it.
There is no application control DATAGRAM; security-sensitive and transactional
operations stay on the reliable ordered control stream.

## 10. Routing, generations, and bounds

### 10.1 Input

Input state payload is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | client monotonic sample time, microseconds |
| 8 | 8 | newest represented edge ID |
| 16 | 2 | state block length |
| 18 | 2 | edge count, `0...64` |
| 20 | 2 | state format, `2` |
| 22 | 2 | edge format, `2` |
| 24 | 8 | zero |
| 32 | variable | complete state-format-2 block, then edge-format-2 records |

State and edge format are both exactly `2`. Format `1` is rejected and is not
silently reinterpreted. ULM3 `object_id` is `state_seq`, starts at one, and
increases exactly once per snapshot.

State-format-2 begins with this exact 112-byte header:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | flags: bit 0 absolute pointer, bit 1 relative pointer, bit 2 initial baseline; exactly one pointer bit set |
| 4 | 4 | mouse-button bitmap, bits 0 through 4 |
| 8 | 8 | cumulative relative X, signed |
| 16 | 8 | cumulative relative Y, signed |
| 24 | 8 | cumulative vertical wheel, signed |
| 32 | 8 | cumulative horizontal wheel, signed |
| 40 | 4 | absolute X Q0.32, zero in relative mode |
| 44 | 4 | absolute Y Q0.32, zero in relative mode |
| 48 | 32 | keyboard HID-usage bitmap |
| 80 | 4 | active-controller bitmap |
| 84 | 1 | controller record count, `0...16` |
| 85 | 1 | touch record count, `0...16` |
| 86 | 1 | pen record count, `0...4` |
| 87 | 25 | zero |

Controller records are 64 bytes, sorted by controller ID:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | controller ID, `0...15` |
| 1 | 1 | controller type, `1...5` |
| 2 | 2 | Moonlight controller capability bits, mask `0x01ff` |
| 4 | 8 | button bitmap, mask `0x003fffff` |
| 12 | 2 each | left and right trigger Q0.16 |
| 16 | 2 each | left X/Y and right X/Y signed axes |
| 24 | 4 each | gyro X/Y/Z signed Q16.16 |
| 36 | 4 each | acceleration X/Y/Z signed Q16.16 |
| 48 | 2 | battery percentage times 100, or `0xffff` unavailable |
| 50 | 1 | Moonlight battery-state code, `0...5` |
| 51 | 1 | zero |
| 52 | 4 | supported-button mask, mask `0x003fffff` |
| 56 | 8 | zero |

Touch records remain 32 bytes. A controller touch uses pointer ID bits 31...24
as controller ID plus one, bits 23...16 as touchpad index, and bits 15...0 as
the controller-local pointer ID. A zero high byte is a normal touchscreen
pointer and preserves all 32 pointer bits. This makes controller zero,
touchpad zero unambiguous.

Edge-format-2 records are exactly 32 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | strictly increasing edge ID |
| 8 | 8 | client monotonic edge time, microseconds |
| 16 | 1 | kind |
| 17 | 1 | device/controller ID |
| 18 | 2 | code or controller capabilities |
| 20 | 4 | signed value or controller type |
| 24 | 4 | auxiliary value |
| 28 | 4 | zero |

Kinds are: `1` keyboard edge, `2` mouse-button edge, `3` controller-button
edge, `4` controller arrival, `5` touch lifecycle, and `6` pen lifecycle.
Controller arrival stores capabilities at offset 18, type at offset 20, and
the supported-button mask at offset 24. The host applies an arrival before the
same batch's controller base state. It acknowledges an edge only after the
ordered platform injector reports success; unsupported, unallocated, or
failed controller operations close the input generation without an ACK.

Input ACK payload is exactly 48 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | host receive time, microseconds |
| 8 | 8 | newest continuous state sequence applied |
| 16 | 8 | highest contiguous edge ID applied |
| 24 | 8 | received-edge bitmap |
| 32 | 8 | newest captured frame carrying these/newer watermarks |
| 40 | 8 | zero |

Input resync payload is exactly 16 bytes: offset 0 expected next edge ID u64,
offset 8 reason u8 (`1` edge pressure, `2` host reset, `3` authority transfer),
offsets 9...15 zero. ACK/resync object ID is the latest accepted state sequence.

Controller feedback payload is exactly 40 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | current input authority generation |
| 4 | 4 | nonzero controller instance generation |
| 8 | 1 | controller ID, `0...15` |
| 9 | 1 | command |
| 10 | 2 | command value length |
| 12 | 24 | command value followed by zero padding |
| 36 | 4 | zero |

Commands are `1` main rumble (`low u16, high u16`), `2` trigger rumble
(`left u16, right u16`), `3` motion state (`type u8, zero u8, report-rate
u16`), `4` RGB LED (`r u8, g u8, b u8`), and `5` adaptive triggers
(`flags u8, left type u8, right type u8, zero u8, left[10], right[10]`).
Command value lengths are respectively 4, 4, 4, 3, and 24. Motion type is
acceleration `1` or gyroscope `2`; rate is `0...2000` Hz and zero disables the
type. Adaptive flags use only bits 2 and 3. ULM3 object ID equals the input
authority generation.

Each client and host starts a controller instance generation at one for the
first accepted arrival of a slot in an input generation and increments it on
every later accepted arrival of that slot. Removal invalidates the current
instance without resetting its counter. `INPUT_RESET` starts a new input
generation and resets controller instance counters. The client applies a
feedback command only when session ID, input generation, controller ID, and
controller instance generation all match its live controller state. Stale
commands are ignored. The host emits these commands from the same production
virtual-controller feedback queue used by legacy GameStream; v3 does not route
them through or alter the legacy control channel.

The host applies pointer motion before a click from the same generation. It
acknowledges the highest complete generation and edge range. On a gap beyond
the retained 256 host / 512 client edge windows it requests a complete reset.
Disconnect, authority replacement, and teardown atomically neutralize pressed
keys, buttons, touches, pens, and controllers.

The negotiated send rate is 60-2000 records/s. Latency mode emits immediately
on an edge and coalesces only replaceable motion observed before the same QUIC
send opportunity. It has no fixed 1 ms batching timer.

### 10.2 Video

Video fragment payload begins with this exact 64-byte header followed by a
nonempty elementary-stream fragment:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | capture time, monotonic microseconds |
| 8 | 4 | encoder-submit delta from capture, microseconds |
| 12 | 4 | encoder-complete delta from capture, microseconds |
| 16 | 8 | newest applied input state sequence before capture submit |
| 24 | 8 | newest contiguous applied edge ID before capture submit |
| 32 | 4 | complete encoded frame size |
| 36 | 4 | fragment byte offset |
| 40 | 2 | fragment index |
| 42 | 2 | fragment count |
| 44 | 2 | slice/tile index, zero phase one |
| 46 | 2 | slice/tile count, zero phase one |
| 48 | 2 | FEC group, zero phase one |
| 50 | 1 | FEC shard index, zero phase one |
| 51 | 1 | FEC data shards, zero phase one |
| 52 | 1 | FEC parity shards, zero phase one |
| 53 | 1 | codec ID |
| 54 | 1 | selected H.273 matrix code |
| 55 | 1 | selected bit depth |
| 56 | 4 | acknowledged video-config generation |
| 60 | 4 | zero |

ULM3 object ID is frame ID. It starts at one, increments per display access unit,
and never wraps. Fragment indexes/offsets must form one exact non-overlapping,
gap-free frame. CONFIG is always rejected; codec initialization bytes exist only
in the acknowledged reliable config request. FINAL is set iff index is
`count-1`, and that fragment's offset plus data length equals frame size. KEY is
consistent across all fragments. A frame is at most 67,108,864 bytes and 65,535
fragments.

Video-repair payload uses the same 64-byte prefix followed by repair bytes and
requires ULM3 flag bit 3. Phase one negotiates FEC scheme zero only, so all FEC
fields are zero, capability is absent, sender never emits channel 2 kind 2, and
receiver rejects it. Its layout is reserved solely so future-version vectors
cannot reinterpret the registered route. Enabling it requires a versioned FEC
specification and new golden vectors.

Video feedback payload begins with 32 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | last completely reassembled frame ID |
| 8 | 8 | last successfully decoded frame ID |
| 16 | 1 | action: 1 complete, 2 loss, 3 decode failure, 4 IDR, 5 RFI |
| 17 | 1 | range count, `0...16` |
| 18 | 2 | zero |
| 20 | 4 | client deadline miss, microseconds |
| 24 | 8 | zero |
| 32 | variable | sorted non-overlapping `(first u16,count u16)` ranges |

Ranges occur only for action 2 and object ID is the affected frame. Deadline
miss is present only for action 1 or 3 and is zero for actions 2, 4, and 5. It is
zero when decode completes by the selected presentation map's key-5
maximum-present-age budget. Otherwise it is the positive number of whole
microseconds after that deadline, rounded up and saturated at `1,000,000`.
Umbra starts the deadline at the first valid fragment's client-local monotonic
receive time and samples completion in that same clock domain. It retains this
deadline through reassembly and decoder completion; it never subtracts host
capture time from a client clock. Pending deadline state is generation-scoped
and bounded independently of frame payload storage. Lumen validates the one-
second miss bound and records sample count, positive-miss count, current
consecutive misses, latest miss, and peak miss in the production session media
snapshot. This observation is reported at teardown and does not switch profiles
or mutate encoder policy during the session.

`VIDEO_CONFIG` is reliable control, has a strictly increasing nonzero
generation, and is acknowledged before dependent video is emitted. A generation
cannot change codec, dimensions, chroma, bit depth, transfer, or codec headers
implicitly. Unknown or retired generations are dropped and trigger bounded
config/keyframe feedback. Reassembly is bounded to one frame in latency mode
and two frames in quality mode, never more than 134,217,728 bytes.

### 10.3 Audio and microphone

Audio and microphone payloads share this exact 48-byte header followed by one
Opus packet (or empty DTX/END):

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | capture time, sender monotonic microseconds |
| 8 | 8 | 48 kHz first-sample position |
| 16 | 4 | acknowledged configuration generation |
| 20 | 2 | frame samples |
| 22 | 1 | channels |
| 23 | 1 | layout ID |
| 24 | 1 | codec, `1` Opus |
| 25 | 1 | payload flags: bit 0 DTX, bit 1 discontinuity, bit 2 end |
| 26 | 1 | Opus stream count |
| 27 | 1 | coupled stream count |
| 28 | 8 | channel mapping, unused bytes `ff` |
| 36 | 4 | selected bitrate bps |
| 40 | 8 | zero |

ULM3 object ID is the exact 48 kHz first-sample position and semantic sequence
is the packet sequence. Configuration is reliable control and monotonic.
Packets using an unacknowledged or retired generation are dropped.

Opus frame duration is selected from supported integral sample counts. The
payload must fit one semantic DATAGRAM; no application fragmentation. Silence
uses codec DTX or a valid silent packet, not device teardown. Microphone data is
accepted only with `SEND_MICROPHONE`, an active owned session, and matching
generation.

Phase one negotiates mono microphone, stereo, 5.1, or 7.1 only. The exact map
must fit the eight-byte payload field; channel guessing is forbidden.

### 10.4 Transport telemetry

Lumen emits channel 5 kind 1 at most once per 250 ms from the real MsQuic
`QUIC_STATISTICS_V2` connection sample. The replaceable record is authenticated
by the active session ID, expires after one second, has the lowest scheduler
priority, and cannot consume the urgent control/input send reserve. Its payload
is exactly 24 bytes:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | nonzero connection-local telemetry generation |
| 8 | 4 | MsQuic smoothed RTT, microseconds, `1...1,000,000` |
| 12 | 4 | MsQuic minimum RTT, microseconds, `1...smoothed RTT` |
| 16 | 4 | bounded RTT variation estimate, microseconds, `0...1,000,000` |
| 20 | 4 | zero |

ULM3 semantic sequence, object ID, and payload generation are identical. A new
authenticated connection resets the namespace. The variation is a one-quarter
EWMA of the greater of the smoothed-RTT sample delta and the current
smoothed-minus-minimum gap; the first sample uses that gap. Umbra validates every
field, ignores an older accepted in-window generation, and displays smoothed RTT,
variation, and minimum RTT. These measurements are observation only and do not
trigger automatic mode switching.

## 11. Latency profile

The latency profile minimizes queued age rather than merely selecting a faster
encoder preset.

- Input, control acknowledgements, audio, microphone, video configuration, and
  the newest decodable video frame are the scheduler order. Assets and verbose
  telemetry run only from remaining congestion budget.
- Input edges and completed encoder fragments are submitted without an
  intentional batching timer. A sender does not wait to fill a UDP packet.
- Host capture, conversion, and NVENC use the verified lowest-copy path for the
  active adapter/output. Any zero-copy or borrowed-texture path is a future
  capability and is never assumed or switched on during a session.
- Encoder reorder, lookahead, and B frames are off. The encoder input queue is
  one. The packetizer stops work on an obsolete frame before enqueueing more
  fragments.
- Host transmit, client reassembly, VideoToolbox, and Metal each admit at most
  one current video object. Superseded non-key frames are discarded rather than
  increasing latency.
- Phase-one FEC is unconditionally disabled. Loss uses deadline feedback and a
  bounded IDR/RFI decision; no receiver waits for repair data.
- Audio starts only after complete valid packets and uses the smallest measured
  stable preroll. It never blocks video or input.
- Presentation is immediate/VRR when supported. A fixed-refresh path uses a
  latest-frame mailbox with no extra application frame queue.

The target is capture-to-Metal-commit p99 below 5 ms and input-to-first-changed-
pixel submit p50 below 10 ms on a documented high-refresh LAN matrix. Those are
measurement gates, not protocol guarantees.

## 12. Quality profile

The quality profile prioritizes faithful, stable output while retaining bounded
latency on the defined LAN matrix. WAN/cellular policy is outside phase one.

- Resolution, refresh, codec, 10-bit depth, HDR, and 4:4:4 are explicit client
  offers/preferences. Quality mode never changes them automatically.
- HDR fields identify the selected transfer, primaries, matrix, range, and
  static metadata exactly. Dynamic metadata and per-frame luminance analysis
  remain future capability extensions, not baseline processing.
- Scaling is avoided at equal resolutions. When explicitly selected, its filter
  and color-light domain are part of the session configuration.
- The baseline encoder policy is P5/high-quality, quarter-resolution multipass,
  adaptive quantization on, lookahead off, and B-frame reorder off.
- Reassembly and decode queues hold at most two video frames. Display pacing is
  tear-free and uses measured refresh timestamps; queues drop toward the newest
  independently decodable frame when the age bound is exceeded.
- Phase-one FEC is unconditionally disabled. Quality mode uses bounded IDR/RFI
  recovery at the explicitly selected bitrate. Any Reed-Solomon profile requires a later
  versioned extension with exact field arithmetic and vectors.
- Audio may use a larger bounded jitter target than latency mode, but it is
  bounded and reported. Continuous audio and microphone paths do not re-open
  devices during silence.

"Indistinguishable from a direct cable" is an evaluation target. A quality
claim requires captured reference comparisons, objective metrics, artifact
inspection, HDR metadata validation, and visual review on the named display.

## 13. Backpressure and congestion behavior

All queues are bounded by item count and age. QUIC writable callbacks drive
sending; no thread busy-spins and no application retry loop creates duplicate
DATAGRAM records.

The sender maintains separate semantic queues and one connection scheduler.
Reliable control always makes progress; large assets/snapshots use the exact
ULB3 unidirectional object stream so they cannot monopolize stream 0.
Live media uses DATAGRAM and therefore is not retransmitted by QUIC. Codec
headers, session transitions, app metadata, and configuration use reliable
streams. Live RTT telemetry is a low-priority replaceable DATAGRAM and never
blocks media or input waiting for delivery.

Congestion response reduces in this order:

1. discard obsolete telemetry and assets;
2. discard obsolete video fragments/frames;
3. reduce discardable video and request bounded bitrate/resolution adjustment;
4. preserve control, input, and a valid continuous audio cadence while possible;
5. end the session with an explicit network-resource status if minima cannot be
   sustained.

Latency mode reacts to queue age first. Quality mode reacts to sustained loss,
bandwidth, and decoder/presentation stability while enforcing its maximum age.
Neither profile interprets configured bitrate as measured available bandwidth.

## 14. QUIC key update and network migration

Endpoints enable normal QUIC key updates at their library's reviewed safe
policy. Application records have no epoch field and no rekey control messages.
A key update cannot reset session, request, sequence, generation, or permission
state.

Address changes use QUIC connection IDs and RFC 9000 path validation. The
application does not send a ULM3 challenge. Until a new path is validated, the
QUIC anti-amplification and migration rules apply. On a validated path:

- the connection remains authenticated to the same stored SPKI and Ed25519
  identity;
- 1,152 remains the immutable negotiated upper bound, but every record is also
  no larger than the QUIC stack's current usable DATAGRAM send maximum; QUIC
  never fragments one ULM3 record. Video refragments only at a frame boundary.
  If the selected audio/microphone tuple no longer fits, control selects and
  ACKs a fitting generation or ends the session;
- congestion and RTT estimators follow the QUIC implementation's migration
  rules;
- video packetization changes only at a frame boundary; and
- mode-specific jitter/backpressure policy adapts without resetting input.

A network transition is telemetry, not a production-facing indefinite "host
state is changing" state. Failure produces a bounded reconnect or explicit
ended reason.

## 15. Telemetry and latency accounting

Both modes record the same monotonic trace points:

- client input sampled and QUIC submitted;
- host input received, validated, queued, and applied;
- host capture acquired, conversion complete, encoder submitted/completed;
- first/last frame fragment submitted;
- client first/last fragment received, reassembly complete, decoder submitted/
  completed, Metal encoded/committed; and
- audio receive, render enqueue, callback underrun/rebuffer, and device changes.

Every reported distribution includes count, p50, p95, p99, maximum, drops, and
the active mode/config generations. Clocks use a bounded offset/uncertainty
estimate derived from repeated control probes; samples whose uncertainty
exceeds the declared bound are not used for cross-host latency claims.

Network contribution is reported separately as RTT, RTT variation, loss,
congestion-window pressure and, only when clock synchronization supports it,
forward/reverse one-way estimates with uncertainty. `end_to_end - RTT` is not a
valid general local-pipeline metric. Compare:

- client-local input sample to QUIC submission;
- host-local receive to apply to capture to encode to QUIC submission; and
- client-local QUIC receive to reassembly to decode to Metal commit.

This decomposition permits honest LAN qualification without crediting or
blaming local code for an unmeasured network direction.

### 15.1 Deterministic watermark/change detector

Benchmark input samples carry a trace ID and target input generation. The host
watermark proves only that the generation was applied before capture submit.
For a declared, static benchmark ROI, Umbra stores the last complete decoded
pre-presentation luma plane before the input. For each later complete decoded
frame whose watermark reaches the generation, it counts ROI samples satisfying
`abs(current_code - baseline_code) >= threshold`, with threshold `4` for 8-bit
and `16` for 10-bit. The first frame with at least
`max(16, ceil(ROI_sample_count / 1000))` changed samples is the deterministic
"first changed frame." Integer code values are compared before tone mapping,
scaling, dithering, or Metal presentation. The ROI, bit depth, threshold,
baseline frame ID, candidate frame ID, watermark, count, and configuration
generation are recorded.

This detector cannot prove causality: animation, cursor blinking, temporal
dithering, codec noise, or unrelated scene motion may satisfy it; an input may
also change game state without changing the ROI. HDR code-value deltas are not
perceptual luminance. Results are labeled input-to-first-detected-change, not
input-to-photon, and optical validation remains required.

## 16. Denial-of-service and lifecycle caps

| Item | Limit |
| --- | ---: |
| TLS/hello deadline | 5 s |
| pre-auth connections | 64 host-wide, 8 per source IP |
| authenticated connections | 4/client, 128 host-wide |
| control payload | 1,048,576 bytes |
| outstanding requests | 32/connection |
| cached responses | 128/connection, 16 MiB host-wide |
| pairing recovery tombstones | 16 host-wide, non-evicting until 10 min expiry |
| active streams | 1/client, 8 host-wide |
| semantic DATAGRAM immutable maximum | 1,152 bytes |
| encoded video frame | 67,108,864 bytes |
| video fragments | 65,535/frame |
| video reassembly | latency 1 frame; quality 2; 134,217,728 bytes host-wide/client |
| input retained edges | host 256, client 512 |
| input rate | 60-2000/s |
| width/height | even; 320-7680 / 200-4320 |
| refresh rational | 1-480 Hz after numerator/denominator validation |
| video bitrate | 1,000-500,000 kbps |
| pairing failures | bounded per source prefix; security failures collapse |

Host-wide limits may be configured downward. Raising a wire-visible limit
requires capability negotiation and hostile allocation tests.

### 16.1 Phase deadlines

| Phase | Deadline from preceding success |
| --- | ---: |
| TLS handshake and SPKI decision | 5 s from first packet |
| client control stream + `CLIENT_HELLO` | 2 s after TLS |
| `SERVER_HELLO` | 2 s after client hello |
| `PAIR_REQUEST` / `CLIENT_AUTH` | 3 s after server hello |
| signed pair/auth response | 2 s after valid request |
| `START_RESPONSE` terminal outcome | 10 s after request |
| `ATTACH_RESPONSE` | 3 s after request |
| configuration ACK | 3 s after config event |
| graceful `STOP_RESPONSE` | 2 s after request |
| complete session teardown/`SESSION_ENDED` | 5 s after stop/control-loss expiry |

Deadlines use monotonic clocks, never extend on malformed data, and produce one
terminal outcome. TLS/control authentication timeout closes the connection;
configuration timeout ends the session; START rollback releases every partially
allocated resource and stores its terminal intent outcome.

### 16.2 QUIC application close codes

| Code | Name | Meaning |
| ---: | --- | --- |
| `0x100` | `MALFORMED` | invalid fixed header/CBOR/length |
| `0x101` | `VERSION_OR_ALPN` | wrong version or protocol namespace |
| `0x102` | `AUTHENTICATION_FAILED` | collapsed security failure |
| `0x103` | `UNAUTHORIZED` | authenticated permission failure |
| `0x104` | `PHASE_TIMEOUT` | deadline above expired |
| `0x105` | `CONNECTION_REPLACED` | newer authority generation installed |
| `0x106` | `ABUSE_LIMIT` | bounded malformed/rate threshold exceeded |
| `0x107` | `RESOURCE_LIMIT` | hard allocation/stream/request cap |
| `0x108` | `REQUEST_ID_CONFLICT` | same ID with different bytes |
| `0x109` | `INTERNAL_FAILURE` | fail-closed internal invariant failure |
| `0x10A` | `NORMAL_SHUTDOWN` | explicit connection shutdown |

Close reasons are fixed names without peer-controlled text or secrets.

### 16.3 Abuse and teardown

Pre-auth DATAGRAM or bulk-stream data closes immediately. Before auth, one
malformed control frame closes; no parser resynchronization scan is attempted.
After auth, 32 malformed control/ULM3/bulk records in any rolling 10 seconds or
more than 256 invalid DATAGRAM records per second for three consecutive seconds
closes with `ABUSE_LIMIT`. Authentication failures are limited to 32/s per
source prefix and logged at most once/s; excess is silently dropped. QUIC
library anti-amplification remains enabled.

Session teardown is serialized and idempotent:

1. revoke session authority generation and remove DATAGRAM routing;
2. neutralize all input and reject new microphone/input records;
3. stop microphone capture, host audio capture, encoder, capture/VDD lease, and
   application ownership in that order, each with its bounded local deadline;
4. cancel reassembly/decode/presentation and bulk objects, then zero/session-
   release tokens and queues;
5. cache the STOP terminal outcome and send exactly one `SESSION_ENDED` after
   all media/input resources are terminal;
6. keep authenticated control alive after ordinary STOP, or close it with the
   applicable code after connection failure/abuse.

Control loss starts a two-second reconnect/attach grace while input is already
neutralized. Expiry performs the same teardown. No path leaves a frozen frame
labelled active or an owned VDD/audio/input resource after `SESSION_ENDED`.

## 17. Deterministic vectors and implementation gate

The independent oracle is:

```text
docs/protocols/vectors/quic_v3_oracle.py
```

The checked-in fixture and regression test are:

```text
docs/protocols/vectors/quic_v3_vectors.json
docs/protocols/vectors/quic_v3_oracle_test.py
```

They cover complete-frame pairing/authentication transcripts, fresh nonce and
SPKI/invited-host binding, host confirmation, exact ULI3/ULC3/ULM3/ULB3
encoding, all ten routes and lifecycle artifacts, direction errors,
truncation, length mismatch, reserved flags, session mismatch, phase-one FEC
rejection, invitation mutation, bulk digest mismatch, and immutable size bounds.

Release acceptance requires the C++ and Swift implementations to:

1. reproduce every positive artifact byte-for-byte;
2. reject every hostile case for the specified reason class;
3. pass fuzzing for ULC3 length/CBOR and ULM3 routing/allocation boundaries;
4. demonstrate TLS 1.3, exact ALPN, SPKI pinning, disabled 0-RTT, QUIC key
   update, migration, and immutable 1,152-byte DATAGRAM cap with packet captures;
5. prove legacy Moonlight paths remain wire-identical through their existing
   test corpus; and
6. pass measured latency/quality profile gates on the documented hardware and
   network matrix without unsupported input-to-photon claims.

The production runtime is linked and the deterministic oracle is passing. Until
the packet-capture and measured cross-machine gates are run, `lumen/3` remains
implemented but not live transport-acceptance validated.
