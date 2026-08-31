# Lumen Streaming Protocol architecture rationale

Status: selected design direction, implementation active. This document records
the clean-room transport decision for the protocol that will replace the
experimental QUIC protocol. It is not a compatibility or migration profile for
that protocol.

## 1. Decision

The new **Lumen Streaming Protocol** (LSP) will use:

- one bidirectional UDP application port;
- DTLS 1.3 for peer authentication, session establishment, key export, and
  protected control records;
- SRTP and SRTCP with AEAD AES-128-GCM for video, audio, microphone, input,
  feedback, repair, and telemetry;
- one RTP session containing explicitly negotiated SSRCs for every real-time
  lane;
- RTP and RTCP multiplexing on the same port;
- RTP payload formats for H.264, HEVC, AV1, and Opus;
- an aggregate, application-owned pacer and congestion controller;
- deadline-aware packet admission, optional FlexFEC, and retransmission only
  when a packet can still arrive before its deadline; and
- a bounded reliable control protocol carried in DTLS application records.

LSP is a ground-up replacement. It does not retain the retired transport
connection, custom records, fixed 1,152-byte envelope, control state machine,
scheduler, media fragment format, replay namespace, input format, feedback
messages, recovery cadence, or queue policy.

Only transport-independent product components may remain: capture, color
conversion, encoders, audio capture, platform input injection, decoders,
renderers, application management, and identity storage. They must connect to
LSP through new interfaces rather than compatibility adapters for the old
protocol.

## 2. Why a new protocol is necessary

The existing QUIC implementation does not provide a usable performance
baseline. Its behavior is low-frame-rate and periodically stuttery even where
the legacy Moonlight path works smoothly on the same host and network.
Consequently, the replacement must not encode existing behavior as a contract
or treat passing existing protocol tests as evidence that its architecture is
sound.

Repository inspection identified structural risks that LSP deliberately
eliminates:

- live video is split into roughly one-kilobyte QUIC DATAGRAM records, creating
  very high packet and callback rates;
- client receive processing crosses several serial Swift dispatch boundaries
  before frame reassembly;
- host send expiration and `CANCEL_ON_BLOCKED` can discard a partially
  submitted frame;
- send pressure and client loss/decode feedback can request full IDR recovery;
- recovery keyframes are larger and can intensify the pressure that caused the
  recovery;
- phase-one FEC is disabled; and
- the configured bitrate is not a measured available-bandwidth estimate.

These observations explain the design constraints for LSP. They are not a list
of old code to patch or preserve.

## 3. Primary objective

LSP is designed first for competitive game streaming on a controlled wired
network. Its ordering of priorities is:

1. input correctness and input-to-host latency;
2. current-frame delivery and low tail latency;
3. stable full-frame-rate presentation without periodic hitches;
4. continuous low-jitter audio;
5. useful visual quality at the sustainable path rate;
6. recovery from actual loss without a keyframe storm;
7. throughput efficiency and low CPU cost; and
8. mobility, WAN convenience, and bulk-transfer throughput.

This ordering is intentional. A transport that produces perfect eventual
delivery after the presentation deadline has failed the primary use case.

## 4. Hard requirements

- Every LSP application packet uses one configured UDP port number. The host
  never announces a second media, input, feedback, or control port.
- One aggregate congestion and pacing policy governs all packets sent to a
  peer, regardless of logical lane or SSRC.
- No live video packet is retransmitted after its presentation deadline.
- No queue may grow without both an item bound and an age bound.
- The network hot path performs no UI work, no main-actor work, and no
  per-packet heap allocation in steady state.
- Ordinary middle video packets carry no optional RTP extensions; infrequent
  frame-boundary packets carry the timing and causal metadata.
- RTP packets are built in their final slab and protected/deprotected in place.
  A decoder-imposed final frame coalescing copy is allowed, but another packet-
  by-packet payload copy is not.
- Sender-side queue pressure does not automatically request an IDR.
- Receiver loss first uses available repair, deadline-eligible retransmission,
  and reference-aware recovery. Full IDR is the last recovery mechanism.
- A clean wired path must not pay a permanent high FEC tax.
- Protocol telemetry must distinguish capture, encode, network, reassembly,
  decode, render submission, and presentation-proxy time.
- Legacy Moonlight compatibility remains separate. It is not tunneled through
  LSP and does not constrain the LSP wire format.

## 5. Why not QUIC

QUIC is a strong general-purpose secure transport. RFC 9221 gives QUIC
DATAGRAM frames unreliable delivery while retaining QUIC authentication,
congestion control, path validation, and connection migration. Those are
valuable properties for browsers, mobile clients, and WAN applications.

They are not the best control boundary for this project:

- QUIC DATAGRAM frames use the connection's congestion controller. The
  application can assign deadlines and priorities only through the API surface
  exposed by the implementation.
- The prior platform transport libraries expose different scheduling and
  callback models. The protocol cannot require identical frame-aware behavior
  from both.
- QUIC datagrams are connection-scoped rather than stream-scoped. Adding QUIC
  streams does not isolate live video datagrams.
- Multiple QUIC connections would create multiple congestion controllers over
  one bottleneck and would not remove per-packet application overhead.
- QUIC's migration and reliable-stream machinery is not worth surrendering
  deterministic packet admission, pacing, feedback timing, and recovery policy
  in the competition-LAN profile.

This is not a claim that QUIC is inherently slow. It is a decision that LSP
needs direct ownership of the real-time data plane and cannot rely on opaque,
platform-specific QUIC scheduling behavior.

## 6. Why not unstructured raw UDP

Bare UDP provides message boundaries and little else. RFC 8085 requires
high-rate UDP applications to implement congestion control, fairness, burst
mitigation, message-size management, and robust error handling.

A fully custom encrypted datagram protocol would also need to recreate:

- authenticated key establishment;
- replay protection and sequence rollover;
- media timestamps and stream identifiers;
- reception and congestion feedback;
- codec packetization;
- repair-stream association; and
- packet-capture tooling and established parser behavior.

LSP therefore uses raw UDP as the socket substrate while adopting DTLS, SRTP,
RTP, RTCP, and existing payload formats above it.

## 7. Why RTP/SRTP

RTP supplies the exact primitives needed by real-time media without promising
eventual delivery: payload identification, timestamps, sequence numbers,
independent SSRC spaces, and delivery monitoring. RTCP supplies feedback and
sender/receiver timing. SRTP and SRTCP add confidentiality, integrity, and
replay protection.

The standards already support the one-port requirement:

- RFC 5761 multiplexes RTP and RTCP on one UDP port.
- RFC 7983 defines first-byte demultiplexing for DTLS, RTP/RTCP, STUN, TURN,
  and related protocols on one receiving socket.
- RFC 8843 demonstrates the established model of multiple media descriptions
  sharing one transport five-tuple. LSP uses its own deterministic control
  negotiation instead of SDP, but follows the same single-transport principle.
- RFC 5764 derives SRTP keys from DTLS and requires non-RTP control data to use
  separate DTLS-framed datagrams on the same socket.

This provides a standards-based packet data plane while allowing LSP to own
the scheduling and recovery algorithms.

## 8. Security selection

LSP targets DTLS 1.3 from RFC 9147 and the
`SRTP_AEAD_AES_128_GCM` protection profile from RFC 7714.

DTLS is used only for handshake and relatively low-rate control. SRTP protects
the high-rate media and input path. The security design therefore does not put
every media packet through a DTLS record API.

The selected provider is commercially licensed wolfSSL 5.9.2. Its stable
release supports DTLS 1.3, stateless HelloRetryRequest cookies, ALPN,
`use_srtp`, and the RFC 5764 exporter. A macOS Stage 0 exchange has proved the
exact `TLS_AES_128_GCM_SHA256` cipher suite, X25519, ALPN
`lumen-stream/1`, `SRTP_AEAD_AES_128_GCM`, and matching 56-byte exporter
output. Windows packaging and the libSRTP wolfCrypt AES-GCM backend remain
mandatory Stage 0 gates. LSP must not silently downgrade to DTLS 1.2.

This gate affects session startup, not the selected media data plane. It is
better to resolve it before building incompatible temporary security framing.

## 9. Congestion-control selection

LSP uses frequent SRTCP congestion-control feedback based on RFC 8888. The
feedback reports packet arrival time and ECN information to the sender. The
sender combines it with its known send times and delivered-byte history.

The default adaptive controller follows the low-queue-delay principles of
SCReAM (RFC 8298):

- a self-clocked byte window;
- delay trend as an early congestion signal;
- loss and ECN as immediate reduction signals;
- an explicit target queue-delay budget; and
- encoder rate controlled by available media credit rather than configured
  bitrate alone.

LSP defines its exact controller behavior rather than claiming generic SCReAM
interoperability. RFC 8298 is an algorithmic reference, while RFC 8888 is the
wire feedback format.

A separate competition-LAN controller may start at an operator-provisioned
rate without slow start. It still has an aggregate shaper, ECN/loss circuit
breaker, and a hard maximum rate. It is not an excuse to transmit at NIC line
rate.

## 10. Repair selection

The protocol supports three distinct repair mechanisms:

1. **FlexFEC:** RFC 8627 repair packets on a separate SRTP SSRC, protected and
   paced with the primary video stream. Small frame-local groups avoid adding a
   multi-frame repair delay.
2. **Conditional RTX:** RFC 4588 retransmission on a separate SSRC, used only
   when the sender predicts arrival before the frame deadline. Competition mode
   disables ordinary delta-frame RTX by default.
3. **Codec recovery:** reference-picture invalidation or bounded intra refresh
   when supported, with PLI/FIR-driven IDR only when decoder state cannot be
   repaired.

No receiver waits beyond the presentation deadline for FEC or RTX. A clean
wired path may negotiate zero active FEC while retaining the ability to enable
it after measured burst loss.

## 11. Codec packetization

LSP uses established formats rather than a new generic video-fragment header:

- H.264 uses RFC 6184.
- HEVC uses RFC 7798.
- AV1 uses the Alliance for Open Media's final **RTP Payload Format For AV1**,
  version 1.0.0. There is no AV1 RTP RFC; RFC 9364 is unrelated and must not be
  cited as one.
- Opus uses RFC 7587.
- RTP header extensions use RFC 8285.
- capture timing uses RFC 8872.
- codec-independent frame start/end, independence, and discardability use
  RFC 9626.

Codec configuration is acknowledged over reliable control before dependent
media is accepted. Required parameter sets are also repeated in-band at the
codec-defined recovery boundary.

The video configuration maps use a dedicated schema revision two without
renaming LSP/1 or changing the surrounding control protocol. Revision two
binds each repeated encrypted frame identity to its recovery epoch as one
12-byte network-order value. This lets authenticated decoded-frame feedback
confirm the exact outstanding recovery attempt and prevents an old epoch from
clearing or retrying a newer one.

## 12. Throughput model

LSP is designed for at least 100,000 aggregate authenticated RTP packets per
second per endpoint without per-packet heap allocation. This covers 500 Mbps
while the path remains at the conservative 1,200-byte UDP payload in one
direction plus the negotiated small-packet input budget and feedback in the
reverse direction. Normal Ethernet-MTU video remains below 45,000 packets/s
before direction-specific feedback.

For comparison:

| Encoded rate | old 1,044-byte payload | LSP safe 1,164-byte payload | LSP Ethernet 1,436-byte payload |
| ---: | ---: | ---: | ---: |
| 100 Mbps | about 11,973 packets/s | about 10,739 packets/s | about 8,705 packets/s |
| 250 Mbps | about 29,933 packets/s | about 26,847 packets/s | about 21,762 packets/s |
| 500 Mbps | about 59,866 packets/s | about 53,694 packets/s | about 43,524 packets/s |

The LSP values conservatively subtract a 12-byte RTP header, 16-byte GCM tag,
and eight codec-payload bytes. Frame-boundary extension packets carry less media;
the high-rate middle packets do not. Larger path-MTU-safe packets help, but
syscall, allocation, dispatch, crypto, and copy amortization remain mandatory.
The client cannot reproduce the old design's one-callback/one-copy/one-
dispatch-chain behavior at these rates.

## 13. Socket and execution model

The data plane uses a raw nonblocking UDP socket and dedicated high-priority
workers.

On Windows, the implementation should evaluate overlapped receive with IOCP or
Registered I/O, `UDP_RECV_MAX_COALESCED_SIZE`, `UDP_SEND_MSG_SIZE`, and
high-resolution waitable timers. Microsoft documents the UDP coalescing and
segmentation socket options and requires the segment size to remain below the
path MTU.

On macOS, the implementation uses a nonblocking socket, kqueue readiness,
`SO_TIMESTAMP_MONOTONIC`, a drain-until-empty receive loop, preallocated packet
slabs, and a dedicated QoS thread. Private or undeclared batching syscalls are
not an acceptable dependency.

The socket worker scans each bounded receive batch for tentative lane metadata,
authenticates urgent lanes first, drains the kernel before doing heavyweight
work, and routes verified packets to fixed-capacity queues. DTLS control,
SRTCP feedback, input, audio, and video do not share one serial application
executor. Spoofed metadata causes no side effect before authentication.

The transmit pacer uses a rate-derived microbatch no longer than 100
microseconds and no larger than eight path-sized datagrams. This bounds burst
delay while amortizing timer and syscall overhead at high rates. Receiver
decode capacity is an explicit negotiated and continuously reported input to
complete-frame admission; adding a hidden compressed-frame queue is forbidden.

The performance-review invariants are:

| Boundary | Invariant |
| --- | --- |
| RTP middle packet | no optional extension; maximum path-safe codec payload |
| Transmit allocation | construct once in final slab; in-place SRTP |
| FEC | incremental plaintext parity; no duplicate source-packet copy |
| RTX | retain final source slab; copy only on actual eligible retransmission |
| User-space pacing | at most 100 microseconds per microbatch |
| Kernel/NIC horizon | at most two quanta and 200 microseconds of earned credit |
| Receive ordering | bounded batch, urgent packets authenticated first |
| Video reassembly | two incomplete frames, no presentation FIFO |
| Decoder | negotiated `2...4` hardware submissions, no compressed software queue |
| Renderer | latest-frame mailbox depth one |
| Input edge | separate small packet; no full state attached |
| Input baseline | multipart only at authority establishment |
| Telemetry | thread-owned counters; no contended per-packet atomic or logging |

## 14. High-rate input research

High-polling gaming mice and keyboards make video-frame-driven input
architecturally invalid. An 8 kHz device can produce one physical report every
125 microseconds, while a 240 Hz video frame spans about 4.17 ms. Tying input
to the video loop would collapse roughly 33 possible input observations into
one frame opportunity before accounting for display or application delay.

The platform evidence also changes the client design:

- Apple's AppKit header states that mouse-movement coalescing is enabled by
  default. A current `NSView.mouseMoved` callback rate therefore cannot be
  treated as the physical polling rate unless coalescing is disabled and the
  delivered rate is measured.
- Public IOHID input callbacks expose `IOHIDValueGetTimeStamp`, documented as
  OS AbsoluteTime. This provides a device-value timestamp before an AppKit
  event reaches the main UI path.
- GameController exposes value/motion change handlers and
  `lastEventTimestamp`; Apple recommends change handlers instead of polling
  controller buttons once per frame.
- Moonlight Common's mature C input sender already applies the same semantic
  split selected for LSP: latency mode bypasses its intentional mouse wait,
  relative motion accumulates rather than losing deltas, absolute/controller
  motion keeps the latest state, and physical button/lifecycle changes use
  reliable events.

LSP consequently separates physical capture, network report, and host apply
rates. It sends cumulative relative pointer values, latest analog/sensor state,
and independently acknowledged edges. A selected 8 kHz network report rate is
independent of 60, 120, 240, or any other video FPS.

The fixed high-rate pointer packet is 124 UDP payload bytes after RTP, the LSP
input header, and the SRTP tag. Including IPv4 and UDP headers it consumes about
9.7 Mbps at 8 kHz and 19.5 Mbps at 16 kHz. LSP reserves this exact wire budget
in the client-to-host direction before microphone or bulk traffic. Forward
video has independent congestion state unless an explicitly characterized
shared/half-duplex link coordinator relates the directions. Sixteen kilohertz
is protocol and synthetic-test headroom, not a claim that macOS or a connected
device provides a 16 kHz physical stream.

Controllers need separate semantics rather than being treated as slow mice:
buttons and touch lifecycles are ordered edges; sticks and analog triggers are
latest state; gyro and accelerometer have independent sample clocks; touch
coordinates are replaceable while contact down/up remains ordered; haptics and
adaptive-trigger feedback are generation-scoped in the reverse direction.

## 15. Umbra implementation language and boundary

The recommended Umbra architecture is a C++23 native core behind a narrow C
ABI, with Swift retained for application lifecycle, settings, persistence,
window management, accessibility, and per-frame media presentation.

The C++ core owns:

- raw UDP and kqueue integration;
- packet slabs and bounded queues;
- DTLS/libSRTP and replay state;
- LSPC framing, selective ACKs, RTO, and idempotent wire delivery;
- RTP/RTCP, FEC, RTX, DPLPMTUD, pacing, and congestion control;
- high-rate input state, edge retention, ACK processing, and packet creation;
- video packet reassembly and frame-deadline decisions; and
- thread-owned telemetry counters.

Objective-C++ adapters terminate IOHID and GameController callbacks and feed
plain native records to the core. Swift receives complete encoded frames,
complete audio units, lifecycle events, and low-rate telemetry snapshots. It
does not receive one callback per UDP packet, mouse poll, or controller-sensor
sample.

The boundary uses opaque handles, fixed-layout C structs, spans expressed as
pointer plus length, explicit retain/release functions, and function pointers.
No STL type, C++ exception, coroutine, allocator ownership, or Swift reference
crosses it. This is intentionally narrower than direct Swift/C++ import: the
official Swift interoperability status still identifies important unsupported
or experimental behavior including exception propagation, move operations, and
virtual member functions.

Pure Swift can be fast, but it provides no advantage for the packet and raw-HID
loops that must share wolfSSL, libSRTP, codec C APIs, and Lumen's C++ protocol
logic. ARC, `Data`, actor, and dispatch use are acceptable at per-frame or
control frequency, not as mandatory work at 100,000 packets/s or 8,000 pointer
reports/s.

Rust is the strongest alternative if the protocol core were an independent new
product and the team accepted another toolchain: it offers comparable native
performance and better memory-safety defaults. It is not automatically better
for this repository pair because Lumen is C++, Apple HID/controller integration
still needs C/Objective-C interop, existing codec/security dependencies use C,
and Rust-to-C++ integration would still need a carefully audited C ABI. A small
Rust parser/security library could be reconsidered later, but mixing Rust and
C++ in the first latency-critical implementation increases build and ownership
risk without removing the FFI boundary.

C is suitable for the ABI and third-party libraries but not preferred for the
whole stateful protocol. Zig has an attractive C boundary but a less mature
Apple-framework and dependency ecosystem for this project. C++ is therefore
the best pragmatic core language here, provided the ABI and ownership rules
remain strict.

## 16. Explicitly rejected architectures

| Candidate | Decision | Reason |
| --- | --- | --- |
| One QUIC connection with DATAGRAM | Reject | Insufficient deterministic ownership of pacing and platform behavior |
| Multiple QUIC connections | Reject | Competing congestion controllers and duplicated state |
| Video on QUIC streams | Reject | Reliable head-of-line delay is wrong for expired video |
| Raw encrypted custom datagrams | Reject | Recreates mature RTP/SRTP functionality and security risk |
| Full WebRTC stack | Reject | ICE, SDP, SCTP, browser interoperability, and multiparty machinery exceed the product need |
| SCTP/DTLS control | Reject for LSP/1 | Large dependency and state surface for a small bounded control plane |
| TCP control plus UDP media | Reject | Violates the one-application-port requirement and adds cross-transport authority races |
| No congestion control on LAN | Reject | Unsafe outside a perfectly provisioned path and contrary to RFC 8085 |

## 17. Evidence and standards references

- [RFC 3550: RTP](https://www.rfc-editor.org/rfc/rfc3550.html)
- [RFC 3711: SRTP](https://www.rfc-editor.org/rfc/rfc3711.html)
- [RFC 4588: RTP retransmission](https://www.rfc-editor.org/rfc/rfc4588.html)
- [RFC 4585: RTP/AVPF feedback](https://www.rfc-editor.org/rfc/rfc4585.html)
- [RFC 5104: codec-control feedback](https://www.rfc-editor.org/rfc/rfc5104.html)
- [RFC 5506: reduced-size RTCP](https://www.rfc-editor.org/rfc/rfc5506.html)
- [RFC 5761: RTP/RTCP multiplexing](https://www.rfc-editor.org/rfc/rfc5761.html)
- [RFC 5764: DTLS-SRTP](https://www.rfc-editor.org/rfc/rfc5764.html)
- [RFC 6184: H.264 RTP payload](https://www.rfc-editor.org/rfc/rfc6184.html)
- [RFC 6904: encrypted RTP header extensions](https://www.rfc-editor.org/rfc/rfc6904.html)
- [RFC 7587: Opus RTP payload](https://www.rfc-editor.org/rfc/rfc7587.html)
- [RFC 7657: differentiated-services considerations](https://www.rfc-editor.org/rfc/rfc7657.html)
- [RFC 7714: AES-GCM for SRTP](https://www.rfc-editor.org/rfc/rfc7714.html)
- [RFC 7798: HEVC RTP payload](https://www.rfc-editor.org/rfc/rfc7798.html)
- [RFC 7983: single-socket packet demultiplexing](https://www.rfc-editor.org/rfc/rfc7983.html)
- [RFC 8085: UDP usage guidelines](https://www.rfc-editor.org/rfc/rfc8085.html)
- [RFC 8285: RTP header extensions](https://www.rfc-editor.org/rfc/rfc8285.html)
- [RFC 8298: SCReAM](https://www.rfc-editor.org/rfc/rfc8298.html)
- [RFC 8627: FlexFEC](https://www.rfc-editor.org/rfc/rfc8627.html)
- [RFC 8843: BUNDLE](https://www.rfc-editor.org/rfc/rfc8843.html)
- [RFC 8872: absolute capture time](https://www.rfc-editor.org/rfc/rfc8872.html)
- [RFC 8888: RTCP congestion-control feedback](https://www.rfc-editor.org/rfc/rfc8888.html)
- [RFC 8899: datagram PLPMTUD](https://www.rfc-editor.org/rfc/rfc8899.html)
- [RFC 9147: DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html)
- [RFC 9626: video frame marking](https://www.rfc-editor.org/rfc/rfc9626.html)
- [AOM RTP Payload Format For AV1 v1.0.0](https://aomediacodec.github.io/av1-rtp-spec/)
- [Cisco libSRTP](https://github.com/cisco/libsrtp)
- [wolfSSL 5.9.2](https://github.com/wolfSSL/wolfssl/releases/tag/v5.9.2-stable)
- [Microsoft UDP socket options](https://learn.microsoft.com/windows/win32/winsock/ipproto-udp-socket-options)
- [Apple `NSEvent` documentation](https://developer.apple.com/documentation/appkit/nsevent)
- [Apple IOKit documentation](https://developer.apple.com/documentation/iokit)
- [Apple GameController `lastEventTimestamp`](https://developer.apple.com/documentation/gamecontroller/gcphysicalinputprofile/lasteventtimestamp)
- [Swift C++ interoperability status](https://www.swift.org/documentation/cxx-interop/status/)
- [Razer HyperPolling technology](https://www.razer.com/technology/razer-hyperpolling)

## 18. Post-revision protocol audit

The complete design was re-audited after the input-frequency and native-client
changes.

| Goal | Audit result | Basis |
| --- | --- | --- |
| Ground-up replacement | aligned | no old wire/state/queue compatibility; explicit deletion stage |
| One application port | aligned | DTLS, SRTP/SRTCP, control, input, feedback, and media share one UDP port |
| Lowest practical input latency | aligned by design | event-driven edges, cumulative high-rate motion, input sub-pacer, no frame callback |
| Input frequency above FPS | aligned | independent capture/network/apply clocks; 8 kHz target and 16 kHz headroom |
| Keyboard correctness | aligned | physical edges, no empty polling packets, ACK/retry, core reconciliation |
| Mouse correctness under loss | aligned | cumulative counters plus edge watermark; no lost distance |
| Controller completeness | aligned | buttons, axes, triggers, sensors, touchpad, lifecycle, and reverse feedback |
| Video tail latency | aligned by design | bounded incremental send, deadline admission, no compressed FIFO, render mailbox one |
| Throughput | aligned by design | extension-free middle packets, PMTU growth, in-place SRTP, microbatching, 100k packet gate |
| Recovery | aligned | FEC-SRTP order, immediate eligible RTX, reference repair, one recovery frame |
| Congestion safety | aligned | independent per-direction controllers plus optional shared-medium coordinator |
| Client hot-path implementation | aligned | C++23/Objective-C++ core, narrow C ABI, Swift at coarse boundaries |
| Security | conditionally aligned | standard DTLS/SRTP design; production provider proof remains mandatory |

The audit corrected these concrete defects:

- per-packet RTP extension overhead;
- a fixed two-packet pacer that could cap throughput or waste CPU;
- unbounded kernel/NIC lookahead;
- missing decoder credit and a possible hidden compressed-frame queue;
- RTX ranked below useful primary/recovery deadlines;
- unspecified FEC/SRTP ordering;
- monolithic input snapshots that could exceed MTU;
- input state lacking its dependent-edge watermark;
- input incorrectly coupled to video-direction congestion credit;
- START-only input-rate negotiation despite device hot-plug;
- controller reliable-output commands without an ACK namespace;
- ambiguous baseline/state sequence one;
- unbounded control message-ID jumps;
- text input larger than one DTLS record without chunking; and
- Swift/AppKit callbacks incorrectly treated as proof of physical polling rate.

The remaining implementation unknowns are explicit gates, not assumptions:

1. wolfSSL 5.9.2 DTLS 1.3 packaging and DTLS-SRTP exporter proof on Windows,
   plus the libSRTP wolfCrypt AES-GCM backend proof on both platforms;
2. real IOHID permissions and sustained callback distributions for named 1/8
   kHz devices, plus honest AppKit fallback behavior;
3. measured Windows virtual-HID keyboard/mouse/controller apply capacity;
4. availability and correctness of bounded incremental output from the
   selected hardware encoders;
5. measured VideoToolbox surface capacity and whether chained block buffers
   avoid the final frame copy;
6. FlexFEC CPU/latency cost at the selected packet rate; and
7. physical input-to-photon results on the named competition rig.

The portable core now freezes and tests the 40-byte input header, device and
sensor object IDs, 24-byte device prefix, 32-byte edge records, 48-byte
baseline metadata, LSPI input acknowledgements, the 28-byte versioned LSPG
envelope, H.264/HEVC/AV1/Opus packetization policy, bounded frame admission and
reassembly, RTCP parsing and AVPF serializers, FlexFEC ordering, RTX retention,
recovery epochs, congestion state, DPLPMTUD, and reconnect generation fencing.
These are dependency-independent primitives, not evidence of a live product
stream. Remaining control CBOR, device-specific state bodies, production
SRTCP APP serialization not covered by those codecs, and cross-process product
wiring still require their scheduled interoperability freeze. No current
performance or latency target is presented as already achieved.

The host product integration additionally seeds the shared recovery controller
from `VIDEO_CONFIG`, reserves one independent recovery frame before its first
RTP commit, carries the epoch with repeated frame identity, and consumes
authenticated `LSPV` decode evidence without holding session authority locks.
It does not treat decoder-surface pressure or a deadline observation alone as
an encoder-recovery command. Encoder reference invalidation is terminally
tracked by exact generation and range; one published request plus one
coalesced queued range matches the replaceable mailbox semantics and prevents
concurrent requests or stale results from silently stranding recovery. The
accepted generation follows the first repaired encoder output, so neither an
older independent-frame completion nor an older `LSPV` confirmation can
override a newer dependency break. One serialized dependency-state boundary
makes the recovery transition and reference-validity change visible together.
Dependent frames additionally reserve and revalidate that version at every
packet commit, preventing admission-time validity from becoming a stale send
authorization. A protected-but-uncommitted first packet remains a pre-submit
drop for dependency recovery even though its SRTP sequence is tombstoned.

## 19. Design-stage completion

The design stage is complete and the user has started the rewrite. Normative
wire requirements remain governed by the companion protocol specification;
implementation evidence updates this rationale without weakening those
requirements.
