# Lumen Streaming Protocol ground-up rewrite plan

Status: implementation active on branch `feature/lsp-rewrite`.

This plan replaces the retired experimental QUIC implementation with the
clean-room [Lumen Streaming Protocol](protocols/lumen-streaming-protocol.md).
The user has authorized implementation. Execution began by deleting the retired
native protocol from Lumen and Umbra and restoring a clean legacy-only baseline;
that completed cutover step supersedes the original deferred ordering in stage
13 without changing any LSP wire requirement.

## 1. Outcome

The completed rewrite will provide:

- one LSP UDP listener on Lumen;
- one raw-UDP LSP client path in Umbra;
- DTLS 1.3 authentication and DTLS-SRTP key export;
- SRTP/SRTCP video, audio, input, microphone, feedback, and repair;
- full-frame-rate competition-LAN streaming without periodic transport
  stutter;
- aggregate frame-aware pacing and congestion control;
- bounded recovery without keyframe storms;
- one application port for all LSP traffic; and
- continued absence of the retired native server, client, wire format, tests,
  documentation, and transport dependencies after cutover.

The rewrite does not patch, wrap, translate, tunnel, or progressively evolve
the old QUIC protocol. Work begins in new modules with new names and new
contracts.

## 0. Implementation status

Last updated: 2026-08-31. This table is the durable progress ledger for the
rewrite. A row moves to **Done** only after the named implementation and its
smallest decisive verification both pass. Source-only scaffolding remains
**In progress** until the real product boundary works.

| Milestone | Status | Verified evidence | Remaining boundary |
| --- | --- | --- | --- |
| Working branches and pre-rewrite checkpoint | **Done** | Both repositories use `feature/lsp-rewrite`; Lumen checkpoint `2397c28c` | None |
| Remove retired Lumen native transport | **Done** | Lumen commit `564b1131`; application link, focused legacy/migration checks, packaging check, and diff audit pass | None |
| Remove retired Umbra native transport | **Done** | Umbra commit `0362c2e`; full Swift tests, warnings-as-errors build, and packaging tests pass | Physical Moonlight smoke test remains part of final hardware validation |
| Select DTLS 1.3 provider | **Done** | Commercial wolfSSL 5.9.2 selected; tag `v5.9.2-stable` pinned | Keep license material external to the repository |
| macOS DTLS-SRTP provider proof | **Done** | Live DTLS 1.3 exchange proved `TLS_AES_128_GCM_SHA256`, X25519, HRR cookie, ALPN `lumen-stream/1`, `SRTP_AEAD_AES_128_GCM`, and identical 56-byte exporter output | Repeat the exact proof on Windows/UCRT64 |
| libSRTP wolfCrypt backend | **In progress** | The reviewed libSRTP 2.8.0 patch and CMake target are integrated; AES-128-GCM SRTP/SRTCP protection, encrypted extensions, authentication, and replay rejection pass on macOS | Repeat the provider-enabled product build and 16-byte-tag RTP/SRTCP proof on Windows/UCRT64 |
| Shared portable C++23 core | **Done** | LSPC, ACK/RTO/cache, RTP, input, media, repair, pacing, congestion, DPLPMTUD, and telemetry checks pass; aggregate digest `987605e2…3593` | Extend the canonical digest whenever shared core files intentionally change |
| Umbra `CLSPCore` C ABI and mirror | **Done** | Umbra commits `7bcbaaf`, `2779806`, and `0da9e46`; ABI v1, digest gate, real UDP/kqueue wolfSSL/libSRTP runtime, persistent LSP state, complete-Opus/timing callbacks, and provider-enabled warnings-as-errors product builds pass | Extend the ABI only at coarse input, completed-media, lifecycle, and telemetry boundaries |
| Lumen configuration, build, UI, and discovery foundation | **Done** | LSP config/UI, real runtime factory, active-only `_lumen-stream._udp`, digest gate, application/test builds, web build, and focused config/mDNS/LSP checks pass | Repeat the provider-enabled full product link on Windows/UCRT64 |
| LSP host security/session foundation | **In progress** | Real nonblocking UDP ownership, wolfSSL DTLS 1.3, libSRTP contexts, fresh LSP identity persistence, invitations, pairing/authentication, LSP-only trust, LSPC reliability, browsing, and trusted-client administration are wired | Run the first real Lumen↔Umbra authenticated pairing/browse session and repeat on Windows/UCRT64 |
| Frozen input wire/state primitives | **Done** | Ten focused tests pass across pointer/edge wire, device/sensor keys, baseline atomicity, loss/reorder, LSPI, LSPG, rates, and text barriers | Extend only when another input wire or safety invariant is implemented |
| Remaining input schemas and product integration | **In progress** | Umbra commit `2df4cd2`; native IOHID/GameController input, public touch lifecycle, authenticated retry-safe LSPG ACKs, LED, CoreHaptics rumble, adaptive triggers, and motion commands are wired; Lumen applies all negotiated input classes and sends generation-qualified controller output | Prove the real Lumen↔Umbra path with physical 1/8 kHz pointer, controller, touch, and output devices |
| Audio/video media primitives | **Done** | Fifteen focused tests verify H.264, HEVC, AV1, Opus, path limits, complete-frame admission, two-frame reassembly, decoder credits, and mailbox depth one | Extend only when another negotiated codec or frame-pipeline invariant is implemented |
| Audio/video product integration | **In progress** | Lumen negotiates ordered Opus offers, gates fresh generations on `AUDIO_CONFIG_ACK`, and sends capture→Opus→RTP/SRTP plus SRTCP sender reports; Umbra commit `0da9e46` performs native SRTP/SRTCP admission, complete-Opus ABI delivery, depth-one reorder/PLC, and real Opus→AudioQueue playout | Run the first cross-process audio session, then connect microphone and encoded video product backends |
| Bounded transport state primitives | **Done** | Thirteen focused tests verify RTCP/AVPF, RFC 8888 cadence, LSPV coalescing, FEC-before-SRTP state, recovered-packet admission, RTX bounds, recovery epochs, congestion, PMTU, and generation fencing | Extend only when another transport wire or safety invariant is implemented |
| Protected transport wire and product integration | **In progress** | Live input SRTP/SRTCP and retained LSPG/LSPI handling are wired; dependency-independent feedback, repair, pacing, congestion, and PMTU state is available | Wire RFC 8888/LSPV/FlexFEC/RTX and DPLPMTUD into live media traffic after the first audio/video slice |
| Reconnect, rekey, lifecycle, telemetry product surfaces | **In progress** | Lumen commit `b322abc3` and the current audio integration rotate connection/input/audio authority transactionally and defer old DTLS/SRTP/media retirement safely; Umbra commits `caa3446` and `c919e4b` use the same fresh-association path and restore the old input/audio path after failed planned rekey | Run a live cross-process reconnect/rekey, then extend the retained generation set as video becomes active |
| Final conformance, packaging, performance, and hardware qualification | **Pending** | None claimed | Run only after the complete live feature works |

Current functional stop point: both products contain real LSP UDP, wolfSSL,
libSRTP, control, trust, START/STOP/ATTACH, input, and matching host-audio
paths. Lumen owns capture, Opus, RTP/SRTP, SRTCP, and configuration-gated
sender lifecycle; Umbra owns native authenticated admission, bounded
reorder/PLC, decoding, and AudioQueue playout. The two compiled product paths
have not yet been exercised in one live cross-process session. Microphone and
encoded video capture/decode/render integration remain pending.

## 2. Non-negotiable boundaries

### 2.1 Not reusable

The following old-protocol components are excluded from reuse:

- retired custom record formats;
- QUIC listener and Network.framework QUIC adapters;
- QUIC DATAGRAM media framing;
- retired control request and state machines;
- retired lane schedulers and queue limits;
- retired sequence/replay namespaces;
- retired media reassembly and feedback records;
- retired input state and edge records;
- retired pairing transcripts;
- retired start/attach/stop schemas;
- retired congestion sampling and recovery behavior; and
- retired golden vectors and tests as LSP acceptance criteria.

Old tests remain only until their code is removed. No LSP implementation is
required to pass or emulate them.

### 2.2 Reusable only behind new interfaces

These transport-independent capabilities may remain:

- Lumen capture and virtual-display backends;
- color conversion and hardware encoder integrations;
- audio capture and Opus codec integrations;
- application launch/stop ownership;
- platform input injectors and controller feedback sources;
- Umbra VideoToolbox and Opus decoders;
- Umbra Metal and audio renderers;
- host/client identity persistence; and
- generic cryptographic, deterministic-CBOR, and bounded-buffer utilities that
  contain no retired native wire assumptions.

Each retained capability is called through an LSP-owned typed boundary. No
adapter may manufacture an old-protocol packet internally.

## 3. Repository layout

### 3.1 Planned Lumen modules

```text
src/protocol_lsp/
  service.{h,cpp}                 listener ownership and lifecycle
  udp_socket.{h,cpp}              IOCP/RIO/portable socket abstraction
  packet_pool.{h,cpp}             fixed packet slabs and budgets
  packet_classifier.{h,cpp}       RFC 7983 demultiplexing
  dtls_endpoint.{h,cpp}           DTLS listener and association
  srtp_context.{h,cpp}            libSRTP policy and SSRC registry
  identity.{h,cpp}                LSP pairing/auth transcript
  control_wire.{h,cpp}            LSPC parser/serializer
  control_reliability.{h,cpp}     ACK window, RTO, response cache
  control_session.{h,cpp}         LSP connection/session state
  negotiation.{h,cpp}             START and configuration selection
  rtp_packetizer.{h,cpp}          common RTP and header extensions
  video_packetizer.{h,cpp}        H.264/HEVC/AV1 RTP formats
  audio_packetizer.{h,cpp}        Opus RTP
  input_protocol.{h,cpp}          new LSP input payload and ACK state
  rtcp.{h,cpp}                     RR/SR/AVPF/APP/RFC8888 processing
  flexfec.{h,cpp}                  RFC 8627 repair integration
  rtx.{h,cpp}                      deadline-qualified RFC 4588 storage
  pacer.{h,cpp}                    aggregate priority/deadline pacer
  congestion_controller.{h,cpp}   adaptive and competition profiles
  recovery_controller.{h,cpp}     frame/reference recovery epochs
  dplpmtud.{h,cpp}                 authenticated path probes
  media_session.{h,cpp}            capture/encoder/audio integration
  telemetry.{h,cpp}                counters and timestamp stages
```

Protocol-independent helpers belong under `src/protocol_common/` only after
their APIs and tests prove they have no LSP or retired native wire semantics.

### 3.2 Planned Umbra modules

```text
Vendor/CLSPCore/
  include/                         narrow public C ABI and opaque handles
  src/*.cpp                        socket, crypto, RTP, pacing, input, reassembly
  src/apple/*.mm                   IOHID and GameController Objective-C++ adapters

Sources/UmbraLSPTransport/
  LSPTransport.swift               lifecycle/configuration facade over C ABI
  LSPControlMessages.swift         deterministic semantic CBOR only
  LSPMediaBridge.swift             complete-frame/audio native callbacks
  LSPInputCoordinator.swift        capture permission and lifecycle only
  LSPTelemetry.swift               low-rate native snapshots

Sources/UmbraLSP/
  LSPClientSession.swift           auth and connection state
  LSPPairing.swift                 invitation and pairing
  LSPNegotiation.swift             START/config schemas
  LSPSessionCoordinator.swift      product integration
```

High-rate receive, SRTP, packet-pool, socket, pacing, RTCP, FEC/RTX, video
reassembly, and input work stays in the C++ core. Swift receives completed
control frames, complete encoded video frames, complete Opus packets, and
summarized telemetry—not one callback per UDP datagram, HID poll, or controller
sensor sample.

### 3.3 Umbra language and ABI boundary

C++23 is the selected hot-path language, matching Lumen's required language
standard. Objective-C++ owns the public Apple IOHID and GameController
framework adapters. Swift remains the application/UI
language and may continue to own VideoToolbox and Metal while their measured
per-frame cost remains within budget.

Swift calls the core through a versioned C ABI containing only:

- opaque pointers;
- fixed-width integers and fixed-layout POD structures;
- pointer/length byte spans;
- explicit create/start/stop/retain/release operations; and
- C function-pointer callbacks at control, complete-frame, audio-unit, or
  telemetry frequency.

No C++ exception, STL type, template, virtual interface, coroutine, or allocator
ownership crosses the ABI. Core entry points catch internal exceptions and
return typed status. Callbacks never invoke Swift while holding packet-pool,
SRTP, pacer, or input-state locks.

Every callback payload has explicit ownership: scalars are copied, transient
views are valid only for the call, and video/audio buffers use opaque retained
handles with paired release functions. Swift cannot store an unretained native
pointer or deallocate native storage. Callback delivery is non-reentrant on a
dedicated bridge queue, and calling back into core lifecycle operations from
inside a callback is rejected or deferred.

Direct Swift/C++ interoperability is not the primary production boundary. Its
official status still has unsupported or experimental exception, move, and
virtual-method behavior, while the C ABI is stable and easy to fuzz. Rust would
be a reasonable memory-safe alternative for an independent greenfield core,
but would still require C/Objective-C FFI and a second build ecosystem beside
Lumen's C++; it is not selected for the first implementation.

Swift receives at most one video callback per completed frame and never a raw
input callback on the main actor. If later measurement identifies
VideoToolbox/Metal bridging as a bottleneck, only that measured boundary moves
to Objective-C++; the rewrite does not move UI code into C++ preemptively.

### 3.4 Dependency changes

Active implementation uses these reviewed dependency decisions:

- wolfSSL 5.9.2 with the project's commercial license, built for DTLS 1.3 on
  MinGW/MSVC Lumen and macOS Umbra;
- Cisco libSRTP 2.8.0 using a reviewed wolfCrypt AES-GCM backend so LSP DTLS
  and SRTP use the same cryptographic provider;
- H.264/HEVC RTP packetization code, implemented locally from the RFCs or
  adopted from a compatible audited source;
- the AOM AV1 RTP payload format; and
- FlexFEC implementation ownership.

Umbra and Lumen link wolfSSL only through an explicit LSP security target.
Existing OpenSSL linkage remains available to legacy product code but is not
part of the LSP handshake or SRTP protection boundary.

No SCTP, WebRTC, QUIC, or browser stack is added.

## 4. Development strategy

The rewrite uses functional vertical slices. Each slice must move real packets
between the actual Lumen and Umbra processes before broader validation begins.

The loop for every slice is:

1. reproduce the current missing behavior with the smallest live scenario;
2. implement one end-to-end path;
3. build only affected targets;
4. run the live scenario immediately;
5. inspect the one metric or trace that controls the next change;
6. add only tests that protect the confirmed behavior or safety invariant; and
7. proceed to the next slice after the live behavior works.

Broad test suites, fuzzing, soak tests, performance matrices, packaging, and
independent review occur only at their scheduled later stages.

## 5. Stage 0: dependency and API proof

### Goal

Prove that the selected standards can be implemented on both production
platforms without building product behavior.

### Work

- Select and pin one DTLS 1.3 provider.
- Prove server-side stateless cookie validation.
- Prove ALPN `lumen-stream/1` and leaf-SPKI extraction.
- Prove `use_srtp` negotiation for `SRTP_AEAD_AES_128_GCM`.
- Export client/server SRTP keys and salts.
- Protect and unprotect one RTP and one RTCP packet through libSRTP.
- Prove encrypted custom RTP header extensions.
- Measure full-duplex protect/unprotect throughput at 100,000 aggregate mixed-
  size packets/s per endpoint on the intended Windows and macOS machines.
- Confirm dependency licenses and static packaging behavior.

### Decision controlled

No LSP runtime work proceeds until the exact DTLS/library combination passes.
If the selected provider cannot meet the security or throughput boundary, the
dependency decision changes; the protocol does not downgrade to DTLS 1.2.

### Exit evidence

- a small non-product interoperability executable in each repository;
- a packet capture showing DTLS 1.3, ALPN, `use_srtp`, SRTP, and SRTCP;
- matched exporter bytes; and
- recorded packet-protection throughput.

Temporary proof executables are removed when the production security boundary
passes the same live exchange.

## 6. Stage 1: raw one-port socket foundation

### Goal

Move authenticated datagrams between Lumen and Umbra on one UDP port with a
steady-state allocation-free receive loop.

### Lumen work

- Bind the new LSP development port.
- Implement the Windows socket backend with multiple outstanding receives.
- Add fixed packet slabs and per-source admission.
- Reserve at least 64 maximum-sized slabs for input/control so video pool
  pressure cannot consume urgent receive/send capacity.
- Add RFC 7983 first-byte classification.
- Add monotonic receive timestamps.
- Add bounded send completion ownership.
- Add `32...256`-datagram batch receive with an initial size of 64.
- Build test RTP packets directly in their final slab and protect in place.

### Umbra work

- Implement a nonblocking UDP socket with kqueue readiness.
- Drain receive until `EWOULDBLOCK` on a dedicated high-QoS native worker.
- Add fixed packet slabs and monotonic kernel timestamp capture.
- Tentatively order urgent lanes from fixed headers, authenticate them first,
  then deliver only verified packet batches to native lane owners.
- Deprotect in place and retain payload slices without constructing Swift
  `Data` for each packet.

### Live proof

- client and host exchange one million numbered encrypted test RTP packets;
- no packet is delivered through Network.framework;
- no packet callback crosses the main actor;
- packet order/loss counters match a packet capture; and
- allocation instrumentation shows no per-packet heap allocation after warmup.

### Tests retained

- classifier ranges;
- pool exhaustion and recovery;
- completion-owned buffer lifetime; and
- malformed length rejection.

## 7. Stage 2: production DTLS and LSPC control

### Goal

Pair, authenticate, browse applications, and stop over the new connection.

### Work

- Implement invitation encoding and parsing.
- Add server cookie admission and DTLS association ownership.
- Implement host pin and application identity verification.
- Implement the 48-byte LSPC frame.
- Implement 64-message selective ACK windows.
- Implement RTT-derived bounded RTO.
- Implement response caching and duplicate request replay.
- Implement `CLIENT_HELLO`, pairing, authentication, application list, ping,
  and connection close.
- Implement generation and permission checks.

### Live proof

Pair a fresh Umbra installation to Lumen, reconnect using stored trust, list
real applications, and close cleanly. Repeat one intentionally dropped control
request and observe exactly one side effect with a cached response.

### Tests retained

- invitation canonical encoding;
- complete authentication transcripts;
- ACK bitmap and wrap rejection;
- forward message-ID jump beyond the 64-frame live window;
- duplicate request idempotence;
- timeout; and
- stale-generation authority rejection.

## 8. Stage 3: input-only competition slice

### Goal

Deliver real keyboard, high-polling-rate mouse, controller, controller sensor,
touchpad, touch, and pen input over SRTP before any new media path exists. Input
must remain independent of video FPS.

### Work

- Freeze pointer-motion, core-state, controller/device-state, controller-sensor,
  edge-batch, baseline-part, `LSPI`, and `LSPG` formats.
- Implement a bounded multipart atomic baseline, cumulative pointer state,
  per-device latest-state records, separate controller sensor streams, and
  repeated-until-ACK edge batches.
- Prove every steady-state input packet fits the 1,200-byte safe path and that
  the 32 KiB maximum baseline completes in at most 32 parts.
- Add the C++ input composer and dedicated input sub-pacer with no video-frame
  callback dependency.
- Add public IOHID input-value/timestamped-report capture on a native queue and
  preserve OS-absolute hardware timestamps.
- Add focused AppKit fallback that disables and later restores mouse coalescing,
  and never overstates its measured event frequency.
- Terminate GameController change/motion callbacks in Objective-C++ using
  `lastEventTimestamp`; do not poll controllers from render callbacks.
- Negotiate pointer up to 16 kHz, controller state up to 2 kHz, controller
  sensors up to 4 kHz, and reconciliation up to 1 kHz independently.
- Implement generation-scoped `INPUT_RATE_REQUEST/RESPONSE` for hot-plugged
  devices and aggregate-budget reallocation without dropping immediate edges.
- Allocate client input and host feedback SSRCs.
- Implement `LSPI` acknowledgements and resynchronization.
- Bind platform input neutralization to DTLS authority.
- Implement controller arrival/removal generations, button/touch lifecycle
  edges, sticks/triggers, gyro/accelerometer, touch coordinates, battery, and
  generation-matched `LSPG` rumble/LED/adaptive-trigger feedback.
- Add highest-priority pacer class.

### Live proof

Use Umbra to control a real application on Lumen. Verify keyboard press/release,
relative/absolute pointer, wheel, controller arrival/removal, buttons, sticks,
triggers, gyro, accelerometer, controller touchpad, rumble, LED,
adaptive-trigger feedback, disconnect neutralization, and reconnect baseline.

Run a real 1 kHz and 8 kHz mouse, plus a synthetic 16 kHz source. Repeat at
60, 120, and 240 video FPS settings even though video is not yet transported;
the selected input rate and capture-to-send distribution must not change with
the configured frame rate. Record raw-callback, composed-report, and host-apply
rates independently.

Measure client sample to host apply directly. Do not run media or broad suites
at this stage.

### Tests retained

- exact state/edge vectors;
- pointer cumulative motion survives loss and coalescing without distance loss;
- edge watermark prevents state application ahead of required physical edges;
- baseline sequence one, first replaceable sequence two, and no wrap/reuse;
- 1/8/16 kHz rate selection and input-wire-budget arithmetic;
- device hot-plug safe-rate operation and authenticated rate transition;
- input rate remains unchanged across 60/120/240 FPS configuration;
- baseline part loss, reorder, digest, atomic commit, and retransmission;
- coalescing only within one pointer/core/controller/sensor/device
  supersession key;
- duplicate and reordered edges;
- edge retry timing and exactly-once application;
- controller instance generation across removal/rebind and every feedback type;
- `LSPG` latest-state supersession plus acknowledged command retry/ACK/stale
  behavior;
- GameController timestamp and sensor supersession behavior;
- AppKit coalescing restoration and raw-HID fallback selection;
- focus/permission-loss release ordering, callback quiescence, and absence of
  raw input values from logs;
- inline/chunked `TEXT_INPUT` obeys its edge barrier without blocking later
  real-time input;
- ACK-window pressure;
- release-on-disconnect; and
- stale controller feedback.

## 9. Stage 4: audio-only slice

### Goal

Stream real host audio as SRTP Opus over the same socket without input jitter.

### Work

- Negotiate Opus SSRC, payload type, channels, mapping, and frame duration.
- Packetize RFC 7587 Opus.
- Produce SRTCP sender/receiver reports.
- Implement one-packet initial jitter buffer and bounded adaptation.
- Preserve continuous audio device lifetime.
- Add audio scheduler reserve.

### Live proof

Play real game audio for ten minutes at 5 ms packetization while generating
high-rate mouse/controller input. Verify no input regression, audio rebuffer,
or periodic device restart.

### Tests retained

- Opus RTP vectors;
- timestamp/sample continuity;
- one-packet loss concealment;
- discontinuity; and
- audio reserve under synthetic video queue pressure.

## 10. Stage 5: first working video slice

### Goal

Display a stable real Lumen capture in Umbra at the requested refresh rate
before adding adaptive repair or broad validation.

### Initial scope

- one codec selected by the actual target hardware, preferably HEVC Main or
  H.264 High;
- SDR 8-bit 4:2:0;
- fixed operator-safe bitrate;
- 1,200-byte UDP payload;
- no FlexFEC;
- no RTX;
- no automatic resolution change; and
- one direct wired LAN.

### Lumen work

- Create a new capture/encoder session boundary.
- Packetize the selected codec using its RTP RFC.
- Add RTP timestamps, frame ID, frame marking, capture time, input watermark,
  and encoder timing.
- Put frame/timing extensions only on the first two and final packets; keep
  ordinary middle packets extension-free and full-sized.
- Add complete-frame admission.
- Add the aggregate, rate-derived 100-microsecond microbatch pacer with a hard
  one-to-eight-datagram bound.
- Never request IDR from local queue admission.

### Umbra work

- Authenticate/decrypt SRTP in native packet slabs.
- Reassemble at most two frames by SSRC/timestamp/frame ID.
- Negotiate two-to-four hardware decoder submissions, expose live credit, and
  add no compressed-frame software queue.
- Submit a completed encoded frame directly to VideoToolbox.
- Use a render mailbox of one.
- Keep all packet events off Swift serial manager queues and the main actor.

### Live proof

Stream a moving game scene for five minutes at 60, then 120, then the target
competition refresh. Verify requested capture rate, encoded frame rate,
received complete-frame rate, decode rate, and presented rate are equal within
explicit startup/teardown exclusions.

The first optimization loop uses only four timestamps:

- host capture;
- host first packet submission;
- client kernel receive; and
- client Metal commit.

No FEC, fuzzing, long soak, or full test suite runs until this slice works.

### Tests retained

- selected codec packetization vectors;
- same-frame small-unit aggregation without cross-frame or wait-for-fill
  behavior;
- first/last/marker consistency;
- path-size boundary;
- complete-frame admission; and
- zero-copy buffer lifetime through decoder submission.

## 11. Stage 6: frame-rate and throughput remediation

### Goal

Reach stable full frame rate and remove every periodic hitch on the clean wired
path.

### Profiling order

1. capture cadence;
2. encoder completion cadence;
3. pacer queue age and completion cadence;
4. socket receive batch and drop counters;
5. SRTP authenticate/decrypt CPU;
6. frame reassembly completion cadence;
7. VideoToolbox capacity and callback cadence; and
8. Metal commit cadence.

Only the first stage that diverges from requested cadence is optimized. Later
stages are not tuned speculatively.

### Likely implementation work

- Windows UDP segmentation/coalescing where it preserves pacing semantics;
- packet-batch receive and protect/unprotect;
- adaptive microbatch pacing and same-quantum UDP segmentation where public;
- a hard two-quantum/200-microsecond kernel submission horizon with public
  transmit-timestamp evidence where available;
- slab ownership through codec reassembly;
- scatter/gather packetization;
- extension-free middle video packets;
- reducing cross-thread hops;
- encoder output buffer adoption;
- bounded-incremental slice/tile/OBU delivery that reserves the encoder's
  declared maximum access-unit bytes before first-packet submission;
- high-resolution pacer timers; and
- cache-aligned lane queues plus thread-owned, cache-line-separated counters.

### Live exit gate

- stable 1080p240 on the named competition machine and display;
- no repeating hitch over 30 minutes;
- no packet-path heap allocation after warmup;
- no more than one decoder-required frame coalescing copy and no payload copy
  per packet beyond construction in the final transmit slab;
- no packet processing on UI/main actor;
- pacer submission error and urgent receive-batch delay within their 100-
  microsecond p99 targets;
- no more than 200 microseconds of video credit submitted ahead into the
  kernel/NIC;
- no sender-queue-triggered IDR; and
- p99 inter-present gap within the specification target.

## 12. Stage 7: congestion controller

### Goal

Keep the working video slice low-latency when capacity changes without turning
the controller into a generic buffering layer.

### Work

- Implement RFC 8888 feedback generation and parsing.
- Add reduced-size SRTCP timing.
- Implement delivered-byte, RTT, delay-trend, loss, and ECN estimation.
- Implement adaptive-low-latency controller.
- Implement explicit competition-LAN profile and circuit breaker.
- Connect available media credit to encoder bitrate at frame boundaries.
- Feed the client's freshness-bounded decoder credit and completion rate into
  host complete-frame admission.
- Account for audio, input, DTLS, RTCP, FEC, and RTX overhead.
- Add frame admission based on complete-frame serialization estimate.

### Live proof

Change a controlled shaper below and above the selected video rate. Verify the
encoder/pacer converge without growing queue age, blocking input/audio, or
creating repeated keyframes.

### Tests retained

- feedback wire vectors;
- deterministic controller traces for step-up, step-down, ECN, loss, and RTT
  variation;
- complete-frame admission arithmetic; and
- minimum-stream termination.

## 13. Stage 8: repair and recovery

### Goal

Recover real loss without a full-IDR feedback loop.

### Work order

1. frame-loss reporting and one recovery epoch;
2. encoder reference invalidation/intra refresh;
3. one outstanding independent recovery frame;
4. FlexFEC single-stream repair using incremental plaintext parity followed by
   in-place source/repair SRTP protection;
5. immediate gap-triggered, deadline-qualified RTX with at most 100
   microseconds of competition-path reorder delay; and
6. adaptive repair ratio.

### Live proof

Inject one packet loss, short burst loss, reordering, and a capacity drop
separately. For every scenario record whether recovery used FEC, RTX, reference
repair, or IDR. Confirm that a recovery epoch creates at most one outstanding
independent frame and that queue age returns to baseline.

### Tests retained

- FlexFEC vectors and source association;
- RFC 3711 FEC-SRTP ordering, authenticated recovered-packet admission, and
  late-original replay suppression;
- FEC recovery suppresses duplicate RTX without waiting beyond the reorder
  deadline;
- RTX deadline eligibility;
- two-generation/16 MiB RTX retention expiry without steady-state copies;
- recovery-epoch idempotence;
- reference-loss transition; and
- decode-confirmed recovery exit.

## 14. Stage 9: remaining media and display modes

After the primary competition slice works:

- add the remaining H.264/HEVC codec profile;
- add AV1 AOM RTP payload support;
- add HDR10/HLG and 10-bit formats;
- add 4:4:4 where hardware proves it;
- add microphone SRTP Opus;
- add 2.5 ms Opus only if measured device latency improves;
- add rational refresh values and variable-refresh presentation;
- add adaptive resolution only when explicitly offered; and
- add DPLPMTUD growth beyond 1,200 bytes.

Each is a separate real vertical slice with its own direct scenario and
regression tests.

## 15. Stage 10: reconnect, rekey, and lifecycle

### Goal

Make authority loss safe without compromising the data plane.

### Work

- Hold a disconnected process/capture session for a bounded attach grace.
- Neutralize input immediately on association loss.
- Complete fresh DTLS and SRTP contexts before `ATTACH` authority transfer.
- Advance every connection-scoped SSRC and generation.
- Implement planned rekey through fresh association/attach.
- Make stop, host stop, app exit, sleep, and display loss deterministic.
- Ensure no old packet buffer retains a destroyed SRTP or decoder context.

### Live proof

Disconnect the client NIC, reconnect, attach, restore input baseline, continue
media, then stop. Repeat during a pressed key, active controller rumble, video
recovery, and microphone capture.

## 16. Stage 11: conformance and hostile validation

Only after the full real feature works:

- freeze every deterministic CBOR schema;
- generate independent positive and hostile wire vectors;
- add parser fuzzing for LSPC, input, RTCP APP, and custom RTP extensions;
- add authentication, replay, generation, and resource-bound adversarial tests;
- validate DTLS cookie amplification bounds;
- validate SRTP sequence rollover and replay windows;
- run packet captures for every codec/repair mode; and
- run targeted static analysis on the native packet boundary.

Temporary fuzz harnesses do not ship. Retained tests protect concrete wire or
security contracts.

## 17. Stage 12: performance qualification

The named hardware matrix records:

- host CPU/GPU, driver, encoder, capture backend, and link;
- client Mac, OS, decoder, display refresh, and link;
- input device model, advertised polling rate, capture API, observed physical
  callback rate, selected network rate, and host apply backend/rate;
- codec, resolution, exact refresh, bitrate, MTU, FEC, and network profile;
- capture, encode, send, receive, decode, render, and presentation-proxy
  percentiles;
- packet rate, batch size, copies, allocations, queue depth/age, loss, repair,
  decoder credit, congestion-feedback overhead, and IDR counts; and
- per-device input callback/compose/protect/send/receive/apply percentiles,
  coalesced physical reports, edge retries, controller feedback, and audio
  behavior.

Required scenarios are:

- clean direct wired path;
- managed switch path;
- controlled capacity below the configured rate;
- isolated loss;
- burst loss;
- reordering;
- ECN marking;
- path-MTU reduction;
- host GPU saturation; and
- client decoder/render saturation.

Physical input-to-photon testing uses an optical rig after software-stage
qualification.

## 18. Stage 13: final cutover audit

The retired native protocol was deleted before LSP product integration. This
final stage therefore verifies the deletion and completes the product cutover
rather than postponing removal until after LSP qualification.

### Entry criteria

- all required LSP product features work on real Lumen/Umbra;
- competition acceptance targets pass;
- security and conformance gates pass;
- packaging includes the reviewed dependencies; and
- legacy Moonlight behavior remains independently functional.

### Final cutover

- make LSP the only native Lumen/Umbra protocol;
- keep legacy GameStream only for explicit Moonlight compatibility;
- remove any old-protocol selection from Umbra UI and persistence;
- remove old discovery advertisements;
- remove old configuration toggles and packaging dependencies; and
- update user documentation to describe LSP as implemented.

### Completed Lumen deletion set

At minimum, remove:

The completed removal covered the retired protocol source tree, Windows
transport shim, protocol document and vectors, runtime wiring, dependency
discovery and packaging, and all dedicated tests and fixtures.

Exact deletion is confirmed with repository search at cutover. No compatibility
shim remains under a renamed file.

### Completed Umbra deletion set

At minimum, remove:

The completed removal covered Umbra's retired transport and protocol targets,
integration managers, dedicated tests and fixtures, preference state,
Network.framework transport imports, and package products.

Transport-independent media components remain only after their imports and
types no longer reference the retired protocol.

## 19. Build and verification commands

Commands are selected when implementation begins and follow repository
platform rules.

On Windows, every command runs through:

```text
C:\msys64\msys2_shell.cmd -defterm -here -no-start -ucrt64 -c
```

Build directories begin with `cmake-build-`. Lumen's gtest executable is
`tests/test_sunshine` inside the selected build directory.

During development, use the smallest affected build and test target. Full
Lumen tests, full Umbra tests, warnings-as-errors, formatting, documentation,
and packaging run only after the working feature reaches its scheduled gate.

All new C/C++ public and private methods, structures, enums, and fields receive
the required Doxygen documentation and conform to `.clang-format`.

## 20. Documentation lifecycle

During implementation:

- the architecture rationale remains the decision record;
- the LSP specification is normative and records frozen portable wire/state
  primitives without presenting them as live product behavior;
- this plan and its status table remain the execution source of truth; and
- retired transport documentation remains deleted.

A primitive milestone moves to **Done** after its exact implementation and
focused verification pass. Product integration remains **In progress** until
real authenticated cross-process traffic proves the corresponding boundary.
Only after the complete feature works may the user documentation describe LSP
streaming as available.

## 21. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| DTLS 1.3 provider is immature | Resolve in Stage 0 before product integration |
| libSRTP/DTLS copies dominate | Benchmark native boundary and preserve packet-slab ownership |
| Swift reintroduces per-packet dispatch | Native receiver emits complete frames/packets, not datagram callbacks |
| Swift/AppKit collapses high polling rates | Preferred IOHID/Objective-C++ capture; disable measured fallback coalescing |
| Direct Swift/C++ interop changes or copies values | Versioned C ABI with opaque handles and explicit ownership |
| Native C++ parser/lifetime bug | Checked spans/integer arithmetic, RAII, ASan/UBSan, fuzzing, opaque retained handles |
| Input is accidentally tied to FPS | Separate device/report/apply clocks and cross-FPS regression gate |
| Controller analog/sensor traffic hides edges | Separate latest-state/sensor streams from acknowledged lifecycle/button edges |
| Raw UDP creates burst loss | One aggregate byte pacer, rate-derived 100-microsecond microbatches, DPLPMTUD |
| Fixed two-packet pacing caps throughput or burns CPU | One-to-eight-packet microbatch derived from earned byte credit |
| RTP extensions waste payload and crypto | Put metadata on frame boundaries; keep middle packets extension-free |
| Hidden decoder queue recreates latency | Negotiate two-to-four hardware credits and forbid a compressed software queue |
| Congestion controller starves video or audio | Explicit class reserves and overhead accounting |
| Frame drop corrupts reference chain | Complete-frame admission plus encoder reference controller |
| FEC adds latency/overhead | Small frame-local groups, zero clean-path ratio, never wait past deadline |
| RTX arrives late | Receiver and sender both enforce deadline eligibility |
| Recovery produces keyframe storm | One recovery epoch and one outstanding independent frame |
| One port complicates demux | RFC 7983 ranges plus authenticated SSRC registry |
| Old protocol contaminates design | New modules, no compatibility adapters, explicit final deletion set |
| Tests replace real verification | Functional vertical slice required before later validation gates |

## 22. Current implementation boundary

The retired protocol deletion and dependency-independent portable foundations
are complete. Security integration remains gated by Stage 0:

1. prove the pinned wolfSSL 5.9.2 DTLS 1.3 provider on both platforms;
2. prove DTLS-SRTP exporter interoperability on Windows and macOS;
3. prove AES-GCM SRTP/SRTCP through libSRTP; and
4. record throughput and packaging evidence.

No product path may claim authenticated LSP operation until that proof passes.

## 23. Implementation start

The user resumed implementation. The rewrite proceeds through the functional
stages above, with the DTLS/SRTP security boundary remaining fail-closed until
the complete Stage 0 proof passes on both production platforms.
