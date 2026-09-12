# Lumen Streaming Protocol ground-up rewrite plan

Status: implementation active on branch `feature/lsp-rewrite`.

### Current delivery scope — user update, 2026-09-12

Deliver fully working Lumen and Umbra builds for actual game streaming using
LSP end to end. The user has cancelled the Svelte/SvelteKit administration
rewrite: preserve the existing administration interface, and do not treat a
frontend redesign as a remaining deliverable. Legacy Moonlight compatibility
remains independent and must not be used to claim the native LSP path works.
Finish real input, audio/microphone, video, pacing/repair and reconnect wiring;
verify them together on the Windows host and macOS client, then package and
hand off the usable builds. Keep supported-hardware limits explicit.
This newer scope supersedes frontend requirements in the original goal prompt.

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

Last updated: 2026-09-12. This table is the durable progress ledger for the
rewrite. A row moves to **Done** only after the named implementation and its
smallest decisive verification both pass. Source-only scaffolding remains
**In progress** until the real product boundary works.

### Resumption checkpoint — 2026-09-11

The user reports Moonlight/Sunshine is working normally and has resumed LSP
development after the pause. Preserve the working Windows installation. A
read-only check finds `LumenService` running, `lsp_enabled = false`,
`lumen_vdd_policy = disabled`, `system_tray = false`, and
`nvenc_twopass = disabled`. Its installed executable SHA-256 is
`BA967E9D02AC29ED09DDF7897725779658F7B78D83BA371907CBA4646B6E2855`,
which differs from the development artifact last deployed in this thread.
The running host must not be overwritten based on the older deployment record.

- [x] Recover the existing feature branches and source-identical Photon pin
  `657833c8fa0cc96f75e248696716d51226ae55f3` in both products.
- [x] Record the prior live discovery, DTLS, PIN pairing, and authenticated
  application-list success as historical evidence, not a current live session.
- [x] Resolve the first live START rejection (`malformed`) at the client/host
  boundary; see the verified September 12 admission fixes below.
  Reconstructing the last live offer with the current Umbra serializer yields
  a 414-byte request that the current Lumen decoder accepts (five audio and
  five video offers). The staged Windows control codec is source-identical.
  This narrows the next live investigation but does not prove streaming works.
- [x] Correct the discovered APPLICATIONS mismatch: Lumen emits six fields per
  entry while Umbra still expected three. A vector emitted by Lumen reproduced
  Umbra's `malformed` rejection. The client now retains authoritative
  running/resume/generation fields and publishes running state in the product
  catalog. The independent Lumen-encoded vector and inconsistent-state rejection
  regressions both pass in the warnings-as-errors app/test build (2026-09-12).
- [x] Create an isolated Windows test instance with its own executable, state,
  credentials, and legacy ports, leaving the installed Lumen process untouched.
  Fresh six-digit PIN pairing to that instance succeeded and persisted client
  trust. This does not establish current application browsing or streaming.
- [x] Fix the host's reentrant DTLS timer double-erase: remove the due timer
  before entering provider callbacks that can also remove it. The affected
  Windows target was rebuilt and deployed only to the isolated instance;
  it remained alive beyond the original crash interval and completed pairing.
  Sustained host stability is not yet qualified.
- [x] Fix Umbra's incorrect authentication on DTLS retransmission success
  (Umbra `9ab268a`).
  A real silent-loopback-peer regression reproduced `dtlsFailure` after the
  first timer, then passed after the fix: at least two ClientHello datagrams,
  no authentication failure, and the configured two-second timeout. The
  warnings-as-errors Swift compile and affected native/app link pass, with
  existing Homebrew dylib deployment-target linker warnings still present.
- [x] Preserve terminal UDP-send failures as socket errors rather than DTLS
  policy failures. A local-client debugger injection of the observed
  `EHOSTUNREACH` send result now produces the socket-specific error message.
  Removed the temporary catalog payload print and the completed local PIN log.
- [x] Resume authenticated catalog/START diagnosis against the isolated host
  after the user's gaming session. At 2026-09-12 01:00 local time, its task
  is stopped (`LastTaskResult = 0xC000013A`) and UDP 48030 has no listener.
  Do not restart it while the user plays: startup can probe capture/encoders.
  Installed `LumenService` remains running at PID 10964 with VDD disabled;
  no production process, configuration, or binary was modified in this turn.
  The user confirmed Local Network access is enabled. The latest ordinary
  Umbra request sends successfully and times out against the stopped host;
  the earlier intermittent `EHOSTUNREACH` cause remains unproven.
- [ ] Qualify streaming and lifecycle on Windows/macOS while preserving the
  working Moonlight service; keep VDD disabled unless explicitly re-enabled.
- [ ] Complete streaming-readiness fixes, qualification, packaging, and final gates.

### Current live debugging — 2026-09-12

The user resumed testing after gaming. Only the isolated scheduled task is
restarted/deployed; installed `LumenService` remains PID 10964, with VDD disabled.

- [x] Fix the **actual** catalog handler. `HostControlServer::list_applications`
  bypassed `encode_applications` and manually emitted three fields. It now uses
  the canonical six-field encoder. The signed macOS client authenticated and
  printed Desktop over both IPv4 and IPv6. An initial stale-object hypothesis
  was disproven by rebuilding; the duplicate handler was the cause.
- [x] Cap START's receiver-advertised capacity to the active family's ceiling,
  as required by section 12.3. Advertising 1,472 bytes on IPv6 previously caused
  an immediate `malformed` rejection. With a 1,452-byte selected ceiling, the
  same live request reached H.264 encoder creation and codec prewarm (249 ms).
- [x] Finish the initial START admission path: the client's request retry window expired
  during synchronous capture preparation. START is now retained in one bounded
  per-connection slot, receipt-ACKed, and dispatched from the next control tick
  after the DTLS output queue is flushed. SRTP overhead is queried only after
  installing exact SSRC contexts, and adaptive pacing accounts audio/control
  above the offered encoded-video ceiling. The signed client then completed
  START, applied the input baseline, and received real 720p60 H.264 frames.
  This does not establish sustained stability.
- [ ] Complete visible CLI streaming. The old CLI path decoded into a headless
  renderer. The new command-to-app handoff uses the existing stream window,
  VideoToolbox/Metal, input capture, and CLI owner IPC. The integrated product
  build and two focused handoff regressions pass (Umbra `7d62171`). The live
  window reached a renderer commit and was revealed. Sustained presentation
  and user-visible picture/input confirmation remain unqualified. The owner
  IPC reply-order regression passes, including half-close before app exit.
- [x] Fix the observed native final-release crash during that handoff:
  `LSPTransport.deinit -> clsp_core_release -> Runtime` teardown emits lifecycle
  callbacks during deletion. The 2026-09-12 02:26 crash report records a second
  runtime destruction reaching `Runtime::Impl::stop` with an invalid pointer.
  Umbra `38fe90a` prevents finalizing-core resurrection, defers callback-held
  final deletion off the worker, and explicitly stops at Swift teardown. The
  same signed command-to-window handoff subsequently completed without a crash.
- [ ] Qualify connection stability using a consistently signed app identity.
  The raw development executable intermittently emitted no packets on en7;
  a signed app bundle subsequently completed authenticated catalogs over both
  families. No permission reset, network reconfiguration, or trust change was
  used. The test host's temporary IPv4 address override was restored to IPv6.
  The signed diagnostic app uses existing local static legacy crypto/Opus
  libraries; their macOS deployment-target warnings remain unresolved release
  packaging issues. The package guard falsely classified wolfSSL's own
  `SSL_CtxResourceFree` finalizer as a dormant libssl facade. A narrowly scoped
  exception, verified against pinned wolfSSL source, lets that signed package
  pass its existing resource/dependency/signature validation; this is not full
  release qualification (Umbra `6ede894`).
- [x] Fix the identified repeated termination causes. The first admitted stream sent more
  than 300 frames, then client receive counters plateaued at 5,047 datagrams;
  authentication failures remained zero. NVENC reported unsupported reference
  invalidation, and the host later tore down media without the client declaring
  termination. Local STOP eventually returned an unconfirmed transport timeout
  and exited. A later start ended immediately. The client also rejects valid
  high-bit unsigned frame IDs at the signed media-token boundary; that concrete
  conversion bug is now fixed using a lossless bit-pattern bridge, with the
  full-width boundary regression passing and a real negative media-token frame
  reaching the renderer. LSP no longer implicitly enables cyclic intra-refresh
  from the independent RFI capability; subsequent runs report no NVENC RFI
  rejection. The repeatable approximately 135-second shutdown was a separate
  host bug: established DTLS associations continued exhausting handshake timer
  backoff. Established associations now expose no handshake timer and ignore a
  stale timer callback. The existing product DTLS integration test passes after
  ten such callbacks and a subsequent real application-record exchange (8 ms).
- [x] Run a 720p60-configured H.264 session beyond the prior timeout: the
  2026-09-12 03:07 run remained active beyond four minutes, sent over 5,700 video
  frames, and delivered a late test tone as 118 Opus/SRTP packets with no reported
  audio loss/expiry or authentication failures. These are static-desktop results,
  not proof of 60 unique frames/s or the higher-refresh performance targets.
  Normal CLI STOP and app exit both returned success, and a fresh START worked.
- [x] Recover from an actual silent peer: the isolated host process was suspended
  for four seconds and resumed automatically, without touching installed Lumen.
  Umbra's new three-report-interval authenticated-activity watchdog triggered
  fresh-DTLS ATTACH. The host reports one committed/completed reconnect, zero
  failures, new audio/video generation 2, and resumed video; commit-to-ready took
  77.7 ms (excluding outage detection and DTLS). The temporary firewall trial
  did not establish a confirmed interruption and is not counted as evidence.
- [ ] Obtain human confirmation of picture, mouse/keyboard, and audible playback.
  The user prohibited Computer Use; no UI automation was used. Host input
  baseline application is verified, but physical input and optical latency are
  not. Audio packet delivery is confirmed, not independently heard by the agent.

The immediate baseline now starts, renders through the native media boundary,
delivers audio, stops, restarts, and recovers from peer silence. Full codec/input/
performance qualification remain unfinished. The later admin rewrite was cancelled by the user.

Handoff: normal STOP also succeeded after the forced-outage reconnect, and the
isolated test task was stopped to release host resources. The installed service
was never restarted or replaced (PID 10964). The latest frame-ID, watchdog,
NVENC-setting, and established-DTLS-timer fixes are built and live-verified but
their final commits await 1Password SSH-signing authorization. Failed/pending
signing attempts were cancelled; preserve the staged/dirty changes and retry
signed commits after the user unlocks 1Password. Earlier checkpoints are Lumen
`1c172777` and Umbra `38fe90a`, `7d62171`, `6ede894`.

### Live continuation — September 12, from 03:15

Only the isolated Windows instance is used. Installed Lumen remains PID 10964;
its last observed Moonlight disconnect is 01:54:24, and VDD remains disabled.

- [x] Expose real bounded-window media timings through the existing CLI owner
  IPC, and host frame/pressure/feedback counters through authenticated status.
  The focused same-user IPC regression passes. Sample counts are not lifetime
  frame totals; render enqueue and Metal commit are not physical presentation.
- [x] Correct Darwin receive timestamps and media clock comparisons. Kernel
  `SCM_TIMESTAMP_MONOTONIC` values are raw Mach ticks, scaled by the cached
  timebase; native expiry and Swift media timing use `CLOCK_UPTIME_RAW`.
  The observed M4 timebase is 125/3, and mixing sleep-inclusive monotonic time
  with uptime previously introduced approximately 111.74 seconds of skew.
  The existing silent-peer regression passes with the corrected clock domain.
- [x] Remove Windows short-wait timer quantization from the LSP forward pacer.
  A requested 100 microseconds actually woke at p50 567.4 / p99 688.4
  microseconds. Active waits now release the scheduler lock and use a bounded
  at-most-50-microsecond CPU pause; empty queues still block normally.
  The isolated Windows build succeeds, and HEVC subsequently completes admitted
  frames without the prior hundreds/thousands of pressure drops. Legacy pacing
  is unchanged; sustained full-rate CPU/latency qualification remains pending.
- [x] Keep the shared renderer active when an LSP predecessor decoder retires.
  Decoder-only cleanup drains callbacks without flushing the successor's
  renderer; normal final stop flushes once. The focused renderer-preservation
  test passes, and real HEVC Metal commits resume after ATTACH.
- [x] Fix receive-ceiling publication when protected LSPP arrives before its
  control-intent callback. Both authenticated match orders now publish the
  proved receive size before acknowledgement. Previously the host advanced to
  1,452-byte packets while Umbra still discarded packets over 1,200, causing
  authenticated-peer silence and an unsolicited startup reconnect.
  The subsequent HEVC 1080p120-configured run remains generation 1, receives
  59,776 datagrams with zero authentication failures and no additional ATTACH
  attempts, and stops normally. An intermediate host snapshot records 1,354
  sent frames, two pressure drops, zero reported video loss, and no rejected
  congestion feedback. Recent receive-to-Metal-enqueue p99 is 1,566 microseconds;
  enqueue-to-commit p99 is 3,855 microseconds, so the final latency target is
  not claimed. Static desktop delivery does not prove 120 unique frames/s.
- [x] Move AppKit fallback samples from Swift into Objective-C++ and rebuild
  the signed client. Keyboard/modifier/button/scroll handling, coalescing
  restoration, and GameController capture now feed the native owner directly.
  The coarse Swift lifecycle binds input to the exact stream window and stops
  on application deactivation, key-window loss, or window close; the native
  AppKit monitor also rejects events from other windows. Physical focus-loss,
  modifier, pointer, and controller behavior remains unconfirmed.
- [x] Exercise AV1 720p60-configured decoding/Metal delivery on Apple M4 Max
  against RTX 4060 Laptop NVENC. Thousands of static-desktop frames and a test
  tone are delivered with zero authentication failures. This is functional
  codec evidence, not FEC/RTX, unique-frame-rate, or sustained-load qualification.
- [x] Fix required-microphone startup disconnects. First resolve the independent
  test configuration requirements: temporarily grant the microphone bit on the
  sole isolated test pairing and enable its `client_microphone` setting. The
  installed service and its audio settings remain unchanged. The live failure
  then reproduces every three seconds: a bare client microphone RTCP SR lacks
  the compound SDES CNAME and makes Lumen close that association before encoder
  creation. Appending SDES with the same established association CNAME fixes
  the exact retry: generation 1 remains active with 489 microphone packets
  accepted, zero rejected, 449 congestion reports, ten receiver reports, and
  307 video frames. The host-side diagnosis independently confirms the chain.
  This proves the authenticated reverse path, not audible application capture.
- [x] Replace opaque numeric `LSPControlStatus` errors with concise descriptions
  of all eleven stable status values, including a client-permission remedy.
  The existing session test's focused localized-status regression passes;
  the updated signed client also builds. No automatic retry or fallback added.
- [x] Verify clocked microphone decode/platform-sink health through real
  administration snapshots. The affected Windows build and private deployment
  pass; artifact SHA-256 is
  `C197B60B5562D026D8B3C3F8D713915360136F796774DFC25D14E11AAF94B0B0`.
  A fresh required-microphone run records 817 accepted packets, 813 ordinary
  decoded PCM frames, active playout, and zero decode errors, sink errors,
  concealment, or silence frames. It simultaneously sends 517 HEVC frames with
  zero admission drops/pressure and zero reconnects. This proves delivery to
  the Windows virtual sink's write boundary, not another application's capture
  or audible playback. Normal STOP succeeds.
- [x] Implement and live-prove clean native microphone reverse-feedback consumption: the prior run's
  746 client dropped datagrams correlate with 747 host microphone CCFB reports.
  The client previously dispatched SR and APP only, rejecting RR/CCFB. It now
  validates compound RR/CNAME, correlates real SR/RR RTT and bounded successful
  sends, applies overlap/CE-safe CCFB accounting to the Photon controller, and
  adjusts native microphone/reverse credit without consuming the input reserve.
  IPv4/IPv6 complete-IP accounting and compound video/audio SR timing are wired.
  Integration caught and corrected an invalid comparison of stream generation
  with independent connection generation. The warnings-as-errors client build
  passes; the signed live retry reports one client drop while the host emits
  751 CCFB packets, with 822 microphone packets accepted, 817 decoded frames,
  zero decode/sink/PLC errors, active HEVC, and no spontaneous reconnect.
  Impairment adaptation, missing-feedback lifetime, and input-only CCFB remain
  unqualified/unfinished; clean receipt is not a congestion qualification claim.
- [x] Fix required-microphone reconnect writer transfer and first-attempt recovery.
  The initial real four-second
  isolated-host suspension resumes the Windows process, but ATTACH fails its
  required microphone activation: generation 1 still owns the platform writer
  when generation 2 attempts to claim it. The bounded fix stops old PCM writes
  and releases that exact writer before replacement construction, keeping old
  feedback callbacks and worker storage alive for deferred retirement. This is
  built in Windows artifact
  `2174474C8713E4A17ED3A698AF8D891EECA128DA5D106C6396226E3B765FE34C`.
  The outage retry advances microphone generations with decoded PCM and no
  sink errors, proving writer transfer, but still fails overall: synchronous
  old-device stop/new-device start delays the microphone control response ACK
  and causes rapid control-timeout reconnects. Defer that bounded activation
  until after its validated receipt ACK is flushed, then repeat the same outage.
  A focused predecessor-stop/deferred-destruction ownership regression is added
  to the existing host foundation tests. Its affected objects compile and the
  single filtered test passes in 4 ms. The older cached coverage files emit
  merge warnings; no coverage percentage is claimed or extra coverage run made.
  The control ACK deferral is now built/deployed in artifact
  `80CA5FF92200712DF12E5A2A209682646D1F4557D7F9DBAC803A83919E703668`:
  exact validated receipt is cached/ACKed before one original-deadline-bounded
  microphone activation runs from the next tick. Repeating the outage with the
  prior client stops the tight control-timeout loop and restores real video and
  microphone PCM, but takes two ATTACH attempts (one failed readiness, one
  successful). This does not establish one-attempt or latency-qualified recovery.
  The combined-client retry also recovers through two attempts: the successful
  generation 3 records 1,320 accepted microphone packets, 1,317 decoded frames,
  zero decode/sink/PLC errors, and 839 sent HEVC frames. Client counters reach
  46,365 received datagrams, one drop, zero authentication failures, and live
  decode/Metal commits before successful STOP. The first post-outage attempt
  still failed at that checkpoint; the background-join fix in the 05:00
  continuation below subsequently proves single-attempt recovery.
  The proposed large control-test fixture was removed; do not recreate that
  harness. This control fix's verification is the exact live scenario, not a
  claimed unit regression.
- [x] Preserve provider-disabled Umbra builds after the feedback change. The
  active-socket overhead helper is platform-guarded and the direct native
  syntax check with `CLSP_CORE_HAS_RUNTIME=0` passes. No default IPv4 wire
  behavior is invented for an unavailable runtime.
- [x] Restore the temporary isolated test microphone grant/configuration when
  the runs end: the test client's microphone bit returns from mask 95 to 87
  through the authenticated API; the exact original private configuration is
  restored from its backup with a current-file hash guard. The test task is
  stopped and installed Lumen remains PID 10964. No installed service restart,
  VDD change, driver installation, or system audio-setting change was made.

At the end of this continuation the isolated task is stopped with its original
private configuration and permission mask restored. The original private
configuration backup remains `lumen.conf.before-microphone`. For future
microphone runs, explicitly re-enable only the isolated setting/grant; neither
the installed host nor its working Moonlight configuration is a test target.
- [ ] Confirm physical picture/audio/input and complete sustained codec/mode,
  congestion/repair, input/controller, and hardware qualification before the
  streaming-readiness fixes and packaging. The admin rewrite is no longer in scope.

The current signed development client passes its affected Swift build with
warnings-as-errors. Temporary legacy static libraries still produce known
deployment-target linker warnings; release packaging remains unqualified.
Stable source changes remain staged/dirty because 1Password Git signing is
unavailable. Signing has not been disabled or bypassed. Photon is unchanged at
`657833c8fa0cc96f75e248696716d51226ae55f3` / digest `72b3a260…679db`;
these native Apple runtime changes are outside its source-identical core.

### Reconnect continuation — September 12, from 05:00

The preceding goal turn made implementation and live-verification progress;
the LSP streaming, qualification, packaging, and relevant final gates remain
the objective. The installed host is still not a test target.

- [x] Identify the remaining first-attempt timeout from the real exchange:
  client `MICROPHONE_CONFIG_ACK` (`0x0215`) reaches its final retry at 77,384
  microseconds with a 5,000-microsecond base RTO. Host lifecycle timing records
  audio retirement at 183,325 microseconds and video retirement at 144,048
  microseconds on the UDP receive thread. Deferring microphone activation alone
  cannot prevent earlier media teardown from delaying reception of that ACK.
- [x] Move blocking audio/video joins to a dedicated owned worker while queued
  runtime objects remain retained. Only acquire-observed completion permits
  socket-owner destruction, generation-checked path/key cleanup, or replacement
  capture activation. Closed five-tuples stay unavailable until the old
  namespace retires; shutdown joins this worker before freeing its borrowed
  owners. The affected Windows build passes. A bounded source-level lifetime
  check additionally confirmed the closed-tuple ingress fence and caught the
  need to defer DTLS-close cleanup for already-queued owners. Cleanup is now
  centralized after every producer joins, and the close drain uses the direct
  owner-thread provider API rather than a potentially full request queue.
  The isolated Windows artifact
  `079C66A8626A0ADE674AAD5838E01B2F9AB9E6AB8F4619C6EC4D3A1748B04256`
  passes the exact four-second host-suspension retry: one ATTACH attempt,
  one commit/completion, zero failures, new audio/video/microphone generation 2,
  614 sent HEVC frames, and 968 decoded microphone frames with no decode/sink,
  PLC, or packet-rejection errors in that recovered generation. The host
  commit-to-ready barrier takes 58,922 microseconds, excluding outage detection
  and DTLS; this is not first-packet or physical-presentation latency.
  Four video pressure events remain visible, so full performance qualification
  is not claimed. Temporary retry/retirement instrumentation is removed.
- [x] Fix intermittent first-start microphone playout rejection. One
  pre-outage generation records 157 rejected packets, 127 FEC frames, and 30 PLC
  frames despite zero decode/sink errors; the recovered generation is clean.
  A first-rejection diagnostic in the exact live retry identifies
  `too_far_ahead`, with no late/timestamp-invalid packets. LSP inherited the
  legacy receiver's 60-ms preroll despite its one-packet requirement; that delay
  consumes headroom in the six-packet receive window before burst arrivals.
  New bounded constructor overloads let LSP select 20 ms while preserving the
  original legacy constructors, signatures, and 60-ms default. The Windows
  affected target builds; the same required-microphone START records 1,167
  accepted packets, 1,165 decoded frames, and zero rejected/FEC/PLC/silence,
  decode-error, or sink-error frames, with active HEVC and no reconnect.
  Three focused tests pass for legacy timing, explicit-delay bounds, and
  one-packet burst headroom (7 ms); no broad suite was run. The temporary
  rejection diagnostic is removed and the affected host target rebuilt.
- [x] Correct the independently confirmed fifth-send retry boundary in canonical
  Photon: a fifth transmission remains ACK-eligible until its next-retry time
  or the earlier operation deadline, and a sixth transmission is never sent.
  The existing `PhotonControlStateTests` target and filtered
  `Photon.ControlState` test pass. Only `src/lsp/core/control.h` and the existing
  `tests/control_state_test.cpp` change in Photon.
- [x] Make the signed Photon checkpoint, regenerate its digest, and advance the
  normal Lumen/Umbra pins and mirrors. After the user confirmed 1Password was
  unlocked, signing succeeded: Photon `6a504910dfeb0489eb33af02e4bd3659e8c11e24`
  carries an SSH signature and is pushed to `origin/main`. Both normal sync
  utilities verify digest `d565644e8c3a00d6c474d6c118b8b8eccd3140d35eda54dbb0bba7c42f1ca7f0`.
  Umbra's affected product build succeeds against that canonical checkout.
  The old signing block is cleared; Windows deployment of the integrated
  input-feedback build is still pending.

### Current LSP game-streaming integration

- [x] Cancel the Svelte/SvelteKit admin rewrite per the latest user request.
  Keep the current admin panel. Delivery is working LSP Lumen/Umbra builds;
  legacy Moonlight success is not evidence for the LSP acceptance gate.
- [ ] Finish input-only/mixed input+microphone RFC 8888 integration. The host
  observation window, shared CCFB send lane/floor, native input sent/tombstone
  ledger, aggregate reverse controller, and client input SR are implemented.
  Parent dispatch now passes actual protected bytes, receive time and ECN.
  Host SR receipt/RR LSR-DLSR echo and live counters are connected. Both product
  builds succeed; focused feedback pacing/wire tests pass (4 ms). The first
  signed input-only LSP run receives the baseline, sends one input CCFB plus
  periodic RR, has no feedback-storage drops, and continues HEVC with zero
  client authentication failures or packet drops. Physical input activity and
  mixed input/microphone qualification are still pending; baseline receipt
  does not prove mouse/keyboard application or high-rate control behavior.
  The runtime pin check caught and corrected a leftover Swift digest constant.
- [ ] Complete real picture/audio/input/controller confirmation, sustained
  game-streaming checks, and release packaging on the named hardware.
- [ ] Recheck Dock activation and focused input with the user. The real
  `Umbra-2026-09-12-170709.ips` crash identifies `matching()` in
  `AppleInputCapture.mm:1165`: IOHID C-string key macros were passed directly to
  a CFType dictionary, which crashed while sending `hash` to string bytes.
  Umbra `c06ddd3` wraps both keys in `CFSTR`; the affected product build and
  signing pass. The corrected LSP stream is reopened for the user's Dock/input
  test. The crashed session was cleared by restarting only the isolated test
  task; installed Lumen PID 10964 was not restarted or replaced.
  The follow-up `Umbra-2026-09-12-180903.ips` identified a separate
  `__IOHIDManagerExtRelease` abort: failed device opening released a
  dispatch-backed manager before activation/cancellation. Umbra `1c343fa`
  defers dispatch queue assignment until fallible preparation has succeeded,
  preserving the native capture path and permitting safe AppKit fallback.
  The affected app build/signing and a real-HID failed-start/retry regression
  pass (one test, 0.123 s). The signed LSP stream reopened at 18:15 after
  clearing the crashed association on only the isolated test task; installed
  PID 10964 is unchanged. User focus/input confirmation remains pending.
- [ ] Resolve the reported disconnect/reconnect failure without interrupting an
  active user stream. The GUI stream log records fullscreen video at 18:37:11;
  an agent-launched second instance sent START at 18:37:27, received `busy`, and
  the first stream dismissed at 18:37:33. The agent should not have launched
  the second instance while the user was testing. The host rejects nonowner
  START and fences association teardown by peer; these timestamps alone do
  not establish the terminal failure's cause. The GUI termination reason was
  not persisted in the support log. Umbra `4e7fb8f` now registers GUI streams
  with the owner endpoint, reserves ownership before START, rejects duplicate
  cross-process ownership with a private lifetime file lock, and persists
  terminal LSP errors. Failed startup finishes window cleanup before releasing
  ownership; delayed old listener tasks cannot unlink or reuse successor
  descriptors. Four focused IPC tests pass and the affected app builds with
  Swift warnings-as-errors. The signed test bundle is refreshed without
  launching it. The disconnect/reconnect cause remains unconfirmed; this is
  not a live stability claim. No host restart or stream launch occurred during
  this local fix/verification step.
- [x] Remove the obsolete September 1 local LSP test pairing
  `12C056C1-813A-1BCF-C32D-19C8DB42A660`, which shared the current host's
  display name/address. Both original LSP host/trust files are backed up in
  `/tmp/umbra-obsolete-pairing.XzxT8a`. Exact comparison confirms current host
  `324363D1-4353-BA2D-7154-8B6FBC75F273` and its trust are unchanged. Legacy
  state and all client identities are untouched.
- [x] Repair LSP host-browser status: saved-but-unconfirmed hosts display
  Offline instead of an indefinitely idle Checking state; discovery-confirmed
  Ready survives persisted-state refresh; manual refresh retries known Bonjour
  services; LSP uses Bonjour TXT metadata directly. Legacy discovery's browser
  descriptor is unchanged. The app build and two focused readiness/snapshot
  regressions pass; the signed app was relaunched without a stream.
- [ ] Complete the live Ready check after resolving macOS Local Network
  permission. At 19:02:42, Network.framework logs for the running signed Umbra
  PID 98662 explicitly reject both IPv4 and IPv6 host endpoints with
  `Local network prohibited`; the LSP resolver times out at three seconds.
  Bonjour itself finds the advertised current host immediately. Local Network
  settings have been opened for the user to enable Umbra. No permission store
  was modified or bypassed; no Windows service was restarted.
  **Correction after the user's screenshots:** all Umbra toggles were already
  enabled. Read-only inspection confirms `DenyMulticast=false` for both the
  stable app identifier and the temporary bundle rule. Asking the user to
  enable it again was not a valid diagnosis.
- [x] Consolidate development launches onto `/Applications/Umbra.app`, signed
  by the same Apple Development identity/requirement as the previous installed
  app. Previous installed/temporary bundles and two remaining old development
  bundles are recoverable under `/tmp/umbra-install-backup.5bRJQr`. Sixteen
  stale LaunchServices registrations are removed; a fresh dump lists only the
  canonical `/Applications/Umbra.app` for this bundle identifier. The private
  network-permissions store was not edited. Historical Local Network rows are
  **not** claimed removed; Apple documents no supported per-program reset.
- [x] Block raw build executable launches before creating network services,
  preserving help/version and explicit local recovery. This prevents future
  raw-build networking from adding per-executable privacy identities. The
  focused bootstrap regression and affected app build pass.
- [x] Check saved host reachability through authenticated LSP APPLICATIONS,
  independently of Bonjour endpoint resolution, and publish each host result.
  No START or ATTACH is sent. The focused regression covers Offline, Ready
  without Bonjour, retained Ready across refresh, and failed-probe Offline.
- [ ] Resolve the GUI-process permission denial. A read-only APPLICATIONS
  request from the shell returns Desktop immediately, but the identical signed
  app opened by LaunchServices fails its real native UDP check and stays
  Offline. This disproves the earlier resolver-only conclusion: Apple's
  TN3179 documents the Terminal/child-process exemption, so shell success is
  not GUI permission evidence. Do not use a shell launch as a bypass. A normal
  Mac restart is the next bounded state-refresh diagnostic, not a guaranteed
  fix, and requires user approval because it closes local applications. No
  further signing, app relocation, toggle cycles, or permission-store surgery
  should substitute for this diagnostic.
  **Further investigation:** Little Snitch 6.4.1 has an active network filter;
  the VPN services inspected are disconnected. The remaining denial must not
  be attributed conclusively to macOS before inspecting Umbra's filter rules.
  The supported Little Snitch rule export requires root, and the noninteractive
  attempt reports that a password is required. No filter was disabled, no
  rules were changed, and no administrator credentials were obtained.
- [x] Umbra `562aee6` adds automatic idle-host status retries at the existing
  legacy monitor's three-second cadence, with one in-flight check, unchanged
  UI/error suppression, and no probes during owned streaming/reconnect. The
  user's 100 ms example was not treated as a timing requirement. The focused
  automatic recovery regression passes in 3.46 seconds and the installed app
  is updated. GUI reachability remains unverified; this timer is not a claim
  that the connection-denial cause has been fixed.
- [x] Repeat the real GUI connection after the user disabled Little Snitch.
  The isolated Windows task had meanwhile stopped at its `PT2H` execution
  limit. A guarded helper started only that stopped task and changed its
  limit to `PT0S`; installed Lumen PID 10964 remained unchanged. With no stream
  owner present, the idle GUI was relaunched to clear its stale association.
  `/Applications/Umbra.app` PID 7739 then refreshed authenticated trust and
  Bonjour last-seen state at 21:16:54, with no GUI connection error recorded.
  This identifies Little Snitch filtering as the removed connectivity block;
  the earlier macOS-toggle/reset diagnosis was incorrect. No firewall rule
  was changed by the agent. Only the user disabled Little Snitch. A narrowly
  scoped Umbra allow rule is still preferable to leaving the firewall disabled.
- [ ] Fix idle catalog-session reuse after host expiry: the previous running
  GUI retained a stale authenticated session and repeatedly returned
  `notAuthenticated` after the test host stopped, until the idle GUI restarted.
  Do not interrupt the newly working client while the user tests streaming.
- [x] Umbra `b3184aa` fixes two faults found in the user's first GUI stream:
  AppKit fallback focus transitions were labelled RESOURCE_EXHAUSTED, and a
  synchronous video-consumer report re-entered the native C ABI callback and
  terminated the stream. Focus-triggered starts now coalesce after the AppKit
  transition and revalidate exact window ownership; genuine queue-allocation
  failure remains distinct from unavailable focus. Retained complete frames
  are delivered on a serial frame-level queue, bounded by the native retained
  frame pool (decoder surfaces + 2), with handler-generation fencing. No
  per-packet Swift queue was introduced. Both focused regressions pass, the
  affected app builds, and the signed installed app is reopened for the user.
- [ ] Recheck physical input, latency, stutter, and picture quality in a new
  live stream. The prior GUI stream rendered at 21:17:42 and closed at
  21:18:15 with `reentrantCallback`. Later host counters include continued
  post-disconnect admission drops, so those totals do not establish active
  stream encoder saturation or network loss. No performance-fix claim is made
  until fresh live timing and user observation confirm the corrected path.

After the successful retry, normal STOP succeeds, the test pairing returns to
mask 87, the original private microphone configuration is restored with its
hash guard, and the isolated scheduled task is stopped. Installed Lumen remains
PID 10964. Temporary control-retry and retirement timing diagnostics have been
removed from source; the signed diagnostic bundle will be refreshed by its affected
  product build. The final client rebuild is currently stopped by the correct
  Photon source-drift check while its new retry fix remains uncommitted. An
  attempted `PHOTON_REPOSITORY` override to a clean pinned worktree did not
  change SwiftPM's prebuild checkout selection. Checks were not disabled;
  the signed bundle still contains the temporary final-retry diagnostic until
  the Photon checkpoint/sync permits its normal rebuild. The source diagnostic
  is removed. No broad suite or repeated outage run is needed for this result.

The earlier ledger describes the September 1 development deployment. It does
not imply LSP is enabled on the currently installed host. The accumulated
pre-pause changes are checkpointed before further implementation; this is not
an assertion that audits or live streaming qualification are complete.

| Milestone | Status | Verified evidence | Remaining boundary |
| --- | --- | --- | --- |
| Working branches and pre-rewrite checkpoint | **Done** | Both repositories use `feature/lsp-rewrite`; Lumen checkpoint `2397c28c` | None |
| Remove retired Lumen native transport | **Done** | Lumen commit `564b1131`; application link, focused legacy/migration checks, packaging check, and diff audit pass | None |
| Remove retired Umbra native transport | **Done** | Umbra commit `0362c2e`; full Swift tests, warnings-as-errors build, and packaging tests pass | Physical Moonlight smoke test remains part of final hardware validation |
| Select DTLS 1.3 provider | **Done** | Commercial wolfSSL 5.9.2 selected; tag `v5.9.2-stable` pinned | Keep license material external to the repository |
| macOS DTLS-SRTP provider proof | **Done** | Live DTLS 1.3 exchange proved `TLS_AES_128_GCM_SHA256`, X25519, HRR cookie, ALPN `lumen-stream/1`, `SRTP_AEAD_AES_128_GCM`, and identical 56-byte exporter output | Repeat the exact proof on Windows/UCRT64 |
| libSRTP wolfCrypt backend | **In progress** | The reviewed libSRTP 2.8.0 patch and CMake target are integrated; AES-128-GCM SRTP/SRTCP protection, encrypted extensions, authentication, replay rejection, exact per-SSRC directional contexts, endpoint-value cache isolation, quiescent context/key retirement, and aggregate-key-safe SRTP/SRTCP lifetime fences pass on macOS. The provider-enabled static Windows/UCRT64 production executable now compiles, links, installs, and starts with process-wide wolfSSL/wolfCrypt initialization before identity RNG use. | Live-prove the 16-byte-tag RTP/SRTCP path and lifetime-to-rekey handoff during the Windows/macOS session. |
| Shared portable C++23 core | **Done** | Photon is canonical at `git@github.com:simonfalke-01/Photon.git` commit `657833c8fa0cc96f75e248696716d51226ae55f3`, aggregate digest `72b3a260…679db`; Lumen and Umbra's offline lock/manifest/source-identity checks pass with exact RFC 8888 ECN and 1/1024-second ATO, compound RTCP authority, CNAME, and late-overlap feedback primitives | Update Photon first, then advance each product's reviewed lock and source-identical mirror with its normal sync utility |
| Umbra `CLSPCore` C ABI and mirror | **Done** | ABI v2, digest gate, real UDP/kqueue wolfSSL/libSRTP runtime, exact multi-SSRC policies, token-retained two-frame reassembly, retained complete encoded-access-unit buffers, complete-Opus/timing callbacks, reverse-microphone sender, and warnings-as-errors product builds pass | Extend the ABI only at coarse input, completed-media, lifecycle, and telemetry boundaries |
| Lumen configuration, build, UI, and discovery foundation | **Done** | LSP config/UI, real runtime factory, active-only `_lumen-stream._udp`, digest gate, application/test builds, web build, and focused config/mDNS/LSP checks pass. The provider-enabled static Windows/UCRT64 production target links and is deployed on the authorized Windows host; the service remains stable, binds UDP 48030 through the installed inbound firewall rule, and registers Lumen mDNS. A real legacy Moonlight session subsequently launched HEVC video and Opus audio and disconnected normally, independently of LSP. | Keep this foundation unchanged while live pairing and streaming exercise the runtime. |
| LSP host security/session foundation | **In progress** | Real nonblocking UDP ownership, wolfSSL DTLS 1.3, libSRTP contexts, fresh LSP identity persistence, dedicated-exporter SPAKE2-P256 six-digit PIN pairing, pairing/authentication, LSP-only trust, LSPC reliability, browsing, and trusted-client administration are wired. URI/QR invitations are removed; max-four 120-second sessions use selected-session async scrypt, uniqueness/rate fences, atomic insert-if-absent trust, exact completed-result replay, and persist before success. Shutdown now stops admission, joins control and platform-feedback workers, drains forward completions while their input/media owners remain alive, drains DTLS after an explicit owner handoff, and closes the leased UDP descriptor last. The Windows host now boots the runtime without DXGI error-path null dereferences or pre-initialization wolfCrypt RNG use, creates `lsp_identity_v1.bin`, removes only the retired protocol credentials, exposes authenticated pending-PIN administration, and reports an active listener on UDP 48030. A real macOS Umbra client now discovers the Windows service, completes DTLS 1.3, receives the first SERVER_HELLO through an association-generation-scoped CLIENT_HELLO response cache, completes the six-digit PIN challenge/PAIR_RESULT flow, persists trust, reauthenticates, and lists the real Desktop and Steam Big Picture applications. | Live-prove lost RESULT recovery, permission failures, authentication replay/rollback handling, and certificate rotation before closing the security/session phase. |
| Frozen input wire/state primitives | **Done** | Ten focused tests pass across pointer/edge wire, device/sensor keys, baseline atomicity, loss/reorder, LSPI, LSPG, rates, and text barriers | Extend only when another input wire or safety invariant is implemented |
| Remaining input schemas and product integration | **In progress** | Umbra commit `2df4cd2`; native IOHID/GameController input, public touch lifecycle, authenticated retry-safe LSPG ACKs, LED, CoreHaptics rumble, adaptive triggers, and motion commands are wired; Lumen applies all negotiated input classes and sends generation-qualified controller output | Prove the real Lumen↔Umbra path with physical 1/8 kHz pointer, controller, touch, and output devices |
| Audio/video media primitives | **Done** | Seventeen focused tests verify H.264, HEVC, AV1, Opus, path limits, complete-frame admission, retained and pooled two-frame reassembly, decoder credits, and mailbox depth one; a direct 100,000-frame check records zero pooled-reassembly allocations after configuration | Extend only when another negotiated codec or frame-pipeline invariant is implemented |
| Audio/video product integration | **In progress** | Lumen and Umbra wire host audio and reverse microphone. Both implement video schema revision three with exact H.264/HEVC/AV1, profile, pixel-class, H.273 SDR/HDR10/HLG, codec-configuration, HDR metadata, access-unit, and repair-association maps. Lumen proves the selected Windows capture/encoder tuple, rejects unproved HLG, preflights VIDEO_CONFIG before START/ATTACH commit, and keeps capture ACK-gated. Host audio now retains its fixed-slab zero-copy path under transient pressure, carries discontinuity on the next successful packet instead of ending capture, and accounts RFC 8888 overlap/loss/CE transitions only after full validation. Reverse microphone records authenticated reception before playout and emits bounded gap/reorder/ATO/ECN feedback whose borrowed report window commits only after final protected send completion. Umbra derives offers from exact VideoToolbox/Metal probes, validates AV1 sequence-header color facts, uses latest-frame depth-one presentation, and fails conflicting decoded pixel/color/HDR state. | Run the first Windows-Lumen to macOS-Umbra media session on every hardware-proven tuple. |
| Bounded transport state primitives | **Done** | Thirteen focused tests verify RTCP/AVPF, RFC 8888 cadence, LSPV coalescing, FEC-before-SRTP state, recovered-packet admission, RTX bounds, recovery epochs, congestion, PMTU, and generation fencing | Extend only when another transport wire or safety invariant is implemented |
| Protected transport wire and product integration | **In progress** | Live SRTP/SRTCP covers input, audio, microphone, primary video, FlexFEC, and RTX through one reviewed aggregate egress owner and exact client SSRC policies. Lumen emits loss-activated frame-local FEC-before-SRTP parity, retains two O(1)-indexed successful AU generations for deadline-qualified RTX, and accounts primary/FEC/RTX RFC 8888 evidence independently. Regular RTCP is now admitted through one validate-first SR/RR plus stable-CNAME authority before RTT/PMTU mutation; the acknowledgement SSRC's completion-fenced RR+SDES must actually send before reduced LSPI/LSPG, and authenticated CCFB is offloaded from the socket worker for one immutable video/audio/ECN parse-and-commit pass. All datagrams default Not-ECT; only deterministic RTP probes may use ECT(0) until three authenticated matching reflections establish per-peer capability through a bounded four-way send index, while contradictions, expiry, MTU/family failures, five-tuple replacement, or payload-size changes reset proof. Darwin uses fail-closed same-port IPv4/IPv6 sockets with `IP_DONTFRAG` and `IPV6_DONTFRAG`. The focused ECN/DF/RTCP/audio/microphone/service/feedback-worker checks pass, including repair-first queue priority and stale-generation rejection. Umbra receives into pool slabs, retains same-frame repair slices without copies, authenticates recovered originals through one replay window, emits bounded urgent NACK retries, and preserves repair across recovery-epoch reorder. Recovery, dependency invalidation, packet admission, and retry are generation-fenced through terminal completion. | Live-prove loss, reorder, FlexFEC, RTX, ECN validation/reset, recovery, and congestion convergence on Windows/macOS hardware. |
| Reconnect, rekey, lifecycle, telemetry product surfaces | **In progress** | Lumen freezes the five-key client-successor ATTACH, atomically installs/echoes the exact successor, caches 64 semantic intents, supports ambiguous-response forward recovery, preflights 512-entry session SSRC history, and holds up to 64 deduplicated retiring peers with their SRTP/path intact behind neutral-baseline-ACK, mandatory-audio, fresh microphone/controller permission, and acknowledged/activated-video readiness. The successor gets the sole VDD lease, retiring DPLPMTUD is cancelled, and a generation-qualified three-second deadline fails only forward. Umbra owns active/candidate/retiring cores through ABI-v2 native handoff fencing, atomically marks and publishes ATTACH, distinguishes pre-submit rollback from post-submit ambiguity/commit, waits exact authority-epoch baselines, drains capture/producers before transfer, coalesces reconnect single-flight, and schedules planned rekey with secret-free telemetry. | Run a live cross-process reconnect/rekey, including lost ATTACH_RESPONSE and rapid successive recovery, and validate every active media generation on hardware |
| Final conformance, packaging, performance, and hardware qualification | **Pending** | None claimed | Run only after the complete live feature works |

Current functional stop point: both products contain real LSP UDP,
wolfSSL, libSRTP, control, trust, START/STOP/ATTACH, input, host-audio, reverse
microphone, and primary video paths. Lumen's compiled control path now uses
video schema revision three for H.264, HEVC, AV1, SDR, HDR10, HLG, 8/10-bit,
and 4:2:0/4:4:4 tuples; only exact Windows capture/hardware-proven tuples are
selectable, and HLG currently fails closed because the Windows configuration
boundary cannot yet prove that transfer. The media paths use real
platform capture, VDD/hardware encode, native authenticated media, bounded
reassembly/credits, VideoToolbox, Metal, and generation-aware reconnect. No
live picture or end-to-end latency claim is made until a Windows Lumen and
macOS Umbra session is exercised. Authenticated multi-SSRC RFC 8888 feedback,
media SR/RR timing, exact-size SRTCP DPLPMTUD, remote black-hole recovery, and
frame-boundary path/rate changes are now product-wired on both sides.
Host-to-client producers use the shared aggregate egress owner, and complete
recovery, FlexFEC, RTX, multi-SSRC feedback, and `LSPV` paths have passed focused
product builds and independent correction review. Umbra allocates its receive
slabs, retained slice descriptors, and decoder-frame pool only when the
authenticated video generation is configured; the steady packet/reassembly
path performs no heap allocation and only the final decoder transform may copy.

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

Photon is the canonical repository for the source-identical portable C++23
core. Lumen pins Photon by repository, commit, ordered source manifest, and
aggregate digest in `src/protocol_lsp/photon.lock`, while retaining an in-tree
mirror so normal builds and packaged products have no Git, network, submodule,
or runtime dependency on Photon. `scripts/sync-photon-core.sh --check` verifies
the local mirror entirely offline and also verifies a local Photon checkout
when one is available; `--sync` advances only to the reviewed lock. Lumen's
host runtime, platform integration, wolfSSL/libSRTP providers, and product
state remain local to Lumen and are not part of Photon.

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
  LSPPairing.swift                 numeric PIN and SPAKE pairing
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

- Implement numeric-PIN SPAKE2 pairing and dedicated exporter binding.
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

- PIN control-map, AAD, confirmation, and identity-signature encoding;
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

Current implementation status: video control schema revision three, exact
optional FlexFEC/RTX associations, and the 12-byte encrypted
`{frame_id, recovery_epoch}` value are wired. Lumen seeds the
Photon recovery controller from configuration, reserves the sole independent
recovery frame before first packet commit, gates a second independent frame,
confirms decode by same-epoch watermark, and permits one retry only after both
deadline expiry and latched decoder failure. Live FlexFEC and RTX remain in
this stage. Dropping a second independent frame while recovery is outstanding
invalidates that unsent encoder dependency, and every reference-invalidation
site is generation/range-qualified through one-active/one-coalesced terminal
tracking. Dependent video reserves the serialized dependency generation before
submission and revalidates it at each packet commit boundary.

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

Current implementation status: the revision-three control wire, Windows host
selection, codec-specific configuration, and fail-closed H.273 tuple validation
are complete for H.264, HEVC, AV1, SDR, HDR10, HLG, 8/10-bit, and 4:2:0/4:4:4.
Actual selection remains limited to the current capture/hardware-encoder
generation's proof; the Windows configuration boundary does not yet prove HLG and therefore
rejects it rather than encoding PQ. Live client decode and hardware
qualification remain the stage exit gate.

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
are complete. The macOS development path has passed the live wolfSSL DTLS 1.3,
DTLS-SRTP exporter, and libSRTP AES-GCM proofs. The remaining Stage 0 boundary
is production-platform evidence:

1. repeat the pinned wolfSSL 5.9.2 DTLS 1.3 and DTLS-SRTP exporter proof on
   Windows/UCRT64;
2. repeat AES-GCM SRTP/SRTCP through the wolfCrypt-backed libSRTP package on
   Windows/UCRT64; and
3. record production throughput and packaging evidence.

The current macOS provider-enabled product builds may claim authenticated LSP
operation. No Windows packaging, interoperability, throughput, or hardware
qualification claim is made until the remaining evidence passes.

## 23. Implementation start

The user resumed implementation. The rewrite proceeds through the functional
stages above. Provider initialization remains fail-closed, while production
claims remain bounded to the platform evidence recorded in the ledger.
