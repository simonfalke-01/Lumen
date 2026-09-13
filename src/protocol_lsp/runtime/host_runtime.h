/**
 * @file src/protocol_lsp/runtime/host_runtime.h
 * @brief Production LSP host runtime factory and lifecycle.
 */

#pragma once

#include "../service.h"
#include "control_server.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumen::lsp::runtime {
  inline constexpr std::size_t maximum_host_feedback_work_bytes = 1'472;  ///< Confirmed LSP/1 UDP payload ceiling.

  /** @brief Priority class selected by the shared feedback worker. */
  enum class HostFeedbackWorkClass : std::uint8_t {
    none,  ///< No feedback is queued.
    repair,  ///< NACK/PLI/FIR always preempts congestion feedback.
    congestion,  ///< CCFB is served only after the repair reserve drains.
  };

  /**
   * @brief Select repair before congestion regardless of CCFB queue occupancy.
   *
   * @param repair_count Queued NACK/PLI/FIR work items.
   * @param congestion_count Queued RFC 8888 CCFB work items.
   * @return Repair when available, otherwise congestion or none.
   */
  [[nodiscard]] constexpr HostFeedbackWorkClass next_host_feedback_work_class(
    const std::size_t repair_count,
    const std::size_t congestion_count
  ) noexcept {
    return repair_count != 0     ? HostFeedbackWorkClass::repair :
           congestion_count != 0 ? HostFeedbackWorkClass::congestion :
                                   HostFeedbackWorkClass::none;
  }

  /**
   * @brief Validate bounded CCFB work against the current association/media generations.
   *
   * @param packet_bytes Complete authenticated plaintext RTCP packet bytes.
   * @param queued_connection_generation Connection generation captured at enqueue.
   * @param queued_input_ssrc Client feedback sender SSRC captured at enqueue.
   * @param queued_video_generation Video generation captured at enqueue.
   * @param queued_audio_generation Audio generation captured at enqueue, or zero.
   * @param current_connection_generation Current authoritative connection generation.
   * @param current_input_ssrc Current authoritative feedback sender SSRC.
   * @param current_video_generation Current active video generation.
   * @param current_audio_generation Current active audio generation, or zero.
   * @return True only for bounded work matching every current generation field.
   */
  [[nodiscard]] constexpr bool host_feedback_work_is_current(
    const std::size_t packet_bytes,
    const std::uint32_t queued_connection_generation,
    const std::uint32_t queued_input_ssrc,
    const std::uint32_t queued_video_generation,
    const std::uint32_t queued_audio_generation,
    const std::uint32_t current_connection_generation,
    const std::uint32_t current_input_ssrc,
    const std::uint32_t current_video_generation,
    const std::uint32_t current_audio_generation
  ) noexcept {
    return packet_bytes >= 12U && packet_bytes <= maximum_host_feedback_work_bytes &&
           queued_connection_generation != 0 && queued_connection_generation == current_connection_generation &&
           queued_input_ssrc != 0 && queued_input_ssrc == current_input_ssrc &&
           queued_video_generation != 0 && queued_video_generation == current_video_generation &&
           queued_audio_generation == current_audio_generation;
  }

  /**
   * @brief Exact active-listener DNS-SD descriptor independent of platform publication APIs.
   */
  struct DiscoveryDescriptor {
    std::string type;  ///< Exact `_lumen-stream._udp` service type.
    std::uint16_t port {};  ///< Active bound UDP port.
    std::vector<std::pair<std::string, std::string>> txt;  ///< Canonical version, host ID, and capability fields.
  };

  /** @brief Web-safe trusted-client administration record. */
  struct TrustedClientSummary {
    Identifier128 client_id {};  ///< Stable client identifier.
    PermissionSet permissions {};  ///< Current effective permissions.
    std::uint32_t revocation_generation {};  ///< Current trust generation.
    bool enabled {};  ///< Whether new authentication is allowed.
  };

  /** @brief Terminal state of the most recent reconnect or planned-rekey attempt. */
  enum class ReconnectOutcome : std::uint8_t {
    none,  ///< No ATTACH attempt has been observed.
    rejected,  ///< ATTACH failed before authority or token commit.
    committed,  ///< Authority committed and the replacement readiness barrier is pending.
    ready,  ///< Input and every negotiated media lane reached the replacement readiness barrier.
    failed,  ///< A post-commit association or required-lane failure ended the handoff.
  };

  /** @brief Secret-free aggregate ATTACH lifecycle telemetry for administration surfaces. */
  struct ReconnectTelemetrySnapshot {
    std::uint64_t attempts {};  ///< Distinct semantic ATTACH attempts.
    std::uint64_t committed {};  ///< Attempts that atomically rotated authority and the attach token.
    std::uint64_t completed {};  ///< Committed attempts that reached the full readiness barrier.
    std::uint64_t rejected {};  ///< Attempts rejected before commit while prior authority remained unchanged.
    std::uint64_t failed {};  ///< Committed attempts that failed before the full readiness barrier.
    std::uint32_t latest_connection_generation {};  ///< Latest attempted nonzero replacement generation.
    ReconnectOutcome latest_outcome {ReconnectOutcome::none};  ///< Latest terminal or intermediate outcome.
    std::uint64_t latest_request_to_commit_microseconds {};  ///< Latest request-to-authority-commit duration.
    std::uint64_t latest_commit_to_ready_microseconds {};  ///< Latest commit-to-full-readiness duration.
    std::uint64_t latest_total_microseconds {};  ///< Latest request-to-terminal-outcome duration.
  };

  /** @brief Generation-qualified aggregate media and transport administration telemetry. */
  struct RuntimeMediaTelemetrySnapshot {
    std::uint32_t audio_generation {};  ///< Active host-audio generation, or zero.
    std::uint32_t video_generation {};  ///< Active video generation, or zero.
    std::uint32_t microphone_generation {};  ///< Active reverse-microphone generation, or zero.
    std::uint64_t audio_sent_packets {};  ///< Final-sent host Opus RTP packets.
    std::uint64_t audio_expired_packets {};  ///< Host audio packets dropped by deadline.
    std::uint64_t audio_delivered_bytes {};  ///< Delivered host-audio complete IP bytes.
    std::uint64_t audio_lost_bytes {};  ///< Lost host-audio complete IP bytes.
    std::uint64_t audio_ecn_ce_bytes {};  ///< CE-marked host-audio complete IP bytes.
    std::uint64_t video_sent_frames {};  ///< Fully submitted primary video frames.
    std::uint64_t video_admitted_frames {};  ///< Complete video access units admitted by the sender.
    std::uint64_t video_dropped_frames {};  ///< Whole video frames rejected before transmission.
    std::uint64_t video_decoder_saturated_drops {};  ///< Video frames rejected because decoder credit was zero.
    std::uint64_t video_deadline_miss_drops {};  ///< Video frames rejected by deadline or serialization bounds.
    std::uint64_t video_invalid_reference_drops {};  ///< Video frames rejected by dependency or recovery state.
    std::uint64_t video_forward_capacity_drops {};  ///< Video frames rejected by queue/path capacity or backpressure.
    std::uint64_t video_pressure_events {};  ///< Queue, admission, pacer, or socket pressure observations.
    std::uint8_t video_decoder_credit {};  ///< Latest authenticated client decoder credit.
    std::uint64_t video_pacing_bits_per_second {};  ///< Current complete-IP aggregate pacing target.
    std::uint64_t video_encoder_bits_per_second {};  ///< Current encoded-video bitrate target.
    std::uint64_t video_feedback_reports {};  ///< Accepted authenticated congestion feedback reports.
    std::uint64_t video_feedback_rejections {};  ///< Rejected malformed/stale congestion reports.
    std::uint64_t video_repair_feedback_packets {};  ///< Accepted NACK/PLI/FIR reports.
    std::uint64_t video_sent_packets {};  ///< Final-sent primary video RTP packets.
    std::uint64_t flexfec_sent_packets {};  ///< Final-sent FlexFEC RTP packets.
    std::uint64_t rtx_sent_packets {};  ///< Final-sent RTX RTP packets.
    std::uint64_t video_lost_bytes {};  ///< Aggregate primary/repair loss bytes from RFC 8888.
    std::uint64_t video_ecn_ce_bytes {};  ///< Aggregate primary/repair CE bytes from RFC 8888.
    std::uint64_t microphone_accepted_packets {};  ///< Accepted reverse Opus RTP packets.
    std::uint64_t microphone_rejected_packets {};  ///< Rejected reverse Opus RTP packets.
    std::uint64_t microphone_receiver_reports {};  ///< Protected regular compound RR/CNAME packets.
    std::uint64_t microphone_congestion_reports {};  ///< Protected reverse-media RFC 8888 packets.
    std::uint64_t microphone_decoded_frames {};  ///< Ordinary Opus frames decoded for platform delivery.
    std::uint64_t microphone_fec_frames {};  ///< Missing Opus frames recovered with in-band FEC.
    std::uint64_t microphone_plc_frames {};  ///< Missing/invalid Opus frames replaced with concealment.
    std::uint64_t microphone_silence_frames {};  ///< Silence or queue-underrun PCM frames generated.
    std::uint64_t microphone_decode_errors {};  ///< Decoder calls failing to produce one complete PCM frame.
    std::uint64_t microphone_sink_errors {};  ///< PCM frames rejected by the platform sink.
    bool microphone_playout_active {};  ///< Whether the generation's clocked PCM receiver is active.
    std::uint64_t forward_sent_bytes {};  ///< Aggregate final-sent host-to-client charged bytes.
    std::uint64_t input_feedback_sent_bytes {};  ///< Final-sent LSPI/LSPG and input RR/CCFB charged bytes.
    std::uint64_t input_authenticated_packets {};  ///< Valid input RTP observations offered to feedback tracking.
    std::uint64_t input_congestion_reports {};  ///< Final-sent input RFC 8888 reports.
    std::uint64_t input_receiver_reports {};  ///< Final-sent regular input RR/CNAME packets.
    std::uint64_t input_feedback_storage_drops {};  ///< Input observations omitted by bounded feedback storage.
    std::size_t input_pending_feedback_positions {};  ///< Input sequence positions awaiting a completed report.
    std::uint64_t applied_input_state_sequence {};  ///< Greatest applied input-state watermark.
    std::uint64_t applied_input_edge_id {};  ///< Greatest contiguous applied input edge.
    std::uint64_t input_latency_samples {};  ///< Receive-to-platform-apply samples.
    std::uint64_t latest_input_latency_microseconds {};  ///< Latest input apply latency.
    std::uint64_t maximum_input_latency_microseconds {};  ///< Maximum input apply latency.
    bool ecn_available {};  ///< Whether ancillary ECN receive/send is active.
    std::uint64_t received_ect0_datagrams {};  ///< Native socket ECT(0) observations.
    std::uint64_t received_ect1_datagrams {};  ///< Native socket ECT(1) observations.
    std::uint64_t received_ce_datagrams {};  ///< Native socket CE observations.
    std::uint64_t sent_ect0_datagrams {};  ///< Native socket ECT(0) submissions.
    std::uint64_t ecn_fallbacks {};  ///< Ancillary failures that safely disabled ECN.
    std::size_t cached_peer_handles {};  ///< Current bounded canonical peer handles.
    std::uint64_t srtp_soft_lifetime_events {};  ///< Per-SSRC soft lifetime first crossings.
    std::uint64_t srtp_hard_lifetime_events {};  ///< Per-SSRC hard lifetime first crossings.
    std::uint64_t planned_srtp_rekeys {};  ///< Soft-limit associations scheduled through fresh DTLS/ATTACH.
    std::uint64_t hard_srtp_stops {};  ///< Hard-limit associations stopped fail closed.
    std::uint64_t feedback_worker_rejections {};  ///< Oversize, full, stale, or invalid worker feedback drops.
  };

  /** @brief Web-safe runtime status without key, PIN, SPAKE, or exporter material. */
  struct RuntimeAdministrationSnapshot {
    bool active {};  ///< Whether the real UDP listener is active.
    NetworkProfile profile {NetworkProfile::adaptive_low_latency};  ///< Configured network profile.
    std::uint16_t port {};  ///< Configured LSP port.
    std::size_t pending_pairings {};  ///< Nonexpired PIN sessions awaiting approval or completion.
    int running_application_id {};  ///< Authoritative active configured application ID, or zero.
    std::uint64_t running_process_generation {};  ///< Active process generation, or zero.
    bool running_application_resumable {};  ///< Whether START resume may reuse the LSP-owned process.
    ReconnectTelemetrySnapshot reconnect {};  ///< Secret-free reconnect/rekey timings and outcomes.
    RuntimeMediaTelemetrySnapshot media {};  ///< Generation-qualified live media/transport counters.
  };

  /** @brief Terminal result of one administrative certificate rotation transaction. */
  enum class IdentityRotationResult : std::uint8_t {
    success,  ///< Every active client persisted, identity persisted, and new-association context swapped.
    inactive,  ///< Runtime or providers are unavailable.
    generation_failed,  ///< Fresh matching certificate/key generation failed.
    client_notification_failed,  ///< A trusted active client could not be notified.
    client_persistence_failed,  ///< A client rejected, failed, or timed out atomic pin persistence.
    persistence_failed,  ///< Host identity replacement could not be atomically persisted.
    provider_swap_failed,  ///< New-association DTLS context swap failed and persistence was rolled back.
    rollback_persistence_failed,  ///< Provider swap failed and the prior persisted identity could not be restored.
  };

  /**
   * @brief Product inputs needed to construct the LSP host runtime.
   */
  struct HostRuntimeConfig {
    HostConfig host;  ///< Validated listener and permission configuration.
    std::filesystem::path identity_file;  ///< Exact LSP-only identity path.
    std::filesystem::path state_file;  ///< Shared state file containing only the `lsp` trust subtree for this runtime.
  };

  /**
   * @brief Runtime construction outcome before any socket bind.
   */
  enum class RuntimeCreateStatus : std::uint8_t {
    ready,  ///< Concrete socket, wolfSSL, libSRTP, identity, and control owners were created.
    provider_unavailable,  ///< Build does not contain both production security providers.
    invalid_configuration,  ///< Required path, hostname, or host configuration is invalid.
    identity_failed,  ///< Fresh LSP identity loading/generation/persistence failed.
    crypto_failed,  ///< wolfCrypt application identity initialization failed.
    srtp_failed,  ///< libSRTP process/provider initialization failed.
    dtls_failed,  ///< wolfSSL exact-policy provider initialization failed.
    control_failed,  ///< Control owner or PIN pairing worker could not be initialized.
    allocation_failed,  ///< A bounded product owner could not be allocated.
  };

  /**
   * @brief Production runtime lifecycle interface returned only by the real provider factory.
   */
  class HostRuntime {
  public:
    virtual ~HostRuntime() = default;

    /**
     * @brief Bind the configured port and start the bounded receive/timer worker.
     *
     * @return Exact host-service activation result.
     */
    virtual ServiceStartResult start() noexcept = 0;

    /** @brief Close the socket, stop the worker, and join it. */
    virtual void stop() noexcept = 0;

    /** @brief Return whether the listener and worker are active. */
    [[nodiscard]] virtual bool active() const noexcept = 0;

    /**
     * @brief Return discovery only while the real listener is active.
     *
     * @return Canonical descriptor or no value while inactive.
     */
    [[nodiscard]] virtual std::optional<DiscoveryDescriptor> discovery() const = 0;

    /** @brief Return the web-safe runtime status and pending PIN-session count. */
    [[nodiscard]] virtual RuntimeAdministrationSnapshot administration_snapshot() const = 0;

    /** @brief Return secret-free pending PIN pairing sessions. */
    [[nodiscard]] virtual std::vector<PendingPairingSummary> pending_pairings() noexcept = 0;

    /**
     * @brief Queue one six-digit PIN for asynchronous SPAKE derivation.
     *
     * @param pairing_session_id Non-secret selected pending session.
     * @param pin_digits Exact six ASCII decimal digits.
     * @return Number of pending sessions admitted to worker processing.
     */
    virtual std::size_t submit_pairing_pin(
      const Identifier128 &pairing_session_id,
      const std::array<std::uint8_t, 6> &pin_digits
    ) noexcept = 0;

    /** @brief Cancel every pending LSP PIN pairing session. */
    virtual void cancel_pairings() noexcept = 0;

    /** @brief Return every persisted LSP trusted client without public keys or secrets. */
    [[nodiscard]] virtual std::vector<TrustedClientSummary> trusted_clients() noexcept = 0;

    /**
     * @brief Replace one trusted client's permissions and advance its revocation generation.
     *
     * @param client_id Stable client identifier.
     * @param permissions New exact permission set.
     * @return True only after persistence; live associations are then disconnected.
     */
    virtual bool update_trusted_client(
      const Identifier128 &client_id,
      PermissionSet permissions,
      bool enabled
    ) noexcept = 0;

    /**
     * @brief Revoke one trusted client and disconnect its live associations.
     *
     * @param client_id Stable client identifier.
     * @return True only after persistent removal.
     */
    virtual bool revoke_trusted_client(const Identifier128 &client_id) noexcept = 0;

    /** @brief Run one complete administrative certificate rotation transaction. */
    virtual IdentityRotationResult rotate_identity() noexcept = 0;
  };

  /**
   * @brief Result of the compile-time-gated production runtime factory.
   */
  struct HostRuntimeCreateResult {
    std::unique_ptr<HostRuntime> runtime;  ///< Real runtime only when status is `ready`.
    RuntimeCreateStatus status {RuntimeCreateStatus::provider_unavailable};  ///< Exact factory outcome.
  };

  /**
   * @brief Create the real LSP runtime only when wolfSSL and libSRTP are linked.
   *
   * No unavailable socket or provider object is created in unsupported builds.
   *
   * @param config Complete product runtime configuration.
   * @return Real runtime and ready status, or a null runtime and exact failure.
   */
  [[nodiscard]] HostRuntimeCreateResult create_host_runtime(HostRuntimeConfig config) noexcept;

  /** @brief Return the process runtime's current web-safe administration snapshot. */
  [[nodiscard]] std::optional<RuntimeAdministrationSnapshot> administration_snapshot();

  /** @brief Return the process runtime's persisted trusted clients. */
  [[nodiscard]] std::vector<TrustedClientSummary> administration_trusted_clients();

  /** @brief Return the process runtime's secret-free pending PIN sessions. */
  [[nodiscard]] std::vector<PendingPairingSummary> administration_pending_pairings();

  /** @brief Queue a six-digit PIN for the process runtime's pending sessions. */
  std::size_t administration_submit_pairing_pin(
    const Identifier128 &pairing_session_id,
    const std::array<std::uint8_t, 6> &pin_digits
  );

  /** @brief Cancel every process-runtime pending PIN session. */
  void administration_cancel_pairings();

  /** @brief Update one process-runtime trusted client. */
  bool administration_update_trusted_client(const Identifier128 &client_id, PermissionSet permissions, bool enabled);

  /** @brief Revoke one process-runtime trusted client. */
  bool administration_revoke_trusted_client(const Identifier128 &client_id);

  /** @brief Rotate the process runtime's certificate through the authenticated transaction. */
  IdentityRotationResult administration_rotate_identity();

  /**
   * @brief Return compile-time production-provider availability.
   *
   * @return True only when both wolfSSL and libSRTP runtime targets are linked.
   */
  [[nodiscard]] constexpr bool providers_available() noexcept {
#ifndef LUMEN_LSP_RUNTIME_AVAILABLE
    return false;
#else
    return LUMEN_LSP_RUNTIME_AVAILABLE != 0;
#endif
  }
}  // namespace lumen::lsp::runtime
