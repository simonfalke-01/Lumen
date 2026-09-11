/**
 * @file src/protocol_lsp/runtime/input_owner.h
 * @brief Bounded ordered LSP input receive and platform-apply owner.
 */

#pragma once

#include "../types.h"
#include "control/wire.h"
#include "host_forward_path.h"
#include "libsrtp_provider.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <utility>

namespace lumen::lsp::runtime {
  /** @brief Completion-fenced regular-compound prerequisite for reduced-size input feedback. */
  class InputFeedbackCompoundGate {
  public:
    /**
     * @brief Reset authority to one exact connection/input generation.
     *
     * @param connection_generation Nonzero connection generation, or zero to clear.
     * @param input_generation Nonzero input generation, or zero to clear.
     */
    void reset(std::uint32_t connection_generation, std::uint32_t input_generation) noexcept;

    /**
     * @brief Return the exact current generation token.
     *
     * @return Nonzero connection/input token, or zero while inactive.
     */
    [[nodiscard]] std::uint64_t token() const noexcept;

    /**
     * @brief Reserve the sole regular-compound submission until terminal completion.
     *
     * @param token Exact active mapping token.
     * @return True only when no compound is sent or already in flight.
     */
    bool begin_submission(std::uint64_t token) noexcept;

    /**
     * @brief Roll back a submission that could not enter aggregate output.
     *
     * @param token Exact in-flight mapping token.
     */
    void cancel_submission(std::uint64_t token) noexcept;

    /**
     * @brief Apply terminal completion; only actual sent establishes reduced-size authority.
     *
     * @param token Exact completed mapping token.
     * @param sent Whether the immutable compound reached the kernel send boundary.
     */
    void complete(std::uint64_t token, bool sent) noexcept;

    /**
     * @brief Return whether actual-sent regular compound authorizes LSPI/LSPG.
     *
     * @param token Exact active mapping token.
     * @return True only after matching terminal sent completion.
     */
    [[nodiscard]] bool reduced_size_allowed(std::uint64_t token) const noexcept;

    /**
     * @brief Return whether the current mapping already has a compound in flight.
     *
     * @return True while aggregate completion remains outstanding.
     */
    [[nodiscard]] bool submission_pending() const noexcept;

  private:
    std::atomic<std::uint64_t> authority_token_ {};  ///< Exact active mapping token.
    std::atomic<std::uint64_t> in_flight_token_ {};  ///< Submitted compound awaiting completion.
    std::atomic<bool> sent_ {};  ///< Actual-sent authority for the active token.
  };

  /**
   * @brief Write one report-block-free RR plus stable SDES CNAME for input feedback authority.
   *
   * @param destination Caller-owned plaintext RTCP storage.
   * @param acknowledgement_ssrc Host LSPI/LSPG sender SSRC.
   * @param cname Stable association CNAME shared with other host RTCP sources.
   * @return Complete compound bytes, or zero for invalid fields or insufficient storage.
   */
  [[nodiscard]] std::size_t write_input_feedback_compound_report(
    std::span<std::uint8_t> destination,
    std::uint32_t acknowledgement_ssrc,
    const RtcpCname &cname
  ) noexcept;

  /** @brief Low-rate input receive-to-platform-apply latency observations. */
  struct InputLatencySnapshot {
    std::uint64_t samples {};  ///< Applied baseline/state/edge observations.
    std::uint64_t latest_microseconds {};  ///< Latest receive-to-apply duration.
    std::uint64_t maximum_microseconds {};  ///< Maximum receive-to-apply duration.
  };

  /** @brief Authenticated input-only session mapping installed by START_RESPONSE. */
  struct InputSessionMapping {
    PeerEndpoint peer;  ///< Exact authoritative DTLS/SRTP five-tuple.
    std::shared_ptr<HostForwardPath> forward_path;  ///< Exact aggregate host-to-client path generation.
    Identifier128 client_id {};  ///< Authenticated client identity.
    Identifier128 session_id {};  ///< Exact active stream-session identifier.
    std::uint32_t connection_generation {};  ///< Connection authority generation.
    std::uint32_t session_generation {};  ///< Stream-session generation.
    std::uint32_t input_generation {};  ///< Input authority generation.
    std::uint32_t input_ssrc {};  ///< Negotiated client input RTP SSRC.
    std::uint32_t acknowledgement_ssrc {};  ///< Host SRTCP LSPI sender SSRC.
    RtcpCname rtcp_cname {};  ///< Stable association CNAME for acknowledgement SSRC compound authority.
    std::uint8_t input_payload_type {};  ///< Negotiated dynamic LSP input payload type.
    std::uint32_t pointer_rate {};  ///< Negotiated aggregate pointer rate.
    std::uint32_t controller_rate {};  ///< Negotiated aggregate controller rate.
    std::uint32_t sensor_rate {};  ///< Negotiated aggregate sensor rate.
    std::uint32_t reconciliation_rate {};  ///< Negotiated aggregate reconciliation rate.
    std::uint64_t reserved_input_wire_bits_per_second {};  ///< Exact aggregate input budget.
    bool controller_output_enabled {};  ///< Whether current fresh authentication permits haptics and LED output.

    /** @brief Return whether every authority/mapping field is valid. */
    [[nodiscard]] bool valid() const noexcept;

    bool operator==(const InputSessionMapping &) const = default;
  };

  /** @brief Non-owning crypto and authority callbacks used by the input owner. */
  struct InputOwnerCallbacks {
    /** @brief Verify SHA-256 for one completed multipart baseline. */
    using VerifyDigest = bool (*)(
      void *context,
      std::span<const std::uint8_t> bytes,
      const Digest256 &expected
    ) noexcept;

    /** @brief Commit baseline authority before any normal input is applied. */
    using BaselineCommitted = bool (*)(
      void *context,
      const PeerEndpoint &peer,
      std::uint32_t session_generation,
      std::uint32_t input_generation
    ) noexcept;

    /** @brief Report that the accepted neutral baseline's urgent LSPI ACK entered aggregate output. */
    using BaselineAcknowledged = void (*)(
      void *context,
      const PeerEndpoint &peer,
      std::uint32_t session_generation,
      std::uint32_t input_generation
    ) noexcept;

    void *context {};  ///< Opaque callback context.
    VerifyDigest verify_digest {};  ///< Required baseline verifier.
    BaselineCommitted baseline_committed {};  ///< Required SessionAuthority commit callback.
    BaselineAcknowledged baseline_acknowledged {};  ///< Required replacement-readiness callback after ACK admission.
  };

  /**
   * @brief Dedicated bounded ordered owner for authenticated input RTP.
   */
  class InputOwner {
  public:
    /**
     * @brief Start the dedicated platform-apply worker.
     *
     * @param callbacks Baseline crypto and authority callbacks.
     * @param srtp Association provider that outlives this owner.
     */
    InputOwner(InputOwnerCallbacks callbacks, LibsrtpServerProvider &srtp) noexcept;
    InputOwner(const InputOwner &) = delete;
    InputOwner &operator=(const InputOwner &) = delete;
    /** @brief Neutralize held input, stop, and join the worker. */
    ~InputOwner();

    /**
     * @brief Install a fresh START-selected mapping and require a neutral baseline.
     *
     * @param mapping Exact authenticated mapping.
     * @return True after old input is neutralized and the new generation is installed.
     */
    bool configure(const InputSessionMapping &mapping) noexcept;

    /**
     * @brief Preflight whether `configure()` has no remaining fallible prerequisite.
     *
     * @param mapping Candidate fresh authority mapping.
     * @return True when the worker/platform owner is stable and the mapping is valid.
     */
    [[nodiscard]] bool ready_for_configuration(const InputSessionMapping &mapping) const noexcept;

    /**
     * @brief Commit a mapping previously accepted by `ready_for_configuration()`.
     *
     * This operation performs no allocation and has no failure return. The
     * caller must serialize the preflight and commit with session authority.
     *
     * @param mapping Preflighted fresh mapping.
     */
    void commit_configuration(const InputSessionMapping &mapping) noexcept;

    /**
     * @brief Validate SSRC/PT and enqueue one authenticated plaintext RTP packet.
     *
     * @param peer Exact receive five-tuple.
     * @param packet Complete decrypted RTP packet.
     * @param received_at_microseconds Socket receive timestamp, or zero to sample the host clock now.
     * @return True when accepted into the bounded ordered owner; unknown mappings are silent drops.
     */
    bool receive(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> packet,
      std::uint64_t received_at_microseconds = 0
    ) noexcept;

    /** @brief Process one authenticated negotiated SRTCP LSPG acknowledgement. */
    bool receive_rtcp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept;

    /**
     * @brief Permanently close producer admission and request the apply worker to stop.
     *
     * Completion callback storage remains alive until this owner is destroyed,
     * allowing the aggregate forward path to be drained safely afterward.
     */
    void begin_shutdown() noexcept;

    /** @brief Neutralize and remove the active mapping synchronously. */
    void neutralize() noexcept;

    /** @brief Return the active mapping, or no value when input authority is absent. */
    [[nodiscard]] std::optional<InputSessionMapping> mapping() const noexcept;

    /**
     * @brief Snapshot the greatest platform-applied state and contiguous edge watermark.
     *
     * @return Applied state sequence and edge identifier; both zero before baseline authority.
     */
    [[nodiscard]] std::pair<std::uint64_t, std::uint64_t> applied_watermark() const noexcept;

    /**
     * @brief Wait for one applied-edge barrier and inject a UTF-8/IME commit exactly once.
     *
     * @param session_id Exact active stream session.
     * @param input_generation Exact active input generation.
     * @param preceding_edge_id Greatest edge that must be contiguously applied.
     * @param utf8 Validated nonempty UTF-8 bytes.
     * @param deadline_microseconds Absolute monotonic control deadline.
     * @return Stable control status for generation, timeout, or platform disposition.
     */
    ControlStatus inject_text(
      const Identifier128 &session_id,
      std::uint32_t input_generation,
      std::uint64_t preceding_edge_id,
      std::span<const std::uint8_t> utf8,
      std::uint64_t deadline_microseconds
    ) noexcept;

    /**
     * @brief Install or remove one generation/device-qualified selected input rate without resetting state.
     *
     * An all-zero observed/state/sensor/packet-bounds tuple removes the exact ledger entry.
     *
     * @param request Exact authenticated device offer or removal tuple.
     * @return True only when authority and live device incarnation match.
     */
    [[nodiscard]] std::expected<InputRateResponsePayload, ControlStatus> configure_input_rate(
      const InputRateRequestPayload &request
    ) noexcept;

    /**
     * @brief Return measured final-sent complete IP/UDP bytes for host input feedback.
     *
     * @return Combined LSPI and LSPG charged bytes for the active owner lifetime.
     */
    [[nodiscard]] std::uint64_t sent_feedback_wire_bytes() const noexcept;

    /** @brief Return current receive-to-platform-apply latency observations. */
    [[nodiscard]] InputLatencySnapshot latency_snapshot() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden queue, state machine, and worker.
  };
}  // namespace lumen::lsp::runtime
