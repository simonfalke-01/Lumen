/**
 * @file src/protocol_lsp/runtime/audio_sender.h
 * @brief Production LSP host-audio RTP/SRTP sender ownership.
 */

#pragma once

#include "../../audio.h"
#include "../media/audio.h"
#include "host_forward_path.h"
#include "libsrtp_provider.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace lumen::lsp::runtime {
  /** @brief Immutable negotiated configuration for one LSP host-audio source. */
  struct HostAudioSenderConfig {
    PeerEndpoint peer {};  ///< Exact authenticated DTLS/SRTP association five-tuple.
    std::shared_ptr<HostForwardPath> forward_path;  ///< Generation-owned aggregate final-send path.
    std::uint32_t forward_path_generation {};  ///< Exact connection/path authority generation.
    std::uint32_t ssrc {};  ///< Random nonzero host audio SSRC.
    std::uint8_t payload_type {};  ///< Negotiated dynamic Opus RTP payload type.
    std::uint16_t initial_sequence {};  ///< Random nonzero initial RTP sequence number.
    std::uint32_t initial_timestamp {};  ///< Random nonzero timestamp corresponding to the first encoded sample.
    std::uint16_t frame_samples {static_cast<std::uint16_t>(media::opus_frame_samples::ms_5)};  ///< Fixed Opus duration at 48 kHz.
    media::path_payload_limit path {};  ///< Current authenticated protected UDP payload bound.
    std::size_t queue_capacity {2};  ///< Encoded-packet ring capacity in the closed range `1...8`.
    std::uint64_t maximum_queue_age_microseconds {10'000};  ///< Packet age deadline before stale audio is discarded.
    std::uint64_t sender_report_interval_microseconds {1'000'000};  ///< Periodic RFC 3550 SRTCP sender-report cadence.

    /**
     * @brief Validate sender, path, timeline, and bounded-queue invariants.
     *
     * @return `true` only when the sender can be started safely.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /** @brief Snapshot of host-audio sender admission, expiry, media, and RTCP counters. */
  struct HostAudioSenderSnapshot {
    std::uint64_t enqueued_packets {};  ///< Packets accepted by the bounded queue.
    std::uint64_t sent_packets {};  ///< RTP packets accepted by the final kernel send.
    std::uint64_t sent_payload_octets {};  ///< Opus payload bytes accepted by the final kernel send.
    std::uint64_t expired_packets {};  ///< Queued or committed RTP packets discarded at their original age bound.
    std::uint64_t backpressure_events {};  ///< Enqueue or aggregate-path capacity pressure observations.
    std::uint64_t malformed_packets {};  ///< Empty, oversized, or invalid-timeline packets rejected by the sender.
    std::uint64_t send_failures {};  ///< Fatal RTP/SRTCP protection or aggregate-path failures.
    std::uint64_t sender_reports {};  ///< SRTCP sender reports accepted by the final kernel send.
    bool started {};  ///< Whether the sender worker was started.
    bool closed {};  ///< Whether packet admission has closed.
    bool failed {};  ///< Whether a protection or submission failure terminated the worker.
  };

  /**
   * @brief Nonblocking encoded-audio destination with a dedicated RTP/SRTP sender worker.
   *
   * The producer transfers already encoded Opus packets through `enqueue()`. The dedicated worker
   * owns RTP sequence/timestamp state, direct-write aggregate-path leases, SRTP calls, sender
   * counters, and periodic sender reports. No FEC, RTX, fragmentation, or socket operation executes
   * on the capture or Opus encoder thread.
   */
  class HostAudioSender final: public audio::AudioPacketDestination {
  public:
    /**
     * @brief Construct a stopped sender bound to an existing SRTP provider.
     *
     * @param config Complete negotiated host-audio configuration.
     * @param srtp Installed association provider that outlives `close()` and `join()`.
     */
    HostAudioSender(HostAudioSenderConfig config, LibsrtpServerProvider &srtp) noexcept;

    HostAudioSender(const HostAudioSender &) = delete;
    HostAudioSender &operator=(const HostAudioSender &) = delete;

    /** @brief Close admission, stop the worker, and drain path completions before releasing state. */
    ~HostAudioSender() override;

    /**
     * @brief Start the dedicated sender worker exactly once.
     *
     * @return `true` only when configuration is valid and the worker was created.
     */
    bool start() noexcept;

    /** @copydoc audio::AudioPacketDestination::enqueue */
    [[nodiscard]] enqueue_result_e enqueue(audio::packet_t packet) override;

    /** @copydoc audio::AudioPacketDestination::close */
    void close() noexcept override;

    /** @brief Join the closed sender worker and wait for every committed datagram completion. */
    void join() noexcept;

    /**
     * @brief Return whether construction retained a valid production configuration.
     *
     * @return `true` before or after start when the immutable configuration is valid.
     */
    [[nodiscard]] bool ready() const noexcept;

    /**
     * @brief Read a lock-free counter and lifecycle snapshot.
     *
     * @return Current sender observations.
     */
    [[nodiscard]] HostAudioSenderSnapshot snapshot() const noexcept;

    /**
     * @brief Apply one asynchronous aggregate-path terminal disposition from a fallback dispatcher.
     *
     * Normal commits install a direct producer target. This entry point remains
     * available to generation-level fatal dispatch and compatibility callers.
     *
     * @param token Sender-local committed datagram token.
     * @param completion Final path disposition.
     * @param completed_at_microseconds Monotonic kernel completion time.
     * @param protected_bytes Exact protected UDP payload bytes.
     * @param charged_bytes Complete IP/UDP bytes charged once.
     * @return `true` only when this sender owned the token.
     */
    bool complete_forward_datagram(
      std::uint64_t token,
      HostForwardCompletion completion,
      std::uint64_t completed_at_microseconds,
      std::size_t protected_bytes,
      std::uint16_t charged_bytes
    ) noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden queue, worker, timeline, and packet-storage owner.
  };
}  // namespace lumen::lsp::runtime
