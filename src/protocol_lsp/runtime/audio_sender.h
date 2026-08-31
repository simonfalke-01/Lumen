/**
 * @file src/protocol_lsp/runtime/audio_sender.h
 * @brief Production LSP host-audio RTP/SRTP sender ownership.
 */

#pragma once

#include "../../audio.h"
#include "../media/audio.h"
#include "libsrtp_provider.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace lumen::lsp::runtime {
  /** @brief Immutable negotiated configuration for one LSP host-audio source. */
  struct HostAudioSenderConfig {
    PeerEndpoint peer {};  ///< Exact authenticated DTLS/SRTP association five-tuple.
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
    std::uint64_t sent_packets {};  ///< RTP packets successfully protected and submitted.
    std::uint64_t sent_payload_octets {};  ///< Opus payload bytes successfully submitted.
    std::uint64_t expired_packets {};  ///< Stale queued packets discarded at their age bound.
    std::uint64_t backpressure_events {};  ///< Nonblocking enqueue attempts rejected by contention or capacity.
    std::uint64_t malformed_packets {};  ///< Empty, oversized, or invalid-timeline packets rejected by the sender.
    std::uint64_t send_failures {};  ///< RTP or SRTCP protection/submission failures.
    std::uint64_t sender_reports {};  ///< SRTCP sender reports successfully submitted.
    bool started {};  ///< Whether the sender worker was started.
    bool closed {};  ///< Whether packet admission has closed.
    bool failed {};  ///< Whether a protection or submission failure terminated the worker.
  };

  /**
   * @brief Nonblocking encoded-audio destination with a dedicated RTP/SRTP sender worker.
   *
   * The producer transfers already encoded Opus packets through `enqueue()`. The dedicated worker
   * owns RTP sequence/timestamp state, caller-owned RTP/RTCP buffers, SRTP calls, sender counters,
   * and periodic sender reports. No FEC, RTX, fragmentation, or socket operation executes on the
   * capture or Opus encoder thread.
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

    /** @brief Close admission, stop the worker, and join it before releasing state. */
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

    /** @brief Join the closed sender worker; safe to call repeatedly. */
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

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden queue, worker, timeline, and packet-storage owner.
  };
}  // namespace lumen::lsp::runtime
