/**
 * @file src/protocol_lsp/runtime/video_sender.h
 * @brief Complete-access-unit LSP SDR H.264/HEVC RTP/SRTP sender ownership.
 */

#pragma once

#include "../../video_egress_queue.h"
#include "../media/common.h"
#include "control/wire.h"
#include "libsrtp_provider.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace lumen::lsp::runtime {
  /** @brief Immutable negotiated configuration for one first-slice LSP video source. */
  struct HostVideoSenderConfig {
    PeerEndpoint peer {};  ///< Exact authenticated DTLS/SRTP destination.
    VideoSelectionPayload video {};  ///< Frozen primary SSRC/PT/codec/extension selection.
    std::uint16_t initial_sequence {};  ///< Random initial RTP sequence number.
    std::uint32_t initial_timestamp {};  ///< Random nonzero initial 90 kHz timestamp.
    std::uint64_t frame_id_origin {};  ///< Random nonzero first frame ID.
    std::uint32_t maximum_access_unit_bytes {};  ///< Complete-AU bound, at most 16 MiB.
    std::uint32_t maximum_capture_to_present_microseconds {};  ///< Positive frame admission budget.
    std::uint64_t aggregate_pacing_bits_per_second {};  ///< Complete IP-layer pacing ceiling.
    media::ip_family family {media::ip_family::ipv4};  ///< Address family for complete wire accounting.
    safe::mail_t capture_mail;  ///< Local capture recovery and shutdown mailbox.
    bool reference_invalidation {};  ///< Whether pressure may invalidate references without IDR.

    /**
     * @brief Validate all sender, path, pacing, and recovery invariants.
     *
     * @return True only for the frozen first-slice tuple.
     */
    [[nodiscard]] bool valid() const noexcept;
  };

  /** @brief Lock-free coarse observations from the dedicated video sender. */
  struct HostVideoSenderSnapshot {
    std::uint64_t admitted_frames {};  ///< Complete access units admitted before first-packet send.
    std::uint64_t submitted_frames {};  ///< Frames whose complete primary RTP packet set was submitted.
    std::uint64_t submitted_packets {};  ///< RTP packets protected and submitted.
    std::uint64_t dropped_frames {};  ///< Whole frames dropped before first-packet submission.
    std::uint64_t submitted_wire_bytes {};  ///< Complete IP/UDP/SRTP bytes charged to pacing.
    std::uint64_t pressure_events {};  ///< Queue, admission, pacer, or socket pressure observations.
    std::uint8_t decoder_credit {};  ///< Latest validated client hardware-decoder credit.
    bool started {};  ///< Whether the sender worker started.
    bool closed {};  ///< Whether packet admission is closed.
    bool failed {};  ///< Whether a malformed frame or send failure stopped the worker.
  };

  /**
   * @brief One-session bounded video egress, packet-slab, pacer, and SRTP owner.
   *
   * Capture/encode publishes at most one unsent encoded access unit through `egress()`. The sender
   * owns one active frame, two preallocated complete-AU scratch slabs, one final RTP/SRTP slab, the
   * 90 kHz timeline, frame IDs, exact boundary extensions, and aggregate byte pacing. FEC and RTX
   * remain disabled without changing this ownership boundary.
   */
  class HostVideoSender final {
  public:
    /**
     * @brief Construct a stopped sender bound to one installed SRTP association.
     *
     * @param config Complete immutable selection and resource bounds.
     * @param srtp Association provider that outlives `close()` and `join()`.
     */
    HostVideoSender(HostVideoSenderConfig config, LibsrtpServerProvider &srtp) noexcept;

    HostVideoSender(const HostVideoSender &) = delete;
    HostVideoSender &operator=(const HostVideoSender &) = delete;

    /** @brief Close admission and join the sender before releasing fixed slabs. */
    ~HostVideoSender();

    /**
     * @brief Register the capacity-one egress queue and start the dedicated sender worker.
     *
     * @return True only when the complete sender became active.
     */
    bool start() noexcept;

    /**
     * @brief Return the typed capacity-one destination passed to `video::capture()`.
     *
     * @return Sender-owned bounded egress queue.
     */
    [[nodiscard]] video::egress_queue_t &egress() noexcept;

    /**
     * @brief Return the stable opaque key registered with the encoded-frame egress queue.
     *
     * @return Sender implementation identity for `video::capture()` channel data.
     */
    [[nodiscard]] void *session_key() noexcept;

    /**
     * @brief Update freshness-bounded decoder credit from authenticated `LSPV`.
     *
     * @param credit Available hardware submissions, zero through four.
     */
    void update_decoder_credit(std::uint8_t credit) noexcept;

    /** @brief Stop packet admission and wake the sender after capture has quiesced. */
    void close() noexcept;

    /** @brief Join the closed sender worker; safe to call repeatedly. */
    void join() noexcept;

    /**
     * @brief Return whether construction retained a valid configuration.
     *
     * @return True when `start()` may be attempted.
     */
    [[nodiscard]] bool ready() const noexcept;

    /**
     * @brief Read a lock-free lifecycle and counter snapshot.
     *
     * @return Current sender observations.
     */
    [[nodiscard]] HostVideoSenderSnapshot snapshot() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Hidden fixed-slab, packetizer, pacer, and worker owner.
  };
}  // namespace lumen::lsp::runtime
