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
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

namespace lumen::lsp::runtime {
  /** @brief Maximum active forward-media SSRC blocks admitted in one RFC 8888 packet. */
  inline constexpr std::size_t maximum_congestion_feedback_blocks = 8;

  /** @brief One validated RFC 8888 per-SSRC report block backed by the input packet. */
  struct CongestionFeedbackBlockView {
    std::uint32_t media_ssrc {};  ///< Active forward-media SSRC.
    std::uint16_t begin_sequence {};  ///< First sequence in the Errata 8166 half-open range.
    std::uint16_t report_count {};  ///< Exact number of following 16-bit metrics.
    std::span<const std::uint8_t> metrics {};  ///< Exact metrics excluding any odd-count zero pad.
  };

  /** @brief Bounded validated RFC 8888 feedback packet backed by caller-owned bytes. */
  struct CongestionFeedbackPacketView {
    std::array<CongestionFeedbackBlockView, maximum_congestion_feedback_blocks> blocks {};  ///< Ordered SSRC blocks.
    std::size_t block_count {};  ///< Populated leading block views.
    std::uint32_t report_timestamp {};  ///< Final middle-32-bit NTP report timestamp.
  };

  /** @brief Product admission result for negotiated video/audio RFC 8888 blocks. */
  enum class CongestionFeedbackContent : std::uint8_t {
    invalid,  ///< A block names an unnegotiated SSRC or configuration is invalid.
    audio_only,  ///< Packet contains only the active audio block and no video accounting.
    video,  ///< Packet contains the active video block, with or without active audio.
  };

  /**
   * @brief Classify structurally validated blocks against active host video/audio SSRCs.
   *
   * @param packet Validated multi-block feedback view.
   * @param video_ssrc Active primary-video SSRC.
   * @param audio_ssrc Active host-audio SSRC.
   * @return Invalid, audio-only cadence, or video-ledger content.
   */
  [[nodiscard]] constexpr CongestionFeedbackContent classify_congestion_feedback_content(
    const CongestionFeedbackPacketView &packet,
    const std::uint32_t video_ssrc,
    const std::uint32_t audio_ssrc
  ) noexcept {
    if (packet.block_count == 0 || packet.block_count > packet.blocks.size() ||
        video_ssrc == 0 || audio_ssrc == 0 || video_ssrc == audio_ssrc) {
      return CongestionFeedbackContent::invalid;
    }
    bool has_video = false;
    bool has_audio = false;
    for (std::size_t index = 0; index < packet.block_count; ++index) {
      if (packet.blocks[index].media_ssrc == video_ssrc) {
        has_video = true;
      } else if (packet.blocks[index].media_ssrc == audio_ssrc) {
        has_audio = true;
      } else {
        return CongestionFeedbackContent::invalid;
      }
    }
    if (has_video) {
      return CongestionFeedbackContent::video;
    }
    return has_audio ? CongestionFeedbackContent::audio_only : CongestionFeedbackContent::invalid;
  }

  /**
   * @brief Parse every exact RFC 8888 block without allocating or interpreting delivery bytes.
   *
   * @param packet Complete plaintext RTCP congestion-feedback packet.
   * @param expected_sender_ssrc Negotiated RTCP feedback sender SSRC.
   * @return Validated block/timestamp views, or no value on any structural mismatch.
   */
  [[nodiscard]] std::optional<CongestionFeedbackPacketView> parse_congestion_feedback_packet(
    std::span<const std::uint8_t> packet,
    std::uint32_t expected_sender_ssrc
  ) noexcept;

  /** @brief Relationship of one protected RTP payload to its frame-boundary confirmed path limit. */
  enum class PathPacketSizeClass : std::uint8_t {
    invalid,  ///< Packet or confirmed limit is invalid, or packet exceeds its generation limit.
    smaller,  ///< Authenticated packet is smaller than its generation's confirmed limit.
    confirmed_size,  ///< Packet exactly exercises its generation's confirmed limit.
  };

  /**
   * @brief Classify PMTU evidence relative to the confirmed limit active when the packet was sent.
   *
   * @param udp_payload_bytes Exact protected RTP UDP payload.
   * @param confirmed_payload_bytes Generation-local confirmed UDP payload limit.
   * @return Invalid, smaller proof, or exact confirmed-size exercise.
   */
  [[nodiscard]] constexpr PathPacketSizeClass classify_path_packet_size(
    const std::uint16_t udp_payload_bytes,
    const std::uint16_t confirmed_payload_bytes
  ) noexcept {
    if (udp_payload_bytes == 0 || confirmed_payload_bytes < 1'200 ||
        udp_payload_bytes > confirmed_payload_bytes) {
      return PathPacketSizeClass::invalid;
    }
    return udp_payload_bytes == confirmed_payload_bytes ?
             PathPacketSizeClass::confirmed_size : PathPacketSizeClass::smaller;
  }

  /**
   * @brief Parse one authenticated plaintext SRTCP APP `LSPP` probe.
   *
   * @param packet Complete plaintext RTCP APP packet after SRTCP authentication.
   * @param protected_bytes Original protected UDP payload size.
   * @param expected_sender_ssrc Negotiated sender SSRC for this direction.
   * @return Exact probe identifier and declared protected size, or no value on any mismatch.
   */
  [[nodiscard]] std::optional<PathProbePayload> parse_path_probe_datagram(
    std::span<const std::uint8_t> packet,
    std::size_t protected_bytes,
    std::uint32_t expected_sender_ssrc
  ) noexcept;

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
    std::uint64_t reserved_overhead_bits_per_second {};  ///< Audio/control/repair rate excluded from encoder target.
    std::uint16_t path_payload_ceiling {1'200};  ///< Negotiated family/operator DPLPMTUD ceiling.
    std::uint32_t feedback_sender_ssrc {};  ///< Negotiated client input SSRC used by RTCP feedback.
    std::uint32_t audio_feedback_ssrc {};  ///< Active host-audio SSRC admitted but not accounted by this video owner.
    VideoNetworkProfile network_profile {VideoNetworkProfile::adaptive_low_latency};  ///< Negotiated controller profile.
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
    std::uint16_t current_path_payload {};  ///< Confirmed UDP payload used at frame boundaries.
    std::uint64_t pacing_bits_per_second {};  ///< Current aggregate complete-IP pacing target.
    std::uint64_t encoder_bits_per_second {};  ///< Current frame-boundary encoder target.
    std::uint64_t feedback_reports {};  ///< Accepted authenticated RFC 8888 reports.
    std::uint64_t feedback_rejections {};  ///< Malformed, stale, or hostile RFC 8888 reports.
    std::uint64_t feedback_delivered_bytes {};  ///< Newly accounted complete IP-layer delivered bytes.
    std::uint64_t feedback_lost_bytes {};  ///< Newly accounted complete IP-layer lost bytes.
    std::uint64_t path_probe_datagrams {};  ///< Freshly protected SRTCP LSPP transmissions.
    std::uint64_t path_probe_retries {};  ///< PROBE_TIMER retries with a new SRTCP index.
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

    /** @brief Begin one authenticated host path-probe state transition. */
    [[nodiscard]] std::optional<PathProbePayload> begin_path_probe(
      std::uint64_t probe_id,
      std::uint64_t now_microseconds,
      std::uint64_t probe_interval_microseconds
    ) noexcept;

    /** @brief Protect and submit one exact-size application-data-free SRTCP `LSPP`. */
    bool send_path_probe(const PathProbePayload &probe, std::uint64_t now_microseconds) noexcept;

    /** @brief Commit one reliable ACK and publish the larger payload at the next frame boundary. */
    bool acknowledge_path_probe(const PathProbePayload &probe) noexcept;

    /** @brief Roll back a candidate whose reliable control intent could not start. */
    bool rollback_path_probe(const PathProbePayload &probe) noexcept;

    /** @brief Retire a peer-rejected candidate without closing the authenticated association. */
    bool reject_path_probe(const PathProbePayload &probe) noexcept;

    /** @brief Drive bounded local-send retry and RFC 8899 PROBE_TIMER state. */
    bool tick_path_probe(std::uint64_t now_microseconds, std::uint64_t probe_interval_microseconds) noexcept;

    /** @brief Return the outstanding logical path probe, or no value. */
    [[nodiscard]] std::optional<PathProbePayload> outstanding_path_probe() const noexcept;

    /** @brief Apply independent black-hole evidence and request 1,200 bytes at the next frame boundary. */
    bool confirm_path_black_hole() noexcept;

    /** @brief Validate a regular compound RTCP report and SDES CNAME prerequisite. */
    bool receive_compound_rtcp(std::span<const std::uint8_t> packet, std::uint64_t now_microseconds) noexcept;

    /** @brief Parse authenticated RFC 8888 CCFB and update independent forward congestion state. */
    bool receive_congestion_feedback(std::span<const std::uint8_t> packet, std::uint64_t now_microseconds) noexcept;

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
