/**
 * @file src/protocol_lsp/runtime/microphone_receiver.h
 * @brief Authenticated LSP reverse-microphone RTP receive and platform-injection owner.
 */

#pragma once

#include "../../client_microphone.h"
#include "../transport/rtcp.h"
#include "../types.h"
#include "host_forward_path.h"
#include "libsrtp_provider.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace lumen::lsp::runtime {
  /** @brief Exact RFC 3550 report-block state for the reverse microphone source. */
  struct MicrophoneReceiverReportState {
    std::uint32_t media_ssrc {};  ///< Negotiated microphone source SSRC.
    std::uint32_t extended_highest_sequence {};  ///< Highest received extended RTP sequence.
    std::uint32_t interarrival_jitter {};  ///< RFC 3550 jitter in 48 kHz timestamp units.
    std::uint32_t last_sender_report {};  ///< Middle 32 bits of the latest valid sender-report NTP timestamp.
    std::uint32_t delay_since_sender_report {};  ///< Delay since SR in 1/65536-second units.
    std::int32_t cumulative_lost {};  ///< Signed cumulative loss clamped to the RTCP 24-bit field.
    std::uint8_t fraction_lost {};  ///< Interval loss fraction in 1/256 units.
  };

  /**
   * @brief Serialize the fixed regular microphone RR plus SDES/CNAME compound packet.
   *
   * @param destination Output storage containing at least 36 bytes.
   * @param feedback_ssrc Nonzero host RTCP feedback sender SSRC.
   * @return Exact 36-byte packet size, or zero on invalid input.
   */
  [[nodiscard]] std::size_t write_microphone_compound_report(
    std::span<std::uint8_t> destination,
    std::uint32_t feedback_ssrc,
    const MicrophoneReceiverReportState &report,
    std::span<const std::uint8_t> cname
  ) noexcept;

  /** @brief Compatibility serializer using an empty report block and fixed test CNAME. */
  [[nodiscard]] std::size_t write_microphone_compound_report(
    std::span<std::uint8_t> destination,
    std::uint32_t feedback_ssrc
  ) noexcept;

  /**
   * @brief Serialize one received microphone packet as reduced RFC 8888 feedback.
   *
   * @param destination Output storage containing at least 24 bytes.
   * @param feedback_ssrc Nonzero host RTCP feedback sender SSRC.
   * @param microphone_ssrc Nonzero negotiated microphone media SSRC.
   * @param sequence Received microphone RTP sequence.
   * @param report_timestamp Middle-NTP report timestamp.
   * @return Exact 24-byte packet size, or zero on invalid input.
   */
  [[nodiscard]] std::size_t write_microphone_congestion_report(
    std::span<std::uint8_t> destination,
    std::uint32_t feedback_ssrc,
    std::uint32_t microphone_ssrc,
    std::uint16_t sequence,
    std::uint32_t report_timestamp
  ) noexcept;

  /**
   * @brief Serialize one gap-preserving RFC 8888 microphone feedback block.
   *
   * @param destination Bounded output storage.
   * @param feedback_ssrc Nonzero host feedback sender SSRC.
   * @param batch Borrowed authenticated sequence range including gaps.
   * @param report_timestamp Middle-32-bit NTP report timestamp.
   * @return Exact aligned packet bytes, or zero when bounds are invalid.
   */
  [[nodiscard]] std::size_t write_microphone_congestion_report(
    std::span<std::uint8_t> destination,
    std::uint32_t feedback_ssrc,
    const transport::reordering_congestion_report_batch &batch,
    std::uint32_t report_timestamp
  ) noexcept;

  /** @brief Exact acknowledged reverse-microphone RTP mapping. */
  struct MicrophoneReceiverConfig {
    PeerEndpoint peer {};  ///< Authenticated client association.
    std::uint32_t generation {};  ///< Nonzero microphone configuration generation.
    std::uint32_t ssrc {};  ///< Negotiated client microphone SSRC.
    std::uint8_t payload_type {};  ///< Negotiated dynamic Opus payload type.
    std::uint32_t clock_rate {48'000};  ///< Required Opus RTP clock.
    std::uint8_t channels {1};  ///< Required mono channel count.
    std::uint16_t frame_samples {960};  ///< Required 20 ms frame size.
    std::shared_ptr<HostForwardPath> forward_path;  ///< Active host aggregate feedback path.
    std::uint32_t forward_path_generation {};  ///< Exact connection/path authority generation.
    std::uint32_t feedback_ssrc {};  ///< Host RTCP receiver/CCFB sender SSRC.
    RtcpCname rtcp_cname {};  ///< Stable host-unique association CNAME for receiver reports.
    bool inband_fec {};  ///< Whether following packets may repair one missing frame.
    bool dtx {};  ///< Whether the sender may emit Opus DTX packets.

    /** @brief Return whether every fixed LSP microphone invariant is valid. */
    [[nodiscard]] bool valid() const noexcept;
  };

  /** @brief LSP microphone packet, RTCP, and parser counters. */
  struct MicrophoneReceiverSnapshot {
    std::uint64_t accepted_rtp_packets {};  ///< Opus RTP packets admitted to the bounded receiver.
    std::uint64_t authenticated_rtp_packets {};  ///< Structurally valid packets received after SRTP authentication.
    std::uint64_t reportable_rtp_packets {};  ///< Packets represented by new/overlap RFC 8888 state.
    std::uint64_t playout_rtp_packets {};  ///< Packets accepted by the clocked microphone playout owner.
    std::uint64_t rejected_rtp_packets {};  ///< Stale, malformed, or out-of-window RTP packets.
    std::uint64_t sender_reports {};  ///< Valid reverse sender reports for the microphone SSRC.
    std::uint64_t receiver_reports {};  ///< Protected compound receiver reports submitted.
    std::uint64_t congestion_reports {};  ///< Protected RFC 8888 feedback packets submitted.
    client_microphone::statistics_t playout {};  ///< Bounded jitter/FEC/PLC/sink counters.
    bool active {};  ///< Whether writer, decoder, and platform sink are active.
  };

  /** @brief Generation-qualified LSP microphone writer and clocked receiver owner. */
  class LspMicrophoneReceiver {
  public:
    /**
     * @brief Create and begin a real generation-qualified microphone receiver.
     *
     * @param config Exact acknowledged microphone mapping.
     * @param sink Probed platform virtual microphone sink.
     * @param srtp Installed association provider that outlives this receiver.
     * @return Active owner, or null when writer, decoder, or sink initialization fails.
     */
    [[nodiscard]] static std::unique_ptr<LspMicrophoneReceiver> create(
      MicrophoneReceiverConfig config,
      std::unique_ptr<client_microphone::sink_t> sink,
      LibsrtpServerProvider &srtp
    ) noexcept;

    LspMicrophoneReceiver(const LspMicrophoneReceiver &) = delete;
    LspMicrophoneReceiver &operator=(const LspMicrophoneReceiver &) = delete;

    /** @brief Stop, join, release the exact writer, and destroy platform state. */
    ~LspMicrophoneReceiver();

    /**
     * @brief Submit one authenticated and decrypted RFC 7587 RTP packet.
     *
     * @param peer Exact received association.
     * @param packet Plaintext RTP packet.
     * @param protected_bytes Authenticated UDP payload size before unprotection.
     * @param received_at_microseconds Original monotonic socket receive time.
     * @param ecn Authenticated IP-layer ECN observation.
     * @return True for an accepted or safely dropped media packet.
     */
    bool receive_rtp(
      const PeerEndpoint &peer,
      std::span<const std::uint8_t> packet,
      std::size_t protected_bytes,
      std::uint64_t received_at_microseconds,
      IpEcn ecn
    ) noexcept;

    /**
     * @brief Parse reverse RTCP sender reports independently from RTP media.
     *
     * @param peer Exact received association.
     * @param packet Plaintext RTCP datagram.
     * @return True for a valid report datagram or an unrelated valid RTCP packet.
     */
    bool receive_rtcp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept;

    /** @brief End platform writes and release writer authority, retaining callback and joinable worker storage. */
    void stop() noexcept;

    /** @brief Stop authority, drain feedback completions, and permanently join playout. */
    void shutdown() noexcept;

    /** @brief Return current parser and playout observations. */
    [[nodiscard]] MicrophoneReceiverSnapshot snapshot() const noexcept;

    /** @brief Return the exact configured association. */
    [[nodiscard]] const PeerEndpoint &peer() const noexcept;

    /** @brief Return the exact active microphone generation. */
    [[nodiscard]] std::uint32_t generation() const noexcept;

  private:
    class Impl;
    explicit LspMicrophoneReceiver(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;  ///< Hidden sequence, decoder, sink, and writer ownership.
  };
}  // namespace lumen::lsp::runtime
