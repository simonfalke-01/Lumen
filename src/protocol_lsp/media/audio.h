/**
 * @file src/protocol_lsp/media/audio.h
 * @brief RFC 7587 Opus RTP and one-packet preroll state for LSP/1.
 */

#pragma once

#include "common.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace lumen::lsp::media {
  /** @brief Maximum Opus packet bytes allowed by RFC 6716 and carried whole by RFC 7587. */
  inline constexpr std::size_t maximum_opus_packet_size = 1'275;

  /** @brief Valid LSP/1 Opus frame durations expressed in 48 kHz RTP clock samples. */
  enum class opus_frame_samples : std::uint16_t {
    ms_2_5 = 120,  ///< 2.5 milliseconds.
    ms_5 = 240,  ///< 5 milliseconds, preferred by competition mode.
    ms_10 = 480,  ///< 10 milliseconds.
    ms_20 = 960,  ///< 20 milliseconds.
  };

  /**
   * @brief Return whether a sample count is one negotiated LSP/1 Opus duration.
   *
   * @param samples Audio samples at the 48 kHz RTP clock.
   * @return `true` for 120, 240, 480, or 960 samples.
   */
  [[nodiscard]] constexpr bool valid_opus_frame_samples(const std::uint16_t samples) noexcept {
    return samples == static_cast<std::uint16_t>(opus_frame_samples::ms_2_5) ||
           samples == static_cast<std::uint16_t>(opus_frame_samples::ms_5) ||
           samples == static_cast<std::uint16_t>(opus_frame_samples::ms_10) ||
           samples == static_cast<std::uint16_t>(opus_frame_samples::ms_20);
  }

  /** @brief RTP metadata assigned to the next complete Opus packet. */
  struct opus_packet_timing {
    std::uint32_t timestamp = 0;  ///< Timestamp of the packet's first audio sample.
    bool marker = false;  ///< RFC 7587 talkspurt marker bit.
  };

  /** @brief Sender-side continuous 48 kHz Opus timeline and talkspurt-marker state. */
  class opus_sender_timeline {
  public:
    /**
     * @brief Construct a timeline at a mandatory random initial RTP timestamp.
     *
     * @param initial_timestamp Initial 48 kHz RTP timestamp.
     */
    explicit constexpr opus_sender_timeline(const std::uint32_t initial_timestamp) noexcept:
        next_timestamp_(initial_timestamp) {
    }

    /**
     * @brief Prepare one complete Opus packet and advance the continuous timeline.
     *
     * The first packet and first packet after a discontinuity carry the RFC 7587 talkspurt marker.
     *
     * @param samples Negotiated packet duration in 48 kHz samples.
     * @return Packet timing, or an empty result when the duration is invalid.
     */
    [[nodiscard]] constexpr std::optional<opus_packet_timing> prepare(const std::uint16_t samples) noexcept {
      if (!valid_opus_frame_samples(samples)) {
        return std::nullopt;
      }
      const opus_packet_timing timing {.timestamp = next_timestamp_, .marker = marker_pending_};
      next_timestamp_ += samples;
      marker_pending_ = false;
      return timing;
    }

    /**
     * @brief Reset sample continuity and mark the next packet as a new talkspurt.
     *
     * @param next_timestamp Timestamp assigned to the next packet.
     */
    constexpr void discontinuity(const std::uint32_t next_timestamp) noexcept {
      next_timestamp_ = next_timestamp;
      marker_pending_ = true;
    }

    /**
     * @brief Return the timestamp that will be assigned to the next packet.
     *
     * @return Next 48 kHz RTP timestamp.
     */
    [[nodiscard]] constexpr std::uint32_t next_timestamp() const noexcept {
      return next_timestamp_;
    }

  private:
    std::uint32_t next_timestamp_ = 0;  ///< Timestamp assigned to the next Opus packet.
    bool marker_pending_ = true;  ///< Whether the next packet begins a talkspurt.
  };

  /** @brief Complete configuration for one RFC 7587 Opus RTP packet. */
  struct opus_packetization_config {
    rtp_stream_config stream {};  ///< RTP stream fields, including packet sampling timestamp.
    path_payload_limit path {};  ///< Validated complete protected UDP payload limit.
    bool marker = false;  ///< RFC 7587 talkspurt marker supplied by `opus_sender_timeline`.
  };

  /** @brief Allocation-free RFC 7587 RTP packet write result. */
  struct opus_packet_write_result {
    std::size_t bytes_written = 0;  ///< Complete plaintext RTP bytes written on success.
    packetization_error error = packetization_error::none;  ///< Packetization status.

    /**
     * @brief Return whether the complete packet was written.
     *
     * @return `true` only when `error` is `packetization_error::none`.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == packetization_error::none;
    }
  };

  /**
   * @brief Write one complete Opus packet into caller-owned RFC 7587 RTP storage.
   *
   * The function performs no allocation, fragmentation, FEC, or RTX construction. The destination
   * contains plaintext RTP and must retain room outside the returned span for the SRTP provider's
   * authentication tag.
   *
   * @param opus_packet Complete encoded Opus packet.
   * @param config RTP, path-payload, and talkspurt-marker configuration.
   * @param destination Caller-owned plaintext RTP storage.
   * @return Complete byte count and typed failure.
   */
  [[nodiscard]] constexpr opus_packet_write_result write_opus_rtp_packet(
    const std::span<const std::uint8_t> opus_packet,
    const opus_packetization_config &config,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (opus_packet.empty()) {
      return {.error = packetization_error::empty_codec_unit};
    }
    if (opus_packet.size() > maximum_opus_packet_size) {
      return {.error = packetization_error::codec_unit_too_large};
    }
    if (!valid_dynamic_payload_type(config.stream.payload_type) || config.stream.ssrc == 0 ||
        config.path.udp_payload_size < initial_udp_payload_size ||
        config.path.udp_payload_size > (config.path.family == ip_family::ipv4 ? ipv4_udp_payload_ceiling : ipv6_udp_payload_ceiling)) {
      return {.error = packetization_error::invalid_rtp_configuration};
    }
    const auto packet_size = rtp_fixed_header_size + opus_packet.size();
    if (packet_size + srtp_aead_tag_size > config.path.udp_payload_size) {
      return {.error = packetization_error::packet_exceeds_path};
    }
    if (destination.size() < packet_size) {
      return {.error = packetization_error::packet_exceeds_path};
    }
    const rtp_fixed_header header {
      .padding = false,
      .extension = false,
      .marker = config.marker,
      .payload_type = config.stream.payload_type,
      .csrc_count = 0,
      .sequence_number = config.stream.first_sequence_number,
      .timestamp = config.stream.timestamp,
      .ssrc = config.stream.ssrc,
    };
    const auto header_result = write_rtp_fixed_header(header, {}, destination.first(packet_size));
    if (!header_result) {
      return {.error = packetization_error::invalid_rtp_configuration};
    }
    std::ranges::copy(
      opus_packet,
      destination.begin() + static_cast<std::ptrdiff_t>(rtp_fixed_header_size)
    );
    return {.bytes_written = packet_size};
  }

  /**
   * @brief Packetize one complete Opus packet into exactly one RFC 7587 RTP packet.
   *
   * LSP audio and microphone packets are never fragmented and have no RTX representation.
   *
   * @param opus_packet Complete encoded Opus packet.
   * @param config RTP, path-payload, and talkspurt-marker configuration.
   * @return A one-packet result or typed failure.
   */
  [[nodiscard]] inline packetization_result packetize_opus(
    const std::span<const std::uint8_t> opus_packet,
    const opus_packetization_config &config
  ) {
    packetization_result result;
    result.next_sequence_number = config.stream.first_sequence_number;
    const auto packet_size = rtp_fixed_header_size + opus_packet.size();
    rtp_packet packet;
    packet.role = frame_packet_role::first_and_final;
    packet.bytes.resize(packet_size);
    const auto written = write_opus_rtp_packet(opus_packet, config, packet.bytes);
    if (!written) {
      result.error = written.error;
      return result;
    }
    result.packets.push_back(std::move(packet));
    ++result.next_sequence_number;
    return result;
  }

  /** @brief Receiver action selected by one-packet Opus preroll state. */
  enum class audio_preroll_action : std::uint8_t {
    hold,  ///< Retain this packet as the one-packet initial preroll.
    start_playout,  ///< Release the retained preroll and this contiguous packet to start playout.
    continue_playout,  ///< Decode and enqueue this contiguous packet during active playout.
    reset_and_hold,  ///< Discard prior continuity and retain this packet as a new preroll.
    invalid_duration,  ///< Reject a packet duration outside the negotiated LSP set.
  };

  /** @brief Receiver-side one-packet initial preroll and discontinuity tracker. */
  class audio_preroll_state {
  public:
    /**
     * @brief Observe one authenticated Opus packet in RTP timestamp order.
     *
     * @param timestamp Packet's first-sample RTP timestamp.
     * @param samples Packet duration in 48 kHz samples.
     * @param discontinuity Explicit configuration or source discontinuity.
     * @return Required preroll/playout action.
     */
    [[nodiscard]] constexpr audio_preroll_action observe(
      const std::uint32_t timestamp,
      const std::uint16_t samples,
      const bool discontinuity = false
    ) noexcept {
      if (!valid_opus_frame_samples(samples)) {
        return audio_preroll_action::invalid_duration;
      }
      if (discontinuity || state_ == state::empty || timestamp != expected_timestamp_) {
        const auto action = state_ == state::empty && !discontinuity ? audio_preroll_action::hold : audio_preroll_action::reset_and_hold;
        state_ = state::primed;
        expected_timestamp_ = timestamp + samples;
        return action;
      }
      expected_timestamp_ = timestamp + samples;
      if (state_ == state::primed) {
        state_ = state::playing;
        return audio_preroll_action::start_playout;
      }
      return audio_preroll_action::continue_playout;
    }

    /** @brief Reset active playout so the next packet becomes the one-packet preroll. */
    constexpr void reset() noexcept {
      state_ = state::empty;
      expected_timestamp_ = 0;
    }

    /**
     * @brief Return whether the receiver has crossed its initial one-packet preroll.
     *
     * @return `true` only during active playout.
     */
    [[nodiscard]] constexpr bool playing() const noexcept {
      return state_ == state::playing;
    }

  private:
    /** @brief Internal preroll lifecycle. */
    enum class state : std::uint8_t {
      empty,  ///< No packet is retained.
      primed,  ///< Exactly one packet is retained as preroll.
      playing,  ///< Playout has started and continuity is active.
    };

    state state_ = state::empty;  ///< Current preroll lifecycle.
    std::uint32_t expected_timestamp_ = 0;  ///< First-sample timestamp required from the next packet.
  };
}  // namespace lumen::lsp::media
