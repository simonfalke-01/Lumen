/**
 * @file src/protocol_lsp/media/common.h
 * @brief Common dependency-free RTP media packetization primitives for LSP/1.
 */

#pragma once

#include "../core/rtp.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>
#include <vector>

namespace lumen::lsp::media {
  /** @brief RTP clock rate used by every LSP video lane. */
  inline constexpr std::uint32_t video_clock_rate = 90'000;

  /** @brief RTP clock rate used by LSP host-audio and microphone lanes. */
  inline constexpr std::uint32_t audio_clock_rate = 48'000;

  /** @brief Initial path-safe UDP payload used before authenticated DPLPMTUD growth. */
  inline constexpr std::size_t initial_udp_payload_size = 1'200;

  /** @brief Largest conforming UDP payload on a standard 1,500-byte IPv4 path. */
  inline constexpr std::size_t ipv4_udp_payload_ceiling = 1'472;

  /** @brief Largest conforming UDP payload on a standard 1,500-byte IPv6 path. */
  inline constexpr std::size_t ipv6_udp_payload_ceiling = 1'452;

  /** @brief Authentication-tag bytes added by the required SRTP AEAD AES-128-GCM profile. */
  inline constexpr std::size_t srtp_aead_tag_size = 16;

  /**
   * @brief Return whether a payload type is in LSP's dynamic RTP/RTCP-mux-safe range.
   *
   * @param payload_type Negotiated seven-bit RTP payload type.
   * @return `true` for dynamic payload types `96...127`.
   */
  [[nodiscard]] constexpr bool valid_dynamic_payload_type(const std::uint8_t payload_type) noexcept {
    return payload_type >= 96U && payload_type <= 127U;
  }

  /** @brief IP family controlling the conforming LSP/1 path-payload ceiling. */
  enum class ip_family : std::uint8_t {
    ipv4,  ///< IPv4 with a 1,472-byte standard-Ethernet UDP payload ceiling.
    ipv6,  ///< IPv6 with a 1,452-byte standard-Ethernet UDP payload ceiling.
  };

  /** @brief Typed path-payload validation failure. */
  enum class path_payload_error : std::uint8_t {
    none,  ///< The proposed path payload is conforming.
    below_initial_safe_size,  ///< The proposed value is below LSP/1's 1,200-byte payload floor.
    above_family_ceiling,  ///< The proposed value exceeds the selected IP family's Ethernet ceiling.
  };

  /** @brief Validated maximum complete UDP payload for one LSP media datagram. */
  struct path_payload_limit {
    ip_family family = ip_family::ipv4;  ///< IP family used for the ceiling calculation.
    std::size_t udp_payload_size = initial_udp_payload_size;  ///< Complete protected UDP payload bytes.

    /**
     * @brief Return the largest plaintext RTP packet that leaves room for the SRTP tag.
     *
     * @return Plain RTP header, extension, and codec-payload byte capacity.
     */
    [[nodiscard]] constexpr std::size_t plaintext_rtp_capacity() const noexcept {
      return udp_payload_size - srtp_aead_tag_size;
    }
  };

  /** @brief Result of validating a path-payload limit. */
  struct path_payload_result {
    path_payload_limit limit {};  ///< Validated limit when `error` is `none`.
    path_payload_error error = path_payload_error::none;  ///< Validation status.

    /**
     * @brief Return whether validation succeeded.
     *
     * @return `true` only for a conforming LSP/1 path payload.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == path_payload_error::none;
    }
  };

  /**
   * @brief Validate an LSP/1 UDP payload against its initial floor and IP-family ceiling.
   *
   * @param family Selected IP family.
   * @param udp_payload_size Complete protected UDP payload bytes.
   * @return Validated limit and typed status.
   */
  [[nodiscard]] constexpr path_payload_result make_path_payload_limit(
    const ip_family family,
    const std::size_t udp_payload_size
  ) noexcept {
    if (udp_payload_size < initial_udp_payload_size) {
      return {.error = path_payload_error::below_initial_safe_size};
    }
    const auto ceiling = family == ip_family::ipv4 ? ipv4_udp_payload_ceiling : ipv6_udp_payload_ceiling;
    if (udp_payload_size > ceiling) {
      return {.error = path_payload_error::above_family_ceiling};
    }
    return {.limit = {.family = family, .udp_payload_size = udp_payload_size}};
  }

  /** @brief Frame-relative packet role used to apply the LSP boundary-extension policy. */
  enum class frame_packet_role : std::uint8_t {
    first_and_final,  ///< The frame fits one packet, which is both first and final.
    first,  ///< First packet of a frame containing at least three packets.
    second_and_final,  ///< Second and final packet of a two-packet frame.
    second,  ///< Second packet of a frame containing at least three packets.
    middle,  ///< Ordinary packet after the first two and before the final packet.
    final,  ///< Final packet of a frame containing at least three packets.
  };

  /**
   * @brief Determine the role of a packet within a complete video frame.
   *
   * @param packet_index Zero-based packet index.
   * @param packet_count Total packets in the frame.
   * @return Frame-relative packet role.
   */
  [[nodiscard]] constexpr frame_packet_role packet_role(
    const std::size_t packet_index,
    const std::size_t packet_count
  ) noexcept {
    if (packet_count == 1) {
      return frame_packet_role::first_and_final;
    }
    if (packet_count == 2) {
      return packet_index == 0 ? frame_packet_role::first : frame_packet_role::second_and_final;
    }
    if (packet_index == 0) {
      return frame_packet_role::first;
    }
    if (packet_index == 1) {
      return frame_packet_role::second;
    }
    if (packet_index + 1 == packet_count) {
      return frame_packet_role::final;
    }
    return frame_packet_role::middle;
  }

  /**
   * @brief Return whether LSP permits ordinary frame-boundary metadata on a packet.
   *
   * @param packet_index Zero-based packet index.
   * @param packet_count Total packets in the frame.
   * @return `true` for the first two or final packet only.
   */
  [[nodiscard]] constexpr bool carries_frame_boundary_extensions(
    const std::size_t packet_index,
    const std::size_t packet_count
  ) noexcept {
    return packet_index < 2 || packet_index + 1 == packet_count;
  }

  /** @brief Complete pre-encoded RFC 8285 extension blocks for every boundary-role overlap. */
  struct frame_extension_blocks {
    std::span<const std::uint8_t> first_and_final {};  ///< Extensions for a one-packet frame.
    std::span<const std::uint8_t> first {};  ///< Extensions for the first packet of a multi-packet frame.
    std::span<const std::uint8_t> second_and_final {};  ///< Extensions for the final packet of a two-packet frame.
    std::span<const std::uint8_t> second {};  ///< Extensions for the second packet of a frame with at least three packets.
    std::span<const std::uint8_t> final {};  ///< Extensions for the final packet of a frame with at least three packets.

    /**
     * @brief Return the exact extension block for one frame-relative packet role.
     *
     * @param role Packet role.
     * @return Borrowed complete RFC 8285 extension block, or an empty span for a middle packet.
     */
    [[nodiscard]] constexpr std::span<const std::uint8_t> for_role(const frame_packet_role role) const noexcept {
      switch (role) {
        case frame_packet_role::first_and_final:
          return first_and_final;
        case frame_packet_role::first:
          return first;
        case frame_packet_role::second_and_final:
          return second_and_final;
        case frame_packet_role::second:
          return second;
        case frame_packet_role::final:
          return final;
        case frame_packet_role::middle:
          return {};
      }
      return {};
    }

    /**
     * @brief Return the largest configured boundary-extension block.
     *
     * Packetization reserves this many bytes on boundary packets so the final packet count cannot
     * make a previously constructed codec payload exceed the path maximum.
     *
     * @return Maximum configured extension-block bytes.
     */
    [[nodiscard]] constexpr std::size_t maximum_size() const noexcept {
      return std::max({first_and_final.size(), first.size(), second_and_final.size(), second.size(), final.size()});
    }
  };

  /** @brief Typed media-packetization failure. */
  enum class packetization_error : std::uint8_t {
    none,  ///< Packetization completed successfully.
    empty_access_unit,  ///< No codec unit was supplied for the frame or temporal unit.
    empty_codec_unit,  ///< A supplied NAL unit, OBU element, or Opus packet is empty.
    malformed_codec_unit,  ///< A codec unit has an invalid header or forbidden payload-format type.
    codec_unit_too_large,  ///< A length-delimited aggregation unit exceeds its wire length field.
    invalid_rtp_configuration,  ///< Payload type, SSRC, or extension configuration is invalid.
    path_payload_too_small,  ///< The validated path leaves insufficient space for required RTP and codec headers.
    packet_exceeds_path,  ///< A constructed packet would exceed the discovered protected UDP payload limit.
  };

  /** @brief RTP stream values shared by every packet of one packetization call. */
  struct rtp_stream_config {
    std::uint8_t payload_type = 0;  ///< Negotiated dynamic RTP payload type.
    std::uint16_t first_sequence_number = 0;  ///< Sequence number assigned to the first produced packet.
    std::uint32_t timestamp = 0;  ///< Frame or audio sampling timestamp.
    std::uint32_t ssrc = 0;  ///< Nonzero negotiated media SSRC.
  };

  /** @brief Complete packetization configuration for one video frame. */
  struct video_packetization_config {
    rtp_stream_config stream {};  ///< RTP stream fields.
    path_payload_limit path {};  ///< Validated protected UDP payload limit.
    frame_extension_blocks extensions {};  ///< Pre-encoded boundary-only RTP extension blocks.
  };

  /** @brief One unprotected RTP packet ready for in-place SRTP protection. */
  struct rtp_packet {
    std::vector<std::uint8_t> bytes {};  ///< Complete plaintext RTP packet bytes.
    frame_packet_role role = frame_packet_role::middle;  ///< Frame-relative role used for extensions.
  };

  /** @brief Complete packetization output for one frame or audio packet. */
  struct packetization_result {
    std::vector<rtp_packet> packets {};  ///< Produced RTP packets in sequence order.
    std::uint16_t next_sequence_number = 0;  ///< Sequence number following the last produced packet.
    packetization_error error = packetization_error::none;  ///< Packetization status.

    /**
     * @brief Return whether packetization succeeded.
     *
     * @return `true` only when all packets were constructed successfully.
     */
    [[nodiscard]] explicit operator bool() const noexcept {
      return error == packetization_error::none;
    }
  };

  namespace detail {
    /**
     * @brief Validate a complete RFC 8285 one-byte extension block.
     *
     * @param block RTP extension header plus padded extension payload.
     * @return `true` for an empty block or an exact `0xBEDE` block.
     */
    [[nodiscard]] constexpr bool valid_extension_block(const std::span<const std::uint8_t> block) noexcept {
      if (block.empty()) {
        return true;
      }
      if (block.size() < 4 || (block.size() % 4) != 0) {
        return false;
      }
      if (block[0] != 0xbeU || block[1] != 0xdeU) {
        return false;
      }
      const auto declared_words = static_cast<std::size_t>((std::uint16_t {block[2]} << 8U) | block[3]);
      return 4U + declared_words * 4U == block.size();
    }

    /**
     * @brief Validate every configured frame-boundary extension block.
     *
     * @param extensions Extension variants.
     * @return `true` only when every variant is a complete RFC 8285 one-byte block.
     */
    [[nodiscard]] constexpr bool valid_extension_blocks(const frame_extension_blocks &extensions) noexcept {
      return valid_extension_block(extensions.first_and_final) &&
             valid_extension_block(extensions.first) &&
             valid_extension_block(extensions.second_and_final) &&
             valid_extension_block(extensions.second) &&
             valid_extension_block(extensions.final);
    }

    /**
     * @brief Return codec-payload capacity for conservative boundary packetization.
     *
     * @param config Frame packetization configuration.
     * @return Codec bytes available after RTP and the largest boundary extension.
     */
    [[nodiscard]] constexpr std::size_t boundary_codec_capacity(const video_packetization_config &config) noexcept {
      const auto overhead = rtp_fixed_header_size + config.extensions.maximum_size();
      return config.path.plaintext_rtp_capacity() > overhead ? config.path.plaintext_rtp_capacity() - overhead : 0;
    }

    /**
     * @brief Return codec-payload capacity for an extension-free ordinary middle packet.
     *
     * @param config Frame packetization configuration.
     * @return Codec bytes available after the fixed RTP header.
     */
    [[nodiscard]] constexpr std::size_t middle_codec_capacity(const video_packetization_config &config) noexcept {
      return config.path.plaintext_rtp_capacity() > rtp_fixed_header_size ? config.path.plaintext_rtp_capacity() - rtp_fixed_header_size : 0;
    }

    /**
     * @brief Validate common video RTP configuration.
     *
     * @param config Frame packetization configuration.
     * @return Typed status.
     */
    [[nodiscard]] constexpr packetization_error validate_video_config(const video_packetization_config &config) noexcept {
      if (!valid_dynamic_payload_type(config.stream.payload_type) || config.stream.ssrc == 0 || !valid_extension_blocks(config.extensions)) {
        return packetization_error::invalid_rtp_configuration;
      }
      if (config.path.udp_payload_size < initial_udp_payload_size ||
          config.path.udp_payload_size > (config.path.family == ip_family::ipv4 ? ipv4_udp_payload_ceiling : ipv6_udp_payload_ceiling)) {
        return packetization_error::invalid_rtp_configuration;
      }
      if (boundary_codec_capacity(config) == 0 || middle_codec_capacity(config) == 0) {
        return packetization_error::path_payload_too_small;
      }
      return packetization_error::none;
    }

    /**
     * @brief Assemble codec payloads into complete RTP packets.
     *
     * @param payloads Codec payloads in frame order.
     * @param config Frame packetization configuration.
     * @return Complete RTP packetization result.
     */
    [[nodiscard]] inline packetization_result assemble_video_packets(
      std::vector<std::vector<std::uint8_t>> payloads,
      const video_packetization_config &config
    ) {
      packetization_result result;
      result.next_sequence_number = config.stream.first_sequence_number;
      if (const auto status = validate_video_config(config); status != packetization_error::none) {
        result.error = status;
        return result;
      }
      if (payloads.empty()) {
        result.error = packetization_error::empty_access_unit;
        return result;
      }

      result.packets.reserve(payloads.size());
      for (std::size_t index = 0; index < payloads.size(); ++index) {
        const auto role = packet_role(index, payloads.size());
        const auto extension = config.extensions.for_role(role);
        const auto packet_size = rtp_fixed_header_size + extension.size() + payloads[index].size();
        if (packet_size + srtp_aead_tag_size > config.path.udp_payload_size) {
          result.packets.clear();
          result.error = packetization_error::packet_exceeds_path;
          return result;
        }

        rtp_packet packet;
        packet.role = role;
        packet.bytes.resize(packet_size);
        const rtp_fixed_header header {
          .padding = false,
          .extension = !extension.empty(),
          .marker = index + 1 == payloads.size(),
          .payload_type = config.stream.payload_type,
          .csrc_count = 0,
          .sequence_number = result.next_sequence_number,
          .timestamp = config.stream.timestamp,
          .ssrc = config.stream.ssrc,
        };
        const auto header_result = write_rtp_fixed_header(header, {}, packet.bytes);
        if (!header_result) {
          result.packets.clear();
          result.error = packetization_error::invalid_rtp_configuration;
          return result;
        }
        auto offset = header_result.bytes_written;
        std::ranges::copy(extension, packet.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += extension.size();
        std::ranges::copy(payloads[index], packet.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
        result.packets.push_back(std::move(packet));
        ++result.next_sequence_number;
      }
      return result;
    }

    /**
     * @brief Encode an unsigned integer using the AV1 payload format's LEB128 form.
     *
     * @param value Value to encode.
     * @return Encoded bytes.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> encode_leb128(std::size_t value) {
      std::vector<std::uint8_t> encoded;
      do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
          byte |= 0x80U;
        }
        encoded.push_back(byte);
      } while (value != 0);
      return encoded;
    }

    /**
     * @brief Return the number of LEB128 bytes required for a size value.
     *
     * @param value Value to measure.
     * @return Encoded byte count.
     */
    [[nodiscard]] constexpr std::size_t leb128_size(std::size_t value) noexcept {
      std::size_t size = 1;
      while (value >= 0x80U) {
        value >>= 7U;
        ++size;
      }
      return size;
    }
  }  // namespace detail
}  // namespace lumen::lsp::media
