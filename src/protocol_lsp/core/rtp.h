/**
 * @file src/protocol_lsp/core/rtp.h
 * @brief Portable RTP version-2 fixed-header parser and writer.
 */

#pragma once

#include "wire.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace lumen::lsp {
  /** @brief Size of an RTP fixed header before any CSRC identifiers. */
  inline constexpr std::size_t rtp_fixed_header_size = 12;

  /** @brief Parsed or serializable RTP version-2 fixed-header fields. */
  struct rtp_fixed_header {
    bool padding = false;  ///< Packet has trailing RTP padding.
    bool extension = false;  ///< CSRC list is followed by an RTP header extension.
    bool marker = false;  ///< Payload-specific RTP marker bit.
    std::uint8_t payload_type = 0;  ///< Seven-bit negotiated payload type.
    std::uint8_t csrc_count = 0;  ///< Number of 32-bit CSRC identifiers following the fixed header.
    std::uint16_t sequence_number = 0;  ///< RTP sequence number.
    std::uint32_t timestamp = 0;  ///< RTP media timestamp.
    std::uint32_t ssrc = 0;  ///< Nonzero synchronization-source identifier.

    /** @brief Compare all RTP fixed-header fields. */
    [[nodiscard]] bool operator==(const rtp_fixed_header &) const noexcept = default;
  };

  /** @brief Typed RTP fixed-header failure. */
  enum class rtp_error : std::uint8_t {
    none,  ///< Operation completed successfully.
    header_too_short,  ///< Packet cannot contain its declared fixed header and CSRC list.
    destination_too_small,  ///< Writer destination cannot contain the fixed header and CSRC list.
    unsupported_version,  ///< RTP version is not two.
    invalid_payload_type,  ///< Payload type exceeds seven bits.
    invalid_csrc_count,  ///< Header count and supplied CSRC list disagree or exceed 15.
    invalid_ssrc,  ///< LSP requires every negotiated SSRC to be nonzero.
  };

  /** @brief Borrowed view of an RTP fixed header and CSRC bytes. */
  struct rtp_parse_result {
    rtp_fixed_header header {};  ///< Parsed fixed-header fields.
    std::span<const std::uint8_t> csrc_bytes {};  ///< Network-order CSRC bytes backed by the packet.
    std::size_t bytes_consumed = 0;  ///< Fixed-header plus CSRC-list length.
    rtp_error error = rtp_error::none;  ///< Parse status.

    /**
     * @brief Return whether parsing succeeded.
     *
     * @return `true` only for a complete valid fixed header.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtp_error::none;
    }
  };

  /** @brief Result of writing an RTP fixed header and CSRC list. */
  struct rtp_write_result {
    std::size_t bytes_written = 0;  ///< Fixed-header plus CSRC-list length on success.
    rtp_error error = rtp_error::none;  ///< Write status.

    /**
     * @brief Return whether writing succeeded.
     *
     * @return `true` only when the complete fixed header and CSRC list were written.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtp_error::none;
    }
  };

  /**
   * @brief Parse the RTP version-2 fixed header and complete CSRC list without allocation.
   *
   * Extension and payload bytes remain unparsed for their lane-specific parser.
   *
   * @param packet Complete or prefix RTP packet bytes.
   * @return Parsed header, borrowed network-order CSRC bytes, and typed status.
   */
  [[nodiscard]] constexpr rtp_parse_result parse_rtp_fixed_header(
    const std::span<const std::uint8_t> packet
  ) noexcept {
    if (packet.size() < rtp_fixed_header_size) {
      return {.error = rtp_error::header_too_short};
    }
    if ((packet[0] >> 6U) != 2U) {
      return {.error = rtp_error::unsupported_version};
    }
    const auto csrc_count = static_cast<std::uint8_t>(packet[0] & 0x0fU);
    const auto consumed = rtp_fixed_header_size + std::size_t {csrc_count} * 4U;
    if (packet.size() < consumed) {
      return {.error = rtp_error::header_too_short};
    }
    const auto ssrc = wire::read_be<std::uint32_t>(packet.subspan(8, 4));
    if (ssrc == 0) {
      return {.error = rtp_error::invalid_ssrc};
    }
    return {
      .header = {
        .padding = (packet[0] & 0x20U) != 0,
        .extension = (packet[0] & 0x10U) != 0,
        .marker = (packet[1] & 0x80U) != 0,
        .payload_type = static_cast<std::uint8_t>(packet[1] & 0x7fU),
        .csrc_count = csrc_count,
        .sequence_number = wire::read_be<std::uint16_t>(packet.subspan(2, 2)),
        .timestamp = wire::read_be<std::uint32_t>(packet.subspan(4, 4)),
        .ssrc = ssrc,
      },
      .csrc_bytes = packet.subspan(rtp_fixed_header_size, std::size_t {csrc_count} * 4U),
      .bytes_consumed = consumed,
      .error = rtp_error::none,
    };
  }

  /**
   * @brief Write an RTP version-2 fixed header and CSRC list without allocation.
   *
   * @param header Fixed-header fields.
   * @param csrcs Host-order CSRC identifiers.
   * @param destination Destination packet storage.
   * @return Encoded byte count and typed status.
   */
  [[nodiscard]] constexpr rtp_write_result write_rtp_fixed_header(
    const rtp_fixed_header &header,
    const std::span<const std::uint32_t> csrcs,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (header.payload_type > 0x7fU) {
      return {.error = rtp_error::invalid_payload_type};
    }
    if (csrcs.size() > 15U || csrcs.size() != header.csrc_count) {
      return {.error = rtp_error::invalid_csrc_count};
    }
    if (header.ssrc == 0) {
      return {.error = rtp_error::invalid_ssrc};
    }
    const auto required = rtp_fixed_header_size + csrcs.size() * 4U;
    if (destination.size() < required) {
      return {.error = rtp_error::destination_too_small};
    }
    destination[0] = static_cast<std::uint8_t>(
      0x80U |
      (header.padding ? 0x20U : 0U) |
      (header.extension ? 0x10U : 0U) |
      header.csrc_count
    );
    destination[1] = static_cast<std::uint8_t>((header.marker ? 0x80U : 0U) | header.payload_type);
    wire::write_be<std::uint16_t>(destination.subspan(2, 2), header.sequence_number);
    wire::write_be<std::uint32_t>(destination.subspan(4, 4), header.timestamp);
    wire::write_be<std::uint32_t>(destination.subspan(8, 4), header.ssrc);
    for (std::size_t index = 0; index < csrcs.size(); ++index) {
      wire::write_be<std::uint32_t>(destination.subspan(rtp_fixed_header_size + index * 4U, 4), csrcs[index]);
    }
    return {.bytes_written = required};
  }
}  // namespace lumen::lsp
