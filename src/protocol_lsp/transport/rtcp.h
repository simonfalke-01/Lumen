/**
 * @file src/lsp/transport/rtcp.h
 * @brief Bounded RTCP parsing and LSP transport-feedback state.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace lumen::lsp::transport {
  /** @brief RTCP sender-report packet type. */
  inline constexpr std::uint8_t rtcp_sender_report_type = 200;

  /** @brief RTCP receiver-report packet type. */
  inline constexpr std::uint8_t rtcp_receiver_report_type = 201;

  /** @brief RTCP application-defined packet type. */
  inline constexpr std::uint8_t rtcp_app_type = 204;

  /** @brief RTCP transport-layer feedback packet type. */
  inline constexpr std::uint8_t rtcp_transport_feedback_type = 205;

  /** @brief RTCP payload-specific feedback packet type. */
  inline constexpr std::uint8_t rtcp_payload_feedback_type = 206;

  /** @brief RFC 8888 congestion-control feedback format value. */
  inline constexpr std::uint8_t rtcp_congestion_feedback_format = 11;

  /** @brief RFC 4585 Generic NACK feedback format value. */
  inline constexpr std::uint8_t rtcp_generic_nack_format = 1;

  /** @brief RFC 4585 Picture Loss Indication feedback format value. */
  inline constexpr std::uint8_t rtcp_picture_loss_indication_format = 1;

  /** @brief RFC 5104 Full Intra Request feedback format value. */
  inline constexpr std::uint8_t rtcp_full_intra_request_format = 4;

  /** @brief Minimum interval between RFC 8888 feedback datagrams. */
  inline constexpr std::uint64_t congestion_feedback_floor_microseconds = 500;

  /** @brief Normal time cadence for RFC 8888 feedback. */
  inline constexpr std::uint64_t congestion_feedback_interval_microseconds = 2'000;

  /** @brief Packet-count cadence for RFC 8888 feedback. */
  inline constexpr std::size_t congestion_feedback_packet_cadence = 128;

  /** @brief Minimum coalescing interval for protected `LSPV` status. */
  inline constexpr std::uint64_t lspv_minimum_interval_microseconds = 500;

  /** @brief Exact RTCP APP name for decoded and presented frame status. */
  inline constexpr std::array<std::uint8_t, 4> lspv_app_name {'L', 'S', 'P', 'V'};

  namespace detail {
    /**
     * @brief Read a 16-bit network-order integer.
     *
     * @param bytes Input containing at least two bytes.
     * @return Decoded host-order value.
     */
    [[nodiscard]] constexpr std::uint16_t read_u16(const std::span<const std::uint8_t> bytes) noexcept {
      return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8U) | bytes[1]);
    }

    /**
     * @brief Read a 32-bit network-order integer.
     *
     * @param bytes Input containing at least four bytes.
     * @return Decoded host-order value.
     */
    [[nodiscard]] constexpr std::uint32_t read_u32(const std::span<const std::uint8_t> bytes) noexcept {
      return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
             (static_cast<std::uint32_t>(bytes[1]) << 16U) |
             (static_cast<std::uint32_t>(bytes[2]) << 8U) |
             static_cast<std::uint32_t>(bytes[3]);
    }

    /**
     * @brief Write a 16-bit network-order integer.
     *
     * @param bytes Output containing at least two bytes.
     * @param value Host-order value.
     */
    constexpr void write_u16(const std::span<std::uint8_t> bytes, const std::uint16_t value) noexcept {
      bytes[0] = static_cast<std::uint8_t>(value >> 8U);
      bytes[1] = static_cast<std::uint8_t>(value);
    }

    /**
     * @brief Write a 32-bit network-order integer.
     *
     * @param bytes Output containing at least four bytes.
     * @param value Host-order value.
     */
    constexpr void write_u32(const std::span<std::uint8_t> bytes, const std::uint32_t value) noexcept {
      bytes[0] = static_cast<std::uint8_t>(value >> 24U);
      bytes[1] = static_cast<std::uint8_t>(value >> 16U);
      bytes[2] = static_cast<std::uint8_t>(value >> 8U);
      bytes[3] = static_cast<std::uint8_t>(value);
    }

    /**
     * @brief Initialize one unpadded RTCP packet header.
     *
     * @param destination Complete RTCP packet storage.
     * @param count Report count, subtype, or feedback format.
     * @param packet_type RTCP packet type.
     */
    constexpr void write_rtcp_header(
      const std::span<std::uint8_t> destination,
      const std::uint8_t count,
      const std::uint8_t packet_type
    ) noexcept {
      destination[0] = static_cast<std::uint8_t>(0x80U | count);
      destination[1] = packet_type;
      write_u16(destination.subspan(2, 2), static_cast<std::uint16_t>(destination.size() / 4U - 1U));
    }
  }  // namespace detail

  /** @brief Whether an RTCP datagram follows compound or RFC 5506 reduced-size rules. */
  enum class rtcp_datagram_form : std::uint8_t {
    compound,  ///< First packet must be a sender or receiver report.
    reduced_size,  ///< A single feedback or application packet is permitted.
  };

  /** @brief Typed RTCP parse failure. */
  enum class rtcp_parse_error : std::uint8_t {
    none,  ///< Parsing completed successfully.
    empty_datagram,  ///< Datagram contains no RTCP packet.
    header_too_short,  ///< Fewer than four bytes remain.
    unsupported_version,  ///< Common header version is not two.
    invalid_length,  ///< Declared RTCP length exceeds or fails to consume the datagram.
    invalid_padding,  ///< Padding length is zero, oversized, or used before the final packet.
    invalid_compound_start,  ///< Compound RTCP does not begin with SR or RR.
    invalid_payload,  ///< Packet payload violates the selected RTCP authority or feedback grammar.
    too_many_packets,  ///< Packet count cannot be represented by the bounded summary.
  };

  /** @brief Parsed RTCP common header and packet-backed byte views. */
  struct rtcp_packet_view {
    std::uint8_t count = 0;  ///< Five-bit report count, subtype, or feedback format.
    std::uint8_t packet_type = 0;  ///< RTCP packet type.
    bool padding = false;  ///< Whether this packet has trailing RTCP padding.
    std::uint8_t padding_bytes = 0;  ///< Validated trailing padding byte count.
    std::span<const std::uint8_t> packet {};  ///< Complete RTCP packet including common header and padding.
    std::span<const std::uint8_t> payload {};  ///< Bytes after the common header and before padding.
    rtcp_parse_error error = rtcp_parse_error::none;  ///< Parse status.

    /**
     * @brief Return whether parsing succeeded.
     *
     * @return `true` only for a complete valid packet.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtcp_parse_error::none;
    }
  };

  /** @brief Bounded validation summary for one RTCP datagram. */
  struct rtcp_datagram_summary {
    std::size_t packet_count = 0;  ///< Number of complete RTCP packets.
    std::size_t bytes_consumed = 0;  ///< Bytes covered by valid RTCP packets.
    rtcp_parse_error error = rtcp_parse_error::none;  ///< Validation status.

    /**
     * @brief Return whether datagram validation succeeded.
     *
     * @return `true` only for an exactly consumed valid datagram.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtcp_parse_error::none;
    }
  };

  /** @brief Fully validated regular compound RTCP authority prerequisite. */
  struct compound_rtcp_authority_view {
    rtcp_packet_view first_report {};  ///< First exact SR/RR packet from the feedback sender.
    std::span<const std::uint8_t> cname {};  ///< Sole complete nonempty SDES CNAME for that sender.
    rtcp_parse_error error {rtcp_parse_error::none};  ///< Structural or authority validation failure.

    /** @brief Return whether both the first report and unique CNAME are valid. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtcp_parse_error::none && !first_report.packet.empty() && !cname.empty();
    }
  };

  /** @brief RFC 3550 sender information for one active RTP source. */
  struct sender_report {
    std::uint32_t sender_ssrc = 0;  ///< SSRC of the RTP source described by this report.
    std::uint32_t ntp_seconds = 0;  ///< Most-significant 32 bits of the NTP timestamp.
    std::uint32_t ntp_fraction = 0;  ///< Least-significant 32-bit NTP fractional seconds.
    std::uint32_t rtp_timestamp = 0;  ///< RTP sampling timestamp corresponding to the NTP instant.
    std::uint32_t packet_count = 0;  ///< Sender packet count modulo 2^32.
    std::uint32_t octet_count = 0;  ///< Sender codec-payload octet count modulo 2^32.
  };

  /** @brief Typed RFC 3550 sender-report serialization failure. */
  enum class sender_report_error : std::uint8_t {
    none,  ///< A complete sender report was written.
    invalid_ssrc,  ///< Sender SSRC is zero.
    destination_too_small,  ///< Destination cannot contain the fixed 28-byte report.
  };

  /** @brief RFC 3550 sender-report serialization result. */
  struct sender_report_write_result {
    std::size_t bytes_written = 0;  ///< Complete RTCP packet bytes written on success.
    sender_report_error error = sender_report_error::none;  ///< Serialization status.

    /**
     * @brief Return whether serialization succeeded.
     *
     * @return `true` only for a complete valid sender report.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == sender_report_error::none;
    }
  };

  /**
   * @brief Serialize one RTCP SDES packet containing one stable CNAME chunk.
   *
   * @param sender_ssrc Nonzero SSRC owning the CNAME.
   * @param cname Nonempty CNAME bytes, at most 255.
   * @param destination Caller-owned packet storage.
   * @return Complete aligned packet bytes, or zero on invalid input/bounds.
   */
  [[nodiscard]] constexpr std::size_t write_sdes_cname(
    const std::uint32_t sender_ssrc,
    const std::span<const std::uint8_t> cname,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (sender_ssrc == 0 || cname.empty() || cname.size() > 255U) {
      return 0;
    }
    const auto unaligned = 4U + 4U + 2U + cname.size() + 1U;
    const auto required = (unaligned + 3U) & ~std::size_t {3U};
    if (destination.size() < required) {
      return 0;
    }
    auto packet = destination.first(required);
    std::fill(packet.begin(), packet.end(), 0);
    detail::write_rtcp_header(packet, 1, 202U);
    detail::write_u32(packet.subspan(4, 4), sender_ssrc);
    packet[8] = 1U;
    packet[9] = static_cast<std::uint8_t>(cname.size());
    std::copy(cname.begin(), cname.end(), packet.begin() + 10);
    return required;
  }

  /**
   * @brief Serialize one report-block-free RFC 3550 sender report.
   *
   * @param report Sender timing and cumulative counters.
   * @param destination Caller-owned packet storage.
   * @return Fixed 28-byte write result and typed status.
   */
  [[nodiscard]] constexpr sender_report_write_result write_sender_report(
    const sender_report &report,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (report.sender_ssrc == 0) {
      return {.error = sender_report_error::invalid_ssrc};
    }
    constexpr auto required = std::size_t {28};
    if (destination.size() < required) {
      return {.error = sender_report_error::destination_too_small};
    }
    const auto packet = destination.first(required);
    detail::write_rtcp_header(packet, 0, rtcp_sender_report_type);
    detail::write_u32(packet.subspan(4, 4), report.sender_ssrc);
    detail::write_u32(packet.subspan(8, 4), report.ntp_seconds);
    detail::write_u32(packet.subspan(12, 4), report.ntp_fraction);
    detail::write_u32(packet.subspan(16, 4), report.rtp_timestamp);
    detail::write_u32(packet.subspan(20, 4), report.packet_count);
    detail::write_u32(packet.subspan(24, 4), report.octet_count);
    return {.bytes_written = required};
  }

  /**
   * @brief Parse one RTCP packet from the start of a datagram without allocation.
   *
   * @param bytes Datagram bytes beginning with an RTCP common header.
   * @return Parsed packet or a typed error.
   */
  [[nodiscard]] constexpr rtcp_packet_view parse_rtcp_packet(
    const std::span<const std::uint8_t> bytes
  ) noexcept {
    if (bytes.size() < 4U) {
      return {.error = rtcp_parse_error::header_too_short};
    }
    if ((bytes[0] >> 6U) != 2U) {
      return {.error = rtcp_parse_error::unsupported_version};
    }
    const auto packet_bytes = (static_cast<std::size_t>(detail::read_u16(bytes.subspan(2, 2))) + 1U) * 4U;
    if (packet_bytes < 4U || packet_bytes > bytes.size()) {
      return {.error = rtcp_parse_error::invalid_length};
    }
    const auto padding = (bytes[0] & 0x20U) != 0;
    std::uint8_t padding_bytes = 0;
    if (padding) {
      padding_bytes = bytes[packet_bytes - 1U];
      if (padding_bytes == 0 || padding_bytes > packet_bytes - 4U) {
        return {.error = rtcp_parse_error::invalid_padding};
      }
    }
    return {
      .count = static_cast<std::uint8_t>(bytes[0] & 0x1fU),
      .packet_type = bytes[1],
      .padding = padding,
      .padding_bytes = padding_bytes,
      .packet = bytes.first(packet_bytes),
      .payload = bytes.subspan(4, packet_bytes - 4U - padding_bytes),
    };
  }

  /**
   * @brief Validate a complete compound or reduced-size RTCP datagram.
   *
   * Compound validation enforces the common RFC 3550 first-packet rule. Reduced-size validation
   * accepts any valid standalone RTCP packet. Both forms require padding only on the final packet.
   *
   * @param datagram Complete unprotected RTCP datagram.
   * @param form Expected RTCP datagram form.
   * @return Bounded validation summary.
   */
  [[nodiscard]] constexpr rtcp_datagram_summary parse_rtcp_datagram(
    const std::span<const std::uint8_t> datagram,
    const rtcp_datagram_form form
  ) noexcept {
    if (datagram.empty()) {
      return {.error = rtcp_parse_error::empty_datagram};
    }
    std::size_t offset = 0;
    std::size_t count = 0;
    while (offset < datagram.size()) {
      const auto parsed = parse_rtcp_packet(datagram.subspan(offset));
      if (!parsed) {
        return {.packet_count = count, .bytes_consumed = offset, .error = parsed.error};
      }
      if (count == 0 && form == rtcp_datagram_form::compound &&
          parsed.packet_type != rtcp_sender_report_type && parsed.packet_type != rtcp_receiver_report_type) {
        return {.error = rtcp_parse_error::invalid_compound_start};
      }
      offset += parsed.packet.size();
      ++count;
      if (count > 255U) {
        return {.packet_count = count, .bytes_consumed = offset, .error = rtcp_parse_error::too_many_packets};
      }
      if (parsed.padding && offset != datagram.size()) {
        return {.packet_count = count, .bytes_consumed = offset, .error = rtcp_parse_error::invalid_padding};
      }
    }
    if (offset != datagram.size()) {
      return {.packet_count = count, .bytes_consumed = offset, .error = rtcp_parse_error::invalid_length};
    }
    return {.packet_count = count, .bytes_consumed = offset};
  }

  /**
   * @brief Validate the complete regular RTCP prerequisite for reduced-size feedback.
   *
   * The first packet must be an exact SR/RR from `expected_sender_ssrc` and the
   * complete compound datagram must carry exactly one nonempty SDES CNAME for
   * that sender. No caller state is mutated by this validation pass.
   *
   * @param datagram Complete plaintext compound RTCP datagram.
   * @param expected_sender_ssrc Negotiated feedback sender SSRC.
   * @return Borrowed first-report and CNAME views, or a fail-closed error.
   */
  [[nodiscard]] constexpr compound_rtcp_authority_view validate_compound_rtcp_authority(
    const std::span<const std::uint8_t> datagram,
    const std::uint32_t expected_sender_ssrc
  ) noexcept {
    const auto summary = parse_rtcp_datagram(datagram, rtcp_datagram_form::compound);
    if (!summary || expected_sender_ssrc == 0) {
      return {.error = summary.error == rtcp_parse_error::none ? rtcp_parse_error::invalid_payload : summary.error};
    }
    const auto first = parse_rtcp_packet(datagram);
    if (!first || (first.packet_type != rtcp_sender_report_type && first.packet_type != rtcp_receiver_report_type) ||
        first.payload.size() < 4U || detail::read_u32(first.payload.first<4>()) != expected_sender_ssrc) {
      return {.error = rtcp_parse_error::invalid_payload};
    }
    const auto report_offset = first.packet_type == rtcp_sender_report_type ? 24U : 4U;
    if (first.payload.size() != report_offset + static_cast<std::size_t>(first.count) * 24U) {
      return {.error = rtcp_parse_error::invalid_payload};
    }

    std::span<const std::uint8_t> cname;
    std::size_t offset = 0;
    while (offset < datagram.size()) {
      const auto packet = parse_rtcp_packet(datagram.subspan(offset));
      if (!packet) {
        return {.error = packet.error};
      }
      if (packet.packet_type == 202U) {
        std::size_t chunk_offset = 0;
        for (std::uint8_t chunk = 0; chunk < packet.count; ++chunk) {
          if (packet.payload.size() - chunk_offset < 4U) {
            return {.error = rtcp_parse_error::invalid_payload};
          }
          const auto chunk_ssrc = detail::read_u32(packet.payload.subspan(chunk_offset, 4));
          chunk_offset += 4U;
          bool ended = false;
          while (chunk_offset < packet.payload.size()) {
            const auto item_type = packet.payload[chunk_offset++];
            if (item_type == 0) {
              ended = true;
              break;
            }
            if (chunk_offset >= packet.payload.size()) {
              return {.error = rtcp_parse_error::invalid_payload};
            }
            const auto item_size = static_cast<std::size_t>(packet.payload[chunk_offset++]);
            if (item_size > packet.payload.size() - chunk_offset) {
              return {.error = rtcp_parse_error::invalid_payload};
            }
            if (chunk_ssrc == expected_sender_ssrc && item_type == 1U) {
              if (item_size == 0 || !cname.empty()) {
                return {.error = rtcp_parse_error::invalid_payload};
              }
              cname = packet.payload.subspan(chunk_offset, item_size);
            }
            chunk_offset += item_size;
          }
          if (!ended) {
            return {.error = rtcp_parse_error::invalid_payload};
          }
          while ((chunk_offset & 3U) != 0U) {
            if (chunk_offset >= packet.payload.size() || packet.payload[chunk_offset] != 0) {
              return {.error = rtcp_parse_error::invalid_payload};
            }
            ++chunk_offset;
          }
        }
        if (chunk_offset != packet.payload.size()) {
          return {.error = rtcp_parse_error::invalid_payload};
        }
      }
      offset += packet.packet.size();
    }
    return cname.empty() ?
             compound_rtcp_authority_view {.error = rtcp_parse_error::invalid_payload} :
             compound_rtcp_authority_view {.first_report = first, .cname = cname};
  }

  /** @brief One RFC 4585 Generic NACK PID/BLP loss description. */
  struct generic_nack_pair {
    std::uint16_t packet_id = 0;  ///< First missing RTP sequence number.
    std::uint16_t lost_packet_bitmask = 0;  ///< Missing status of the next sixteen sequence numbers.

    /** @brief Compare both NACK fields. */
    [[nodiscard]] bool operator==(const generic_nack_pair &) const noexcept = default;
  };

  /**
   * @brief Fixed-capacity RFC 4585 Generic NACK model.
   *
   * @tparam MaximumPairs Maximum number of PID/BLP pairs retained.
   */
  template<std::size_t MaximumPairs = 32>
  struct generic_nack {
    std::uint32_t sender_ssrc = 0;  ///< Feedback sender SSRC.
    std::uint32_t media_ssrc = 0;  ///< Primary media SSRC reporting loss.
    std::array<generic_nack_pair, MaximumPairs> pairs {};  ///< Bounded PID/BLP records.
    std::size_t pair_count = 0;  ///< Number of populated records.
  };

  /** @brief RFC 4585 Picture Loss Indication model. */
  struct picture_loss_indication {
    std::uint32_t sender_ssrc = 0;  ///< Feedback sender SSRC.
    std::uint32_t media_ssrc = 0;  ///< Media source requiring an independent picture.
  };

  /** @brief One RFC 5104 Full Intra Request entry. */
  struct full_intra_request_entry {
    std::uint32_t media_sender_ssrc = 0;  ///< SSRC of the media sender receiving the request.
    std::uint8_t sequence_number = 0;  ///< FIR command sequence number.
  };

  /**
   * @brief Fixed-capacity RFC 5104 Full Intra Request model.
   *
   * @tparam MaximumEntries Maximum FIR entries retained.
   */
  template<std::size_t MaximumEntries = 4>
  struct full_intra_request {
    std::uint32_t sender_ssrc = 0;  ///< Feedback sender SSRC.
    std::array<full_intra_request_entry, MaximumEntries> entries {};  ///< Bounded FIR entries.
    std::size_t entry_count = 0;  ///< Number of populated FIR entries.
  };

  /** @brief Typed RFC 4585/5104 feedback parse failure. */
  enum class rtcp_feedback_parse_error : std::uint8_t {
    none,  ///< Feedback packet parsed completely.
    invalid_packet,  ///< Input RTCP view is invalid.
    wrong_packet_type,  ///< RTCP packet type does not match the requested feedback model.
    wrong_format,  ///< Five-bit RTCP feedback format does not match the requested model.
    invalid_length,  ///< Feedback Control Information has an invalid or empty length.
    invalid_ssrc,  ///< A required sender, media, or FIR target SSRC is zero or forbidden.
    duplicate_entry,  ///< FIR repeats a media-sender target in one feedback packet.
    capacity_exceeded,  ///< Caller model cannot retain every feedback record.
  };

  /**
   * @brief Parse one RFC 4585 Generic NACK from an authenticated RTCP packet view.
   *
   * @tparam MaximumPairs Fixed PID/BLP pair capacity.
   * @param packet Parsed complete RTCP packet view.
   * @param nack Receives the model only after complete validation.
   * @return Typed parse status.
   */
  template<std::size_t MaximumPairs>
  [[nodiscard]] constexpr rtcp_feedback_parse_error parse_generic_nack(
    const rtcp_packet_view &packet,
    generic_nack<MaximumPairs> &nack
  ) noexcept {
    if (!packet) {
      return rtcp_feedback_parse_error::invalid_packet;
    }
    if (packet.packet_type != rtcp_transport_feedback_type) {
      return rtcp_feedback_parse_error::wrong_packet_type;
    }
    if (packet.count != rtcp_generic_nack_format) {
      return rtcp_feedback_parse_error::wrong_format;
    }
    if (packet.payload.size() < 12U || (packet.payload.size() - 8U) % 4U != 0) {
      return rtcp_feedback_parse_error::invalid_length;
    }
    const auto pair_count = (packet.payload.size() - 8U) / 4U;
    if (pair_count > MaximumPairs) {
      return rtcp_feedback_parse_error::capacity_exceeded;
    }
    generic_nack<MaximumPairs> parsed;
    parsed.sender_ssrc = detail::read_u32(packet.payload.first(4));
    parsed.media_ssrc = detail::read_u32(packet.payload.subspan(4, 4));
    if (parsed.sender_ssrc == 0 || parsed.media_ssrc == 0) {
      return rtcp_feedback_parse_error::invalid_ssrc;
    }
    parsed.pair_count = pair_count;
    for (std::size_t index = 0; index < pair_count; ++index) {
      parsed.pairs[index] = {
        .packet_id = detail::read_u16(packet.payload.subspan(8U + index * 4U, 2)),
        .lost_packet_bitmask = detail::read_u16(packet.payload.subspan(10U + index * 4U, 2)),
      };
    }
    nack = parsed;
    return rtcp_feedback_parse_error::none;
  }

  /**
   * @brief Parse one RFC 4585 Picture Loss Indication from authenticated RTCP.
   *
   * @param packet Parsed complete RTCP packet view.
   * @param pli Receives the model only after complete validation.
   * @return Typed parse status.
   */
  [[nodiscard]] constexpr rtcp_feedback_parse_error parse_picture_loss_indication(
    const rtcp_packet_view &packet,
    picture_loss_indication &pli
  ) noexcept {
    if (!packet) {
      return rtcp_feedback_parse_error::invalid_packet;
    }
    if (packet.packet_type != rtcp_payload_feedback_type) {
      return rtcp_feedback_parse_error::wrong_packet_type;
    }
    if (packet.count != rtcp_picture_loss_indication_format) {
      return rtcp_feedback_parse_error::wrong_format;
    }
    if (packet.payload.size() != 8U) {
      return rtcp_feedback_parse_error::invalid_length;
    }
    picture_loss_indication parsed {
      .sender_ssrc = detail::read_u32(packet.payload.first(4)),
      .media_ssrc = detail::read_u32(packet.payload.subspan(4, 4)),
    };
    if (parsed.sender_ssrc == 0 || parsed.media_ssrc == 0) {
      return rtcp_feedback_parse_error::invalid_ssrc;
    }
    pli = parsed;
    return rtcp_feedback_parse_error::none;
  }

  /**
   * @brief Parse one RFC 5104 Full Intra Request from authenticated RTCP.
   *
   * The common media-source SSRC must be zero. Reserved FIR entry bits are ignored as required by
   * RFC 5104, while every target media-sender SSRC must be nonzero.
   *
   * @tparam MaximumEntries Fixed FIR entry capacity.
   * @param packet Parsed complete RTCP packet view.
   * @param fir Receives the model only after complete validation.
   * @return Typed parse status.
   */
  template<std::size_t MaximumEntries>
  [[nodiscard]] constexpr rtcp_feedback_parse_error parse_full_intra_request(
    const rtcp_packet_view &packet,
    full_intra_request<MaximumEntries> &fir
  ) noexcept {
    if (!packet) {
      return rtcp_feedback_parse_error::invalid_packet;
    }
    if (packet.packet_type != rtcp_payload_feedback_type) {
      return rtcp_feedback_parse_error::wrong_packet_type;
    }
    if (packet.count != rtcp_full_intra_request_format) {
      return rtcp_feedback_parse_error::wrong_format;
    }
    if (packet.payload.size() < 16U || (packet.payload.size() - 8U) % 8U != 0) {
      return rtcp_feedback_parse_error::invalid_length;
    }
    const auto entry_count = (packet.payload.size() - 8U) / 8U;
    if (entry_count > MaximumEntries) {
      return rtcp_feedback_parse_error::capacity_exceeded;
    }
    full_intra_request<MaximumEntries> parsed;
    parsed.sender_ssrc = detail::read_u32(packet.payload.first(4));
    if (parsed.sender_ssrc == 0 || detail::read_u32(packet.payload.subspan(4, 4)) != 0) {
      return rtcp_feedback_parse_error::invalid_ssrc;
    }
    parsed.entry_count = entry_count;
    for (std::size_t index = 0; index < entry_count; ++index) {
      const auto offset = 8U + index * 8U;
      parsed.entries[index] = {
        .media_sender_ssrc = detail::read_u32(packet.payload.subspan(offset, 4)),
        .sequence_number = packet.payload[offset + 4U],
      };
      if (parsed.entries[index].media_sender_ssrc == 0) {
        return rtcp_feedback_parse_error::invalid_ssrc;
      }
      for (std::size_t prior = 0; prior < index; ++prior) {
        if (parsed.entries[prior].media_sender_ssrc == parsed.entries[index].media_sender_ssrc) {
          return rtcp_feedback_parse_error::duplicate_entry;
        }
      }
    }
    fir = parsed;
    return rtcp_feedback_parse_error::none;
  }

  /** @brief Typed bounded Generic NACK sequence expansion failure. */
  enum class generic_nack_expansion_error : std::uint8_t {
    none,  ///< Every unique missing sequence was written.
    invalid_count,  ///< Pair count is zero or exceeds model capacity.
    destination_too_small,  ///< Caller storage cannot contain every unique missing sequence.
  };

  /** @brief Result of expanding PID/BLP pairs into unique missing source sequences. */
  struct generic_nack_expansion_result {
    std::size_t sequence_count = 0;  ///< Unique missing sequences written on success.
    std::size_t required = 0;  ///< Unique sequences required even when storage is too small.
    generic_nack_expansion_error error = generic_nack_expansion_error::none;  ///< Typed status.

    /**
     * @brief Return whether expansion succeeded.
     *
     * @return `true` only when every unique sequence was written.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == generic_nack_expansion_error::none;
    }
  };

  /**
   * @brief Expand RFC 4585 PID/BLP pairs into a bounded unique sequence list.
   *
   * Pair order and ascending BLP bit order are preserved. Overlapping pairs are deduplicated. The
   * function performs a validation/count pass before writing, so insufficient storage never leaves
   * a partial list that could be mistaken for complete feedback.
   *
   * @tparam MaximumPairs Fixed PID/BLP pair capacity.
   * @param nack Parsed Generic NACK model.
   * @param destination Caller-owned sequence storage.
   * @return Written/required counts and typed status.
   */
  template<std::size_t MaximumPairs>
  [[nodiscard]] constexpr generic_nack_expansion_result expand_generic_nack(
    const generic_nack<MaximumPairs> &nack,
    const std::span<std::uint16_t> destination
  ) noexcept {
    if (nack.pair_count == 0 || nack.pair_count > MaximumPairs) {
      return {.error = generic_nack_expansion_error::invalid_count};
    }
    const auto selected = [&nack](const std::size_t pair_index, const std::size_t position) constexpr noexcept {
      return position == 0 ||
             (nack.pairs[pair_index].lost_packet_bitmask & (std::uint16_t {1} << (position - 1U))) != 0;
    };
    const auto sequence = [&nack](const std::size_t pair_index, const std::size_t position) constexpr noexcept {
      return static_cast<std::uint16_t>(nack.pairs[pair_index].packet_id + position);
    };
    const auto appeared_before = [&selected, &sequence](
                                   const std::size_t pair_index,
                                   const std::size_t position,
                                   const std::uint16_t candidate
                                 ) constexpr noexcept {
      for (std::size_t prior_pair = 0; prior_pair <= pair_index; ++prior_pair) {
        const auto positions = prior_pair == pair_index ? position : 17U;
        for (std::size_t prior_position = 0; prior_position < positions; ++prior_position) {
          if (selected(prior_pair, prior_position) && sequence(prior_pair, prior_position) == candidate) {
            return true;
          }
        }
      }
      return false;
    };

    std::size_t required = 0;
    for (std::size_t pair_index = 0; pair_index < nack.pair_count; ++pair_index) {
      for (std::size_t position = 0; position < 17U; ++position) {
        if (!selected(pair_index, position)) {
          continue;
        }
        const auto candidate = sequence(pair_index, position);
        if (!appeared_before(pair_index, position, candidate)) {
          ++required;
        }
      }
    }
    if (destination.size() < required) {
      return {.required = required, .error = generic_nack_expansion_error::destination_too_small};
    }
    std::size_t written = 0;
    for (std::size_t pair_index = 0; pair_index < nack.pair_count; ++pair_index) {
      for (std::size_t position = 0; position < 17U; ++position) {
        if (!selected(pair_index, position)) {
          continue;
        }
        const auto candidate = sequence(pair_index, position);
        if (!appeared_before(pair_index, position, candidate)) {
          destination[written++] = candidate;
        }
      }
    }
    return {.sequence_count = written, .required = required};
  }

  /** @brief Typed feedback model serialization failure. */
  enum class rtcp_feedback_error : std::uint8_t {
    none,  ///< Serialization completed successfully.
    invalid_ssrc,  ///< A required SSRC is zero.
    empty_feedback,  ///< A NACK or FIR contains no feedback records.
    invalid_count,  ///< Populated record count exceeds fixed storage or RTCP length bounds.
    duplicate_entry,  ///< FIR repeats a media-sender target in one packet.
    destination_too_small,  ///< Destination cannot contain the complete RTCP packet.
  };

  /** @brief Result of serializing one RTCP feedback model. */
  struct rtcp_feedback_write_result {
    std::size_t bytes_written = 0;  ///< Complete RTCP packet size on success.
    rtcp_feedback_error error = rtcp_feedback_error::none;  ///< Serialization status.

    /**
     * @brief Return whether serialization succeeded.
     *
     * @return `true` only when a complete packet was written.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtcp_feedback_error::none;
    }
  };

  /**
   * @brief Serialize one RFC 4585 Generic NACK as reduced-size RTCP.
   *
   * @tparam MaximumPairs Fixed pair capacity.
   * @param nack Feedback model.
   * @param destination Destination RTCP packet storage.
   * @return Byte count and typed status.
   */
  template<std::size_t MaximumPairs>
  [[nodiscard]] constexpr rtcp_feedback_write_result write_generic_nack(
    const generic_nack<MaximumPairs> &nack,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (nack.sender_ssrc == 0 || nack.media_ssrc == 0) {
      return {.error = rtcp_feedback_error::invalid_ssrc};
    }
    if (nack.pair_count == 0) {
      return {.error = rtcp_feedback_error::empty_feedback};
    }
    if (nack.pair_count > MaximumPairs || nack.pair_count > 16'380U) {
      return {.error = rtcp_feedback_error::invalid_count};
    }
    const auto required = 12U + nack.pair_count * 4U;
    if (destination.size() < required) {
      return {.error = rtcp_feedback_error::destination_too_small};
    }
    const auto packet = destination.first(required);
    detail::write_rtcp_header(packet, rtcp_generic_nack_format, rtcp_transport_feedback_type);
    detail::write_u32(packet.subspan(4, 4), nack.sender_ssrc);
    detail::write_u32(packet.subspan(8, 4), nack.media_ssrc);
    for (std::size_t index = 0; index < nack.pair_count; ++index) {
      detail::write_u16(packet.subspan(12U + index * 4U, 2), nack.pairs[index].packet_id);
      detail::write_u16(packet.subspan(14U + index * 4U, 2), nack.pairs[index].lost_packet_bitmask);
    }
    return {.bytes_written = required};
  }

  /**
   * @brief Serialize one RFC 4585 Picture Loss Indication as reduced-size RTCP.
   *
   * @param pli Feedback model.
   * @param destination Destination RTCP packet storage.
   * @return Byte count and typed status.
   */
  [[nodiscard]] constexpr rtcp_feedback_write_result write_picture_loss_indication(
    const picture_loss_indication &pli,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (pli.sender_ssrc == 0 || pli.media_ssrc == 0) {
      return {.error = rtcp_feedback_error::invalid_ssrc};
    }
    constexpr auto required = std::size_t {12};
    if (destination.size() < required) {
      return {.error = rtcp_feedback_error::destination_too_small};
    }
    const auto packet = destination.first(required);
    detail::write_rtcp_header(packet, rtcp_picture_loss_indication_format, rtcp_payload_feedback_type);
    detail::write_u32(packet.subspan(4, 4), pli.sender_ssrc);
    detail::write_u32(packet.subspan(8, 4), pli.media_ssrc);
    return {.bytes_written = required};
  }

  /**
   * @brief Serialize one RFC 5104 Full Intra Request as reduced-size RTCP.
   *
   * @tparam MaximumEntries Fixed entry capacity.
   * @param fir Feedback model.
   * @param destination Destination RTCP packet storage.
   * @return Byte count and typed status.
   */
  template<std::size_t MaximumEntries>
  [[nodiscard]] constexpr rtcp_feedback_write_result write_full_intra_request(
    const full_intra_request<MaximumEntries> &fir,
    const std::span<std::uint8_t> destination
  ) noexcept {
    if (fir.sender_ssrc == 0) {
      return {.error = rtcp_feedback_error::invalid_ssrc};
    }
    if (fir.entry_count == 0) {
      return {.error = rtcp_feedback_error::empty_feedback};
    }
    if (fir.entry_count > MaximumEntries || fir.entry_count > 8'190U) {
      return {.error = rtcp_feedback_error::invalid_count};
    }
    for (std::size_t index = 0; index < fir.entry_count; ++index) {
      if (fir.entries[index].media_sender_ssrc == 0) {
        return {.error = rtcp_feedback_error::invalid_ssrc};
      }
      for (std::size_t prior = 0; prior < index; ++prior) {
        if (fir.entries[prior].media_sender_ssrc == fir.entries[index].media_sender_ssrc) {
          return {.error = rtcp_feedback_error::duplicate_entry};
        }
      }
    }
    const auto required = 12U + fir.entry_count * 8U;
    if (destination.size() < required) {
      return {.error = rtcp_feedback_error::destination_too_small};
    }
    const auto packet = destination.first(required);
    detail::write_rtcp_header(packet, rtcp_full_intra_request_format, rtcp_payload_feedback_type);
    detail::write_u32(packet.subspan(4, 4), fir.sender_ssrc);
    detail::write_u32(packet.subspan(8, 4), 0);
    for (std::size_t index = 0; index < fir.entry_count; ++index) {
      const auto offset = 12U + index * 8U;
      detail::write_u32(packet.subspan(offset, 4), fir.entries[index].media_sender_ssrc);
      packet[offset + 4U] = fir.entries[index].sequence_number;
      std::fill(packet.begin() + static_cast<std::ptrdiff_t>(offset + 5U), packet.begin() + static_cast<std::ptrdiff_t>(offset + 8U), 0);
    }
    return {.bytes_written = required};
  }

  /** @brief ECN state carried by one RFC 8888 received-packet report. */
  enum class ecn_mark : std::uint8_t {
    not_ect = 0,  ///< Packet was not ECN capable.
    ect1 = 1,  ///< Packet carried ECT(1), IP ECN codepoint `01`.
    ect0 = 2,  ///< Packet carried ECT(0), IP ECN codepoint `10`.
    congestion_experienced = 3,  ///< Packet carried ECN-CE.
  };

  /** @brief Largest ordinary RFC 8888 arrival-time offset. */
  inline constexpr std::uint16_t congestion_ato_maximum = 0x1ffdU;
  /** @brief RFC 8888 arrival-time offset meaning older than the representable interval. */
  inline constexpr std::uint16_t congestion_ato_over_range = 0x1ffeU;
  /** @brief RFC 8888 arrival-time offset meaning no usable arrival timestamp. */
  inline constexpr std::uint16_t congestion_ato_unavailable = 0x1fffU;

  /**
   * @brief Encode a monotonic receive-to-report delay into RFC 8888 ATO units.
   *
   * @param arrival_microseconds Authenticated packet arrival, or zero when unavailable.
   * @param report_microseconds Monotonic instant represented by the report timestamp.
   * @return Ordinary 1/1024-second ATO, over-range, or unavailable sentinel.
   */
  [[nodiscard]] constexpr std::uint16_t encode_congestion_ato(
    const std::uint64_t arrival_microseconds,
    const std::uint64_t report_microseconds
  ) noexcept {
    if (arrival_microseconds == 0 || report_microseconds < arrival_microseconds) {
      return congestion_ato_unavailable;
    }
    const auto delay = report_microseconds - arrival_microseconds;
    const auto maximum_delay = static_cast<std::uint64_t>(congestion_ato_maximum) * 1'000'000ULL / 1'024ULL;
    if (delay > maximum_delay) {
      return congestion_ato_over_range;
    }
    return static_cast<std::uint16_t>(delay * 1'024ULL / 1'000'000ULL);
  }

  /** @brief Maximum distinct SSRC report blocks admitted from one RFC 8888 packet. */
  inline constexpr std::size_t maximum_congestion_feedback_blocks = 8;

  /** @brief One structurally validated RFC 8888 SSRC block backed by the input packet. */
  struct congestion_feedback_block_view {
    std::uint32_t media_ssrc = 0;  ///< Nonzero reported media SSRC.
    std::uint16_t begin_sequence = 0;  ///< First sequence in the Errata 8166 half-open range.
    std::uint16_t report_count = 0;  ///< Exact number of following metrics.
    std::span<const std::uint8_t> metrics {};  ///< Exact metrics without odd-count alignment padding.
  };

  /** @brief Complete structurally validated RFC 8888 feedback backed by caller-owned bytes. */
  struct congestion_feedback_packet_view {
    std::array<congestion_feedback_block_view, maximum_congestion_feedback_blocks> blocks {};  ///< Unique blocks.
    std::size_t block_count = 0;  ///< Populated leading block count.
    std::uint32_t report_timestamp = 0;  ///< Final middle-32-bit NTP report timestamp.
    rtcp_parse_error error {rtcp_parse_error::none};  ///< Structural validation result.

    /** @brief Return whether the complete standalone feedback packet is valid. */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == rtcp_parse_error::none && block_count != 0;
    }
  };

  /**
   * @brief Validate one complete standalone or compound-member RFC 8888 packet.
   *
   * @param packet Exact RTCP feedback packet, not an enclosing compound datagram.
   * @param expected_sender_ssrc Negotiated RTCP feedback sender SSRC.
   * @return Immutable bounded block/timestamp views or a fail-closed error.
   */
  [[nodiscard]] constexpr congestion_feedback_packet_view validate_congestion_feedback_packet(
    const std::span<const std::uint8_t> packet,
    const std::uint32_t expected_sender_ssrc
  ) noexcept {
    const auto parsed = parse_rtcp_packet(packet);
    if (!parsed || parsed.packet.size() != packet.size() || parsed.padding || expected_sender_ssrc == 0 ||
        parsed.packet_type != rtcp_transport_feedback_type || parsed.count != rtcp_congestion_feedback_format ||
        parsed.payload.size() < 16U || detail::read_u32(parsed.payload.first<4>()) != expected_sender_ssrc) {
      return {.error = rtcp_parse_error::invalid_payload};
    }

    congestion_feedback_packet_view result;
    const auto blocks_end = parsed.payload.size() - 4U;
    std::size_t offset = 4U;
    std::size_t aggregate_metrics = 0;
    while (offset < blocks_end) {
      if (result.block_count == result.blocks.size() || blocks_end - offset < 8U) {
        return {.error = rtcp_parse_error::invalid_payload};
      }
      const auto media_ssrc = detail::read_u32(parsed.payload.subspan(offset, 4));
      const auto begin_sequence = detail::read_u16(parsed.payload.subspan(offset + 4U, 2));
      const auto report_count = detail::read_u16(parsed.payload.subspan(offset + 6U, 2));
      if (media_ssrc == 0 || report_count > 16'384U || aggregate_metrics > 16'384U - report_count) {
        return {.error = rtcp_parse_error::invalid_payload};
      }
      for (std::size_t index = 0; index < result.block_count; ++index) {
        if (result.blocks[index].media_ssrc == media_ssrc) {
          return {.error = rtcp_parse_error::invalid_payload};
        }
      }
      offset += 8U;
      const auto metric_bytes = static_cast<std::size_t>(report_count) * 2U;
      const auto alignment_bytes = (report_count & 1U) != 0U ? 2U : 0U;
      if (metric_bytes + alignment_bytes > blocks_end - offset) {
        return {.error = rtcp_parse_error::invalid_payload};
      }
      const auto metrics = parsed.payload.subspan(offset, metric_bytes);
      for (std::size_t index = 0; index < report_count; ++index) {
        const auto metric = detail::read_u16(metrics.subspan(index * 2U, 2));
        if ((metric & 0x8000U) == 0 && (metric & 0x7fffU) != 0) {
          return {.error = rtcp_parse_error::invalid_payload};
        }
      }
      if (alignment_bytes != 0U && detail::read_u16(parsed.payload.subspan(offset + metric_bytes, 2)) != 0) {
        return {.error = rtcp_parse_error::invalid_payload};
      }
      result.blocks[result.block_count++] = {
        .media_ssrc = media_ssrc,
        .begin_sequence = begin_sequence,
        .report_count = report_count,
        .metrics = metrics,
      };
      aggregate_metrics += report_count;
      offset += metric_bytes + alignment_bytes;
    }
    if (offset != blocks_end || result.block_count == 0) {
      return {.error = rtcp_parse_error::invalid_payload};
    }
    result.report_timestamp = detail::read_u32(parsed.payload.last<4>());
    return result;
  }

  /** @brief One bounded RFC 8888 packet-reception observation. */
  struct congestion_packet_report {
    std::uint32_t media_ssrc = 0;  ///< Active received media SSRC.
    std::uint32_t extended_sequence_number = 0;  ///< Extended RTP sequence number.
    std::uint64_t arrival_microseconds = 0;  ///< Monotonic packet arrival time.
    std::uint16_t received_bytes = 0;  ///< Complete received IP-layer bytes.
    ecn_mark ecn = ecn_mark::not_ect;  ///< Observed ECN field.
  };

  /** @brief Result of adding a packet to the bounded feedback window. */
  enum class congestion_report_result : std::uint8_t {
    accepted,  ///< Observation was retained.
    invalid_ssrc,  ///< Media SSRC zero is forbidden.
    invalid_size,  ///< Complete packet byte count is zero.
    non_monotonic_arrival,  ///< Arrival time moved backwards within the window.
    full,  ///< Caller-provided bounded storage is exhausted.
  };

  /** @brief Two-span view of the disjoint reports pending transmission. */
  struct congestion_report_batch {
    std::span<const congestion_packet_report> first {};  ///< First contiguous ring segment.
    std::span<const congestion_packet_report> second {};  ///< Wrapped ring segment, if any.
    std::uint64_t interval_begin_microseconds = 0;  ///< Prior committed report time.
    std::uint64_t interval_end_microseconds = 0;  ///< Proposed report time.

    /**
     * @brief Return the number of pending packet reports.
     *
     * @return Aggregate record count across both spans.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return first.size() + second.size();
    }
  };

  /**
   * @brief Allocation-free RFC 8888 feedback cadence and report window.
   *
   * Reports become eligible at the earlier of two milliseconds or 128 packets, while the
   * 500-microsecond floor always prevents feedback storms. Committing a report consumes the exact
   * disjoint record range; no packet observation is repeated by the state machine.
   *
   * @tparam Capacity Maximum packet observations retained between reports.
   */
  template<std::size_t Capacity = 512>
  class congestion_feedback_window {
  public:
    static_assert(Capacity >= congestion_feedback_packet_cadence, "RFC 8888 window must hold one packet-cadence interval");

    /**
     * @brief Establish the first feedback interval.
     *
     * @param now_microseconds Current monotonic time.
     */
    constexpr void reset(const std::uint64_t now_microseconds) noexcept {
      head_ = 0;
      size_ = 0;
      last_report_microseconds_ = now_microseconds;
      latest_arrival_microseconds_ = 0;
      initialized_ = true;
    }

    /**
     * @brief Retain one authenticated received-packet observation.
     *
     * @param report Packet report.
     * @return Typed insertion result.
     */
    constexpr congestion_report_result record(const congestion_packet_report &report) noexcept {
      if (report.media_ssrc == 0) {
        return congestion_report_result::invalid_ssrc;
      }
      if (report.received_bytes == 0) {
        return congestion_report_result::invalid_size;
      }
      if (size_ != 0 && report.arrival_microseconds < latest_arrival_microseconds_) {
        return congestion_report_result::non_monotonic_arrival;
      }
      if (size_ == Capacity) {
        return congestion_report_result::full;
      }
      reports_[(head_ + size_) % Capacity] = report;
      ++size_;
      latest_arrival_microseconds_ = report.arrival_microseconds;
      return congestion_report_result::accepted;
    }

    /**
     * @brief Return whether cadence and hard-floor rules permit a report now.
     *
     * @param now_microseconds Current monotonic time.
     * @return `true` when at least one report is pending and a cadence trigger fired.
     */
    [[nodiscard]] constexpr bool report_due(const std::uint64_t now_microseconds) const noexcept {
      if (!initialized_ || size_ == 0 || now_microseconds < last_report_microseconds_) {
        return false;
      }
      const auto elapsed = now_microseconds - last_report_microseconds_;
      return elapsed >= congestion_feedback_floor_microseconds &&
             (size_ >= congestion_feedback_packet_cadence || elapsed >= congestion_feedback_interval_microseconds);
    }

    /**
     * @brief Borrow every packet observation for the next disjoint report.
     *
     * @param now_microseconds Proposed report transmission time.
     * @return Two-span ring view, empty when feedback is not due.
     */
    [[nodiscard]] constexpr congestion_report_batch pending_report(
      const std::uint64_t now_microseconds
    ) const noexcept {
      if (!report_due(now_microseconds)) {
        return {};
      }
      const auto first_count = std::min(size_, Capacity - head_);
      return {
        .first = std::span<const congestion_packet_report> {reports_}.subspan(head_, first_count),
        .second = std::span<const congestion_packet_report> {reports_}.first(size_ - first_count),
        .interval_begin_microseconds = last_report_microseconds_,
        .interval_end_microseconds = now_microseconds,
      };
    }

    /**
     * @brief Commit the current disjoint report after successful SRTCP submission.
     *
     * New observations cannot be added between borrowing and committing the report on the
     * thread-owned feedback state.
     *
     * @param now_microseconds Exact monotonic transmission time used by `pending_report()`.
     * @return Number of observations consumed, or zero when feedback is not due.
     */
    constexpr std::size_t commit_report(const std::uint64_t now_microseconds) noexcept {
      if (!report_due(now_microseconds)) {
        return 0;
      }
      const auto consumed = size_;
      head_ = (head_ + consumed) % Capacity;
      size_ = 0;
      latest_arrival_microseconds_ = 0;
      last_report_microseconds_ = now_microseconds;
      return consumed;
    }

    /**
     * @brief Return the number of pending packet observations.
     *
     * @return Bounded pending count.
     */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

  private:
    std::array<congestion_packet_report, Capacity> reports_ {};  ///< Fixed packet-report ring.
    std::size_t head_ = 0;  ///< First pending report index.
    std::size_t size_ = 0;  ///< Number of pending reports.
    std::uint64_t last_report_microseconds_ = 0;  ///< Most recent committed report time.
    std::uint64_t latest_arrival_microseconds_ = 0;  ///< Latest retained arrival time.
    bool initialized_ = false;  ///< Whether `reset()` established the interval origin.
  };

  /** @brief One sequence position in a reorder-tolerant RFC 8888 receive window. */
  struct congestion_reception_slot {
    std::uint64_t arrival_microseconds = 0;  ///< First authenticated arrival, or zero for a gap.
    ecn_mark ecn = ecn_mark::not_ect;  ///< First mark, upgraded to CE on any duplicate CE copy.
    bool received = false;  ///< Whether at least one authenticated copy arrived.
  };

  /** @brief Borrowed contiguous sequence range for one RFC 8888 block. */
  struct reordering_congestion_report_batch {
    std::span<const congestion_reception_slot> first {};  ///< First ring segment.
    std::span<const congestion_reception_slot> second {};  ///< Wrapped ring segment.
    std::uint32_t media_ssrc = 0;  ///< Sole media SSRC represented by the block.
    std::uint32_t begin_extended_sequence = 0;  ///< First extended sequence, including gaps.
    std::uint64_t interval_begin_microseconds = 0;  ///< Prior committed report time.
    std::uint64_t interval_end_microseconds = 0;  ///< Proposed final-send time.
    bool correction = false;  ///< Whether this is one late overlap correction rather than the main prefix.

    /** @brief Return the exact half-open report count including missing packets. */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return first.size() + second.size();
    }
  };

  /** @brief Admission result for reorder-tolerant authenticated reception. */
  enum class reordering_congestion_report_result : std::uint8_t {
    accepted,  ///< New sequence position was retained.
    duplicate,  ///< Existing reception was retained or upgraded to CE.
    stale,  ///< Sequence precedes the current uncommitted range.
    invalid,  ///< SSRC, size, or arrival time is invalid.
    full,  ///< Sequence would exceed bounded range capacity.
  };

  /**
   * @brief Bounded gap-preserving, reorder-tolerant RFC 8888 receive window.
   *
   * @tparam Capacity Maximum contiguous sequence positions retained, including gaps.
   */
  template<std::size_t Capacity = 512>
  class reordering_congestion_feedback_window {
  public:
    static_assert(Capacity >= congestion_feedback_packet_cadence);

    /** @brief Reset one SSRC and feedback interval, discarding uncommitted state. */
    constexpr void reset(const std::uint32_t media_ssrc, const std::uint64_t now_microseconds) noexcept {
      slots_ = {};
      head_ = 0;
      size_ = 0;
      media_ssrc_ = media_ssrc;
      begin_extended_sequence_ = 0;
      last_report_microseconds_ = now_microseconds;
      has_sequence_ = false;
      history_ = {};
      history_head_ = 0;
      history_size_ = 0;
      corrections_ = {};
      correction_head_ = 0;
      correction_size_ = 0;
    }

    /** @brief Retain authenticated reception before any downstream playout admission. */
    constexpr reordering_congestion_report_result record(
      const congestion_packet_report &report
    ) noexcept {
      if (report.media_ssrc == 0 || report.media_ssrc != media_ssrc_ || report.received_bytes == 0 ||
          report.arrival_microseconds == 0) {
        return reordering_congestion_report_result::invalid;
      }
      if (!has_sequence_) {
        begin_extended_sequence_ = report.extended_sequence_number;
        has_sequence_ = true;
        size_ = 1;
      }
      if (report.extended_sequence_number < begin_extended_sequence_) {
        auto *history = find_history(report.extended_sequence_number);
        if (history == nullptr) {
          return reordering_congestion_report_result::stale;
        }
        const auto was_received = history->slot.received;
        const auto prior_ecn = history->slot.ecn;
        if (was_received) {
          history->slot.arrival_microseconds = std::min(
            history->slot.arrival_microseconds,
            report.arrival_microseconds
          );
          if (report.ecn == ecn_mark::congestion_experienced) {
            history->slot.ecn = ecn_mark::congestion_experienced;
          }
        } else {
          history->slot = {
            .arrival_microseconds = report.arrival_microseconds,
            .ecn = report.ecn,
            .received = true,
          };
        }
        if (!was_received ||
            (prior_ecn != ecn_mark::congestion_experienced &&
             history->slot.ecn == ecn_mark::congestion_experienced)) {
          queue_correction(report.extended_sequence_number, history->slot);
        }
        return was_received ?
                 reordering_congestion_report_result::duplicate :
                 reordering_congestion_report_result::accepted;
      }
      const auto offset = static_cast<std::uint64_t>(report.extended_sequence_number) - begin_extended_sequence_;
      if (offset >= Capacity) {
        return reordering_congestion_report_result::full;
      }
      if (offset >= size_) {
        size_ = static_cast<std::size_t>(offset) + 1U;
      }
      auto &slot = slots_[(head_ + static_cast<std::size_t>(offset)) % Capacity];
      if (slot.received) {
        if (report.ecn == ecn_mark::congestion_experienced) {
          slot.ecn = ecn_mark::congestion_experienced;
        }
        slot.arrival_microseconds = std::min(slot.arrival_microseconds, report.arrival_microseconds);
        return reordering_congestion_report_result::duplicate;
      }
      slot = {
        .arrival_microseconds = report.arrival_microseconds,
        .ecn = report.ecn,
        .received = true,
      };
      return reordering_congestion_report_result::accepted;
    }

    /** @brief Return whether the two-millisecond/128-position cadence is due. */
    [[nodiscard]] constexpr bool report_due(const std::uint64_t now_microseconds) const noexcept {
      if (!has_sequence_ || now_microseconds < last_report_microseconds_) {
        return false;
      }
      const auto elapsed = now_microseconds - last_report_microseconds_;
      if (elapsed < congestion_feedback_floor_microseconds) {
        return false;
      }
      return correction_size_ != 0 ||
             (size_ != 0 &&
              (size_ >= congestion_feedback_packet_cadence ||
               elapsed >= congestion_feedback_interval_microseconds));
    }

    /** @brief Borrow the current exact sequence prefix without consuming it. */
    [[nodiscard]] constexpr reordering_congestion_report_batch pending_report(
      const std::uint64_t now_microseconds
    ) const noexcept {
      if (!report_due(now_microseconds)) {
        return {};
      }
      if (correction_size_ != 0) {
        const auto &correction = corrections_[correction_head_];
        return {
          .first = std::span<const congestion_reception_slot> {&correction.slot, 1},
          .media_ssrc = media_ssrc_,
          .begin_extended_sequence = correction.extended_sequence,
          .interval_begin_microseconds = last_report_microseconds_,
          .interval_end_microseconds = now_microseconds,
          .correction = true,
        };
      }
      const auto first_size = std::min(size_, Capacity - head_);
      return {
        .first = std::span<const congestion_reception_slot> {slots_}.subspan(head_, first_size),
        .second = std::span<const congestion_reception_slot> {slots_}.first(size_ - first_size),
        .media_ssrc = media_ssrc_,
        .begin_extended_sequence = begin_extended_sequence_,
        .interval_begin_microseconds = last_report_microseconds_,
        .interval_end_microseconds = now_microseconds,
      };
    }

    /** @brief Consume only the borrowed prefix after successful final socket submission. */
    constexpr bool commit_report(
      const std::uint32_t begin_extended_sequence,
      const std::size_t count,
      const std::uint64_t sent_microseconds
    ) noexcept {
      if (count == 0 || sent_microseconds < last_report_microseconds_) {
        return false;
      }
      if (correction_size_ != 0 && count == 1 &&
          corrections_[correction_head_].extended_sequence == begin_extended_sequence) {
        corrections_[correction_head_] = {};
        correction_head_ = (correction_head_ + 1U) % corrections_.size();
        --correction_size_;
        last_report_microseconds_ = sent_microseconds;
        return true;
      }
      if (begin_extended_sequence != begin_extended_sequence_ || count > size_) {
        return false;
      }
      for (std::size_t index = 0; index < count; ++index) {
        const auto extended_sequence = begin_extended_sequence_ + static_cast<std::uint32_t>(index);
        retain_history(extended_sequence, slots_[(head_ + index) % Capacity]);
        slots_[(head_ + index) % Capacity] = {};
      }
      head_ = (head_ + count) % Capacity;
      size_ -= count;
      begin_extended_sequence_ += static_cast<std::uint32_t>(count);
      last_report_microseconds_ = sent_microseconds;
      return true;
    }

    /** @brief Compatibility commit for callers that borrowed the current leading report. */
    constexpr bool commit_report(const std::size_t count, const std::uint64_t sent_microseconds) noexcept {
      const auto begin = correction_size_ != 0 ?
                           corrections_[correction_head_].extended_sequence :
                           begin_extended_sequence_;
      return commit_report(begin, count, sent_microseconds);
    }

    /** @brief Return current report positions including gaps. */
    [[nodiscard]] constexpr std::size_t size() const noexcept {
      return size_;
    }

  private:
    /** @brief One recently committed sequence retained for bounded overlap correction. */
    struct committed_reception {
      congestion_reception_slot slot {};  ///< Last reportable reception state.
      std::uint32_t extended_sequence = 0;  ///< Exact committed sequence identity.
      bool occupied = false;  ///< Whether this entry is live.
    };

    /** @brief One pending one-sequence overlap correction. */
    struct correction_reception {
      congestion_reception_slot slot {};  ///< Corrected received/CE state.
      std::uint32_t extended_sequence = 0;  ///< Exact sequence reported by overlap.
      bool occupied = false;  ///< Whether this queue entry is live.
    };

    static constexpr std::size_t overlap_capacity = std::min<std::size_t>(Capacity, 64U);

    [[nodiscard]] constexpr committed_reception *find_history(const std::uint32_t sequence) noexcept {
      for (std::size_t index = 0; index < history_size_; ++index) {
        auto &entry = history_[(history_head_ + index) % history_.size()];
        if (entry.occupied && entry.extended_sequence == sequence) {
          return &entry;
        }
      }
      return nullptr;
    }

    constexpr void retain_history(
      const std::uint32_t sequence,
      const congestion_reception_slot slot
    ) noexcept {
      const auto index = history_size_ < history_.size() ?
                           (history_head_ + history_size_++) % history_.size() :
                           history_head_;
      if (history_size_ == history_.size() && index == history_head_) {
        history_head_ = (history_head_ + 1U) % history_.size();
      }
      history_[index] = {
        .slot = slot,
        .extended_sequence = sequence,
        .occupied = true,
      };
    }

    constexpr void queue_correction(
      const std::uint32_t sequence,
      const congestion_reception_slot slot
    ) noexcept {
      for (std::size_t index = 0; index < correction_size_; ++index) {
        auto &entry = corrections_[(correction_head_ + index) % corrections_.size()];
        if (entry.occupied && entry.extended_sequence == sequence) {
          entry.slot = slot;
          return;
        }
      }
      const auto index = correction_size_ < corrections_.size() ?
                           (correction_head_ + correction_size_++) % corrections_.size() :
                           correction_head_;
      if (correction_size_ == corrections_.size() && index == correction_head_) {
        correction_head_ = (correction_head_ + 1U) % corrections_.size();
      }
      corrections_[index] = {
        .slot = slot,
        .extended_sequence = sequence,
        .occupied = true,
      };
    }

    std::array<congestion_reception_slot, Capacity> slots_ {};  ///< Bounded ring of receptions and gaps.
    std::array<committed_reception, overlap_capacity> history_ {};  ///< Recently committed overlap state.
    std::array<correction_reception, overlap_capacity> corrections_ {};  ///< Pending overlap corrections.
    std::size_t head_ = 0;  ///< First uncommitted sequence position.
    std::size_t size_ = 0;  ///< Current contiguous range length including gaps.
    std::size_t history_head_ = 0;  ///< Oldest committed overlap entry.
    std::size_t history_size_ = 0;  ///< Live committed overlap entries.
    std::size_t correction_head_ = 0;  ///< Oldest pending correction.
    std::size_t correction_size_ = 0;  ///< Live pending corrections.
    std::uint32_t media_ssrc_ = 0;  ///< Sole authenticated RTP source.
    std::uint32_t begin_extended_sequence_ = 0;  ///< Extended sequence at `head_`.
    std::uint64_t last_report_microseconds_ = 0;  ///< Last final-sent feedback time.
    bool has_sequence_ = false;  ///< Whether a report range has an origin.
  };

  /** @brief Decoder state carried by protected RTCP APP `LSPV`. */
  enum class lspv_decoder_status : std::uint8_t {
    ready,  ///< Decoder accepts complete frames.
    surface_exhausted,  ///< Hardware decode credit is temporarily exhausted.
    recoverable_error,  ///< Decoder needs reference repair or bounded recovery.
    unrecoverable_error,  ///< Decoder requires an independent recovery frame.
  };

  /** @brief Protected `LSPV` decoded and presented frame status model. */
  struct lspv_status {
    std::uint32_t session_generation = 0;  ///< Active stream-session generation.
    std::uint32_t video_generation = 0;  ///< Active video-configuration generation.
    std::uint32_t recovery_epoch = 0;  ///< Current recovery epoch, or zero before recovery.
    std::uint64_t largest_complete_frame_id = 0;  ///< Largest fully reassembled frame.
    std::uint64_t largest_decoded_frame_id = 0;  ///< Largest completed decoder frame.
    std::uint64_t largest_metal_committed_frame_id = 0;  ///< Largest frame committed for rendering.
    bool deadline_miss = false;  ///< Whether the coalesced transition observed a deadline miss.
    lspv_decoder_status decoder_status = lspv_decoder_status::ready;  ///< Current decoder health.
    std::uint8_t decode_submissions_in_flight = 0;  ///< Current hardware decode submissions.
    std::uint8_t maximum_decode_submissions = 2;  ///< Negotiated hardware credit, two through four.
    std::uint8_t render_mailbox_occupancy = 0;  ///< Latest-frame mailbox occupancy, zero or one.
  };

  /** @brief Validation failure for an `LSPV` status snapshot. */
  enum class lspv_status_error : std::uint8_t {
    none,  ///< Status is internally consistent.
    invalid_generation,  ///< Session or video generation is zero.
    invalid_frame_order,  ///< Presented/decoded/complete frame identifiers are inconsistent.
    invalid_decode_capacity,  ///< Maximum decode credit is outside two through four or is overdrawn.
    invalid_mailbox_occupancy,  ///< Render mailbox occupancy exceeds one.
  };

  /**
   * @brief Validate one protected `LSPV` semantic status before wire serialization.
   *
   * @param status Candidate status.
   * @return Typed validation status.
   */
  [[nodiscard]] constexpr lspv_status_error validate_lspv_status(const lspv_status &status) noexcept {
    if (status.session_generation == 0 || status.video_generation == 0) {
      return lspv_status_error::invalid_generation;
    }
    if (status.largest_metal_committed_frame_id > status.largest_decoded_frame_id ||
        status.largest_decoded_frame_id > status.largest_complete_frame_id) {
      return lspv_status_error::invalid_frame_order;
    }
    if (status.maximum_decode_submissions < 2U || status.maximum_decode_submissions > 4U ||
        status.decode_submissions_in_flight > status.maximum_decode_submissions) {
      return lspv_status_error::invalid_decode_capacity;
    }
    if (status.render_mailbox_occupancy > 1U) {
      return lspv_status_error::invalid_mailbox_occupancy;
    }
    return lspv_status_error::none;
  }

  /** @brief Event that requires a protected `LSPV` status update. */
  enum class lspv_event : std::uint8_t {
    decode_completion,  ///< A hardware decode completed.
    capacity_transition,  ///< Decoder credit or render mailbox capacity changed.
  };

  /** @brief Result of coalescing a new `LSPV` status update. */
  enum class lspv_update_result : std::uint8_t {
    accepted,  ///< Latest status replaced the pending snapshot.
    invalid_status,  ///< Status failed semantic validation.
    stale_generation,  ///< Status is older than the pending generation or recovery epoch.
  };

  /**
   * @brief Allocation-free 500-microsecond `LSPV` status coalescer.
   *
   * Recoverable and unrecoverable decoder evidence survives coalesced capacity updates in the
   * same recovery scope. A later ready decode clears it only after the decoded-frame watermark
   * advances, while a newer session, video generation, or recovery epoch starts a clean scope.
   */
  class lspv_coalescer {
  public:
    /**
     * @brief Retain the latest status for a decode completion or capacity transition.
     *
     * @param status Latest semantic status.
     * @param event Triggering transition.
     * @return Typed update result.
     */
    constexpr lspv_update_result update(const lspv_status &status, const lspv_event event) noexcept {
      if (validate_lspv_status(status) != lspv_status_error::none) {
        return lspv_update_result::invalid_status;
      }
      bool newer_scope = !has_generation_;
      if (has_generation_) {
        if (status.session_generation < session_generation_ ||
            (status.session_generation == session_generation_ && status.video_generation < video_generation_) ||
            (status.session_generation == session_generation_ && status.video_generation == video_generation_ &&
             status.recovery_epoch < recovery_epoch_)) {
          return lspv_update_result::stale_generation;
        }
        newer_scope = status.session_generation > session_generation_ ||
                      status.video_generation > video_generation_ || status.recovery_epoch > recovery_epoch_;
      }
      if (newer_scope) {
        evidence_ = {};
        evidence_valid_ = false;
      }
      pending_ = status;
      if (evidence_valid_ && event == lspv_event::decode_completion &&
          status.decoder_status == lspv_decoder_status::ready &&
          status.largest_decoded_frame_id > evidence_.decoded_frame_watermark) {
        evidence_ = {};
        evidence_valid_ = false;
      }
      const auto decoder_error = status.decoder_status == lspv_decoder_status::recoverable_error ||
                                 status.decoder_status == lspv_decoder_status::unrecoverable_error;
      if (decoder_error || status.deadline_miss) {
        evidence_.decoded_frame_watermark = evidence_valid_ ?
                                              std::max(evidence_.decoded_frame_watermark, status.largest_decoded_frame_id) :
                                              status.largest_decoded_frame_id;
        evidence_.deadline_miss = evidence_.deadline_miss || status.deadline_miss;
        if (decoder_error &&
            (!evidence_.has_decoder_error || status.decoder_status == lspv_decoder_status::unrecoverable_error)) {
          evidence_.decoder_status = status.decoder_status;
          evidence_.has_decoder_error = true;
        }
        evidence_valid_ = true;
      }
      if (evidence_valid_) {
        pending_.deadline_miss = pending_.deadline_miss || evidence_.deadline_miss;
        if (evidence_.has_decoder_error) {
          pending_.decoder_status = evidence_.decoder_status;
        }
      }
      pending_event_ = event;
      session_generation_ = status.session_generation;
      video_generation_ = status.video_generation;
      recovery_epoch_ = status.recovery_epoch;
      has_generation_ = true;
      pending_valid_ = true;
      return lspv_update_result::accepted;
    }

    /**
     * @brief Return whether one coalesced status may be submitted now.
     *
     * @param now_microseconds Current monotonic time.
     * @return `true` when status is pending and the 500-microsecond floor permits it.
     */
    [[nodiscard]] constexpr bool due(const std::uint64_t now_microseconds) const noexcept {
      if (!pending_valid_) {
        return false;
      }
      return !has_emitted_ ||
             (now_microseconds >= last_emit_microseconds_ &&
              now_microseconds - last_emit_microseconds_ >= lspv_minimum_interval_microseconds);
    }

    /**
     * @brief Consume the latest coalesced status after SRTCP submission is possible.
     *
     * @param now_microseconds Current monotonic time.
     * @param status Receives the coalesced status.
     * @param event Receives the latest triggering event.
     * @return `true` when a status was consumed.
     */
    constexpr bool take(
      const std::uint64_t now_microseconds,
      lspv_status &status,
      lspv_event &event
    ) noexcept {
      if (!due(now_microseconds)) {
        return false;
      }
      status = pending_;
      event = pending_event_;
      pending_valid_ = false;
      last_emit_microseconds_ = now_microseconds;
      has_emitted_ = true;
      return true;
    }

  private:
    /** @brief Decoder evidence retained until a later successful decode proves recovery. */
    struct latched_evidence {
      std::uint64_t decoded_frame_watermark = 0;  ///< Greatest decoded watermark carrying evidence.
      bool deadline_miss = false;  ///< Whether any retained update observed a deadline miss.
      lspv_decoder_status decoder_status = lspv_decoder_status::ready;  ///< Greatest retained decoder-error severity.
      bool has_decoder_error = false;  ///< Whether `decoder_status` carries an error.
    };

    lspv_status pending_ {};  ///< Latest coalesced semantic status.
    latched_evidence evidence_ {};  ///< Monotonic decoder evidence for the active recovery scope.
    lspv_event pending_event_ = lspv_event::decode_completion;  ///< Latest transition type.
    std::uint64_t last_emit_microseconds_ = 0;  ///< Latest committed SRTCP submission time.
    std::uint32_t session_generation_ = 0;  ///< Latest accepted session generation.
    std::uint32_t video_generation_ = 0;  ///< Latest accepted video generation.
    std::uint32_t recovery_epoch_ = 0;  ///< Latest accepted recovery epoch within the generation.
    bool pending_valid_ = false;  ///< Whether a status awaits transmission.
    bool has_emitted_ = false;  ///< Whether the coalescing floor has an origin.
    bool has_generation_ = false;  ///< Whether stale-generation checks have an origin.
    bool evidence_valid_ = false;  ///< Whether retained evidence must survive non-recovering updates.
  };
}  // namespace lumen::lsp::transport
