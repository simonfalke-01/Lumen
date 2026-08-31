/**
 * @file src/protocol_lsp/transport/rtcp.h
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

  /** @brief Typed feedback model serialization failure. */
  enum class rtcp_feedback_error : std::uint8_t {
    none,  ///< Serialization completed successfully.
    invalid_ssrc,  ///< A required SSRC is zero.
    empty_feedback,  ///< A NACK or FIR contains no feedback records.
    invalid_count,  ///< Populated record count exceeds fixed storage or RTCP length bounds.
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
    not_ect,  ///< Packet was not ECN capable.
    ect0,  ///< Packet carried ECT(0).
    ect1,  ///< Packet carried ECT(1).
    congestion_experienced,  ///< Packet carried ECN-CE.
  };

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
    stale_generation,  ///< Status is older than the pending or last emitted generation.
  };

  /** @brief Allocation-free 500-microsecond `LSPV` status coalescer. */
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
      if (has_generation_ &&
          (status.session_generation < session_generation_ ||
           (status.session_generation == session_generation_ && status.video_generation < video_generation_))) {
        return lspv_update_result::stale_generation;
      }
      pending_ = status;
      pending_event_ = event;
      session_generation_ = status.session_generation;
      video_generation_ = status.video_generation;
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
    lspv_status pending_ {};  ///< Latest coalesced semantic status.
    lspv_event pending_event_ = lspv_event::decode_completion;  ///< Latest transition type.
    std::uint64_t last_emit_microseconds_ = 0;  ///< Latest committed SRTCP submission time.
    std::uint32_t session_generation_ = 0;  ///< Latest accepted session generation.
    std::uint32_t video_generation_ = 0;  ///< Latest accepted video generation.
    bool pending_valid_ = false;  ///< Whether a status awaits transmission.
    bool has_emitted_ = false;  ///< Whether the coalescing floor has an origin.
    bool has_generation_ = false;  ///< Whether stale-generation checks have an origin.
  };
}  // namespace lumen::lsp::transport
