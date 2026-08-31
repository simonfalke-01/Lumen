/**
 * @file src/protocol_lsp/media/av1.h
 * @brief AOM AV1 RTP payload-format version 1.0 packetization for LSP/1.
 */

#pragma once

#include "common.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace lumen::lsp::media {
  /** @brief Parsed one-byte AV1 RTP aggregation header. */
  struct av1_aggregation_header {
    bool continuation_from_previous = false;  ///< `Z`: first element continues an OBU from the prior packet.
    bool continues_in_next = false;  ///< `Y`: final element continues in the next packet.
    std::uint8_t element_count = 0;  ///< `W`: zero means every element has a length, otherwise `1...3` elements.
    bool starts_coded_video_sequence = false;  ///< `N`: packet begins a new coded video sequence.

    /** @brief Compare every AV1 aggregation-header field. */
    [[nodiscard]] bool operator==(const av1_aggregation_header &) const noexcept = default;
  };

  /** @brief Typed AV1 aggregation-header parse failure. */
  enum class av1_header_error : std::uint8_t {
    none,  ///< Header is valid.
    header_too_short,  ///< No aggregation-header byte is available.
    reserved_bits,  ///< One or more reserved low bits are nonzero.
    invalid_sequence_start,  ///< `N` is set while `Z` says the first OBU began in an earlier packet.
  };

  /** @brief AV1 aggregation-header parse result. */
  struct av1_header_result {
    av1_aggregation_header header {};  ///< Parsed header fields.
    av1_header_error error = av1_header_error::none;  ///< Parse status.

    /**
     * @brief Return whether parsing succeeded.
     *
     * @return `true` only for a valid aggregation header.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept {
      return error == av1_header_error::none;
    }
  };

  /**
   * @brief Parse the one-byte AV1 RTP aggregation header.
   *
   * @param payload Complete or prefix AV1 RTP payload.
   * @return Parsed descriptor and typed status.
   */
  [[nodiscard]] constexpr av1_header_result parse_av1_aggregation_header(
    const std::span<const std::uint8_t> payload
  ) noexcept {
    if (payload.empty()) {
      return {.error = av1_header_error::header_too_short};
    }
    if ((payload[0] & 0x07U) != 0) {
      return {.error = av1_header_error::reserved_bits};
    }
    const av1_aggregation_header header {
      .continuation_from_previous = (payload[0] & 0x80U) != 0,
      .continues_in_next = (payload[0] & 0x40U) != 0,
      .element_count = static_cast<std::uint8_t>((payload[0] >> 4U) & 0x03U),
      .starts_coded_video_sequence = (payload[0] & 0x08U) != 0,
    };
    if (header.continuation_from_previous && header.starts_coded_video_sequence) {
      return {.error = av1_header_error::invalid_sequence_start};
    }
    return {.header = header};
  }

  namespace detail {
    /**
     * @brief Return whether an AV1 OBU element is normalized for the RTP payload format.
     *
     * OBU elements supplied to this packetizer exclude an external Annex-B length and must clear
     * `obu_has_size_field`. Temporal delimiter OBUs are omitted as required by the payload format.
     *
     * @param obu Complete normalized OBU element.
     * @return `true` when its header is suitable for RTP aggregation or fragmentation.
     */
    [[nodiscard]] constexpr bool valid_av1_obu(const std::span<const std::uint8_t> obu) noexcept {
      if (obu.empty() || (obu[0] & 0x80U) != 0 || (obu[0] & 0x03U) != 0) {
        return false;
      }
      const auto type = static_cast<std::uint8_t>((obu[0] >> 3U) & 0x0fU);
      if (type == 0U || type == 2U || type == 8U || (type >= 9U && type <= 14U)) {
        return false;
      }
      const auto has_extension = (obu[0] & 0x04U) != 0;
      return !has_extension || (obu.size() >= 2 && (obu[1] & 0x07U) == 0);
    }

    /**
     * @brief Return whether complete OBUs may share one AV1 aggregation packet.
     *
     * When multiple contained OBUs have extension headers, the AOM payload format requires their
     * temporal and spatial IDs to match.
     *
     * @param obus Same-temporal-unit OBU elements.
     * @param first First OBU index included.
     * @param count Number of candidate elements.
     * @return `true` when all extended elements have identical layer identifiers.
     */
    [[nodiscard]] inline bool av1_elements_may_aggregate(
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::size_t first,
      const std::size_t count
    ) noexcept {
      std::optional<std::uint8_t> layer_ids;
      for (std::size_t index = first; index < first + count; ++index) {
        if ((obus[index][0] & 0x04U) == 0) {
          continue;
        }
        const auto current = static_cast<std::uint8_t>(obus[index][1] & 0xf8U);
        if (layer_ids && *layer_ids != current) {
          return false;
        }
        layer_ids = current;
      }
      return true;
    }

    /**
     * @brief Calculate an AV1 packet size for complete aggregated OBU elements.
     *
     * @param obus Same-temporal-unit OBU elements.
     * @param first First OBU index included.
     * @param count Number of complete elements included.
     * @return Aggregation header, length fields, and element bytes.
     */
    [[nodiscard]] inline std::size_t av1_complete_packet_size(
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::size_t first,
      const std::size_t count
    ) noexcept {
      std::size_t size = 1;
      const auto explicit_all_lengths = count > 3;
      for (std::size_t relative = 0; relative < count; ++relative) {
        const auto element_size = obus[first + relative].size();
        if (explicit_all_lengths || relative + 1 < count) {
          size += leb128_size(element_size);
        }
        size += element_size;
      }
      return size;
    }

    /**
     * @brief Build an AV1 RTP payload containing complete OBU elements.
     *
     * @param obus Same-temporal-unit OBU elements.
     * @param first First OBU index included.
     * @param count Number of complete elements included.
     * @param starts_sequence Whether this is the first packet of a new coded video sequence.
     * @return Complete AV1 RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_av1_complete_payload(
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::size_t first,
      const std::size_t count,
      const bool starts_sequence
    ) {
      const auto w = count <= 3 ? static_cast<std::uint8_t>(count) : std::uint8_t {0};
      std::vector<std::uint8_t> payload;
      payload.reserve(av1_complete_packet_size(obus, first, count));
      payload.push_back(static_cast<std::uint8_t>((w << 4U) | (starts_sequence ? 0x08U : 0U)));
      for (std::size_t relative = 0; relative < count; ++relative) {
        const auto obu = obus[first + relative];
        if (w == 0 || relative + 1 < count) {
          const auto encoded_size = encode_leb128(obu.size());
          payload.insert(payload.end(), encoded_size.begin(), encoded_size.end());
        }
        payload.insert(payload.end(), obu.begin(), obu.end());
      }
      return payload;
    }

    /**
     * @brief Build one AV1 fragmented-OBU RTP payload.
     *
     * @param obu Complete source OBU element.
     * @param offset Source byte offset.
     * @param count Source bytes carried in this fragment.
     * @param continuation Whether the OBU started in a previous packet.
     * @param continues Whether the OBU continues in the next packet.
     * @param starts_sequence Whether this packet begins a new coded video sequence.
     * @return Complete AV1 RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_av1_fragment_payload(
      const std::span<const std::uint8_t> obu,
      const std::size_t offset,
      const std::size_t count,
      const bool continuation,
      const bool continues,
      const bool starts_sequence
    ) {
      std::vector<std::uint8_t> payload;
      payload.reserve(1 + count);
      payload.push_back(static_cast<std::uint8_t>((continuation ? 0x80U : 0U) | (continues ? 0x40U : 0U) | 0x10U | (starts_sequence ? 0x08U : 0U)));
      payload.insert(
        payload.end(),
        obu.begin() + static_cast<std::ptrdiff_t>(offset),
        obu.begin() + static_cast<std::ptrdiff_t>(offset + count)
      );
      return payload;
    }
  }  // namespace detail

  /**
   * @brief Packetize one AV1 temporal unit using AOM RTP payload format version 1.0.
   *
   * Complete normalized OBU elements are aggregated without crossing the supplied temporal-unit
   * boundary. Large elements use `Z`/`Y` fragmentation descriptors. `N` is emitted only on the
   * first packet of an explicitly identified coded-video-sequence start, and RTP marker is set on
   * the final packet of the temporal unit.
   *
   * @param obus Normalized OBU elements from one temporal unit, with OBU size fields removed.
   * @param starts_coded_video_sequence Whether this temporal unit begins a coded video sequence.
   * @param config RTP, path-payload, and frame-boundary extension configuration.
   * @return Complete RTP packets and typed status.
   */
  [[nodiscard]] inline packetization_result packetize_av1(
    const std::span<const std::span<const std::uint8_t>> obus,
    const bool starts_coded_video_sequence,
    const video_packetization_config &config
  ) {
    packetization_result failure;
    failure.next_sequence_number = config.stream.first_sequence_number;
    if (obus.empty()) {
      failure.error = packetization_error::empty_access_unit;
      return failure;
    }
    for (const auto obu : obus) {
      if (obu.empty()) {
        failure.error = packetization_error::empty_codec_unit;
        return failure;
      }
      if (!detail::valid_av1_obu(obu)) {
        failure.error = packetization_error::malformed_codec_unit;
        return failure;
      }
    }
    if (const auto status = detail::validate_video_config(config); status != packetization_error::none) {
      failure.error = status;
      return failure;
    }

    const auto boundary_capacity = detail::boundary_codec_capacity(config);
    const auto middle_capacity = detail::middle_codec_capacity(config);
    if (boundary_capacity < 2 || middle_capacity < 2) {
      failure.error = packetization_error::path_payload_too_small;
      return failure;
    }

    std::vector<std::vector<std::uint8_t>> payloads;
    std::size_t obu_index = 0;
    std::size_t fragment_offset = 0;
    while (obu_index < obus.size()) {
      const auto obu = obus[obu_index];
      if (fragment_offset != 0 && obu_index + 1 == obus.size() && obu.size() - fragment_offset <= boundary_capacity - 1) {
        const auto remaining = obu.size() - fragment_offset;
        payloads.push_back(detail::make_av1_fragment_payload(obu, fragment_offset, remaining, true, false, false));
        ++obu_index;
        break;
      }

      if (fragment_offset == 0) {
        std::size_t final_count = 0;
        for (std::size_t count = 1; count <= obus.size() - obu_index; ++count) {
          if (!detail::av1_elements_may_aggregate(obus, obu_index, count) ||
              detail::av1_complete_packet_size(obus, obu_index, count) > boundary_capacity) {
            break;
          }
          final_count = count;
        }
        if (final_count == obus.size() - obu_index) {
          payloads.push_back(detail::make_av1_complete_payload(obus, obu_index, final_count, starts_coded_video_sequence && payloads.empty()));
          obu_index = obus.size();
          break;
        }
      }

      const auto capacity = payloads.size() < 2 ? boundary_capacity : middle_capacity;
      if (fragment_offset != 0 || obu.size() + 1 > capacity || (obu_index + 1 == obus.size() && obu.size() + 1 > boundary_capacity)) {
        const auto remaining = obu.size() - fragment_offset;
        const auto data_capacity = capacity - 1;
        auto count = std::min(remaining, data_capacity);
        if (obu_index + 1 == obus.size() && count == remaining && remaining > boundary_capacity - 1) {
          --count;
        }
        if (count == 0) {
          failure.error = packetization_error::path_payload_too_small;
          return failure;
        }
        const auto end = count == remaining;
        payloads.push_back(detail::make_av1_fragment_payload(obu, fragment_offset, count, fragment_offset != 0, !end, starts_coded_video_sequence && payloads.empty() && fragment_offset == 0));
        fragment_offset += count;
        if (end) {
          ++obu_index;
          fragment_offset = 0;
        }
        continue;
      }

      std::size_t aggregate_count = 0;
      for (std::size_t count = 1; count <= obus.size() - obu_index; ++count) {
        if (!detail::av1_elements_may_aggregate(obus, obu_index, count)) {
          break;
        }
        const auto size = detail::av1_complete_packet_size(obus, obu_index, count);
        if (size > capacity) {
          break;
        }
        if (obu_index + count == obus.size() && size > boundary_capacity) {
          break;
        }
        aggregate_count = count;
      }
      if (aggregate_count == 0) {
        fragment_offset = 0;
        continue;
      }
      payloads.push_back(detail::make_av1_complete_payload(obus, obu_index, aggregate_count, starts_coded_video_sequence && payloads.empty()));
      obu_index += aggregate_count;
    }
    return detail::assemble_video_packets(std::move(payloads), config);
  }
}  // namespace lumen::lsp::media
