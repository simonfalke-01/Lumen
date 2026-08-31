/**
 * @file src/protocol_lsp/media/hevc.h
 * @brief RFC 7798 single-stream HEVC RTP packetization for LSP/1.
 */

#pragma once

#include "common.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace lumen::lsp::media {
  /** @brief RFC 7798 aggregation-packet NAL-unit type. */
  inline constexpr std::uint8_t hevc_ap_type = 48;

  /** @brief RFC 7798 fragmentation-unit NAL-unit type. */
  inline constexpr std::uint8_t hevc_fu_type = 49;

  namespace detail {
    /**
     * @brief Extract the six-bit HEVC NAL-unit type.
     *
     * @param nal Complete NAL unit.
     * @return HEVC NAL-unit type.
     */
    [[nodiscard]] constexpr std::uint8_t hevc_nal_type(const std::span<const std::uint8_t> nal) noexcept {
      return static_cast<std::uint8_t>((nal[0] >> 1U) & 0x3fU);
    }

    /**
     * @brief Return whether a source NAL unit is valid for RFC 7798 packetization.
     *
     * @param nal Complete Annex-B-prefix-free NAL unit.
     * @return `true` for a complete source NAL with valid forbidden, type, and temporal-ID fields.
     */
    [[nodiscard]] constexpr bool valid_hevc_nal(const std::span<const std::uint8_t> nal) noexcept {
      if (nal.size() < 2 || (nal[0] & 0x80U) != 0 || (nal[1] & 0x07U) == 0) {
        return false;
      }
      return hevc_nal_type(nal) <= 47U;
    }

    /**
     * @brief Extract the six-bit HEVC layer ID.
     *
     * @param nal Complete NAL unit.
     * @return Layer ID.
     */
    [[nodiscard]] constexpr std::uint8_t hevc_layer_id(const std::span<const std::uint8_t> nal) noexcept {
      return static_cast<std::uint8_t>(((nal[0] & 0x01U) << 5U) | (nal[1] >> 3U));
    }

    /**
     * @brief Extract the three-bit HEVC temporal ID plus one value.
     *
     * @param nal Complete NAL unit.
     * @return Nonzero temporal ID plus one.
     */
    [[nodiscard]] constexpr std::uint8_t hevc_temporal_id(const std::span<const std::uint8_t> nal) noexcept {
      return static_cast<std::uint8_t>(nal[1] & 0x07U);
    }

    /**
     * @brief Return whether all remaining HEVC data fits one final boundary packet.
     *
     * @param nals Same-frame source NAL units.
     * @param nal_index Current NAL index.
     * @param fragment_offset Offset after the two-byte NAL header, or zero outside fragmentation.
     * @param capacity Final packet codec-payload capacity.
     * @return `true` when one legal final single NAL, AP, or FU can contain all remaining bytes.
     */
    [[nodiscard]] inline bool hevc_remaining_fits_final(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t nal_index,
      const std::size_t fragment_offset,
      const std::size_t capacity
    ) noexcept {
      if (fragment_offset != 0) {
        return nal_index + 1 == nals.size() && capacity >= 3 && nals[nal_index].size() - fragment_offset <= capacity - 3;
      }
      if (nal_index + 1 == nals.size()) {
        return nals[nal_index].size() <= capacity;
      }
      std::size_t aggregate_size = 2;
      for (std::size_t index = nal_index; index < nals.size(); ++index) {
        if (nals[index].size() > std::numeric_limits<std::uint16_t>::max()) {
          return false;
        }
        aggregate_size += 2 + nals[index].size();
        if (aggregate_size > capacity) {
          return false;
        }
      }
      return true;
    }

    /**
     * @brief Build one RFC 7798 aggregation-packet payload.
     *
     * @param nals Same-frame source NAL units.
     * @param first First NAL index included.
     * @param count Number of NAL units included.
     * @return Complete HEVC AP RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_hevc_ap(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t first,
      const std::size_t count
    ) {
      std::size_t size = 2;
      for (std::size_t index = first; index < first + count; ++index) {
        size += 2 + nals[index].size();
      }
      std::vector<std::uint8_t> payload;
      payload.reserve(size);
      std::uint8_t lowest_layer_id = std::numeric_limits<std::uint8_t>::max();
      std::uint8_t lowest_temporal_id = std::numeric_limits<std::uint8_t>::max();
      for (std::size_t index = first; index < first + count; ++index) {
        lowest_layer_id = std::min(lowest_layer_id, hevc_layer_id(nals[index]));
        lowest_temporal_id = std::min(lowest_temporal_id, hevc_temporal_id(nals[index]));
      }
      payload.push_back(static_cast<std::uint8_t>((hevc_ap_type << 1U) | (lowest_layer_id >> 5U)));
      payload.push_back(static_cast<std::uint8_t>((lowest_layer_id << 3U) | lowest_temporal_id));
      for (std::size_t index = first; index < first + count; ++index) {
        const auto nal_size = static_cast<std::uint16_t>(nals[index].size());
        payload.push_back(static_cast<std::uint8_t>(nal_size >> 8U));
        payload.push_back(static_cast<std::uint8_t>(nal_size));
        payload.insert(payload.end(), nals[index].begin(), nals[index].end());
      }
      return payload;
    }

    /**
     * @brief Build one RFC 7798 fragmentation-unit payload.
     *
     * @param nal Complete source NAL unit.
     * @param offset Payload offset after the two-byte NAL header.
     * @param count Source payload bytes carried in this fragment.
     * @param start Whether this is the first fragment.
     * @param end Whether this is the final fragment.
     * @return Complete HEVC FU RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_hevc_fu(
      const std::span<const std::uint8_t> nal,
      const std::size_t offset,
      const std::size_t count,
      const bool start,
      const bool end
    ) {
      std::vector<std::uint8_t> payload;
      payload.reserve(3 + count);
      payload.push_back(static_cast<std::uint8_t>((nal[0] & 0x81U) | (hevc_fu_type << 1U)));
      payload.push_back(nal[1]);
      payload.push_back(static_cast<std::uint8_t>((start ? 0x80U : 0U) | (end ? 0x40U : 0U) | hevc_nal_type(nal)));
      payload.insert(
        payload.end(),
        nal.begin() + static_cast<std::ptrdiff_t>(offset),
        nal.begin() + static_cast<std::ptrdiff_t>(offset + count)
      );
      return payload;
    }
  }  // namespace detail

  /**
   * @brief Packetize one HEVC access unit using RFC 7798 single-stream mode.
   *
   * Small same-frame NAL units with matching layer and temporal IDs are aggregated immediately
   * into AP packets. Large NAL units use FU packets. PACI, DONL, and cross-frame aggregation are
   * not emitted. RTP marker is set only on the final packet of the access unit.
   *
   * @param nals Complete Annex-B-prefix-free NAL units from one encoded frame.
   * @param config RTP, path-payload, and frame-boundary extension configuration.
   * @return Complete RTP packets and typed status.
   */
  [[nodiscard]] inline packetization_result packetize_hevc(
    const std::span<const std::span<const std::uint8_t>> nals,
    const video_packetization_config &config
  ) {
    packetization_result failure;
    failure.next_sequence_number = config.stream.first_sequence_number;
    if (nals.empty()) {
      failure.error = packetization_error::empty_access_unit;
      return failure;
    }
    for (const auto nal : nals) {
      if (nal.empty()) {
        failure.error = packetization_error::empty_codec_unit;
        return failure;
      }
      if (!detail::valid_hevc_nal(nal)) {
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
    if (boundary_capacity < 4 || middle_capacity < 4) {
      failure.error = packetization_error::path_payload_too_small;
      return failure;
    }

    std::vector<std::vector<std::uint8_t>> payloads;
    std::size_t nal_index = 0;
    std::size_t fragment_offset = 0;
    while (nal_index < nals.size()) {
      if (detail::hevc_remaining_fits_final(nals, nal_index, fragment_offset, boundary_capacity)) {
        if (fragment_offset != 0) {
          const auto remaining = nals[nal_index].size() - fragment_offset;
          payloads.push_back(detail::make_hevc_fu(nals[nal_index], fragment_offset, remaining, fragment_offset == 2, true));
        } else if (nal_index + 1 == nals.size()) {
          payloads.emplace_back(nals[nal_index].begin(), nals[nal_index].end());
        } else {
          payloads.push_back(detail::make_hevc_ap(nals, nal_index, nals.size() - nal_index));
        }
        nal_index = nals.size();
        break;
      }

      const auto capacity = payloads.size() < 2 ? boundary_capacity : middle_capacity;
      const auto nal = nals[nal_index];
      if (fragment_offset != 0 || nal.size() > capacity || (nal_index + 1 == nals.size() && nal.size() > boundary_capacity)) {
        if (fragment_offset == 0) {
          fragment_offset = 2;
        }
        const auto remaining = nal.size() - fragment_offset;
        const auto data_capacity = capacity - 3;
        auto count = std::min(remaining, data_capacity);
        if (nal_index + 1 == nals.size() && count == remaining && remaining > boundary_capacity - 3) {
          --count;
        }
        if (count == 0) {
          failure.error = packetization_error::path_payload_too_small;
          return failure;
        }
        const auto end = count == remaining;
        payloads.push_back(detail::make_hevc_fu(nal, fragment_offset, count, fragment_offset == 2, end));
        fragment_offset += count;
        if (end) {
          ++nal_index;
          fragment_offset = 0;
        }
        continue;
      }

      std::size_t aggregate_count = 0;
      std::size_t aggregate_size = 2;
      for (std::size_t index = nal_index; index < nals.size(); ++index) {
        if (nals[index].size() > std::numeric_limits<std::uint16_t>::max()) {
          break;
        }
        const auto next_size = aggregate_size + 2 + nals[index].size();
        if (next_size > capacity) {
          break;
        }
        if (index + 1 == nals.size() && next_size > boundary_capacity) {
          break;
        }
        aggregate_size = next_size;
        ++aggregate_count;
      }
      if (aggregate_count >= 2) {
        payloads.push_back(detail::make_hevc_ap(nals, nal_index, aggregate_count));
        nal_index += aggregate_count;
      } else {
        payloads.emplace_back(nal.begin(), nal.end());
        ++nal_index;
      }
    }
    return detail::assemble_video_packets(std::move(payloads), config);
  }
}  // namespace lumen::lsp::media
