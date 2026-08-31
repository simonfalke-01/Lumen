/**
 * @file src/protocol_lsp/media/h264.h
 * @brief RFC 6184 non-interleaved H.264 RTP packetization for LSP/1.
 */

#pragma once

#include "common.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace lumen::lsp::media {
  /** @brief RFC 6184 STAP-A NAL-unit type. */
  inline constexpr std::uint8_t h264_stap_a_type = 24;

  /** @brief RFC 6184 FU-A NAL-unit type. */
  inline constexpr std::uint8_t h264_fu_a_type = 28;

  namespace detail {
    /**
     * @brief Return whether a source NAL unit is valid for non-interleaved packetization.
     *
     * @param nal Complete Annex-B-prefix-free NAL unit.
     * @return `true` for a nonempty single-NAL source type with a clear forbidden bit.
     */
    [[nodiscard]] constexpr bool valid_h264_nal(const std::span<const std::uint8_t> nal) noexcept {
      if (nal.empty() || (nal.front() & 0x80U) != 0) {
        return false;
      }
      const auto type = static_cast<std::uint8_t>(nal.front() & 0x1fU);
      return type >= 1U && type <= 23U;
    }

    /**
     * @brief Return whether all remaining H.264 data fits one final boundary packet.
     *
     * @param nals Same-frame source NAL units.
     * @param nal_index Current NAL index.
     * @param fragment_offset Offset after the one-byte NAL header, or zero outside fragmentation.
     * @param capacity Final packet's codec-payload capacity.
     * @return `true` when the remaining access unit has one legal single, STAP-A, or FU-A form.
     */
    [[nodiscard]] inline bool h264_remaining_fits_final(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t nal_index,
      const std::size_t fragment_offset,
      const std::size_t capacity
    ) noexcept {
      if (fragment_offset != 0) {
        return nal_index + 1 == nals.size() && capacity >= 2 && nals[nal_index].size() - fragment_offset <= capacity - 2;
      }
      if (nal_index + 1 == nals.size()) {
        return nals[nal_index].size() <= capacity;
      }
      std::size_t aggregate_size = 1;
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
     * @brief Build one RFC 6184 STAP-A payload.
     *
     * @param nals Same-frame source NAL units.
     * @param first First NAL index included.
     * @param count Number of NAL units included.
     * @return Complete STAP-A RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_h264_stap_a(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t first,
      const std::size_t count
    ) {
      std::uint8_t maximum_nri = 0;
      std::size_t size = 1;
      for (std::size_t index = first; index < first + count; ++index) {
        maximum_nri = std::max(maximum_nri, static_cast<std::uint8_t>(nals[index].front() & 0x60U));
        size += 2 + nals[index].size();
      }
      std::vector<std::uint8_t> payload;
      payload.reserve(size);
      payload.push_back(static_cast<std::uint8_t>(maximum_nri | h264_stap_a_type));
      for (std::size_t index = first; index < first + count; ++index) {
        const auto nal_size = static_cast<std::uint16_t>(nals[index].size());
        payload.push_back(static_cast<std::uint8_t>(nal_size >> 8U));
        payload.push_back(static_cast<std::uint8_t>(nal_size));
        payload.insert(payload.end(), nals[index].begin(), nals[index].end());
      }
      return payload;
    }

    /**
     * @brief Build one RFC 6184 FU-A payload fragment.
     *
     * @param nal Complete source NAL unit.
     * @param offset Payload offset after the source NAL header.
     * @param count Source payload bytes carried in this fragment.
     * @param start Whether this is the first fragment.
     * @param end Whether this is the final fragment.
     * @return Complete FU-A RTP payload.
     */
    [[nodiscard]] inline std::vector<std::uint8_t> make_h264_fu_a(
      const std::span<const std::uint8_t> nal,
      const std::size_t offset,
      const std::size_t count,
      const bool start,
      const bool end
    ) {
      std::vector<std::uint8_t> payload;
      payload.reserve(2 + count);
      payload.push_back(static_cast<std::uint8_t>((nal.front() & 0x60U) | h264_fu_a_type));
      payload.push_back(static_cast<std::uint8_t>((start ? 0x80U : 0U) | (end ? 0x40U : 0U) | (nal.front() & 0x1fU)));
      payload.insert(
        payload.end(),
        nal.begin() + static_cast<std::ptrdiff_t>(offset),
        nal.begin() + static_cast<std::ptrdiff_t>(offset + count)
      );
      return payload;
    }
  }  // namespace detail

  /**
   * @brief Packetize one H.264 access unit using RFC 6184 non-interleaved mode.
   *
   * Small same-frame NAL units are aggregated immediately into STAP-A packets. A large NAL unit
   * uses FU-A fragments. The routine never emits STAP-B, MTAP, FU-B, or cross-frame aggregation.
   * RTP marker is set only on the final packet of the access unit.
   *
   * @param nals Complete Annex-B-prefix-free NAL units from one encoded frame.
   * @param config RTP, path-payload, and frame-boundary extension configuration.
   * @return Complete RTP packets and typed status.
   */
  [[nodiscard]] inline packetization_result packetize_h264(
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
      if (!detail::valid_h264_nal(nal)) {
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
    if (boundary_capacity < 3 || middle_capacity < 3) {
      failure.error = packetization_error::path_payload_too_small;
      return failure;
    }

    std::vector<std::vector<std::uint8_t>> payloads;
    std::size_t nal_index = 0;
    std::size_t fragment_offset = 0;
    while (nal_index < nals.size()) {
      if (detail::h264_remaining_fits_final(nals, nal_index, fragment_offset, boundary_capacity)) {
        if (fragment_offset != 0) {
          const auto remaining = nals[nal_index].size() - fragment_offset;
          payloads.push_back(detail::make_h264_fu_a(nals[nal_index], fragment_offset, remaining, fragment_offset == 1, true));
        } else if (nal_index + 1 == nals.size()) {
          payloads.emplace_back(nals[nal_index].begin(), nals[nal_index].end());
        } else {
          payloads.push_back(detail::make_h264_stap_a(nals, nal_index, nals.size() - nal_index));
        }
        nal_index = nals.size();
        break;
      }

      const auto capacity = payloads.size() < 2 ? boundary_capacity : middle_capacity;
      const auto nal = nals[nal_index];
      if (fragment_offset != 0 || nal.size() > capacity || (nal_index + 1 == nals.size() && nal.size() > boundary_capacity)) {
        if (fragment_offset == 0) {
          fragment_offset = 1;
        }
        const auto remaining = nal.size() - fragment_offset;
        const auto data_capacity = capacity - 2;
        auto count = std::min(remaining, data_capacity);
        if (nal_index + 1 == nals.size() && count == remaining && remaining > boundary_capacity - 2) {
          --count;
        }
        if (count == 0) {
          failure.error = packetization_error::path_payload_too_small;
          return failure;
        }
        const auto end = count == remaining;
        payloads.push_back(detail::make_h264_fu_a(nal, fragment_offset, count, fragment_offset == 1, end));
        fragment_offset += count;
        if (end) {
          ++nal_index;
          fragment_offset = 0;
        }
        continue;
      }

      std::size_t aggregate_count = 0;
      std::size_t aggregate_size = 1;
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
        payloads.push_back(detail::make_h264_stap_a(nals, nal_index, aggregate_count));
        nal_index += aggregate_count;
      } else {
        payloads.emplace_back(nal.begin(), nal.end());
        ++nal_index;
      }
    }
    return detail::assemble_video_packets(std::move(payloads), config);
  }
}  // namespace lumen::lsp::media
