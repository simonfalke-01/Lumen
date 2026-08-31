/**
 * @file src/protocol_lsp/runtime/video_sender.cpp
 * @brief Complete-access-unit LSP SDR H.264/HEVC RTP/SRTP sender implementation.
 */

#include "video_sender.h"

#include "../../globals.h"
#include "../core/transport.h"
#include "../core/wire.h"
#include "../media/frame_pipeline.h"
#include "../media/h264.h"
#include "../media/hevc.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <thread>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

namespace lumen::lsp::runtime {
  namespace {
    constexpr std::size_t maximum_nal_units_per_access_unit = 1'024;  ///< Fixed Annex-B view bound.
    constexpr std::size_t maximum_extension_block_bytes = 64;  ///< Largest first-slice RFC 8285 block.
    constexpr std::size_t final_packet_slab_bytes = media::ipv4_udp_payload_ceiling;  ///< Largest protected UDP payload.
    constexpr std::size_t sender_srtp_tag_bytes = media::srtp_aead_tag_size;  ///< AEAD AES-128-GCM tag size.

    /** @brief One detected Annex-B prefix and its byte width. */
    struct AnnexBPrefix {
      std::size_t offset {};  ///< First zero byte of the prefix.
      std::size_t size {};  ///< Three- or four-byte prefix size.
    };

    /** @brief Allocation-free planned H.264/HEVC RTP codec-payload operation. */
    struct PacketPlan {
      /** @brief Codec-payload construction kind for one final RTP packet. */
      enum class Kind : std::uint8_t {
        single,  ///< One complete NAL unit.
        aggregate,  ///< Same-frame STAP-A or AP payload.
        fragment,  ///< H.264 FU-A or HEVC FU payload.
      } kind {Kind::single};  ///< Codec-payload construction kind.
      std::size_t nal_index {};  ///< First source NAL index.
      std::size_t nal_count {1};  ///< Aggregate NAL count.
      std::size_t fragment_offset {};  ///< Offset after the source NAL header.
      std::size_t fragment_bytes {};  ///< Source bytes in one fragment.
      bool fragment_start {};  ///< Whether this fragment starts its source NAL.
      bool fragment_end {};  ///< Whether this fragment ends its source NAL.
      std::size_t payload_bytes {};  ///< Exact codec-payload bytes.
    };

    /** @brief Calculate one H.264 STAP-A byte count. */
    [[nodiscard]] std::size_t h264_aggregate_bytes(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t first,
      const std::size_t count
    ) noexcept {
      std::size_t size = 1;
      for (std::size_t index = first; index < first + count; ++index) {
        size += 2U + nals[index].size();
      }
      return size;
    }

    /** @brief Calculate one HEVC AP byte count. */
    [[nodiscard]] std::size_t hevc_aggregate_bytes(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t first,
      const std::size_t count
    ) noexcept {
      std::size_t size = 2;
      for (std::size_t index = first; index < first + count; ++index) {
        size += 2U + nals[index].size();
      }
      return size;
    }

    /** @brief Plan H.264 payload packets without allocating or copying codec bytes. */
    [[nodiscard]] std::size_t plan_h264_packets(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t boundary_capacity,
      const std::size_t middle_capacity,
      const std::span<PacketPlan> plans
    ) noexcept {
      std::size_t plan_count = 0;
      std::size_t nal_index = 0;
      std::size_t fragment_offset = 0;
      while (nal_index < nals.size()) {
        if (plan_count == plans.size() || !media::detail::valid_h264_nal(nals[nal_index])) {
          return 0;
        }
        if (media::detail::h264_remaining_fits_final(nals, nal_index, fragment_offset, boundary_capacity)) {
          if (fragment_offset != 0) {
            const auto remaining = nals[nal_index].size() - fragment_offset;
            plans[plan_count++] = {.kind = PacketPlan::Kind::fragment, .nal_index = nal_index, .fragment_offset = fragment_offset, .fragment_bytes = remaining, .fragment_start = fragment_offset == 1, .fragment_end = true, .payload_bytes = remaining + 2U};
          } else if (nal_index + 1U == nals.size()) {
            plans[plan_count++] = {.kind = PacketPlan::Kind::single, .nal_index = nal_index, .payload_bytes = nals[nal_index].size()};
          } else {
            const auto count = nals.size() - nal_index;
            plans[plan_count++] = {.kind = PacketPlan::Kind::aggregate, .nal_index = nal_index, .nal_count = count, .payload_bytes = h264_aggregate_bytes(nals, nal_index, count)};
          }
          break;
        }
        const auto capacity = plan_count < 2U ? boundary_capacity : middle_capacity;
        const auto nal = nals[nal_index];
        if (fragment_offset != 0 || nal.size() > capacity || (nal_index + 1U == nals.size() && nal.size() > boundary_capacity)) {
          if (fragment_offset == 0) {
            fragment_offset = 1;
          }
          const auto remaining = nal.size() - fragment_offset;
          auto count = std::min(remaining, capacity - 2U);
          if (nal_index + 1U == nals.size() && count == remaining && remaining > boundary_capacity - 2U) {
            --count;
          }
          if (count == 0) {
            return 0;
          }
          const auto end = count == remaining;
          plans[plan_count++] = {.kind = PacketPlan::Kind::fragment, .nal_index = nal_index, .fragment_offset = fragment_offset, .fragment_bytes = count, .fragment_start = fragment_offset == 1, .fragment_end = end, .payload_bytes = count + 2U};
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
          const auto next_size = aggregate_size + 2U + nals[index].size();
          if (next_size > capacity || (index + 1U == nals.size() && next_size > boundary_capacity)) {
            break;
          }
          aggregate_size = next_size;
          ++aggregate_count;
        }
        if (aggregate_count >= 2) {
          plans[plan_count++] = {.kind = PacketPlan::Kind::aggregate, .nal_index = nal_index, .nal_count = aggregate_count, .payload_bytes = aggregate_size};
          nal_index += aggregate_count;
        } else {
          plans[plan_count++] = {.kind = PacketPlan::Kind::single, .nal_index = nal_index, .payload_bytes = nal.size()};
          ++nal_index;
        }
      }
      return plan_count;
    }

    /** @brief Plan HEVC payload packets without allocating or copying codec bytes. */
    [[nodiscard]] std::size_t plan_hevc_packets(
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::size_t boundary_capacity,
      const std::size_t middle_capacity,
      const std::span<PacketPlan> plans
    ) noexcept {
      std::size_t plan_count = 0;
      std::size_t nal_index = 0;
      std::size_t fragment_offset = 0;
      while (nal_index < nals.size()) {
        if (plan_count == plans.size() || !media::detail::valid_hevc_nal(nals[nal_index])) {
          return 0;
        }
        if (media::detail::hevc_remaining_fits_final(nals, nal_index, fragment_offset, boundary_capacity)) {
          if (fragment_offset != 0) {
            const auto remaining = nals[nal_index].size() - fragment_offset;
            plans[plan_count++] = {.kind = PacketPlan::Kind::fragment, .nal_index = nal_index, .fragment_offset = fragment_offset, .fragment_bytes = remaining, .fragment_start = fragment_offset == 2, .fragment_end = true, .payload_bytes = remaining + 3U};
          } else if (nal_index + 1U == nals.size()) {
            plans[plan_count++] = {.kind = PacketPlan::Kind::single, .nal_index = nal_index, .payload_bytes = nals[nal_index].size()};
          } else {
            const auto count = nals.size() - nal_index;
            plans[plan_count++] = {.kind = PacketPlan::Kind::aggregate, .nal_index = nal_index, .nal_count = count, .payload_bytes = hevc_aggregate_bytes(nals, nal_index, count)};
          }
          break;
        }
        const auto capacity = plan_count < 2U ? boundary_capacity : middle_capacity;
        const auto nal = nals[nal_index];
        if (fragment_offset != 0 || nal.size() > capacity || (nal_index + 1U == nals.size() && nal.size() > boundary_capacity)) {
          if (fragment_offset == 0) {
            fragment_offset = 2;
          }
          const auto remaining = nal.size() - fragment_offset;
          auto count = std::min(remaining, capacity - 3U);
          if (nal_index + 1U == nals.size() && count == remaining && remaining > boundary_capacity - 3U) {
            --count;
          }
          if (count == 0) {
            return 0;
          }
          const auto end = count == remaining;
          plans[plan_count++] = {.kind = PacketPlan::Kind::fragment, .nal_index = nal_index, .fragment_offset = fragment_offset, .fragment_bytes = count, .fragment_start = fragment_offset == 2, .fragment_end = end, .payload_bytes = count + 3U};
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
          const auto next_size = aggregate_size + 2U + nals[index].size();
          if (next_size > capacity || (index + 1U == nals.size() && next_size > boundary_capacity)) {
            break;
          }
          aggregate_size = next_size;
          ++aggregate_count;
        }
        if (aggregate_count >= 2) {
          plans[plan_count++] = {.kind = PacketPlan::Kind::aggregate, .nal_index = nal_index, .nal_count = aggregate_count, .payload_bytes = aggregate_size};
          nal_index += aggregate_count;
        } else {
          plans[plan_count++] = {.kind = PacketPlan::Kind::single, .nal_index = nal_index, .payload_bytes = nal.size()};
          ++nal_index;
        }
      }
      return plan_count;
    }

    /** @brief Write one planned H.264 codec payload into the final RTP slab. */
    [[nodiscard]] bool write_h264_payload(
      const PacketPlan &plan,
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::span<std::uint8_t> destination
    ) noexcept {
      if (destination.size() != plan.payload_bytes || plan.nal_index >= nals.size()) {
        return false;
      }
      const auto nal = nals[plan.nal_index];
      std::size_t offset = 0;
      if (plan.kind == PacketPlan::Kind::single) {
        std::copy(nal.begin(), nal.end(), destination.begin());
        return true;
      }
      if (plan.kind == PacketPlan::Kind::fragment) {
        if (plan.fragment_offset + plan.fragment_bytes > nal.size() || destination.size() < 2U) {
          return false;
        }
        destination[offset++] = static_cast<std::uint8_t>((nal.front() & 0x60U) | media::h264_fu_a_type);
        destination[offset++] = static_cast<std::uint8_t>((plan.fragment_start ? 0x80U : 0U) | (plan.fragment_end ? 0x40U : 0U) | (nal.front() & 0x1fU));
        std::copy_n(nal.begin() + static_cast<std::ptrdiff_t>(plan.fragment_offset), plan.fragment_bytes, destination.begin() + static_cast<std::ptrdiff_t>(offset));
        return true;
      }
      if (plan.nal_count < 2U || plan.nal_index + plan.nal_count > nals.size()) {
        return false;
      }
      std::uint8_t maximum_nri = 0;
      for (std::size_t index = plan.nal_index; index < plan.nal_index + plan.nal_count; ++index) {
        maximum_nri = std::max(maximum_nri, static_cast<std::uint8_t>(nals[index].front() & 0x60U));
      }
      destination[offset++] = static_cast<std::uint8_t>(maximum_nri | media::h264_stap_a_type);
      for (std::size_t index = plan.nal_index; index < plan.nal_index + plan.nal_count; ++index) {
        const auto size = static_cast<std::uint16_t>(nals[index].size());
        destination[offset++] = static_cast<std::uint8_t>(size >> 8U);
        destination[offset++] = static_cast<std::uint8_t>(size);
        std::copy(nals[index].begin(), nals[index].end(), destination.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += nals[index].size();
      }
      return offset == destination.size();
    }

    /** @brief Write one planned HEVC codec payload into the final RTP slab. */
    [[nodiscard]] bool write_hevc_payload(
      const PacketPlan &plan,
      const std::span<const std::span<const std::uint8_t>> nals,
      const std::span<std::uint8_t> destination
    ) noexcept {
      if (destination.size() != plan.payload_bytes || plan.nal_index >= nals.size()) {
        return false;
      }
      const auto nal = nals[plan.nal_index];
      std::size_t offset = 0;
      if (plan.kind == PacketPlan::Kind::single) {
        std::copy(nal.begin(), nal.end(), destination.begin());
        return true;
      }
      if (plan.kind == PacketPlan::Kind::fragment) {
        if (plan.fragment_offset + plan.fragment_bytes > nal.size() || destination.size() < 3U) {
          return false;
        }
        destination[offset++] = static_cast<std::uint8_t>((nal[0] & 0x81U) | (media::hevc_fu_type << 1U));
        destination[offset++] = nal[1];
        destination[offset++] = static_cast<std::uint8_t>((plan.fragment_start ? 0x80U : 0U) | (plan.fragment_end ? 0x40U : 0U) | media::detail::hevc_nal_type(nal));
        std::copy_n(nal.begin() + static_cast<std::ptrdiff_t>(plan.fragment_offset), plan.fragment_bytes, destination.begin() + static_cast<std::ptrdiff_t>(offset));
        return true;
      }
      if (plan.nal_count < 2U || plan.nal_index + plan.nal_count > nals.size()) {
        return false;
      }
      std::uint8_t lowest_layer = std::numeric_limits<std::uint8_t>::max();
      std::uint8_t lowest_temporal = std::numeric_limits<std::uint8_t>::max();
      for (std::size_t index = plan.nal_index; index < plan.nal_index + plan.nal_count; ++index) {
        lowest_layer = std::min(lowest_layer, media::detail::hevc_layer_id(nals[index]));
        lowest_temporal = std::min(lowest_temporal, media::detail::hevc_temporal_id(nals[index]));
      }
      destination[offset++] = static_cast<std::uint8_t>((media::hevc_ap_type << 1U) | (lowest_layer >> 5U));
      destination[offset++] = static_cast<std::uint8_t>((lowest_layer << 3U) | lowest_temporal);
      for (std::size_t index = plan.nal_index; index < plan.nal_index + plan.nal_count; ++index) {
        const auto size = static_cast<std::uint16_t>(nals[index].size());
        destination[offset++] = static_cast<std::uint8_t>(size >> 8U);
        destination[offset++] = static_cast<std::uint8_t>(size);
        std::copy(nals[index].begin(), nals[index].end(), destination.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += nals[index].size();
      }
      return offset == destination.size();
    }

    /** @brief Return the next complete Annex-B prefix at or after `offset`. */
    [[nodiscard]] std::optional<AnnexBPrefix> next_annex_b_prefix(
      const std::span<const std::uint8_t> access_unit,
      const std::size_t offset
    ) noexcept {
      if (offset >= access_unit.size()) {
        return std::nullopt;
      }
      for (std::size_t index = offset; index + 3U <= access_unit.size(); ++index) {
        if (access_unit[index] != 0 || access_unit[index + 1U] != 0) {
          continue;
        }
        if (access_unit[index + 2U] == 1U) {
          return AnnexBPrefix {.offset = index, .size = 3};
        }
        if (index + 4U <= access_unit.size() && access_unit[index + 2U] == 0 && access_unit[index + 3U] == 1U) {
          return AnnexBPrefix {.offset = index, .size = 4};
        }
      }
      return std::nullopt;
    }

    /** @brief Split one complete Annex-B access unit into prefix-free retained views. */
    [[nodiscard]] std::size_t split_annex_b(
      const std::span<const std::uint8_t> access_unit,
      std::array<std::span<const std::uint8_t>, maximum_nal_units_per_access_unit> &units
    ) noexcept {
      auto prefix = next_annex_b_prefix(access_unit, 0);
      if (!prefix || prefix->offset != 0) {
        return 0;
      }
      std::size_t count = 0;
      while (prefix) {
        const auto payload_start = prefix->offset + prefix->size;
        const auto next = next_annex_b_prefix(access_unit, payload_start);
        const auto payload_end = next ? next->offset : access_unit.size();
        if (payload_start >= payload_end || count == units.size()) {
          return 0;
        }
        units[count++] = access_unit.subspan(payload_start, payload_end - payload_start);
        prefix = next;
      }
      return count;
    }

    /** @brief Saturate one duration to an unsigned 32-bit microsecond field. */
    [[nodiscard]] std::uint32_t saturated_microseconds(
      const std::chrono::steady_clock::duration duration
    ) noexcept {
      if (duration <= std::chrono::steady_clock::duration::zero()) {
        return 0;
      }
      const auto value = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
      return value >= std::numeric_limits<std::uint32_t>::max() ?
               std::numeric_limits<std::uint32_t>::max() :
               static_cast<std::uint32_t>(value);
    }

    /** @brief Convert an estimated wall-clock capture instant to RFC 8872 64-bit NTP form. */
    [[nodiscard]] std::uint64_t absolute_capture_ntp(
      const std::chrono::steady_clock::time_point capture_time,
      const std::chrono::steady_clock::time_point steady_now
    ) noexcept {
      constexpr std::uint64_t ntp_epoch_offset_seconds = 2'208'988'800ULL;
      const auto wall_capture = std::chrono::system_clock::now() - (steady_now - capture_time);
      const auto since_epoch = wall_capture.time_since_epoch();
      const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
      const auto fraction_duration = since_epoch - seconds;
      if (seconds.count() < 0) {
        return 0;
      }
      const auto ntp_seconds = static_cast<std::uint64_t>(seconds.count()) + ntp_epoch_offset_seconds;
      const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(fraction_duration).count();
      const auto fraction = static_cast<std::uint64_t>(nanoseconds) * (std::uint64_t {1} << 32U) / 1'000'000'000ULL;
      return (ntp_seconds << 32U) | fraction;
    }

    /** @brief Owned variants of all first-two/final RFC 8285 extension blocks. */
    struct OwnedExtensionBlocks {
      std::array<std::uint8_t, maximum_extension_block_bytes> first_and_final {};  ///< One-packet frame block.
      std::array<std::uint8_t, maximum_extension_block_bytes> first {};  ///< First multi-packet block.
      std::array<std::uint8_t, maximum_extension_block_bytes> second_and_final {};  ///< Second/final block.
      std::array<std::uint8_t, maximum_extension_block_bytes> second {};  ///< Second nonfinal block.
      std::array<std::uint8_t, maximum_extension_block_bytes> final {};  ///< Final block after packet two.
      std::size_t first_and_final_size {};  ///< Populated first/final bytes.
      std::size_t first_size {};  ///< Populated first bytes.
      std::size_t second_and_final_size {};  ///< Populated second/final bytes.
      std::size_t second_size {};  ///< Populated second bytes.
      std::size_t final_size {};  ///< Populated final bytes.

      /** @brief Return borrowed block variants for the packetizer call. */
      [[nodiscard]] media::frame_extension_blocks views() const noexcept {
        return {
          .first_and_final = std::span<const std::uint8_t> {first_and_final}.first(first_and_final_size),
          .first = std::span<const std::uint8_t> {first}.first(first_size),
          .second_and_final = std::span<const std::uint8_t> {second_and_final}.first(second_and_final_size),
          .second = std::span<const std::uint8_t> {second}.first(second_size),
          .final = std::span<const std::uint8_t> {final}.first(final_size),
        };
      }
    };

    /** @brief Append one RFC 8285 one-byte extension element. */
    bool append_extension(
      const std::span<std::uint8_t> block,
      std::size_t &offset,
      const std::uint8_t id,
      const std::span<const std::uint8_t> value
    ) noexcept {
      if (id == 0 || id >= 15 || value.empty() || value.size() > 16 || offset + 1U + value.size() > block.size()) {
        return false;
      }
      block[offset++] = static_cast<std::uint8_t>((id << 4U) | (value.size() - 1U));
      std::copy(value.begin(), value.end(), block.begin() + static_cast<std::ptrdiff_t>(offset));
      offset += value.size();
      return true;
    }

    /** @brief Build one complete RFC 8285 block for a boundary packet role. */
    [[nodiscard]] std::size_t write_extension_block(
      const std::span<std::uint8_t> output,
      const std::uint8_t marking,
      const bool full_metadata,
      const std::uint64_t capture_ntp,
      const std::uint64_t frame_id,
      const std::uint64_t input_state_sequence,
      const std::uint64_t input_edge_id,
      const std::uint32_t capture_to_submit_us,
      const std::uint32_t capture_to_complete_us
    ) noexcept {
      std::array<std::uint8_t, 8> capture_bytes {};
      std::array<std::uint8_t, 8> frame_id_bytes {};
      std::array<std::uint8_t, 16> watermark_bytes {};
      std::array<std::uint8_t, 8> timing_bytes {};
      wire::write_be<std::uint64_t>(capture_bytes, capture_ntp);
      wire::write_be<std::uint64_t>(frame_id_bytes, frame_id);
      wire::write_be<std::uint64_t>(std::span<std::uint8_t> {watermark_bytes}.first<8>(), input_state_sequence);
      wire::write_be<std::uint64_t>(std::span<std::uint8_t> {watermark_bytes}.subspan<8, 8>(), input_edge_id);
      wire::write_be<std::uint32_t>(std::span<std::uint8_t> {timing_bytes}.first<4>(), capture_to_submit_us);
      wire::write_be<std::uint32_t>(std::span<std::uint8_t> {timing_bytes}.subspan<4, 4>(), capture_to_complete_us);

      if (output.size() < 8) {
        return 0;
      }
      std::size_t offset = 4;
      const std::array marking_bytes {marking};
      if (!append_extension(output, offset, video_frame_marking_extension_id, marking_bytes)) {
        return 0;
      }
      if (full_metadata &&
          (!append_extension(output, offset, video_absolute_capture_time_extension_id, capture_bytes) ||
           !append_extension(output, offset, video_frame_id_extension_id, frame_id_bytes) ||
           !append_extension(output, offset, video_input_watermark_extension_id, watermark_bytes) ||
           !append_extension(output, offset, video_encoder_timing_extension_id, timing_bytes))) {
        return 0;
      }
      if (!full_metadata && !append_extension(output, offset, video_frame_id_extension_id, frame_id_bytes)) {
        return 0;
      }
      while ((offset % 4U) != 0) {
        if (offset == output.size()) {
          return 0;
        }
        output[offset++] = 0;
      }
      output[0] = 0xbeU;
      output[1] = 0xdeU;
      wire::write_be<std::uint16_t>(output.subspan(2, 2), static_cast<std::uint16_t>((offset - 4U) / 4U));
      return offset;
    }

    /** @brief Build all overlap-specific extension variants for one encoded frame. */
    [[nodiscard]] std::optional<OwnedExtensionBlocks> make_extensions(
      const bool independent,
      const std::uint64_t capture_ntp,
      const std::uint64_t frame_id,
      const std::uint64_t input_state_sequence,
      const std::uint64_t input_edge_id,
      const std::uint32_t capture_to_submit_us,
      const std::uint32_t capture_to_complete_us
    ) noexcept {
      constexpr std::uint8_t start = 0x80U;
      constexpr std::uint8_t end = 0x40U;
      constexpr std::uint8_t independent_bit = 0x20U;
      const auto independent_mark = independent ? independent_bit : 0U;
      OwnedExtensionBlocks blocks;
      blocks.first_and_final_size = write_extension_block(blocks.first_and_final, static_cast<std::uint8_t>(start | end | independent_mark), true, capture_ntp, frame_id, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.first_size = write_extension_block(blocks.first, static_cast<std::uint8_t>(start | independent_mark), true, capture_ntp, frame_id, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.second_and_final_size = write_extension_block(blocks.second_and_final, static_cast<std::uint8_t>(end | independent_mark), true, capture_ntp, frame_id, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.second_size = write_extension_block(blocks.second, independent_mark, true, capture_ntp, frame_id, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.final_size = write_extension_block(blocks.final, static_cast<std::uint8_t>(end | independent_mark), false, capture_ntp, frame_id, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      if (blocks.first_and_final_size == 0 || blocks.first_size == 0 || blocks.second_and_final_size == 0 ||
          blocks.second_size == 0 || blocks.final_size == 0) {
        return std::nullopt;
      }
      return blocks;
    }

    /** @brief Return monotonic microseconds for frame admission and pacing. */
    [[nodiscard]] std::uint64_t monotonic_microseconds() noexcept {
      const auto count = std::chrono::duration_cast<std::chrono::microseconds>(
                           std::chrono::steady_clock::now().time_since_epoch()
      )
                           .count();
      return count < 0 ? 0 : static_cast<std::uint64_t>(count);
    }
  }  // namespace

  bool HostVideoSenderConfig::valid() const noexcept {
    const auto codec_profile = (video.codec == VideoCodec::h264 && video.profile == VideoProfile::h264_high) ||
                               (video.codec == VideoCodec::hevc && video.profile == VideoProfile::hevc_main);
    return peer.valid() && codec_profile && video.video_generation != 0 && video.primary_ssrc != 0 &&
           video.primary_payload_type >= 96 && video.primary_payload_type <= 127 && video.clock_rate == 90'000 &&
           video.width > 0 && video.height > 0 && video.refresh_numerator > 0 && video.refresh_denominator > 0 &&
           video.selected_bits_per_second > 0 && video.pixel_format == video_pixel_format_nv12 &&
           video.initial_udp_payload_size == media::initial_udp_payload_size && video.decoder_surfaces >= 2 &&
           video.decoder_surfaces <= 4 && video.render_mailbox == 1 &&
           video.delivery == video_delivery_complete_access_unit && !video.flexfec && !video.rtx &&
           initial_timestamp != 0 && frame_id_origin != 0 && maximum_access_unit_bytes > 0 &&
           maximum_access_unit_bytes <= media::competition_frame_size_limit &&
           maximum_capture_to_present_microseconds > 0 &&
           video.maximum_frame_age_microseconds == maximum_capture_to_present_microseconds &&
           aggregate_pacing_bits_per_second > 0 && capture_mail;
  }

  class HostVideoSender::Impl {
  public:
    /** @brief Validate configuration and allocate every lifetime-bounded slab and descriptor. */
    Impl(HostVideoSenderConfig config, LibsrtpServerProvider &srtp) noexcept:
        config_ {std::move(config)},
        srtp_ {srtp},
        pacer_({
          .pacing_bits_per_second = config_.aggregate_pacing_bits_per_second,
          .input_reserve_bits_per_second = 0,
          .path_datagram_bytes = static_cast<std::uint16_t>(config_.video.initial_udp_payload_size + ip_udp_overhead()),
          .quantum_microseconds = 100,
          .submission_horizon_microseconds = 200,
          .max_datagrams_per_batch = 8,
        }),
        next_sequence_ {config_.initial_sequence},
        initial_timestamp_ {config_.initial_timestamp},
        next_frame_id_ {config_.frame_id_origin},
        decoder_credit_ {config_.video.decoder_surfaces} {
      if (!config_.valid() || pacer_.error() != pacer_error::none) {
        return;
      }
      try {
        for (auto &slab : frame_slabs_) {
          slab.resize(config_.maximum_access_unit_bytes);
        }
        packet_plans_.resize(media::maximum_fragments_per_frame);
        ready_ = true;
      } catch (...) {
        ready_ = false;
      }
    }

    /** @brief Close and join sender ownership before releasing fixed storage. */
    ~Impl() {
      close();
      join();
    }

    /** @brief Register capacity-one egress and start the packet worker. */
    bool start() noexcept {
      if (!ready_ || started_.exchange(true, std::memory_order_acq_rel)) {
        return false;
      }
      const auto numerator = static_cast<std::uint64_t>(config_.video.refresh_numerator);
      const auto denominator = static_cast<std::uint64_t>(config_.video.refresh_denominator);
      const auto frame_interval = std::chrono::nanoseconds {
        static_cast<std::chrono::nanoseconds::rep>(1'000'000'000ULL * denominator / numerator)
      };
      const auto registered = egress_.register_session(
        this,
        video::egress_queue_t::behavior_e::latency,
        {.capacity = 1, .max_queue_age = std::max(frame_interval, 1ns)},
        [this](const video::egress_queue_t::recovery_request_t &request) {
          pressure_events_.fetch_add(1, std::memory_order_relaxed);
          if (config_.reference_invalidation) {
            config_.capture_mail->event<std::pair<std::int64_t, std::int64_t>>(mail::invalidate_ref_frames)->raise(std::make_pair(request.first_frame, request.last_frame));
          } else {
            failed_.store(true, std::memory_order_release);
            config_.capture_mail->event<bool>(mail::shutdown)->raise(true);
          }
        }
      );
      if (!registered) {
        started_.store(false, std::memory_order_release);
        return false;
      }
      registered_ = true;
      pacer_.reset(monotonic_microseconds());
      try {
        worker_ = std::jthread([this]() noexcept {
          run();
        });
      } catch (...) {
        egress_.stop();
        (void) egress_.unregister_session(this);
        registered_ = false;
        started_.store(false, std::memory_order_release);
        return false;
      }
      return true;
    }

    /** @brief Return the sender-owned encoded-frame egress boundary. */
    [[nodiscard]] video::egress_queue_t &egress() noexcept {
      return egress_;
    }

    /** @brief Install latest authenticated decoder availability. */
    void update_decoder_credit(const std::uint8_t credit) noexcept {
      decoder_credit_.store(std::min<std::uint8_t>(credit, 4), std::memory_order_release);
    }

    /** @brief Close admission and wake the packet worker. */
    void close() noexcept {
      if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
      }
      egress_.stop();
    }

    /** @brief Join sender and retire its egress registration. */
    void join() noexcept {
      if (worker_.joinable()) {
        worker_.join();
      }
      if (registered_) {
        (void) egress_.unregister_session(this);
        registered_ = false;
      }
    }

    /** @brief Copy lock-free counters and lifecycle flags. */
    [[nodiscard]] HostVideoSenderSnapshot snapshot() const noexcept {
      return {
        .admitted_frames = admitted_frames_.load(std::memory_order_relaxed),
        .submitted_frames = submitted_frames_.load(std::memory_order_relaxed),
        .submitted_packets = submitted_packets_.load(std::memory_order_relaxed),
        .dropped_frames = dropped_frames_.load(std::memory_order_relaxed),
        .submitted_wire_bytes = submitted_wire_bytes_.load(std::memory_order_relaxed),
        .pressure_events = pressure_events_.load(std::memory_order_relaxed),
        .decoder_credit = decoder_credit_.load(std::memory_order_relaxed),
        .started = started_.load(std::memory_order_relaxed),
        .closed = closed_.load(std::memory_order_relaxed),
        .failed = failed_.load(std::memory_order_relaxed),
      };
    }

    /** @brief Return constructor validation and slab-allocation status. */
    [[nodiscard]] bool ready() const noexcept {
      return ready_;
    }

  private:
    /** @brief Return complete IP plus UDP header bytes for this path. */
    [[nodiscard]] std::size_t ip_udp_overhead() const noexcept {
      return config_.family == media::ip_family::ipv4 ? 28U : 48U;
    }

    /** @brief Drain encoded access units until close or fatal packet submission failure. */
    void run() noexcept {
      while (auto dequeued = egress_.pop()) {
        if (closed_.load(std::memory_order_acquire)) {
          break;
        }
        if (!process_frame(*dequeued->packet)) {
          failed_.store(true, std::memory_order_release);
          config_.capture_mail->event<bool>(mail::shutdown)->raise(true);
          break;
        }
      }
    }

    /** @brief Materialize, admit, packetize, pace, protect, and submit one complete access unit. */
    [[nodiscard]] bool process_frame(video::packet_raw_t &packet) noexcept {
      auto &frame_storage = frame_slabs_[next_frame_slab_];
      next_frame_slab_ = (next_frame_slab_ + 1U) % frame_slabs_.size();
      std::size_t access_unit_bytes = 0;
      if (!video::materialize_lsp_access_unit(packet, frame_storage, access_unit_bytes) ||
          access_unit_bytes == 0 || access_unit_bytes > config_.maximum_access_unit_bytes) {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        return false;
      }

      std::array<std::span<const std::uint8_t>, maximum_nal_units_per_access_unit> nal_storage {};
      const auto access_unit = std::span<const std::uint8_t> {frame_storage}.first(access_unit_bytes);
      const auto nal_count = split_annex_b(access_unit, nal_storage);
      if (nal_count == 0) {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        return false;
      }

      const auto complete_time = std::chrono::steady_clock::now();
      const auto capture_time = packet.frame_timestamp.value_or(complete_time);
      const auto submit_time = packet.encoder_submit_timestamp.value_or(capture_time);
      const auto capture_us_count = std::chrono::duration_cast<std::chrono::microseconds>(capture_time.time_since_epoch()).count();
      if (capture_us_count < 0 || next_frame_id_ == 0) {
        return false;
      }
      const auto capture_us = static_cast<std::uint64_t>(capture_us_count);
      if (!capture_origin_) {
        capture_origin_ = capture_time;
      }
      const auto elapsed = capture_time >= *capture_origin_ ? capture_time - *capture_origin_ : std::chrono::steady_clock::duration::zero();
      const auto elapsed_us = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count());
      const auto timestamp_delta = elapsed_us > std::numeric_limits<std::uint64_t>::max() / media::video_clock_rate ?
                                     std::numeric_limits<std::uint64_t>::max() :
                                     elapsed_us * media::video_clock_rate / 1'000'000ULL;
      const auto rtp_timestamp = initial_timestamp_ + static_cast<std::uint32_t>(timestamp_delta);
      const auto frame_id = next_frame_id_++;
      if (next_frame_id_ == 0) {
        failed_.store(true, std::memory_order_release);
      }
      const auto extension_storage = make_extensions(
        packet.is_idr(),
        absolute_capture_ntp(capture_time, complete_time),
        frame_id,
        packet.applied_input_state_sequence,
        packet.applied_input_edge_id,
        saturated_microseconds(submit_time - capture_time),
        saturated_microseconds(complete_time - capture_time)
      );
      if (!extension_storage) {
        return false;
      }
      const auto units = std::span<const std::span<const std::uint8_t>> {nal_storage}.first(nal_count);
      const auto extension_views = extension_storage->views();
      const auto plaintext_capacity = static_cast<std::size_t>(config_.video.initial_udp_payload_size) - sender_srtp_tag_bytes;
      const auto boundary_overhead = rtp_fixed_header_size + extension_views.maximum_size();
      if (plaintext_capacity <= boundary_overhead || plaintext_capacity <= rtp_fixed_header_size) {
        return false;
      }
      const auto plans = std::span<PacketPlan> {packet_plans_};
      const auto plan_count = config_.video.codec == VideoCodec::h264 ?
                                plan_h264_packets(
                                  units,
                                  plaintext_capacity - boundary_overhead,
                                  plaintext_capacity - rtp_fixed_header_size,
                                  plans
                                ) :
                                plan_hevc_packets(
                                  units,
                                  plaintext_capacity - boundary_overhead,
                                  plaintext_capacity - rtp_fixed_header_size,
                                  plans
                                );
      if (plan_count == 0) {
        return false;
      }

      const auto now_us = monotonic_microseconds();
      const auto deadline = media::compute_network_deadline({
        .capture_time_us = capture_us,
        .maximum_capture_to_client_us = config_.maximum_capture_to_present_microseconds,
      });
      const auto credit = decoder_credit_.load(std::memory_order_acquire);
      const auto admission = media::admit_frame({
        .size_mode = media::frame_size_mode::complete_access_unit,
        .source_bytes = access_unit_bytes,
        .selected_repair_bytes = 0,
        .pacing_rate_bits_per_second = config_.aggregate_pacing_bits_per_second,
        .now_us = now_us,
        .network_deadline_us = deadline,
        .decoder_credits = credit,
        .reference_path_valid = packet.is_idr() || packet.after_ref_frame_invalidation || reference_path_valid_,
      });
      if (!admission) {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        pressure_events_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }

      std::uint64_t complete_wire_bytes = 0;
      for (std::size_t index = 0; index < plan_count; ++index) {
        const auto extension = extension_views.for_role(media::packet_role(index, plan_count));
        const auto plaintext_bytes = rtp_fixed_header_size + extension.size() + plans[index].payload_bytes;
        const auto charged = plaintext_bytes + sender_srtp_tag_bytes + ip_udp_overhead();
        if (charged > std::numeric_limits<std::uint16_t>::max() ||
            complete_wire_bytes > std::numeric_limits<std::uint64_t>::max() - charged) {
          return false;
        }
        complete_wire_bytes += charged;
      }
      const auto wire_bits = complete_wire_bytes * 8U;
      const auto serialization_us = wire_bits > std::numeric_limits<std::uint64_t>::max() / 1'000'000U ?
                                      std::numeric_limits<std::uint64_t>::max() :
                                      (wire_bits * 1'000'000U + config_.aggregate_pacing_bits_per_second - 1U) /
                                        config_.aggregate_pacing_bits_per_second;
      if (now_us >= deadline || serialization_us > deadline - now_us) {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        pressure_events_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }

      admitted_frames_.fetch_add(1, std::memory_order_relaxed);
      std::size_t packet_index = 0;
      while (packet_index < plan_count) {
        std::array<std::uint16_t, 8> charges {};
        const auto remaining = std::min<std::size_t>(charges.size(), plan_count - packet_index);
        for (std::size_t index = 0; index < remaining; ++index) {
          const auto absolute_index = packet_index + index;
          const auto extension = extension_views.for_role(media::packet_role(absolute_index, plan_count));
          charges[index] = static_cast<std::uint16_t>(rtp_fixed_header_size + extension.size() + plans[absolute_index].payload_bytes + sender_srtp_tag_bytes + ip_udp_overhead());
        }
        const auto now = monotonic_microseconds();
        if (now >= deadline) {
          reference_path_valid_ = false;
          pressure_events_.fetch_add(1, std::memory_order_relaxed);
          return false;
        }
        const auto grant = pacer_.grant(std::span<const std::uint16_t> {charges}.first(remaining), false, now);
        if (grant.datagrams == 0) {
          const auto wait = pacer_.wait_microseconds(charges[0], false, now);
          if (wait == std::numeric_limits<std::uint64_t>::max() || wait >= deadline - now) {
            reference_path_valid_ = false;
            pressure_events_.fetch_add(1, std::memory_order_relaxed);
            return false;
          }
          std::this_thread::sleep_for(std::chrono::microseconds {wait});
          continue;
        }
        for (std::size_t index = 0; index < grant.datagrams; ++index) {
          const auto absolute_index = packet_index + index;
          const auto role = media::packet_role(absolute_index, plan_count);
          const auto extension = extension_views.for_role(role);
          const auto &plan = plans[absolute_index];
          const auto plaintext_bytes = rtp_fixed_header_size + extension.size() + plan.payload_bytes;
          if (plaintext_bytes + sender_srtp_tag_bytes > config_.video.initial_udp_payload_size) {
            return false;
          }
          const rtp_fixed_header rtp {
            .padding = false,
            .extension = !extension.empty(),
            .marker = absolute_index + 1U == plan_count,
            .payload_type = config_.video.primary_payload_type,
            .csrc_count = 0,
            .sequence_number = static_cast<std::uint16_t>(next_sequence_ + absolute_index),
            .timestamp = rtp_timestamp,
            .ssrc = config_.video.primary_ssrc,
          };
          const auto header = write_rtp_fixed_header(rtp, {}, packet_slab_);
          if (!header || header.bytes_written != rtp_fixed_header_size) {
            return false;
          }
          std::copy(extension.begin(), extension.end(), packet_slab_.begin() + static_cast<std::ptrdiff_t>(rtp_fixed_header_size));
          const auto payload = std::span<std::uint8_t> {packet_slab_}.subspan(
            rtp_fixed_header_size + extension.size(),
            plan.payload_bytes
          );
          const auto payload_written = config_.video.codec == VideoCodec::h264 ?
                                         write_h264_payload(plan, units, payload) :
                                         write_hevc_payload(plan, units, payload);
          if (!payload_written) {
            return false;
          }
          if (!srtp_.protect_and_send_in_place(
                config_.peer,
                SecurePacketClass::rtp,
                std::span<std::uint8_t> {packet_slab_}.first(config_.video.initial_udp_payload_size),
                plaintext_bytes
              )) {
            reference_path_valid_ = false;
            pressure_events_.fetch_add(1, std::memory_order_relaxed);
            return false;
          }
          submitted_packets_.fetch_add(1, std::memory_order_relaxed);
          submitted_wire_bytes_.fetch_add(charges[index], std::memory_order_relaxed);
        }
        packet_index += grant.datagrams;
      }
      next_sequence_ = static_cast<std::uint16_t>(next_sequence_ + plan_count);
      reference_path_valid_ = true;
      if (credit != 0) {
        auto expected_credit = credit;
        (void) decoder_credit_.compare_exchange_strong(expected_credit, static_cast<std::uint8_t>(credit - 1U));
      }
      submitted_frames_.fetch_add(1, std::memory_order_relaxed);
      return true;
    }

    HostVideoSenderConfig config_;  ///< Immutable negotiated sender configuration.
    LibsrtpServerProvider &srtp_;  ///< Installed association provider.
    video::egress_queue_t egress_ {1};  ///< One-unsent-frame encoded egress owner.
    aggregate_pacer pacer_;  ///< Complete IP-layer rate-derived microbatch pacer.
    std::array<std::vector<std::uint8_t>, 2> frame_slabs_ {};  ///< Two preallocated complete-AU scratch slabs.
    std::vector<PacketPlan> packet_plans_ {};  ///< Preallocated fixed-capacity packet descriptor storage.
    std::array<std::uint8_t, final_packet_slab_bytes> packet_slab_ {};  ///< Final in-place RTP/SRTP packet slab.
    std::jthread worker_;  ///< Dedicated packetization, pacing, and send worker.
    std::optional<std::chrono::steady_clock::time_point> capture_origin_ {};  ///< First capture sampling origin.
    std::uint16_t next_sequence_ {};  ///< Next primary RTP sequence number.
    std::uint32_t initial_timestamp_ {};  ///< Random initial 90 kHz timestamp.
    std::uint64_t next_frame_id_ {};  ///< Next nonzero frame identifier.
    std::size_t next_frame_slab_ {};  ///< Alternating complete-AU scratch slot.
    bool reference_path_valid_ {true};  ///< Whether known encoder dependencies remain decodable.
    bool ready_ {};  ///< Constructor validation and fixed-slab allocation status.
    bool registered_ {};  ///< Whether egress retains this session key.
    std::atomic<std::uint8_t> decoder_credit_ {};  ///< Latest freshness-bounded available decoder surfaces.
    std::atomic<std::uint64_t> admitted_frames_ {};  ///< Complete-AU admission count.
    std::atomic<std::uint64_t> submitted_frames_ {};  ///< Fully submitted frame count.
    std::atomic<std::uint64_t> submitted_packets_ {};  ///< Protected RTP packet count.
    std::atomic<std::uint64_t> dropped_frames_ {};  ///< Whole pre-send frame drop count.
    std::atomic<std::uint64_t> submitted_wire_bytes_ {};  ///< Complete charged wire bytes.
    std::atomic<std::uint64_t> pressure_events_ {};  ///< Bounded pressure observation count.
    std::atomic<bool> started_ {};  ///< Whether start succeeded.
    std::atomic<bool> closed_ {};  ///< Whether admission is closed.
    std::atomic<bool> failed_ {};  ///< Whether fatal packetization/send failure occurred.
  };

  HostVideoSender::HostVideoSender(HostVideoSenderConfig config, LibsrtpServerProvider &srtp) noexcept:
      impl_ {new (std::nothrow) Impl {std::move(config), srtp}} {
  }

  HostVideoSender::~HostVideoSender() = default;

  bool HostVideoSender::start() noexcept {
    return impl_ && impl_->start();
  }

  video::egress_queue_t &HostVideoSender::egress() noexcept {
    return impl_->egress();
  }

  void *HostVideoSender::session_key() noexcept {
    return impl_.get();
  }

  void HostVideoSender::update_decoder_credit(const std::uint8_t credit) noexcept {
    if (impl_) {
      impl_->update_decoder_credit(credit);
    }
  }

  void HostVideoSender::close() noexcept {
    if (impl_) {
      impl_->close();
    }
  }

  void HostVideoSender::join() noexcept {
    if (impl_) {
      impl_->join();
    }
  }

  bool HostVideoSender::ready() const noexcept {
    return impl_ && impl_->ready();
  }

  HostVideoSenderSnapshot HostVideoSender::snapshot() const noexcept {
    return impl_ ? impl_->snapshot() : HostVideoSenderSnapshot {};
  }
}  // namespace lumen::lsp::runtime
