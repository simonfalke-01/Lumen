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
#include "../transport/congestion.h"
#include "../transport/rtcp.h"

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
    constexpr std::array<std::uint8_t, 4> lspp_name {'L', 'S', 'P', 'P'};  ///< Exact path-probe APP name.
    constexpr std::uint64_t minimum_probe_timer_microseconds = 15'000'000;  ///< LSP conservative PROBE_TIMER floor.
    constexpr std::uint8_t maximum_probe_attempts = 3;  ///< RFC 8899 default MAX_PROBES.
    constexpr std::uint64_t compound_rtcp_freshness_microseconds = 5'000'000;  ///< Reduced-size prerequisite freshness.
    constexpr std::uint64_t feedback_packet_freshness_microseconds = 5'000'000;  ///< Sent-ledger age bound.
    constexpr std::uint64_t video_sender_report_interval_microseconds = 1'000'000;  ///< Media RTT timing cadence.
    constexpr std::uint64_t path_raise_timer_microseconds = 600'000'000;  ///< RFC 8899 PMTU_RAISE_TIMER.
    constexpr std::uint64_t black_hole_confirmation_microseconds = 3'000'000;  ///< Sustained large-packet delivery-loss window.
    constexpr std::uint64_t black_hole_feedback_freshness_microseconds = 5'000'000;  ///< Recent small-path proof requirement.
    constexpr std::uint64_t black_hole_minimum_large_packets = 8;  ///< Minimum large sends before fallback.

    /** @brief Atomic sent-packet ledger slot indexed by the 16-bit RTP sequence number. */
    struct SentPacketRecord {
      std::atomic_flag access = ATOMIC_FLAG_INIT;  ///< Serializes rare sequence-wrap reuse with feedback accounting.
      std::atomic<std::uint64_t> send_serial {};  ///< Nonzero release-published packet incarnation.
      std::atomic<std::uint64_t> sent_microseconds {};  ///< Last-opportunity sender timestamp.
      std::atomic<std::uint32_t> complete_ip_bytes {};  ///< Complete IP-layer bytes charged.
      std::atomic<std::uint16_t> udp_payload_bytes {};  ///< Exact protected UDP payload for PMTU evidence.
      std::atomic<std::uint16_t> confirmed_path_payload_bytes {};  ///< Frame-boundary limit active at send.
      std::atomic<std::uint32_t> path_generation {};  ///< Frame-boundary PMTU evidence generation.
      std::atomic<std::uint8_t> feedback_state {};  ///< Zero unreported, one lost, two received.
      std::atomic<std::uint8_t> ecn_state {};  ///< First echoed ECN value, upgraded once to CE when duplicated.
    };

    /** @brief Retained exact protected LSPP bytes and logical retry state. */
    struct PathProbeTransmission {
      PathProbePayload probe {};  ///< Logical identifier and protected target size.
      std::array<std::uint8_t, media::ipv4_udp_payload_ceiling> protected_packet {};  ///< Exact immutable local-send retry bytes.
      std::size_t protected_bytes {};  ///< Populated exact candidate bytes.
      std::uint64_t began_microseconds {};  ///< Authenticated control-intent initiation time.
      std::uint64_t last_transmission_microseconds {};  ///< Last accepted local submission time.
      std::uint8_t transmissions {};  ///< Fresh SRTCP-index transmissions accepted locally.
      bool local_send_pending {};  ///< Exact protected packet awaits retry after local send failure.
      bool protected_is_probe_timer_retry {};  ///< Retained protected bytes are a fresh PROBE_TIMER retry.
    };

    /** @brief Retained middle-NTP sender-report timing used to validate RR RTT samples. */
    struct SenderReportTiming {
      std::atomic<std::uint32_t> lsr {};  ///< Middle 32 bits of the transmitted SR NTP timestamp.
      std::atomic<std::uint64_t> sent_microseconds {};  ///< Local monotonic SRTCP submission time.
    };

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

    /** @brief Add a monotonic interval without wrapping a deadline. */
    [[nodiscard]] std::uint64_t saturating_add_time(
      const std::uint64_t now_microseconds,
      const std::uint64_t interval_microseconds
    ) noexcept {
      return now_microseconds > std::numeric_limits<std::uint64_t>::max() - interval_microseconds ?
               std::numeric_limits<std::uint64_t>::max() : now_microseconds + interval_microseconds;
    }

    /** @brief Clamp the initial aggregate rate to selected video plus reserved overhead. */
    [[nodiscard]] std::uint64_t initial_pacing_rate(const HostVideoSenderConfig &config) noexcept {
      const auto media_rate = config.video.selected_bits_per_second >
                                  std::numeric_limits<std::uint64_t>::max() - config.reserved_overhead_bits_per_second ?
                                std::numeric_limits<std::uint64_t>::max() :
                                config.video.selected_bits_per_second + config.reserved_overhead_bits_per_second;
      return std::min(config.aggregate_pacing_bits_per_second, media_rate);
    }
  }  // namespace

  std::optional<PathProbePayload> parse_path_probe_datagram(
    const std::span<const std::uint8_t> packet,
    const std::size_t protected_bytes,
    const std::uint32_t expected_sender_ssrc
  ) noexcept {
    const auto parsed = transport::parse_rtcp_packet(packet);
    if (!parsed || parsed.packet.size() != packet.size() || parsed.packet_type != transport::rtcp_app_type ||
        parsed.count != 0 || parsed.payload.size() < 20U || expected_sender_ssrc == 0 ||
        protected_bytes < packet.size() ||
        wire::read_be<std::uint32_t>(parsed.payload.first<4>()) != expected_sender_ssrc ||
        !std::ranges::equal(lspp_name, parsed.payload.subspan<4, 4>()) ||
        parsed.payload[8] != wire_version || parsed.payload[9] != 0) {
      return std::nullopt;
    }
    const auto declared_size = wire::read_be<std::uint16_t>(parsed.payload.subspan<10, 2>());
    const auto probe_id = wire::read_be<std::uint64_t>(parsed.payload.subspan<12, 8>());
    if (probe_id == 0 || declared_size != protected_bytes ||
        !std::ranges::all_of(parsed.payload.subspan(20), [](const std::uint8_t byte) {
          return byte == 0;
        })) {
      return std::nullopt;
    }
    if (parsed.padding) {
      const auto padding = parsed.packet.last(parsed.padding_bytes);
      if (padding.back() != parsed.padding_bytes ||
          !std::ranges::all_of(padding.first(padding.size() - 1U), [](const std::uint8_t byte) {
            return byte == 0;
          })) {
        return std::nullopt;
      }
    }
    return PathProbePayload {
      .probe_id = probe_id,
      .udp_payload_size = declared_size,
    };
  }

  std::optional<CongestionFeedbackPacketView> parse_congestion_feedback_packet(
    const std::span<const std::uint8_t> packet,
    const std::uint32_t expected_sender_ssrc
  ) noexcept {
    const auto parsed = transport::parse_rtcp_packet(packet);
    if (!parsed || parsed.packet.size() != packet.size() || parsed.padding ||
        parsed.packet_type != transport::rtcp_transport_feedback_type ||
        parsed.count != transport::rtcp_congestion_feedback_format ||
        parsed.payload.size() < 16U || expected_sender_ssrc == 0 ||
        wire::read_be<std::uint32_t>(parsed.payload.first<4>()) != expected_sender_ssrc) {
      return std::nullopt;
    }

    CongestionFeedbackPacketView result;
    const auto blocks_end = parsed.payload.size() - 4U;
    std::size_t offset = 4U;
    std::size_t aggregate_metrics = 0;
    while (offset < blocks_end) {
      if (result.block_count == result.blocks.size() || blocks_end - offset < 8U) {
        return std::nullopt;
      }
      const auto media_ssrc = wire::read_be<std::uint32_t>(parsed.payload.subspan(offset, 4));
      const auto begin_sequence = wire::read_be<std::uint16_t>(parsed.payload.subspan(offset + 4U, 2));
      const auto report_count = wire::read_be<std::uint16_t>(parsed.payload.subspan(offset + 6U, 2));
      if (media_ssrc == 0 || report_count > 16'384U ||
          aggregate_metrics > 16'384U - report_count) {
        return std::nullopt;
      }
      for (std::size_t index = 0; index < result.block_count; ++index) {
        if (result.blocks[index].media_ssrc == media_ssrc) {
          return std::nullopt;
        }
      }
      offset += 8U;
      const auto metric_bytes = static_cast<std::size_t>(report_count) * 2U;
      const auto alignment_bytes = (report_count & 1U) != 0U ? 2U : 0U;
      if (metric_bytes + alignment_bytes > blocks_end - offset) {
        return std::nullopt;
      }
      const auto metrics = parsed.payload.subspan(offset, metric_bytes);
      for (std::size_t index = 0; index < report_count; ++index) {
        const auto metric = wire::read_be<std::uint16_t>(metrics.subspan(index * 2U, 2));
        if ((metric & 0x8000U) == 0 && (metric & 0x7fffU) != 0) {
          return std::nullopt;
        }
      }
      if (alignment_bytes != 0U &&
          wire::read_be<std::uint16_t>(parsed.payload.subspan(offset + metric_bytes, 2)) != 0) {
        return std::nullopt;
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
      return std::nullopt;
    }
    result.report_timestamp = wire::read_be<std::uint32_t>(parsed.payload.last<4>());
    return result;
  }

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
           aggregate_pacing_bits_per_second > reserved_overhead_bits_per_second &&
           path_payload_ceiling >= 1'200 &&
           path_payload_ceiling <= (family == media::ip_family::ipv4 ? 1'472U : 1'452U) &&
           feedback_sender_ssrc != 0 && audio_feedback_ssrc != 0 &&
           audio_feedback_ssrc != video.primary_ssrc && capture_mail;
  }

  class HostVideoSender::Impl {
  public:
    /** @brief Validate configuration and allocate every lifetime-bounded slab and descriptor. */
    Impl(HostVideoSenderConfig config, LibsrtpServerProvider &srtp) noexcept:
        config_ {std::move(config)},
        srtp_ {srtp},
        pacer_({
          .pacing_bits_per_second = initial_pacing_rate(config_),
          .input_reserve_bits_per_second = 0,
          .path_datagram_bytes = static_cast<std::uint16_t>(config_.video.initial_udp_payload_size + ip_udp_overhead()),
          .quantum_microseconds = 100,
          .submission_horizon_microseconds = 200,
          .max_datagrams_per_batch = 8,
        }),
        congestion_({
          .profile = config_.network_profile == VideoNetworkProfile::competition ?
                       transport::controller_profile::competition_lan :
                       transport::controller_profile::adaptive_low_latency,
          .initial_pacing_bits_per_second = initial_pacing_rate(config_),
          .minimum_pacing_bits_per_second = std::min(
            config_.aggregate_pacing_bits_per_second,
            config_.reserved_overhead_bits_per_second + 1'000'000U
          ),
          .maximum_pacing_bits_per_second = config_.aggregate_pacing_bits_per_second,
          .competition_capacity_bits_per_second = config_.network_profile == VideoNetworkProfile::competition ?
                                                    config_.aggregate_pacing_bits_per_second : 0,
          .reserved_overhead_bits_per_second = config_.reserved_overhead_bits_per_second,
          .maximum_rtt_microseconds = 100'000,
          .queue_delay_budget_microseconds = config_.network_profile == VideoNetworkProfile::competition ? 2'000U : 10'000U,
        }),
        path_mtu_({
          .ip_version = config_.family == media::ip_family::ipv4 ?
                          transport::path_ip_version::ipv4 : transport::path_ip_version::ipv6,
          .sender_interface_limit = config_.path_payload_ceiling,
          .receiver_advertised_limit = config_.path_payload_ceiling,
          .operator_configured_limit = config_.path_payload_ceiling,
        }),
        next_sequence_ {config_.initial_sequence},
        initial_timestamp_ {config_.initial_timestamp},
        next_frame_id_ {config_.frame_id_origin},
        decoder_credit_ {config_.video.decoder_surfaces},
        requested_pacing_bits_per_second_ {initial_pacing_rate(config_)},
        requested_encoder_bits_per_second_ {config_.video.selected_bits_per_second},
        requested_path_payload_ {config_.video.initial_udp_payload_size},
        current_pacing_bits_per_second_ {initial_pacing_rate(config_)},
        current_encoder_bits_per_second_ {config_.video.selected_bits_per_second},
        current_path_payload_ {config_.video.initial_udp_payload_size} {
      if (!config_.valid() || pacer_.error() != pacer_error::none ||
          congestion_.error() != transport::controller_error::none || !path_mtu_.valid()) {
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

    [[nodiscard]] std::optional<PathProbePayload> begin_path_probe(
      const std::uint64_t probe_id,
      const std::uint64_t now_microseconds,
      const std::uint64_t probe_interval_microseconds
    ) noexcept {
      if (probe_id == 0 || std::ranges::find(recent_probe_ids_, probe_id) != recent_probe_ids_.end()) {
        return std::nullopt;
      }
      const auto raise_deadline = next_path_raise_microseconds_.load(std::memory_order_acquire);
      if (raise_deadline != 0 && now_microseconds >= raise_deadline) {
        const auto raised = path_mtu_.raise_timer_elapsed();
        if (raised == transport::path_mtu_result::accepted ||
            raised == transport::path_mtu_result::no_candidate) {
          next_path_raise_microseconds_.store(0, std::memory_order_release);
        }
      }
      const auto prior_path_mtu = path_mtu_;
      const auto media_probe_interval = smoothed_rtt_microseconds_ == 0 ?
                                          probe_interval_microseconds : smoothed_rtt_microseconds_;
      const auto result = path_mtu_.start_probe(
        probe_id,
        now_microseconds,
        std::max(minimum_probe_timer_microseconds, media_probe_interval)
      );
      if (result != transport::path_mtu_result::accepted) {
        return std::nullopt;
      }
      path_mtu_before_probe_ = prior_path_mtu;
      const auto outstanding = path_mtu_.outstanding_probe();
      path_probe_ = {
        .probe = {.probe_id = outstanding.probe_id, .udp_payload_size = outstanding.payload_bytes},
        .began_microseconds = now_microseconds,
      };
      recent_probe_ids_[next_recent_probe_id_] = probe_id;
      next_recent_probe_id_ = (next_recent_probe_id_ + 1U) % recent_probe_ids_.size();
      return path_probe_.probe;
    }

    bool send_path_probe(
      const PathProbePayload &probe,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (path_probe_.probe != probe || path_probe_.local_send_pending) {
        return false;
      }
      return protect_and_submit_path_probe(now_microseconds, path_probe_.transmissions != 0);
    }

    bool acknowledge_path_probe(const PathProbePayload &probe) noexcept {
      if (last_acknowledged_probe_ == probe) {
        return true;
      }
      if (path_probe_.probe != probe ||
          path_mtu_.acknowledge_probe(probe.probe_id, probe.udp_payload_size) != transport::path_mtu_result::accepted) {
        return false;
      }
      last_acknowledged_probe_ = probe;
      path_probe_ = {};
      path_mtu_before_probe_.reset();
      requested_path_payload_.store(probe.udp_payload_size, std::memory_order_release);
      return true;
    }

    bool rollback_path_probe(const PathProbePayload &probe) noexcept {
      if (path_probe_.probe != probe || !path_mtu_before_probe_) {
        return false;
      }
      path_mtu_ = *path_mtu_before_probe_;
      path_mtu_before_probe_.reset();
      path_probe_ = {};
      next_path_raise_microseconds_.store(
        saturating_add_time(monotonic_microseconds(), path_raise_timer_microseconds),
        std::memory_order_release
      );
      return true;
    }

    bool reject_path_probe(const PathProbePayload &probe) noexcept {
      if (path_probe_.probe != probe || path_probe_.transmissions == 0 ||
          path_mtu_.probe_timed_out() != transport::path_mtu_result::accepted) {
        return false;
      }
      path_mtu_before_probe_.reset();
      path_probe_ = {};
      return true;
    }

    bool tick_path_probe(
      const std::uint64_t now_microseconds,
      const std::uint64_t probe_interval_microseconds
    ) noexcept {
      evaluate_path_black_hole(now_microseconds);
      if (local_candidate_failed_.exchange(false, std::memory_order_acq_rel)) {
        if (path_probe_.probe.probe_id == 0 ||
            path_mtu_.probe_timed_out() != transport::path_mtu_result::accepted) {
          return false;
        }
        path_probe_ = {};
        path_mtu_before_probe_.reset();
        next_path_raise_microseconds_.store(
          saturating_add_time(now_microseconds, path_raise_timer_microseconds),
          std::memory_order_release
        );
        return true;
      }
      if (path_probe_.probe.probe_id == 0) {
        if (!black_hole_requested_.exchange(false, std::memory_order_acq_rel)) {
          return true;
        }
        if (path_mtu_.confirm_black_hole(1'200) != transport::path_mtu_result::accepted) {
          return false;
        }
        path_mtu_before_probe_.reset();
        return true;
      }
      if (black_hole_requested_.exchange(false, std::memory_order_acq_rel)) {
        if (path_mtu_.confirm_black_hole(1'200) != transport::path_mtu_result::accepted) {
          return false;
        }
        path_probe_ = {};
        path_mtu_before_probe_.reset();
        return true;
      }
      if (path_probe_.local_send_pending) {
        const auto send_result = srtp_.send_protected(
          config_.peer,
          std::span<const std::uint8_t> {path_probe_.protected_packet}.first(path_probe_.protected_bytes)
        );
        if (send_result == ProtectedSendResult::would_block) {
          return true;
        }
        if (send_result == ProtectedSendResult::message_too_large) {
          path_probe_.local_send_pending = false;
          local_candidate_failed_.store(true, std::memory_order_release);
          return true;
        }
        if (send_result == ProtectedSendResult::fatal) {
          return false;
        }
        path_probe_.local_send_pending = false;
        ++path_probe_.transmissions;
        path_probe_.last_transmission_microseconds = now_microseconds;
        path_probe_datagrams_.fetch_add(1, std::memory_order_relaxed);
        if (path_probe_.protected_is_probe_timer_retry) {
          path_probe_retries_.fetch_add(1, std::memory_order_relaxed);
        }
        path_probe_.protected_is_probe_timer_retry = false;
        return true;
      }
      const auto media_probe_interval = smoothed_rtt_microseconds_ == 0 ?
                                          probe_interval_microseconds : smoothed_rtt_microseconds_;
      const auto timer = std::max(minimum_probe_timer_microseconds, media_probe_interval);
      if (path_probe_.last_transmission_microseconds == 0) {
        if (now_microseconds < path_probe_.began_microseconds ||
            now_microseconds - path_probe_.began_microseconds < timer * maximum_probe_attempts) {
          return true;
        }
        if (path_mtu_.probe_timed_out() != transport::path_mtu_result::accepted) {
          return false;
        }
        path_probe_ = {};
        path_mtu_before_probe_.reset();
        next_path_raise_microseconds_.store(
          saturating_add_time(now_microseconds, path_raise_timer_microseconds),
          std::memory_order_release
        );
        return true;
      }
      if (now_microseconds < path_probe_.last_transmission_microseconds ||
          now_microseconds - path_probe_.last_transmission_microseconds < timer) {
        return true;
      }
      if (path_probe_.transmissions < maximum_probe_attempts) {
        return protect_and_submit_path_probe(now_microseconds, true);
      }
      if (path_mtu_.probe_timed_out() != transport::path_mtu_result::accepted) {
        return false;
      }
      path_probe_ = {};
      path_mtu_before_probe_.reset();
      next_path_raise_microseconds_.store(
        saturating_add_time(now_microseconds, path_raise_timer_microseconds),
        std::memory_order_release
      );
      return true;
    }

    [[nodiscard]] std::optional<PathProbePayload> outstanding_path_probe() const noexcept {
      return path_probe_.probe.probe_id == 0 ? std::nullopt : std::optional {path_probe_.probe};
    }

    bool confirm_path_black_hole() noexcept {
      if (current_path_payload_.load(std::memory_order_acquire) <= 1'200) {
        return false;
      }
      requested_path_payload_.store(1'200, std::memory_order_release);
      black_hole_requested_.store(true, std::memory_order_release);
      next_path_raise_microseconds_.store(
        saturating_add_time(monotonic_microseconds(), path_raise_timer_microseconds),
        std::memory_order_release
      );
      return true;
    }

    bool receive_compound_rtcp(
      const std::span<const std::uint8_t> packet,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto summary = transport::parse_rtcp_datagram(packet, transport::rtcp_datagram_form::compound);
      if (!summary || now_microseconds < last_compound_rtcp_microseconds_) {
        return false;
      }
      bool sender_report_valid = false;
      bool cname_valid = false;
      std::size_t offset = 0;
      std::size_t packet_index = 0;
      while (offset < packet.size()) {
        const auto parsed = transport::parse_rtcp_packet(packet.subspan(offset));
        if (!parsed) {
          return false;
        }
        if (packet_index == 0) {
          if ((parsed.packet_type != transport::rtcp_sender_report_type &&
               parsed.packet_type != transport::rtcp_receiver_report_type) ||
              parsed.payload.size() < 4U ||
              wire::read_be<std::uint32_t>(parsed.payload.first<4>()) != config_.feedback_sender_ssrc) {
            return false;
          }
          const auto report_offset = parsed.packet_type == transport::rtcp_sender_report_type ? 24U : 4U;
          if (parsed.payload.size() != report_offset + static_cast<std::size_t>(parsed.count) * 24U) {
            return false;
          }
          for (std::size_t report = 0; report < parsed.count; ++report) {
            const auto block = parsed.payload.subspan(report_offset + report * 24U, 24U);
            if (wire::read_be<std::uint32_t>(block.first<4>()) != config_.video.primary_ssrc) {
              continue;
            }
            const auto lsr = wire::read_be<std::uint32_t>(block.subspan<16, 4>());
            const auto dlsr = wire::read_be<std::uint32_t>(block.subspan<20, 4>());
            std::uint64_t sr_sent_microseconds = 0;
            for (const auto &timing : sender_report_timings_) {
              if (timing.lsr.load(std::memory_order_acquire) == lsr) {
                sr_sent_microseconds = timing.sent_microseconds.load(std::memory_order_relaxed);
                break;
              }
            }
            if (lsr == 0 || sr_sent_microseconds == 0 || sr_sent_microseconds > now_microseconds) {
              continue;
            }
            const auto receiver_delay = static_cast<std::uint64_t>(dlsr) * 1'000'000ULL / 65'536ULL;
            const auto elapsed = now_microseconds - sr_sent_microseconds;
            if (receiver_delay >= elapsed || elapsed - receiver_delay > 10'000'000U) {
              continue;
            }
            const auto sample = static_cast<std::uint32_t>(elapsed - receiver_delay);
            if (smoothed_rtt_microseconds_ == 0) {
              smoothed_rtt_microseconds_ = sample;
              rtt_variation_microseconds_ = sample / 2U;
            } else {
              const auto difference = smoothed_rtt_microseconds_ > sample ?
                                        smoothed_rtt_microseconds_ - sample : sample - smoothed_rtt_microseconds_;
              rtt_variation_microseconds_ =
                (rtt_variation_microseconds_ * 3U + difference) / 4U;
              smoothed_rtt_microseconds_ =
                (smoothed_rtt_microseconds_ * 7U + sample) / 8U;
            }
            small_path_delivery_evidence_.fetch_add(1, std::memory_order_relaxed);
            last_small_path_delivery_microseconds_.store(now_microseconds, std::memory_order_release);
          }
          sender_report_valid = true;
        }
        if (parsed.packet_type == 202U) {
          std::size_t chunk_offset = 0;
          for (std::uint8_t chunk = 0; chunk < parsed.count; ++chunk) {
            if (parsed.payload.size() - chunk_offset < 4U) {
              return false;
            }
            const auto chunk_ssrc = wire::read_be<std::uint32_t>(parsed.payload.subspan(chunk_offset, 4));
            chunk_offset += 4U;
            bool ended = false;
            while (chunk_offset < parsed.payload.size()) {
              const auto item_type = parsed.payload[chunk_offset++];
              if (item_type == 0) {
                ended = true;
                break;
              }
              if (chunk_offset >= parsed.payload.size()) {
                return false;
              }
              const auto item_size = static_cast<std::size_t>(parsed.payload[chunk_offset++]);
              if (item_size > parsed.payload.size() - chunk_offset) {
                return false;
              }
              if (chunk_ssrc == config_.feedback_sender_ssrc && item_type == 1U && item_size != 0) {
                cname_valid = true;
              }
              chunk_offset += item_size;
            }
            if (!ended) {
              return false;
            }
            while ((chunk_offset & 3U) != 0U) {
              if (chunk_offset >= parsed.payload.size() || parsed.payload[chunk_offset] != 0) {
                return false;
              }
              ++chunk_offset;
            }
          }
          if (chunk_offset != parsed.payload.size()) {
            return false;
          }
        }
        offset += parsed.packet.size();
        ++packet_index;
      }
      if (!sender_report_valid || !cname_valid) {
        return false;
      }
      last_compound_rtcp_microseconds_ = now_microseconds;
      has_compound_rtcp_ = true;
      return true;
    }

    bool receive_congestion_feedback(
      const std::span<const std::uint8_t> packet,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto reject = [this]() noexcept {
        feedback_rejections_.fetch_add(1, std::memory_order_relaxed);
        return false;
      };
      const auto feedback = parse_congestion_feedback_packet(packet, config_.feedback_sender_ssrc);
      if (!feedback || !has_compound_rtcp_ || now_microseconds < last_compound_rtcp_microseconds_ ||
          now_microseconds - last_compound_rtcp_microseconds_ > compound_rtcp_freshness_microseconds ||
          (has_feedback_receive_time_ &&
           (now_microseconds < last_feedback_receive_microseconds_ ||
            now_microseconds - last_feedback_receive_microseconds_ <
              transport::congestion_feedback_floor_microseconds))) {
        return reject();
      }

      const auto content = classify_congestion_feedback_content(
        *feedback,
        config_.video.primary_ssrc,
        config_.audio_feedback_ssrc
      );
      if (content == CongestionFeedbackContent::invalid) {
        return reject();
      }
      const CongestionFeedbackBlockView *video_block = nullptr;
      for (std::size_t index = 0; index < feedback->block_count; ++index) {
        const auto &block = feedback->blocks[index];
        if (block.media_ssrc == config_.video.primary_ssrc) {
          video_block = &block;
        }
      }
      const auto report_timestamp = feedback->report_timestamp;
      if (has_feedback_timestamp_ && static_cast<std::int32_t>(report_timestamp - last_feedback_timestamp_) <= 0) {
        return reject();
      }
      if (content == CongestionFeedbackContent::audio_only) {
        last_feedback_timestamp_ = report_timestamp;
        last_feedback_receive_microseconds_ = now_microseconds;
        has_feedback_timestamp_ = true;
        has_feedback_receive_time_ = true;
        feedback_reports_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      if (video_block == nullptr) {
        return reject();
      }
      const auto begin_sequence = video_block->begin_sequence;
      const auto report_count = static_cast<std::size_t>(video_block->report_count);
      const auto metrics = video_block->metrics;

      std::uint64_t first_serial = 0;
      std::uint64_t last_serial = 0;
      const auto current_path_generation = path_generation_.load(std::memory_order_acquire);
      for (std::size_t index = 0; index < report_count; ++index) {
        const auto metric = wire::read_be<std::uint16_t>(metrics.subspan(index * 2U, 2));
        const auto received = (metric & 0x8000U) != 0;
        if (!received && (metric & 0x7fffU) != 0) {
          return reject();
        }
        const auto sequence = static_cast<std::uint16_t>(begin_sequence + index);
        auto &record = sent_ledger_[sequence];
        while (record.access.test_and_set(std::memory_order_acquire)) {
        }
        const auto serial = record.send_serial.load(std::memory_order_acquire);
        const auto sent = record.sent_microseconds.load(std::memory_order_relaxed);
        const auto bytes = record.complete_ip_bytes.load(std::memory_order_relaxed);
        const auto udp_payload_bytes = record.udp_payload_bytes.load(std::memory_order_relaxed);
        const auto confirmed_path_payload_bytes =
          record.confirmed_path_payload_bytes.load(std::memory_order_relaxed);
        const auto record_path_generation = record.path_generation.load(std::memory_order_relaxed);
        const auto state = record.feedback_state.load(std::memory_order_relaxed);
        const auto serial_confirmed = record.send_serial.load(std::memory_order_acquire);
        const auto invalid = serial == 0 || serial != serial_confirmed || bytes == 0 ||
                             classify_path_packet_size(udp_payload_bytes, confirmed_path_payload_bytes) ==
                               PathPacketSizeClass::invalid ||
                             record_path_generation == 0 ||
                             sent > now_microseconds ||
                             now_microseconds - sent > feedback_packet_freshness_microseconds ||
                             (index != 0 && serial != first_serial + index) || (!received && state == 2U);
        record.access.clear(std::memory_order_release);
        if (invalid) {
          return reject();
        }
        if (index == 0) {
          first_serial = serial;
        }
        last_serial = serial;
      }
      const auto highest_sent = last_send_serial_.load(std::memory_order_acquire);
      if (report_count != 0 && (last_serial > highest_sent ||
          (highest_feedback_serial_ != 0 && last_serial + 16'384U < highest_feedback_serial_))) {
        return reject();
      }

      std::uint64_t delivered_bytes = 0;
      std::uint64_t lost_bytes = 0;
      std::uint64_t ecn_ce_bytes = 0;
      std::uint64_t large_path_delivered = 0;
      std::uint64_t large_path_lost = 0;
      std::uint64_t small_path_delivered = 0;
      std::int32_t queue_delay_trend = 0;
      for (std::size_t index = 0; index < report_count; ++index) {
        const auto metric = wire::read_be<std::uint16_t>(metrics.subspan(index * 2U, 2));
        const auto received = (metric & 0x8000U) != 0;
        const auto ecn = static_cast<std::uint8_t>((metric >> 13U) & 0x03U);
        const auto sequence = static_cast<std::uint16_t>(begin_sequence + index);
        auto &record = sent_ledger_[sequence];
        while (record.access.test_and_set(std::memory_order_acquire)) {
        }
        const auto expected_serial = first_serial + index;
        if (record.send_serial.load(std::memory_order_acquire) != expected_serial) {
          record.access.clear(std::memory_order_release);
          return reject();
        }
        const auto bytes = record.complete_ip_bytes.load(std::memory_order_relaxed);
        const auto udp_payload_bytes = record.udp_payload_bytes.load(std::memory_order_relaxed);
        const auto confirmed_path_payload_bytes =
          record.confirmed_path_payload_bytes.load(std::memory_order_relaxed);
        const auto record_path_generation = record.path_generation.load(std::memory_order_relaxed);
        const auto path_size_class = classify_path_packet_size(
          udp_payload_bytes,
          confirmed_path_payload_bytes
        );
        const auto current_path_evidence = record_path_generation == current_path_generation;
        auto state = record.feedback_state.load(std::memory_order_relaxed);
        if (received) {
          const auto newly_received = state != 2U;
          if (state != 2U) {
            record.feedback_state.store(2U, std::memory_order_relaxed);
            delivered_bytes += bytes;
            if (current_path_evidence && path_size_class == PathPacketSizeClass::confirmed_size &&
                confirmed_path_payload_bytes > 1'200) {
              ++large_path_delivered;
            } else if (current_path_evidence && path_size_class == PathPacketSizeClass::smaller) {
              ++small_path_delivered;
            }
            if (state == 0U) {
              subtract_in_flight(bytes);
            }
          }
          const auto prior_ecn = record.ecn_state.load(std::memory_order_relaxed);
          if (newly_received) {
            record.ecn_state.store(ecn, std::memory_order_relaxed);
            if (ecn == 3U) {
              ecn_ce_bytes += bytes;
            }
          } else if (ecn == 3U && prior_ecn != 3U) {
            record.ecn_state.store(3U, std::memory_order_relaxed);
            ecn_ce_bytes += bytes;
          }
          const auto ato = static_cast<std::uint16_t>(metric & 0x1fffU);
          const auto sent = record.sent_microseconds.load(std::memory_order_relaxed);
          if (newly_received && ato <= 0x1ffdU &&
              (!has_delay_sample_ || sent > last_delay_send_microseconds_)) {
            const auto arrival = report_timestamp - static_cast<std::uint32_t>(ato) * 64U;
            if (has_delay_sample_) {
              const auto arrival_ticks = static_cast<std::int32_t>(arrival - last_delay_arrival_timestamp_);
              if (arrival_ticks >= 0) {
                const auto arrival_delta = static_cast<std::int64_t>(arrival_ticks) * 1'000'000LL / 65'536LL;
                const auto send_delta = static_cast<std::int64_t>(sent - last_delay_send_microseconds_);
                const auto trend = arrival_delta - send_delta;
                queue_delay_trend = static_cast<std::int32_t>(std::clamp<std::int64_t>(
                  trend,
                  std::numeric_limits<std::int32_t>::min(),
                  std::numeric_limits<std::int32_t>::max()
                ));
              }
            }
            last_delay_arrival_timestamp_ = arrival;
            last_delay_send_microseconds_ = sent;
            has_delay_sample_ = true;
          }
        } else {
          if (state == 0U) {
            record.feedback_state.store(1U, std::memory_order_relaxed);
            lost_bytes += bytes;
            if (current_path_evidence && path_size_class == PathPacketSizeClass::confirmed_size &&
                confirmed_path_payload_bytes > 1'200) {
              ++large_path_lost;
            }
            subtract_in_flight(bytes);
          }
        }
        if (record.send_serial.load(std::memory_order_acquire) != expected_serial) {
          record.access.clear(std::memory_order_release);
          return reject();
        }
        record.access.clear(std::memory_order_release);
      }

      if (last_serial != 0) {
        highest_feedback_serial_ = std::max(highest_feedback_serial_, last_serial);
      }
      last_feedback_timestamp_ = report_timestamp;
      last_feedback_receive_microseconds_ = now_microseconds;
      has_feedback_timestamp_ = true;
      has_feedback_receive_time_ = true;
      observe_path_feedback(
        now_microseconds,
        large_path_delivered,
        large_path_lost,
        small_path_delivered
      );
      const auto has_new_evidence = delivered_bytes != 0 || lost_bytes != 0 || ecn_ce_bytes != 0;
      if (!has_new_evidence) {
        feedback_reports_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      congestion_.apply_feedback({
        .delivered_bytes = delivered_bytes,
        .lost_bytes = lost_bytes,
        .ecn_ce_bytes = ecn_ce_bytes,
        .bytes_in_flight = bytes_in_flight_.load(std::memory_order_relaxed),
        .smoothed_rtt_microseconds = smoothed_rtt_microseconds_,
        .rtt_variation_microseconds = rtt_variation_microseconds_,
        .queue_delay_trend_microseconds = queue_delay_trend,
      });
      const auto congestion = congestion_.snapshot();
      requested_pacing_bits_per_second_.store(congestion.pacing_bits_per_second, std::memory_order_release);
      requested_encoder_bits_per_second_.store(
        std::min<std::uint64_t>(congestion.encoder_bits_per_second, std::numeric_limits<std::uint32_t>::max()),
        std::memory_order_release
      );
      feedback_reports_.fetch_add(1, std::memory_order_relaxed);
      feedback_delivered_bytes_.fetch_add(delivered_bytes, std::memory_order_relaxed);
      feedback_lost_bytes_.fetch_add(lost_bytes, std::memory_order_relaxed);
      return true;
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
        .current_path_payload = current_path_payload_.load(std::memory_order_relaxed),
        .pacing_bits_per_second = current_pacing_bits_per_second_.load(std::memory_order_relaxed),
        .encoder_bits_per_second = current_encoder_bits_per_second_.load(std::memory_order_relaxed),
        .feedback_reports = feedback_reports_.load(std::memory_order_relaxed),
        .feedback_rejections = feedback_rejections_.load(std::memory_order_relaxed),
        .feedback_delivered_bytes = feedback_delivered_bytes_.load(std::memory_order_relaxed),
        .feedback_lost_bytes = feedback_lost_bytes_.load(std::memory_order_relaxed),
        .path_probe_datagrams = path_probe_datagrams_.load(std::memory_order_relaxed),
        .path_probe_retries = path_probe_retries_.load(std::memory_order_relaxed),
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

    /** @brief Fold newly authenticated per-packet feedback into independent PMTU evidence. */
    void observe_path_feedback(
      const std::uint64_t now_microseconds,
      const std::uint64_t large_delivered,
      const std::uint64_t large_lost,
      const std::uint64_t small_delivered
    ) noexcept {
      if (current_path_payload_.load(std::memory_order_acquire) <= 1'200) {
        return;
      }
      if (large_delivered != 0) {
        last_large_path_delivery_microseconds_.store(now_microseconds, std::memory_order_release);
        path_confirmation_started_microseconds_.store(now_microseconds, std::memory_order_release);
        large_path_sent_packets_.store(0, std::memory_order_relaxed);
        large_path_lost_packets_.store(0, std::memory_order_relaxed);
      } else if (large_lost != 0) {
        large_path_lost_packets_.fetch_add(large_lost, std::memory_order_relaxed);
      }
      if (small_delivered != 0) {
        small_path_delivery_evidence_.fetch_add(small_delivered, std::memory_order_relaxed);
        last_small_path_delivery_microseconds_.store(now_microseconds, std::memory_order_release);
      }
      evaluate_path_black_hole(now_microseconds);
    }

    /** @brief Confirm a sustained large-only delivery failure while smaller authenticated traffic succeeds. */
    void evaluate_path_black_hole(const std::uint64_t now_microseconds) noexcept {
      if (current_path_payload_.load(std::memory_order_acquire) <= 1'200 ||
          black_hole_requested_.load(std::memory_order_acquire) ||
          large_path_sent_packets_.load(std::memory_order_relaxed) < black_hole_minimum_large_packets ||
          small_path_delivery_evidence_.load(std::memory_order_relaxed) == 0) {
        return;
      }
      const auto last_small = last_small_path_delivery_microseconds_.load(std::memory_order_acquire);
      const auto last_large = last_large_path_delivery_microseconds_.load(std::memory_order_acquire);
      const auto started = path_confirmation_started_microseconds_.load(std::memory_order_acquire);
      const auto origin = std::max(last_large, started);
      if (origin == 0 || now_microseconds < origin || now_microseconds - origin < black_hole_confirmation_microseconds ||
          last_small == 0 || now_microseconds < last_small ||
          now_microseconds - last_small > black_hole_feedback_freshness_microseconds) {
        return;
      }
      (void) confirm_path_black_hole();
    }

    /** @brief Start or clear sustained delivery confirmation for one frame-boundary path size. */
    void reset_path_confirmation(
      const std::uint16_t path_payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      auto next_generation = path_generation_.load(std::memory_order_relaxed) + 1U;
      if (next_generation == 0) {
        next_generation = 1;
      }
      path_generation_.store(next_generation, std::memory_order_release);
      large_path_sent_packets_.store(0, std::memory_order_relaxed);
      large_path_lost_packets_.store(0, std::memory_order_relaxed);
      small_path_delivery_evidence_.store(0, std::memory_order_relaxed);
      last_small_path_delivery_microseconds_.store(0, std::memory_order_release);
      if (path_payload > 1'200) {
        path_confirmation_started_microseconds_.store(now_microseconds, std::memory_order_release);
        last_large_path_delivery_microseconds_.store(now_microseconds, std::memory_order_release);
      } else {
        path_confirmation_started_microseconds_.store(0, std::memory_order_release);
        last_large_path_delivery_microseconds_.store(0, std::memory_order_release);
      }
    }

    /** @brief Subtract newly reported bytes from the bounded aggregate in-flight counter. */
    void subtract_in_flight(const std::uint64_t bytes) noexcept {
      auto current = bytes_in_flight_.load(std::memory_order_relaxed);
      while (!bytes_in_flight_.compare_exchange_weak(
        current,
        current > bytes ? current - bytes : 0,
        std::memory_order_relaxed,
        std::memory_order_relaxed
      )) {
      }
    }

    /** @brief Publish one successful final socket submission into the bounded sequence ledger. */
    void record_sent_packet(
      const std::uint16_t sequence,
      const std::uint32_t complete_ip_bytes,
      const std::uint16_t udp_payload_bytes,
      const std::uint16_t confirmed_path_payload_bytes,
      const std::uint64_t sent_microseconds
    ) noexcept {
      auto &record = sent_ledger_[sequence];
      while (record.access.test_and_set(std::memory_order_acquire)) {
      }
      if (record.send_serial.load(std::memory_order_acquire) != 0 &&
          record.feedback_state.load(std::memory_order_relaxed) == 0U) {
        subtract_in_flight(record.complete_ip_bytes.load(std::memory_order_relaxed));
      }
      record.send_serial.store(0, std::memory_order_release);
      auto serial = next_send_serial_.fetch_add(1, std::memory_order_relaxed);
      if (serial == 0) {
        serial = next_send_serial_.fetch_add(1, std::memory_order_relaxed);
      }
      record.sent_microseconds.store(sent_microseconds, std::memory_order_relaxed);
      record.complete_ip_bytes.store(complete_ip_bytes, std::memory_order_relaxed);
      record.udp_payload_bytes.store(udp_payload_bytes, std::memory_order_relaxed);
      record.confirmed_path_payload_bytes.store(confirmed_path_payload_bytes, std::memory_order_relaxed);
      record.path_generation.store(path_generation_.load(std::memory_order_relaxed), std::memory_order_relaxed);
      record.feedback_state.store(0, std::memory_order_relaxed);
      record.ecn_state.store(0, std::memory_order_relaxed);
      last_send_serial_.store(serial, std::memory_order_release);
      bytes_in_flight_.fetch_add(complete_ip_bytes, std::memory_order_relaxed);
      record.send_serial.store(serial, std::memory_order_release);
      record.access.clear(std::memory_order_release);
      if (confirmed_path_payload_bytes > 1'200 &&
          classify_path_packet_size(udp_payload_bytes, confirmed_path_payload_bytes) ==
            PathPacketSizeClass::confirmed_size) {
        large_path_sent_packets_.fetch_add(1, std::memory_order_relaxed);
      }
    }

    /** @brief Reconfigure sender-thread pacing immediately and other targets only at a frame boundary. */
    [[nodiscard]] bool apply_requested_targets(
      const std::uint64_t now_microseconds,
      const bool frame_boundary
    ) noexcept {
      auto path_payload = current_path_payload_.load(std::memory_order_relaxed);
      if (frame_boundary) {
        const auto prior_path_payload = path_payload;
        path_payload = requested_path_payload_.load(std::memory_order_acquire);
        if (path_payload < 1'200 || path_payload > config_.path_payload_ceiling) {
          return false;
        }
        current_path_payload_.store(path_payload, std::memory_order_release);
        if (path_payload != prior_path_payload) {
          reset_path_confirmation(path_payload, now_microseconds);
        }
        const auto requested_encoder = requested_encoder_bits_per_second_.load(std::memory_order_acquire);
        const auto encoder = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(
          requested_encoder,
          1'000U,
          std::numeric_limits<std::uint32_t>::max()
        ));
        if (encoder != current_encoder_bits_per_second_.load(std::memory_order_relaxed)) {
          config_.capture_mail->event<std::uint32_t>(mail::lsp_bitrate)->raise(encoder);
          current_encoder_bits_per_second_.store(encoder, std::memory_order_release);
        }
      }

      const auto pacing = requested_pacing_bits_per_second_.load(std::memory_order_acquire);
      if (pacing == 0) {
        return false;
      }
      if (pacing != current_pacing_bits_per_second_.load(std::memory_order_relaxed) ||
          path_payload != pacer_path_payload_) {
        if (!pacer_.reconfigure({
          .pacing_bits_per_second = pacing,
          .input_reserve_bits_per_second = 0,
          .path_datagram_bytes = static_cast<std::uint16_t>(path_payload + ip_udp_overhead()),
          .quantum_microseconds = 100,
          .submission_horizon_microseconds = 200,
          .max_datagrams_per_batch = 8,
        }, now_microseconds)) {
          return false;
        }
        pacer_path_payload_ = path_payload;
        current_pacing_bits_per_second_.store(pacing, std::memory_order_release);
      }
      return true;
    }

    /** @brief Freshly protect and submit one exact candidate, retaining bytes only for local retry. */
    [[nodiscard]] bool protect_and_submit_path_probe(
      const std::uint64_t now_microseconds,
      const bool probe_timer_retry
    ) noexcept {
      if (path_probe_.probe.probe_id == 0 || path_probe_.probe.udp_payload_size > path_probe_.protected_packet.size()) {
        return false;
      }
      const auto trailer = srtp_.protect_trailer_length(config_.peer, SecurePacketClass::rtcp);
      if (!trailer || *trailer >= path_probe_.probe.udp_payload_size) {
        return false;
      }
      const auto plaintext_bytes = static_cast<std::size_t>(path_probe_.probe.udp_payload_size) - *trailer;
      if (plaintext_bytes < 24U || (plaintext_bytes & 3U) != 0U) {
        return false;
      }
      std::ranges::fill(path_probe_.protected_packet, 0);
      auto packet = std::span<std::uint8_t> {path_probe_.protected_packet}.first(path_probe_.probe.udp_payload_size);
      packet[0] = 0x80U;
      packet[1] = transport::rtcp_app_type;
      wire::write_be<std::uint16_t>(packet.subspan<2, 2>(), static_cast<std::uint16_t>(plaintext_bytes / 4U - 1U));
      wire::write_be<std::uint32_t>(packet.subspan<4, 4>(), config_.video.primary_ssrc);
      std::ranges::copy(lspp_name, packet.begin() + 8);
      packet[12] = wire_version;
      packet[13] = 0;
      wire::write_be<std::uint16_t>(packet.subspan<14, 2>(), path_probe_.probe.udp_payload_size);
      wire::write_be<std::uint64_t>(packet.subspan<16, 8>(), path_probe_.probe.probe_id);

      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtcp,
            packet,
            plaintext_bytes,
            protected_bytes
          ) || protected_bytes != path_probe_.probe.udp_payload_size) {
        return false;
      }
      path_probe_.protected_bytes = protected_bytes;
      path_probe_.protected_is_probe_timer_retry = probe_timer_retry;
      const auto send_result = srtp_.send_protected(config_.peer, packet.first(protected_bytes));
      if (send_result == ProtectedSendResult::would_block) {
        path_probe_.local_send_pending = true;
        return true;
      }
      if (send_result == ProtectedSendResult::message_too_large) {
        path_probe_.local_send_pending = false;
        local_candidate_failed_.store(true, std::memory_order_release);
        return true;
      }
      if (send_result == ProtectedSendResult::fatal) {
        return false;
      }
      path_probe_.local_send_pending = false;
      ++path_probe_.transmissions;
      path_probe_.last_transmission_microseconds = now_microseconds;
      path_probe_datagrams_.fetch_add(1, std::memory_order_relaxed);
      if (probe_timer_retry) {
        path_probe_retries_.fetch_add(1, std::memory_order_relaxed);
      }
      path_probe_.protected_is_probe_timer_retry = false;
      return true;
    }

    /** @brief Submit a periodic video SR and retain its LSR timing for authenticated RR RTT. */
    void maybe_send_sender_report(
      const std::uint32_t rtp_timestamp,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (last_sender_report_microseconds_ != 0 &&
          (now_microseconds < last_sender_report_microseconds_ ||
           now_microseconds - last_sender_report_microseconds_ < video_sender_report_interval_microseconds)) {
        return;
      }
      const auto now = std::chrono::steady_clock::now();
      const auto ntp = absolute_capture_ntp(now, now);
      if (ntp == 0) {
        return;
      }
      const transport::sender_report report {
        .sender_ssrc = config_.video.primary_ssrc,
        .ntp_seconds = static_cast<std::uint32_t>(ntp >> 32U),
        .ntp_fraction = static_cast<std::uint32_t>(ntp),
        .rtp_timestamp = rtp_timestamp,
        .packet_count = rtp_packet_count_,
        .octet_count = rtp_octet_count_,
      };
      const auto written = transport::write_sender_report(report, rtcp_slab_);
      if (!written || !srtp_.protect_and_send(
                        config_.peer,
                        SecurePacketClass::rtcp,
                        std::span<const std::uint8_t> {rtcp_slab_}.first(written.bytes_written)
                      )) {
        return;
      }
      auto &timing = sender_report_timings_[next_sender_report_timing_];
      timing.lsr.store(0, std::memory_order_release);
      timing.sent_microseconds.store(now_microseconds, std::memory_order_relaxed);
      timing.lsr.store(static_cast<std::uint32_t>(ntp >> 16U), std::memory_order_release);
      next_sender_report_timing_ = (next_sender_report_timing_ + 1U) % sender_report_timings_.size();
      last_sender_report_microseconds_ = now_microseconds;
    }

    /** @brief Retire a protected partial frame without reusing any consumed RTP sequence. */
    [[nodiscard]] bool abandon_partially_submitted_frame(
      video::packet_raw_t &packet,
      const std::size_t consumed_packets,
      const bool independent_recovery_permitted
    ) noexcept {
      next_sequence_ = static_cast<std::uint16_t>(next_sequence_ + consumed_packets);
      reference_path_valid_ = false;
      dropped_frames_.fetch_add(1, std::memory_order_relaxed);
      pressure_events_.fetch_add(1, std::memory_order_relaxed);
      if (config_.reference_invalidation) {
        const auto frame_index = packet.frame_index();
        config_.capture_mail->event<std::pair<std::int64_t, std::int64_t>>(mail::invalidate_ref_frames)
          ->raise(std::make_pair(frame_index, frame_index));
        return true;
      }
      if (independent_recovery_permitted) {
        config_.capture_mail->event<bool>(mail::idr)->raise(true);
        return true;
      }
      return false;
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
      const auto boundary_now = monotonic_microseconds();
      if (!apply_requested_targets(boundary_now, true)) {
        return false;
      }
      const auto path_payload = current_path_payload_.load(std::memory_order_acquire);
      const auto pacing_rate = current_pacing_bits_per_second_.load(std::memory_order_acquire);
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
      const auto plaintext_capacity = static_cast<std::size_t>(path_payload) - sender_srtp_tag_bytes;
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
        .pacing_rate_bits_per_second = pacing_rate,
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
                                      (wire_bits * 1'000'000U + pacing_rate - 1U) / pacing_rate;
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
        if (!apply_requested_targets(now, false)) {
          return false;
        }
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
          if (plaintext_bytes + sender_srtp_tag_bytes > path_payload) {
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
          std::size_t protected_bytes = 0;
          auto send_result = srtp_.protect_and_send_in_place_result(
            config_.peer,
            SecurePacketClass::rtp,
            std::span<std::uint8_t> {packet_slab_}.first(path_payload),
            plaintext_bytes,
            protected_bytes
          );
          while (send_result == ProtectedSendResult::would_block) {
            const auto retry_time = monotonic_microseconds();
            if (retry_time >= deadline) {
              return abandon_partially_submitted_frame(packet, absolute_index + 1U, false);
            }
            std::this_thread::sleep_for(std::chrono::microseconds {50});
            send_result = srtp_.send_protected(
              config_.peer,
              std::span<const std::uint8_t> {packet_slab_}.first(protected_bytes)
            );
          }
          if (send_result == ProtectedSendResult::message_too_large && confirm_path_black_hole()) {
            return abandon_partially_submitted_frame(packet, absolute_index + 1U, true);
          }
          if (send_result != ProtectedSendResult::sent || protected_bytes == 0) {
            reference_path_valid_ = false;
            pressure_events_.fetch_add(1, std::memory_order_relaxed);
            return false;
          }
          record_sent_packet(
            rtp.sequence_number,
            charges[index],
            static_cast<std::uint16_t>(protected_bytes),
            path_payload,
            monotonic_microseconds()
          );
          ++rtp_packet_count_;
          rtp_octet_count_ += static_cast<std::uint32_t>(plan.payload_bytes);
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
      maybe_send_sender_report(rtp_timestamp, monotonic_microseconds());
      return true;
    }

    HostVideoSenderConfig config_;  ///< Immutable negotiated sender configuration.
    LibsrtpServerProvider &srtp_;  ///< Installed association provider.
    video::egress_queue_t egress_ {1};  ///< One-unsent-frame encoded egress owner.
    aggregate_pacer pacer_;  ///< Complete IP-layer rate-derived microbatch pacer.
    transport::congestion_controller congestion_;  ///< Independent forward-path RFC 8888 controller.
    transport::path_mtu_discovery path_mtu_;  ///< Authenticated host-to-client DPLPMTUD search state.
    std::optional<transport::path_mtu_discovery> path_mtu_before_probe_ {};  ///< Rollback state until control intent starts.
    std::array<std::vector<std::uint8_t>, 2> frame_slabs_ {};  ///< Two preallocated complete-AU scratch slabs.
    std::vector<PacketPlan> packet_plans_ {};  ///< Preallocated fixed-capacity packet descriptor storage.
    std::array<std::uint8_t, final_packet_slab_bytes> packet_slab_ {};  ///< Final in-place RTP/SRTP packet slab.
    std::array<std::uint8_t, 64> rtcp_slab_ {};  ///< Periodic report-block-free video SR storage.
    std::array<SentPacketRecord, 65'536> sent_ledger_ {};  ///< Current incarnation for every RTP sequence value.
    std::array<SenderReportTiming, 8> sender_report_timings_ {};  ///< Recent authenticated RR timing matches.
    PathProbeTransmission path_probe_ {};  ///< One protected logical DPLPMTUD transmission.
    PathProbePayload last_acknowledged_probe_ {};  ///< Idempotent latest semantic probe acknowledgement.
    std::array<std::uint64_t, 64> recent_probe_ids_ {};  ///< Session-retained probe-ID replay fence.
    std::jthread worker_;  ///< Dedicated packetization, pacing, and send worker.
    std::optional<std::chrono::steady_clock::time_point> capture_origin_ {};  ///< First capture sampling origin.
    std::uint16_t next_sequence_ {};  ///< Next primary RTP sequence number.
    std::uint16_t pacer_path_payload_ {1'200};  ///< UDP payload reflected by the active sender-thread pacer.
    std::uint32_t initial_timestamp_ {};  ///< Random initial 90 kHz timestamp.
    std::uint64_t next_frame_id_ {};  ///< Next nonzero frame identifier.
    std::uint64_t last_compound_rtcp_microseconds_ {};  ///< Latest valid regular compound report time.
    std::uint64_t last_feedback_receive_microseconds_ {};  ///< Local hard-floor origin for accepted CCFB.
    std::uint64_t highest_feedback_serial_ {};  ///< Greatest sent incarnation covered by valid CCFB.
    std::uint64_t last_delay_send_microseconds_ {};  ///< Prior sender time for delay-trend differencing.
    std::uint64_t last_sender_report_microseconds_ {};  ///< Last accepted video SRTCP SR submission.
    std::uint32_t last_delay_arrival_timestamp_ {};  ///< Prior receiver middle-NTP arrival timestamp.
    std::uint32_t last_feedback_timestamp_ {};  ///< Latest accepted RFC 8888 report timestamp.
    std::uint32_t smoothed_rtt_microseconds_ {};  ///< Latest regular-RTCP RTT estimate when available.
    std::uint32_t rtt_variation_microseconds_ {};  ///< Latest regular-RTCP RTT variation when available.
    std::uint32_t rtp_packet_count_ {};  ///< Video RTP packet count modulo 2^32 for SR.
    std::uint32_t rtp_octet_count_ {};  ///< Video codec-payload octets modulo 2^32 for SR.
    std::size_t next_frame_slab_ {};  ///< Alternating complete-AU scratch slot.
    std::size_t next_recent_probe_id_ {};  ///< Next session replay-cache replacement slot.
    std::size_t next_sender_report_timing_ {};  ///< Next recent-SR timing replacement slot.
    bool reference_path_valid_ {true};  ///< Whether known encoder dependencies remain decodable.
    bool has_compound_rtcp_ {};  ///< Whether reduced-size CCFB has a fresh regular-report prerequisite.
    bool has_feedback_timestamp_ {};  ///< Whether report timestamp monotonicity has an origin.
    bool has_feedback_receive_time_ {};  ///< Whether local CCFB cadence has an origin.
    bool has_delay_sample_ {};  ///< Whether delay-trend differencing has an origin.
    bool ready_ {};  ///< Constructor validation and fixed-slab allocation status.
    bool registered_ {};  ///< Whether egress retains this session key.
    std::atomic<std::uint8_t> decoder_credit_ {};  ///< Latest freshness-bounded available decoder surfaces.
    std::atomic<std::uint64_t> next_send_serial_ {1};  ///< Next nonzero RTP incarnation serial.
    std::atomic<std::uint64_t> last_send_serial_ {};  ///< Greatest release-published RTP incarnation serial.
    std::atomic<std::uint64_t> bytes_in_flight_ {};  ///< Unreported complete IP-layer bytes.
    std::atomic<std::uint64_t> next_path_raise_microseconds_ {};  ///< Earliest upward search after a failed candidate/black hole.
    std::atomic<std::uint64_t> path_confirmation_started_microseconds_ {};  ///< Current >1,200-byte monitoring origin.
    std::atomic<std::uint64_t> last_large_path_delivery_microseconds_ {};  ///< Latest authenticated large-packet receipt.
    std::atomic<std::uint64_t> last_small_path_delivery_microseconds_ {};  ///< Latest authenticated small forward-path proof.
    std::atomic<std::uint64_t> large_path_sent_packets_ {};  ///< Large protected RTP packets since last confirmed delivery.
    std::atomic<std::uint64_t> large_path_lost_packets_ {};  ///< Authenticated large-packet loss reports in the window.
    std::atomic<std::uint64_t> small_path_delivery_evidence_ {};  ///< Small RTP/SR delivery proofs in the window.
    std::atomic<std::uint32_t> path_generation_ {1};  ///< Current frame-boundary PMTU evidence generation.
    std::atomic<bool> black_hole_requested_ {};  ///< Sender-thread EMSGSIZE evidence awaiting path-state ownership.
    std::atomic<bool> local_candidate_failed_ {};  ///< LSPP EMSGSIZE awaiting candidate-only failure transition.
    std::atomic<std::uint64_t> requested_pacing_bits_per_second_ {};  ///< Socket-thread controller target.
    std::atomic<std::uint64_t> requested_encoder_bits_per_second_ {};  ///< Next-frame encoder target.
    std::atomic<std::uint16_t> requested_path_payload_ {};  ///< Next-frame confirmed UDP payload.
    std::atomic<std::uint64_t> current_pacing_bits_per_second_ {};  ///< Active sender-thread aggregate rate.
    std::atomic<std::uint64_t> current_encoder_bits_per_second_ {};  ///< Last published encoder rate.
    std::atomic<std::uint16_t> current_path_payload_ {};  ///< Active frame-boundary UDP payload.
    std::atomic<std::uint64_t> admitted_frames_ {};  ///< Complete-AU admission count.
    std::atomic<std::uint64_t> submitted_frames_ {};  ///< Fully submitted frame count.
    std::atomic<std::uint64_t> submitted_packets_ {};  ///< Protected RTP packet count.
    std::atomic<std::uint64_t> dropped_frames_ {};  ///< Whole pre-send frame drop count.
    std::atomic<std::uint64_t> submitted_wire_bytes_ {};  ///< Complete charged wire bytes.
    std::atomic<std::uint64_t> pressure_events_ {};  ///< Bounded pressure observation count.
    std::atomic<std::uint64_t> feedback_reports_ {};  ///< Accepted authenticated RFC 8888 reports.
    std::atomic<std::uint64_t> feedback_rejections_ {};  ///< Rejected malformed or hostile reports.
    std::atomic<std::uint64_t> feedback_delivered_bytes_ {};  ///< Newly accounted delivered IP bytes.
    std::atomic<std::uint64_t> feedback_lost_bytes_ {};  ///< Newly accounted lost IP bytes.
    std::atomic<std::uint64_t> path_probe_datagrams_ {};  ///< Accepted exact protected LSPP submissions.
    std::atomic<std::uint64_t> path_probe_retries_ {};  ///< Fresh SRTCP-index PROBE_TIMER retries.
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

  std::optional<PathProbePayload> HostVideoSender::begin_path_probe(
    const std::uint64_t probe_id,
    const std::uint64_t now_microseconds,
    const std::uint64_t probe_interval_microseconds
  ) noexcept {
    return impl_ ? impl_->begin_path_probe(probe_id, now_microseconds, probe_interval_microseconds) : std::nullopt;
  }

  bool HostVideoSender::send_path_probe(
    const PathProbePayload &probe,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->send_path_probe(probe, now_microseconds);
  }

  bool HostVideoSender::acknowledge_path_probe(const PathProbePayload &probe) noexcept {
    return impl_ && impl_->acknowledge_path_probe(probe);
  }

  bool HostVideoSender::rollback_path_probe(const PathProbePayload &probe) noexcept {
    return impl_ && impl_->rollback_path_probe(probe);
  }

  bool HostVideoSender::reject_path_probe(const PathProbePayload &probe) noexcept {
    return impl_ && impl_->reject_path_probe(probe);
  }

  bool HostVideoSender::tick_path_probe(
    const std::uint64_t now_microseconds,
    const std::uint64_t probe_interval_microseconds
  ) noexcept {
    return impl_ && impl_->tick_path_probe(now_microseconds, probe_interval_microseconds);
  }

  std::optional<PathProbePayload> HostVideoSender::outstanding_path_probe() const noexcept {
    return impl_ ? impl_->outstanding_path_probe() : std::nullopt;
  }

  bool HostVideoSender::confirm_path_black_hole() noexcept {
    return impl_ && impl_->confirm_path_black_hole();
  }

  bool HostVideoSender::receive_compound_rtcp(
    const std::span<const std::uint8_t> packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_compound_rtcp(packet, now_microseconds);
  }

  bool HostVideoSender::receive_congestion_feedback(
    const std::span<const std::uint8_t> packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_congestion_feedback(packet, now_microseconds);
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
