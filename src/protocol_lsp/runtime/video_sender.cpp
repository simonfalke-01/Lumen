/**
 * @file src/protocol_lsp/runtime/video_sender.cpp
 * @brief Complete-access-unit LSP H.264/HEVC/AV1 RTP/SRTP sender and repair implementation.
 */

#include "video_sender.h"

#include "../../globals.h"
#include "../../logging.h"
#include "../core/transport.h"
#include "../core/wire.h"
#include "../media/av1.h"
#include "../media/frame_pipeline.h"
#include "../media/h264.h"
#include "../media/hevc.h"
#include "../transport/congestion.h"
#include "../transport/repair.h"
#include "../transport/rtcp.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
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
    constexpr std::size_t maximum_product_flexfec_group_packets = 15;  ///< Frozen short-mask frame-local group bound.
    constexpr std::uint64_t flexfec_activation_microseconds = 1'000'000;  ///< Loss-triggered repair lifetime.
    constexpr std::uint64_t rtx_decode_safety_microseconds = 500;  ///< Minimum post-arrival decoder reserve.
    constexpr std::size_t pending_datagram_slot_count = 128;  ///< Completion metadata bounded above path slots.
    constexpr std::size_t pending_frame_slot_count = 32;  ///< Whole-frame completion states bounded above queued video.
    constexpr std::uint8_t pending_datagram_index_bits = 7;  ///< Bits naming one of 128 datagram slots.
    constexpr std::uint8_t pending_frame_index_bits = 5;  ///< Bits naming one of 32 frame slots.
    constexpr std::uint64_t pending_datagram_index_mask = pending_datagram_slot_count - 1U;  ///< Datagram token slot bits.
    constexpr std::uint64_t pending_frame_index_mask = pending_frame_slot_count - 1U;  ///< Frame ticket slot bits.
    constexpr std::uint64_t pending_datagram_incarnation_mask =
      (std::uint64_t {1} << (60U - pending_datagram_index_bits)) - 1U;  ///< Datagram token incarnation bits.
    constexpr std::uint64_t pending_frame_incarnation_mask =
      (std::uint64_t {1} << (64U - pending_frame_index_bits)) - 1U;  ///< Frame ticket incarnation bits.
    constexpr std::uint8_t feedback_unreported = 0;  ///< Actually sent and not yet reported.
    constexpr std::uint8_t feedback_lost = 1;  ///< Actually sent and reported lost.
    constexpr std::uint8_t feedback_received = 2;  ///< Actually sent and reported received.
    constexpr std::uint8_t feedback_local_unsent = 3;  ///< Protected sequence consumed without transmission.
    constexpr std::uint8_t retained_token_packet_bits = 17;  ///< Bits encoding packet index plus one.
    constexpr std::uint8_t retained_token_slot_bits = 2;  ///< Bits encoding one of three AU slots plus one.
    constexpr std::uint64_t retained_token_packet_mask =
      (std::uint64_t {1} << retained_token_packet_bits) - 1U;  ///< Packet token bits.
    constexpr std::uint64_t retained_token_slot_mask =
      (std::uint64_t {1} << retained_token_slot_bits) - 1U;  ///< Storage-slot token bits.

    /** @brief Saturatingly subtract one overlap correction from a cumulative counter. */
    void subtract_counter(std::atomic<std::uint64_t> &counter, const std::uint64_t value) noexcept {
      auto current = counter.load(std::memory_order_relaxed);
      while (!counter.compare_exchange_weak(
        current,
        current > value ? current - value : 0,
        std::memory_order_relaxed,
        std::memory_order_relaxed
      )) {
      }
    }

    /** @brief Decoded retained-AU reconstruction-token identity. */
    struct RetainedTokenIdentity {
      std::uint64_t storage_incarnation {};  ///< Nonzero AU slot reuse generation.
      std::size_t storage_index {};  ///< Fixed AU storage slot.
      std::size_t packet_index {};  ///< Packet-plan index within the AU.
    };

    /**
     * @brief Encode a unique AU slot incarnation and packet plan into one Photon token.
     *
     * @param storage_index Fixed AU storage slot.
     * @param storage_incarnation Nonzero slot reuse generation.
     * @param packet_index Packet-plan index within the AU.
     * @return Unique nonzero token, or zero when a component exceeds its fixed bit field.
     */
    [[nodiscard]] constexpr std::uint64_t make_retained_token(
      const std::size_t storage_index,
      const std::uint64_t storage_incarnation,
      const std::size_t packet_index
    ) noexcept {
      const auto slot_value = storage_index + 1U;
      const auto packet_value = packet_index + 1U;
      if (slot_value > retained_token_slot_mask || packet_value > retained_token_packet_mask ||
          storage_incarnation == 0 ||
          storage_incarnation >
            (std::numeric_limits<std::uint64_t>::max() >>
             (retained_token_slot_bits + retained_token_packet_bits))) {
        return 0;
      }
      return (storage_incarnation << (retained_token_slot_bits + retained_token_packet_bits)) |
             (static_cast<std::uint64_t>(slot_value) << retained_token_packet_bits) |
             packet_value;
    }

    /**
     * @brief Decode and validate one AU reconstruction token.
     *
     * @param token Nonzero Photon reconstruction token.
     * @return Exact storage/packet identity, or no value for a malformed token.
     */
    [[nodiscard]] constexpr std::optional<RetainedTokenIdentity> parse_retained_token(
      const std::uint64_t token
    ) noexcept {
      const auto packet_value = token & retained_token_packet_mask;
      const auto slot_value = (token >> retained_token_packet_bits) & retained_token_slot_mask;
      const auto incarnation = token >> (retained_token_packet_bits + retained_token_slot_bits);
      if (packet_value == 0 || slot_value == 0 || incarnation == 0) {
        return std::nullopt;
      }
      return RetainedTokenIdentity {
        .storage_incarnation = incarnation,
        .storage_index = static_cast<std::size_t>(slot_value - 1U),
        .packet_index = static_cast<std::size_t>(packet_value - 1U),
      };
    }

    /** @brief Atomic sent-packet ledger slot indexed by the 16-bit RTP sequence number. */
    struct SentPacketRecord {
      std::atomic_flag access = ATOMIC_FLAG_INIT;  ///< Serializes rare sequence-wrap reuse with feedback accounting.
      std::atomic<std::uint64_t> send_serial {};  ///< Nonzero release-published packet incarnation.
      std::atomic<std::uint64_t> sent_microseconds {};  ///< Last-opportunity sender timestamp.
      std::atomic<std::uint32_t> complete_ip_bytes {};  ///< Complete IP-layer bytes charged.
      std::atomic<std::uint16_t> udp_payload_bytes {};  ///< Exact protected UDP payload for PMTU evidence.
      std::atomic<std::uint16_t> confirmed_path_payload_bytes {};  ///< Frame-boundary limit active at send.
      std::atomic<std::uint32_t> path_generation {};  ///< Frame-boundary PMTU evidence generation.
      std::atomic<std::uint8_t> feedback_state {};  ///< Sent delivery state or local-unsent tombstone.
      std::atomic<std::uint8_t> ecn_state {};  ///< First echoed ECN value, upgraded once to CE when duplicated.
    };

    /** @brief One independently sequenced primary, FlexFEC, or RTX RFC 8888 sent ledger. */
    struct SentPacketLedger {
      std::array<SentPacketRecord, 65'536> records {};  ///< Current incarnation for every RTP sequence value.
      std::atomic<std::uint64_t> next_serial {1};  ///< Next protected sequence incarnation.
      std::atomic<std::uint64_t> last_serial {};  ///< Greatest sent-or-tombstoned incarnation.
      std::atomic<std::uint64_t> bytes_in_flight {};  ///< Unreported complete IP bytes for this stream.
      std::atomic<std::uint64_t> delivered_bytes {};  ///< Newly delivered complete IP bytes.
      std::atomic<std::uint64_t> lost_bytes {};  ///< Newly lost complete IP bytes.
      std::atomic<std::uint64_t> ecn_ce_bytes {};  ///< Newly CE-marked complete IP bytes.
      std::uint64_t highest_feedback_serial {};  ///< Greatest validated feedback incarnation under control lock.
    };

    /** @brief Retained logical LSPP retry state; protected bytes live only in the aggregate path. */
    struct PathProbeTransmission {
      PathProbePayload probe {};  ///< Logical identifier and protected target size.
      std::uint64_t began_microseconds {};  ///< Authenticated control-intent initiation time.
      std::uint64_t last_attempt_microseconds {};  ///< Latest protected aggregate-path admission time.
      std::uint64_t last_transmission_microseconds {};  ///< Last accepted local submission time.
      std::uint8_t transmissions {};  ///< Fresh SRTCP-index transmissions accepted locally.
      bool completion_pending {};  ///< Fresh protection is queued in the aggregate path.
    };

    /** @brief Retained middle-NTP sender-report timing used to validate RR RTT samples. */
    struct SenderReportTiming {
      std::atomic<std::uint32_t> lsr {};  ///< Middle 32 bits of the transmitted SR NTP timestamp.
      std::atomic<std::uint64_t> sent_microseconds {};  ///< Local monotonic SRTCP submission time.
    };

    /** @brief Stack guard that retires callback ownership as its final action. */
    struct CallbackRetirement {
      void *context {};  ///< Opaque callback owner.
      void (*retire)(void *context) noexcept {};  ///< Required final-action hook.

      /** @brief Invoke the final-action hook exactly once. */
      ~CallbackRetirement() {
        if (retire != nullptr) {
          retire(context);
        }
      }
    };

    /** @brief One detected Annex-B prefix and its byte width. */
    struct AnnexBPrefix {
      std::size_t offset {};  ///< First zero byte of the prefix.
      std::size_t size {};  ///< Three- or four-byte prefix size.
    };

    /** @brief One retained prefix-free codec unit in a materialized access-unit slab. */
    struct CodecUnit {
      std::size_t offset {};  ///< First retained byte in the access-unit slab.
      std::size_t size {};  ///< Prefix-free NAL or normalized OBU byte count.
    };

    /** @brief Allocation-free planned H.264/HEVC/AV1 RTP codec-payload operation. */
    struct PacketPlan {
      /** @brief Codec-payload construction kind for one final RTP packet. */
      enum class Kind : std::uint8_t {
        single,  ///< One complete NAL unit.
        aggregate,  ///< Same-frame STAP-A or AP payload.
        fragment,  ///< H.264 FU-A or HEVC FU payload.
        av1_complete,  ///< One AOM aggregation packet containing complete normalized OBUs.
        av1_fragment,  ///< One AOM Z/Y fragment of a normalized OBU.
      } kind {Kind::single};  ///< Codec-payload construction kind.
      std::size_t nal_index {};  ///< First source NAL index.
      std::size_t nal_count {1};  ///< Aggregate NAL count.
      std::size_t fragment_offset {};  ///< Offset after the source NAL header.
      std::size_t fragment_bytes {};  ///< Source bytes in one fragment.
      bool fragment_start {};  ///< Whether this fragment starts its source NAL.
      bool fragment_end {};  ///< Whether this fragment ends its source NAL.
      bool starts_coded_video_sequence {};  ///< Whether AV1 `N` is set on this packet.
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

    /**
     * @brief Normalize one low-overhead AV1 temporal unit in place.
     *
     * Temporal-delimiter and tile-list OBUs are omitted, retained OBU size fields are removed, and
     * the compacted prefix is represented by caller-owned views.
     *
     * @param access_unit Writable complete low-overhead temporal-unit bytes.
     * @param units Fixed output storage for normalized OBU views.
     * @param normalized_bytes Receives the compacted leading byte count.
     * @return Number of normalized transmissible OBUs, or zero on malformed input.
     */
    [[nodiscard]] std::size_t normalize_av1_obus(
      const std::span<std::uint8_t> access_unit,
      std::array<std::span<const std::uint8_t>, maximum_nal_units_per_access_unit> &units,
      std::size_t &normalized_bytes
    ) noexcept {
      std::size_t read_offset = 0;
      std::size_t write_offset = 0;
      std::size_t unit_count = 0;
      while (read_offset < access_unit.size()) {
        const auto header = access_unit[read_offset++];
        if ((header & 0x81U) != 0 || (header & 0x02U) == 0) {
          return 0;
        }
        const auto obu_type = static_cast<std::uint8_t>((header >> 3U) & 0x0fU);
        const auto extension_bytes = (header & 0x04U) != 0 ? std::size_t {1} : std::size_t {0};
        if (extension_bytes > access_unit.size() - read_offset) {
          return 0;
        }
        const auto extension = extension_bytes != 0 ? access_unit[read_offset] : std::uint8_t {0};
        if (extension_bytes != 0 && (extension & 0x07U) != 0) {
          return 0;
        }
        read_offset += extension_bytes;

        std::size_t payload_bytes = 0;
        std::size_t shift = 0;
        bool terminated = false;
        for (std::size_t byte_index = 0; byte_index < 8U; ++byte_index) {
          if (read_offset == access_unit.size()) {
            return 0;
          }
          const auto byte = access_unit[read_offset++];
          const auto value = static_cast<std::size_t>(byte & 0x7fU);
          if (shift >= std::numeric_limits<std::size_t>::digits ||
              value > (std::numeric_limits<std::size_t>::max() >> shift)) {
            return 0;
          }
          payload_bytes |= value << shift;
          if ((byte & 0x80U) == 0) {
            terminated = true;
            break;
          }
          shift += 7U;
        }
        if (!terminated || payload_bytes > std::numeric_limits<std::uint32_t>::max() ||
            payload_bytes > access_unit.size() - read_offset) {
          return 0;
        }

        if (obu_type != 2U && obu_type != 8U) {
          if (unit_count == units.size()) {
            return 0;
          }
          const auto unit_begin = write_offset;
          access_unit[write_offset++] = static_cast<std::uint8_t>(header & ~0x02U);
          if (extension_bytes != 0) {
            access_unit[write_offset++] = extension;
          }
          std::memmove(access_unit.data() + write_offset, access_unit.data() + read_offset, payload_bytes);
          write_offset += payload_bytes;
          units[unit_count++] = std::span<const std::uint8_t> {access_unit}.subspan(
            unit_begin,
            write_offset - unit_begin
          );
        }
        read_offset += payload_bytes;
      }
      normalized_bytes = write_offset;
      return unit_count;
    }

    /**
     * @brief Plan AOM AV1 RTP payloads into fixed caller storage without heap allocation.
     *
     * @param obus Normalized OBUs from one temporal unit.
     * @param starts_coded_video_sequence Whether the first emitted packet sets AOM `N`.
     * @param boundary_capacity Codec bytes available on boundary-extension packets.
     * @param middle_capacity Codec bytes available on extension-free packets.
     * @param plans Fixed packet-plan output storage.
     * @return Populated leading plan count, or zero on malformed input or insufficient storage.
     */
    [[nodiscard]] std::size_t plan_av1_packets(
      const std::span<const std::span<const std::uint8_t>> obus,
      const bool starts_coded_video_sequence,
      const std::size_t boundary_capacity,
      const std::size_t middle_capacity,
      const std::span<PacketPlan> plans
    ) noexcept {
      if (boundary_capacity < 2U || middle_capacity < 2U) {
        return 0;
      }
      for (const auto obu : obus) {
        if (media::detail::classify_av1_source_obu(obu) !=
            media::detail::av1_source_obu_status::valid) {
          return 0;
        }
      }

      std::size_t plan_count = 0;
      std::size_t obu_index = 0;
      std::size_t fragment_offset = 0;
      while (obu_index < obus.size()) {
        if (plan_count == plans.size()) {
          return 0;
        }
        const auto obu = obus[obu_index];
        if (fragment_offset != 0 && obu_index + 1U == obus.size() &&
            obu.size() - fragment_offset <= boundary_capacity - 1U) {
          const auto remaining = obu.size() - fragment_offset;
          plans[plan_count++] = {
            .kind = PacketPlan::Kind::av1_fragment,
            .nal_index = obu_index,
            .fragment_offset = fragment_offset,
            .fragment_bytes = remaining,
            .fragment_start = false,
            .fragment_end = true,
            .payload_bytes = remaining + 1U,
          };
          ++obu_index;
          break;
        }

        if (fragment_offset == 0) {
          std::size_t final_count = 0;
          for (std::size_t count = 1; count <= obus.size() - obu_index; ++count) {
            if (!media::detail::av1_elements_may_aggregate(obus, obu_index, count) ||
                media::detail::av1_complete_packet_size(obus, obu_index, count) > boundary_capacity) {
              break;
            }
            final_count = count;
          }
          if (final_count == obus.size() - obu_index) {
            plans[plan_count++] = {
              .kind = PacketPlan::Kind::av1_complete,
              .nal_index = obu_index,
              .nal_count = final_count,
              .starts_coded_video_sequence = starts_coded_video_sequence && plan_count == 0,
              .payload_bytes = media::detail::av1_complete_packet_size(obus, obu_index, final_count),
            };
            obu_index = obus.size();
            break;
          }
        }

        const auto capacity = plan_count < 2U ? boundary_capacity : middle_capacity;
        if (fragment_offset != 0 || obu.size() + 1U > capacity ||
            (obu_index + 1U == obus.size() && obu.size() + 1U > boundary_capacity)) {
          const auto remaining = obu.size() - fragment_offset;
          auto count = std::min(remaining, capacity - 1U);
          if (obu_index + 1U == obus.size() && count == remaining && remaining > boundary_capacity - 1U) {
            --count;
          }
          if (count == 0) {
            return 0;
          }
          const auto end = count == remaining;
          plans[plan_count++] = {
            .kind = PacketPlan::Kind::av1_fragment,
            .nal_index = obu_index,
            .fragment_offset = fragment_offset,
            .fragment_bytes = count,
            .fragment_start = fragment_offset == 0,
            .fragment_end = end,
            .starts_coded_video_sequence = starts_coded_video_sequence && plan_count == 0 && fragment_offset == 0,
            .payload_bytes = count + 1U,
          };
          fragment_offset += count;
          if (end) {
            ++obu_index;
            fragment_offset = 0;
          }
          continue;
        }

        std::size_t aggregate_count = 0;
        for (std::size_t count = 1; count <= obus.size() - obu_index; ++count) {
          if (!media::detail::av1_elements_may_aggregate(obus, obu_index, count)) {
            break;
          }
          const auto size = media::detail::av1_complete_packet_size(obus, obu_index, count);
          if (size > capacity || (obu_index + count == obus.size() && size > boundary_capacity)) {
            break;
          }
          aggregate_count = count;
        }
        if (aggregate_count == 0) {
          return 0;
        }
        plans[plan_count++] = {
          .kind = PacketPlan::Kind::av1_complete,
          .nal_index = obu_index,
          .nal_count = aggregate_count,
          .starts_coded_video_sequence = starts_coded_video_sequence && plan_count == 0,
          .payload_bytes = media::detail::av1_complete_packet_size(obus, obu_index, aggregate_count),
        };
        obu_index += aggregate_count;
      }
      return plan_count;
    }

    /**
     * @brief Write one unsigned LEB128 value into caller storage.
     *
     * @param value Value to encode minimally.
     * @param destination Output storage.
     * @return Encoded byte count, or zero when storage is insufficient.
     */
    [[nodiscard]] std::size_t write_leb128(
      std::size_t value,
      const std::span<std::uint8_t> destination
    ) noexcept {
      std::size_t written = 0;
      do {
        if (written == destination.size()) {
          return 0;
        }
        auto byte = static_cast<std::uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) {
          byte |= 0x80U;
        }
        destination[written++] = byte;
      } while (value != 0);
      return written;
    }

    /**
     * @brief Write one planned AOM AV1 codec payload into a final RTP slab.
     *
     * @param plan Immutable packet reconstruction plan.
     * @param obus Normalized OBU views retained by the access-unit slab.
     * @param destination Exact codec-payload destination.
     * @return True only when the exact planned payload was written.
     */
    [[nodiscard]] bool write_av1_payload(
      const PacketPlan &plan,
      const std::span<const std::span<const std::uint8_t>> obus,
      const std::span<std::uint8_t> destination
    ) noexcept {
      if (destination.size() != plan.payload_bytes || plan.nal_index >= obus.size()) {
        return false;
      }
      if (plan.kind == PacketPlan::Kind::av1_fragment) {
        const auto obu = obus[plan.nal_index];
        if (plan.fragment_offset + plan.fragment_bytes > obu.size() || destination.empty()) {
          return false;
        }
        destination[0] = static_cast<std::uint8_t>(
          (plan.fragment_start ? 0U : 0x80U) |
          (plan.fragment_end ? 0U : 0x40U) |
          0x10U |
          (plan.starts_coded_video_sequence ? 0x08U : 0U)
        );
        std::copy_n(
          obu.begin() + static_cast<std::ptrdiff_t>(plan.fragment_offset),
          plan.fragment_bytes,
          destination.begin() + 1
        );
        return true;
      }
      if (plan.kind != PacketPlan::Kind::av1_complete || plan.nal_count == 0 ||
          plan.nal_index + plan.nal_count > obus.size()) {
        return false;
      }
      const auto w = plan.nal_count <= 3U ? static_cast<std::uint8_t>(plan.nal_count) : std::uint8_t {0};
      destination[0] = static_cast<std::uint8_t>(
        (w << 4U) | (plan.starts_coded_video_sequence ? 0x08U : 0U)
      );
      std::size_t offset = 1;
      for (std::size_t relative = 0; relative < plan.nal_count; ++relative) {
        const auto obu = obus[plan.nal_index + relative];
        if (w == 0 || relative + 1U < plan.nal_count) {
          const auto length_bytes = write_leb128(obu.size(), destination.subspan(offset));
          if (length_bytes == 0) {
            return false;
          }
          offset += length_bytes;
        }
        if (obu.size() > destination.size() - offset) {
          return false;
        }
        std::copy(obu.begin(), obu.end(), destination.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += obu.size();
      }
      return offset == destination.size();
    }

    /**
     * @brief Write one codec-specific retained packet plan into exact destination storage.
     *
     * @param codec Negotiated video codec.
     * @param plan Immutable packet reconstruction plan.
     * @param units Prefix-free codec-unit views.
     * @param destination Exact codec-payload destination.
     * @return True only when the selected packetizer wrote the complete planned payload.
     */
    [[nodiscard]] bool write_codec_payload(
      const VideoCodec codec,
      const PacketPlan &plan,
      const std::span<const std::span<const std::uint8_t>> units,
      const std::span<std::uint8_t> destination
    ) noexcept {
      switch (codec) {
        case VideoCodec::h264:
          return write_h264_payload(plan, units, destination);
        case VideoCodec::hevc:
          return write_hevc_payload(plan, units, destination);
        case VideoCodec::av1:
        case VideoCodec::bc1:
          return write_av1_payload(plan, units, destination);
      }
      return false;
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

    /** @brief One staging/current slot or one of two immutable successful RTX generations. */
    struct RetainedAccessUnit {
      /** @brief Product ownership phase for one of three preallocated AU storage slots. */
      enum class Phase : std::uint8_t {
        free,  ///< Available for the next staging frame.
        staging,  ///< Materialized/planned but not yet network-visible.
        current,  ///< Admitted current frame without active RTX retention.
        building,  ///< Network-visible frame retained in a speculative Photon transaction.
        committed,  ///< Fully sent frame visible to O(1) NACK lookup.
      };

      std::vector<std::uint8_t> bytes {};  ///< Preallocated materialized/normalized access-unit slab.
      std::vector<PacketPlan> plans {};  ///< Preallocated exact packet-reconstruction plans.
      std::array<CodecUnit, maximum_nal_units_per_access_unit> units {};  ///< Prefix-free retained codec units.
      OwnedExtensionBlocks extensions {};  ///< Reproducible boundary metadata for primary or RTX.
      std::size_t access_unit_bytes {};  ///< Populated immutable leading access-unit bytes.
      std::size_t plan_count {};  ///< Populated leading packet plans.
      std::size_t unit_count {};  ///< Populated leading codec-unit descriptors.
      std::uint64_t frame_id {};  ///< Nonzero LSP frame identity for retention eviction.
      std::uint64_t incarnation {};  ///< Nonzero storage-slot reuse generation.
      std::uint64_t deadline_microseconds {};  ///< Strict absolute frame repair deadline.
      std::uint32_t rtp_timestamp {};  ///< Original primary-video RTP timestamp.
      std::uint16_t first_sequence {};  ///< Original first primary RTP sequence.
      transport::rtx_frame_handle rtx_handle {};  ///< Photon building/committed frame transaction handle.
      std::size_t retained_tokens {};  ///< Live Photon reconstruction tokens naming this storage.
      bool independent {};  ///< Whether the retained frame is independently decodable.
      bool rtx_disabled {};  ///< Whether this current frame stopped attempting RTX retention.
      Phase phase {Phase::free};  ///< Current staging/transaction/history ownership phase.
    };

    /**
     * @brief Rebuild borrowed codec-unit spans from immutable retained descriptors.
     *
     * @param frame Published retained access-unit generation.
     * @param storage Fixed output storage for borrowed codec-unit views.
     * @return True only when every retained descriptor is within the immutable slab prefix.
     */
    [[nodiscard]] bool retained_unit_views(
      const RetainedAccessUnit &frame,
      std::array<std::span<const std::uint8_t>, maximum_nal_units_per_access_unit> &storage
    ) noexcept {
      if (frame.phase != RetainedAccessUnit::Phase::committed || frame.unit_count == 0 ||
          frame.unit_count > storage.size() ||
          frame.access_unit_bytes == 0 || frame.access_unit_bytes > frame.bytes.size()) {
        return false;
      }
      const auto access_unit = std::span<const std::uint8_t> {frame.bytes}.first(frame.access_unit_bytes);
      for (std::size_t index = 0; index < frame.unit_count; ++index) {
        const auto &unit = frame.units[index];
        if (unit.size == 0 || unit.offset > access_unit.size() || unit.size > access_unit.size() - unit.offset) {
          return false;
        }
        storage[index] = access_unit.subspan(unit.offset, unit.size);
      }
      return true;
    }

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
      const std::uint32_t recovery_epoch,
      const std::uint64_t input_state_sequence,
      const std::uint64_t input_edge_id,
      const std::uint32_t capture_to_submit_us,
      const std::uint32_t capture_to_complete_us
    ) noexcept {
      std::array<std::uint8_t, 8> capture_bytes {};
      std::array<std::uint8_t, video_frame_identity_extension_size> frame_identity_bytes {};
      std::array<std::uint8_t, 16> watermark_bytes {};
      std::array<std::uint8_t, 8> timing_bytes {};
      wire::write_be<std::uint64_t>(capture_bytes, capture_ntp);
      if (!write_video_frame_identity_extension(frame_identity_bytes, frame_id, recovery_epoch)) {
        return 0;
      }
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
           !append_extension(output, offset, video_frame_id_extension_id, frame_identity_bytes) ||
           !append_extension(output, offset, video_input_watermark_extension_id, watermark_bytes) ||
           !append_extension(output, offset, video_encoder_timing_extension_id, timing_bytes))) {
        return 0;
      }
      if (!full_metadata && !append_extension(output, offset, video_frame_id_extension_id, frame_identity_bytes)) {
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
      const std::uint32_t recovery_epoch,
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
      blocks.first_and_final_size = write_extension_block(blocks.first_and_final, static_cast<std::uint8_t>(start | end | independent_mark), true, capture_ntp, frame_id, recovery_epoch, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.first_size = write_extension_block(blocks.first, static_cast<std::uint8_t>(start | independent_mark), true, capture_ntp, frame_id, recovery_epoch, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.second_and_final_size = write_extension_block(blocks.second_and_final, static_cast<std::uint8_t>(end | independent_mark), true, capture_ntp, frame_id, recovery_epoch, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.second_size = write_extension_block(blocks.second, independent_mark, true, capture_ntp, frame_id, recovery_epoch, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      blocks.final_size = write_extension_block(blocks.final, static_cast<std::uint8_t>(end | independent_mark), false, capture_ntp, frame_id, recovery_epoch, input_state_sequence, input_edge_id, capture_to_submit_us, capture_to_complete_us);
      if (blocks.first_and_final_size == 0 || blocks.first_size == 0 || blocks.second_and_final_size == 0 ||
          blocks.second_size == 0 || blocks.final_size == 0) {
        return std::nullopt;
      }
      return blocks;
    }

    /** @brief Return monotonic microseconds for frame admission and pacing. */
    [[nodiscard]] std::uint64_t video_monotonic_microseconds() noexcept {
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
               std::numeric_limits<std::uint64_t>::max() :
               now_microseconds + interval_microseconds;
    }

    /** @brief Clamp the initial aggregate rate to selected video plus reserved overhead. */
    [[nodiscard]] std::uint64_t initial_pacing_rate(const HostVideoSenderConfig &config) noexcept {
      if (config.video.codec == VideoCodec::bc1) {
        return config.aggregate_pacing_bits_per_second;  // Fixed-rate; the wire bitrate field caps at 1 Gbit/s.
      }
      const auto media_rate = config.video.selected_bits_per_second >
                                  std::numeric_limits<std::uint64_t>::max() - config.reserved_overhead_bits_per_second ?
                                std::numeric_limits<std::uint64_t>::max() :
                                config.video.selected_bits_per_second + config.reserved_overhead_bits_per_second;
      return std::min(config.aggregate_pacing_bits_per_second, media_rate);
    }

    /** @brief Bound unsent encoded frames so the sender plus queue cannot exceed decoder surfaces. */
    [[nodiscard]] std::size_t video_egress_capacity(const HostVideoSenderConfig &config) noexcept {
      return config.video.decoder_surfaces > 1U ?
               static_cast<std::size_t>(config.video.decoder_surfaces - 1U) :
               1U;
    }
  }  // namespace

  bool write_video_frame_identity_extension(
    const std::span<std::uint8_t> destination,
    const std::uint64_t frame_id,
    const std::uint32_t recovery_epoch
  ) noexcept {
    if (destination.size() != video_frame_identity_extension_size || frame_id == 0 || recovery_epoch == 0) {
      return false;
    }
    wire::write_be<std::uint64_t>(destination.first<8>(), frame_id);
    wire::write_be<std::uint32_t>(destination.subspan<8, 4>(), recovery_epoch);
    return true;
  }

  VideoRecoveryFeedbackAction apply_authenticated_lspv_recovery(
    transport::recovery_controller &recovery,
    bool &failure_latched,
    const transport::lspv_status &status,
    const std::uint64_t latest_sent_frame_id,
    const std::uint64_t now_microseconds
  ) noexcept {
    if (transport::validate_lspv_status(status) != transport::lspv_status_error::none) {
      return VideoRecoveryFeedbackAction::ignored;
    }
    auto snapshot = recovery.snapshot();
    if (status.recovery_epoch != snapshot.epoch) {
      return VideoRecoveryFeedbackAction::ignored;
    }

    const auto decoder_error = status.decoder_status == transport::lspv_decoder_status::recoverable_error ||
                               status.decoder_status == transport::lspv_decoder_status::unrecoverable_error;
    if (snapshot.phase == transport::recovery_phase::recovery_frame_outstanding &&
        status.largest_decoded_frame_id >= snapshot.outstanding_recovery_frame_id &&
        recovery.confirm_recovery_decoded_through(
          status.recovery_epoch,
          status.largest_decoded_frame_id
        ) == transport::recovery_result::accepted) {
      failure_latched = false;
      snapshot = recovery.snapshot();
    }

    if (snapshot.phase == transport::recovery_phase::healthy && decoder_error) {
      const auto damaged_frame_id = status.largest_complete_frame_id != 0 ?
                                      status.largest_complete_frame_id :
                                      latest_sent_frame_id;
      if (recovery.report_unrecoverable_damage(
            damaged_frame_id,
            transport::recovery_cause::decoder_unrecoverable
          ) == transport::recovery_result::accepted) {
        failure_latched = false;
        return VideoRecoveryFeedbackAction::request_independent_frame;
      }
      return VideoRecoveryFeedbackAction::ignored;
    }

    snapshot = recovery.snapshot();
    if (decoder_error) {
      failure_latched = true;
    }
    if (snapshot.phase == transport::recovery_phase::recovery_frame_outstanding &&
        failure_latched && now_microseconds >= snapshot.recovery_deadline_microseconds &&
        recovery.permit_retry(now_microseconds, true) == transport::recovery_result::accepted) {
      failure_latched = false;
      return VideoRecoveryFeedbackAction::request_independent_frame;
    }
    return VideoRecoveryFeedbackAction::accepted;
  }

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
    const auto validated = transport::validate_congestion_feedback_packet(packet, expected_sender_ssrc);
    return validated ? std::optional {validated} : std::nullopt;
  }

  bool HostVideoSenderConfig::valid() const noexcept {
    const auto codec_profile =
      (video.codec == VideoCodec::h264 && video.profile == VideoProfile::h264_high &&
       video.pixel_format == VideoPixelClass::yuv420_8) ||
      (video.codec == VideoCodec::h264 && video.profile == VideoProfile::h264_high_444_predictive &&
       video.pixel_format == VideoPixelClass::yuv444_8) ||
      (video.codec == VideoCodec::hevc && video.profile == VideoProfile::hevc_main &&
       video.pixel_format == VideoPixelClass::yuv420_8) ||
      (video.codec == VideoCodec::hevc && video.profile == VideoProfile::hevc_main10 &&
       video.pixel_format == VideoPixelClass::yuv420_10) ||
      (video.codec == VideoCodec::hevc && video.profile == VideoProfile::hevc_range_extensions &&
       (video.pixel_format == VideoPixelClass::yuv444_8 ||
        video.pixel_format == VideoPixelClass::yuv444_10)) ||
      (video.codec == VideoCodec::av1 && video.profile == VideoProfile::av1_main &&
       (video.pixel_format == VideoPixelClass::yuv420_8 ||
        video.pixel_format == VideoPixelClass::yuv420_10)) ||
      (video.codec == VideoCodec::av1 && video.profile == VideoProfile::av1_high &&
       (video.pixel_format == VideoPixelClass::yuv444_8 ||
        video.pixel_format == VideoPixelClass::yuv444_10)) ||
      (video.codec == VideoCodec::bc1 && video.profile == VideoProfile::bc1 &&
       video.pixel_format == VideoPixelClass::yuv420_8);
    const auto ten_bit = video.pixel_format == VideoPixelClass::yuv420_10 ||
                         video.pixel_format == VideoPixelClass::yuv444_10;
    const auto color_valid =
      (video.color_primaries == video_color_bt709 && video.transfer_function == video_color_bt709 &&
       video.matrix_coefficients == video_color_bt709) ||
      (video.color_primaries == video_color_bt709 && video.transfer_function == video_color_bt709 &&
       video.matrix_coefficients == video_matrix_bt601 && video.pixel_format == VideoPixelClass::yuv420_8 &&
       !video.full_range) ||
      (ten_bit && video.color_primaries == video_color_primaries_bt2020 &&
       (video.transfer_function == video_transfer_pq || video.transfer_function == video_transfer_hlg) &&
       video.matrix_coefficients == video_matrix_bt2020_ncl && !video.full_range);
    const auto flexfec_valid = !video.flexfec ||
                               (video.flexfec->repair_ssrc != 0 &&
                                video.flexfec->repair_ssrc != video.primary_ssrc &&
                                media::valid_dynamic_payload_type(video.flexfec->repair_payload_type) &&
                                video.flexfec->repair_payload_type != video.primary_payload_type &&
                                video.flexfec->window_microseconds != 0 &&
                                video.flexfec->window_microseconds <= video_maximum_frame_age_microseconds &&
                                video.flexfec->window_microseconds <= video.maximum_frame_age_microseconds &&
                                video.flexfec->maximum_group_packets == maximum_product_flexfec_group_packets);
    const auto rtx_valid = !video.rtx ||
                           (video.rtx->rtx_ssrc != 0 && video.rtx->rtx_ssrc != video.primary_ssrc &&
                            (!video.flexfec || video.rtx->rtx_ssrc != video.flexfec->repair_ssrc) &&
                            media::valid_dynamic_payload_type(video.rtx->rtx_payload_type) &&
                            video.rtx->rtx_payload_type != video.primary_payload_type &&
                            (!video.flexfec ||
                             video.rtx->rtx_payload_type != video.flexfec->repair_payload_type) &&
                            video.rtx->associated_payload_type == video.primary_payload_type);
    return peer.valid() && forward_path && forward_path->ready() && forward_path->snapshot().started &&
           !forward_path->snapshot().closed && forward_path_generation != 0 &&
           forward_path->generation() == forward_path_generation && codec_profile && color_valid && flexfec_valid &&
           rtx_valid &&
           video.video_generation != 0 && video.primary_ssrc != 0 &&
           video.primary_payload_type >= 96 && video.primary_payload_type <= 127 && video.clock_rate == 90'000 &&
           video.width > 0 && video.width <= 16'384 && video.height > 0 && video.height <= 16'384 &&
           video.refresh_numerator > 0 && video.refresh_denominator > 0 &&
           video.selected_bits_per_second >= video_minimum_bits_per_second &&
           video.selected_bits_per_second <= 1'000'000'000ULL &&
           video.initial_udp_payload_size == media::initial_udp_payload_size && video.decoder_surfaces >= 2 &&
           video.decoder_surfaces <= 4 && video.render_mailbox == 1 &&
           video.delivery == video_delivery_complete_access_unit &&
           video.frame_marking_extension == video_frame_marking_extension_id &&
           video.absolute_capture_time_extension == video_absolute_capture_time_extension_id &&
           video.frame_id_extension == video_frame_id_extension_id &&
           video.input_watermark_extension == video_input_watermark_extension_id &&
           video.encoder_timing_extension == video_encoder_timing_extension_id &&
           initial_timestamp != 0 && frame_id_origin != 0 && initial_recovery_epoch != 0 &&
           maximum_access_unit_bytes > 0 &&
           maximum_access_unit_bytes <= media::competition_frame_size_limit &&
           video.maximum_complete_access_unit_bytes == maximum_access_unit_bytes &&
           maximum_capture_to_present_microseconds > 0 &&
           video.maximum_frame_age_microseconds == maximum_capture_to_present_microseconds &&
           video.maximum_frame_age_microseconds <= video_maximum_frame_age_microseconds &&
           aggregate_pacing_bits_per_second > reserved_overhead_bits_per_second &&
           path_payload_ceiling >= 1'200 &&
           path_payload_ceiling <= (family == media::ip_family::ipv4 ? media::ipv4_udp_payload_ceiling :
                                                                       media::ipv6_udp_payload_ceiling) &&
           feedback_sender_ssrc != 0 && audio_feedback_ssrc != 0 &&
           audio_feedback_ssrc != video.primary_ssrc && rtcp_cname.valid() && capture_mail;
  }

  class HostVideoSender::Impl {
  public:
    /** @brief Validate configuration and allocate every lifetime-bounded slab and descriptor. */
    Impl(HostVideoSenderConfig config, LibsrtpServerProvider &srtp) noexcept:
        config_ {std::move(config)},
        srtp_ {srtp},
        invalidation_request_events_ {config_.capture_mail ? config_.capture_mail->event<video::reference_invalidation_request_t>(mail::lsp_invalidate_ref_frames) : safe::mail_raw_t::event_t<video::reference_invalidation_request_t> {}},
        invalidation_result_events_ {config_.capture_mail ? config_.capture_mail->event<video::reference_invalidation_result_t>(mail::invalidate_ref_frames_result) : safe::mail_raw_t::event_t<video::reference_invalidation_result_t> {}},
        egress_ {video_egress_capacity(config_)},
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
                                                    config_.aggregate_pacing_bits_per_second :
                                                    0,
          .reserved_overhead_bits_per_second = config_.reserved_overhead_bits_per_second,
          .rtt_inflation_budget_microseconds = config_.network_profile == VideoNetworkProfile::competition ? 20'000U : 50'000U,
          .queue_delay_budget_microseconds = config_.network_profile == VideoNetworkProfile::competition ? 2'000U : 10'000U,
        }),
        path_mtu_({
          .ip_version = config_.family == media::ip_family::ipv4 ?
                          transport::path_ip_version::ipv4 :
                          transport::path_ip_version::ipv6,
          .sender_interface_limit = config_.path_payload_ceiling,
          .receiver_advertised_limit = config_.path_payload_ceiling,
          .operator_configured_limit = config_.path_payload_ceiling,
        }),
        recovery_ {config_.initial_recovery_epoch},
        next_sequence_ {config_.initial_sequence},
        next_flexfec_sequence_ {config_.initial_flexfec_sequence},
        next_rtx_sequence_ {config_.initial_rtx_sequence},
        initial_timestamp_ {config_.initial_timestamp},
        next_frame_id_ {config_.frame_id_origin},
        decoder_credit_ {config_.video.decoder_surfaces},
        requested_pacing_bits_per_second_ {initial_pacing_rate(config_)},
        requested_encoder_bits_per_second_ {config_.video.selected_bits_per_second},
        requested_path_payload_ {config_.video.initial_udp_payload_size},
        current_pacing_bits_per_second_ {initial_pacing_rate(config_)},
        current_encoder_bits_per_second_ {config_.video.selected_bits_per_second},
        current_path_payload_ {config_.video.initial_udp_payload_size} {
      for (std::size_t index = 0; index < free_pending_datagrams_.size(); ++index) {
        free_pending_datagrams_[index] = static_cast<std::uint8_t>(free_pending_datagrams_.size() - 1U - index);
      }
      free_pending_datagram_count_ = free_pending_datagrams_.size();
      for (std::size_t index = 0; index < free_pending_frames_.size(); ++index) {
        free_pending_frames_[index] = static_cast<std::uint8_t>(free_pending_frames_.size() - 1U - index);
      }
      free_pending_frame_count_ = free_pending_frames_.size();
      if (!config_.valid() || congestion_.error() != transport::controller_error::none || !path_mtu_.valid()) {
        return;
      }
      try {
        for (auto &frame : retained_frames_) {
          frame.bytes.resize(config_.maximum_access_unit_bytes);
          frame.plans.resize(media::maximum_fragments_per_frame);
        }
        retained_frames_[0].phase = RetainedAccessUnit::Phase::staging;
        staging_frame_index_ = 0;
        if (config_.video.rtx) {
          rtx_retention_slots_.resize(transport::required_rtx_retention_slots);
          rtx_retention_.emplace(std::span<transport::rtx_retained_packet> {rtx_retention_slots_});
          if (!rtx_retention_->valid()) {
            return;
          }
        }
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

    /** @brief Register negotiated bounded egress and start the packet worker. */
    bool start() noexcept {
      if (!ready_ || started_.exchange(true, std::memory_order_acq_rel)) {
        return false;
      }
      const auto queue_capacity = video_egress_capacity(config_);
      const auto maximum_queue_age = std::chrono::microseconds {
        config_.maximum_capture_to_present_microseconds
      };
      const auto registered = egress_.register_session(
        this,
        video::egress_queue_t::behavior_e::latency,
        {
          .capacity = queue_capacity,
          // Queueing remains opportunistic: the sender pops immediately. The
          // negotiated capture-relative deadline, rather than one refresh, is
          // the safety bound when one paced frame transiently spans intervals.
          .max_queue_age = std::max(maximum_queue_age, 1us),
        },
        [this](const video::egress_queue_t::recovery_request_t &request) {
          pressure_events_.fetch_add(1, std::memory_order_relaxed);
          forward_capacity_drops_.fetch_add(request.dropped_frames, std::memory_order_relaxed);
          if (config_.reference_invalidation) {
            if (!request_reference_invalidation(
                  request.first_frame,
                  request.last_frame,
                  InvalidationFailurePolicy::fail_closed
                )) {
              fail_forward_path();
            }
          } else {
            (void) mark_reference_dependency_broken(request.last_frame);
            fail_forward_path();
          }
        }
      );
      if (!registered) {
        started_.store(false, std::memory_order_release);
        return false;
      }
      registered_ = true;
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

    /**
     * @brief Apply authenticated decoder capacity and recovery evidence.
     *
     * @param status Generation-qualified client status.
     * @param now_microseconds Current monotonic receive time.
     * @return True when the status is structurally valid for this video generation.
     */
    bool receive_video_status(
      const transport::lspv_status &status,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (transport::validate_lspv_status(status) != transport::lspv_status_error::none ||
          status.video_generation != config_.video.video_generation) {
        return false;
      }
      VideoRecoveryFeedbackAction action;
      bool recovery_confirmed = false;
      bool decoder_failure_newly_latched = false;
      bool dependency_exhausted = false;
      {
        std::scoped_lock pending_lock(pending_mutex_);
        std::scoped_lock dependency_lock(dependency_state_mutex_);
        const auto before = recovery_.snapshot();
        const auto failure_latched_before = recovery_failure_latched_;
        action = apply_authenticated_lspv_recovery(
          recovery_,
          recovery_failure_latched_,
          status,
          latest_sent_frame_id_.load(std::memory_order_acquire),
          now_microseconds
        );
        recovery_confirmed = before.phase == transport::recovery_phase::recovery_frame_outstanding &&
                             recovery_.snapshot().phase == transport::recovery_phase::healthy;
        decoder_failure_newly_latched = !failure_latched_before && recovery_failure_latched_;
        if (action != VideoRecoveryFeedbackAction::ignored &&
            (action == VideoRecoveryFeedbackAction::request_independent_frame || decoder_failure_newly_latched) &&
            !mark_reference_dependency_broken_locked(std::nullopt)) {
          dependency_exhausted = true;
        }
        const auto decoder_error = status.decoder_status == transport::lspv_decoder_status::recoverable_error ||
                                   status.decoder_status == transport::lspv_decoder_status::unrecoverable_error;
        if (action != VideoRecoveryFeedbackAction::ignored && !dependency_exhausted && !decoder_error &&
            recovery_confirmed && !dependency_repair_pending_ && !invalidation_pending_locked()) {
          reference_path_valid_.store(true, std::memory_order_release);
        }
      }
      if (action == VideoRecoveryFeedbackAction::ignored) {
        return false;
      }
      if (dependency_exhausted) {
        fail_forward_path();
        return false;
      }
      update_decoder_credit(static_cast<std::uint8_t>(status.maximum_decode_submissions - status.decode_submissions_in_flight));
      if (action == VideoRecoveryFeedbackAction::request_independent_frame) {
        config_.capture_mail->event<bool>(mail::idr)->raise(true);
      }
      return true;
    }

    [[nodiscard]] std::optional<PathProbePayload> begin_path_probe(
      const std::uint64_t probe_id,
      const std::uint64_t now_microseconds,
      const std::uint64_t probe_interval_microseconds
    ) noexcept {
      std::scoped_lock lock(control_mutex_);
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
                                          probe_interval_microseconds :
                                          smoothed_rtt_microseconds_;
      // Spacing between probes only needs one RTT; the 15 s PROBE_TIMER governs retrying a lost
      // probe, not stepping up after a confirmed one, so search reaches the ceiling in seconds.
      const auto result = path_mtu_.start_probe(probe_id, now_microseconds, media_probe_interval);
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
      std::scoped_lock lock(control_mutex_);
      if (path_probe_.probe != probe || path_probe_.completion_pending) {
        return false;
      }
      return protect_and_submit_path_probe(now_microseconds, path_probe_.transmissions != 0);
    }

    bool acknowledge_path_probe(const PathProbePayload &probe) noexcept {
      std::scoped_lock lock(control_mutex_);
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
      BOOST_LOG(info) << "LSP DPLPMTUD confirmed " << probe.udp_payload_size << "-byte UDP payload (ceiling "
                      << path_mtu_.ceiling_payload_bytes() << ")";
      return true;
    }

    bool rollback_path_probe(const PathProbePayload &probe) noexcept {
      std::scoped_lock lock(control_mutex_);
      if (path_probe_.probe != probe || !path_mtu_before_probe_) {
        return false;
      }
      path_mtu_ = *path_mtu_before_probe_;
      path_mtu_before_probe_.reset();
      path_probe_ = {};
      next_path_raise_microseconds_.store(
        saturating_add_time(video_monotonic_microseconds(), path_raise_timer_microseconds),
        std::memory_order_release
      );
      return true;
    }

    bool reject_path_probe(const PathProbePayload &probe) noexcept {
      std::scoped_lock lock(control_mutex_);
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
      std::scoped_lock lock(control_mutex_);
      evaluate_path_black_hole(now_microseconds);
      if (local_candidate_failed_.exchange(false, std::memory_order_acq_rel)) {
        if (path_probe_.probe.probe_id == 0 ||
            path_mtu_.probe_timed_out() != transport::path_mtu_result::accepted) {
          return false;
        }
        BOOST_LOG(info) << "LSP DPLPMTUD " << path_probe_.probe.udp_payload_size
                        << "-byte probe exceeds the local interface MTU";
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
      if (path_probe_.completion_pending) {
        return true;
      }
      const auto media_probe_interval = smoothed_rtt_microseconds_ == 0 ?
                                          probe_interval_microseconds :
                                          smoothed_rtt_microseconds_;
      const auto timer = std::max(minimum_probe_timer_microseconds, media_probe_interval);
      if (path_probe_.last_transmission_microseconds == 0) {
        if (path_probe_.last_attempt_microseconds == 0 ||
            now_microseconds < path_probe_.last_attempt_microseconds ||
            now_microseconds - path_probe_.last_attempt_microseconds < timer) {
          return true;
        }
        return protect_and_submit_path_probe(now_microseconds, false);
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
      BOOST_LOG(info) << "LSP DPLPMTUD " << path_probe_.probe.udp_payload_size
                      << "-byte probe unacknowledged after " << static_cast<unsigned>(maximum_probe_attempts)
                      << " attempts";
      path_probe_ = {};
      path_mtu_before_probe_.reset();
      next_path_raise_microseconds_.store(
        saturating_add_time(now_microseconds, path_raise_timer_microseconds),
        std::memory_order_release
      );
      return true;
    }

    [[nodiscard]] std::optional<PathProbePayload> outstanding_path_probe() const noexcept {
      std::scoped_lock lock(control_mutex_);
      return path_probe_.probe.probe_id == 0 ? std::nullopt : std::optional {path_probe_.probe};
    }

    bool confirm_path_black_hole() noexcept {
      if (current_path_payload_.load(std::memory_order_acquire) <= 1'200) {
        return false;
      }
      requested_path_payload_.store(1'200, std::memory_order_release);
      black_hole_requested_.store(true, std::memory_order_release);
      next_path_raise_microseconds_.store(
        saturating_add_time(video_monotonic_microseconds(), path_raise_timer_microseconds),
        std::memory_order_release
      );
      return true;
    }

    bool receive_compound_rtcp(
      const std::span<const std::uint8_t> packet,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(control_mutex_);
      const auto authority = transport::validate_compound_rtcp_authority(packet, config_.feedback_sender_ssrc);
      if (!authority || now_microseconds < last_compound_rtcp_microseconds_ ||
          (feedback_cname_size_ != 0 &&
           (feedback_cname_size_ != authority.cname.size() ||
            !std::ranges::equal(std::span<const std::uint8_t> {feedback_cname_}.first(feedback_cname_size_), authority.cname)))) {
        return false;
      }

      std::uint32_t candidate_rtt = 0;
      const auto &report_packet = authority.first_report;
      const auto report_offset = report_packet.packet_type == transport::rtcp_sender_report_type ? 24U : 4U;
      for (std::size_t report = 0; report < report_packet.count; ++report) {
        const auto block = report_packet.payload.subspan(report_offset + report * 24U, 24U);
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
        if (receiver_delay < elapsed && elapsed - receiver_delay <= 10'000'000U) {
          candidate_rtt = static_cast<std::uint32_t>(elapsed - receiver_delay);
        }
      }

      if (feedback_cname_size_ == 0) {
        std::copy(authority.cname.begin(), authority.cname.end(), feedback_cname_.begin());
        feedback_cname_size_ = authority.cname.size();
      }
      if (candidate_rtt != 0) {
        if (smoothed_rtt_microseconds_ == 0) {
          smoothed_rtt_microseconds_ = candidate_rtt;
          rtt_variation_microseconds_ = candidate_rtt / 2U;
        } else {
          const auto difference = smoothed_rtt_microseconds_ > candidate_rtt ?
                                    smoothed_rtt_microseconds_ - candidate_rtt :
                                    candidate_rtt - smoothed_rtt_microseconds_;
          rtt_variation_microseconds_ = (rtt_variation_microseconds_ * 3U + difference) / 4U;
          smoothed_rtt_microseconds_ = (smoothed_rtt_microseconds_ * 7U + candidate_rtt) / 8U;
        }
        repair_rtt_microseconds_.store(smoothed_rtt_microseconds_, std::memory_order_release);
        small_path_delivery_evidence_.fetch_add(1, std::memory_order_relaxed);
        last_small_path_delivery_microseconds_.store(now_microseconds, std::memory_order_release);
      }
      last_compound_rtcp_microseconds_ = now_microseconds;
      has_compound_rtcp_ = true;
      return true;
    }

    bool receive_congestion_feedback(
      const std::span<const std::uint8_t> packet,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto feedback = parse_congestion_feedback_packet(packet, config_.feedback_sender_ssrc);
      return feedback && receive_congestion_feedback(*feedback, now_microseconds);
    }

    bool receive_congestion_feedback(
      const CongestionFeedbackPacketView &feedback,
      const std::uint64_t now_microseconds
    ) noexcept {
      return process_congestion_feedback(feedback, now_microseconds, true);
    }

    bool validate_congestion_feedback(
      const CongestionFeedbackPacketView &feedback,
      const std::uint64_t now_microseconds
    ) noexcept {
      return process_congestion_feedback(feedback, now_microseconds, false);
    }

    [[nodiscard]] std::optional<VideoCongestionFeedbackPreview> preview_congestion_feedback(
      const CongestionFeedbackPacketView &feedback,
      const std::uint64_t now_microseconds
    ) noexcept {
      return validate_congestion_feedback(feedback, now_microseconds) ?
               std::optional<VideoCongestionFeedbackPreview> {{feedback, now_microseconds}} :
               std::nullopt;
    }

    bool commit_congestion_feedback(const VideoCongestionFeedbackPreview &preview) noexcept {
      return receive_congestion_feedback(preview.packet, preview.now_microseconds);
    }

    /** @brief Validate, and optionally atomically commit, all video and repair feedback blocks. */
    bool process_congestion_feedback(
      const CongestionFeedbackPacketView &feedback,
      const std::uint64_t now_microseconds,
      const bool commit
    ) noexcept {
      std::scoped_lock lock(control_mutex_);
      const auto reject = [this, commit]() noexcept {
        if (commit) {
          feedback_rejections_.fetch_add(1, std::memory_order_relaxed);
        }
        return false;
      };
      if (!feedback || !has_compound_rtcp_ || now_microseconds < last_compound_rtcp_microseconds_ ||
          now_microseconds - last_compound_rtcp_microseconds_ > compound_rtcp_freshness_microseconds ||
          (has_feedback_receive_time_ &&
           (now_microseconds < last_feedback_receive_microseconds_ ||
            now_microseconds - last_feedback_receive_microseconds_ <
              transport::congestion_feedback_floor_microseconds))) {
        return reject();
      }

      const auto content = classify_congestion_feedback_content(
        feedback,
        config_.video.primary_ssrc,
        config_.audio_feedback_ssrc,
        config_.video.flexfec ? config_.video.flexfec->repair_ssrc : 0,
        config_.video.rtx ? config_.video.rtx->rtx_ssrc : 0
      );
      if (content == CongestionFeedbackContent::invalid) {
        return reject();
      }
      const auto report_timestamp = feedback.report_timestamp;
      if (has_feedback_timestamp_ && static_cast<std::int32_t>(report_timestamp - last_feedback_timestamp_) <= 0) {
        return reject();
      }
      if (content == CongestionFeedbackContent::audio_only) {
        if (!commit) {
          return true;
        }
        last_feedback_timestamp_ = report_timestamp;
        last_feedback_receive_microseconds_ = now_microseconds;
        has_feedback_timestamp_ = true;
        has_feedback_receive_time_ = true;
        feedback_reports_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }

      struct FeedbackLedgerBlock {
        const CongestionFeedbackBlockView *block {};  ///< Borrowed validated RFC 8888 block.
        SentPacketLedger *ledger {};  ///< Independently sequenced producer ledger.
        std::uint64_t first_serial {};  ///< First exact send incarnation in the block.
        std::uint64_t last_serial {};  ///< Last exact send incarnation in the block.
        std::size_t locked_records {};  ///< Leading records retained through transactional commit.
        bool primary {};  ///< Whether this block drives source-loss repair and delay trend.
      };

      std::array<FeedbackLedgerBlock, 3> ledger_blocks {};
      std::size_t ledger_block_count = 0;
      for (std::size_t block_index = 0; block_index < feedback.block_count; ++block_index) {
        const auto &block = feedback.blocks[block_index];
        SentPacketLedger *ledger = nullptr;
        bool primary = false;
        if (block.media_ssrc == config_.video.primary_ssrc) {
          ledger = &primary_ledger_;
          primary = true;
        } else if (config_.video.flexfec && block.media_ssrc == config_.video.flexfec->repair_ssrc) {
          ledger = &flexfec_ledger_;
        } else if (config_.video.rtx && block.media_ssrc == config_.video.rtx->rtx_ssrc) {
          ledger = &rtx_ledger_;
        } else if (block.media_ssrc == config_.audio_feedback_ssrc) {
          continue;
        } else {
          return reject();
        }
        if (ledger_block_count == ledger_blocks.size()) {
          return reject();
        }
        ledger_blocks[ledger_block_count++] = {
          .block = &block,
          .ledger = ledger,
          .primary = primary,
        };
      }

      const auto unlock_ledger_records = [&]() noexcept {
        for (std::size_t block_index = 0; block_index < ledger_block_count; ++block_index) {
          auto &ledger_block = ledger_blocks[block_index];
          for (std::size_t index = 0; index < ledger_block.locked_records; ++index) {
            const auto sequence = static_cast<std::uint16_t>(
              ledger_block.block->begin_sequence + index
            );
            ledger_block.ledger->records[sequence].access.clear(std::memory_order_release);
          }
          ledger_block.locked_records = 0;
        }
      };

      for (std::size_t block_index = 0; block_index < ledger_block_count; ++block_index) {
        auto &ledger_block = ledger_blocks[block_index];
        const auto &block = *ledger_block.block;
        const auto report_count = static_cast<std::size_t>(block.report_count);
        for (std::size_t index = 0; index < report_count; ++index) {
          const auto metric = wire::read_be<std::uint16_t>(block.metrics.subspan(index * 2U, 2));
          const auto received = (metric & 0x8000U) != 0;
          if (!received && (metric & 0x7fffU) != 0) {
            unlock_ledger_records();
            return reject();
          }
          const auto sequence = static_cast<std::uint16_t>(block.begin_sequence + index);
          auto &record = ledger_block.ledger->records[sequence];
          while (record.access.test_and_set(std::memory_order_acquire)) {
          }
          ++ledger_block.locked_records;
          const auto serial = record.send_serial.load(std::memory_order_acquire);
          const auto sent = record.sent_microseconds.load(std::memory_order_relaxed);
          const auto bytes = record.complete_ip_bytes.load(std::memory_order_relaxed);
          const auto udp_payload_bytes = record.udp_payload_bytes.load(std::memory_order_relaxed);
          const auto confirmed_path_payload_bytes =
            record.confirmed_path_payload_bytes.load(std::memory_order_relaxed);
          const auto record_path_generation = record.path_generation.load(std::memory_order_relaxed);
          const auto state = record.feedback_state.load(std::memory_order_relaxed);
          const auto local_unsent = state == feedback_local_unsent;
          const auto serial_confirmed = record.send_serial.load(std::memory_order_acquire);
          const auto actual_send_invalid =
            !local_unsent &&
            (bytes == 0 ||
             classify_path_packet_size(udp_payload_bytes, confirmed_path_payload_bytes) ==
               PathPacketSizeClass::invalid ||
             record_path_generation == 0);
          const auto tombstone_invalid = local_unsent && (received || bytes != 0);
          const auto invalid =
            serial == 0 || serial != serial_confirmed || actual_send_invalid || tombstone_invalid ||
            sent > now_microseconds || now_microseconds - sent > feedback_packet_freshness_microseconds ||
            (index != 0 && serial != ledger_block.first_serial + index) ||
            (!received && state == feedback_received);
          if (invalid) {
            unlock_ledger_records();
            return reject();
          }
          if (index == 0) {
            ledger_block.first_serial = serial;
          }
          ledger_block.last_serial = serial;
        }
        const auto highest_sent = ledger_block.ledger->last_serial.load(std::memory_order_acquire);
        if (report_count != 0 &&
            (ledger_block.last_serial > highest_sent ||
             (ledger_block.ledger->highest_feedback_serial != 0 &&
              ledger_block.last_serial + 16'384U < ledger_block.ledger->highest_feedback_serial))) {
          unlock_ledger_records();
          return reject();
        }
      }

      if (!commit) {
        unlock_ledger_records();
        return true;
      }

      const auto current_path_generation = path_generation_.load(std::memory_order_acquire);

      std::uint64_t delivered_bytes = 0;
      std::uint64_t lost_bytes = 0;
      std::uint64_t primary_delivered_bytes = 0;
      std::uint64_t primary_lost_bytes = 0;
      std::uint64_t ecn_ce_bytes = 0;
      std::uint64_t large_path_delivered = 0;
      std::uint64_t large_path_lost = 0;
      std::uint64_t small_path_delivered = 0;
      std::int32_t queue_delay_trend = 0;
      for (std::size_t block_index = 0; block_index < ledger_block_count; ++block_index) {
        auto &ledger_block = ledger_blocks[block_index];
        const auto &block = *ledger_block.block;
        const auto report_count = static_cast<std::size_t>(block.report_count);
        for (std::size_t index = 0; index < report_count; ++index) {
          const auto metric = wire::read_be<std::uint16_t>(block.metrics.subspan(index * 2U, 2));
          const auto received = (metric & 0x8000U) != 0;
          const auto ecn = static_cast<std::uint8_t>((metric >> 13U) & 0x03U);
          const auto sequence = static_cast<std::uint16_t>(block.begin_sequence + index);
          auto &record = ledger_block.ledger->records[sequence];
          const auto expected_serial = ledger_block.first_serial + index;
          if (record.send_serial.load(std::memory_order_acquire) != expected_serial) {
            unlock_ledger_records();
            return reject();
          }
          const auto state = record.feedback_state.load(std::memory_order_relaxed);
          if (state == feedback_local_unsent) {
            if (received || record.send_serial.load(std::memory_order_acquire) != expected_serial) {
              unlock_ledger_records();
              return reject();
            }
            continue;
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
          if (received) {
            const auto newly_received = state != feedback_received;
            if (newly_received) {
              record.feedback_state.store(feedback_received, std::memory_order_relaxed);
              delivered_bytes += bytes;
              ledger_block.ledger->delivered_bytes.fetch_add(bytes, std::memory_order_relaxed);
              if (ledger_block.primary) {
                primary_delivered_bytes += bytes;
              }
              if (current_path_evidence && path_size_class == PathPacketSizeClass::confirmed_size &&
                  confirmed_path_payload_bytes > 1'200) {
                ++large_path_delivered;
              } else if (current_path_evidence && path_size_class == PathPacketSizeClass::smaller) {
                ++small_path_delivered;
              }
              if (state == feedback_unreported) {
                subtract_in_flight(*ledger_block.ledger, bytes);
              } else if (state == feedback_lost) {
                subtract_counter(ledger_block.ledger->lost_bytes, bytes);
                subtract_counter(feedback_lost_bytes_, bytes);
                feedback_loss_corrections_.fetch_add(bytes, std::memory_order_relaxed);
              }
            }
            const auto prior_ecn = record.ecn_state.load(std::memory_order_relaxed);
            if (newly_received) {
              record.ecn_state.store(ecn, std::memory_order_relaxed);
              if (ecn == 3U) {
                ecn_ce_bytes += bytes;
                ledger_block.ledger->ecn_ce_bytes.fetch_add(bytes, std::memory_order_relaxed);
              }
            } else if (ecn == 3U && prior_ecn != 3U) {
              record.ecn_state.store(3U, std::memory_order_relaxed);
              ecn_ce_bytes += bytes;
              ledger_block.ledger->ecn_ce_bytes.fetch_add(bytes, std::memory_order_relaxed);
            }
            const auto ato = static_cast<std::uint16_t>(metric & 0x1fffU);
            const auto sent = record.sent_microseconds.load(std::memory_order_relaxed);
            if (ledger_block.primary && newly_received && ato <= 0x1ffdU &&
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
          } else if (state == feedback_unreported) {
            record.feedback_state.store(feedback_lost, std::memory_order_relaxed);
            lost_bytes += bytes;
            ledger_block.ledger->lost_bytes.fetch_add(bytes, std::memory_order_relaxed);
            if (ledger_block.primary) {
              primary_lost_bytes += bytes;
            }
            if (current_path_evidence && path_size_class == PathPacketSizeClass::confirmed_size &&
                confirmed_path_payload_bytes > 1'200) {
              ++large_path_lost;
            }
            subtract_in_flight(*ledger_block.ledger, bytes);
          }
          if (record.send_serial.load(std::memory_order_acquire) != expected_serial) {
            unlock_ledger_records();
            return reject();
          }
        }
        if (ledger_block.last_serial != 0) {
          ledger_block.ledger->highest_feedback_serial = std::max(
            ledger_block.ledger->highest_feedback_serial,
            ledger_block.last_serial
          );
        }
      }
      unlock_ledger_records();
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
      update_measured_forward_overhead(now_microseconds);
      const auto has_new_evidence = delivered_bytes != 0 || lost_bytes != 0 || ecn_ce_bytes != 0;
      if (config_.video.flexfec && primary_lost_bytes != 0) {
        const auto total_bytes = primary_delivered_bytes >
                                     std::numeric_limits<std::uint64_t>::max() - primary_lost_bytes ?
                                   std::numeric_limits<std::uint64_t>::max() :
                                   primary_delivered_bytes + primary_lost_bytes;
        const auto five_percent = total_bytes / 20U + (total_bytes % 20U != 0 ? 1U : 0U);
        const auto two_percent = total_bytes / 50U + (total_bytes % 50U != 0 ? 1U : 0U);
        const auto group_packets = total_bytes != 0 && primary_lost_bytes >= five_percent ?
                                     std::uint8_t {5} :
                                     (total_bytes != 0 && primary_lost_bytes >= two_percent ?
                                        std::uint8_t {8} :
                                        static_cast<std::uint8_t>(maximum_product_flexfec_group_packets));
        flexfec_group_packets_.store(group_packets, std::memory_order_release);
        flexfec_active_until_microseconds_.store(
          saturating_add_time(now_microseconds, flexfec_activation_microseconds),
          std::memory_order_release
        );
      }
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
        .report_microseconds = now_microseconds,
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

    /**
     * @brief Parse and apply authenticated Generic NACK, PLI, or FIR feedback.
     *
     * @param packet Complete plaintext RTCP feedback packet.
     * @param now_microseconds Current monotonic receive time.
     * @return True only when structure and negotiated associations are valid.
     */
    bool receive_repair_feedback(
      const std::span<const std::uint8_t> packet,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock control_lock(control_mutex_);
      const auto reject = [this]() noexcept {
        repair_feedback_rejections_.fetch_add(1, std::memory_order_relaxed);
        return false;
      };
      if (closed_.load(std::memory_order_acquire) || failed_.load(std::memory_order_acquire) ||
          !has_compound_rtcp_ || now_microseconds < last_compound_rtcp_microseconds_ ||
          now_microseconds - last_compound_rtcp_microseconds_ > compound_rtcp_freshness_microseconds) {
        return reject();
      }
      const auto parsed = transport::parse_rtcp_packet(packet);
      if (!parsed || parsed.packet.size() != packet.size()) {
        return reject();
      }

      if (parsed.packet_type == transport::rtcp_transport_feedback_type &&
          parsed.count == transport::rtcp_generic_nack_format) {
        if (!config_.video.rtx) {
          return reject();
        }
        transport::generic_nack<32> nack;
        if (transport::parse_generic_nack(parsed, nack) != transport::rtcp_feedback_parse_error::none ||
            nack.sender_ssrc != config_.feedback_sender_ssrc ||
            nack.media_ssrc != config_.video.primary_ssrc) {
          return reject();
        }
        std::array<std::uint16_t, 32U * 17U> sequences {};
        const auto expanded = transport::expand_generic_nack(nack, sequences);
        if (!expanded) {
          return reject();
        }
        for (std::size_t index = 0; index < expanded.sequence_count; ++index) {
          if (submit_rtx(sequences[index], now_microseconds) == RtxSubmitResult::fatal) {
            return reject();
          }
        }
        repair_feedback_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }

      if (parsed.packet_type == transport::rtcp_payload_feedback_type &&
          parsed.count == transport::rtcp_picture_loss_indication_format) {
        transport::picture_loss_indication pli;
        if (transport::parse_picture_loss_indication(parsed, pli) !=
              transport::rtcp_feedback_parse_error::none ||
            pli.sender_ssrc != config_.feedback_sender_ssrc ||
            pli.media_ssrc != config_.video.primary_ssrc ||
            !request_feedback_recovery()) {
          return reject();
        }
        repair_feedback_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }

      if (parsed.packet_type == transport::rtcp_payload_feedback_type &&
          parsed.count == transport::rtcp_full_intra_request_format) {
        transport::full_intra_request<4> fir;
        if (transport::parse_full_intra_request(parsed, fir) !=
              transport::rtcp_feedback_parse_error::none ||
            fir.sender_ssrc != config_.feedback_sender_ssrc || fir.entry_count != 1 ||
            fir.entries[0].media_sender_ssrc != config_.video.primary_ssrc) {
          return reject();
        }
        const auto &entry = fir.entries[0];
        if (video_fir_command_is_duplicate(
              has_fir_command_,
              last_fir_sender_ssrc_,
              last_fir_media_ssrc_,
              last_fir_command_sequence_,
              fir.sender_ssrc,
              entry.media_sender_ssrc,
              entry.sequence_number
            )) {
          repair_feedback_packets_.fetch_add(1, std::memory_order_relaxed);
          return true;
        }
        if (!request_feedback_recovery()) {
          return reject();
        }
        last_fir_sender_ssrc_ = fir.sender_ssrc;
        last_fir_media_ssrc_ = entry.media_sender_ssrc;
        last_fir_command_sequence_ = entry.sequence_number;
        has_fir_command_ = true;
        repair_feedback_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      return reject();
    }

    /** @brief Close admission and wake the packet worker. */
    void close() noexcept {
      if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
      }
      egress_.stop();
      pending_condition_.notify_all();
    }

    /** @brief Join sender and retire its egress registration. */
    void join() noexcept {
      if (worker_.joinable()) {
        worker_.join();
      }
      {
        std::unique_lock lock(pending_mutex_);
        pending_condition_.wait(lock, [this]() {
          return free_pending_datagram_count_ == pending_datagrams_.size() &&
                 free_pending_frame_count_ == pending_frames_.size() && active_completion_callbacks_ == 0;
        });
      }
      {
        std::scoped_lock repair_lock(repair_mutex_);
        if (rtx_retention_) {
          (void) rtx_retention_->clear([this](const std::uint64_t token) noexcept {
            release_retained_token_locked(token);
          });
        }
        for (auto &frame : retained_frames_) {
          frame.phase = RetainedAccessUnit::Phase::free;
          frame.rtx_handle = {};
          frame.retained_tokens = 0;
        }
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
        .decoder_saturated_drops = decoder_saturated_drops_.load(std::memory_order_relaxed),
        .deadline_miss_drops = deadline_miss_drops_.load(std::memory_order_relaxed),
        .invalid_reference_drops = invalid_reference_drops_.load(std::memory_order_relaxed),
        .forward_capacity_drops = forward_capacity_drops_.load(std::memory_order_relaxed),
        .submitted_wire_bytes = submitted_wire_bytes_.load(std::memory_order_relaxed),
        .flexfec_submitted_packets = flexfec_submitted_packets_.load(std::memory_order_relaxed),
        .flexfec_submitted_wire_bytes = flexfec_submitted_wire_bytes_.load(std::memory_order_relaxed),
        .flexfec_dropped_packets = flexfec_dropped_packets_.load(std::memory_order_relaxed),
        .rtx_submitted_packets = rtx_submitted_packets_.load(std::memory_order_relaxed),
        .rtx_submitted_wire_bytes = rtx_submitted_wire_bytes_.load(std::memory_order_relaxed),
        .rtx_dropped_packets = rtx_dropped_packets_.load(std::memory_order_relaxed),
        .repair_feedback_packets = repair_feedback_packets_.load(std::memory_order_relaxed),
        .repair_feedback_rejections = repair_feedback_rejections_.load(std::memory_order_relaxed),
        .primary_bytes_in_flight = primary_ledger_.bytes_in_flight.load(std::memory_order_relaxed),
        .primary_delivered_bytes = primary_ledger_.delivered_bytes.load(std::memory_order_relaxed),
        .primary_lost_bytes = primary_ledger_.lost_bytes.load(std::memory_order_relaxed),
        .primary_ecn_ce_bytes = primary_ledger_.ecn_ce_bytes.load(std::memory_order_relaxed),
        .flexfec_bytes_in_flight = flexfec_ledger_.bytes_in_flight.load(std::memory_order_relaxed),
        .flexfec_delivered_bytes = flexfec_ledger_.delivered_bytes.load(std::memory_order_relaxed),
        .flexfec_lost_bytes = flexfec_ledger_.lost_bytes.load(std::memory_order_relaxed),
        .flexfec_ecn_ce_bytes = flexfec_ledger_.ecn_ce_bytes.load(std::memory_order_relaxed),
        .rtx_bytes_in_flight = rtx_ledger_.bytes_in_flight.load(std::memory_order_relaxed),
        .rtx_delivered_bytes = rtx_ledger_.delivered_bytes.load(std::memory_order_relaxed),
        .rtx_lost_bytes = rtx_ledger_.lost_bytes.load(std::memory_order_relaxed),
        .rtx_ecn_ce_bytes = rtx_ledger_.ecn_ce_bytes.load(std::memory_order_relaxed),
        .pressure_events = pressure_events_.load(std::memory_order_relaxed),
        .decoder_credit = decoder_credit_.load(std::memory_order_relaxed),
        .current_path_payload = current_path_payload_.load(std::memory_order_relaxed),
        .pacing_bits_per_second = current_pacing_bits_per_second_.load(std::memory_order_relaxed),
        .encoder_bits_per_second = current_encoder_bits_per_second_.load(std::memory_order_relaxed),
        .feedback_reports = feedback_reports_.load(std::memory_order_relaxed),
        .feedback_rejections = feedback_rejections_.load(std::memory_order_relaxed),
        .feedback_delivered_bytes = feedback_delivered_bytes_.load(std::memory_order_relaxed),
        .feedback_lost_bytes = feedback_lost_bytes_.load(std::memory_order_relaxed),
        .feedback_loss_corrections = feedback_loss_corrections_.load(std::memory_order_relaxed),
        .path_probe_datagrams = path_probe_datagrams_.load(std::memory_order_relaxed),
        .path_probe_retries = path_probe_retries_.load(std::memory_order_relaxed),
        .flexfec_active = video_monotonic_microseconds() <
                          flexfec_active_until_microseconds_.load(std::memory_order_relaxed),
        .started = started_.load(std::memory_order_relaxed),
        .closed = closed_.load(std::memory_order_relaxed),
        .failed = failed_.load(std::memory_order_relaxed),
      };
    }

    bool complete_forward_datagram(
      const std::uint64_t token,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      const auto pending = take_pending(token, true);
      if (!pending) {
        return false;
      }
      const CallbackRetirement callback_retirement {
        .context = this,
        .retire = [](void *context) noexcept {
          static_cast<Impl *>(context)->retire_completion_callback();
        },
      };
      if (pending->kind == PendingKind::primary_rtp) {
        if (completion == HostForwardCompletion::sent) {
          record_sent_packet(
            primary_ledger_,
            pending->sequence,
            pending->packet_serial,
            charged_bytes,
            static_cast<std::uint16_t>(protected_bytes),
            pending->confirmed_path_payload,
            completed_at_microseconds
          );
          rtp_packet_count_.fetch_add(1, std::memory_order_relaxed);
          rtp_octet_count_.fetch_add(pending->payload_octets, std::memory_order_relaxed);
          submitted_packets_.fetch_add(1, std::memory_order_relaxed);
          submitted_wire_bytes_.fetch_add(charged_bytes, std::memory_order_relaxed);
          complete_pending_frame(pending->frame_ticket, true, completed_at_microseconds);
          return true;
        }
        record_unsent_packet(primary_ledger_, *pending, completed_at_microseconds);
        if (!mark_reference_dependency_broken(std::nullopt)) {
          fail_forward_path();
        }
        complete_pending_frame(pending->frame_ticket, false, completed_at_microseconds);
        pressure_events_.fetch_add(1, std::memory_order_relaxed);
        if (completion == HostForwardCompletion::message_too_large) {
          if (!confirm_path_black_hole()) {
            fail_forward_path();
          }
        } else if (completion == HostForwardCompletion::fatal) {
          fail_forward_path();
        }
        return true;
      }

      if (pending->kind == PendingKind::flexfec_rtp || pending->kind == PendingKind::rtx_rtp) {
        auto *ledger = ledger_for(pending->kind);
        if (ledger == nullptr) {
          fail_forward_path();
          return false;
        }
        auto &packets = pending->kind == PendingKind::flexfec_rtp ?
                          flexfec_submitted_packets_ :
                          rtx_submitted_packets_;
        auto &wire_bytes = pending->kind == PendingKind::flexfec_rtp ?
                             flexfec_submitted_wire_bytes_ :
                             rtx_submitted_wire_bytes_;
        auto &dropped = pending->kind == PendingKind::flexfec_rtp ?
                          flexfec_dropped_packets_ :
                          rtx_dropped_packets_;
        if (completion == HostForwardCompletion::sent) {
          record_sent_packet(
            *ledger,
            pending->sequence,
            pending->packet_serial,
            charged_bytes,
            static_cast<std::uint16_t>(protected_bytes),
            pending->confirmed_path_payload,
            completed_at_microseconds
          );
          packets.fetch_add(1, std::memory_order_relaxed);
          wire_bytes.fetch_add(charged_bytes, std::memory_order_relaxed);
        } else {
          record_unsent_packet(*ledger, *pending, completed_at_microseconds);
          dropped.fetch_add(1, std::memory_order_relaxed);
          if (completion == HostForwardCompletion::message_too_large) {
            (void) confirm_path_black_hole();
          } else if (completion == HostForwardCompletion::fatal) {
            fail_forward_path();
          }
        }
        return true;
      }

      std::scoped_lock lock(control_mutex_);
      if (pending->kind == PendingKind::sender_report) {
        sender_report_pending_ = false;
        if (completion == HostForwardCompletion::sent) {
          auto &timing = sender_report_timings_[next_sender_report_timing_];
          timing.lsr.store(0, std::memory_order_release);
          timing.sent_microseconds.store(completed_at_microseconds, std::memory_order_relaxed);
          timing.lsr.store(pending->lsr, std::memory_order_release);
          next_sender_report_timing_ = (next_sender_report_timing_ + 1U) % sender_report_timings_.size();
          last_sender_report_microseconds_ = completed_at_microseconds;
        } else if (completion == HostForwardCompletion::fatal) {
          fail_forward_path();
        }
        return true;
      }

      if (path_probe_.probe.probe_id == pending->probe_id) {
        path_probe_.completion_pending = false;
        if (completion == HostForwardCompletion::sent) {
          ++path_probe_.transmissions;
          path_probe_.last_transmission_microseconds = completed_at_microseconds;
          path_probe_datagrams_.fetch_add(1, std::memory_order_relaxed);
          if (pending->probe_timer_retry) {
            path_probe_retries_.fetch_add(1, std::memory_order_relaxed);
          }
        } else if (completion == HostForwardCompletion::message_too_large) {
          local_candidate_failed_.store(true, std::memory_order_release);
        } else if (completion == HostForwardCompletion::fatal) {
          fail_forward_path();
        }
      }
      return true;
    }

    void set_forward_backpressure(const bool blocked) noexcept {
      const auto prior = forward_backpressured_.exchange(blocked, std::memory_order_acq_rel);
      if (blocked && !prior) {
        pressure_events_.fetch_add(1, std::memory_order_relaxed);
      }
    }

    /** @brief Return constructor validation and slab-allocation status. */
    [[nodiscard]] bool ready() const noexcept {
      return ready_;
    }

  private:
    enum class PendingKind : std::uint8_t {
      primary_rtp,
      flexfec_rtp,
      rtx_rtp,
      sender_report,
      path_probe,
    };

    /** @brief Outcome of one sender-side RTX lookup, deadline gate, and submission. */
    enum class RtxSubmitResult : std::uint8_t {
      submitted,  ///< One freshly protected RTX packet was accepted by the aggregate path.
      ineligible,  ///< Retention, path size, timing, or capacity suppressed retransmission.
      fatal,  ///< Reconstruction or SRTP state was internally inconsistent.
    };

    /**
     * @brief Return the independent RFC 8888 ledger for one RTP producer kind.
     *
     * @param kind Primary, FlexFEC, or RTX RTP producer.
     * @return Matching ledger, or null for non-RTP control datagrams.
     */
    [[nodiscard]] SentPacketLedger *ledger_for(const PendingKind kind) noexcept {
      switch (kind) {
        case PendingKind::primary_rtp:
          return &primary_ledger_;
        case PendingKind::flexfec_rtp:
          return &flexfec_ledger_;
        case PendingKind::rtx_rtp:
          return &rtx_ledger_;
        case PendingKind::sender_report:
        case PendingKind::path_probe:
          return nullptr;
      }
      return nullptr;
    }

    struct PendingDatagram {
      std::uint64_t token {};  ///< Nonzero namespaced sender-local completion token.
      std::uint64_t incarnation {};  ///< Slot incarnation encoded into `token`.
      std::uint64_t frame_ticket {};  ///< Nonzero whole-frame completion owner for primary RTP.
      std::uint64_t packet_serial {};  ///< Sequence incarnation assigned before successful protection.
      std::uint64_t probe_id {};  ///< Logical LSPP identifier for probe completion.
      std::uint32_t payload_octets {};  ///< Codec bytes credited only after final send.
      std::uint32_t lsr {};  ///< Middle NTP bits retained for final-sent SR timing.
      std::uint16_t sequence {};  ///< Primary RTP sequence for exact sent-ledger publication.
      std::uint16_t confirmed_path_payload {};  ///< PMTU generation limit active at protection.
      PendingKind kind {PendingKind::primary_rtp};  ///< Producer type for terminal handling.
      bool probe_timer_retry {};  ///< Whether this LSPP is a fresh PROBE_TIMER retry.
    };

    struct PendingFrame {
      std::uint64_t ticket {};  ///< Nonzero frame completion incarnation.
      std::uint64_t incarnation {};  ///< Slot incarnation encoded into `ticket`.
      std::uint64_t frame_id {};  ///< Nonzero protocol frame identity used by recovery epochs.
      std::uint64_t terminal_microseconds {};  ///< Latest packet terminal time for recovery deadlines.
      std::size_t committed_packets {};  ///< Packets successfully admitted to the path.
      std::size_t completed_packets {};  ///< Terminal callbacks already received.
      std::int64_t frame_index {};  ///< Capture frame identity used for asynchronous recovery.
      std::uint64_t reference_invalidation_generation {};  ///< Encoder invalidation generation carried by this frame.
      std::uint64_t dependency_generation {};  ///< Local dependency-break generation captured at admission.
      std::uint64_t storage_incarnation {};  ///< Exact retained-AU storage reuse generation.
      std::size_t storage_index {};  ///< Fixed retained-AU storage slot used by packet reconstruction.
      bool commit_complete {};  ///< Producer finished admitting this frame.
      bool failed {};  ///< At least one packet did not reach the kernel.
      bool reference_damaged {};  ///< Protected/committed media can make following dependencies undecodable.
      bool independent {};  ///< IDR or post-invalidation frame may restore references.
      bool idr {};  ///< Whether the encoder declared a codec-independent IDR.
      bool recovery_reserved {};  ///< Frame exclusively owns the active recovery epoch before first commit.
      bool suppress_recovery {};  ///< Fatal non-primary transport failure forbids a repair-triggered epoch.
      bool producer_waiting {};  ///< Sender worker awaits the exact terminal disposition.
      bool terminal_ready {};  ///< Every committed primary packet reached terminal disposition.
    };

    /** @brief Action taken when one exact encoder invalidation request is rejected. */
    enum class InvalidationFailurePolicy : std::uint8_t {
      fail_closed,  ///< Queue/admission recovery cannot legitimately request an IDR.
      independent_recovery,  ///< An active recovery epoch permits one independent-frame fallback.
    };

    /** @brief One generation/range-qualified invalidation awaiting an encoder terminal result. */
    struct PendingInvalidation {
      video::reference_invalidation_request_t request {};  ///< Exact request written to the capture mailbox.
      std::uint64_t dependency_generation {};  ///< Logical dependency break satisfied by this request.
      InvalidationFailurePolicy failure_policy {InvalidationFailurePolicy::fail_closed};  ///< Rejection action.
      bool occupied {};  ///< Whether this fixed slot awaits a terminal result.
    };

    /** @brief Exact invalidation completion plus an atomically promoted queued request. */
    struct InvalidationCompletion {
      PendingInvalidation completed {};  ///< Matched request and its rejection policy.
      std::optional<video::reference_invalidation_request_t> promoted {};  ///< Next sole published request.
      bool promotion_failed {};  ///< Queued request could not receive a nonzero generation.
    };

    /** @brief Frame-boundary recovery epoch and independent-frame admission decision. */
    struct RecoveryBoundary {
      std::uint32_t epoch {};  ///< Nonzero recovery epoch encoded into every boundary extension.
      bool blocked {};  ///< Whether this encoded frame must not reach the network.
      bool request_independent_frame {};  ///< Whether an expired failed recovery needs a new encoder request.
    };

    /** @brief Result of reserving one independent frame for an active recovery epoch. */
    enum class RecoveryReservation : std::uint8_t {
      not_required,  ///< Healthy independent frame or dependent frame needs no recovery reservation.
      reserved,  ///< This frame now exclusively owns the active recovery attempt.
      rejected,  ///< Epoch changed or another independent recovery frame is outstanding.
    };

    /** @brief Exact whole-frame terminal outcome returned to the sender worker. */
    struct PendingFrameOutcome {
      std::uint64_t frame_id {};  ///< Protocol frame identifier.
      std::uint64_t storage_incarnation {};  ///< Retained-AU reuse generation.
      std::uint64_t terminal_microseconds {};  ///< Latest primary packet terminal time.
      std::size_t storage_index {};  ///< Fixed retained-AU storage slot.
      bool succeeded {};  ///< Whether every committed primary packet reached the kernel.
    };

    /** @brief Dispatch one exact path completion directly to its producer in O(1). */
    static void forward_completion_callback(
      void *context,
      const std::uint64_t token,
      const HostForwardLane lane,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      (void) lane;
      auto *self = static_cast<Impl *>(context);
      if (self != nullptr) {
        (void) self->complete_forward_datagram(
          token,
          completion,
          completed_at_microseconds,
          protected_bytes,
          charged_bytes
        );
      }
    }

    /** @brief Return the callback retained by every committed video-owned datagram. */
    [[nodiscard]] HostForwardCompletionTarget completion_target() noexcept {
      return {.context = this, .completed = forward_completion_callback};
    }

    /** @brief Reserve one indexed, incarnation-qualified asynchronous completion token. */
    [[nodiscard]] std::uint64_t register_pending(PendingDatagram pending) noexcept {
      std::scoped_lock lock(pending_mutex_);
      if (closed_.load(std::memory_order_acquire) || free_pending_datagram_count_ == 0) {
        return 0;
      }
      const auto index = free_pending_datagrams_[--free_pending_datagram_count_];
      auto &slot = pending_datagrams_[index];
      auto incarnation = (slot.incarnation + 1U) & pending_datagram_incarnation_mask;
      if (incarnation == 0) {
        incarnation = 1;
      }
      pending.incarnation = incarnation;
      if (auto *ledger = ledger_for(pending.kind)) {
        pending.packet_serial = ledger->next_serial.fetch_add(1, std::memory_order_relaxed);
        if (pending.packet_serial == 0) {
          pending.packet_serial = ledger->next_serial.fetch_add(1, std::memory_order_relaxed);
        }
      }
      pending.token = (std::uint64_t {2} << 60U) |
                      (incarnation << pending_datagram_index_bits) |
                      index;
      slot = pending;
      return pending.token;
    }

    /** @brief Register exact RTP sent-ledger metadata before consuming an SRTP index. */
    [[nodiscard]] std::uint64_t register_pending_rtp(
      const std::uint16_t sequence,
      const std::uint32_t payload_octets,
      const std::uint16_t confirmed_path_payload,
      const std::uint64_t frame_ticket
    ) noexcept {
      return register_pending({
        .frame_ticket = frame_ticket,
        .payload_octets = payload_octets,
        .sequence = sequence,
        .confirmed_path_payload = confirmed_path_payload,
        .kind = PendingKind::primary_rtp,
      });
    }

    /**
     * @brief Register one independent repair-stream completion token.
     *
     * @param kind FlexFEC or RTX producer kind.
     * @param sequence Repair-stream RTP sequence consumed by protection.
     * @param confirmed_path_payload Frame-boundary path payload active at protection.
     * @return Nonzero completion token, or zero when bounded metadata is unavailable.
     */
    [[nodiscard]] std::uint64_t register_pending_repair(
      const PendingKind kind,
      const std::uint16_t sequence,
      const std::uint16_t confirmed_path_payload
    ) noexcept {
      if (kind != PendingKind::flexfec_rtp && kind != PendingKind::rtx_rtp) {
        return 0;
      }
      return register_pending({
        .sequence = sequence,
        .confirmed_path_payload = confirmed_path_payload,
        .kind = kind,
      });
    }

    /**
     * @brief Reserve whole-frame completion state before committing its first packet.
     *
     * @param independent Whether the frame is independently decodable.
     * @param idr Whether the encoder declared an IDR.
     * @param frame_id Nonzero LSP frame identifier.
     * @param frame_index Encoder frame index used by dependency recovery.
     * @param reference_invalidation_generation Encoder invalidation generation carried by the frame.
     * @param dependency_generation Reserved dependency-break generation.
     * @param storage_index Fixed staging/current AU slot.
     * @param storage_incarnation Exact AU slot reuse generation.
     * @return Nonzero pending-frame ticket, or zero when bounded state is unavailable.
     */
    [[nodiscard]] std::uint64_t begin_pending_frame(
      const bool independent,
      const bool idr,
      const std::uint64_t frame_id,
      const std::int64_t frame_index,
      const std::uint64_t reference_invalidation_generation,
      const std::uint64_t dependency_generation,
      const std::size_t storage_index,
      const std::uint64_t storage_incarnation
    ) noexcept {
      std::scoped_lock lock(pending_mutex_);
      if (closed_.load(std::memory_order_acquire) || free_pending_frame_count_ == 0) {
        return 0;
      }
      const auto index = free_pending_frames_[--free_pending_frame_count_];
      auto &frame = pending_frames_[index];
      auto incarnation = (frame.incarnation + 1U) & pending_frame_incarnation_mask;
      if (incarnation == 0) {
        incarnation = 1;
      }
      const auto ticket = (incarnation << pending_frame_index_bits) | index;
      frame = {
        .ticket = ticket,
        .incarnation = incarnation,
        .frame_id = frame_id,
        .frame_index = frame_index,
        .reference_invalidation_generation = reference_invalidation_generation,
        .dependency_generation = dependency_generation,
        .storage_incarnation = storage_incarnation,
        .storage_index = storage_index,
        .independent = independent,
        .idr = idr,
      };
      last_reference_frame_ticket_ = ticket;
      return ticket;
    }

    /**
     * @brief Reserve the current dependency generation before first packet construction.
     *
     * @param independent Whether the frame bypasses dependent-reference validity.
     * @return Reserved nonzero generation, or no value when dependent admission is already stale.
     */
    [[nodiscard]] std::optional<std::uint64_t> reserve_dependency_generation(
      const bool independent
    ) noexcept {
      std::scoped_lock lock(dependency_state_mutex_);
      if (!video_dependency_reservation_valid(
            independent,
            dependency_break_generation_,
            dependency_break_generation_,
            reference_path_valid_.load(std::memory_order_acquire),
            dependency_repair_pending_
          )) {
        return std::nullopt;
      }
      return dependency_break_generation_;
    }

    /**
     * @brief Resolve retry timing and freeze the epoch used by one encoded frame.
     *
     * @param independent Whether the encoder declares this frame independent.
     * @param now_microseconds Current monotonic frame-boundary time.
     * @return Frozen epoch plus retry and admission decisions.
     */
    [[nodiscard]] RecoveryBoundary prepare_recovery_boundary(
      const bool independent,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(pending_mutex_);
      auto snapshot = recovery_.snapshot();
      bool request_independent_frame = false;
      if (snapshot.phase == transport::recovery_phase::recovery_frame_outstanding &&
          recovery_failure_latched_ && now_microseconds >= snapshot.recovery_deadline_microseconds &&
          recovery_.permit_retry(now_microseconds, true) == transport::recovery_result::accepted) {
        recovery_failure_latched_ = false;
        request_independent_frame = true;
        snapshot = recovery_.snapshot();
      }
      return {
        .epoch = snapshot.epoch,
        .blocked = independent && snapshot.phase == transport::recovery_phase::recovery_frame_outstanding,
        .request_independent_frame = request_independent_frame,
      };
    }

    /**
     * @brief Reserve the sole recovery frame before its first RTP packet is committed.
     *
     * @param ticket Live pending-frame ticket.
     * @param independent Whether the frame is independently decodable.
     * @param recovery_epoch Epoch already encoded into the frame extensions.
     * @param now_microseconds Current monotonic admission time.
     * @param deadline_microseconds Strict recovery-frame deadline.
     * @return Whether no reservation was needed, it succeeded, or the frame must be rejected.
     */
    [[nodiscard]] RecoveryReservation reserve_recovery_frame(
      const std::uint64_t ticket,
      const bool independent,
      const std::uint32_t recovery_epoch,
      const std::uint64_t now_microseconds,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      std::scoped_lock lock(pending_mutex_);
      auto *frame = pending_frame_for_ticket(ticket);
      const auto snapshot = recovery_.snapshot();
      if (frame == nullptr || snapshot.epoch != recovery_epoch) {
        return RecoveryReservation::rejected;
      }
      if (!independent || snapshot.phase == transport::recovery_phase::healthy) {
        return RecoveryReservation::not_required;
      }
      if (snapshot.phase == transport::recovery_phase::recovery_frame_outstanding ||
          recovery_.mark_independent_frame_sent(
            frame->frame_id,
            now_microseconds,
            deadline_microseconds
          ) != transport::recovery_result::accepted) {
        return RecoveryReservation::rejected;
      }
      frame->recovery_reserved = true;
      recovery_failure_latched_ = false;
      return RecoveryReservation::reserved;
    }

    /** @brief Fence one dependent admission on its predecessor's terminal disposition. */
    [[nodiscard]] bool wait_for_reference_terminal(
      const bool independent,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      if (independent) {
        return true;
      }
      std::unique_lock lock(pending_mutex_);
      while (last_reference_frame_ticket_ != 0 && !closed_.load(std::memory_order_acquire)) {
        const auto now = video_monotonic_microseconds();
        if (now >= deadline_microseconds) {
          return false;
        }
        pending_condition_.wait_for(lock, std::chrono::microseconds {deadline_microseconds - now});
      }
      return last_reference_frame_ticket_ == 0 &&
             reference_path_valid_.load(std::memory_order_acquire) &&
             video_monotonic_microseconds() < deadline_microseconds;
    }

    /**
     * @brief Wait until a frame's committed source prefix reaches terminal socket disposition.
     *
     * @param frame_ticket Live whole-frame completion ticket.
     * @param expected_packets Number of committed leading source packets that must complete.
     * @param deadline_microseconds Strict absolute repair deadline.
     * @return True only when the entire prefix reached the kernel successfully before the deadline.
     */
    [[nodiscard]] bool wait_for_source_prefix_terminal(
      const std::uint64_t frame_ticket,
      const std::size_t expected_packets,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      std::unique_lock lock(pending_mutex_);
      while (!closed_.load(std::memory_order_acquire)) {
        const auto *frame = pending_frame_for_ticket(frame_ticket);
        if (frame == nullptr) {
          return false;
        }
        if (frame->failed) {
          return false;
        }
        if (frame->completed_packets >= expected_packets) {
          return true;
        }
        const auto now = video_monotonic_microseconds();
        if (now >= deadline_microseconds) {
          return false;
        }
        pending_condition_.wait_for(lock, std::chrono::microseconds {deadline_microseconds - now});
      }
      return false;
    }

    /**
     * @brief Construct, protect, and schedule one sealed frame-local FlexFEC group.
     *
     * @param group Incremental plaintext parity group.
     * @param frame_ticket Live source-frame completion ticket.
     * @param committed_source_packets Number of source packets covered through this group.
     * @param rtp_timestamp Source-frame 90 kHz RTP timestamp.
     * @param deadline_microseconds Strict source-frame repair deadline.
     * @return True after successful submission or an optional deadline/capacity drop; false on fatal state corruption.
     */
    [[nodiscard]] bool submit_flexfec_group(
      transport::flexfec_group &group,
      const std::uint64_t frame_ticket,
      const std::size_t committed_source_packets,
      const std::uint32_t rtp_timestamp,
      const std::uint64_t deadline_microseconds
    ) noexcept {
      transport::flexfec_parity_view parity;
      if (group.seal_plaintext_repair(parity) != transport::flexfec_result::accepted) {
        return false;
      }
      if (!wait_for_source_prefix_terminal(frame_ticket, committed_source_packets, deadline_microseconds)) {
        flexfec_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      auto lease = config_.forward_path->acquire(HostForwardLane::recovery);
      if (!lease) {
        flexfec_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      const auto written = transport::write_flexfec_repair(
        parity,
        {
          .payload_type = config_.video.flexfec->repair_payload_type,
          .sequence_number = next_flexfec_sequence_,
          .timestamp = rtp_timestamp,
        },
        lease->storage
      );
      if (!written ||
          group.mark_repair_plaintext_constructed() != transport::flexfec_result::accepted) {
        return false;
      }
      const auto token = register_pending_repair(
        PendingKind::flexfec_rtp,
        next_flexfec_sequence_,
        current_path_payload_.load(std::memory_order_acquire)
      );
      if (token == 0) {
        flexfec_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtp,
            lease->storage,
            written.bytes_written,
            protected_bytes
          ) ||
          protected_bytes == 0 ||
          group.mark_repair_protected() != transport::flexfec_result::accepted) {
        (void) take_pending(token, false);
        return false;
      }
      ++next_flexfec_sequence_;
      if (config_.forward_path->commit(
            *lease,
            protected_bytes,
            deadline_microseconds,
            token,
            completion_target()
          ) != HostForwardSubmitResult::accepted) {
        if (const auto pending = take_pending(token, false)) {
          record_unsent_packet(flexfec_ledger_, *pending, video_monotonic_microseconds());
        }
        flexfec_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
      }
      return true;
    }

    /**
     * @brief Release one Photon reconstruction token while holding `repair_mutex_`.
     *
     * @param token Exact nonzero storage-incarnation/packet token.
     */
    void release_retained_token_locked(const std::uint64_t token) noexcept {
      const auto identity = parse_retained_token(token);
      if (!identity || identity->storage_index >= retained_frames_.size()) {
        fail_forward_path();
        return;
      }
      auto &frame = retained_frames_[identity->storage_index];
      if (frame.incarnation != identity->storage_incarnation || frame.retained_tokens == 0) {
        fail_forward_path();
        return;
      }
      --frame.retained_tokens;
      if (frame.retained_tokens == 0 && frame.phase == RetainedAccessUnit::Phase::committed) {
        frame.phase = RetainedAccessUnit::Phase::free;
      }
    }

    /**
     * @brief Select one token-free AU slot as the next staging owner.
     *
     * @return True when a free slot became the sole staging owner.
     */
    [[nodiscard]] bool select_staging_frame_locked() noexcept {
      for (std::size_t index = 0; index < retained_frames_.size(); ++index) {
        auto &frame = retained_frames_[index];
        if (frame.phase == RetainedAccessUnit::Phase::free && frame.retained_tokens == 0) {
          frame.phase = RetainedAccessUnit::Phase::staging;
          staging_frame_index_ = index;
          return true;
        }
      }
      return false;
    }

    /**
     * @brief Abort one exact current/building AU generation and select replacement staging storage.
     *
     * @param storage_index Fixed AU storage slot.
     * @param storage_incarnation Exact slot reuse generation.
     */
    void abort_retained_frame(
      const std::size_t storage_index,
      const std::uint64_t storage_incarnation
    ) noexcept {
      if (storage_index >= retained_frames_.size()) {
        return;
      }
      std::scoped_lock repair_lock(repair_mutex_);
      auto &frame = retained_frames_[storage_index];
      if (frame.incarnation != storage_incarnation) {
        return;
      }
      if (frame.phase == RetainedAccessUnit::Phase::building && rtx_retention_) {
        const auto aborted = rtx_retention_->abort_frame(
          frame.rtx_handle,
          [this](const std::uint64_t token) noexcept {
            release_retained_token_locked(token);
          }
        );
        if (!aborted) {
          fail_forward_path();
        }
      }
      if (frame.phase == RetainedAccessUnit::Phase::current ||
          frame.phase == RetainedAccessUnit::Phase::building) {
        frame.phase = RetainedAccessUnit::Phase::free;
        frame.rtx_handle = {};
        frame.rtx_disabled = true;
      }
      if (retained_frames_[staging_frame_index_].phase != RetainedAccessUnit::Phase::staging &&
          !select_staging_frame_locked()) {
        fail_forward_path();
      }
    }

    /**
     * @brief Commit or retire the current RTX transaction after exact primary terminal success.
     *
     * @param outcome Successful pending-frame storage and terminal identity.
     * @return True after retention commit or an optional expired/no-RTT retirement.
     */
    [[nodiscard]] bool commit_retained_frame(const PendingFrameOutcome &outcome) noexcept {
      if (outcome.storage_index >= retained_frames_.size()) {
        return false;
      }
      std::scoped_lock repair_lock(repair_mutex_);
      auto &frame = retained_frames_[outcome.storage_index];
      if (frame.incarnation != outcome.storage_incarnation || frame.frame_id != outcome.frame_id) {
        return false;
      }
      if (frame.phase == RetainedAccessUnit::Phase::building && rtx_retention_) {
        const auto committed = rtx_retention_->commit_frame(
          frame.rtx_handle,
          outcome.terminal_microseconds
        );
        if (committed == transport::rtx_frame_result::accepted) {
          frame.phase = RetainedAccessUnit::Phase::committed;
        } else {
          const auto aborted = rtx_retention_->abort_frame(
            frame.rtx_handle,
            [this](const std::uint64_t token) noexcept {
              release_retained_token_locked(token);
            }
          );
          if (!aborted) {
            return false;
          }
          frame.phase = RetainedAccessUnit::Phase::free;
          frame.rtx_handle = {};
        }
      } else if (frame.phase == RetainedAccessUnit::Phase::current) {
        frame.phase = RetainedAccessUnit::Phase::free;
      } else {
        return false;
      }
      if (!select_staging_frame_locked()) {
        return false;
      }
      return true;
    }

    /**
     * @brief Retain one O(1)-indexed source reconstruction plan after primary path admission.
     *
     * @param frame_slot Current AU storage slot.
     * @param packet_index Packet-plan index within the frame.
     * @param source_sequence Original primary RTP sequence.
     * @param source_packet_bytes Complete plaintext source RTP byte count.
     * @param now_microseconds Current monotonic path-admission time.
     */
    void retain_rtx_source(
      const std::size_t frame_slot,
      const std::size_t packet_index,
      const std::uint16_t source_sequence,
      const std::size_t source_packet_bytes,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto measured_rtt = repair_rtt_microseconds_.load(std::memory_order_acquire);
      if (!config_.video.rtx || !rtx_retention_ || frame_slot >= retained_frames_.size() ||
          packet_index >= media::maximum_fragments_per_frame) {
        return;
      }
      std::scoped_lock repair_lock(repair_mutex_);
      auto &frame = retained_frames_[frame_slot];
      if (frame.rtx_disabled || packet_index >= frame.plan_count) {
        return;
      }
      if (!video_rtx_frame_allowed(
            config_.network_profile,
            config_.competition_delta_rtx,
            frame.independent
          )) {
        frame.rtx_disabled = true;
        return;
      }
      if (measured_rtt == 0) {
        frame.rtx_disabled = true;
        return;
      }
      if (frame.phase == RetainedAccessUnit::Phase::current) {
        if (packet_index != 0) {
          return;
        }
        const auto begun = rtx_retention_->begin_frame(
          {
            .frame_id = frame.frame_id,
            .frame_deadline_microseconds = frame.deadline_microseconds,
            .now_microseconds = now_microseconds,
            .retention_origin_microseconds = now_microseconds,
            .measured_rtt_microseconds = measured_rtt,
            .source_ssrc = config_.video.primary_ssrc,
            .video_generation = config_.video.video_generation,
          },
          [this](const std::uint64_t token) noexcept {
            release_retained_token_locked(token);
          }
        );
        if (!begun) {
          if (begun.status == transport::rtx_frame_result::expired ||
              begun.status == transport::rtx_frame_result::invalid_rtt) {
            frame.rtx_disabled = true;
            return;
          }
          fail_forward_path();
          frame.rtx_disabled = true;
          return;
        }
        frame.rtx_handle = begun.handle;
        frame.phase = RetainedAccessUnit::Phase::building;
      }
      if (frame.phase != RetainedAccessUnit::Phase::building) {
        return;
      }
      const auto token = make_retained_token(frame_slot, frame.incarnation, packet_index);
      if (token == 0) {
        fail_forward_path();
        return;
      }
      const auto retained = rtx_retention_->retain(
        frame.rtx_handle,
        {
          .reconstruction_token = token,
          .source_sequence_number = source_sequence,
          .source_packet_bytes = source_packet_bytes,
        }
      );
      if (retained == transport::rtx_retention_result::retained) {
        ++frame.retained_tokens;
        return;
      }
      if (retained == transport::rtx_retention_result::byte_capacity_exceeded) {
        const auto aborted = rtx_retention_->abort_frame(
          frame.rtx_handle,
          [this](const std::uint64_t released_token) noexcept {
            release_retained_token_locked(released_token);
          }
        );
        if (!aborted) {
          fail_forward_path();
        }
        frame.phase = RetainedAccessUnit::Phase::current;
        frame.rtx_handle = {};
        frame.rtx_disabled = true;
        return;
      }
      (void) rtx_retention_->abort_frame(
        frame.rtx_handle,
        [this](const std::uint64_t released_token) noexcept {
          release_retained_token_locked(released_token);
        }
      );
      frame.phase = RetainedAccessUnit::Phase::current;
      frame.rtx_handle = {};
      fail_forward_path();
      frame.rtx_disabled = true;
    }

    /**
     * @brief Reconstruct and submit one NACKed source packet after the strict sender deadline gate.
     *
     * @param source_sequence Original primary RTP sequence named by Generic NACK.
     * @param feedback_receive_microseconds Authenticated feedback receive time.
     * @return Submitted, deadline/capacity ineligible, or fatal reconstruction state.
     */
    [[nodiscard]] RtxSubmitResult submit_rtx(
      const std::uint16_t source_sequence,
      const std::uint64_t feedback_receive_microseconds
    ) noexcept {
      if (!config_.video.rtx || !rtx_retention_) {
        return RtxSubmitResult::ineligible;
      }
      std::scoped_lock repair_lock(repair_mutex_);
      const auto measured_rtt = repair_rtt_microseconds_.load(std::memory_order_acquire);
      const auto pacing_rate = current_pacing_bits_per_second_.load(std::memory_order_acquire);
      const auto current_path_payload = current_path_payload_.load(std::memory_order_acquire);
      if (measured_rtt == 0 || pacing_rate == 0) {
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }
      const auto maximum_wire_bytes = static_cast<std::uint64_t>(current_path_payload) + ip_udp_overhead();
      const auto maximum_serialization_microseconds =
        (maximum_wire_bytes * 8'000'000U + pacing_rate - 1U) / pacing_rate;
      const transport::rtx_deadline_estimate estimate {
        .reverse_feedback_microseconds = measured_rtt / 2U,
        .retransmission_serialization_microseconds = maximum_serialization_microseconds,
        .forward_delivery_microseconds = measured_rtt - measured_rtt / 2U,
        .decode_safety_reserve_microseconds = rtx_decode_safety_microseconds,
      };
      const auto now_microseconds = std::max(feedback_receive_microseconds, video_monotonic_microseconds());
      const auto eligible = rtx_retention_->find_eligible(
        config_.video.video_generation,
        config_.video.primary_ssrc,
        source_sequence,
        now_microseconds,
        estimate
      );
      if (!eligible) {
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }
      const auto identity = parse_retained_token(eligible->reconstruction_token);
      if (!identity || identity->storage_index >= retained_frames_.size()) {
        fail_forward_path();
        return RtxSubmitResult::fatal;
      }
      auto *source_frame = &retained_frames_[identity->storage_index];
      const auto source_packet_index = identity->packet_index;
      if (source_frame->phase != RetainedAccessUnit::Phase::committed ||
          source_frame->incarnation != identity->storage_incarnation ||
          source_frame->frame_id != eligible->frame_id || source_packet_index >= source_frame->plan_count ||
          static_cast<std::uint16_t>(source_frame->first_sequence + source_packet_index) != source_sequence) {
        fail_forward_path();
        return RtxSubmitResult::fatal;
      }
      if (!video_rtx_frame_allowed(
            config_.network_profile,
            config_.competition_delta_rtx,
            source_frame->independent
          )) {
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }

      std::array<std::span<const std::uint8_t>, maximum_nal_units_per_access_unit> unit_storage {};
      if (!retained_unit_views(*source_frame, unit_storage)) {
        fail_forward_path();
        return RtxSubmitResult::fatal;
      }
      const auto units = std::span<const std::span<const std::uint8_t>> {unit_storage}.first(
        source_frame->unit_count
      );
      const auto role = media::packet_role(source_packet_index, source_frame->plan_count);
      const auto extension = source_frame->extensions.views().for_role(role);
      const auto &plan = source_frame->plans[source_packet_index];
      const auto plaintext_bytes = rtp_fixed_header_size + extension.size() + 2U + plan.payload_bytes;
      if (plaintext_bytes + sender_srtp_tag_bytes > current_path_payload) {
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }
      auto lease = config_.forward_path->acquire(HostForwardLane::recovery);
      if (!lease) {
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }
      const rtp_fixed_header rtp {
        .padding = false,
        .extension = !extension.empty(),
        .marker = source_packet_index + 1U == source_frame->plan_count,
        .payload_type = config_.video.rtx->rtx_payload_type,
        .csrc_count = 0,
        .sequence_number = next_rtx_sequence_,
        .timestamp = source_frame->rtp_timestamp,
        .ssrc = config_.video.rtx->rtx_ssrc,
      };
      const auto header = write_rtp_fixed_header(rtp, {}, lease->storage);
      if (!header || header.bytes_written != rtp_fixed_header_size) {
        fail_forward_path();
        return RtxSubmitResult::fatal;
      }
      std::copy(
        extension.begin(),
        extension.end(),
        lease->storage.begin() + static_cast<std::ptrdiff_t>(rtp_fixed_header_size)
      );
      auto payload = lease->storage.subspan(
        rtp_fixed_header_size + extension.size(),
        2U + plan.payload_bytes
      );
      wire::write_be<std::uint16_t>(payload.first<2>(), source_sequence);
      if (!write_codec_payload(config_.video.codec, plan, units, payload.subspan(2))) {
        fail_forward_path();
        return RtxSubmitResult::fatal;
      }
      const auto token = register_pending_repair(
        PendingKind::rtx_rtp,
        next_rtx_sequence_,
        current_path_payload
      );
      if (token == 0) {
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtp,
            lease->storage,
            plaintext_bytes,
            protected_bytes
          ) ||
          protected_bytes == 0) {
        (void) take_pending(token, false);
        fail_forward_path();
        return RtxSubmitResult::fatal;
      }
      ++next_rtx_sequence_;
      if (config_.forward_path->commit(
            *lease,
            protected_bytes,
            source_frame->deadline_microseconds,
            token,
            completion_target()
          ) != HostForwardSubmitResult::accepted) {
        if (const auto pending = take_pending(token, false)) {
          record_unsent_packet(rtx_ledger_, *pending, video_monotonic_microseconds());
        }
        rtx_dropped_packets_.fetch_add(1, std::memory_order_relaxed);
        return RtxSubmitResult::ineligible;
      }
      (void) rtx_retention_->erase(
        config_.video.video_generation,
        config_.video.primary_ssrc,
        source_sequence,
        [this](const std::uint64_t released_token) noexcept {
          release_retained_token_locked(released_token);
        }
      );
      return RtxSubmitResult::submitted;
    }

    /**
     * @brief Coalesce authenticated PLI/FIR into one generation-fenced recovery epoch.
     *
     * @return True after accepting or coalescing the request; false on exhausted recovery state.
     */
    [[nodiscard]] bool request_feedback_recovery() noexcept {
      bool request_independent = false;
      bool exhausted = false;
      {
        std::scoped_lock pending_lock(pending_mutex_);
        std::scoped_lock dependency_lock(dependency_state_mutex_);
        const auto damaged_frame = latest_sent_frame_id_.load(std::memory_order_acquire);
        if (damaged_frame == 0) {
          return true;
        }
        const auto result = recovery_.report_unrecoverable_damage(
          damaged_frame,
          transport::recovery_cause::decoder_unrecoverable
        );
        if (result == transport::recovery_result::accepted) {
          exhausted = !mark_reference_dependency_broken_locked(std::nullopt).has_value();
        } else if (result == transport::recovery_result::epoch_exhausted ||
                   result == transport::recovery_result::invalid_frame) {
          exhausted = true;
        }
        const auto recovery = recovery_.snapshot();
        if (!exhausted &&
            (recovery.phase == transport::recovery_phase::repairing_references ||
             recovery.phase == transport::recovery_phase::retry_permitted) &&
            last_feedback_independent_request_epoch_ != recovery.epoch) {
          last_feedback_independent_request_epoch_ = recovery.epoch;
          request_independent = true;
        }
      }
      if (exhausted) {
        fail_forward_path();
        return false;
      }
      if (request_independent) {
        config_.capture_mail->event<bool>(mail::idr)->raise(true);
      }
      return true;
    }

    /** @brief Resolve one exact live frame ticket through its encoded slot and incarnation. */
    [[nodiscard]] PendingFrame *pending_frame_for_ticket(const std::uint64_t ticket) noexcept {
      const auto index = static_cast<std::size_t>(ticket & pending_frame_index_mask);
      const auto incarnation = ticket >> pending_frame_index_bits;
      if (ticket == 0 || index >= pending_frames_.size()) {
        return nullptr;
      }
      auto &frame = pending_frames_[index];
      return frame.ticket == ticket && frame.incarnation == incarnation ? &frame : nullptr;
    }

    /** @brief Count one packet accepted by the aggregate path for a pending frame. */
    void mark_frame_packet_committed(const std::uint64_t ticket) noexcept {
      std::scoped_lock lock(pending_mutex_);
      if (auto *frame = pending_frame_for_ticket(ticket)) {
        ++frame->committed_packets;
      }
    }

    /** @brief Publish that the producer admitted all possible packets for one frame. */
    void finish_pending_frame(
      const std::uint64_t ticket,
      const bool producer_succeeded
    ) noexcept {
      std::optional<std::pair<std::size_t, std::uint64_t>> abort_storage;
      {
        std::scoped_lock lock(pending_mutex_);
        if (auto *frame = pending_frame_for_ticket(ticket)) {
          frame->commit_complete = true;
          frame->failed = frame->failed || !producer_succeeded;
          frame->reference_damaged = frame->reference_damaged ||
                                     (!producer_succeeded &&
                                      video_frame_is_partial_network_submission(frame->committed_packets));
          if (!producer_succeeded) {
            abort_storage = std::pair {frame->storage_index, frame->storage_incarnation};
          }
          finalize_pending_frame(*frame);
        }
      }
      if (abort_storage) {
        abort_retained_frame(abort_storage->first, abort_storage->second);
      }
      pending_condition_.notify_all();
    }

    /**
     * @brief Publish producer completion and await exact terminal primary disposition.
     *
     * @param ticket Live whole-frame completion ticket.
     * @return Terminal frame/storage identity and success, or no value after invalidation.
     */
    [[nodiscard]] std::optional<PendingFrameOutcome> finish_and_wait_pending_frame(
      const std::uint64_t ticket
    ) noexcept {
      std::unique_lock lock(pending_mutex_);
      auto *frame = pending_frame_for_ticket(ticket);
      if (frame == nullptr) {
        return std::nullopt;
      }
      frame->producer_waiting = true;
      frame->commit_complete = true;
      finalize_pending_frame(*frame);
      pending_condition_.wait(lock, [this, ticket]() {
        const auto *current = pending_frame_for_ticket(ticket);
        return current == nullptr || current->terminal_ready;
      });
      frame = pending_frame_for_ticket(ticket);
      if (frame == nullptr || !frame->terminal_ready) {
        return std::nullopt;
      }
      const PendingFrameOutcome outcome {
        .frame_id = frame->frame_id,
        .storage_incarnation = frame->storage_incarnation,
        .terminal_microseconds = frame->terminal_microseconds,
        .storage_index = frame->storage_index,
        .succeeded = !frame->failed,
      };
      release_pending_frame_locked(*frame);
      return outcome;
    }

    /**
     * @brief Terminate a frame after fatal repair plumbing without opening a media recovery epoch.
     *
     * @param ticket Live whole-frame completion ticket.
     */
    void abort_pending_frame_after_repair_failure(const std::uint64_t ticket) noexcept {
      std::optional<std::pair<std::size_t, std::uint64_t>> abort_storage;
      {
        std::scoped_lock lock(pending_mutex_);
        if (auto *frame = pending_frame_for_ticket(ticket)) {
          frame->commit_complete = true;
          frame->failed = true;
          frame->suppress_recovery = true;
          abort_storage = std::pair {frame->storage_index, frame->storage_incarnation};
          finalize_pending_frame(*frame);
        }
      }
      if (abort_storage) {
        abort_retained_frame(abort_storage->first, abort_storage->second);
      }
    }

    /** @brief Fold one packet terminal disposition into whole-frame completion state. */
    void complete_pending_frame(
      const std::uint64_t ticket,
      const bool sent,
      const std::uint64_t completed_at_microseconds
    ) noexcept {
      std::optional<std::pair<std::size_t, std::uint64_t>> abort_storage;
      {
        std::scoped_lock lock(pending_mutex_);
        if (auto *frame = pending_frame_for_ticket(ticket)) {
          ++frame->completed_packets;
          frame->failed = frame->failed || !sent;
          frame->reference_damaged = frame->reference_damaged || !sent;
          frame->terminal_microseconds = std::max(frame->terminal_microseconds, completed_at_microseconds);
          if (!sent) {
            abort_storage = std::pair {frame->storage_index, frame->storage_incarnation};
          }
          finalize_pending_frame(*frame);
        }
      }
      if (abort_storage) {
        abort_retained_frame(abort_storage->first, abort_storage->second);
      }
      pending_condition_.notify_all();
    }

    /** @brief Publish sent-frame counters or recovery after every terminal callback arrives. */
    void finalize_pending_frame(PendingFrame &frame) noexcept {
      if (frame.terminal_ready || !frame.commit_complete ||
          frame.completed_packets != frame.committed_packets) {
        return;
      }
      if (!frame.failed) {
        submitted_frames_.fetch_add(1, std::memory_order_relaxed);
        latest_sent_frame_id_.store(frame.frame_id, std::memory_order_release);
        if (frame.independent) {
          std::scoped_lock dependency_lock(dependency_state_mutex_);
          const auto satisfies_dependency = video_independent_satisfies_dependency_fence(
            frame.idr,
            frame.reference_invalidation_generation,
            latest_published_invalidation_generation_,
            latest_published_dependency_generation_,
            frame.dependency_generation,
            dependency_break_generation_,
            frame.frame_index,
            dependency_frame_fence_
          );
          if (satisfies_dependency && !invalidation_pending_locked()) {
            dependency_repair_pending_ = false;
            reference_path_valid_.store(true, std::memory_order_release);
            pre_submit_invalidation_pending_ = false;
            pre_submit_invalidation_frame_ = 0;
          }
        }
      } else {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        std::optional<std::uint64_t> dependency_generation;
        bool recovery_opened = false;
        if (!frame.suppress_recovery && (frame.recovery_reserved || frame.reference_damaged)) {
          std::scoped_lock dependency_lock(dependency_state_mutex_);
          dependency_generation = mark_reference_dependency_broken_locked(frame.frame_index);
          if (frame.recovery_reserved) {
            recovery_failure_latched_ = true;
          }
          if (frame.reference_damaged) {
            recovery_opened = recovery_.report_unrecoverable_damage(
                                frame.frame_id,
                                transport::recovery_cause::unexpected_partial_frame
                              ) == transport::recovery_result::accepted;
          }
        }
        if (!frame.suppress_recovery && !dependency_generation &&
            (frame.recovery_reserved || frame.reference_damaged)) {
          fail_forward_path();
        } else if (recovery_opened) {
          if (config_.reference_invalidation) {
            if (!request_reference_invalidation(
                  frame.frame_index,
                  frame.frame_index,
                  InvalidationFailurePolicy::independent_recovery,
                  dependency_generation
                )) {
              config_.capture_mail->event<bool>(mail::idr)->raise(true);
            }
          } else {
            config_.capture_mail->event<bool>(mail::idr)->raise(true);
          }
        }
      }
      frame.terminal_ready = true;
      if (!frame.producer_waiting) {
        release_pending_frame_locked(frame);
      }
      pending_condition_.notify_all();
    }

    /**
     * @brief Return one terminal pending-frame slot to its O(1) free list.
     *
     * @param frame Terminal frame owned by the caller-held pending mutex.
     */
    void release_pending_frame_locked(PendingFrame &frame) noexcept {
      const auto index = static_cast<std::size_t>(frame.ticket & pending_frame_index_mask);
      const auto incarnation = frame.incarnation;
      if (last_reference_frame_ticket_ == frame.ticket) {
        last_reference_frame_ticket_ = 0;
      }
      frame = {};
      frame.incarnation = incarnation;
      free_pending_frames_[free_pending_frame_count_++] = static_cast<std::uint8_t>(index);
      pending_condition_.notify_all();
    }

    /**
     * @brief Consume sender-local metadata for one exact completion token.
     *
     * @param token Incarnation-qualified sender token.
     * @param claim_callback Whether a live aggregate callback now retains the sender.
     * @return Removed metadata, or no value for an unknown/stale token.
     */
    [[nodiscard]] std::optional<PendingDatagram> take_pending(
      const std::uint64_t token,
      const bool claim_callback
    ) noexcept {
      if ((token >> 60U) != 2U) {
        return std::nullopt;
      }
      std::scoped_lock lock(pending_mutex_);
      const auto index = static_cast<std::size_t>(token & pending_datagram_index_mask);
      const auto incarnation = (token >> pending_datagram_index_bits) & pending_datagram_incarnation_mask;
      if (index >= pending_datagrams_.size()) {
        return std::nullopt;
      }
      auto &pending = pending_datagrams_[index];
      if (pending.token != token || pending.incarnation != incarnation) {
        return std::nullopt;
      }
      const auto result = pending;
      pending = {};
      pending.incarnation = incarnation;
      free_pending_datagrams_[free_pending_datagram_count_++] = static_cast<std::uint8_t>(index);
      if (claim_callback) {
        ++active_completion_callbacks_;
      }
      return result;
    }

    /** @brief End one claimed direct callback after its final sender access. */
    void retire_completion_callback() noexcept {
      {
        std::scoped_lock lock(pending_mutex_);
        if (active_completion_callbacks_ != 0) {
          --active_completion_callbacks_;
        }
      }
      pending_condition_.notify_all();
    }

    /** @brief Stop video after a fatal aggregate-path terminal disposition. */
    void fail_forward_path() noexcept {
      if (!failed_.exchange(true, std::memory_order_acq_rel)) {
        closed_.store(true, std::memory_order_release);
        egress_.stop();
        pending_condition_.notify_all();
        config_.capture_mail->event<bool>(mail::shutdown)->raise(true);
      }
    }

    /** @brief Return complete IP plus UDP header bytes for this path. */
    [[nodiscard]] std::size_t ip_udp_overhead() const noexcept {
      return config_.family == media::ip_family::ipv4 ? 28U : 48U;
    }

    /** @brief Feed measured non-video aggregate wire rate into encoder headroom. */
    void update_measured_forward_overhead(const std::uint64_t now_microseconds) noexcept {
      constexpr std::uint64_t sample_interval_microseconds = 100'000;
      const auto path_bytes = config_.forward_path->snapshot().sent_charged_bytes;
      const auto video_bytes = submitted_wire_bytes_.load(std::memory_order_relaxed);
      if (last_overhead_sample_microseconds_ == 0 || now_microseconds < last_overhead_sample_microseconds_) {
        last_overhead_sample_microseconds_ = now_microseconds;
        last_path_charged_bytes_ = path_bytes;
        last_video_charged_bytes_ = video_bytes;
        return;
      }
      const auto elapsed = now_microseconds - last_overhead_sample_microseconds_;
      if (elapsed < sample_interval_microseconds) {
        return;
      }
      const auto path_delta = path_bytes >= last_path_charged_bytes_ ? path_bytes - last_path_charged_bytes_ : 0;
      const auto video_delta = video_bytes >= last_video_charged_bytes_ ? video_bytes - last_video_charged_bytes_ : 0;
      const auto overhead_bytes = path_delta > video_delta ? path_delta - video_delta : 0;
      const auto measured = overhead_bytes > std::numeric_limits<std::uint64_t>::max() / 8'000'000U ?
                              std::numeric_limits<std::uint64_t>::max() :
                              overhead_bytes * 8'000'000U / elapsed;
      const auto bounded_measured = std::min(
        measured,
        config_.aggregate_pacing_bits_per_second > 1U ? config_.aggregate_pacing_bits_per_second - 1U : 0U
      );
      smoothed_forward_overhead_bits_per_second_ = smoothed_forward_overhead_bits_per_second_ == 0 ? bounded_measured :
                                                                                                     (smoothed_forward_overhead_bits_per_second_ * 3U + bounded_measured) / 4U;
      const auto reserved = std::max(config_.reserved_overhead_bits_per_second, smoothed_forward_overhead_bits_per_second_);
      (void) congestion_.update_reserved_overhead(reserved);
      last_overhead_sample_microseconds_ = now_microseconds;
      last_path_charged_bytes_ = path_bytes;
      last_video_charged_bytes_ = video_bytes;
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
    void subtract_in_flight(
      SentPacketLedger &ledger,
      const std::uint64_t bytes
    ) noexcept {
      auto stream_current = ledger.bytes_in_flight.load(std::memory_order_relaxed);
      while (!ledger.bytes_in_flight.compare_exchange_weak(
        stream_current,
        stream_current > bytes ? stream_current - bytes : 0,
        std::memory_order_relaxed
      )) {
      }
      auto current = bytes_in_flight_.load(std::memory_order_relaxed);
      while (!bytes_in_flight_.compare_exchange_weak(
        current,
        current > bytes ? current - bytes : 0,
        std::memory_order_relaxed,
        std::memory_order_relaxed
      )) {
      }
    }

    /** @brief Publish the greatest protected RTP sequence incarnation without regressing on callback order. */
    void publish_last_send_serial(
      SentPacketLedger &ledger,
      const std::uint64_t serial
    ) noexcept {
      auto current = ledger.last_serial.load(std::memory_order_relaxed);
      while (current < serial && !ledger.last_serial.compare_exchange_weak(
                                   current,
                                   serial,
                                   std::memory_order_release,
                                   std::memory_order_relaxed
                                 )) {
      }
    }

    /** @brief Replace one sequence slot while retiring any prior unreported actual send. */
    void replace_packet_record(
      SentPacketLedger &ledger,
      const std::uint16_t sequence,
      const std::uint64_t serial,
      const std::uint32_t complete_ip_bytes,
      const std::uint16_t udp_payload_bytes,
      const std::uint16_t confirmed_path_payload_bytes,
      const std::uint64_t completed_microseconds,
      const std::uint8_t feedback_state
    ) noexcept {
      auto &record = ledger.records[sequence];
      while (record.access.test_and_set(std::memory_order_acquire)) {
      }
      if (record.send_serial.load(std::memory_order_acquire) != 0 &&
          record.feedback_state.load(std::memory_order_relaxed) == feedback_unreported) {
        subtract_in_flight(ledger, record.complete_ip_bytes.load(std::memory_order_relaxed));
      }
      record.send_serial.store(0, std::memory_order_release);
      record.sent_microseconds.store(completed_microseconds, std::memory_order_relaxed);
      record.complete_ip_bytes.store(complete_ip_bytes, std::memory_order_relaxed);
      record.udp_payload_bytes.store(udp_payload_bytes, std::memory_order_relaxed);
      record.confirmed_path_payload_bytes.store(confirmed_path_payload_bytes, std::memory_order_relaxed);
      record.path_generation.store(
        feedback_state == feedback_local_unsent ? 0U : path_generation_.load(std::memory_order_relaxed),
        std::memory_order_relaxed
      );
      record.feedback_state.store(feedback_state, std::memory_order_relaxed);
      record.ecn_state.store(0, std::memory_order_relaxed);
      publish_last_send_serial(ledger, serial);
      if (feedback_state == feedback_unreported) {
        ledger.bytes_in_flight.fetch_add(complete_ip_bytes, std::memory_order_relaxed);
        bytes_in_flight_.fetch_add(complete_ip_bytes, std::memory_order_relaxed);
      }
      record.send_serial.store(serial, std::memory_order_release);
      record.access.clear(std::memory_order_release);
    }

    /** @brief Publish one successful final socket submission into the bounded sequence ledger. */
    void record_sent_packet(
      SentPacketLedger &ledger,
      const std::uint16_t sequence,
      const std::uint64_t serial,
      const std::uint32_t complete_ip_bytes,
      const std::uint16_t udp_payload_bytes,
      const std::uint16_t confirmed_path_payload_bytes,
      const std::uint64_t sent_microseconds
    ) noexcept {
      replace_packet_record(
        ledger,
        sequence,
        serial,
        complete_ip_bytes,
        udp_payload_bytes,
        confirmed_path_payload_bytes,
        sent_microseconds,
        feedback_unreported
      );
      if (confirmed_path_payload_bytes > 1'200 &&
          classify_path_packet_size(udp_payload_bytes, confirmed_path_payload_bytes) ==
            PathPacketSizeClass::confirmed_size) {
        large_path_sent_packets_.fetch_add(1, std::memory_order_relaxed);
      }
    }

    /** @brief Publish one protected but never transmitted RTP sequence for CCFB range continuity. */
    void record_unsent_packet(
      SentPacketLedger &ledger,
      const PendingDatagram &pending,
      const std::uint64_t completed_microseconds
    ) noexcept {
      replace_packet_record(
        ledger,
        pending.sequence,
        pending.packet_serial,
        0,
        0,
        0,
        completed_microseconds,
        feedback_local_unsent
      );
    }

    /** @brief Reconfigure the aggregate path and publish other targets at a frame boundary. */
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
          path_payload != config_.forward_path->snapshot().path_payload_bytes) {
        if (!config_.forward_path->reconfigure(pacing, path_payload)) {
          return false;
        }
        current_pacing_bits_per_second_.store(pacing, std::memory_order_release);
      }
      return true;
    }

    /** @brief Freshly protect and commit one exact candidate into the path-probe reserve. */
    [[nodiscard]] bool protect_and_submit_path_probe(
      const std::uint64_t now_microseconds,
      const bool probe_timer_retry
    ) noexcept {
      if (path_probe_.probe.probe_id == 0 || path_probe_.completion_pending) {
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
      auto lease = config_.forward_path->acquire(HostForwardLane::path_probe);
      if (!lease || path_probe_.probe.udp_payload_size > lease->storage.size()) {
        return false;
      }
      auto packet = lease->storage.first(path_probe_.probe.udp_payload_size);
      std::ranges::fill(packet, 0);
      packet[0] = 0x80U;
      packet[1] = transport::rtcp_app_type;
      wire::write_be<std::uint16_t>(packet.subspan<2, 2>(), static_cast<std::uint16_t>(plaintext_bytes / 4U - 1U));
      wire::write_be<std::uint32_t>(packet.subspan<4, 4>(), config_.video.primary_ssrc);
      std::ranges::copy(lspp_name, packet.begin() + 8);
      packet[12] = wire_version;
      packet[13] = 0;
      wire::write_be<std::uint16_t>(packet.subspan<14, 2>(), path_probe_.probe.udp_payload_size);
      wire::write_be<std::uint64_t>(packet.subspan<16, 8>(), path_probe_.probe.probe_id);

      const auto token = register_pending({
        .probe_id = path_probe_.probe.probe_id,
        .kind = PendingKind::path_probe,
        .probe_timer_retry = probe_timer_retry,
      });
      if (token == 0) {
        return false;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtcp,
            packet,
            plaintext_bytes,
            protected_bytes
          ) ||
          protected_bytes != path_probe_.probe.udp_payload_size) {
        (void) take_pending(token, false);
        return false;
      }
      const auto deadline = saturating_add_time(now_microseconds, minimum_probe_timer_microseconds);
      path_probe_.completion_pending = true;
      if (config_.forward_path->commit(*lease, protected_bytes, deadline, token, completion_target()) !=
          HostForwardSubmitResult::accepted) {
        path_probe_.completion_pending = false;
        (void) take_pending(token, false);
        return false;
      }
      path_probe_.last_attempt_microseconds = now_microseconds;
      return true;
    }

    /** @brief Submit a periodic video SR and retain its LSR timing for authenticated RR RTT. */
    void maybe_send_sender_report(
      const std::uint32_t rtp_timestamp,
      const std::uint64_t now_microseconds
    ) noexcept {
      std::scoped_lock lock(control_mutex_);
      if (last_sender_report_microseconds_ != 0 &&
          (now_microseconds < last_sender_report_microseconds_ ||
           now_microseconds - last_sender_report_microseconds_ < video_sender_report_interval_microseconds)) {
        return;
      }
      if (sender_report_pending_) {
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
        .packet_count = rtp_packet_count_.load(std::memory_order_relaxed),
        .octet_count = rtp_octet_count_.load(std::memory_order_relaxed),
      };
      auto lease = config_.forward_path->acquire(HostForwardLane::periodic);
      if (!lease) {
        return;
      }
      const auto written = transport::write_sender_report(report, lease->storage);
      if (!written) {
        return;
      }
      const auto sdes_bytes = transport::write_sdes_cname(
        config_.video.primary_ssrc,
        config_.rtcp_cname.view(),
        lease->storage.subspan(written.bytes_written)
      );
      if (sdes_bytes == 0) {
        return;
      }
      const auto compound_bytes = written.bytes_written + sdes_bytes;
      const auto token = register_pending({
        .lsr = static_cast<std::uint32_t>(ntp >> 16U),
        .kind = PendingKind::sender_report,
      });
      if (token == 0) {
        return;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtcp,
            lease->storage,
            compound_bytes,
            protected_bytes
          )) {
        (void) take_pending(token, false);
        return;
      }
      const auto deadline = saturating_add_time(now_microseconds, 20'000U);
      sender_report_pending_ = true;
      if (config_.forward_path->commit(*lease, protected_bytes, deadline, token, completion_target()) !=
          HostForwardSubmitResult::accepted) {
        sender_report_pending_ = false;
        (void) take_pending(token, false);
        return;
      }
    }

    /** @brief Retire consumed RTP sequence values without changing reference state a second time. */
    [[nodiscard]] bool retire_consumed_sequences(const std::size_t consumed_packets) noexcept {
      next_sequence_ = static_cast<std::uint16_t>(next_sequence_ + consumed_packets);
      pressure_events_.fetch_add(1, std::memory_order_relaxed);
      return true;
    }

    /**
     * @brief Publish a monotonic local dependency break before any recovery side effect.
     *
     * @param frame_fence Damaged/dropped encoder frame index, or no value for remote decoder evidence.
     * @return New nonzero dependency generation, or no value on exhaustion.
     */
    [[nodiscard]] std::optional<std::uint64_t> mark_reference_dependency_broken_locked(
      const std::optional<std::int64_t> frame_fence
    ) noexcept {
      if (dependency_break_generation_ == std::numeric_limits<std::uint64_t>::max()) {
        return std::nullopt;
      }
      ++dependency_break_generation_;
      if (frame_fence) {
        dependency_frame_fence_ = std::max(dependency_frame_fence_, *frame_fence);
      }
      dependency_repair_pending_ = true;
      reference_path_valid_.store(false, std::memory_order_release);
      return dependency_break_generation_;
    }

    /** @brief Publish a dependency break under the common dependency-state lock. */
    [[nodiscard]] std::optional<std::uint64_t> mark_reference_dependency_broken(
      const std::optional<std::int64_t> frame_fence
    ) noexcept {
      std::scoped_lock lock(dependency_state_mutex_);
      return mark_reference_dependency_broken_locked(frame_fence);
    }

    /** @brief Return whether an exact or coalesced invalidation awaits completion; lock required. */
    [[nodiscard]] bool invalidation_pending_locked() const noexcept {
      return active_invalidation_.occupied || queued_invalidation_.occupied;
    }

    /**
     * @brief Publish one bounded generation/range-qualified encoder invalidation request.
     *
     * @param first_frame First inclusive encoder frame index.
     * @param last_frame Last inclusive encoder frame index.
     * @param failure_policy Permitted action if the encoder rejects this exact request.
     * @param existing_dependency_generation Already-published atomic recovery break, if any.
     * @param pre_submit Whether this request fences a locally dropped pre-submit frame.
     * @return True after the sole active request was raised or the next range was safely coalesced.
     */
    [[nodiscard]] bool request_reference_invalidation(
      const std::int64_t first_frame,
      const std::int64_t last_frame,
      const InvalidationFailurePolicy failure_policy,
      const std::optional<std::uint64_t> existing_dependency_generation = std::nullopt,
      const bool pre_submit = false
    ) noexcept {
      if (!invalidation_request_events_ || first_frame > last_frame) {
        return false;
      }
      video::reference_invalidation_request_t request;
      {
        std::scoped_lock lock(dependency_state_mutex_);
        if (existing_dependency_generation &&
            (*existing_dependency_generation == 0 || *existing_dependency_generation > dependency_break_generation_)) {
          return false;
        }
        const auto dependency_generation = existing_dependency_generation ?
                                             existing_dependency_generation :
                                             mark_reference_dependency_broken_locked(last_frame);
        if (!dependency_generation) {
          return false;
        }
        const auto bound_dependency_generation = bind_video_invalidation_dependency_generation(
          *dependency_generation,
          dependency_break_generation_,
          latest_published_dependency_generation_
        );
        if (pre_submit) {
          pre_submit_invalidation_pending_ = true;
          pre_submit_invalidation_frame_ = last_frame;
        }
        if (active_invalidation_.occupied) {
          if (!queued_invalidation_.occupied) {
            queued_invalidation_ = {
              .request = {
                .first_frame = first_frame,
                .last_frame = last_frame,
              },
              .dependency_generation = bound_dependency_generation,
              .failure_policy = failure_policy,
              .occupied = true,
            };
          } else {
            if (!video::coalesce_reference_invalidation_range(
                  queued_invalidation_.request,
                  first_frame,
                  last_frame
                )) {
              return false;
            }
            if (failure_policy == InvalidationFailurePolicy::fail_closed) {
              queued_invalidation_.failure_policy = InvalidationFailurePolicy::fail_closed;
            }
            queued_invalidation_.dependency_generation = std::max(
              queued_invalidation_.dependency_generation,
              bound_dependency_generation
            );
          }
          return true;
        }
        if (next_invalidation_generation_ == 0) {
          return false;
        }
        request = {
          .generation = next_invalidation_generation_++,
          .first_frame = first_frame,
          .last_frame = last_frame,
        };
        active_invalidation_ = {
          .request = request,
          .dependency_generation = bound_dependency_generation,
          .failure_policy = failure_policy,
          .occupied = true,
        };
        latest_published_invalidation_generation_ = request.generation;
        latest_published_dependency_generation_ = std::max(
          latest_published_dependency_generation_,
          bound_dependency_generation
        );
      }
      invalidation_request_events_->raise(request);
      return true;
    }

    /**
     * @brief Consume the exact pending invalidation named by one encoder terminal result.
     *
     * @param result Generation and inclusive range echoed by the encoder.
     * @return Matched policy and any atomically promoted next request, or no value when stale.
     */
    [[nodiscard]] std::optional<InvalidationCompletion> take_invalidation_result(
      const video::reference_invalidation_result_t &result
    ) noexcept {
      std::scoped_lock lock(dependency_state_mutex_);
      if (!active_invalidation_.occupied ||
          !video::reference_invalidation_result_matches(active_invalidation_.request, result)) {
        return std::nullopt;
      }
      InvalidationCompletion completion {
        .completed = active_invalidation_,
      };
      active_invalidation_ = {};
      if (!result.succeeded) {
        queued_invalidation_ = {};
        return completion;
      }
      if (queued_invalidation_.occupied) {
        if (next_invalidation_generation_ == 0) {
          queued_invalidation_ = {};
          completion.promotion_failed = true;
          return completion;
        }
        queued_invalidation_.request.generation = next_invalidation_generation_++;
        queued_invalidation_.dependency_generation = bind_video_invalidation_dependency_generation(
          queued_invalidation_.dependency_generation,
          dependency_break_generation_,
          latest_published_dependency_generation_
        );
        active_invalidation_ = queued_invalidation_;
        completion.promoted = active_invalidation_.request;
        latest_published_invalidation_generation_ = active_invalidation_.request.generation;
        latest_published_dependency_generation_ = std::max(
          latest_published_dependency_generation_,
          active_invalidation_.dependency_generation
        );
        queued_invalidation_ = {};
      }
      return completion;
    }

    /**
     * @brief Invalidate one encoded frame that reached no aggregate-path commit.
     *
     * @param packet Unsent encoded frame whose future reference use is forbidden.
     * @return True after exact invalidation was queued; false after fail-closed teardown.
     */
    [[nodiscard]] bool invalidate_uncommitted_frame_dependency(video::packet_raw_t &packet) noexcept {
      const auto frame_index = packet.frame_index();
      if (!config_.reference_invalidation) {
        {
          std::scoped_lock lock(dependency_state_mutex_);
          pre_submit_invalidation_pending_ = true;
          pre_submit_invalidation_frame_ = frame_index;
          (void) mark_reference_dependency_broken_locked(frame_index);
        }
        fail_forward_path();
        return false;
      }
      if (!request_reference_invalidation(
            frame_index,
            frame_index,
            InvalidationFailurePolicy::fail_closed,
            std::nullopt,
            true
          )) {
        fail_forward_path();
        return false;
      }
      return true;
    }

    /** @brief Coarse mutually exclusive reason for rejecting one whole frame before submission. */
    enum class FrameAdmissionDropReason : std::uint8_t {
      other,  ///< Failure is outside the production admission categories.
      decoder_saturated,  ///< Authenticated client hardware-decoder credit is zero.
      deadline_miss,  ///< The deadline elapsed or complete serialization cannot finish in time.
      invalid_reference,  ///< Dependency or recovery state rejects this encoded frame.
      forward_capacity,  ///< Aggregate forward-path capacity or backpressure rejects the frame.
    };

    /** @brief Exact sender stage at which a frame exhausted its capture-relative deadline. */
    enum class FrameDeadlineMissStage : std::uint8_t {
      reference_wait,  ///< The preceding reference frame did not become terminal in time.
      coarse_admission_expired,  ///< Capture-relative deadline elapsed before size admission.
      coarse_serialization,  ///< Codec plus selected-repair bytes exceeded remaining pacing time.
      exact_serialization,  ///< Complete IP/UDP/SRTP bytes exceeded remaining pacing time.
      packet_submission,  ///< Packet construction reached the deadline after admission.
    };

    /** @brief Return a stable secret-free label for one deadline diagnostic stage. */
    [[nodiscard]] static constexpr const char *deadline_stage_name(
      const FrameDeadlineMissStage stage
    ) noexcept {
      switch (stage) {
        case FrameDeadlineMissStage::reference_wait:
          return "reference-wait";
        case FrameDeadlineMissStage::coarse_admission_expired:
          return "coarse-expired";
        case FrameDeadlineMissStage::coarse_serialization:
          return "coarse-serialization";
        case FrameDeadlineMissStage::exact_serialization:
          return "exact-wire-serialization";
        case FrameDeadlineMissStage::packet_submission:
          return "packet-submission";
      }
      return "unknown";
    }

    /**
     * @brief Rate-limit one exact capture-relative deadline diagnostic.
     *
     * @param stage Admission or submission stage that exhausted the deadline.
     * @param packet Encoded frame carrying host capture and encoder timestamps.
     * @param queue_age Time retained by the bounded encoder-egress queue.
     * @param capture_microseconds Monotonic capture timestamp used by admission.
     * @param now_microseconds Monotonic deadline observation time.
     * @param deadline_microseconds Absolute negotiated frame deadline.
     * @param source_bytes Encoded access-unit bytes before RTP framing.
     * @param complete_wire_bytes Exact complete IP-layer bytes when already known.
     * @param selected_repair_bytes Selected repair bytes included by admission.
     * @param packet_count Planned primary RTP packet count.
     * @param serialization_microseconds Serialization estimate for this stage.
     * @param pacing_bits_per_second Aggregate pacing rate used by admission.
     */
    void log_deadline_miss(
      const FrameDeadlineMissStage stage,
      video::packet_raw_t &packet,
      const std::chrono::nanoseconds queue_age,
      const std::uint64_t capture_microseconds,
      const std::uint64_t now_microseconds,
      const std::uint64_t deadline_microseconds,
      const std::size_t source_bytes,
      const std::uint64_t complete_wire_bytes,
      const std::size_t selected_repair_bytes,
      const std::size_t packet_count,
      const std::uint64_t serialization_microseconds,
      const std::uint64_t pacing_bits_per_second
    ) noexcept {
      constexpr std::uint64_t diagnostic_interval_microseconds = 1'000'000;
      if (last_deadline_diagnostic_microseconds_ != 0 &&
          now_microseconds >= last_deadline_diagnostic_microseconds_ &&
          now_microseconds - last_deadline_diagnostic_microseconds_ < diagnostic_interval_microseconds) {
        ++suppressed_deadline_diagnostics_;
        return;
      }
      const auto frame_age = now_microseconds >= capture_microseconds ?
                               now_microseconds - capture_microseconds :
                               0;
      const auto remaining = deadline_microseconds > now_microseconds ?
                               deadline_microseconds - now_microseconds :
                               0;
      const auto capture_to_submit = packet.frame_timestamp && packet.encoder_submit_timestamp &&
                                             *packet.encoder_submit_timestamp >= *packet.frame_timestamp ?
                                       saturated_microseconds(
                                         *packet.encoder_submit_timestamp - *packet.frame_timestamp
                                       ) :
                                       0;
      const auto encoder_duration = packet.encoder_submit_timestamp && packet.encoder_complete_timestamp &&
                                            *packet.encoder_complete_timestamp >= *packet.encoder_submit_timestamp ?
                                      saturated_microseconds(
                                        *packet.encoder_complete_timestamp - *packet.encoder_submit_timestamp
                                      ) :
                                      0;
      BOOST_LOG(warning) << "LSP video deadline miss: stage=" << deadline_stage_name(stage)
                         << " frame=" << packet.frame_index()
                         << " age_us=" << frame_age
                         << " budget_us=" << config_.maximum_capture_to_present_microseconds
                         << " remaining_us=" << remaining
                         << " capture_to_submit_us=" << capture_to_submit
                         << " encode_us=" << encoder_duration
                         << " egress_queue_us="
                         << std::chrono::duration_cast<std::chrono::microseconds>(queue_age).count()
                         << " source_bytes=" << source_bytes
                         << " wire_bytes=" << complete_wire_bytes
                         << " repair_bytes=" << selected_repair_bytes
                         << " packets=" << packet_count
                         << " serialization_us=" << serialization_microseconds
                         << " pacing_bps=" << pacing_bits_per_second
                         << " suppressed=" << suppressed_deadline_diagnostics_;
      last_deadline_diagnostic_microseconds_ = now_microseconds;
      suppressed_deadline_diagnostics_ = 0;
    }

    /**
     * @brief Drop an encoded frame before submission and invalidate its future reference use.
     *
     * @param packet Unsent encoded frame whose dependency is invalidated.
     * @param reason Coarse admission reason recorded exactly once for this frame.
     * @return True after dependency invalidation was queued; false after fail-closed teardown.
     */
    [[nodiscard]] bool drop_pre_submit_frame(
      video::packet_raw_t &packet,
      const FrameAdmissionDropReason reason = FrameAdmissionDropReason::other
    ) noexcept {
      dropped_frames_.fetch_add(1, std::memory_order_relaxed);
      pressure_events_.fetch_add(1, std::memory_order_relaxed);
      switch (reason) {
        case FrameAdmissionDropReason::decoder_saturated:
          decoder_saturated_drops_.fetch_add(1, std::memory_order_relaxed);
          break;
        case FrameAdmissionDropReason::deadline_miss:
          deadline_miss_drops_.fetch_add(1, std::memory_order_relaxed);
          break;
        case FrameAdmissionDropReason::invalid_reference:
          invalid_reference_drops_.fetch_add(1, std::memory_order_relaxed);
          break;
        case FrameAdmissionDropReason::forward_capacity:
          forward_capacity_drops_.fetch_add(1, std::memory_order_relaxed);
          break;
        case FrameAdmissionDropReason::other:
          break;
      }
      if (reason == FrameAdmissionDropReason::invalid_reference) {
        std::scoped_lock lock(dependency_state_mutex_);
        if (invalidation_pending_locked()) {
          // NVENC expands the active invalidation through its last encoded frame on the
          // encoder thread. Any unmarked dependent already queued behind that request is
          // therefore covered; issuing another request here chases the encoder forever.
          return true;
        }
      }
      return invalidate_uncommitted_frame_dependency(packet);
    }

    /** @brief Apply exact encoder invalidation results and the request's bounded rejection policy. */
    [[nodiscard]] bool consume_invalidation_results() noexcept {
      if (!invalidation_result_events_) {
        return false;
      }
      while (invalidation_result_events_->peek()) {
        const auto result = invalidation_result_events_->pop(std::chrono::milliseconds {0});
        if (!result) {
          continue;
        }
        const auto completion = take_invalidation_result(*result);
        if (!completion) {
          continue;
        }
        if (completion->promotion_failed) {
          fail_forward_path();
          return false;
        }
        if (completion->promoted) {
          invalidation_request_events_->raise(*completion->promoted);
        }
        if (result->succeeded) {
          continue;
        }
        if (completion->completed.failure_policy == InvalidationFailurePolicy::independent_recovery) {
          bool request_independent_frame = false;
          bool recovery_already_outstanding = false;
          {
            std::scoped_lock lock(pending_mutex_);
            const auto recovery = recovery_.snapshot();
            request_independent_frame = recovery.phase == transport::recovery_phase::repairing_references ||
                                        recovery.phase == transport::recovery_phase::retry_permitted;
            recovery_already_outstanding =
              recovery.phase == transport::recovery_phase::recovery_frame_outstanding;
          }
          if (request_independent_frame) {
            config_.capture_mail->event<bool>(mail::idr)->raise(true);
            continue;
          }
          if (recovery_already_outstanding) {
            continue;
          }
        }
        fail_forward_path();
        return false;
      }
      return !failed_.load(std::memory_order_acquire);
    }

    /** @brief Drain encoded access units until close or fatal packet submission failure. */
    void run() noexcept {
      while (auto dequeued = egress_.pop()) {
        if (closed_.load(std::memory_order_acquire)) {
          break;
        }
        if (!process_frame(*dequeued->packet, dequeued->queue_age)) {
          failed_.store(true, std::memory_order_release);
          config_.capture_mail->event<bool>(mail::shutdown)->raise(true);
          break;
        }
      }
    }

    /**
     * @brief Materialize, admit, packetize, pace, protect, and submit one complete access unit.
     *
     * @param packet Encoded access unit transferred from the capture/encoder pipeline.
     * @param queue_age Time retained by the bounded encoder-egress queue.
     * @return True after bounded processing; false on terminal sender failure.
     */
    [[nodiscard]] bool process_frame(
      video::packet_raw_t &packet,
      const std::chrono::nanoseconds queue_age
    ) noexcept {
      if (!consume_invalidation_results()) {
        return false;
      }
      const auto boundary_now = video_monotonic_microseconds();
      if (!apply_requested_targets(boundary_now, true)) {
        return false;
      }
      const auto independent = packet.is_idr() || packet.after_ref_frame_invalidation;
      const auto path_payload = current_path_payload_.load(std::memory_order_acquire);
      const auto pacing_rate = current_pacing_bits_per_second_.load(std::memory_order_acquire);
      const auto retained_frame_index = staging_frame_index_;
      auto &retained_frame = retained_frames_[retained_frame_index];
      {
        std::scoped_lock repair_lock(repair_mutex_);
        if (retained_frame.phase != RetainedAccessUnit::Phase::staging ||
            retained_frame.retained_tokens != 0) {
          return false;
        }
        retained_frame.frame_id = 0;
        retained_frame.plan_count = 0;
        retained_frame.unit_count = 0;
        retained_frame.access_unit_bytes = 0;
        retained_frame.deadline_microseconds = 0;
        retained_frame.rtp_timestamp = 0;
        retained_frame.first_sequence = 0;
        retained_frame.rtx_handle = {};
        retained_frame.independent = false;
        retained_frame.rtx_disabled = false;
        ++retained_frame.incarnation;
        if (retained_frame.incarnation == 0) {
          retained_frame.incarnation = 1;
        }
      }
      std::size_t access_unit_bytes = 0;
      if (!video::materialize_lsp_access_unit(packet, retained_frame.bytes, access_unit_bytes) ||
          access_unit_bytes == 0 || access_unit_bytes > config_.maximum_access_unit_bytes) {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        return false;
      }

      std::array<std::span<const std::uint8_t>, maximum_nal_units_per_access_unit> unit_storage {};
      auto access_unit = std::span<std::uint8_t> {retained_frame.bytes}.first(access_unit_bytes);
      std::size_t unit_count = 0;
      if (config_.video.codec == VideoCodec::av1 || config_.video.codec == VideoCodec::bc1) {
        std::size_t normalized_bytes = 0;
        unit_count = normalize_av1_obus(access_unit, unit_storage, normalized_bytes);
        access_unit_bytes = normalized_bytes;
        access_unit = std::span<std::uint8_t> {retained_frame.bytes}.first(access_unit_bytes);
      } else {
        unit_count = split_annex_b(access_unit, unit_storage);
      }
      if (unit_count == 0) {
        dropped_frames_.fetch_add(1, std::memory_order_relaxed);
        return false;
      }
      for (std::size_t index = 0; index < unit_count; ++index) {
        retained_frame.units[index] = {
          .offset = static_cast<std::size_t>(unit_storage[index].data() - retained_frame.bytes.data()),
          .size = unit_storage[index].size(),
        };
      }
      retained_frame.access_unit_bytes = access_unit_bytes;
      retained_frame.unit_count = unit_count;

      const auto complete_time = std::chrono::steady_clock::now();
      const auto capture_time = packet.frame_timestamp.value_or(complete_time);
      const auto submit_time = packet.encoder_submit_timestamp.value_or(capture_time);
      const auto encoder_complete_time = packet.encoder_complete_timestamp.value_or(complete_time);
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
      const auto recovery_boundary = prepare_recovery_boundary(independent, video_monotonic_microseconds());
      if (recovery_boundary.epoch == 0) {
        return false;
      }
      if (video_recovery_drop_requires_dependency_invalidation(
            recovery_boundary.blocked,
            recovery_boundary.request_independent_frame,
            independent
          )) {
        return drop_pre_submit_frame(packet, FrameAdmissionDropReason::invalid_reference);
      }
      const auto extension_storage = make_extensions(
        independent,
        absolute_capture_ntp(capture_time, complete_time),
        frame_id,
        recovery_boundary.epoch,
        packet.applied_input_state_sequence,
        packet.applied_input_edge_id,
        saturated_microseconds(submit_time - capture_time),
        saturated_microseconds(encoder_complete_time - capture_time)
      );
      if (!extension_storage) {
        return false;
      }
      const auto units = std::span<const std::span<const std::uint8_t>> {unit_storage}.first(unit_count);
      const auto extension_views = extension_storage->views();
      const auto plaintext_capacity = static_cast<std::size_t>(path_payload) - sender_srtp_tag_bytes;
      const auto boundary_overhead = rtp_fixed_header_size + extension_views.maximum_size();
      if (plaintext_capacity <= boundary_overhead || plaintext_capacity <= rtp_fixed_header_size) {
        return false;
      }
      const auto fec_enabled = config_.video.flexfec &&
                               boundary_now < flexfec_active_until_microseconds_.load(std::memory_order_acquire);
      const auto repair_packet_overhead = video_repair_packetization_reserve(
        fec_enabled,
        config_.video.rtx.has_value()
      );
      if (plaintext_capacity <= boundary_overhead + repair_packet_overhead ||
          plaintext_capacity <= rtp_fixed_header_size + repair_packet_overhead) {
        return false;
      }
      const auto boundary_capacity = plaintext_capacity - boundary_overhead - repair_packet_overhead;
      const auto middle_capacity = plaintext_capacity - rtp_fixed_header_size - repair_packet_overhead;
      const auto plans = std::span<PacketPlan> {retained_frame.plans};
      std::size_t plan_count = 0;
      switch (config_.video.codec) {
        case VideoCodec::h264:
          plan_count = plan_h264_packets(units, boundary_capacity, middle_capacity, plans);
          break;
        case VideoCodec::hevc:
          plan_count = plan_hevc_packets(units, boundary_capacity, middle_capacity, plans);
          break;
        case VideoCodec::bc1:
          plan_count = plan_av1_packets(units, false, boundary_capacity, middle_capacity, plans);
          break;
        case VideoCodec::av1:
          plan_count = plan_av1_packets(
            units,
            packet.is_idr() &&
              static_cast<std::uint8_t>((units.front().front() >> 3U) & 0x0fU) == 1U,
            boundary_capacity,
            middle_capacity,
            plans
          );
          break;
      }
      if (plan_count == 0) {
        return false;
      }

      const auto deadline = media::compute_network_deadline({
        .capture_time_us = capture_us,
        .maximum_capture_to_client_us = config_.maximum_capture_to_present_microseconds,
      });
      if (!wait_for_reference_terminal(independent, deadline)) {
        const auto deadline_observation = video_monotonic_microseconds();
        const auto reason = closed_.load(std::memory_order_acquire) ?
                              FrameAdmissionDropReason::other :
                            deadline_observation >= deadline ?
                              FrameAdmissionDropReason::deadline_miss :
                              FrameAdmissionDropReason::invalid_reference;
        if (reason == FrameAdmissionDropReason::deadline_miss) {
          log_deadline_miss(
            FrameDeadlineMissStage::reference_wait,
            packet,
            queue_age,
            capture_us,
            deadline_observation,
            deadline,
            access_unit_bytes,
            0,
            0,
            plan_count,
            0,
            pacing_rate
          );
        }
        return drop_pre_submit_frame(packet, reason);
      }
      const auto now_us = video_monotonic_microseconds();
      const auto credit = decoder_credit_.load(std::memory_order_acquire);
      const auto fec_group_packets = video_flexfec_group_packet_limit(
        flexfec_group_packets_.load(std::memory_order_acquire),
        independent
      );
      std::size_t selected_repair_bytes = 0;
      if (fec_enabled) {
        for (std::size_t group_begin = 0; group_begin < plan_count; group_begin += fec_group_packets) {
          const auto group_end = std::min(plan_count, group_begin + fec_group_packets);
          std::size_t maximum_source_tail = 0;
          for (std::size_t index = group_begin; index < group_end; ++index) {
            const auto extension = extension_views.for_role(media::packet_role(index, plan_count));
            maximum_source_tail = std::max(
              maximum_source_tail,
              extension.size() + plans[index].payload_bytes
            );
          }
          const auto repair_bytes = transport::flexfec_repair_rtp_header_size +
                                    transport::flexfec_minimum_header_size + maximum_source_tail +
                                    sender_srtp_tag_bytes;
          if (repair_bytes > path_payload ||
              selected_repair_bytes > std::numeric_limits<std::size_t>::max() - repair_bytes) {
            return false;
          }
          selected_repair_bytes += repair_bytes;
        }
      }
      const auto admission = media::admit_frame({
        .size_mode = media::frame_size_mode::complete_access_unit,
        .source_bytes = access_unit_bytes,
        .selected_repair_bytes = selected_repair_bytes,
        .pacing_rate_bits_per_second = pacing_rate,
        .now_us = now_us,
        .network_deadline_us = deadline,
        .decoder_credits = credit,
        .reference_path_valid = independent || reference_path_valid_.load(std::memory_order_acquire),
      });
      if (!admission) {
        auto reason = FrameAdmissionDropReason::other;
        std::optional<FrameDeadlineMissStage> deadline_stage;
        switch (admission.status) {
          case media::frame_admission_status::decoder_saturated:
            reason = FrameAdmissionDropReason::decoder_saturated;
            break;
          case media::frame_admission_status::expired:
            deadline_stage = FrameDeadlineMissStage::coarse_admission_expired;
            reason = FrameAdmissionDropReason::deadline_miss;
            break;
          case media::frame_admission_status::misses_deadline:
            deadline_stage = FrameDeadlineMissStage::coarse_serialization;
            reason = FrameAdmissionDropReason::deadline_miss;
            break;
          case media::frame_admission_status::invalid_reference_path:
            reason = FrameAdmissionDropReason::invalid_reference;
            break;
          case media::frame_admission_status::admitted:
          case media::frame_admission_status::invalid_size:
          case media::frame_admission_status::invalid_pacing_rate:
            break;
        }
        if (deadline_stage) {
          log_deadline_miss(
            *deadline_stage,
            packet,
            queue_age,
            capture_us,
            now_us,
            deadline,
            access_unit_bytes,
            0,
            selected_repair_bytes,
            plan_count,
            admission.estimated_serialization_us,
            pacing_rate
          );
        }
        return drop_pre_submit_frame(packet, reason);
      }
      if (forward_backpressured_.load(std::memory_order_acquire) ||
          !config_.forward_path->video_admission_open()) {
        return drop_pre_submit_frame(packet, FrameAdmissionDropReason::forward_capacity);
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
      if (fec_enabled) {
        const auto repair_charged_bytes = selected_repair_bytes +
                                          ((plan_count + fec_group_packets - 1U) / fec_group_packets) *
                                            ip_udp_overhead();
        if (complete_wire_bytes > std::numeric_limits<std::uint64_t>::max() - repair_charged_bytes) {
          return false;
        }
        complete_wire_bytes += repair_charged_bytes;
      }
      const auto wire_bits = complete_wire_bytes * 8U;
      const auto serialization_us = wire_bits > std::numeric_limits<std::uint64_t>::max() / 1'000'000U ?
                                      std::numeric_limits<std::uint64_t>::max() :
                                      (wire_bits * 1'000'000U + pacing_rate - 1U) / pacing_rate;
      if (now_us >= deadline || serialization_us > deadline - now_us) {
        log_deadline_miss(
          FrameDeadlineMissStage::exact_serialization,
          packet,
          queue_age,
          capture_us,
          now_us,
          deadline,
          access_unit_bytes,
          complete_wire_bytes,
          selected_repair_bytes,
          plan_count,
          serialization_us,
          pacing_rate
        );
        return drop_pre_submit_frame(packet, FrameAdmissionDropReason::deadline_miss);
      }

      const auto dependency_generation = reserve_dependency_generation(independent);
      if (!dependency_generation) {
        return drop_pre_submit_frame(packet, FrameAdmissionDropReason::invalid_reference);
      }
      admitted_frames_.fetch_add(1, std::memory_order_relaxed);
      {
        std::scoped_lock repair_lock(repair_mutex_);
        retained_frame.extensions = *extension_storage;
        retained_frame.plan_count = plan_count;
        retained_frame.frame_id = frame_id;
        retained_frame.deadline_microseconds = deadline;
        retained_frame.rtp_timestamp = rtp_timestamp;
        retained_frame.first_sequence = next_sequence_;
        retained_frame.independent = independent;
        retained_frame.phase = RetainedAccessUnit::Phase::current;
      }
      const auto frame_ticket = begin_pending_frame(
        independent,
        packet.is_idr(),
        frame_id,
        packet.frame_index(),
        packet.reference_invalidation_generation,
        *dependency_generation,
        retained_frame_index,
        retained_frame.incarnation
      );
      if (frame_ticket == 0) {
        abort_retained_frame(retained_frame_index, retained_frame.incarnation);
        const auto reason = closed_.load(std::memory_order_acquire) ?
                              FrameAdmissionDropReason::other :
                              FrameAdmissionDropReason::forward_capacity;
        return drop_pre_submit_frame(packet, reason);
      }
      const auto reservation = reserve_recovery_frame(
        frame_ticket,
        independent,
        recovery_boundary.epoch,
        now_us,
        deadline
      );
      if (reservation == RecoveryReservation::rejected) {
        pressure_events_.fetch_add(1, std::memory_order_relaxed);
        finish_pending_frame(frame_ticket, false);
        return true;
      }
      std::array<std::uint8_t, host_forward_maximum_payload_bytes> flexfec_parity_storage {};
      transport::flexfec_group flexfec_group {flexfec_parity_storage};
      bool flexfec_available = fec_enabled;
      for (std::size_t packet_index = 0; packet_index < plan_count; ++packet_index) {
        const auto now = video_monotonic_microseconds();
        if (!apply_requested_targets(now, false)) {
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        if (now >= deadline) {
          deadline_miss_drops_.fetch_add(1, std::memory_order_relaxed);
          log_deadline_miss(
            FrameDeadlineMissStage::packet_submission,
            packet,
            queue_age,
            capture_us,
            now,
            deadline,
            access_unit_bytes,
            complete_wire_bytes,
            selected_repair_bytes,
            plan_count,
            serialization_us,
            pacing_rate
          );
          finish_pending_frame(frame_ticket, false);
          return retire_consumed_sequences(packet_index);
        }
        bool dependency_valid = false;
        {
          std::scoped_lock dependency_lock(dependency_state_mutex_);
          dependency_valid = video_dependency_reservation_valid(
            independent,
            *dependency_generation,
            dependency_break_generation_,
            reference_path_valid_.load(std::memory_order_acquire),
            dependency_repair_pending_
          );
        }
        if (!dependency_valid) {
          finish_pending_frame(frame_ticket, false);
          if (packet_index == 0) {
            if (!config_.reference_invalidation ||
                !request_reference_invalidation(
                  packet.frame_index(),
                  packet.frame_index(),
                  InvalidationFailurePolicy::fail_closed,
                  std::nullopt,
                  true
                )) {
              fail_forward_path();
              return false;
            }
          }
          return retire_consumed_sequences(packet_index);
        }
        auto lease = config_.forward_path->acquire_until(HostForwardLane::video, deadline);
        if (!lease) {
          finish_pending_frame(frame_ticket, false);
          return retire_consumed_sequences(packet_index);
        }
        const auto role = media::packet_role(packet_index, plan_count);
        const auto extension = extension_views.for_role(role);
        const auto &plan = plans[packet_index];
        const auto plaintext_bytes = rtp_fixed_header_size + extension.size() + plan.payload_bytes;
        if (plaintext_bytes + sender_srtp_tag_bytes > path_payload) {
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        const rtp_fixed_header rtp {
          .padding = false,
          .extension = !extension.empty(),
          .marker = packet_index + 1U == plan_count,
          .payload_type = config_.video.primary_payload_type,
          .csrc_count = 0,
          .sequence_number = static_cast<std::uint16_t>(next_sequence_ + packet_index),
          .timestamp = rtp_timestamp,
          .ssrc = config_.video.primary_ssrc,
        };
        const auto header = write_rtp_fixed_header(rtp, {}, lease->storage);
        if (!header || header.bytes_written != rtp_fixed_header_size) {
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        std::copy(extension.begin(), extension.end(), lease->storage.begin() + static_cast<std::ptrdiff_t>(rtp_fixed_header_size));
        const auto payload = lease->storage.subspan(
          rtp_fixed_header_size + extension.size(),
          plan.payload_bytes
        );
        if (!write_codec_payload(config_.video.codec, plan, units, payload)) {
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        if (flexfec_available && packet_index % fec_group_packets == 0 &&
            flexfec_group.begin(
              frame_id,
              config_.video.primary_ssrc,
              config_.video.flexfec->repair_ssrc
            ) != transport::flexfec_result::accepted) {
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        if (flexfec_available &&
            flexfec_group.add_plaintext_source(
              frame_id,
              config_.video.primary_ssrc,
              rtp.sequence_number,
              lease->storage.first(plaintext_bytes)
            ) != transport::flexfec_result::accepted) {
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        const auto token = register_pending_rtp(
          rtp.sequence_number,
          static_cast<std::uint32_t>(plan.payload_bytes),
          path_payload,
          frame_ticket
        );
        if (token == 0) {
          finish_pending_frame(frame_ticket, false);
          return retire_consumed_sequences(packet_index);
        }
        std::size_t protected_bytes = 0;
        if (!srtp_.protect_in_place(
              config_.peer,
              SecurePacketClass::rtp,
              lease->storage,
              plaintext_bytes,
              protected_bytes
            ) ||
            protected_bytes == 0) {
          (void) take_pending(token, false);
          finish_pending_frame(frame_ticket, false);
          return false;
        }
        auto submit_result = HostForwardSubmitResult::invalid;
        {
          std::scoped_lock dependency_lock(dependency_state_mutex_);
          dependency_valid = video_dependency_reservation_valid(
            independent,
            *dependency_generation,
            dependency_break_generation_,
            reference_path_valid_.load(std::memory_order_acquire),
            dependency_repair_pending_
          );
          if (dependency_valid) {
            submit_result = config_.forward_path->commit(
              *lease,
              protected_bytes,
              deadline,
              token,
              completion_target()
            );
          }
        }
        if (!dependency_valid) {
          if (const auto pending = take_pending(token, false)) {
            record_unsent_packet(primary_ledger_, *pending, video_monotonic_microseconds());
          }
          finish_pending_frame(frame_ticket, false);
          const auto retired = retire_consumed_sequences(packet_index + 1U);
          if (packet_index == 0 && !invalidate_uncommitted_frame_dependency(packet)) {
            return false;
          }
          return retired;
        }
        if (submit_result != HostForwardSubmitResult::accepted) {
          if (const auto pending = take_pending(token, false)) {
            record_unsent_packet(primary_ledger_, *pending, video_monotonic_microseconds());
          }
          finish_pending_frame(frame_ticket, false);
          const auto retired = retire_consumed_sequences(packet_index + 1U);
          if (packet_index == 0 && !invalidate_uncommitted_frame_dependency(packet)) {
            return false;
          }
          return retired;
        }
        mark_frame_packet_committed(frame_ticket);
        retain_rtx_source(
          retained_frame_index,
          packet_index,
          rtp.sequence_number,
          plaintext_bytes,
          video_monotonic_microseconds()
        );
        const auto flexfec_group_complete = flexfec_available &&
                                            ((packet_index + 1U) % fec_group_packets == 0 ||
                                             packet_index + 1U == plan_count);
        if (flexfec_group_complete &&
            !submit_flexfec_group(
              flexfec_group,
              frame_ticket,
              packet_index + 1U,
              rtp_timestamp,
              deadline
            )) {
          abort_pending_frame_after_repair_failure(frame_ticket);
          fail_forward_path();
          return false;
        }
        if (flexfec_group_complete && flexfec_group.phase() != transport::flexfec_phase::complete) {
          flexfec_available = false;
        }
      }
      next_sequence_ = static_cast<std::uint16_t>(next_sequence_ + plan_count);
      const auto terminal = finish_and_wait_pending_frame(frame_ticket);
      if (!terminal) {
        return false;
      }
      if (terminal->succeeded && !commit_retained_frame(*terminal)) {
        fail_forward_path();
        return false;
      }
      if (credit != 0) {
        auto expected_credit = credit;
        (void) decoder_credit_.compare_exchange_strong(expected_credit, static_cast<std::uint8_t>(credit - 1U));
      }
      if (!terminal->succeeded) {
        return true;
      }
      maybe_send_sender_report(rtp_timestamp, video_monotonic_microseconds());
      return true;
    }

    HostVideoSenderConfig config_;  ///< Immutable negotiated sender configuration.
    LibsrtpServerProvider &srtp_;  ///< Installed association provider.
    safe::mail_raw_t::event_t<video::reference_invalidation_request_t> invalidation_request_events_;  ///< Generation-qualified encoder invalidation requests.
    safe::mail_raw_t::event_t<video::reference_invalidation_result_t> invalidation_result_events_;  ///< Encoder invalidation terminal results.
    video::egress_queue_t egress_;  ///< Decoder-surface-bounded encoded egress owner.
    transport::congestion_controller congestion_;  ///< Independent forward-path RFC 8888 controller.
    transport::path_mtu_discovery path_mtu_;  ///< Authenticated host-to-client DPLPMTUD search state.
    transport::recovery_controller recovery_;  ///< Coalesces reference damage into one recovery epoch/request.
    std::optional<transport::path_mtu_discovery> path_mtu_before_probe_ {};  ///< Rollback state until control intent starts.
    std::array<RetainedAccessUnit, transport::maximum_rtx_frame_generations + 1U> retained_frames_ {};  ///< Staging/current plus two successful AU generations.
    std::vector<transport::rtx_retained_packet> rtx_retention_slots_ {};  ///< Setup-allocated Photon RTX metadata slots.
    std::optional<transport::rtx_retention> rtx_retention_ {};  ///< Bounded opaque reconstruction retention state.
    std::array<PendingDatagram, pending_datagram_slot_count> pending_datagrams_ {};  ///< Indexed final-send metadata.
    std::array<PendingFrame, pending_frame_slot_count> pending_frames_ {};  ///< Indexed whole-frame completion state.
    PendingInvalidation active_invalidation_ {};  ///< Sole request published through the replaceable mailbox event.
    PendingInvalidation queued_invalidation_ {};  ///< Coalesced next range retained until active completion.
    std::array<std::uint8_t, pending_datagram_slot_count> free_pending_datagrams_ {};  ///< O(1) datagram free list.
    std::array<std::uint8_t, pending_frame_slot_count> free_pending_frames_ {};  ///< O(1) frame free list.
    std::mutex pending_mutex_;  ///< Serializes path completions with producer token registration.
    std::condition_variable pending_condition_;  ///< Wakes dependency and lifetime drain waiters.
    mutable std::recursive_mutex control_mutex_;  ///< Serializes path-probe, report, and feedback state with completions.
    mutable std::mutex dependency_state_mutex_;  ///< Serializes dependency breaks, invalidation correlation, and restoration.
    mutable std::mutex repair_mutex_;  ///< Serializes retained-AU publication, eviction, and feedback reconstruction.
    std::size_t free_pending_datagram_count_ {};  ///< Available leading datagram free-list entries.
    std::size_t free_pending_frame_count_ {};  ///< Available leading frame free-list entries.
    std::size_t active_completion_callbacks_ {};  ///< Claimed callbacks that still access this sender.
    std::uint64_t last_reference_frame_ticket_ {};  ///< Terminal fence for the next dependent admission.
    std::uint64_t next_invalidation_generation_ {1};  ///< Next nonzero encoder request generation.
    std::uint32_t last_feedback_independent_request_epoch_ {};  ///< Last epoch for which PLI/FIR requested one IDR.
    bool recovery_failure_latched_ {};  ///< Authenticated or local failure retained until retry deadline.
    SentPacketLedger primary_ledger_ {};  ///< Primary-video sent and feedback sequence state.
    SentPacketLedger flexfec_ledger_ {};  ///< FlexFEC sent and feedback sequence state.
    SentPacketLedger rtx_ledger_ {};  ///< RTX sent and feedback sequence state.
    std::array<SenderReportTiming, 8> sender_report_timings_ {};  ///< Recent authenticated RR timing matches.
    PathProbeTransmission path_probe_ {};  ///< One protected logical DPLPMTUD transmission.
    PathProbePayload last_acknowledged_probe_ {};  ///< Idempotent latest semantic probe acknowledgement.
    std::array<std::uint64_t, 64> recent_probe_ids_ {};  ///< Session-retained probe-ID replay fence.
    std::jthread worker_;  ///< Dedicated packetization, pacing, and send worker.
    std::optional<std::chrono::steady_clock::time_point> capture_origin_ {};  ///< First capture sampling origin.
    std::uint16_t next_sequence_ {};  ///< Next primary RTP sequence number.
    std::uint16_t next_flexfec_sequence_ {};  ///< Next independent FlexFEC RTP sequence number.
    std::uint16_t next_rtx_sequence_ {};  ///< Next independent RTX RTP sequence number.
    std::uint32_t initial_timestamp_ {};  ///< Random initial 90 kHz timestamp.
    std::uint64_t next_frame_id_ {};  ///< Next nonzero frame identifier.
    std::uint64_t last_compound_rtcp_microseconds_ {};  ///< Latest valid regular compound report time.
    std::uint64_t last_feedback_receive_microseconds_ {};  ///< Local hard-floor origin for accepted CCFB.
    std::uint64_t last_delay_send_microseconds_ {};  ///< Prior sender time for delay-trend differencing.
    std::uint64_t last_sender_report_microseconds_ {};  ///< Last accepted video SRTCP SR submission.
    std::uint64_t last_overhead_sample_microseconds_ {};  ///< Latest non-video aggregate-rate sample time.
    std::uint64_t last_path_charged_bytes_ {};  ///< Aggregate path bytes at the prior overhead sample.
    std::uint64_t last_video_charged_bytes_ {};  ///< Primary video bytes at the prior overhead sample.
    std::uint64_t smoothed_forward_overhead_bits_per_second_ {};  ///< Smoothed measured non-video wire rate.
    std::uint32_t last_delay_arrival_timestamp_ {};  ///< Prior receiver middle-NTP arrival timestamp.
    std::uint32_t last_feedback_timestamp_ {};  ///< Latest accepted RFC 8888 report timestamp.
    std::array<std::uint8_t, 255> feedback_cname_ {};  ///< Stable regular-report CNAME authorizing reduced feedback.
    std::size_t feedback_cname_size_ {};  ///< Populated stable CNAME byte count.
    std::uint32_t last_fir_sender_ssrc_ {};  ///< Feedback source of the latest accepted FIR command.
    std::uint32_t last_fir_media_ssrc_ {};  ///< Media source targeted by the latest accepted FIR command.
    std::uint32_t smoothed_rtt_microseconds_ {};  ///< Latest regular-RTCP RTT estimate when available.
    std::uint32_t rtt_variation_microseconds_ {};  ///< Latest regular-RTCP RTT variation when available.
    std::atomic<std::uint32_t> rtp_packet_count_ {};  ///< Final-sent video RTP packet count modulo 2^32 for SR.
    std::atomic<std::uint32_t> rtp_octet_count_ {};  ///< Final-sent video codec-payload octets modulo 2^32 for SR.
    std::atomic<std::uint64_t> latest_sent_frame_id_ {};  ///< Greatest fully submitted frame for decoder damage attribution.
    std::uint64_t dependency_break_generation_ {1};  ///< Latest local encoder/decoder dependency break under state lock.
    std::int64_t dependency_frame_fence_ {std::numeric_limits<std::int64_t>::min()};  ///< Greatest frame invalidated by a local break.
    std::uint64_t latest_published_invalidation_generation_ {};  ///< Sole active encoder request generation.
    std::uint64_t latest_published_dependency_generation_ {};  ///< Dependency break owned by the active request.
    std::size_t staging_frame_index_ {};  ///< Fixed free/staging AU slot selected for the next frame.
    std::size_t next_recent_probe_id_ {};  ///< Next session replay-cache replacement slot.
    std::size_t next_sender_report_timing_ {};  ///< Next recent-SR timing replacement slot.
    std::atomic<bool> reference_path_valid_ {true};  ///< Whether known encoder dependencies remain decodable.
    bool pre_submit_invalidation_pending_ {};  ///< Whether exact local-drop invalidation awaits an independent frame.
    bool dependency_repair_pending_ {};  ///< Whether only a latest-generation independent may restore validity.
    std::int64_t pre_submit_invalidation_frame_ {};  ///< Exact frame index awaiting encoder invalidation.
    bool has_compound_rtcp_ {};  ///< Whether reduced-size CCFB has a fresh regular-report prerequisite.
    bool has_feedback_timestamp_ {};  ///< Whether report timestamp monotonicity has an origin.
    bool has_feedback_receive_time_ {};  ///< Whether local CCFB cadence has an origin.
    bool has_fir_command_ {};  ///< Whether one FIR command tuple is retained for idempotence.
    bool has_delay_sample_ {};  ///< Whether delay-trend differencing has an origin.
    bool sender_report_pending_ {};  ///< Whether one protected periodic SR awaits terminal completion.
    bool ready_ {};  ///< Constructor validation and fixed-slab allocation status.
    bool registered_ {};  ///< Whether egress retains this session key.
    std::atomic<std::uint8_t> decoder_credit_ {};  ///< Latest freshness-bounded available decoder surfaces.
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
    std::atomic<bool> forward_backpressured_ {};  ///< Aggregate path blocks new whole-frame admission.
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
    std::atomic<std::uint64_t> decoder_saturated_drops_ {};  ///< Zero-credit frame rejections.
    std::atomic<std::uint64_t> deadline_miss_drops_ {};  ///< Deadline and serialization frame rejections.
    std::atomic<std::uint64_t> invalid_reference_drops_ {};  ///< Dependency and recovery frame rejections.
    std::uint64_t last_deadline_diagnostic_microseconds_ {};  ///< Sender-thread rate-limit timestamp.
    std::uint64_t suppressed_deadline_diagnostics_ {};  ///< Deadline logs suppressed since the last publication.
    std::atomic<std::uint64_t> forward_capacity_drops_ {};  ///< Queue and aggregate-path capacity rejections.
    std::atomic<std::uint64_t> submitted_wire_bytes_ {};  ///< Complete charged wire bytes.
    std::atomic<std::uint64_t> pressure_events_ {};  ///< Bounded pressure observation count.
    std::atomic<std::uint64_t> feedback_reports_ {};  ///< Accepted authenticated RFC 8888 reports.
    std::atomic<std::uint64_t> feedback_rejections_ {};  ///< Rejected malformed or hostile reports.
    std::atomic<std::uint64_t> feedback_delivered_bytes_ {};  ///< Newly accounted delivered IP bytes.
    std::atomic<std::uint64_t> feedback_lost_bytes_ {};  ///< Newly accounted lost IP bytes.
    std::atomic<std::uint64_t> feedback_loss_corrections_ {};  ///< Loss bytes corrected by legal overlap.
    std::atomic<std::uint64_t> path_probe_datagrams_ {};  ///< Accepted exact protected LSPP submissions.
    std::atomic<std::uint64_t> path_probe_retries_ {};  ///< Fresh SRTCP-index PROBE_TIMER retries.
    std::atomic<std::uint64_t> flexfec_submitted_packets_ {};  ///< Final-sent FlexFEC RTP packet count.
    std::atomic<std::uint64_t> flexfec_submitted_wire_bytes_ {};  ///< Final-sent complete FlexFEC wire bytes.
    std::atomic<std::uint64_t> flexfec_dropped_packets_ {};  ///< Selected FlexFEC packets not submitted.
    std::atomic<std::uint64_t> rtx_submitted_packets_ {};  ///< Final-sent RTX RTP packet count.
    std::atomic<std::uint64_t> rtx_submitted_wire_bytes_ {};  ///< Final-sent complete RTX wire bytes.
    std::atomic<std::uint64_t> rtx_dropped_packets_ {};  ///< Requested RTX packets not submitted.
    std::atomic<std::uint64_t> repair_feedback_packets_ {};  ///< Accepted authenticated repair feedback packets.
    std::atomic<std::uint64_t> repair_feedback_rejections_ {};  ///< Rejected authenticated repair feedback packets.
    std::atomic<std::uint64_t> flexfec_active_until_microseconds_ {};  ///< Loss-triggered parity expiry.
    std::atomic<std::uint8_t> flexfec_group_packets_ {maximum_product_flexfec_group_packets};  ///< Current adaptive source group size.
    std::uint8_t last_fir_command_sequence_ {};  ///< Latest accepted RFC 5104 FIR command sequence.
    std::atomic<std::uint32_t> repair_rtt_microseconds_ {};  ///< Cross-thread RTT snapshot for strict RTX gates.
    std::atomic<bool> started_ {};  ///< Whether start succeeded.
    std::atomic<bool> closed_ {};  ///< Whether admission is closed.
    std::atomic<bool> failed_ {};  ///< Whether fatal packetization/send failure occurred.
  };

  HostVideoSender::HostVideoSender(HostVideoSenderConfig config, LibsrtpServerProvider &srtp) noexcept:
      impl_ {new(std::nothrow) Impl {std::move(config), srtp}} {
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

  bool HostVideoSender::validate_congestion_feedback(
    const CongestionFeedbackPacketView &packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->validate_congestion_feedback(packet, now_microseconds);
  }

  std::optional<VideoCongestionFeedbackPreview> HostVideoSender::preview_congestion_feedback(
    const CongestionFeedbackPacketView &packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ ? impl_->preview_congestion_feedback(packet, now_microseconds) : std::nullopt;
  }

  bool HostVideoSender::commit_congestion_feedback(
    const VideoCongestionFeedbackPreview &preview
  ) noexcept {
    return impl_ && impl_->commit_congestion_feedback(preview);
  }

  bool HostVideoSender::receive_congestion_feedback(
    const CongestionFeedbackPacketView &packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_congestion_feedback(packet, now_microseconds);
  }

  bool HostVideoSender::receive_repair_feedback(
    const std::span<const std::uint8_t> packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_repair_feedback(packet, now_microseconds);
  }

  bool HostVideoSender::receive_video_status(
    const transport::lspv_status &status,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_video_status(status, now_microseconds);
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

  bool HostVideoSender::complete_forward_datagram(
    const std::uint64_t token,
    const HostForwardCompletion completion,
    const std::uint64_t completed_at_microseconds,
    const std::size_t protected_bytes,
    const std::uint16_t charged_bytes
  ) noexcept {
    return impl_ && impl_->complete_forward_datagram(
                      token,
                      completion,
                      completed_at_microseconds,
                      protected_bytes,
                      charged_bytes
                    );
  }

  void HostVideoSender::set_forward_backpressure(const bool blocked) noexcept {
    if (impl_) {
      impl_->set_forward_backpressure(blocked);
    }
  }
}  // namespace lumen::lsp::runtime
