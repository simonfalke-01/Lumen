/**
 * @file src/protocol_lsp/runtime/host_congestion_feedback.h
 * @brief Shared host-side RFC 8888 feedback serialization.
 */

#pragma once

#include "../core/wire.h"
#include "../transport/rtcp.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace lumen::lsp::runtime {
  /**
   * @brief Serialize one gap-preserving RFC 8888 received-SSRC feedback block.
   *
   * @param destination Bounded plaintext RTCP output storage.
   * @param feedback_ssrc Nonzero receiver feedback SSRC distinct from the media source.
   * @param batch Borrowed authenticated sequence range including gaps and overlap corrections.
   * @param report_timestamp Middle 32 bits of the report's NTP timestamp.
   * @return Exact aligned RTCP bytes, or zero when any invariant or bound is invalid.
   */
  [[nodiscard]] inline std::size_t write_host_congestion_report(
    const std::span<std::uint8_t> destination,
    const std::uint32_t feedback_ssrc,
    const transport::reordering_congestion_report_batch &batch,
    const std::uint32_t report_timestamp
  ) noexcept {
    const auto report_count = batch.size();
    const auto metric_bytes = report_count * 2U;
    const auto alignment_bytes = (report_count & 1U) != 0U ? 2U : 0U;
    const auto required = 20U + metric_bytes + alignment_bytes;
    if (feedback_ssrc == 0 || batch.media_ssrc == 0 || feedback_ssrc == batch.media_ssrc ||
        report_count == 0 || report_count > 16'384U || required > destination.size() || required > 1'200U ||
        batch.interval_end_microseconds < batch.interval_begin_microseconds) {
      return 0;
    }
    auto packet = destination.first(required);
    std::ranges::fill(packet, 0);
    packet[0] = static_cast<std::uint8_t>(0x80U | transport::rtcp_congestion_feedback_format);
    packet[1] = transport::rtcp_transport_feedback_type;
    wire::write_be<std::uint16_t>(packet.subspan<2, 2>(), static_cast<std::uint16_t>(required / 4U - 1U));
    wire::write_be<std::uint32_t>(packet.subspan<4, 4>(), feedback_ssrc);
    wire::write_be<std::uint32_t>(packet.subspan<8, 4>(), batch.media_ssrc);
    wire::write_be<std::uint16_t>(packet.subspan<12, 2>(), static_cast<std::uint16_t>(batch.begin_extended_sequence));
    wire::write_be<std::uint16_t>(packet.subspan<14, 2>(), static_cast<std::uint16_t>(report_count));

    std::size_t metric_index = 0;
    const auto write_slots = [&](const std::span<const transport::congestion_reception_slot> slots) {
      for (const auto &slot : slots) {
        std::uint16_t metric = 0;
        if (slot.received) {
          const auto ato = transport::encode_congestion_ato(
            slot.arrival_microseconds,
            batch.interval_end_microseconds
          );
          metric = static_cast<std::uint16_t>(
            0x8000U | (static_cast<std::uint16_t>(slot.ecn) << 13U) | ato
          );
        }
        wire::write_be<std::uint16_t>(packet.subspan(16U + metric_index * 2U, 2), metric);
        ++metric_index;
      }
    };
    write_slots(batch.first);
    write_slots(batch.second);
    wire::write_be<std::uint32_t>(packet.last<4>(), report_timestamp);
    return required;
  }
}  // namespace lumen::lsp::runtime
