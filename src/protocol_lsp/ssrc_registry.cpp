/**
 * @file src/protocol_lsp/ssrc_registry.cpp
 * @brief Authenticated LSP RTP lane and SSRC registry validation.
 */

#include "ssrc_registry.h"

#include <algorithm>
#include <utility>

namespace lumen::lsp {
  namespace {
    bool video_format(const PayloadFormat format) noexcept {
      return format == PayloadFormat::h264 || format == PayloadFormat::hevc || format == PayloadFormat::av1;
    }

    bool valid_direction(const SsrcAssignment &assignment) noexcept {
      switch (assignment.lane) {
        case MediaLane::video_primary:
        case MediaLane::video_repair:
        case MediaLane::video_rtx:
        case MediaLane::audio:
          return assignment.direction == MediaDirection::host_to_client;
        case MediaLane::input:
        case MediaLane::microphone:
          return assignment.direction == MediaDirection::client_to_host;
      }
      return false;
    }

    bool valid_format(const SsrcAssignment &assignment) noexcept {
      switch (assignment.lane) {
        case MediaLane::video_primary:
          return video_format(assignment.format);
        case MediaLane::video_repair:
          return assignment.format == PayloadFormat::flexfec;
        case MediaLane::video_rtx:
          return assignment.format == PayloadFormat::video_rtx;
        case MediaLane::audio:
        case MediaLane::microphone:
          return assignment.format == PayloadFormat::opus;
        case MediaLane::input:
          return assignment.format == PayloadFormat::lsp_input;
      }
      return false;
    }

    bool valid_clock_rate(const SsrcAssignment &assignment) noexcept {
      switch (assignment.lane) {
        case MediaLane::video_primary:
        case MediaLane::video_repair:
        case MediaLane::video_rtx:
          return assignment.clock_rate == 90'000;
        case MediaLane::audio:
        case MediaLane::microphone:
          return assignment.clock_rate == 48'000;
        case MediaLane::input:
          return assignment.clock_rate == 1'000'000;
      }
      return false;
    }

    std::optional<SsrcRegistryError> validate_assignment(const SsrcAssignment &assignment) noexcept {
      if (assignment.ssrc == 0) {
        return SsrcRegistryError::zero_ssrc;
      }
      if (assignment.payload_type < 96 || assignment.payload_type > 127) {
        return SsrcRegistryError::invalid_payload_type;
      }
      if (assignment.generation == 0) {
        return SsrcRegistryError::zero_generation;
      }
      if (!valid_direction(assignment)) {
        return SsrcRegistryError::invalid_direction;
      }
      if (!valid_format(assignment)) {
        return SsrcRegistryError::invalid_format;
      }
      if (!valid_clock_rate(assignment)) {
        return SsrcRegistryError::invalid_clock_rate;
      }
      const auto is_repair = assignment.lane == MediaLane::video_repair || assignment.lane == MediaLane::video_rtx;
      if (is_repair != (assignment.associated_primary_ssrc != 0)) {
        return SsrcRegistryError::invalid_repair_association;
      }
      return std::nullopt;
    }
  }  // namespace

  SsrcRegistry::SsrcRegistry(std::vector<SsrcAssignment> assignments):
      assignments_ {std::move(assignments)} {
  }

  std::expected<SsrcRegistry, SsrcRegistryError> SsrcRegistry::create(
    const std::span<const SsrcAssignment> assignments
  ) {
    if (assignments.empty()) {
      return std::unexpected(SsrcRegistryError::empty);
    }
    if (assignments.size() > maximum_entries) {
      return std::unexpected(SsrcRegistryError::too_many_entries);
    }
    for (const auto &assignment : assignments) {
      if (const auto error = validate_assignment(assignment)) {
        return std::unexpected(*error);
      }
    }

    for (std::size_t left = 0; left < assignments.size(); ++left) {
      for (std::size_t right = left + 1; right < assignments.size(); ++right) {
        if (assignments[left].ssrc == assignments[right].ssrc) {
          return std::unexpected(SsrcRegistryError::duplicate_ssrc);
        }
        if (assignments[left].lane == assignments[right].lane) {
          return std::unexpected(SsrcRegistryError::duplicate_lane);
        }
        if (assignments[left].payload_type == assignments[right].payload_type &&
            (assignments[left].format != assignments[right].format || assignments[left].clock_rate != assignments[right].clock_rate)) {
          return std::unexpected(SsrcRegistryError::conflicting_payload_type);
        }
      }
    }

    for (const auto &assignment : assignments) {
      if (assignment.associated_primary_ssrc == 0) {
        continue;
      }
      const auto primary = std::ranges::find_if(assignments, [&](const auto &candidate) {
        return candidate.ssrc == assignment.associated_primary_ssrc;
      });
      if (primary == assignments.end() || primary->lane != MediaLane::video_primary ||
          primary->direction != assignment.direction || primary->generation != assignment.generation) {
        return std::unexpected(SsrcRegistryError::invalid_repair_association);
      }
    }

    return SsrcRegistry {{assignments.begin(), assignments.end()}};
  }

  const SsrcAssignment *SsrcRegistry::find(const std::uint32_t ssrc) const noexcept {
    const auto found = std::ranges::find_if(assignments_, [ssrc](const auto &assignment) {
      return assignment.ssrc == ssrc;
    });
    return found == assignments_.end() ? nullptr : &*found;
  }

  std::span<const SsrcAssignment> SsrcRegistry::assignments() const noexcept {
    return assignments_;
  }
}  // namespace lumen::lsp
