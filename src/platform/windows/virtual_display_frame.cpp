/**
 * @file src/platform/windows/virtual_display_frame.cpp
 * @brief Pure validation for the production VDD direct-frame ABI.
 */

// standard includes
#include <algorithm>
#include <atomic>
#include <limits>

// local includes
#include "virtual_display_frame.h"

namespace platf::virtual_display {
#if !defined(_WIN32)
  namespace {
    std::atomic_bool portable_runtime_quarantined {false};  ///< Mirrors sticky host behavior in portable tests.
  }
#endif
  bool valid_direct_frame_adapter_binding(
    const bool nvenc_active,
    const direct_frame_adapter_identity_t &imported,
    const std::optional<direct_frame_adapter_identity_t> &encoder_probe
  ) noexcept {
    constexpr std::uint32_t nvidia_vendor_id = 0x10de;
    return nvenc_active && imported.adapter_luid != 0 && imported.vendor_id == nvidia_vendor_id &&
           imported.device_id != 0 && imported.driver_version != 0 && encoder_probe &&
           imported == *encoder_probe;
  }

  bool valid_frame_resources(
    const frame_resources_t &resources,
    const std::uint64_t generation,
    const mode_t &mode
  ) noexcept {
    if (generation == 0 || resources.generation != generation ||
        resources.width != mode.width || resources.height != mode.height ||
        resources.format != frame_format_e::bgra8 ||
        resources.slot_count != direct_frame_slot_count) {
      return false;
    }

    std::array<std::uintptr_t, direct_frame_slot_count * 2> handles {};
    for (std::size_t slot = 0; slot < direct_frame_slot_count; ++slot) {
      if (resources.texture_handles[slot] == 0 || resources.fence_handles[slot] == 0) {
        return false;
      }
      handles[slot] = resources.texture_handles[slot];
      handles[direct_frame_slot_count + slot] = resources.fence_handles[slot];
    }
    std::ranges::sort(handles);
    return std::ranges::adjacent_find(handles) == handles.end();
  }

  bool valid_frame_descriptor(
    const frame_descriptor_t &frame,
    const frame_resources_t &resources
  ) noexcept {
    return frame.generation == resources.generation && frame.sequence != 0 &&
           frame.slot < direct_frame_slot_count && frame.slot < resources.slot_count &&
           frame.producer_fence_value != 0 && (frame.producer_fence_value & 1U) != 0 &&
           frame.producer_fence_value != std::numeric_limits<std::uint64_t>::max() &&
           frame.capture_qpc > 0 && frame.producer_signal_qpc >= frame.capture_qpc;
  }

#if !defined(_WIN32)
  std::shared_ptr<frame_source_t> make_system_frame_source(
    const stream_selection_t &,
    std::chrono::milliseconds
  ) {
    return {};
  }

  void quarantine_direct_frame_runtime() noexcept {
    portable_runtime_quarantined.store(true, std::memory_order_release);
  }

  bool direct_frame_runtime_quarantined() noexcept {
    return portable_runtime_quarantined.load(std::memory_order_acquire);
  }
#endif
}  // namespace platf::virtual_display
