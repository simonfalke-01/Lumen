/**
 * @file src/platform/windows/virtual_display_driver/LumenDirectFrameSlotPolicy.h
 * @brief Portable ownership transitions for one ABI3 direct-frame slot.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_DIRECT_FRAME_SLOT_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_DIRECT_FRAME_SLOT_POLICY_H

namespace lumen::vdd::frame {
  /** Driver-side ownership state for one persistent direct-frame slot. */
  enum class slot_state_e {
    empty,
    writing,
    ready,
    acquired,
    released_pending,
    quarantined,
  };

  /** GPU submission outcome that determines whether a written slot is publishable. */
  enum class submission_result_e {
    success,
    wait_failed,
    copy_failed,
    signal_failed,
  };

  /** Return whether a slot can begin a new producer write. */
  [[nodiscard]] constexpr bool can_begin_write(slot_state_e state) noexcept {
    return state == slot_state_e::empty || state == slot_state_e::released_pending;
  }

  /** Complete one write without ever recycling an unproven GPU submission. */
  [[nodiscard]] constexpr slot_state_e complete_write(submission_result_e result) noexcept {
    return result == submission_result_e::success ? slot_state_e::ready : slot_state_e::quarantined;
  }
}  // namespace lumen::vdd::frame

#endif  // LUMEN_PLATFORM_WINDOWS_DIRECT_FRAME_SLOT_POLICY_H
