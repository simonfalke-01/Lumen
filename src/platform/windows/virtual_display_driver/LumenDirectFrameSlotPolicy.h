/**
 * @file src/platform/windows/virtual_display_driver/LumenDirectFrameSlotPolicy.h
 * @brief Portable ownership transitions for one ABI v4 direct-frame slot.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_DIRECT_FRAME_SLOT_POLICY_H
#define LUMEN_PLATFORM_WINDOWS_DIRECT_FRAME_SLOT_POLICY_H

#include <cstddef>
#include <cstdint>
#include <optional>

namespace lumen::vdd::frame {
  /** Return whether the actual IddCx swap-chain adapter matches the frozen encoder preference. */
  [[nodiscard]] constexpr bool render_adapter_matches(
    const std::uint64_t preferred,
    const std::uint64_t actual
  ) noexcept {
    return preferred != 0 && actual == preferred;
  }

  /** Return whether all four published texture/fence handles are nonzero and pairwise distinct. */
  [[nodiscard]] constexpr bool published_handles_are_distinct(
    const std::uintptr_t texture0,
    const std::uintptr_t texture1,
    const std::uintptr_t fence0,
    const std::uintptr_t fence1
  ) noexcept {
    return texture0 != 0 && texture1 != 0 && fence0 != 0 && fence1 != 0 &&
           texture0 != texture1 && texture0 != fence0 && texture0 != fence1 &&
           texture1 != fence0 && texture1 != fence1 && fence0 != fence1;
  }

  /** Return the odd keyed-mutex value the host must acquire for the published producer frame. */
  [[nodiscard]] constexpr std::uint64_t host_acquire_key(const std::uint64_t producer_fence) noexcept {
    return producer_fence;
  }

  /** Return the next even keyed-mutex value released back to the producer. */
  [[nodiscard]] constexpr std::uint64_t producer_return_key(const std::uint64_t producer_fence) noexcept {
    return producer_fence + 1;
  }

  /** Driver-side ownership state for one persistent direct-frame slot. */
  enum class slot_state_e {
    empty,
    writing,
    ready,
    discarded_ready,
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

  /** @brief Keyed-mutex and fence requirements for one producer write. */
  struct producer_acquisition_t {
    bool can_write {};  ///< Whether the slot has returned to producer ownership.
    std::uint64_t keyed_mutex_key {};  ///< Exact keyed-mutex value the producer must acquire.
    std::uint64_t consumer_fence_wait {};  ///< Even consumer fence to wait for, or zero when none exists.
  };

  /**
   * @brief Resolve the exact producer ownership proof for a slot state.
   *
   * @param state Current driver-side ownership state.
   * @param producer_fence Odd fence/key published by the most recent producer write.
   * @param consumer_fence Even fence/key returned by the most recent consumer release.
   * @return Acquisition requirements, with can_write false for non-producer-owned states.
   */
  [[nodiscard]] constexpr producer_acquisition_t producer_acquisition(
    const slot_state_e state,
    const std::uint64_t producer_fence,
    const std::uint64_t consumer_fence
  ) noexcept {
    switch (state) {
      case slot_state_e::empty:
        return {true, 0, 0};
      case slot_state_e::discarded_ready:
        return {true, producer_fence, 0};
      case slot_state_e::released_pending:
        return {true, consumer_fence, consumer_fence};
      default:
        return {};
    }
  }

  /** @brief Producer-selected slot and the proof required before its next write. */
  struct producer_selection_t {
    std::optional<std::size_t> slot;  ///< Selected slot, or no value when the incoming frame must be dropped.
    producer_acquisition_t acquisition;  ///< Keyed-mutex and fence requirements for the selected slot.
  };

  /**
   * @brief Select a producer-owned slot, optionally reclaiming the oldest ready latency frame.
   *
   * @tparam SlotRange Random-access range whose elements expose ownership and fence members.
   * @param slots Fixed direct-frame slot range to update.
   * @param allow_ready_overwrite Reclaim the oldest unleased ready frame when no slot was returned normally.
   * @return Selected slot and acquisition proof, or no slot when the incoming frame must be dropped.
   */
  template<typename SlotRange>
  [[nodiscard]] constexpr producer_selection_t select_producer_slot(
    SlotRange &slots,
    const bool allow_ready_overwrite
  ) noexcept {
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
      const auto acquisition = producer_acquisition(
        slots[slot].state,
        slots[slot].producer_fence_value,
        slots[slot].consumer_fence_value
      );
      if (acquisition.can_write) {
        slots[slot].state = slot_state_e::writing;
        return {slot, acquisition};
      }
    }
    if (!allow_ready_overwrite) {
      return {};
    }

    std::optional<std::size_t> oldest_ready;
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
      if (slots[slot].state == slot_state_e::ready &&
          (!oldest_ready || slots[slot].sequence < slots[*oldest_ready].sequence)) {
        oldest_ready = slot;
      }
    }
    if (!oldest_ready) {
      return {};
    }

    const producer_acquisition_t acquisition {
      true,
      slots[*oldest_ready].producer_fence_value,
      0,
    };
    slots[*oldest_ready].state = slot_state_e::writing;
    return {*oldest_ready, acquisition};
  }

  /**
   * @brief Select one ready slot and preserve the ownership of latency-dropped frames.
   *
   * @tparam SlotRange Random-access range whose elements expose state and sequence members.
   * @param slots Fixed direct-frame slot range to update.
   * @param prefer_newest Select the newest frame and discard older ready frames when true.
   * @return Selected slot index, or no value when no frame is ready.
   */
  template<typename SlotRange>
  [[nodiscard]] constexpr std::optional<std::size_t> dequeue_ready_slot(
    SlotRange &slots,
    const bool prefer_newest
  ) noexcept {
    std::optional<std::size_t> selected;
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
      if (slots[slot].state == slot_state_e::ready &&
          (!selected ||
           (prefer_newest ?
              slots[slot].sequence > slots[*selected].sequence :
              slots[slot].sequence < slots[*selected].sequence))) {
        selected = slot;
      }
    }
    if (!selected) {
      return std::nullopt;
    }

    slots[*selected].state = slot_state_e::acquired;
    if (prefer_newest) {
      for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        if (slot != *selected && slots[slot].state == slot_state_e::ready) {
          slots[slot].state = slot_state_e::discarded_ready;
        }
      }
    }
    return selected;
  }

  /** Complete one write without ever recycling an unproven GPU submission. */
  [[nodiscard]] constexpr slot_state_e complete_write(submission_result_e result) noexcept {
    return result == submission_result_e::success ? slot_state_e::ready : slot_state_e::quarantined;
  }
}  // namespace lumen::vdd::frame

#endif  // LUMEN_PLATFORM_WINDOWS_DIRECT_FRAME_SLOT_POLICY_H
