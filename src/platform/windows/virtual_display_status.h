/**
 * @file src/platform/windows/virtual_display_status.h
 * @brief Read-only Lumen virtual-display health and active-path diagnostics.
 */
#pragma once

#include "virtual_display.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace platf::virtual_display {
  /** @brief Exact active VDD generation and mode reported by the driver. */
  struct active_display_status_t {
    std::uint64_t generation {};  ///< Nonzero active driver generation.
    mode_t mode;  ///< Exact mode retained by the active generation.
    delivery_policy_e delivery_policy;  ///< Exact active policy returned by the driver.
  };

  /** @brief Stable capture-path classification for one current VDD generation. */
  enum class capture_path_status_e {
    inactive,  ///< No VDD generation is active.
    direct,  ///< The active generation owns a healthy direct-frame source.
    fallback,  ///< The active generation explicitly uses desktop capture.
    quarantined,  ///< Direct-frame capture failed and the generation is quarantined.
    unavailable,  ///< A generation is active but no capture path is bound.
  };

  /** @brief Return the stable authenticated-status value for a capture-path classification. */
  [[nodiscard]] constexpr std::string_view capture_path_status_name(
    const capture_path_status_e status
  ) noexcept {
    switch (status) {
      case capture_path_status_e::inactive:
        return "inactive";
      case capture_path_status_e::direct:
        return "direct";
      case capture_path_status_e::fallback:
        return "fallback";
      case capture_path_status_e::quarantined:
        return "quarantined";
      case capture_path_status_e::unavailable:
        return "unavailable";
    }
    return "unavailable";
  }

  /** @brief Read-only host and driver state exposed to the authenticated dashboard. */
  struct system_status_t {
    bool installed {};  ///< Whether Windows enumerates a present Lumen VDD device.
    bool compatible {};  ///< Whether the secured control channel accepts the current ABI.
    bool device_healthy {};  ///< Whether Windows reports the device started without a problem.
    std::optional<std::uint32_t> device_problem;  ///< Windows Configuration Manager problem code, when present.
    std::optional<active_display_status_t> active;  ///< Exact active generation, or empty while inactive.
    bool direct_frame_bound {};  ///< Whether this process owns a healthy direct-frame source for `active`.
    bool direct_frame_quarantined {};  ///< Whether a runtime failure disabled direct frames for `active`.
    bool fallback {};  ///< Whether the active VDD generation is using desktop capture instead of direct frames.
    capture_path_status_e capture_path {capture_path_status_e::inactive};  ///< Typed capture availability for API consumers.
    std::string diagnostic;  ///< Concise operator-facing health or recovery message.
  };

  /** @brief Direct-frame state correlated to one exact VDD generation. */
  struct direct_frame_generation_status_t {
    bool bound {};  ///< A healthy direct-frame source is retained for the requested generation.
    bool quarantined {};  ///< That generation stopped after a direct-frame runtime failure.
    bool fallback {};  ///< That generation explicitly failed direct-frame initialization.
  };

  /**
   * @brief Classify active capture availability without treating an unbound generation as healthy.
   * @param active Whether the driver reports an active monitor generation.
   * @param direct Exact process-local direct-frame state for that generation.
   * @return Stable capture-path status.
   */
  [[nodiscard]] constexpr capture_path_status_e classify_capture_path(
    const bool active,
    const direct_frame_generation_status_t direct
  ) noexcept {
    if (!active) {
      return capture_path_status_e::inactive;
    }
    if (direct.quarantined) {
      return capture_path_status_e::quarantined;
    }
    if (direct.bound) {
      return capture_path_status_e::direct;
    }
    if (direct.fallback) {
      return capture_path_status_e::fallback;
    }
    return capture_path_status_e::unavailable;
  }

  /**
   * @brief Record successful direct-frame ownership for one exact generation.
   * @param generation Active nonzero VDD generation.
   */
  void report_direct_frame_bound(std::uint64_t generation) noexcept;

  /**
   * @brief Record an explicit direct-frame initialization failure for one generation.
   * @param generation Active nonzero VDD generation using desktop capture when policy permits.
   */
  void report_direct_frame_fallback(std::uint64_t generation) noexcept;

  /**
   * @brief Record source teardown for an exact generation without allowing an older source to clear a newer one.
   * @param generation VDD generation whose source stopped.
   * @param quarantined Whether a runtime failure quarantined this generation.
   */
  void report_direct_frame_stopped(std::uint64_t generation, bool quarantined) noexcept;

  /** @brief Mark the currently bound generation quarantined before its source teardown completes. */
  void report_direct_frame_quarantined() noexcept;

  /**
   * @brief Return direct-frame state only when it matches an exact active generation.
   * @param generation Active VDD generation to match.
   * @return Exact matching state, or an empty state for zero/stale generations.
   */
  [[nodiscard]] direct_frame_generation_status_t direct_frame_status_for_generation(
    std::uint64_t generation
  ) noexcept;

  /**
   * @brief Query installed-device, ABI, active-mode, and capture-path status without mutation.
   * @return Current real VDD status.
   */
  [[nodiscard]] system_status_t query_system_status();
}  // namespace platf::virtual_display
