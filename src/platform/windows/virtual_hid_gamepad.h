/**
 * @file src/platform/windows/virtual_hid_gamepad.h
 * @brief Lumen dynamic VHF gamepad state and feedback adapter.
 */
#pragma once

// local includes
#include "gamepad_router.h"
#include "libvirtualhid_gamepad_core.h"
#include "virtual_hid_session.h"

// standard includes
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

namespace platf::win_gamepad {

  /**
   * @brief One dynamic VHF device backed by the approved portable report core.
   */
  class virtual_hid_gamepad_t final: public backend_t {
  public:
    virtual_hid_gamepad_t(const virtual_hid_gamepad_t &) = delete;
    virtual_hid_gamepad_t &operator=(const virtual_hid_gamepad_t &) = delete;
    virtual_hid_gamepad_t(virtual_hid_gamepad_t &&) = delete;
    virtual_hid_gamepad_t &operator=(virtual_hid_gamepad_t &&) = delete;

    /**
     * @brief Neutralize and destroy the device if the router did not already close it.
     */
    ~virtual_hid_gamepad_t() override;

    /**
     * @brief Create a dynamic VHF backend for a router slot.
     *
     * @param session Validated dynamic-gamepad driver session.
     * @param profile Selected modern HID profile.
     * @param id Global and client-relative gamepad identifiers.
     * @param metadata Client-reported capabilities.
     * @param feedback_queue Stream feedback queue.
     * @param generation Router slot generation.
     * @return Router factory result preserving the visibility boundary.
     */
    static create_result_t create(
      std::shared_ptr<virtual_hid_session_t> session,
      profile_kind_e profile,
      const gamepad_id_t &id,
      const gamepad_arrival_t &metadata,
      feedback_queue_t feedback_queue,
      std::uint64_t generation
    );

    backend_kind_e kind() const noexcept override;
    profile_kind_e profile() const noexcept override;
    backend_identity_t identity() const noexcept override;
    bool update(const gamepad_state_t &state) override;
    bool touch(const gamepad_touch_t &touch) override;
    bool motion(const gamepad_motion_t &motion) override;
    bool battery(const gamepad_battery_t &battery) override;
    void close() noexcept override;

    /**
     * @brief Return a thread-safe copy of the retained complete normalized state.
     *
     * @return Complete state, including auxiliary motion, touch, and battery fields.
     */
    lvh_core::normalized_state_t state_snapshot() const;

  private:
    /**
     * @brief Feedback/output state that remains valid through callback drain.
     */
    struct feedback_state_t;

    /**
     * @brief Construct an already-created dynamic gamepad.
     *
     * @param session Owning dynamic-gamepad session.
     * @param device Driver-created device metadata.
     * @param definition Canonical portable profile definition.
     * @param feedback Shared feedback routing state.
     * @param generation Router slot generation.
     */
    virtual_hid_gamepad_t(
      std::shared_ptr<virtual_hid_session_t> session,
      session_device_t device,
      lvh_core::profile_definition_t definition,
      std::shared_ptr<feedback_state_t> feedback,
      std::uint64_t generation
    );

    /**
     * @brief Pack and submit the complete cached state while `state_mutex_` is held.
     *
     * @return `true` when the driver accepted the full report.
     */
    bool submit_state_locked();

    /**
     * @brief Convert a profile kind to the additive driver ABI value.
     *
     * @param profile Lumen profile kind.
     * @return LUMEN_VHID_GAMEPAD_PROFILE_* value.
     */
    static std::uint32_t protocol_profile(profile_kind_e profile);

    /**
     * @brief Convert one signed GameStream axis to `[-1, 1]`.
     *
     * @param value Signed 16-bit axis.
     * @return Normalized axis.
     */
    static float normalize_axis(std::int16_t value);

    /**
     * @brief Convert one unsigned GameStream trigger to `[0, 1]`.
     *
     * @param value Unsigned 8-bit trigger.
     * @return Normalized trigger.
     */
    static float normalize_trigger(std::uint8_t value);

    std::shared_ptr<virtual_hid_session_t> session_;  ///< Shared dynamic-gamepad driver session.
    session_device_t device_;  ///< Exact authenticated driver generation.
    lvh_core::profile_definition_t definition_;  ///< Portable profile/report codec definition.
    std::shared_ptr<feedback_state_t> feedback_;  ///< Output routing and deduplication state.
    std::uint64_t generation_ {};  ///< Router slot generation.
    mutable std::mutex state_mutex_;  ///< Protects complete cached input state.
    lvh_core::normalized_state_t state_;  ///< Complete retained input state.
    std::array<std::optional<std::uint32_t>, 2> touch_ids_;  ///< Client contact IDs assigned to two HID contacts.
    std::atomic_bool closed_ {};  ///< Idempotent close fence.
  };

  /**
   * @brief Build a router factory bound to a shared dynamic-gamepad session.
   *
   * @param session Validated session, which may be unavailable for fallback decisions.
   * @return Router-compatible VHF backend factory.
   */
  backend_factory_t make_virtual_hid_gamepad_factory(std::shared_ptr<virtual_hid_session_t> session);

}  // namespace platf::win_gamepad
