/**
 * @file src/platform/windows/gamepad_router.h
 * @brief Tagged Windows virtual-gamepad backend routing.
 */
#pragma once

// standard includes
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

// local includes
#include "gamepad_profile.h"
#include "src/platform/common.h"

namespace platf::win_gamepad {

  /**
   * @brief Concrete transport owning a global Windows gamepad slot.
   */
  enum class backend_kind_e {
    none,  ///< No virtual device exists for the slot.
    virtual_hid,  ///< Lumen's dynamic VHF gamepad transport.
    vigem,  ///< ViGEm-backed Xbox 360 XInput transport.
  };

  /**
   * @brief Driver identity scoped to one slot generation.
   */
  struct backend_identity_t {
    std::uint64_t device_id {};  ///< Driver-assigned dynamic device identifier.
    std::array<std::uint8_t, 32> token {};  ///< Driver session token; zero for ViGEm.
  };

  /**
   * @brief Result returned by a backend creation factory.
   */
  struct create_result_t;

  /**
   * @brief Abstract live backend stored by the tagged router.
   */
  class backend_t {
  public:
    backend_t() = default;
    backend_t(const backend_t &) = delete;
    backend_t &operator=(const backend_t &) = delete;
    backend_t(backend_t &&) = delete;
    backend_t &operator=(backend_t &&) = delete;

    /**
     * @brief Destroy the backend after derived teardown completes.
     */
    virtual ~backend_t() = default;

    /**
     * @brief Return the concrete backend discriminator.
     *
     * @return Concrete backend kind.
     */
    virtual backend_kind_e kind() const noexcept = 0;

    /**
     * @brief Return the emulated controller profile.
     *
     * @return Controller profile kind.
     */
    virtual profile_kind_e profile() const noexcept = 0;

    /**
     * @brief Return the backend driver identity.
     *
     * @return Device ID and token for the active generation.
     */
    virtual backend_identity_t identity() const noexcept = 0;

    /**
     * @brief Submit ordinary buttons, sticks, and triggers.
     *
     * @param state Current GameStream controller state.
     * @return `true` when the backend accepted the complete state.
     */
    virtual bool update(const gamepad_state_t &state) = 0;

    /**
     * @brief Submit a controller touchpad event.
     *
     * @param touch Touchpad event.
     * @return `true` when the event was accepted or intentionally unsupported.
     */
    virtual bool touch(const gamepad_touch_t &touch) = 0;

    /**
     * @brief Submit a controller motion event.
     *
     * @param motion Motion sensor sample.
     * @return `true` when the event was accepted or intentionally unsupported.
     */
    virtual bool motion(const gamepad_motion_t &motion) = 0;

    /**
     * @brief Submit controller battery metadata.
     *
     * @param battery Battery event.
     * @return `true` when the event was accepted or intentionally unsupported.
     */
    virtual bool battery(const gamepad_battery_t &battery) = 0;

    /**
     * @brief Neutralize, destroy, and drain the backend.
     */
    virtual void close() noexcept = 0;
  };

  /**
   * @brief Result returned by a backend creation factory.
   */
  struct create_result_t {
    std::unique_ptr<backend_t> backend;  ///< Live backend on success.
    bool became_visible {};  ///< Whether a failed creation exposed an OS device.
    std::string error;  ///< Diagnostic text when creation failed.

    /**
     * @brief Check whether creation produced a live backend.
     *
     * @return `true` when `backend` owns a live device.
     */
    explicit operator bool() const noexcept {
      return backend != nullptr;
    }
  };

  /**
   * @brief Factory invoked after the router has selected a profile and backend.
   */
  using backend_factory_t = std::function<create_result_t(
    profile_kind_e profile,
    const gamepad_id_t &id,
    const gamepad_arrival_t &metadata,
    feedback_queue_t feedback_queue,
    std::uint64_t generation
  )>;

  /**
   * @brief Immutable route selected for a new controller.
   */
  struct route_t {
    backend_kind_e backend {backend_kind_e::none};  ///< Required backend.
    profile_kind_e profile {profile_kind_e::xbox_360};  ///< Required profile.
    bool allow_pre_visibility_fallback {};  ///< Whether auto may try X360 ViGEm before exposure.
  };

  /**
   * @brief Public state snapshot used for diagnostics and tests.
   */
  struct slot_snapshot_t {
    backend_kind_e backend {backend_kind_e::none};  ///< Active backend discriminator.
    profile_kind_e profile {profile_kind_e::xbox_360};  ///< Active profile.
    std::uint64_t generation {};  ///< Monotonic slot generation.
    backend_identity_t identity;  ///< Backend identity scoped to `generation`.
    bool accepted_state {};  ///< Whether this generation accepted client state.
    bool closing {};  ///< Whether teardown is in progress.
  };

  /**
   * @brief Select a profile and backend without creating a device.
   *
   * @param requested_profile Configured profile name.
   * @param requested_backend Configured backend name.
   * @param metadata Client-reported controller metadata.
   * @param route Receives the selected route.
   * @param error Receives a diagnostic when the combination is invalid.
   * @return `true` when the combination selects a valid route.
   */
  bool select_route(
    std::string_view requested_profile,
    std::string_view requested_backend,
    const gamepad_arrival_t &metadata,
    route_t &route,
    std::string &error
  );

  /**
   * @brief Own exactly one tagged virtual-gamepad backend per global slot.
   */
  class router_t {
  public:
    /**
     * @brief Construct an empty router with the supplied backend factories.
     *
     * @param virtual_hid_factory Dynamic VHF backend factory.
     * @param vigem_factory ViGEm Xbox 360 backend factory.
     */
    router_t(backend_factory_t virtual_hid_factory, backend_factory_t vigem_factory);

    router_t(const router_t &) = delete;
    router_t &operator=(const router_t &) = delete;
    router_t(router_t &&) = delete;
    router_t &operator=(router_t &&) = delete;

    /**
     * @brief Neutralize and destroy every live backend.
     */
    ~router_t();

    /**
     * @brief Allocate a new backend for a currently empty global slot.
     *
     * @param id Global and client-relative slot identifiers.
     * @param metadata Client-reported capabilities.
     * @param requested_profile Configured controller profile.
     * @param requested_backend Configured Windows backend.
     * @param feedback_queue Stream feedback queue.
     * @param error Receives a diagnostic on failure.
     * @return `true` when exactly one live backend owns the slot.
     */
    bool allocate(
      const gamepad_id_t &id,
      const gamepad_arrival_t &metadata,
      std::string_view requested_profile,
      std::string_view requested_backend,
      feedback_queue_t feedback_queue,
      std::string &error
    );

    /**
     * @brief Neutralize, destroy, and drain one slot.
     *
     * @param global_index Global gamepad slot.
     */
    void free(int global_index) noexcept;

    /**
     * @brief Route an ordinary state update to the active backend.
     *
     * @param global_index Global gamepad slot.
     * @param state Current buttons, sticks, and triggers.
     * @return `true` when the active generation accepted the update.
     */
    bool update(int global_index, const gamepad_state_t &state);

    /**
     * @brief Route a touchpad event to the active backend.
     *
     * @param touch Controller touch event.
     * @return `true` when the active generation accepted the event.
     */
    bool touch(const gamepad_touch_t &touch);

    /**
     * @brief Route a motion event to the active backend.
     *
     * @param motion Controller motion event.
     * @return `true` when the active generation accepted the event.
     */
    bool motion(const gamepad_motion_t &motion);

    /**
     * @brief Route battery metadata to the active backend.
     *
     * @param battery Controller battery event.
     * @return `true` when the active generation accepted the event.
     */
    bool battery(const gamepad_battery_t &battery);

    /**
     * @brief Read a consistent snapshot of one global slot.
     *
     * @param global_index Global gamepad slot.
     * @return Snapshot; an out-of-range slot returns the default empty state.
     */
    slot_snapshot_t snapshot(int global_index) const;

  private:
    /**
     * @brief Mutable state for one global gamepad slot.
     */
    struct slot_t {
      std::unique_ptr<backend_t> backend;  ///< Exactly one backend, or null.
      profile_kind_e profile {profile_kind_e::xbox_360};  ///< Selected profile.
      std::uint64_t generation {};  ///< Monotonic slot generation.
      bool accepted_state {};  ///< Whether an input operation succeeded.
      bool closing {};  ///< Teardown fence.
    };

    /**
     * @brief Return a mutable in-range slot.
     *
     * @param global_index Global gamepad slot.
     * @return Slot pointer, or null when out of range.
     */
    slot_t *slot(int global_index) noexcept;

    /**
     * @brief Return an immutable in-range slot.
     *
     * @param global_index Global gamepad slot.
     * @return Slot pointer, or null when out of range.
     */
    const slot_t *slot(int global_index) const noexcept;

    std::array<slot_t, MAX_GAMEPADS> slots_;  ///< Tagged global slot table.
    backend_factory_t virtual_hid_factory_;  ///< Dynamic VHF backend factory.
    backend_factory_t vigem_factory_;  ///< ViGEm X360 backend factory.
    mutable std::mutex mutex_;  ///< Serializes allocation, dispatch, teardown, and snapshots.
  };

}  // namespace platf::win_gamepad
