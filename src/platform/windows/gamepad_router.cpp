/**
 * @file src/platform/windows/gamepad_router.cpp
 * @brief Tagged Windows virtual-gamepad backend routing definitions.
 */

// local includes
#include "gamepad_router.h"

namespace platf::win_gamepad {
  namespace {

    /**
     * @brief Parse a configured explicit profile.
     *
     * @param name Configured profile name.
     * @param profile Receives the parsed profile.
     * @return `true` when `name` is a known explicit profile.
     */
    bool parse_profile(std::string_view name, profile_kind_e &profile) {
      if (name == "generic") {
        profile = profile_kind_e::generic;
      } else if (name == "x360") {
        profile = profile_kind_e::xbox_360;
      } else if (name == "xone") {
        profile = profile_kind_e::xbox_one;
      } else if (name == "xseries") {
        profile = profile_kind_e::xbox_series;
      } else if (name == "ds4") {
        profile = profile_kind_e::dualshock4;
      } else if (name == "ds5") {
        profile = profile_kind_e::dualsense;
      } else if (name == "switch") {
        profile = profile_kind_e::switch_pro;
      } else {
        return false;
      }
      return true;
    }

    /**
     * @brief Select an automatic profile from client metadata.
     *
     * @param metadata Client-reported controller metadata.
     * @param force_virtual_hid Whether the caller explicitly requires VHF.
     * @return Automatically selected profile.
     */
    profile_kind_e automatic_profile(const gamepad_arrival_t &metadata, bool force_virtual_hid) {
      if (metadata.type == LI_CTYPE_PS) {
        return profile_kind_e::dualsense;
      }
      if (metadata.type == LI_CTYPE_NINTENDO) {
        return profile_kind_e::switch_pro;
      }
      if (force_virtual_hid) {
        return profile_kind_e::xbox_one;
      }
      return profile_kind_e::xbox_360;
    }

    /**
     * @brief Check whether a profile is the ViGEm-only XUSB profile.
     *
     * @param profile Profile to test.
     * @return `true` only for Xbox 360.
     */
    bool is_xusb(profile_kind_e profile) {
      return profile == profile_kind_e::xbox_360;
    }

  }  // namespace

  bool select_route(
    std::string_view requested_profile,
    std::string_view requested_backend,
    const gamepad_arrival_t &metadata,
    route_t &route,
    std::string &error
  ) {
    error.clear();
    const bool automatic = requested_profile == "auto";
    const bool force_virtual_hid = requested_backend == "virtualhid";
    const bool force_vigem = requested_backend == "vigem";
    if (!force_virtual_hid && !force_vigem && requested_backend != "auto") {
      error = "unknown Windows gamepad backend";
      return false;
    }

    if (automatic) {
      route.profile = force_vigem ? profile_kind_e::xbox_360 : automatic_profile(metadata, force_virtual_hid);
    } else if (!parse_profile(requested_profile, route.profile)) {
      error = "unknown gamepad profile";
      return false;
    }

    if (is_xusb(route.profile)) {
      if (force_virtual_hid) {
        error = "Xbox 360 requires the ViGEm/XInput backend";
        return false;
      }
      route.backend = backend_kind_e::vigem;
    } else {
      if (force_vigem) {
        error = "the selected modern HID profile requires Lumen Virtual HID";
        return false;
      }
      route.backend = backend_kind_e::virtual_hid;
    }

    route.allow_pre_visibility_fallback = automatic && requested_backend == "auto" && route.backend == backend_kind_e::virtual_hid;
    return true;
  }

  router_t::router_t(backend_factory_t virtual_hid_factory, backend_factory_t vigem_factory):
      virtual_hid_factory_ {std::move(virtual_hid_factory)},
      vigem_factory_ {std::move(vigem_factory)} {
  }

  router_t::~router_t() {
    for (int index = 0; index < static_cast<int>(slots_.size()); ++index) {
      free(index);
    }
  }

  bool router_t::allocate(
    const gamepad_id_t &id,
    const gamepad_arrival_t &metadata,
    std::string_view requested_profile,
    std::string_view requested_backend,
    feedback_queue_t feedback_queue,
    std::string &error
  ) {
    std::lock_guard lock(mutex_);
    auto *target = slot(id.globalIndex);
    if (!target) {
      error = "global gamepad slot is out of range";
      return false;
    }
    if (target->backend || target->closing) {
      error = "global gamepad slot already has a live backend";
      return false;
    }

    route_t route;
    if (!select_route(requested_profile, requested_backend, metadata, route, error)) {
      return false;
    }

    ++target->generation;
    target->profile = route.profile;
    target->accepted_state = false;

    const auto create = [&](backend_kind_e kind, profile_kind_e profile) {
      if (kind == backend_kind_e::virtual_hid) {
        if (!virtual_hid_factory_) {
          return create_result_t {
            .backend = {},
            .became_visible = false,
            .error = "Lumen Virtual HID factory is unavailable",
          };
        }
        return virtual_hid_factory_(profile, id, metadata, feedback_queue, target->generation);
      }
      if (!vigem_factory_) {
        return create_result_t {
          .backend = {},
          .became_visible = false,
          .error = "ViGEm factory is unavailable",
        };
      }
      return vigem_factory_(profile, id, metadata, feedback_queue, target->generation);
    };

    auto selected_backend = route.backend;
    auto result = create(selected_backend, route.profile);
    if (!result && route.allow_pre_visibility_fallback && !result.became_visible) {
      const auto primary_error = result.error.empty() ? "Lumen Virtual HID creation failed" : result.error;
      auto fallback = create(backend_kind_e::vigem, profile_kind_e::xbox_360);
      if (fallback) {
        result = std::move(fallback);
        selected_backend = backend_kind_e::vigem;
        target->profile = profile_kind_e::xbox_360;
        error = primary_error + "; using Xbox 360 through ViGEm before device visibility";
      } else {
        error = primary_error + "; ViGEm fallback failed: " + fallback.error;
        return false;
      }
    }

    if (!result) {
      error = result.error.empty() ? "gamepad backend creation failed" : std::move(result.error);
      return false;
    }
    if (result.backend->kind() != selected_backend) {
      result.backend->close();
      error = "backend factory returned a conflicting transport";
      return false;
    }
    if (result.backend->profile() != target->profile) {
      result.backend->close();
      error = "backend factory returned a conflicting controller profile";
      return false;
    }

    target->backend = std::move(result.backend);
    return true;
  }

  void router_t::free(int global_index) noexcept {
    std::lock_guard lock(mutex_);
    auto *target = slot(global_index);
    if (!target || target->closing) {
      return;
    }
    if (!target->backend) {
      return;
    }

    target->closing = true;
    ++target->generation;
    target->backend->close();
    target->backend.reset();
    target->accepted_state = false;
    target->closing = false;
  }

  bool router_t::update(int global_index, const gamepad_state_t &state) {
    std::lock_guard lock(mutex_);
    auto *target = slot(global_index);
    if (!target || !target->backend || target->closing) {
      return false;
    }
    const bool accepted = target->backend->update(state);
    target->accepted_state = target->accepted_state || accepted;
    return accepted;
  }

  bool router_t::touch(const gamepad_touch_t &touch_event) {
    std::lock_guard lock(mutex_);
    auto *target = slot(touch_event.id.globalIndex);
    if (!target || !target->backend || target->closing) {
      return false;
    }
    const bool accepted = target->backend->touch(touch_event);
    target->accepted_state = target->accepted_state || accepted;
    return accepted;
  }

  bool router_t::motion(const gamepad_motion_t &motion_event) {
    std::lock_guard lock(mutex_);
    auto *target = slot(motion_event.id.globalIndex);
    if (!target || !target->backend || target->closing) {
      return false;
    }
    const bool accepted = target->backend->motion(motion_event);
    target->accepted_state = target->accepted_state || accepted;
    return accepted;
  }

  bool router_t::battery(const gamepad_battery_t &battery_event) {
    std::lock_guard lock(mutex_);
    auto *target = slot(battery_event.id.globalIndex);
    if (!target || !target->backend || target->closing) {
      return false;
    }
    const bool accepted = target->backend->battery(battery_event);
    target->accepted_state = target->accepted_state || accepted;
    return accepted;
  }

  slot_snapshot_t router_t::snapshot(int global_index) const {
    std::lock_guard lock(mutex_);
    const auto *target = slot(global_index);
    if (!target) {
      return {};
    }
    slot_snapshot_t result {
      .profile = target->profile,
      .generation = target->generation,
      .identity = {},
      .accepted_state = target->accepted_state,
      .closing = target->closing,
    };
    if (target->backend) {
      result.backend = target->backend->kind();
      result.profile = target->backend->profile();
      result.identity = target->backend->identity();
    }
    return result;
  }

  router_t::slot_t *router_t::slot(int global_index) noexcept {
    if (global_index < 0 || global_index >= static_cast<int>(slots_.size())) {
      return nullptr;
    }
    return &slots_[global_index];
  }

  const router_t::slot_t *router_t::slot(int global_index) const noexcept {
    if (global_index < 0 || global_index >= static_cast<int>(slots_.size())) {
      return nullptr;
    }
    return &slots_[global_index];
  }

}  // namespace platf::win_gamepad
