/**
 * @file src/platform/windows/libvirtualhid_gamepad_core.cpp
 * @brief Lumen-owned gamepad-only facade over libvirtualhid's portable core.
 */

// local includes
#include "src/platform/windows/libvirtualhid_gamepad_core.h"

// libvirtualhid includes
#include <libvirtualhid/profiles.hpp>
#include <libvirtualhid/report.hpp>
#include <libvirtualhid/types.hpp>

// Approved private Windows helpers
#include "generic_pid_protocol.hpp"
#include "generic_pid_rumble.hpp"

namespace platf::win_gamepad::lvh_core {
  namespace {

    static_assert(static_cast<std::uint8_t>(button_e::a) == static_cast<std::uint8_t>(lvh::GamepadButton::a));
    static_assert(static_cast<std::uint8_t>(button_e::b) == static_cast<std::uint8_t>(lvh::GamepadButton::b));
    static_assert(static_cast<std::uint8_t>(button_e::x) == static_cast<std::uint8_t>(lvh::GamepadButton::x));
    static_assert(static_cast<std::uint8_t>(button_e::y) == static_cast<std::uint8_t>(lvh::GamepadButton::y));
    static_assert(static_cast<std::uint8_t>(button_e::back) == static_cast<std::uint8_t>(lvh::GamepadButton::back));
    static_assert(static_cast<std::uint8_t>(button_e::start) == static_cast<std::uint8_t>(lvh::GamepadButton::start));
    static_assert(static_cast<std::uint8_t>(button_e::guide) == static_cast<std::uint8_t>(lvh::GamepadButton::guide));
    static_assert(static_cast<std::uint8_t>(button_e::left_stick) == static_cast<std::uint8_t>(lvh::GamepadButton::left_stick));
    static_assert(static_cast<std::uint8_t>(button_e::right_stick) == static_cast<std::uint8_t>(lvh::GamepadButton::right_stick));
    static_assert(static_cast<std::uint8_t>(button_e::left_shoulder) == static_cast<std::uint8_t>(lvh::GamepadButton::left_shoulder));
    static_assert(static_cast<std::uint8_t>(button_e::right_shoulder) == static_cast<std::uint8_t>(lvh::GamepadButton::right_shoulder));
    static_assert(static_cast<std::uint8_t>(button_e::dpad_up) == static_cast<std::uint8_t>(lvh::GamepadButton::dpad_up));
    static_assert(static_cast<std::uint8_t>(button_e::dpad_down) == static_cast<std::uint8_t>(lvh::GamepadButton::dpad_down));
    static_assert(static_cast<std::uint8_t>(button_e::dpad_left) == static_cast<std::uint8_t>(lvh::GamepadButton::dpad_left));
    static_assert(static_cast<std::uint8_t>(button_e::dpad_right) == static_cast<std::uint8_t>(lvh::GamepadButton::dpad_right));
    static_assert(static_cast<std::uint8_t>(button_e::misc1) == static_cast<std::uint8_t>(lvh::GamepadButton::misc1));
    static_assert(static_cast<std::uint8_t>(button_e::touchpad) == static_cast<std::uint8_t>(lvh::GamepadButton::touchpad));
    static_assert(static_cast<std::uint8_t>(button_e::paddle1) == static_cast<std::uint8_t>(lvh::GamepadButton::paddle1));
    static_assert(static_cast<std::uint8_t>(button_e::paddle2) == static_cast<std::uint8_t>(lvh::GamepadButton::paddle2));
    static_assert(static_cast<std::uint8_t>(button_e::paddle3) == static_cast<std::uint8_t>(lvh::GamepadButton::paddle3));
    static_assert(static_cast<std::uint8_t>(button_e::paddle4) == static_cast<std::uint8_t>(lvh::GamepadButton::paddle4));

    static_assert(static_cast<std::uint8_t>(battery_state_e::unknown) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::unknown));
    static_assert(static_cast<std::uint8_t>(battery_state_e::discharging) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::discharging));
    static_assert(static_cast<std::uint8_t>(battery_state_e::charging) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::charging));
    static_assert(static_cast<std::uint8_t>(battery_state_e::full) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::full));
    static_assert(static_cast<std::uint8_t>(battery_state_e::voltage_or_temperature_error) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::voltage_or_temperature_error));
    static_assert(static_cast<std::uint8_t>(battery_state_e::temperature_error) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::temperature_error));
    static_assert(static_cast<std::uint8_t>(battery_state_e::charging_error) == static_cast<std::uint8_t>(lvh::GamepadBatteryState::charging_error));

    static_assert(static_cast<std::uint8_t>(output_kind_e::rumble) == static_cast<std::uint8_t>(lvh::GamepadOutputKind::rumble));
    static_assert(static_cast<std::uint8_t>(output_kind_e::rgb_led) == static_cast<std::uint8_t>(lvh::GamepadOutputKind::rgb_led));
    static_assert(static_cast<std::uint8_t>(output_kind_e::adaptive_triggers) == static_cast<std::uint8_t>(lvh::GamepadOutputKind::adaptive_triggers));
    static_assert(static_cast<std::uint8_t>(output_kind_e::raw_report) == static_cast<std::uint8_t>(lvh::GamepadOutputKind::raw_report));
    static_assert(static_cast<std::uint8_t>(output_kind_e::trigger_rumble) == static_cast<std::uint8_t>(lvh::GamepadOutputKind::trigger_rumble));

    /**
     * @brief Select an upstream gamepad profile without exposing non-gamepad factories.
     *
     * @param kind Selected Lumen gamepad profile.
     * @return Matching upstream portable profile.
     */
    lvh::DeviceProfile upstream_profile(profile_kind_e kind) {
      lvh::DeviceProfile result;
      switch (kind) {
        case profile_kind_e::generic:
          result = lvh::profiles::generic_gamepad();
          result.report_descriptor = lvh::detail::windows::make_generic_pid_report_descriptor(result.report_descriptor);
          result.output_report_size = lvh::detail::windows::generic_pid_output_report_size;
          break;
        case profile_kind_e::xbox_360:
          result = lvh::profiles::xbox_360();
          break;
        case profile_kind_e::xbox_one:
          result = lvh::profiles::xbox_one();
          break;
        case profile_kind_e::xbox_series:
          result = lvh::profiles::xbox_series();
          result.version = 0x0509U;
          break;
        case profile_kind_e::dualshock4:
          result = lvh::profiles::dualshock4_usb();
          break;
        case profile_kind_e::dualsense:
          result = lvh::profiles::dualsense_usb();
          break;
        case profile_kind_e::switch_pro:
          result = lvh::profiles::switch_pro();
          break;
      }
      return result;
    }

    /**
     * @brief Check that a caller-provided definition retains its expected identity.
     *
     * @param definition Lumen profile definition to validate.
     * @param upstream Reference upstream profile.
     * @return `true` when compatibility-critical fields match.
     */
    bool matches_profile(const profile_definition_t &definition, const lvh::DeviceProfile &upstream) {
      return definition.vendor_id == upstream.vendor_id &&
             definition.product_id == upstream.product_id &&
             definition.version == upstream.version &&
             definition.report_id == upstream.report_id &&
             definition.input_size == upstream.input_report_size &&
             definition.output_size == upstream.output_report_size &&
             definition.descriptor == upstream.report_descriptor;
    }

    /**
     * @brief Convert Lumen's retained state into libvirtualhid's portable model.
     *
     * @param state Lumen-owned normalized gamepad state.
     * @return Equivalent upstream state.
     */
    lvh::GamepadState upstream_state(const normalized_state_t &state) {
      lvh::GamepadState result;
      for (std::uint8_t index = 0; index <= static_cast<std::uint8_t>(button_e::paddle4); ++index) {
        const auto button = static_cast<button_e>(index);
        result.buttons.set(static_cast<lvh::GamepadButton>(index), (state.buttons & button_bit(button)) != 0U);
      }
      result.left_stick = {.x = state.left_stick.x, .y = state.left_stick.y};
      result.right_stick = {.x = state.right_stick.x, .y = state.right_stick.y};
      result.left_trigger = state.left_trigger;
      result.right_trigger = state.right_trigger;
      if (state.acceleration) {
        result.acceleration = lvh::Vector3 {
          .x = state.acceleration->x,
          .y = state.acceleration->y,
          .z = state.acceleration->z,
        };
      }
      if (state.gyroscope) {
        result.gyroscope = lvh::Vector3 {
          .x = state.gyroscope->x,
          .y = state.gyroscope->y,
          .z = state.gyroscope->z,
        };
      }
      if (state.battery) {
        result.battery = lvh::GamepadBattery {
          .state = static_cast<lvh::GamepadBatteryState>(state.battery->state),
          .percentage = state.battery->percentage,
        };
      }
      for (std::size_t index = 0; index < state.touchpad_contacts.size(); ++index) {
        result.touchpad_contacts[index] = {
          .id = state.touchpad_contacts[index].id,
          .active = state.touchpad_contacts[index].active,
          .x = state.touchpad_contacts[index].x,
          .y = state.touchpad_contacts[index].y,
        };
      }
      return result;
    }

    /**
     * @brief Convert one upstream output into Lumen's private model.
     *
     * @param output Upstream portable output event.
     * @return Equivalent Lumen-owned event.
     */
    output_t lumen_output(const lvh::GamepadOutput &output) {
      return {
        .kind = static_cast<output_kind_e>(output.kind),
        .low_frequency_rumble = output.low_frequency_rumble,
        .high_frequency_rumble = output.high_frequency_rumble,
        .left_trigger_rumble = output.left_trigger_rumble,
        .right_trigger_rumble = output.right_trigger_rumble,
        .red = output.red,
        .green = output.green,
        .blue = output.blue,
        .adaptive_trigger_flags = output.adaptive_trigger_flags,
        .left_trigger_effect_type = output.left_trigger_effect_type,
        .right_trigger_effect_type = output.right_trigger_effect_type,
        .left_trigger_effect = output.left_trigger_effect,
        .right_trigger_effect = output.right_trigger_effect,
        .raw_report = output.raw_report,
      };
    }

  }  // namespace

  class generic_pid_rumble_t::impl_t {
  public:
    lvh::detail::windows::GenericPidRumbleState state;  ///< Approved private PID state.
  };

  generic_pid_rumble_t::generic_pid_rumble_t():
      impl_ {std::make_unique<impl_t>()} {
  }

  generic_pid_rumble_t::generic_pid_rumble_t(generic_pid_rumble_t &&other) noexcept = default;

  generic_pid_rumble_t &generic_pid_rumble_t::operator=(generic_pid_rumble_t &&other) noexcept = default;

  generic_pid_rumble_t::~generic_pid_rumble_t() = default;

  pid_rumble_update_t generic_pid_rumble_t::handle_output_report(
    std::span<const std::uint8_t> report,
    time_point_t now
  ) {
    if (!impl_) {
      return {};
    }
    const auto update = impl_->state.handle_output_report(report, now);
    return {
      .recognized = update.recognized,
      .rumble_changed = update.rumble_changed,
      .strength = update.strength,
    };
  }

  pid_rumble_update_t generic_pid_rumble_t::advance(time_point_t now) {
    if (!impl_) {
      return {};
    }
    const auto update = impl_->state.advance(now);
    return {
      .recognized = update.recognized,
      .rumble_changed = update.rumble_changed,
      .strength = update.strength,
    };
  }

  std::optional<generic_pid_rumble_t::time_point_t> generic_pid_rumble_t::next_transition() const {
    if (!impl_) {
      return std::nullopt;
    }
    return impl_->state.next_transition();
  }

  profile_definition_t profile(profile_kind_e kind) {
    const auto upstream = upstream_profile(kind);
    return {
      .kind = kind,
      .vendor_id = upstream.vendor_id,
      .product_id = upstream.product_id,
      .version = upstream.version,
      .report_id = upstream.report_id,
      .input_size = upstream.input_report_size,
      .output_size = upstream.output_report_size,
      .name = upstream.name,
      .manufacturer = upstream.manufacturer,
      .descriptor = upstream.report_descriptor,
      .capabilities = {
        .rumble = upstream.capabilities.supports_rumble,
        .motion = upstream.capabilities.supports_motion,
        .touchpad = upstream.capabilities.supports_touchpad,
        .rgb_led = upstream.capabilities.supports_rgb_led,
        .battery = upstream.capabilities.supports_battery,
        .adaptive_triggers = upstream.capabilities.supports_adaptive_triggers,
      },
    };
  }

  std::vector<std::uint8_t> pack(const profile_definition_t &definition, const normalized_state_t &state) {
    const auto upstream = upstream_profile(definition.kind);
    if (!matches_profile(definition, upstream)) {
      return {};
    }
    auto report = lvh::reports::pack_input_report(upstream, upstream_state(state));
    if (definition.kind == profile_kind_e::generic) {
      report = lvh::detail::windows::make_generic_windows_input_report(report);
    }
    return report;
  }

  std::vector<output_t> parse_outputs(
    const profile_definition_t &definition,
    const std::vector<std::uint8_t> &bytes
  ) {
    const auto upstream = upstream_profile(definition.kind);
    if (!matches_profile(definition, upstream)) {
      return {};
    }

    std::vector<output_t> outputs;
    for (const auto &output : lvh::reports::parse_output_reports(upstream, bytes)) {
      outputs.push_back(lumen_output(output));
    }
    return outputs;
  }

}  // namespace platf::win_gamepad::lvh_core
