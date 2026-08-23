/**
 * @file src/platform/windows/libvirtualhid_gamepad_core.h
 * @brief Lumen-owned gamepad-only facade over libvirtualhid's portable core.
 */
#pragma once

// standard includes
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

// local includes
#include "src/platform/windows/gamepad_profile.h"

namespace platf::win_gamepad::lvh_core {

  /**
   * @brief Portable gamepad feature flags consumed by Lumen's driver transport.
   */
  struct profile_capabilities_t {
    bool rumble {};  ///< Whether the profile accepts rumble output.
    bool motion {};  ///< Whether the profile exposes motion sensors.
    bool touchpad {};  ///< Whether the profile exposes touchpad input.
    bool rgb_led {};  ///< Whether the profile accepts RGB LED output.
    bool battery {};  ///< Whether the profile exposes battery state.
    bool adaptive_triggers {};  ///< Whether the profile accepts adaptive-trigger output.
  };

  /**
   * @brief Lumen-owned descriptor and identity for one known gamepad profile.
   */
  struct profile_definition_t {
    profile_kind_e kind {profile_kind_e::generic};  ///< Logical gamepad profile.
    std::uint16_t vendor_id {};  ///< Compatibility-critical USB vendor identifier.
    std::uint16_t product_id {};  ///< Compatibility-critical USB product identifier.
    std::uint16_t version {};  ///< Compatibility-critical device revision.
    std::uint8_t report_id {};  ///< Primary input report identifier.
    std::size_t input_size {};  ///< Packed input report size.
    std::size_t output_size {};  ///< Expected output report size.
    std::string name;  ///< Device name reported to Windows.
    std::string manufacturer;  ///< Device manufacturer reported to Windows.
    std::vector<std::uint8_t> descriptor;  ///< Exact HID report descriptor.
    profile_capabilities_t capabilities;  ///< Supported optional features.
  };

  /**
   * @brief Logical button positions in `normalized_state_t::buttons`.
   */
  enum class button_e : std::uint8_t {
    a = 0,  ///< South face button.
    b,  ///< East face button.
    x,  ///< West face button.
    y,  ///< North face button.
    back,  ///< Back, select, or share button.
    start,  ///< Start or options button.
    guide,  ///< System guide button.
    left_stick,  ///< Left stick press.
    right_stick,  ///< Right stick press.
    left_shoulder,  ///< Left shoulder button.
    right_shoulder,  ///< Right shoulder button.
    dpad_up,  ///< Directional pad up.
    dpad_down,  ///< Directional pad down.
    dpad_left,  ///< Directional pad left.
    dpad_right,  ///< Directional pad right.
    misc1,  ///< Profile-specific miscellaneous button.
    touchpad,  ///< Touchpad click button.
    paddle1,  ///< First rear paddle button.
    paddle2,  ///< Second rear paddle button.
    paddle3,  ///< Third rear paddle button.
    paddle4,  ///< Fourth rear paddle button.
  };

  /**
   * @brief Return the bit mask for a normalized logical button.
   *
   * @param button Button to encode.
   * @return Corresponding `normalized_state_t::buttons` bit.
   */
  constexpr std::uint32_t button_bit(button_e button) {
    return 1U << static_cast<std::uint8_t>(button);
  }

  /**
   * @brief Normalized two-axis stick state.
   */
  struct stick_t {
    float x {};  ///< Horizontal axis in `[-1.0, 1.0]`.
    float y {};  ///< Vertical axis in `[-1.0, 1.0]`.
  };

  /**
   * @brief Normalized three-axis sensor sample.
   */
  struct vector3_t {
    float x {};  ///< X-axis sample.
    float y {};  ///< Y-axis sample.
    float z {};  ///< Z-axis sample.
  };

  /**
   * @brief Portable battery state used by the Lumen gamepad adapter.
   */
  enum class battery_state_e : std::uint8_t {
    unknown,  ///< Battery state is unknown.
    discharging,  ///< Battery is discharging.
    charging,  ///< Battery is charging.
    full,  ///< Battery is fully charged.
    voltage_or_temperature_error,  ///< Voltage or temperature is out of range.
    temperature_error,  ///< Battery reports a temperature error.
    charging_error,  ///< Battery reports a charging error.
  };

  /**
   * @brief Normalized battery metadata.
   */
  struct battery_t {
    battery_state_e state {battery_state_e::unknown};  ///< Current charge state.
    std::uint8_t percentage {100};  ///< Charge percentage in `[0, 100]`.
  };

  /**
   * @brief Normalized gamepad touch contact.
   */
  struct touch_contact_t {
    std::uint8_t id {};  ///< Stable contact identifier.
    bool active {};  ///< Whether the contact is active.
    float x {};  ///< Horizontal coordinate in `[0.0, 1.0]`.
    float y {};  ///< Vertical coordinate in `[0.0, 1.0]`.
  };

  /**
   * @brief Complete profile-neutral gamepad state retained by Lumen.
   */
  struct normalized_state_t {
    std::uint32_t buttons {};  ///< Logical button bit mask using `button_e` positions.
    stick_t left_stick;  ///< Left stick state.
    stick_t right_stick;  ///< Right stick state.
    float left_trigger {};  ///< Left trigger in `[0.0, 1.0]`.
    float right_trigger {};  ///< Right trigger in `[0.0, 1.0]`.
    std::optional<vector3_t> acceleration;  ///< Acceleration in meters per second squared.
    std::optional<vector3_t> gyroscope;  ///< Angular velocity in degrees per second.
    std::optional<battery_t> battery;  ///< Battery state when known.
    std::array<touch_contact_t, 2> touchpad_contacts {};  ///< Retained touchpad contacts.
  };

  /**
   * @brief Profile-neutral output categories delivered to Lumen.
   */
  enum class output_kind_e : std::uint8_t {
    rumble,  ///< Main motor rumble output.
    rgb_led,  ///< RGB LED output.
    adaptive_triggers,  ///< Adaptive-trigger effect output.
    raw_report,  ///< Unrecognized raw output report.
    trigger_rumble,  ///< Independent trigger rumble output.
  };

  /**
   * @brief One parsed gamepad output event using only Lumen-owned types.
   */
  struct output_t {
    output_kind_e kind {output_kind_e::raw_report};  ///< Parsed event category.
    std::uint16_t low_frequency_rumble {};  ///< Low-frequency motor strength.
    std::uint16_t high_frequency_rumble {};  ///< High-frequency motor strength.
    std::uint16_t left_trigger_rumble {};  ///< Left trigger motor strength.
    std::uint16_t right_trigger_rumble {};  ///< Right trigger motor strength.
    std::uint8_t red {};  ///< Red LED channel.
    std::uint8_t green {};  ///< Green LED channel.
    std::uint8_t blue {};  ///< Blue LED channel.
    std::uint8_t adaptive_trigger_flags {};  ///< Profile-specific adaptive-trigger flags.
    std::uint8_t left_trigger_effect_type {};  ///< Left adaptive-trigger effect type.
    std::uint8_t right_trigger_effect_type {};  ///< Right adaptive-trigger effect type.
    std::array<std::uint8_t, 10> left_trigger_effect {};  ///< Left trigger effect payload.
    std::array<std::uint8_t, 10> right_trigger_effect {};  ///< Right trigger effect payload.
    std::vector<std::uint8_t> raw_report;  ///< Original output report bytes.
  };

  /**
   * @brief Result of decoding or advancing Windows Generic PID rumble state.
   */
  struct pid_rumble_update_t {
    bool recognized {};  ///< Whether the report belongs to the supported PID subset.
    bool rumble_changed {};  ///< Whether `strength` differs from the previous result.
    std::uint16_t strength {};  ///< Combined symmetric motor strength.
  };

  /**
   * @brief Lumen-owned stateful facade for Windows DirectInput PID rumble.
   *
   * Callers serialize access externally. The upstream implementation type is
   * private to the facade and never appears in Lumen's consumer headers.
   */
  class generic_pid_rumble_t {
  public:
    using clock_t = std::chrono::steady_clock;  ///< Monotonic PID scheduler clock.
    using time_point_t = clock_t::time_point;  ///< Monotonic PID transition time.

    /**
     * @brief Construct empty PID effect state.
     */
    generic_pid_rumble_t();

    generic_pid_rumble_t(const generic_pid_rumble_t &) = delete;
    generic_pid_rumble_t &operator=(const generic_pid_rumble_t &) = delete;

    /**
     * @brief Move PID state from another facade instance.
     *
     * @param other Instance to move from.
     */
    generic_pid_rumble_t(generic_pid_rumble_t &&other) noexcept;

    /**
     * @brief Replace this PID state with another facade instance.
     *
     * @param other Instance to move from.
     * @return This instance.
     */
    generic_pid_rumble_t &operator=(generic_pid_rumble_t &&other) noexcept;

    /**
     * @brief Destroy private PID effect state.
     */
    ~generic_pid_rumble_t();

    /**
     * @brief Decode one DirectInput PID output report.
     *
     * @param report Complete PID output report including report ID.
     * @param now Monotonic report arrival time.
     * @return Recognition and rumble-change result.
     */
    pid_rumble_update_t handle_output_report(
      std::span<const std::uint8_t> report,
      time_point_t now = clock_t::now()
    );

    /**
     * @brief Advance delayed or expiring PID effects.
     *
     * @param now Monotonic scheduler time.
     * @return Current rumble update.
     */
    pid_rumble_update_t advance(time_point_t now = clock_t::now());

    /**
     * @brief Return the next delayed-start or expiration transition.
     *
     * @return Next monotonic transition, or `std::nullopt` when none is pending.
     */
    std::optional<time_point_t> next_transition() const;

  private:
    class impl_t;
    std::unique_ptr<impl_t> impl_;  ///< Private approved PID implementation.
  };

  /**
   * @brief Resolve the Windows-effective gamepad profile for Lumen's selected identity.
   *
   * PlayStation identities always use USB framing because Windows VHF cannot
   * expose a Bluetooth transport identity. Generic uses the DirectInput PID
   * descriptor and 22-byte output bound. Xbox Series uses the Windows-tested
   * `0x0509` device revision.
   *
   * @param kind Selected Lumen gamepad profile.
   * @return Exact Windows descriptor, identity, sizes, and feature flags.
   */
  profile_definition_t profile(profile_kind_e kind);

  /**
   * @brief Pack a complete normalized state using a known Windows profile.
   *
   * Generic trigger bytes are converted to DirectInput's idle-at-maximum
   * polarity after portable report packing.
   *
   * @param profile Known profile definition returned by `profile()`.
   * @param state Complete normalized gamepad state.
   * @return Packed HID input report bytes, or an empty vector for a mismatched definition.
   */
  std::vector<std::uint8_t> pack(const profile_definition_t &profile, const normalized_state_t &state);

  /**
   * @brief Parse one HID output report using a known Lumen profile.
   *
   * @param profile Known profile definition returned by `profile()`.
   * @param bytes Raw HID output report.
   * @return Zero or more profile-neutral output events.
   */
  std::vector<output_t> parse_outputs(
    const profile_definition_t &profile,
    const std::vector<std::uint8_t> &bytes
  );

}  // namespace platf::win_gamepad::lvh_core
