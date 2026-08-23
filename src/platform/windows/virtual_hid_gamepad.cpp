/**
 * @file src/platform/windows/virtual_hid_gamepad.cpp
 * @brief Lumen dynamic VHF gamepad adapter definitions.
 */

// local includes
#include "virtual_hid_gamepad.h"

#include "src/config.h"

// standard includes
#include <algorithm>
#include <cmath>
#include <condition_variable>
#include <limits>
#include <thread>
#include <utility>
#include <vector>

namespace platf::win_gamepad {
  namespace {
    /**
     * @brief Translate driver feature flags from a profile definition.
     *
     * @param definition Portable profile definition.
     * @return LUMEN_VHID_GAMEPAD_FEATURE_* bitmap.
     */
    std::uint32_t expected_features(const lvh_core::profile_definition_t &definition) {
      std::uint32_t flags = 0;
      if (definition.capabilities.rumble) {
        flags |= LUMEN_VHID_GAMEPAD_FEATURE_RUMBLE;
      }
      if (definition.capabilities.motion) {
        flags |= LUMEN_VHID_GAMEPAD_FEATURE_MOTION;
      }
      if (definition.capabilities.touchpad) {
        flags |= LUMEN_VHID_GAMEPAD_FEATURE_TOUCHPAD;
      }
      if (definition.capabilities.rgb_led) {
        flags |= LUMEN_VHID_GAMEPAD_FEATURE_RGB_LED;
      }
      if (definition.capabilities.battery) {
        flags |= LUMEN_VHID_GAMEPAD_FEATURE_BATTERY;
      }
      if (definition.capabilities.adaptive_triggers) {
        flags |= LUMEN_VHID_GAMEPAD_FEATURE_ADAPTIVE_TRIGGERS;
      }
      return flags;
    }

    /**
     * @brief Set one normalized button from a GameStream mask bit.
     *
     * @param buttons Normalized button bitmap.
     * @param button Normalized button index.
     * @param flags GameStream button flags.
     * @param mask GameStream mask bit.
     */
    void set_button(
      std::uint32_t &buttons,
      lvh_core::button_e button,
      std::uint32_t flags,
      std::uint32_t mask
    ) {
      if ((flags & mask) != 0U) {
        buttons |= lvh_core::button_bit(button);
      }
    }

    /**
     * @brief Convert a GameStream battery state to the portable model.
     *
     * @param state LI_BATTERY_STATE_* value.
     * @return Portable battery state.
     */
    lvh_core::battery_state_e battery_state(std::uint8_t state) {
      switch (state) {
        case LI_BATTERY_STATE_DISCHARGING:
          return lvh_core::battery_state_e::discharging;
        case LI_BATTERY_STATE_CHARGING:
          return lvh_core::battery_state_e::charging;
        case LI_BATTERY_STATE_FULL:
          return lvh_core::battery_state_e::full;
        case LI_BATTERY_STATE_NOT_PRESENT:
        case LI_BATTERY_STATE_NOT_CHARGING:
          return lvh_core::battery_state_e::charging_error;
        case LI_BATTERY_STATE_UNKNOWN:
        default:
          return lvh_core::battery_state_e::unknown;
      }
    }

  }  // namespace

  /**
   * @brief Feedback/output state that remains valid through session callback drain.
   */
  struct virtual_hid_gamepad_t::feedback_state_t {
    /**
     * @brief Construct feedback routing and optional Generic PID timer state.
     *
     * @param profile Selected profile.
     * @param definition Portable profile definition.
     * @param queue Stream feedback queue.
     * @param client_index Client-relative controller index.
     * @param generation Router generation.
     */
    feedback_state_t(
      profile_kind_e profile,
      lvh_core::profile_definition_t definition,
      feedback_queue_t queue,
      std::uint8_t client_index,
      std::uint64_t generation
    ):
        profile {profile},
        definition {std::move(definition)},
        queue {std::move(queue)},
        client_index {client_index},
        generation {generation} {
      if (profile == profile_kind_e::generic) {
        pid_thread = std::jthread([this](std::stop_token stop_token) {
          pid_timer_loop(stop_token);
        });
      }
    }

    /**
     * @brief Stop Generic PID scheduling before callback state destruction.
     */
    ~feedback_state_t() {
      active.store(false);
      if (pid_thread.joinable()) {
        pid_thread.request_stop();
      }
      pid_wake.notify_all();
      if (pid_thread.joinable()) {
        pid_thread.join();
      }
    }

    /**
     * @brief Parse and route one exact raw output report.
     *
     * @param callback_generation Generation captured at registration.
     * @param bytes Complete HID output report.
     */
    void output(std::uint64_t callback_generation, std::span<const std::uint8_t> bytes) {
      if (!active.load() || callback_generation != generation) {
        return;
      }
      std::vector<std::uint8_t> report {bytes.begin(), bytes.end()};
      if (profile == profile_kind_e::generic) {
        lvh_core::pid_rumble_update_t update;
        {
          std::lock_guard lock(pid_mutex);
          update = pid_rumble.handle_output_report(report);
          pid_revision.fetch_add(1U);
        }
        pid_wake.notify_all();
        if (update.recognized) {
          if (update.rumble_changed) {
            dispatch_rumble(update.strength, update.strength);
          }
          return;
        }
      }

      for (const auto &event : lvh_core::parse_outputs(definition, report)) {
        dispatch(event);
      }
    }

    /**
     * @brief Mark feedback inactive and stop timer scheduling.
     */
    void deactivate() {
      active.store(false);
      if (pid_thread.joinable()) {
        pid_thread.request_stop();
      }
      pid_wake.notify_all();
    }

    /**
     * @brief Deliver one parsed output with per-kind deduplication.
     *
     * @param event Parsed output event.
     */
    void dispatch(const lvh_core::output_t &event) {
      std::lock_guard lock(feedback_mutex);
      if (!active.load() || !queue) {
        return;
      }
      switch (event.kind) {
        case lvh_core::output_kind_e::rumble:
          if (last_rumble == std::pair {event.low_frequency_rumble, event.high_frequency_rumble}) {
            return;
          }
          last_rumble = std::pair {event.low_frequency_rumble, event.high_frequency_rumble};
          queue->raise(gamepad_feedback_msg_t::make_rumble(client_index, event.low_frequency_rumble, event.high_frequency_rumble));
          break;
        case lvh_core::output_kind_e::trigger_rumble:
          if (last_trigger_rumble == std::pair {event.left_trigger_rumble, event.right_trigger_rumble}) {
            return;
          }
          last_trigger_rumble = std::pair {event.left_trigger_rumble, event.right_trigger_rumble};
          queue->raise(gamepad_feedback_msg_t::make_rumble_triggers(client_index, event.left_trigger_rumble, event.right_trigger_rumble));
          break;
        case lvh_core::output_kind_e::rgb_led:
          {
            const std::array color {event.red, event.green, event.blue};
            if (last_rgb == color) {
              return;
            }
            last_rgb = color;
            queue->raise(gamepad_feedback_msg_t::make_rgb_led(client_index, event.red, event.green, event.blue));
            break;
          }
        case lvh_core::output_kind_e::adaptive_triggers:
          {
            const adaptive_state_t state {
              .flags = event.adaptive_trigger_flags,
              .left_type = event.left_trigger_effect_type,
              .right_type = event.right_trigger_effect_type,
              .left = event.left_trigger_effect,
              .right = event.right_trigger_effect,
            };
            if (last_adaptive == state) {
              return;
            }
            last_adaptive = state;
            queue->raise(gamepad_feedback_msg_t::make_adaptive_triggers(client_index, event.adaptive_trigger_flags, event.left_trigger_effect_type, event.right_trigger_effect_type, event.left_trigger_effect, event.right_trigger_effect));
            break;
          }
        case lvh_core::output_kind_e::raw_report:
          break;
      }
    }

    /**
     * @brief Dispatch a Generic PID rumble update through common deduplication.
     *
     * @param low Low-frequency strength.
     * @param high High-frequency strength.
     */
    void dispatch_rumble(std::uint16_t low, std::uint16_t high) {
      lvh_core::output_t event;
      event.kind = lvh_core::output_kind_e::rumble;
      event.low_frequency_rumble = low;
      event.high_frequency_rumble = high;
      dispatch(event);
    }

    /**
     * @brief Advance timed Generic PID effects at their next transition.
     *
     * @param stop_token Cooperative thread stop token.
     */
    void pid_timer_loop(std::stop_token stop_token) {
      while (!stop_token.stop_requested() && active.load()) {
        lvh_core::pid_rumble_update_t update;
        std::optional<lvh_core::generic_pid_rumble_t::time_point_t> next;
        std::uint64_t revision;
        {
          std::lock_guard lock(pid_mutex);
          update = pid_rumble.advance();
          next = pid_rumble.next_transition();
          revision = pid_revision.load();
        }
        if (update.rumble_changed) {
          dispatch_rumble(update.strength, update.strength);
        }

        std::unique_lock lock(pid_wait_mutex);
        const auto interrupted = [this, revision, &stop_token] {
          return stop_token.stop_requested() || !active.load() || pid_revision.load() != revision;
        };
        if (next) {
          static_cast<void>(pid_wake.wait_until(lock, *next, interrupted));
        } else {
          pid_wake.wait(lock, interrupted);
        }
      }
    }

    /**
     * @brief Deduplication value for adaptive trigger effects.
     */
    struct adaptive_state_t {
      std::uint8_t flags {};  ///< Event flags.
      std::uint8_t left_type {};  ///< Left effect type.
      std::uint8_t right_type {};  ///< Right effect type.
      std::array<std::uint8_t, 10> left {};  ///< Left effect payload.
      std::array<std::uint8_t, 10> right {};  ///< Right effect payload.

      /**
       * @brief Compare all adaptive trigger fields.
       *
       * @param other Value to compare.
       * @return `true` when equivalent.
       */
      bool operator==(const adaptive_state_t &other) const = default;
    };

    profile_kind_e profile;  ///< Selected profile.
    lvh_core::profile_definition_t definition;  ///< Portable output parser profile.
    feedback_queue_t queue;  ///< Current stream feedback queue.
    std::uint8_t client_index {};  ///< Client-relative controller index.
    std::uint64_t generation {};  ///< Router slot generation.
    std::atomic_bool active {true};  ///< Stale-event fence.
    std::mutex feedback_mutex;  ///< Serializes deduplication and queue raises.
    std::optional<std::pair<std::uint16_t, std::uint16_t>> last_rumble;  ///< Last main rumble.
    std::optional<std::pair<std::uint16_t, std::uint16_t>> last_trigger_rumble;  ///< Last trigger rumble.
    std::optional<std::array<std::uint8_t, 3>> last_rgb;  ///< Last RGB LED output.
    std::optional<adaptive_state_t> last_adaptive;  ///< Last adaptive trigger output.
    std::mutex pid_mutex;  ///< Protects stateful Generic PID decoding.
    lvh_core::generic_pid_rumble_t pid_rumble;  ///< Generic DirectInput PID effect state.
    std::atomic_uint64_t pid_revision {};  ///< Wakes the timer when output modifies an effect.
    std::jthread pid_thread;  ///< Generic PID transition scheduler.
    std::mutex pid_wait_mutex;  ///< Protects timer waits.
    std::condition_variable pid_wake;  ///< Wakes timer on output or teardown.
  };

  virtual_hid_gamepad_t::virtual_hid_gamepad_t(
    std::shared_ptr<virtual_hid_session_t> session,
    session_device_t device,
    lvh_core::profile_definition_t definition,
    std::shared_ptr<feedback_state_t> feedback,
    std::uint64_t generation
  ):
      session_ {std::move(session)},
      device_ {device},
      definition_ {std::move(definition)},
      feedback_ {std::move(feedback)},
      generation_ {generation} {
  }

  virtual_hid_gamepad_t::~virtual_hid_gamepad_t() {
    close();
  }

  create_result_t virtual_hid_gamepad_t::create(
    std::shared_ptr<virtual_hid_session_t> session,
    profile_kind_e profile,
    const gamepad_id_t &id,
    const gamepad_arrival_t &metadata,
    feedback_queue_t feedback_queue,
    std::uint64_t generation
  ) {
    static_cast<void>(metadata);
    if (!session || !session->available() || profile == profile_kind_e::xbox_360) {
      return {
        .backend = {},
        .became_visible = false,
        .error = "Lumen dynamic Virtual HID gamepads are unavailable for the selected profile",
      };
    }

    auto definition = lvh_core::profile(profile);
    auto feedback = std::make_shared<feedback_state_t>(
      profile,
      definition,
      std::move(feedback_queue),
      id.clientRelativeIndex,
      generation
    );
    const auto callback_generation = generation;
    auto created = session->create(
      (generation << 8U) | static_cast<std::uint64_t>(static_cast<unsigned int>(id.globalIndex) & 0xFFU),
      protocol_profile(profile),
      [feedback, callback_generation](const session_device_t &, std::span<const std::uint8_t> report) {
        feedback->output(callback_generation, report);
      }
    );
    if (!created.success) {
      feedback->deactivate();
      return {
        .backend = {},
        .became_visible = created.became_visible,
        .error = std::move(created.error),
      };
    }

    const bool metadata_valid =
      created.device.profile == protocol_profile(profile) &&
      created.device.feature_flags == expected_features(definition) &&
      created.device.vendor_id == definition.vendor_id &&
      created.device.product_id == definition.product_id &&
      created.device.version_number == definition.version &&
      created.device.input_report_id == definition.report_id &&
      created.device.input_report_size == definition.input_size &&
      created.device.output_report_size == definition.output_size;
    if (!metadata_valid) {
      feedback->deactivate();
      static_cast<void>(session->destroy(created.device));
      return {
        .backend = {},
        .became_visible = true,
        .error = "dynamic-gamepad driver returned profile metadata that conflicts with the approved core",
      };
    }

    auto backend = std::unique_ptr<virtual_hid_gamepad_t> {new virtual_hid_gamepad_t {
      session,
      created.device,
      std::move(definition),
      std::move(feedback),
      generation,
    }};
    {
      std::lock_guard lock(backend->state_mutex_);
      if (!backend->submit_state_locked()) {
        backend->feedback_->deactivate();
        static_cast<void>(session->destroy(created.device));
        backend->closed_.store(true);
        return {
          .backend = {},
          .became_visible = true,
          .error = "dynamic-gamepad driver rejected the initial neutral report",
        };
      }
    }

    if (backend->definition_.capabilities.motion && backend->feedback_->queue) {
      backend->feedback_->queue->raise(gamepad_feedback_msg_t::make_motion_event_state(id.clientRelativeIndex, LI_MOTION_TYPE_ACCEL, 100));
      backend->feedback_->queue->raise(gamepad_feedback_msg_t::make_motion_event_state(id.clientRelativeIndex, LI_MOTION_TYPE_GYRO, 100));
    }
    return {
      .backend = std::move(backend),
      .became_visible = false,
      .error = {},
    };
  }

  backend_kind_e virtual_hid_gamepad_t::kind() const noexcept {
    return backend_kind_e::virtual_hid;
  }

  profile_kind_e virtual_hid_gamepad_t::profile() const noexcept {
    return definition_.kind;
  }

  backend_identity_t virtual_hid_gamepad_t::identity() const noexcept {
    backend_identity_t result {.device_id = device_.handle.device_id};
    std::copy(
      std::begin(device_.handle.session_token),
      std::end(device_.handle.session_token),
      result.token.begin()
    );
    return result;
  }

  bool virtual_hid_gamepad_t::update(const gamepad_state_t &state) {
    if (closed_.load()) {
      return false;
    }
    std::lock_guard lock(state_mutex_);
    const auto flags = state.buttonFlags;
    std::uint32_t buttons = 0;
    set_button(buttons, lvh_core::button_e::dpad_up, flags, DPAD_UP);
    set_button(buttons, lvh_core::button_e::dpad_down, flags, DPAD_DOWN);
    set_button(buttons, lvh_core::button_e::dpad_left, flags, DPAD_LEFT);
    set_button(buttons, lvh_core::button_e::dpad_right, flags, DPAD_RIGHT);
    set_button(buttons, lvh_core::button_e::start, flags, START);
    set_button(buttons, lvh_core::button_e::back, flags, BACK);
    set_button(buttons, lvh_core::button_e::left_stick, flags, LEFT_STICK);
    set_button(buttons, lvh_core::button_e::right_stick, flags, RIGHT_STICK);
    set_button(buttons, lvh_core::button_e::left_shoulder, flags, LEFT_BUTTON);
    set_button(buttons, lvh_core::button_e::right_shoulder, flags, RIGHT_BUTTON);
    set_button(buttons, lvh_core::button_e::guide, flags, HOME);
    set_button(buttons, lvh_core::button_e::a, flags, A);
    set_button(buttons, lvh_core::button_e::b, flags, B);
    set_button(buttons, lvh_core::button_e::x, flags, X);
    set_button(buttons, lvh_core::button_e::y, flags, Y);
    set_button(buttons, lvh_core::button_e::misc1, flags, MISC_BUTTON);
    set_button(buttons, lvh_core::button_e::touchpad, flags, TOUCHPAD_BUTTON);
    set_button(buttons, lvh_core::button_e::paddle1, flags, PADDLE1);
    set_button(buttons, lvh_core::button_e::paddle2, flags, PADDLE2);
    set_button(buttons, lvh_core::button_e::paddle3, flags, PADDLE3);
    set_button(buttons, lvh_core::button_e::paddle4, flags, PADDLE4);
    if (definition_.kind == profile_kind_e::dualshock4 &&
        config::input.ds4_back_as_touchpad_click && (flags & BACK) != 0U) {
      buttons |= lvh_core::button_bit(lvh_core::button_e::touchpad);
    }

    // Intentionally replace only ordinary state. Auxiliary motion, touch, and
    // battery fields remain cached across every buttons/sticks update.
    state_.buttons = buttons;
    state_.left_stick = {.x = normalize_axis(state.lsX), .y = normalize_axis(state.lsY)};
    state_.right_stick = {.x = normalize_axis(state.rsX), .y = normalize_axis(state.rsY)};
    state_.left_trigger = normalize_trigger(state.lt);
    state_.right_trigger = normalize_trigger(state.rt);
    return submit_state_locked();
  }

  bool virtual_hid_gamepad_t::touch(const gamepad_touch_t &touch_event) {
    if (closed_.load() || !definition_.capabilities.touchpad) {
      return !closed_.load();
    }
    std::lock_guard lock(state_mutex_);
    if (touch_event.eventType == LI_TOUCH_EVENT_CANCEL_ALL) {
      touch_ids_.fill(std::nullopt);
      state_.touchpad_contacts = {};
      return submit_state_locked();
    }

    std::optional<std::size_t> index;
    for (std::size_t current = 0; current < touch_ids_.size(); ++current) {
      if (touch_ids_[current] == touch_event.pointerId) {
        index = current;
        break;
      }
    }
    if (touch_event.eventType == LI_TOUCH_EVENT_DOWN && !index) {
      for (std::size_t current = 0; current < touch_ids_.size(); ++current) {
        if (!touch_ids_[current]) {
          index = current;
          touch_ids_[current] = touch_event.pointerId;
          break;
        }
      }
    }
    if (!index) {
      return false;
    }

    auto &contact = state_.touchpad_contacts[*index];
    contact.id = static_cast<std::uint8_t>(touch_event.pointerId);
    contact.x = std::clamp(touch_event.x, 0.0F, 1.0F);
    contact.y = std::clamp(touch_event.y, 0.0F, 1.0F);
    switch (touch_event.eventType) {
      case LI_TOUCH_EVENT_DOWN:
      case LI_TOUCH_EVENT_MOVE:
        contact.active = true;
        break;
      case LI_TOUCH_EVENT_UP:
      case LI_TOUCH_EVENT_CANCEL:
        contact.active = false;
        touch_ids_[*index].reset();
        break;
      default:
        return false;
    }
    return submit_state_locked();
  }

  bool virtual_hid_gamepad_t::motion(const gamepad_motion_t &motion_event) {
    if (closed_.load() || !definition_.capabilities.motion) {
      return !closed_.load();
    }
    std::lock_guard lock(state_mutex_);
    const lvh_core::vector3_t sample {.x = motion_event.x, .y = motion_event.y, .z = motion_event.z};
    if (motion_event.motionType == LI_MOTION_TYPE_ACCEL) {
      state_.acceleration = sample;
    } else if (motion_event.motionType == LI_MOTION_TYPE_GYRO) {
      state_.gyroscope = sample;
    } else {
      return false;
    }
    return submit_state_locked();
  }

  bool virtual_hid_gamepad_t::battery(const gamepad_battery_t &battery_event) {
    if (closed_.load() || !definition_.capabilities.battery) {
      return !closed_.load();
    }
    std::lock_guard lock(state_mutex_);
    auto percentage = state_.battery ? state_.battery->percentage : 100U;
    if (battery_event.percentage != LI_BATTERY_PERCENTAGE_UNKNOWN) {
      percentage = std::min<std::uint8_t>(battery_event.percentage, 100U);
    }
    state_.battery = lvh_core::battery_t {
      .state = battery_state(battery_event.state),
      .percentage = static_cast<std::uint8_t>(percentage),
    };
    return submit_state_locked();
  }

  void virtual_hid_gamepad_t::close() noexcept {
    if (closed_.exchange(true)) {
      return;
    }
    {
      std::lock_guard lock(state_mutex_);
      state_ = {};
      touch_ids_.fill(std::nullopt);
      static_cast<void>(submit_state_locked());
    }
    feedback_->deactivate();
    static_cast<void>(session_->destroy(device_));
  }

  lvh_core::normalized_state_t virtual_hid_gamepad_t::state_snapshot() const {
    std::lock_guard lock(state_mutex_);
    return state_;
  }

  bool virtual_hid_gamepad_t::submit_state_locked() {
    auto report = lvh_core::pack(definition_, state_);
    if (report.size() != device_.input_report_size) {
      return false;
    }
    return static_cast<bool>(session_->submit(device_, report));
  }

  std::uint32_t virtual_hid_gamepad_t::protocol_profile(profile_kind_e profile) {
    switch (profile) {
      case profile_kind_e::generic:
        return LUMEN_VHID_GAMEPAD_PROFILE_GENERIC;
      case profile_kind_e::xbox_360:
        return LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED;
      case profile_kind_e::xbox_one:
        return LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE;
      case profile_kind_e::xbox_series:
        return LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES;
      case profile_kind_e::dualshock4:
        return LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4;
      case profile_kind_e::dualsense:
        return LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE;
      case profile_kind_e::switch_pro:
        return LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO;
    }
    return LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED;
  }

  float virtual_hid_gamepad_t::normalize_axis(std::int16_t value) {
    if (value < 0) {
      return std::max(-1.0F, static_cast<float>(value) / 32768.0F);
    }
    return std::min(1.0F, static_cast<float>(value) / 32767.0F);
  }

  float virtual_hid_gamepad_t::normalize_trigger(std::uint8_t value) {
    return static_cast<float>(value) / static_cast<float>(std::numeric_limits<std::uint8_t>::max());
  }

  backend_factory_t make_virtual_hid_gamepad_factory(std::shared_ptr<virtual_hid_session_t> session) {
    return [session = std::move(session)](
             profile_kind_e profile,
             const gamepad_id_t &id,
             const gamepad_arrival_t &metadata,
             feedback_queue_t feedback_queue,
             std::uint64_t generation
           ) {
      return virtual_hid_gamepad_t::create(
        session,
        profile,
        id,
        metadata,
        std::move(feedback_queue),
        generation
      );
    };
  }

}  // namespace platf::win_gamepad
