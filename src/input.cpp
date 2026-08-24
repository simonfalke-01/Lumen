/**
 * @file src/input.cpp
 * @brief Definitions for gamepad, keyboard, and mouse input handling.
 */
#include <cstdint>
extern "C" {
#include <moonlight-common-c/src/Input.h>
#include <moonlight-common-c/src/Limelight.h>
}

// standard includes
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
  // clang-format off: avrt.h depends on the Windows base types.
  #include <windows.h>
  #include <avrt.h>
  // clang-format on
#endif

// lib includes
#include <boost/endian/buffers.hpp>

// local includes
#include "config.h"
#include "globals.h"
#include "input.h"
#include "input_state.h"
#include "logging.h"
#include "ordered_input_dispatcher.h"
#include "platform/common.h"
#include "utility.h"

// Win32 WHEEL_DELTA constant
#ifndef WHEEL_DELTA
constexpr int WHEEL_DELTA = 120;  ///< Standard Windows wheel delta used to normalize scroll events.
#endif

using namespace std::literals;

namespace input {

  void detail::delayed_left_state_t::on_absolute_move() noexcept {
    delay_enabled_ = true;
  }

  detail::delayed_left_decision_t detail::delayed_left_state_t::on_relative_move() noexcept {
    delayed_left_decision_t decision {};
    delay_enabled_ = false;
    if (release_pending_) {
      release_pending_ = false;
      ++generation_;
      decision.cancel_timer = true;
      decision.emit_left_release = true;
    }
    return decision;
  }

  detail::delayed_left_decision_t detail::delayed_left_state_t::on_left_down() noexcept {
    delayed_left_decision_t decision {};
    if (release_pending_) {
      release_pending_ = false;
      ++generation_;
      decision.cancel_timer = true;
      decision.emit_left_release = true;
    }
    return decision;
  }

  detail::delayed_left_decision_t detail::delayed_left_state_t::on_left_up() noexcept {
    delayed_left_decision_t decision {};
    if (!delay_enabled_ || release_pending_) {
      return decision;
    }
    release_pending_ = true;
    decision.schedule_timer = true;
    decision.generation = ++generation_;
    return decision;
  }

  detail::delayed_left_decision_t detail::delayed_left_state_t::on_right_down() const noexcept {
    delayed_left_decision_t decision {};
    decision.synthesize_right_click = release_pending_;
    return decision;
  }

  detail::delayed_left_decision_t detail::delayed_left_state_t::on_timer(
    std::uint64_t generation,
    bool left_pressed
  ) noexcept {
    delayed_left_decision_t decision {};
    if (!release_pending_ || generation != generation_) {
      return decision;
    }
    release_pending_ = false;
    decision.consume_timer = true;
    decision.emit_left_release = !left_pressed;
    return decision;
  }

  detail::delayed_left_decision_t detail::delayed_left_state_t::on_reset() noexcept {
    delayed_left_decision_t decision {};
    delay_enabled_ = true;
    ++generation_;
    if (release_pending_) {
      release_pending_ = false;
      decision.cancel_timer = true;
      decision.emit_left_release = true;
    }
    return decision;
  }

  bool detail::checked_add_int16(std::int16_t lhs, std::int16_t rhs, std::int16_t &result) {
    const auto sum = static_cast<std::int32_t>(lhs) + static_cast<std::int32_t>(rhs);
    if (sum < std::numeric_limits<std::int16_t>::min() || sum > std::numeric_limits<std::int16_t>::max()) {
      return false;
    }

    result = static_cast<std::int16_t>(sum);
    return true;
  }

  constexpr auto MAX_GAMEPADS = std::min((std::size_t) platf::MAX_GAMEPADS, sizeof(std::int16_t) * 8);  ///< Maximum gamepads representable by the active gamepad mask.
/**
 * @def DISABLE_LEFT_BUTTON_DELAY
 * @brief Macro for DISABLE LEFT BUTTON DELAY.
 */
#define DISABLE_LEFT_BUTTON_DELAY (std::numeric_limits<std::uint64_t>::max())
/**
 * @def ENABLE_LEFT_BUTTON_DELAY
 * @brief Macro for ENABLE LEFT BUTTON DELAY.
 */
#define ENABLE_LEFT_BUTTON_DELAY 0

  constexpr auto VKEY_SHIFT = 0x10;  ///< Windows virtual-key code for shift.
  constexpr auto VKEY_LSHIFT = 0xA0;  ///< Windows virtual-key code for lshift.
  constexpr auto VKEY_RSHIFT = 0xA1;  ///< Windows virtual-key code for rshift.
  constexpr auto VKEY_CONTROL = 0x11;  ///< Windows virtual-key code for control.
  constexpr auto VKEY_LCONTROL = 0xA2;  ///< Windows virtual-key code for lcontrol.
  constexpr auto VKEY_RCONTROL = 0xA3;  ///< Windows virtual-key code for rcontrol.
  constexpr auto VKEY_MENU = 0x12;  ///< Windows virtual-key code for menu.
  constexpr auto VKEY_LMENU = 0xA4;  ///< Windows virtual-key code for lmenu.
  constexpr auto VKEY_RMENU = 0xA5;  ///< Windows virtual-key code for rmenu.

  /**
   * @brief Enumerates supported button state options.
   */
  enum class button_state_e {
    NONE,  ///< No button state
    DOWN,  ///< Button is down
    UP  ///< Button is up
  };

  /**
   * @brief Packed identifier for a pressed key and its modifier flags.
   */
  typedef uint32_t key_press_id_t;

  /**
   * @brief Create a key-press identifier from the virtual-key code and flags.
   *
   * @param vk Virtual-key code from the client input packet.
   * @param flags Bit flags that modify the requested operation.
   * @return Constructed kpid object.
   */
  key_press_id_t make_kpid(uint16_t vk, uint8_t flags) {
    return (key_press_id_t) vk << 8 | flags;
  }

  /**
   * @brief Extract the virtual-key code from a packed key-press identifier.
   *
   * @param kpid Key-press identifier containing the virtual-key code and flags.
   * @return Virtual-key code stored in the high byte.
   */
  uint16_t vk_from_kpid(key_press_id_t kpid) {
    return kpid >> 8;
  }

  /**
   * @brief Extract the modifier flags from a packed key-press identifier.
   *
   * @param kpid Key-press identifier containing the virtual-key code and flags.
   * @return Modifier flags stored in the low byte.
   */
  uint8_t flags_from_kpid(key_press_id_t kpid) {
    return kpid & 0xFF;
  }

  /**
   * @brief Convert a little-endian netfloat to a native endianness float.
   * @param f Little-endian network float bytes.
   * @return Floating-point value decoded for the host CPU.
   */
  float from_netfloat(netfloat f) {
    return boost::endian::endian_load<float, sizeof(float), boost::endian::order::little>(f);
  }

  /**
   * @brief Convert a little-endian netfloat to a native float and clamp it to a range.
   * @param f Little-endian network float bytes.
   * @param min The minimium value for clamping.
   * @param max The maximum value for clamping.
   * @return Decoded floating-point value clamped between min and max.
   */
  float from_clamped_netfloat(netfloat f, float min, float max) {
    return std::clamp(from_netfloat(f), min, max);
  }

  static platf::input_t platf_input;
  static std::mutex platform_input_mutex;  ///< Serializes shared keyboard and mouse platform transitions.
  static detail::held_state_counts_t<key_press_id_t> global_key_holds;  ///< Cross-session held-key contributions.
  static detail::held_state_counts_t<int> global_mouse_holds;  ///< Cross-session held-button contributions.
  using gamepad_slot_allocator_t = detail::synchronized_slot_allocator_t<platf::MAX_GAMEPADS>;  ///< Global gamepad slot allocator type.
  static gamepad_slot_allocator_t gamepad_slots;  ///< Generation-qualified slots shared by session consumers.
  static detail::input_session_reset_gate_t input_session_gate;  ///< Shared transport reset serialization gate.

  /**
   * @brief Release all platform resources associated with a virtual gamepad.
   *
   * @param platf_input Platf input.
   * @param reservation Generation-qualified gamepad slot reservation.
   */
  void free_gamepad(platf::input_t &platf_input, gamepad_slot_allocator_t::reservation_t reservation) {
    if (!reservation) {
      return;
    }
    const auto id = reservation.id;
    gamepad_slots.release(reservation, [&platf_input, id]() {
      platf::gamepad_update(platf_input, id, platf::gamepad_state_t {});
      platf::free_gamepad(platf_input, id);
    });
  }

  /**
   * @brief Per-client gamepad slot and feedback state.
   */
  struct gamepad_t {
    gamepad_t():
        gamepad_state {},
        id {-1},
        back_button_state {button_state_e::NONE} {
    }

    ~gamepad_t() {
      if (id >= 0) {
        free_gamepad(platf_input, reservation);
      }
    }

    platf::gamepad_state_t gamepad_state;  ///< Gamepad state.

    detail::controller_timer_generation_t timers;  ///< Connection generation and cancellable delayed work.
    gamepad_slot_allocator_t::reservation_t reservation;  ///< Generation-qualified global slot ownership.

    int id;  ///< Global gamepad slot assigned to this client controller.

    // When emulating the HOME button, we may need to artificially release the back button.
    // Afterwards, the gamepad state on sunshine won't match the state on Moonlight.
    // To prevent Sunshine from sending erroneous input data to the active application,
    // Sunshine forces the button to be in a specific state until the gamepad state matches that of
    // Moonlight once more.
    button_state_e back_button_state;  ///< Back button state.
  };

  void neutralize_input(input_t &input);

  /**
   * @brief Input emulation settings loaded from configuration.
   */
  struct input_t {
    using dispatcher_t = detail::ordered_input_dispatcher_t<std::vector<std::uint8_t>>;  ///< Per-session ordered input dispatcher.

    /**
     * @brief Enumerates supported shortkey options.
     */
    enum shortkey_e {
      CTRL = 0x1,  ///< Control key
      ALT = 0x2,  ///< Alt key
      SHIFT = 0x4,  ///< Shift key
      SHORTCUT = CTRL | ALT | SHIFT  ///< Shortcut combination
    };

    /**
     * @brief Construct input state from the mailbox and platform backend.
     *
     * @param touch_port_event Event carrying the active touch port.
     * @param feedback_queue Queue used for controller feedback.
     */
    input_t(
      safe::mail_raw_t::event_t<input::touch_port_t> touch_port_event,
      platf::feedback_queue_t feedback_queue
    ):
        shortcutFlags {},
        gamepads(MAX_GAMEPADS),
        client_context {platf::allocate_client_input_context(platf_input)},
        touch_port_event {std::move(touch_port_event)},
        feedback_queue {std::move(feedback_queue)},
        mouse_left_button_timeout {},
        touch_port {{0, 0, 0, 0}, 0, 0, 1.0f, 1.0f, 0, 0},
        accumulated_vscroll_delta {},
        accumulated_hscroll_delta {} {
    }

    /**
     * @brief Stop any remaining dispatch work before dependent session fields are destroyed.
     */
    ~input_t() {
      if (dispatcher) {
        dispatcher->close(false);
      }
      if (session_registration != 0) {
        neutralize_input(*this);
      }
    }

    // Keep track of alt+ctrl+shift key combo
    int shortcutFlags;  ///< Shortcut flags.

    bool left_alt_pressed = false;  ///< Tracks whether the left Alt key is currently pressed.
    bool right_alt_pressed = false;  ///< Tracks whether the right Alt key is currently pressed.

    std::vector<gamepad_t> gamepads;  ///< Virtual gamepad slots tracked for the stream.
    std::unique_ptr<platf::client_input_t> client_context;  ///< Client context.

    safe::mail_raw_t::event_t<input::touch_port_t> touch_port_event;  ///< Touch port event.
    platf::feedback_queue_t feedback_queue;  ///< Queue used to deliver controller feedback to the platform backend.

    std::unordered_map<key_press_id_t, bool> key_press;  ///< Pressed keyboard state local to this stream.
    std::array<std::uint8_t, BUTTON_X2 + 1> mouse_press {};  ///< Logical mouse-button state local to this stream.
    std::array<std::uint8_t, BUTTON_X2 + 1> mouse_platform_press {};  ///< Physical held contributions owned by this stream.
    static_assert(std::tuple_size_v<std::array<std::uint8_t, BUTTON_X2 + 1>> > BUTTON_X2, "Mouse state must include every Moonlight button ID");
    dispatcher_t::task_id_t key_press_repeat_id {};  ///< Ordered key-repeat timer.
    dispatcher_t::task_id_t mouse_left_button_timeout {};  ///< Ordered mouse left-button timeout.
    detail::delayed_left_state_t delayed_left_button;  ///< Portable delayed left-button decision state.

    input::touch_port_t touch_port;  ///< Touch coordinate bounds for the current stream.

    int32_t accumulated_vscroll_delta;  ///< Accumulated vscroll delta.
    int32_t accumulated_hscroll_delta;  ///< Accumulated hscroll delta.
    detail::input_session_reset_gate_t::session_id_t session_registration {};  ///< Shared transport reset-gate registration.
    std::unique_ptr<dispatcher_t> dispatcher;  ///< Dedicated FIFO consumer destroyed before session state.
  };

  short map_keycode(short keycode);

  /**
   * @brief Invalidate and cancel delayed callbacks owned by one controller instance.
   *
   * @param input Session dispatcher that owns the timers.
   * @param gamepad Controller state whose generation is invalidated.
   */
  void disconnect_controller_timers(input_t &input, gamepad_t &gamepad) {
    const auto cancellations = gamepad.timers.disconnect();
    if (input.dispatcher) {
      input.dispatcher->cancel(cancellations.timeout);
      input.dispatcher->cancel(cancellations.release);
    }
  }

  /**
   * @brief Apply one reference-counted platform mouse-button transition.
   *
   * The caller must hold platform_input_mutex.
   *
   * @param input Session contributing the held state.
   * @param button Moonlight mouse-button identifier.
   * @param release Whether to release the session's physical contribution.
   */
  void update_platform_mouse_locked(input_t &input, int button, bool release) {
    if (button < BUTTON_LEFT || button > BUTTON_X2) {
      platf::button_mouse(platf_input, button, release);
      return;
    }

    auto &session_pressed = input.mouse_platform_press[button];
    if (session_pressed == !release) {
      return;
    }
    session_pressed = !release;
    if (!release) {
      if (global_mouse_holds.acquire(button)) {
        platf::button_mouse(platf_input, button, false);
      }
    } else if (global_mouse_holds.release(button)) {
      platf::button_mouse(platf_input, button, true);
    }
  }

  /**
   * @brief Apply one reference-counted platform keyboard transition.
   *
   * The caller must hold platform_input_mutex.
   *
   * @param key_code Moonlight virtual key code.
   * @param release Whether to release the session's held contribution.
   * @param flags Keyboard packet flags.
   */
  void update_platform_keyboard_locked(uint16_t key_code, bool release, uint8_t flags) {
    const auto mapped_key = map_keycode(key_code);
    const auto identity = make_kpid(mapped_key, flags);
    if (!release) {
      if (global_key_holds.acquire(identity)) {
        platf::keyboard_update(platf_input, mapped_key, false, flags);
      }
    } else if (global_key_holds.release(identity)) {
      platf::keyboard_update(platf_input, mapped_key, true, flags);
    }
  }

  /**
   * @brief Apply shortcut based on VKEY
   * @param keyCode The VKEY code
   * @return 0 if no shortcut applied, > 0 if shortcut applied.
   */
  inline int apply_shortcut(short keyCode) {
    constexpr auto shortcut_key_first = 0x70;
    constexpr auto shortcut_key_last = 0x7C;

    BOOST_LOG(debug) << "Apply Shortcut: 0x"sv << util::hex((std::uint8_t) keyCode).to_string_view();

    if (keyCode >= shortcut_key_first && keyCode <= shortcut_key_last) {
      mail::man->event<int>(mail::switch_display)->raise(keyCode - shortcut_key_first);
      return 1;
    }

    switch (keyCode) {
      case 0x4E /* VKEY_N */:
        display_cursor = !display_cursor;
        return 1;
    }

    return 0;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_REL_MOUSE_MOVE_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin relative mouse move packet--"sv << std::endl
      << "deltaX ["sv << util::endian::big(packet->deltaX) << ']' << std::endl
      << "deltaY ["sv << util::endian::big(packet->deltaY) << ']' << std::endl
      << "--end relative mouse move packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_ABS_MOUSE_MOVE_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin absolute mouse move packet--"sv << std::endl
      << "x      ["sv << util::endian::big(packet->x) << ']' << std::endl
      << "y      ["sv << util::endian::big(packet->y) << ']' << std::endl
      << "width  ["sv << util::endian::big(packet->width) << ']' << std::endl
      << "height ["sv << util::endian::big(packet->height) << ']' << std::endl
      << "--end absolute mouse move packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_MOUSE_BUTTON_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin mouse button packet--"sv << std::endl
      << "action ["sv << util::hex(packet->header.magic).to_string_view() << ']' << std::endl
      << "button ["sv << util::hex(packet->button).to_string_view() << ']' << std::endl
      << "--end mouse button packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_SCROLL_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin mouse scroll packet--"sv << std::endl
      << "scrollAmt1 ["sv << util::endian::big(packet->scrollAmt1) << ']' << std::endl
      << "--end mouse scroll packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PSS_HSCROLL_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin mouse hscroll packet--"sv << std::endl
      << "scrollAmount ["sv << util::endian::big(packet->scrollAmount) << ']' << std::endl
      << "--end mouse hscroll packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_KEYBOARD_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin keyboard packet--"sv << std::endl
      << "keyAction ["sv << util::hex(packet->header.magic).to_string_view() << ']' << std::endl
      << "keyCode ["sv << util::hex(packet->keyCode).to_string_view() << ']' << std::endl
      << "modifiers ["sv << util::hex(packet->modifiers).to_string_view() << ']' << std::endl
      << "flags ["sv << util::hex(packet->flags).to_string_view() << ']' << std::endl
      << "--end keyboard packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_UNICODE_PACKET packet) {
    std::string text(packet->text, util::endian::big(packet->header.size) - sizeof(packet->header.magic));
    BOOST_LOG(debug)
      << "--begin unicode packet--"sv << std::endl
      << "text ["sv << text << ']' << std::endl
      << "--end unicode packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   *
   * @param packet Protocol packet being processed.
   */
  void print(PNV_MULTI_CONTROLLER_PACKET packet) {
    // Moonlight spams controller packet even when not necessary
    BOOST_LOG(verbose)
      << "--begin controller packet--"sv << std::endl
      << "controllerNumber ["sv << packet->controllerNumber << ']' << std::endl
      << "activeGamepadMask ["sv << util::hex(packet->activeGamepadMask).to_string_view() << ']' << std::endl
      << "buttonFlags ["sv << util::hex((uint32_t) packet->buttonFlags | (packet->buttonFlags2 << 16)).to_string_view() << ']' << std::endl
      << "leftTrigger ["sv << util::hex(packet->leftTrigger).to_string_view() << ']' << std::endl
      << "rightTrigger ["sv << util::hex(packet->rightTrigger).to_string_view() << ']' << std::endl
      << "leftStickX ["sv << packet->leftStickX << ']' << std::endl
      << "leftStickY ["sv << packet->leftStickY << ']' << std::endl
      << "rightStickX ["sv << packet->rightStickX << ']' << std::endl
      << "rightStickY ["sv << packet->rightStickY << ']' << std::endl
      << "--end controller packet--"sv;
  }

  /**
   * @brief Prints a touch packet.
   * @param packet The touch packet.
   */
  void print(PSS_TOUCH_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin touch packet--"sv << std::endl
      << "eventType ["sv << util::hex(packet->eventType).to_string_view() << ']' << std::endl
      << "pointerId ["sv << util::hex(packet->pointerId).to_string_view() << ']' << std::endl
      << "x ["sv << from_netfloat(packet->x) << ']' << std::endl
      << "y ["sv << from_netfloat(packet->y) << ']' << std::endl
      << "pressureOrDistance ["sv << from_netfloat(packet->pressureOrDistance) << ']' << std::endl
      << "contactAreaMajor ["sv << from_netfloat(packet->contactAreaMajor) << ']' << std::endl
      << "contactAreaMinor ["sv << from_netfloat(packet->contactAreaMinor) << ']' << std::endl
      << "rotation ["sv << (uint32_t) packet->rotation << ']' << std::endl
      << "--end touch packet--"sv;
  }

  /**
   * @brief Prints a pen packet.
   * @param packet The pen packet.
   */
  void print(PSS_PEN_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin pen packet--"sv << std::endl
      << "eventType ["sv << util::hex(packet->eventType).to_string_view() << ']' << std::endl
      << "toolType ["sv << util::hex(packet->toolType).to_string_view() << ']' << std::endl
      << "penButtons ["sv << util::hex(packet->penButtons).to_string_view() << ']' << std::endl
      << "x ["sv << from_netfloat(packet->x) << ']' << std::endl
      << "y ["sv << from_netfloat(packet->y) << ']' << std::endl
      << "pressureOrDistance ["sv << from_netfloat(packet->pressureOrDistance) << ']' << std::endl
      << "contactAreaMajor ["sv << from_netfloat(packet->contactAreaMajor) << ']' << std::endl
      << "contactAreaMinor ["sv << from_netfloat(packet->contactAreaMinor) << ']' << std::endl
      << "rotation ["sv << (uint32_t) packet->rotation << ']' << std::endl
      << "tilt ["sv << (uint32_t) packet->tilt << ']' << std::endl
      << "--end pen packet--"sv;
  }

  /**
   * @brief Prints a controller arrival packet.
   * @param packet The controller arrival packet.
   */
  void print(PSS_CONTROLLER_ARRIVAL_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin controller arrival packet--"sv << std::endl
      << "controllerNumber ["sv << (uint32_t) packet->controllerNumber << ']' << std::endl
      << "type ["sv << util::hex(packet->type).to_string_view() << ']' << std::endl
      << "capabilities ["sv << util::hex(packet->capabilities).to_string_view() << ']' << std::endl
      << "supportedButtonFlags ["sv << util::hex(packet->supportedButtonFlags).to_string_view() << ']' << std::endl
      << "--end controller arrival packet--"sv;
  }

  /**
   * @brief Prints a controller touch packet.
   * @param packet The controller touch packet.
   */
  void print(PSS_CONTROLLER_TOUCH_PACKET packet) {
    BOOST_LOG(debug)
      << "--begin controller touch packet--"sv << std::endl
      << "controllerNumber ["sv << (uint32_t) packet->controllerNumber << ']' << std::endl
      << "eventType ["sv << util::hex(packet->eventType).to_string_view() << ']' << std::endl
      << "pointerId ["sv << util::hex(packet->pointerId).to_string_view() << ']' << std::endl
      << "x ["sv << from_netfloat(packet->x) << ']' << std::endl
      << "y ["sv << from_netfloat(packet->y) << ']' << std::endl
      << "pressure ["sv << from_netfloat(packet->pressure) << ']' << std::endl
      << "--end controller touch packet--"sv;
  }

  /**
   * @brief Prints a controller motion packet.
   * @param packet The controller motion packet.
   */
  void print(PSS_CONTROLLER_MOTION_PACKET packet) {
    BOOST_LOG(verbose)
      << "--begin controller motion packet--"sv << std::endl
      << "controllerNumber ["sv << util::hex(packet->controllerNumber).to_string_view() << ']' << std::endl
      << "motionType ["sv << util::hex(packet->motionType).to_string_view() << ']' << std::endl
      << "x ["sv << from_netfloat(packet->x) << ']' << std::endl
      << "y ["sv << from_netfloat(packet->y) << ']' << std::endl
      << "z ["sv << from_netfloat(packet->z) << ']' << std::endl
      << "--end controller motion packet--"sv;
  }

  /**
   * @brief Prints a controller battery packet.
   * @param packet The controller battery packet.
   */
  void print(PSS_CONTROLLER_BATTERY_PACKET packet) {
    BOOST_LOG(verbose)
      << "--begin controller battery packet--"sv << std::endl
      << "controllerNumber ["sv << util::hex(packet->controllerNumber).to_string_view() << ']' << std::endl
      << "batteryState ["sv << util::hex(packet->batteryState).to_string_view() << ']' << std::endl
      << "batteryPercentage ["sv << util::hex(packet->batteryPercentage).to_string_view() << ']' << std::endl
      << "--end controller battery packet--"sv;
  }

  /**
   * @brief Write a debug log representation of the input packet.
   */
  void print(void *payload) {
    auto header = (PNV_INPUT_HEADER) payload;

    switch (util::endian::little(header->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        print((PNV_REL_MOUSE_MOVE_PACKET) payload);
        break;
      case MOUSE_MOVE_ABS_MAGIC:
        print((PNV_ABS_MOUSE_MOVE_PACKET) payload);
        break;
      case MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5:
      case MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5:
        print((PNV_MOUSE_BUTTON_PACKET) payload);
        break;
      case SCROLL_MAGIC_GEN5:
        print((PNV_SCROLL_PACKET) payload);
        break;
      case SS_HSCROLL_MAGIC:
        print((PSS_HSCROLL_PACKET) payload);
        break;
      case KEY_DOWN_EVENT_MAGIC:
      case KEY_UP_EVENT_MAGIC:
        print((PNV_KEYBOARD_PACKET) payload);
        break;
      case UTF8_TEXT_EVENT_MAGIC:
        print((PNV_UNICODE_PACKET) payload);
        break;
      case MULTI_CONTROLLER_MAGIC_GEN5:
        print((PNV_MULTI_CONTROLLER_PACKET) payload);
        break;
      case SS_TOUCH_MAGIC:
        print((PSS_TOUCH_PACKET) payload);
        break;
      case SS_PEN_MAGIC:
        print((PSS_PEN_PACKET) payload);
        break;
      case SS_CONTROLLER_ARRIVAL_MAGIC:
        print((PSS_CONTROLLER_ARRIVAL_PACKET) payload);
        break;
      case SS_CONTROLLER_TOUCH_MAGIC:
        print((PSS_CONTROLLER_TOUCH_PACKET) payload);
        break;
      case SS_CONTROLLER_MOTION_MAGIC:
        print((PSS_CONTROLLER_MOTION_PACKET) payload);
        break;
      case SS_CONTROLLER_BATTERY_MAGIC:
        print((PSS_CONTROLLER_BATTERY_PACKET) payload);
        break;
    }
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  void passthrough(input_t *input, PNV_REL_MOUSE_MOVE_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    std::lock_guard lock(platform_input_mutex);
    const auto decision = input->delayed_left_button.on_relative_move();
    if (decision.cancel_timer) {
      input->dispatcher->cancel(input->mouse_left_button_timeout);
    }
    if (decision.emit_left_release) {
      update_platform_mouse_locked(*input, BUTTON_LEFT, true);
    }
    input->mouse_left_button_timeout = DISABLE_LEFT_BUTTON_DELAY;
    platf::move_mouse(platf_input, util::endian::big(packet->deltaX), util::endian::big(packet->deltaY));
  }

  /**
   * @brief Converts client coordinates on the specified surface into screen coordinates.
   * @param input The input context.
   * @param val The cartesian coordinate pair to convert.
   * @param size The size of the client's surface containing the value.
   * @return The host-relative coordinate pair if a touchport is available.
   */
  std::optional<std::pair<float, float>> client_to_touchport(input_t *input, const std::pair<float, float> &val, const std::pair<float, float> &size) {
    auto &touch_port_event = input->touch_port_event;
    auto &touch_port = input->touch_port;
    if (touch_port_event->peek()) {
      touch_port = *touch_port_event->pop();
    }
    if (!touch_port) {
      BOOST_LOG(verbose) << "Ignoring early absolute input without a touch port"sv;
      return std::nullopt;
    }

    auto scalarX = touch_port.width / size.first;
    auto scalarY = touch_port.height / size.second;

    float x = std::clamp(val.first, 0.0f, size.first) * scalarX;
    float y = std::clamp(val.second, 0.0f, size.second) * scalarY;

    auto offsetX = touch_port.client_offsetX;
    auto offsetY = touch_port.client_offsetY;

    x = std::clamp(x, offsetX, (size.first * scalarX) - offsetX);
    y = std::clamp(y, offsetY, (size.second * scalarY) - offsetY);

    /*
    x and y here below have the coordinates of the surface of the streaming resolution,
    and are dependent on how that comes configured from the client (scalar_inv is calculated
    from the proportion of that and the device's **physical** size).
    */
    x = (x - offsetX) * touch_port.scalar_inv;
    y = (y - offsetY) * touch_port.scalar_inv;

    /*
    This final operation is a bit weird and has been brought about with lots of trial and error. A better
    way to do this may exist.

    Basically, this is what makes the touchscreen map to the coordinates inputtino expects properly.
    Since inputtino's dimensions are now logical (because scaling breaks everything otherwise), using the previous
    x and y coordinates would be incorrect when screens are scaled, because the touch port is smaller (or larger)
    by a factor (that factor is touch_port.scalar_tpcoords), and that factor must be used to account for that difference
    when moving the cursor. Otherwise, it will move either slower or faster than your finger proportionally to
    scalar_tpcoords, and be offset *inversely* proportionally to scalar_tpcoords. So you must account for both differences
    by multiplying and dividing.
    */
    float final_x = (x + touch_port.offset_x * touch_port.scalar_tpcoords) / touch_port.scalar_tpcoords;
    float final_y = (y + touch_port.offset_y * touch_port.scalar_tpcoords) / touch_port.scalar_tpcoords;
    return std::pair {final_x, final_y};
  }

  /**
   * @brief Multiply a polar coordinate pair by a cartesian scaling factor.
   * @param r The radial coordinate.
   * @param angle The angular coordinate (radians).
   * @param scalar The scalar cartesian coordinate pair.
   * @return The scaled radial coordinate.
   */
  float multiply_polar_by_cartesian_scalar(float r, float angle, const std::pair<float, float> &scalar) {
    // Convert polar to cartesian coordinates
    float x = r * std::cos(angle);
    float y = r * std::sin(angle);

    // Scale the values
    x *= scalar.first;
    y *= scalar.second;

    // Convert the result back to a polar radial coordinate
    return std::sqrt(std::pow(x, 2) + std::pow(y, 2));
  }

  std::pair<float, float> scale_client_contact_area(const std::pair<float, float> &val, uint16_t rotation, const std::pair<float, float> &scalar) {
    // If the rotation is unknown, we'll just scale both axes equally by using
    // a 45-degree angle for our scaling calculations
    float angle = rotation == LI_ROT_UNKNOWN ? (M_PI / 4) : (rotation * (M_PI / 180));

    // If we have a major but not a minor axis, treat the touch as circular
    float major = val.first;
    float minor = val.second != 0.0f ? val.second : val.first;

    // The minor axis is perpendicular to major axis so the angle must be rotated by 90 degrees
    return {multiply_polar_by_cartesian_scalar(major, angle, scalar), multiply_polar_by_cartesian_scalar(minor, angle + (M_PI / 2), scalar)};
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  void passthrough(input_t *input, PNV_ABS_MOUSE_MOVE_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    {
      std::lock_guard lock(platform_input_mutex);
      input->delayed_left_button.on_absolute_move();
      if (input->mouse_left_button_timeout == DISABLE_LEFT_BUTTON_DELAY) {
        input->mouse_left_button_timeout = ENABLE_LEFT_BUTTON_DELAY;
      }
    }

    float x = util::endian::big(packet->x);
    float y = util::endian::big(packet->y);

    // Prevent divide by zero
    // Don't expect it to happen, but just in case
    if (!packet->width || !packet->height) {
      BOOST_LOG(warning) << "Moonlight passed invalid dimensions"sv;

      return;
    }

    auto width = (float) util::endian::big(packet->width);
    auto height = (float) util::endian::big(packet->height);

    auto tpcoords = client_to_touchport(input, {x, y}, {width, height});
    if (!tpcoords) {
      return;
    }

    auto &touch_port = input->touch_port;

    int touch_port_dim_x;
    int touch_port_dim_y;
    if (touch_port.env_logical_width != 0 && touch_port.env_logical_height != 0) {
      touch_port_dim_x = touch_port.env_logical_width;
      touch_port_dim_y = touch_port.env_logical_height;
    } else {
      touch_port_dim_x = touch_port.env_width;
      touch_port_dim_y = touch_port.env_height;
    }

    platf::touch_port_t abs_port {
      touch_port.offset_x,
      touch_port.offset_y,
      touch_port_dim_x,
      touch_port_dim_y
    };

    std::lock_guard lock(platform_input_mutex);
    platf::abs_mouse(platf_input, abs_port, tpcoords->first, tpcoords->second);
  }

  /**
   * @brief Called to pass a mouse button message to the platform backend.
   *
   * @param input The input context pointer.
   * @param packet The mouse button packet.
   */
  void passthrough(input_t *input, PNV_MOUSE_BUTTON_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    auto release = util::endian::little(packet->header.magic) == MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5;
    auto button = util::endian::big(packet->button);
    std::lock_guard lock(platform_input_mutex);

    if (button == BUTTON_LEFT && !release) {
      const auto decision = input->delayed_left_button.on_left_down();
      if (decision.cancel_timer) {
        input->dispatcher->cancel(input->mouse_left_button_timeout);
      }
      if (decision.emit_left_release) {
        update_platform_mouse_locked(*input, BUTTON_LEFT, true);
      }
      input->mouse_left_button_timeout = ENABLE_LEFT_BUTTON_DELAY;
    }
    if (button >= BUTTON_LEFT && button <= BUTTON_X2) {
      if (input->mouse_press[button] != release) {
        // button state is already what we want
        return;
      }

      input->mouse_press[button] = !release;
    }
    /**
     * When Moonlight sends mouse input through absolute coordinates,
     * it's possible that BUTTON_RIGHT is pressed down immediately after releasing BUTTON_LEFT.
     * As a result, Sunshine will left-click on hyperlinks in the browser before right-clicking
     *
     * This can be solved by delaying BUTTON_LEFT, however, any delay on input is undesirable during gaming
     * As a compromise, Sunshine will only put delays on BUTTON_LEFT when
     * absolute mouse coordinates have been sent.
     *
     * Try to make sure BUTTON_RIGHT gets called before BUTTON_LEFT is released.
     *
     * delayed_left_button determines whether this logical release needs a timer.
     */
    if (button == BUTTON_LEFT && release) {
      const auto decision = input->delayed_left_button.on_left_up();
      if (!decision.schedule_timer) {
        update_platform_mouse_locked(*input, button, release);
        return;
      }
      const auto generation = decision.generation;
      auto f = [input, generation]() {
        std::lock_guard lock(platform_input_mutex);
        const auto timer_decision = input->delayed_left_button.on_timer(
          generation,
          input->mouse_press[BUTTON_LEFT]
        );
        if (timer_decision.consume_timer) {
          input->mouse_left_button_timeout = ENABLE_LEFT_BUTTON_DELAY;
        }
        if (timer_decision.emit_left_release) {
          update_platform_mouse_locked(*input, BUTTON_LEFT, true);
        }
      };

      input->mouse_left_button_timeout = input->dispatcher->schedule(std::move(f), 10ms);

      return;
    }
    if (button == BUTTON_RIGHT && !release && input->delayed_left_button.on_right_down().synthesize_right_click) {
      update_platform_mouse_locked(*input, BUTTON_RIGHT, false);
      update_platform_mouse_locked(*input, BUTTON_RIGHT, true);
      input->mouse_press[BUTTON_RIGHT] = false;

      return;
    }

    update_platform_mouse_locked(*input, button, release);
  }

  /**
   * @brief Apply configured keybinding remaps to a platform keycode.
   *
   * @param keycode Platform keycode being translated or emitted.
   * @return Remapped keycode when configured, otherwise the original keycode.
   */
  short map_keycode(short keycode) {
    auto it = config::input.keybindings.find(keycode);
    if (it != std::end(config::input.keybindings)) {
      return it->second;
    }

    return keycode;
  }

  /**
   * @brief Update flags for keyboard shortcut combo's
   *
   * @param flags Bit flags that modify the requested operation.
   * @param keyCode Moonlight keyboard packet key code.
   * @param release Whether the key or button event is a release.
   */
  inline void update_shortcutFlags(int *flags, short keyCode, bool release) {
    switch (keyCode) {
      case VKEY_SHIFT:
      case VKEY_LSHIFT:
      case VKEY_RSHIFT:
        if (release) {
          *flags &= ~input_t::SHIFT;
        } else {
          *flags |= input_t::SHIFT;
        }
        break;
      case VKEY_CONTROL:
      case VKEY_LCONTROL:
      case VKEY_RCONTROL:
        if (release) {
          *flags &= ~input_t::CTRL;
        } else {
          *flags |= input_t::CTRL;
        }
        break;
      case VKEY_MENU:
      case VKEY_LMENU:
      case VKEY_RMENU:
        if (release) {
          *flags &= ~input_t::ALT;
        } else {
          *flags |= input_t::ALT;
        }
        break;
    }
  }

  /**
   * @brief Check whether modifier.
   *
   * @param keyCode Moonlight keyboard packet key code.
   * @return True when the key code is a keyboard modifier.
   */
  bool is_modifier(uint16_t keyCode) {
    switch (keyCode) {
      case VKEY_SHIFT:
      case VKEY_LSHIFT:
      case VKEY_RSHIFT:
      case VKEY_CONTROL:
      case VKEY_LCONTROL:
      case VKEY_RCONTROL:
      case VKEY_MENU:
      case VKEY_LMENU:
      case VKEY_RMENU:
        return true;
      default:
        return false;
    }
  }

  /**
   * @brief Send key and modifiers.
   *
   * @param key_code Moonlight keyboard packet key code.
   * @param release Whether the key or button event is a release.
   * @param flags Bit flags that modify the requested operation.
   * @param synthetic_modifiers Synthetic modifiers.
   */
  void send_key_and_modifiers(uint16_t key_code, bool release, uint8_t flags, uint8_t synthetic_modifiers) {
    std::lock_guard lock(platform_input_mutex);
    if (!release) {
      // Press any synthetic modifiers required for this key
      if (synthetic_modifiers & MODIFIER_SHIFT) {
        update_platform_keyboard_locked(VKEY_SHIFT, false, flags);
      }
      if (synthetic_modifiers & MODIFIER_CTRL) {
        update_platform_keyboard_locked(VKEY_CONTROL, false, flags);
      }
      if (synthetic_modifiers & MODIFIER_ALT) {
        update_platform_keyboard_locked(VKEY_MENU, false, flags);
      }
    }

    update_platform_keyboard_locked(key_code, release, flags);

    if (!release) {
      // Raise any synthetic modifier keys we pressed
      if (synthetic_modifiers & MODIFIER_SHIFT) {
        update_platform_keyboard_locked(VKEY_SHIFT, true, flags);
      }
      if (synthetic_modifiers & MODIFIER_CTRL) {
        update_platform_keyboard_locked(VKEY_CONTROL, true, flags);
      }
      if (synthetic_modifiers & MODIFIER_ALT) {
        update_platform_keyboard_locked(VKEY_MENU, true, flags);
      }
    }
  }

  /**
   * @brief Emit one repeat pulse without changing held-state reference counts.
   *
   * @param key_code Moonlight keyboard packet key code.
   * @param flags Bit flags that modify the requested operation.
   * @param synthetic_modifiers Synthetic modifiers required for the repeat pulse.
   */
  void send_key_repeat(uint16_t key_code, uint8_t flags, uint8_t synthetic_modifiers) {
    std::lock_guard lock(platform_input_mutex);
    if (synthetic_modifiers & MODIFIER_SHIFT) {
      update_platform_keyboard_locked(VKEY_SHIFT, false, flags);
    }
    if (synthetic_modifiers & MODIFIER_CTRL) {
      update_platform_keyboard_locked(VKEY_CONTROL, false, flags);
    }
    if (synthetic_modifiers & MODIFIER_ALT) {
      update_platform_keyboard_locked(VKEY_MENU, false, flags);
    }

    platf::keyboard_update(platf_input, map_keycode(key_code), false, flags);

    if (synthetic_modifiers & MODIFIER_SHIFT) {
      update_platform_keyboard_locked(VKEY_SHIFT, true, flags);
    }
    if (synthetic_modifiers & MODIFIER_CTRL) {
      update_platform_keyboard_locked(VKEY_CONTROL, true, flags);
    }
    if (synthetic_modifiers & MODIFIER_ALT) {
      update_platform_keyboard_locked(VKEY_MENU, true, flags);
    }
  }

  /**
   * @brief Re-emit a held key until its repeat task is cancelled.
   *
   * @param input Session whose dispatcher and held state own the repeat.
   * @param key_code Moonlight keyboard packet key code.
   * @param flags Bit flags that modify the requested operation.
   * @param synthetic_modifiers Synthetic modifiers.
   */
  void repeat_key(input_t *input, uint16_t key_code, uint8_t flags, uint8_t synthetic_modifiers) {
    // If key no longer pressed, stop repeating
    if (!input->key_press[make_kpid(key_code, flags)]) {
      input->key_press_repeat_id = 0;
      return;
    }

    // A hardware-style Virtual HID keyboard is repeated by the Windows keyboard stack.
    // Keep this task scheduled without injecting while that transport is active so a
    // one-way runtime fallback can resume the portable cadence without a second task.
#ifdef _WIN32
    if (!platf::uses_native_keyboard_repeat(platf_input)) {
      send_key_repeat(key_code, flags, synthetic_modifiers);
    }
#else
    send_key_repeat(key_code, flags, synthetic_modifiers);
#endif

    input->key_press_repeat_id = input->dispatcher->schedule(
      [input, key_code, flags, synthetic_modifiers]() {
        repeat_key(input, key_code, flags, synthetic_modifiers);
      },
      config::input.key_repeat_period
    );
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  void passthrough(input_t *input, PNV_KEYBOARD_PACKET packet) {
    if (!config::input.keyboard) {
      return;
    }

    auto release = util::endian::little(packet->header.magic) == KEY_UP_EVENT_MAGIC;
    auto keyCode = packet->keyCode & 0x00FF;

    if (keyCode == VKEY_LMENU) {
      input->left_alt_pressed = !release;
    } else if (keyCode == VKEY_RMENU) {
      input->right_alt_pressed = !release;
    }

    // Right-alt maps to meta, so it must not also register as ALT
    int modifiers = packet->modifiers;
    if (config::input.key_rightalt_to_key_win && input->right_alt_pressed && !input->left_alt_pressed) {
      modifiers &= ~MODIFIER_ALT;
    }

    // Set synthetic modifier flags if the keyboard packet is requesting modifier
    // keys that are not current pressed.
    uint8_t synthetic_modifiers = 0;
    if (!release && !is_modifier(keyCode)) {
      if (!(input->shortcutFlags & input_t::SHIFT) && (modifiers & MODIFIER_SHIFT)) {
        synthetic_modifiers |= MODIFIER_SHIFT;
      }
      if (!(input->shortcutFlags & input_t::CTRL) && (modifiers & MODIFIER_CTRL)) {
        synthetic_modifiers |= MODIFIER_CTRL;
      }
      if (!(input->shortcutFlags & input_t::ALT) && (modifiers & MODIFIER_ALT)) {
        synthetic_modifiers |= MODIFIER_ALT;
      }
    }

    auto &pressed = input->key_press[make_kpid(keyCode, packet->flags)];
    if (!pressed) {
      if (!release) {
        // A new key has been pressed down, we need to check for key combo's
        // If a key-combo has been pressed down, don't pass it through
        if (input->shortcutFlags == input_t::SHORTCUT && apply_shortcut(keyCode) > 0) {
          return;
        }

        if (input->key_press_repeat_id) {
          input->dispatcher->cancel(input->key_press_repeat_id);
        }

        if (config::input.key_repeat_delay.count() > 0) {
          input->key_press_repeat_id = input->dispatcher->schedule(
            [input, keyCode, flags = packet->flags, synthetic_modifiers]() {
              repeat_key(input, keyCode, flags, synthetic_modifiers);
            },
            config::input.key_repeat_delay
          );
        }
      } else {
        // Already released
        return;
      }
    } else if (!release) {
      // Already pressed down key
      return;
    }

    pressed = !release;

    send_key_and_modifiers(keyCode, release, packet->flags, synthetic_modifiers);

    update_shortcutFlags(&input->shortcutFlags, map_keycode(keyCode), release);
  }

  /**
   * @brief Called to pass a vertical scroll message the platform backend.
   * @param input The input context pointer.
   * @param packet The scroll packet.
   */
  void passthrough(input_t *input, PNV_SCROLL_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    if (config::input.high_resolution_scrolling) {
      std::lock_guard lock(platform_input_mutex);
      platf::scroll(platf_input, util::endian::big(packet->scrollAmt1));
    } else {
      input->accumulated_vscroll_delta += util::endian::big(packet->scrollAmt1);
      auto full_ticks = input->accumulated_vscroll_delta / WHEEL_DELTA;
      if (full_ticks) {
        // Send any full ticks that have accumulated and store the rest
        std::lock_guard lock(platform_input_mutex);
        platf::scroll(platf_input, full_ticks * WHEEL_DELTA);
        input->accumulated_vscroll_delta -= full_ticks * WHEEL_DELTA;
      }
    }
  }

  /**
   * @brief Called to pass a horizontal scroll message the platform backend.
   * @param input The input context pointer.
   * @param packet The scroll packet.
   */
  void passthrough(input_t *input, PSS_HSCROLL_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    if (config::input.high_resolution_scrolling) {
      std::lock_guard lock(platform_input_mutex);
      platf::hscroll(platf_input, util::endian::big(packet->scrollAmount));
    } else {
      input->accumulated_hscroll_delta += util::endian::big(packet->scrollAmount);
      auto full_ticks = input->accumulated_hscroll_delta / WHEEL_DELTA;
      if (full_ticks) {
        // Send any full ticks that have accumulated and store the rest
        std::lock_guard lock(platform_input_mutex);
        platf::hscroll(platf_input, full_ticks * WHEEL_DELTA);
        input->accumulated_hscroll_delta -= full_ticks * WHEEL_DELTA;
      }
    }
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param packet Protocol packet being processed.
   */
  void passthrough(PNV_UNICODE_PACKET packet) {
    if (!config::input.keyboard) {
      return;
    }

    int size = util::endian::big(packet->header.size) - sizeof(packet->header.magic);
    std::lock_guard lock(platform_input_mutex);
    platf::unicode(platf_input, packet->text, size);
  }

  /**
   * @brief Called to pass a controller arrival message to the platform backend.
   * @param input The input context pointer.
   * @param packet The controller arrival packet.
   */
  bool passthrough(input_t *input, PSS_CONTROLLER_ARRIVAL_PACKET packet) {
    if (!config::input.controller) {
      return false;
    }

    if (packet->controllerNumber < 0 || packet->controllerNumber >= input->gamepads.size()) {
      BOOST_LOG(warning) << "ControllerNumber out of range ["sv << packet->controllerNumber << ']';
      return false;
    }

    if (input->gamepads[packet->controllerNumber].id >= 0) {
      BOOST_LOG(warning) << "ControllerNumber already allocated ["sv << packet->controllerNumber << ']';
      return false;
    }

    platf::gamepad_arrival_t arrival {
      packet->type,
      util::endian::little(packet->capabilities),
      util::endian::little(packet->supportedButtonFlags),
    };

    const auto reservation = gamepad_slots.allocate();
    if (!reservation) {
      return false;
    }

    // Allocate a new gamepad
    if (platf::alloc_gamepad(platf_input, {reservation.id, packet->controllerNumber}, arrival, input->feedback_queue)) {
      gamepad_slots.release(reservation);
      return false;
    }

    auto &gamepad = input->gamepads[packet->controllerNumber];
    gamepad.reservation = reservation;
    gamepad.id = reservation.id;
    gamepad.timers.connect();
    return true;
  }

  /**
   * @brief Normalizes coordinates to monitor-local logical touch dimensions.
   * @param touch_port The current touch port metadata.
   * @param coords The in/out coordinate pair to normalize.
   * @return The monitor-local touch port, or std::nullopt if dimensions are invalid.
   */
  std::optional<platf::touch_port_t> monitor_touch_port(const input::touch_port_t &touch_port, std::pair<float, float> &coords) {
    const float monitor_logical_w = (touch_port.width * touch_port.scalar_inv) / touch_port.scalar_tpcoords;
    const float monitor_logical_h = (touch_port.height * touch_port.scalar_inv) / touch_port.scalar_tpcoords;
    if (monitor_logical_w <= 0.0f || monitor_logical_h <= 0.0f) {
      BOOST_LOG(warning) << "Ignoring touch/pen input due to invalid logical touch dimensions"sv;
      return std::nullopt;
    }

    coords.first = (coords.first - touch_port.offset_x) / monitor_logical_w;
    coords.second = (coords.second - touch_port.offset_y) / monitor_logical_h;

    return platf::touch_port_t {
      touch_port.offset_x,
      touch_port.offset_y,
      static_cast<int>(monitor_logical_w),
      static_cast<int>(monitor_logical_h)
    };
  }

  /**
   * @brief Called to pass a touch message to the platform backend.
   * @param input The input context pointer.
   * @param packet The touch packet.
   */
  void passthrough(input_t *input, PSS_TOUCH_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    // Convert the client normalized coordinates to touchport coordinates
    auto coords = client_to_touchport(input, {from_clamped_netfloat(packet->x, 0.0f, 1.0f) * 65535.f, from_clamped_netfloat(packet->y, 0.0f, 1.0f) * 65535.f}, {65535.f, 65535.f});
    if (!coords) {
      return;
    }

    auto &touch_port = input->touch_port;

    auto abs_port = monitor_touch_port(touch_port, *coords);
    if (!abs_port) {
      return;
    }

    // Normalize rotation value to 0-359 degree range
    auto rotation = util::endian::little(packet->rotation);
    if (rotation != LI_ROT_UNKNOWN) {
      rotation %= 360;
    }

    // Normalize the contact area based on the touchport
    auto contact_area = scale_client_contact_area(
      {from_clamped_netfloat(packet->contactAreaMajor, 0.0f, 1.0f) * 65535.f,
       from_clamped_netfloat(packet->contactAreaMinor, 0.0f, 1.0f) * 65535.f},
      rotation,
      {abs_port->width / 65535.f, abs_port->height / 65535.f}
    );

    platf::touch_input_t touch {
      packet->eventType,
      rotation,
      util::endian::little(packet->pointerId),
      coords->first,
      coords->second,
      from_clamped_netfloat(packet->pressureOrDistance, 0.0f, 1.0f),
      contact_area.first,
      contact_area.second,
    };

    platf::touch_update(input->client_context.get(), *abs_port, touch);
  }

  /**
   * @brief Called to pass a pen message to the platform backend.
   * @param input The input context pointer.
   * @param packet The pen packet.
   */
  void passthrough(input_t *input, PSS_PEN_PACKET packet) {
    if (!config::input.mouse) {
      return;
    }

    // Convert the client normalized coordinates to touchport coordinates
    auto coords = client_to_touchport(input, {from_clamped_netfloat(packet->x, 0.0f, 1.0f) * 65535.f, from_clamped_netfloat(packet->y, 0.0f, 1.0f) * 65535.f}, {65535.f, 65535.f});
    if (!coords) {
      return;
    }

    auto &touch_port = input->touch_port;

    auto abs_port = monitor_touch_port(touch_port, *coords);
    if (!abs_port) {
      return;
    }

    // Normalize rotation value to 0-359 degree range
    auto rotation = util::endian::little(packet->rotation);
    if (rotation != LI_ROT_UNKNOWN) {
      rotation %= 360;
    }

    // Normalize the contact area based on the touchport
    auto contact_area = scale_client_contact_area(
      {from_clamped_netfloat(packet->contactAreaMajor, 0.0f, 1.0f) * 65535.f,
       from_clamped_netfloat(packet->contactAreaMinor, 0.0f, 1.0f) * 65535.f},
      rotation,
      {abs_port->width / 65535.f, abs_port->height / 65535.f}
    );

    platf::pen_input_t pen {
      packet->eventType,
      packet->toolType,
      packet->penButtons,
      packet->tilt,
      rotation,
      coords->first,
      coords->second,
      from_clamped_netfloat(packet->pressureOrDistance, 0.0f, 1.0f),
      contact_area.first,
      contact_area.second,
    };

    platf::pen_update(input->client_context.get(), *abs_port, pen);
  }

  /**
   * @brief Called to pass a controller touch message to the platform backend.
   * @param input The input context pointer.
   * @param packet The controller touch packet.
   */
  bool passthrough(input_t *input, PSS_CONTROLLER_TOUCH_PACKET packet) {
    if (!config::input.controller) {
      return false;
    }

    if (packet->controllerNumber < 0 || packet->controllerNumber >= input->gamepads.size()) {
      BOOST_LOG(warning) << "ControllerNumber out of range ["sv << packet->controllerNumber << ']';
      return false;
    }

    auto &gamepad = input->gamepads[packet->controllerNumber];
    if (gamepad.id < 0) {
      BOOST_LOG(warning) << "ControllerNumber ["sv << packet->controllerNumber << "] not allocated"sv;
      return false;
    }

    platf::gamepad_touch_t touch {
      {gamepad.id, packet->controllerNumber},
      packet->eventType,
      util::endian::little(packet->pointerId),
      from_clamped_netfloat(packet->x, 0.0f, 1.0f),
      from_clamped_netfloat(packet->y, 0.0f, 1.0f),
      from_clamped_netfloat(packet->pressure, 0.0f, 1.0f),
    };

    platf::gamepad_touch(platf_input, touch);
    return true;
  }

  /**
   * @brief Called to pass a controller motion message to the platform backend.
   * @param input The input context pointer.
   * @param packet The controller motion packet.
   */
  bool passthrough(input_t *input, PSS_CONTROLLER_MOTION_PACKET packet) {
    if (!config::input.controller) {
      return false;
    }

    if (packet->controllerNumber < 0 || packet->controllerNumber >= input->gamepads.size()) {
      BOOST_LOG(warning) << "ControllerNumber out of range ["sv << packet->controllerNumber << ']';
      return false;
    }

    auto &gamepad = input->gamepads[packet->controllerNumber];
    if (gamepad.id < 0) {
      BOOST_LOG(warning) << "ControllerNumber ["sv << packet->controllerNumber << "] not allocated"sv;
      return false;
    }

    platf::gamepad_motion_t motion {
      {gamepad.id, packet->controllerNumber},
      packet->motionType,
      from_netfloat(packet->x),
      from_netfloat(packet->y),
      from_netfloat(packet->z),
    };

    platf::gamepad_motion(platf_input, motion);
    return true;
  }

  /**
   * @brief Called to pass a controller battery message to the platform backend.
   * @param input The input context pointer.
   * @param packet The controller battery packet.
   */
  bool passthrough(input_t *input, PSS_CONTROLLER_BATTERY_PACKET packet) {
    if (!config::input.controller) {
      return false;
    }

    if (packet->controllerNumber < 0 || packet->controllerNumber >= input->gamepads.size()) {
      BOOST_LOG(warning) << "ControllerNumber out of range ["sv << packet->controllerNumber << ']';
      return false;
    }

    auto &gamepad = input->gamepads[packet->controllerNumber];
    if (gamepad.id < 0) {
      BOOST_LOG(warning) << "ControllerNumber ["sv << packet->controllerNumber << "] not allocated"sv;
      return false;
    }

    platf::gamepad_battery_t battery {
      {gamepad.id, packet->controllerNumber},
      packet->batteryState,
      packet->batteryPercentage
    };

    platf::gamepad_battery(platf_input, battery);
    return true;
  }

  /**
   * @brief Forward a client input packet directly to the platform backend.
   *
   * @param input Platform input backend that receives the event.
   * @param packet Protocol packet being processed.
   */
  bool passthrough(input_t *input, PNV_MULTI_CONTROLLER_PACKET packet) {
    if (!config::input.controller) {
      return false;
    }

    if (packet->controllerNumber < 0 || packet->controllerNumber >= input->gamepads.size()) {
      BOOST_LOG(warning) << "ControllerNumber out of range ["sv << packet->controllerNumber << ']';

      return false;
    }

    auto &gamepad = input->gamepads[packet->controllerNumber];

    // If this is an event for a new gamepad, create the gamepad now. Ideally, the client would
    // send a controller arrival instead of this but it's still supported for legacy clients.
    if ((packet->activeGamepadMask & (1 << packet->controllerNumber)) && gamepad.id < 0) {
      const auto reservation = gamepad_slots.allocate();
      if (!reservation) {
        return false;
      }

      if (platf::alloc_gamepad(platf_input, {reservation.id, (uint8_t) packet->controllerNumber}, {}, input->feedback_queue)) {
        gamepad_slots.release(reservation);
        return false;
      }

      gamepad.reservation = reservation;
      gamepad.id = reservation.id;
      gamepad.timers.connect();
    } else if (!(packet->activeGamepadMask & (1 << packet->controllerNumber)) && gamepad.id >= 0) {
      // If this is the final event for a gamepad being removed, free the gamepad and return.
      disconnect_controller_timers(*input, gamepad);
      free_gamepad(platf_input, gamepad.reservation);
      gamepad.reservation = {};
      gamepad.id = -1;
      gamepad.gamepad_state = {};
      gamepad.back_button_state = button_state_e::NONE;
      return true;
    }

    // If this gamepad has not been initialized, ignore it.
    // This could happen when platf::alloc_gamepad fails
    if (gamepad.id < 0) {
      BOOST_LOG(warning) << "ControllerNumber ["sv << packet->controllerNumber << "] not allocated"sv;
      return false;
    }

    std::uint16_t bf = packet->buttonFlags;
    std::uint32_t bf2 = packet->buttonFlags2;
    platf::gamepad_state_t gamepad_state {
      bf | (bf2 << 16),
      packet->leftTrigger,
      packet->rightTrigger,
      packet->leftStickX,
      packet->leftStickY,
      packet->rightStickX,
      packet->rightStickY
    };

    auto bf_new = gamepad_state.buttonFlags;
    switch (gamepad.back_button_state) {
      case button_state_e::UP:
        if (!(platf::BACK & bf_new)) {
          gamepad.back_button_state = button_state_e::NONE;
        }
        gamepad_state.buttonFlags &= ~platf::BACK;
        break;
      case button_state_e::DOWN:
        if (platf::BACK & bf_new) {
          gamepad.back_button_state = button_state_e::NONE;
        }
        gamepad_state.buttonFlags |= platf::BACK;
        break;
      case button_state_e::NONE:
        break;
    }

    bf = gamepad_state.buttonFlags ^ gamepad.gamepad_state.buttonFlags;
    bf_new = gamepad_state.buttonFlags;

    if (platf::BACK & bf) {
      if (platf::BACK & bf_new) {
        // Don't emulate home button if timeout < 0
        if (config::input.back_button_timeout >= 0ms) {
          const auto controller_generation = gamepad.timers.generation();
          auto f = [input, controller = packet->controllerNumber, controller_generation]() {
            auto &gamepad = input->gamepads[controller];
            if (gamepad.id < 0 || !gamepad.timers.is_current(controller_generation)) {
              return;
            }

            auto &state = gamepad.gamepad_state;

            // Force the back button up
            gamepad.back_button_state = button_state_e::UP;
            state.buttonFlags &= ~platf::BACK;
            platf::gamepad_update(platf_input, gamepad.id, state);

            // Press Home button
            state.buttonFlags |= platf::HOME;
            platf::gamepad_update(platf_input, gamepad.id, state);

            gamepad.timers.set_timeout(0);
            gamepad.timers.set_release(input->dispatcher->schedule([input, controller, controller_generation]() {
              auto &gamepad = input->gamepads[controller];
              if (gamepad.id < 0 || !gamepad.timers.is_current(controller_generation)) {
                return;
              }
              gamepad.gamepad_state.buttonFlags &= ~platf::HOME;
              platf::gamepad_update(platf_input, gamepad.id, gamepad.gamepad_state);
              gamepad.timers.set_release(0);
            },
                                                                   100ms));
          };

          gamepad.timers.set_timeout(input->dispatcher->schedule(std::move(f), config::input.back_button_timeout));
        }
      } else if (gamepad.timers.timeout()) {
        input->dispatcher->cancel(gamepad.timers.timeout());
        gamepad.timers.set_timeout(0);
      }
    }

    platf::gamepad_update(platf_input, gamepad.id, gamepad_state);

    gamepad.gamepad_state = gamepad_state;
    return true;
  }

  /**
   * @brief Enumerates supported batch result options.
   */
  enum class batch_result_e {
    batched,  ///< This entry was batched with the source entry
    not_batchable,  ///< Not eligible to batch but continue attempts to batch
    terminate_batch,  ///< Stop trying to batch with this entry
  };

  /**
   * @brief Batch two relative mouse messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_REL_MOUSE_MOVE_PACKET dest, PNV_REL_MOUSE_MOVE_PACKET src) {
    std::int16_t delta_x;
    std::int16_t delta_y;

    // Batching is safe as long as the result doesn't overflow a 16-bit integer
    if (!detail::checked_add_int16(util::endian::big(dest->deltaX), util::endian::big(src->deltaX), delta_x)) {
      return batch_result_e::terminate_batch;
    }
    if (!detail::checked_add_int16(util::endian::big(dest->deltaY), util::endian::big(src->deltaY), delta_y)) {
      return batch_result_e::terminate_batch;
    }

    // Take the sum of deltas
    dest->deltaX = util::endian::big(delta_x);
    dest->deltaY = util::endian::big(delta_y);
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two absolute mouse messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_ABS_MOUSE_MOVE_PACKET dest, PNV_ABS_MOUSE_MOVE_PACKET src) {
    // Batching must only happen if the reference width and height don't change
    if (dest->width != src->width || dest->height != src->height) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest absolute position
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two vertical scroll messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_SCROLL_PACKET dest, PNV_SCROLL_PACKET src) {
    std::int16_t scroll_amount;

    // Batching is safe as long as the result doesn't overflow a 16-bit integer
    if (!detail::checked_add_int16(util::endian::big(dest->scrollAmt1), util::endian::big(src->scrollAmt1), scroll_amount)) {
      return batch_result_e::terminate_batch;
    }

    // Take the sum of delta
    dest->scrollAmt1 = util::endian::big(scroll_amount);
    dest->scrollAmt2 = util::endian::big(scroll_amount);
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two horizontal scroll messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_HSCROLL_PACKET dest, PSS_HSCROLL_PACKET src) {
    std::int16_t scroll_amount;

    // Batching is safe as long as the result doesn't overflow a 16-bit integer
    if (!detail::checked_add_int16(util::endian::big(dest->scrollAmount), util::endian::big(src->scrollAmount), scroll_amount)) {
      return batch_result_e::terminate_batch;
    }

    // Take the sum of delta
    dest->scrollAmount = util::endian::big(scroll_amount);
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two controller state messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_MULTI_CONTROLLER_PACKET dest, PNV_MULTI_CONTROLLER_PACKET src) {
    // Do not allow batching if the active controllers change
    if (dest->activeGamepadMask != src->activeGamepadMask) {
      return batch_result_e::terminate_batch;
    }

    // We can only batch entries for the same controller, but allow batching attempts to continue
    // in case we have more packets for this controller later in the queue.
    if (dest->controllerNumber != src->controllerNumber) {
      return batch_result_e::not_batchable;
    }

    // Do not allow batching if the button state changes on this controller
    if (dest->buttonFlags != src->buttonFlags || dest->buttonFlags2 != src->buttonFlags2) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest state
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two touch messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_TOUCH_PACKET dest, PSS_TOUCH_PACKET src) {
    // Only batch hover or move events
    if (dest->eventType != LI_TOUCH_EVENT_MOVE && dest->eventType != LI_TOUCH_EVENT_HOVER) {
      return batch_result_e::terminate_batch;
    }

    // Don't batch beyond state changing events
    if (src->eventType != LI_TOUCH_EVENT_MOVE && src->eventType != LI_TOUCH_EVENT_HOVER) {
      return batch_result_e::terminate_batch;
    }

    // Batched events must be the same pointer ID
    if (dest->pointerId != src->pointerId) {
      return batch_result_e::not_batchable;
    }

    // The pointer must be in the same state
    if (dest->eventType != src->eventType) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest state
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two pen messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_PEN_PACKET dest, PSS_PEN_PACKET src) {
    // Only batch hover or move events
    if (dest->eventType != LI_TOUCH_EVENT_MOVE && dest->eventType != LI_TOUCH_EVENT_HOVER) {
      return batch_result_e::terminate_batch;
    }

    // Batched events must be the same type
    if (dest->eventType != src->eventType) {
      return batch_result_e::terminate_batch;
    }

    // Do not allow batching if the button state changes
    if (dest->penButtons != src->penButtons) {
      return batch_result_e::terminate_batch;
    }

    // Do not batch beyond tool changes
    if (dest->toolType != src->toolType) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest state
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two controller touch messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_CONTROLLER_TOUCH_PACKET dest, PSS_CONTROLLER_TOUCH_PACKET src) {
    // Only batch hover or move events
    if (dest->eventType != LI_TOUCH_EVENT_MOVE && dest->eventType != LI_TOUCH_EVENT_HOVER) {
      return batch_result_e::terminate_batch;
    }

    // We can only batch entries for the same controller, but allow batching attempts to continue
    // in case we have more packets for this controller later in the queue.
    if (dest->controllerNumber != src->controllerNumber) {
      return batch_result_e::not_batchable;
    }

    // Don't batch beyond state changing events
    if (src->eventType != LI_TOUCH_EVENT_MOVE && src->eventType != LI_TOUCH_EVENT_HOVER) {
      return batch_result_e::terminate_batch;
    }

    // Batched events must be the same pointer ID
    if (dest->pointerId != src->pointerId) {
      return batch_result_e::not_batchable;
    }

    // The pointer must be in the same state
    if (dest->eventType != src->eventType) {
      return batch_result_e::terminate_batch;
    }

    // Take the latest state
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two controller motion messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PSS_CONTROLLER_MOTION_PACKET dest, PSS_CONTROLLER_MOTION_PACKET src) {
    // We can only batch entries for the same controller, but allow batching attempts to continue
    // in case we have more packets for this controller later in the queue.
    if (dest->controllerNumber != src->controllerNumber) {
      return batch_result_e::not_batchable;
    }

    // Batched events must be the same sensor
    if (dest->motionType != src->motionType) {
      return batch_result_e::not_batchable;
    }

    // Take the latest state
    *dest = *src;
    return batch_result_e::batched;
  }

  /**
   * @brief Batch two input messages.
   * @param dest The original packet to batch into.
   * @param src A later packet to attempt to batch.
   * @return The status of the batching operation.
   */
  batch_result_e batch(PNV_INPUT_HEADER dest, PNV_INPUT_HEADER src) {
    // We can only batch if the packet types are the same
    if (dest->magic != src->magic) {
      return batch_result_e::terminate_batch;
    }

    // We can only batch certain message types
    switch (util::endian::little(dest->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        return batch((PNV_REL_MOUSE_MOVE_PACKET) dest, (PNV_REL_MOUSE_MOVE_PACKET) src);
      case MOUSE_MOVE_ABS_MAGIC:
        return batch((PNV_ABS_MOUSE_MOVE_PACKET) dest, (PNV_ABS_MOUSE_MOVE_PACKET) src);
      case SCROLL_MAGIC_GEN5:
        return batch((PNV_SCROLL_PACKET) dest, (PNV_SCROLL_PACKET) src);
      case SS_HSCROLL_MAGIC:
        return batch((PSS_HSCROLL_PACKET) dest, (PSS_HSCROLL_PACKET) src);
      case MULTI_CONTROLLER_MAGIC_GEN5:
        return batch((PNV_MULTI_CONTROLLER_PACKET) dest, (PNV_MULTI_CONTROLLER_PACKET) src);
      case SS_TOUCH_MAGIC:
        return batch((PSS_TOUCH_PACKET) dest, (PSS_TOUCH_PACKET) src);
      case SS_PEN_MAGIC:
        return batch((PSS_PEN_PACKET) dest, (PSS_PEN_PACKET) src);
      case SS_CONTROLLER_TOUCH_MAGIC:
        return batch((PSS_CONTROLLER_TOUCH_PACKET) dest, (PSS_CONTROLLER_TOUCH_PACKET) src);
      case SS_CONTROLLER_MOTION_MAGIC:
        return batch((PSS_CONTROLLER_MOTION_PACKET) dest, (PSS_CONTROLLER_MOTION_PACKET) src);
      default:
        // Not a batchable message type
        return batch_result_e::terminate_batch;
    }
  }

#ifdef SUNSHINE_TESTS
  bool detail::batch_relative_mouse_for_test(std::int16_t &dest_x, std::int16_t &dest_y, std::int16_t src_x, std::int16_t src_y) {
    NV_REL_MOUSE_MOVE_PACKET dest {};
    NV_REL_MOUSE_MOVE_PACKET src {};
    dest.deltaX = util::endian::big(dest_x);
    dest.deltaY = util::endian::big(dest_y);
    src.deltaX = util::endian::big(src_x);
    src.deltaY = util::endian::big(src_y);

    const auto result = batch(&dest, &src);
    dest_x = util::endian::big(dest.deltaX);
    dest_y = util::endian::big(dest.deltaY);
    return result == batch_result_e::batched;
  }

  bool detail::batch_vertical_scroll_for_test(std::int16_t &dest_primary, std::int16_t &dest_secondary, std::int16_t src_amount) {
    NV_SCROLL_PACKET dest {};
    NV_SCROLL_PACKET src {};
    dest.scrollAmt1 = util::endian::big(dest_primary);
    dest.scrollAmt2 = util::endian::big(dest_secondary);
    src.scrollAmt1 = util::endian::big(src_amount);
    src.scrollAmt2 = util::endian::big(src_amount);

    const auto result = batch(&dest, &src);
    dest_primary = util::endian::big(dest.scrollAmt1);
    dest_secondary = util::endian::big(dest.scrollAmt2);
    return result == batch_result_e::batched;
  }

  bool detail::batch_horizontal_scroll_for_test(std::int16_t &dest_amount, std::int16_t src_amount) {
    SS_HSCROLL_PACKET dest {};
    SS_HSCROLL_PACKET src {};
    dest.scrollAmount = util::endian::big(dest_amount);
    src.scrollAmount = util::endian::big(src_amount);

    const auto result = batch(&dest, &src);
    dest_amount = util::endian::big(dest.scrollAmount);
    return result == batch_result_e::batched;
  }
#endif

  /**
   * @brief Check whether a packet contains state-neutral pointer motion.
   *
   * @param entry Raw input packet.
   * @return True only for relative or absolute mouse motion.
   */
  bool is_mouse_motion_packet(const std::vector<std::uint8_t> &entry) {
    if (entry.size() < sizeof(NV_INPUT_HEADER)) {
      return false;
    }
    const auto payload = reinterpret_cast<const NV_INPUT_HEADER *>(entry.data());
    const auto magic = util::endian::little(payload->magic);
    return magic == MOUSE_MOVE_REL_MAGIC_GEN5 || magic == MOUSE_MOVE_ABS_MAGIC;
  }

  /**
   * @brief Preserve every accepted legacy input packet under backpressure.
   *
   * Relative and absolute pointer motion can determine the target of a following
   * button edge, so legacy packets are coalesced consecutively but never dropped.
   *
   * @param entry Raw input packet.
   * @return Always false.
   */
  bool is_droppable_legacy_input_packet(const std::vector<std::uint8_t> &entry) {
    (void) entry;
    return false;
  }

  /**
   * @brief Coalesce only consecutive compatible mouse-motion packets.
   *
   * @param destination Existing FIFO tail packet.
   * @param source Newly received packet.
   * @return True when source was safely merged into destination.
   */
  bool coalesce_mouse_motion(std::vector<std::uint8_t> &destination, std::vector<std::uint8_t> &source) {
    if (!is_mouse_motion_packet(destination) || !is_mouse_motion_packet(source)) {
      return false;
    }
    auto destination_header = reinterpret_cast<PNV_INPUT_HEADER>(destination.data());
    auto source_header = reinterpret_cast<PNV_INPUT_HEADER>(source.data());
    if (destination_header->magic != source_header->magic) {
      return false;
    }

    switch (util::endian::little(destination_header->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        if (destination.size() < sizeof(NV_REL_MOUSE_MOVE_PACKET) || source.size() < sizeof(NV_REL_MOUSE_MOVE_PACKET)) {
          return false;
        }
        return batch(
                 reinterpret_cast<PNV_REL_MOUSE_MOVE_PACKET>(destination.data()),
                 reinterpret_cast<PNV_REL_MOUSE_MOVE_PACKET>(source.data())
               ) == batch_result_e::batched;
      case MOUSE_MOVE_ABS_MAGIC:
        if (destination.size() < sizeof(NV_ABS_MOUSE_MOVE_PACKET) || source.size() < sizeof(NV_ABS_MOUSE_MOVE_PACKET)) {
          return false;
        }
        return batch(
                 reinterpret_cast<PNV_ABS_MOUSE_MOVE_PACKET>(destination.data()),
                 reinterpret_cast<PNV_ABS_MOUSE_MOVE_PACKET>(source.data())
               ) == batch_result_e::batched;
      default:
        return false;
    }
  }

#ifdef _WIN32
  /**
   * @brief MMCSS Games registration retained for the lifetime of one input consumer thread.
   */
  class input_mmcss_guard_t {
  public:
    /**
     * @brief Register the current thread with the MMCSS Games task at high priority.
     */
    input_mmcss_guard_t() {
      DWORD task_index = 0;
      handle_ = AvSetMmThreadCharacteristicsW(L"Games", &task_index);
      if (!handle_) {
        BOOST_LOG(warning) << "Unable to register ordered input thread with MMCSS Games: "sv << GetLastError();
        return;
      }
      if (!AvSetMmThreadPriority(handle_, AVRT_PRIORITY_HIGH)) {
        BOOST_LOG(warning) << "Unable to raise ordered input MMCSS priority: "sv << GetLastError();
      }
    }

    /**
     * @brief Revert MMCSS registration on consumer-thread exit.
     */
    ~input_mmcss_guard_t() {
      if (handle_) {
        AvRevertMmThreadCharacteristics(handle_);
      }
    }

  private:
    HANDLE handle_ {nullptr};  ///< MMCSS registration handle.
  };
#endif

  /**
   * @brief Configure the dedicated input consumer for latency-sensitive scheduling.
   */
  void configure_input_dispatch_thread() {
    platf::set_thread_name("input::ordered");
    platf::adjust_thread_priority(platf::thread_priority_e::critical);
#ifdef _WIN32
    static thread_local input_mmcss_guard_t mmcss_guard;
    (void) mmcss_guard;
#endif
  }

  /**
   * @brief Process one raw message on its session's ordered consumer.
   *
   * @param input The input context pointer.
   * @param entry Raw packet owning the payload storage.
   */
  bool passthrough_next_message(input_t *input, std::vector<std::uint8_t> entry) {
    if (entry.size() < sizeof(NV_INPUT_HEADER)) {
      BOOST_LOG(warning) << "Ignoring undersized input packet"sv;
      return false;
    }
    auto payload = reinterpret_cast<PNV_INPUT_HEADER>(entry.data());

    // Print the final input packet
    input::print((void *) payload);

    // Send the batched input to the OS
    switch (util::endian::little(payload->magic)) {
      case MOUSE_MOVE_REL_MAGIC_GEN5:
        passthrough(input, (PNV_REL_MOUSE_MOVE_PACKET) payload);
        return true;
      case MOUSE_MOVE_ABS_MAGIC:
        passthrough(input, (PNV_ABS_MOUSE_MOVE_PACKET) payload);
        return true;
      case MOUSE_BUTTON_DOWN_EVENT_MAGIC_GEN5:
      case MOUSE_BUTTON_UP_EVENT_MAGIC_GEN5:
        passthrough(input, (PNV_MOUSE_BUTTON_PACKET) payload);
        return true;
      case SCROLL_MAGIC_GEN5:
        passthrough(input, (PNV_SCROLL_PACKET) payload);
        return true;
      case SS_HSCROLL_MAGIC:
        passthrough(input, (PSS_HSCROLL_PACKET) payload);
        return true;
      case KEY_DOWN_EVENT_MAGIC:
      case KEY_UP_EVENT_MAGIC:
        passthrough(input, (PNV_KEYBOARD_PACKET) payload);
        return true;
      case UTF8_TEXT_EVENT_MAGIC:
        passthrough((PNV_UNICODE_PACKET) payload);
        return true;
      case MULTI_CONTROLLER_MAGIC_GEN5:
        return passthrough(input, (PNV_MULTI_CONTROLLER_PACKET) payload);
      case SS_TOUCH_MAGIC:
        passthrough(input, (PSS_TOUCH_PACKET) payload);
        return true;
      case SS_PEN_MAGIC:
        passthrough(input, (PSS_PEN_PACKET) payload);
        return true;
      case SS_CONTROLLER_ARRIVAL_MAGIC:
        return passthrough(input, (PSS_CONTROLLER_ARRIVAL_PACKET) payload);
      case SS_CONTROLLER_TOUCH_MAGIC:
        return passthrough(input, (PSS_CONTROLLER_TOUCH_PACKET) payload);
      case SS_CONTROLLER_MOTION_MAGIC:
        return passthrough(input, (PSS_CONTROLLER_MOTION_PACKET) payload);
      case SS_CONTROLLER_BATTERY_MAGIC:
        return passthrough(input, (PSS_CONTROLLER_BATTERY_PACKET) payload);
      default:
        return false;
    }
  }

#ifdef SUNSHINE_TESTS
  bool detail::passthrough_packet_for_test(input_t *input, std::vector<std::uint8_t> packet) {
    return passthrough_next_message(input, std::move(packet));
  }
#endif

  /**
   * @brief Called on the control stream thread to queue an input message.
   * @param input The input context pointer.
   * @param input_data The input message.
   */
  bool passthrough(std::shared_ptr<input_t> &input, std::vector<std::uint8_t> &&input_data) {
    if (!input || !input->dispatcher) {
      return false;
    }
    const auto result = input->dispatcher->enqueue(std::move(input_data));
    if (result == input_t::dispatcher_t::enqueue_result_e::closed) {
      BOOST_LOG(debug) << "Ignoring input packet after ordered dispatcher shutdown"sv;
    }
    return result == input_t::dispatcher_t::enqueue_result_e::queued ||
           result == input_t::dispatcher_t::enqueue_result_e::coalesced;
  }

  bool passthrough_state(
    std::shared_ptr<input_t> &input,
    ordered_state_operation_t operation,
    bool supersedable,
    std::function<void()> completion
  ) {
    if (!input || !input->dispatcher || !operation) {
      return false;
    }
    auto *const raw_input = input.get();
    const auto result = input->dispatcher->enqueue_operation(
      [raw_input, operation = std::move(operation), completion = std::move(completion)]() mutable {
        const ordered_injector_t injector {[raw_input](std::vector<std::uint8_t> &&packet) {
          return passthrough_next_message(raw_input, std::move(packet));
        }};
        if (!operation(injector)) {
          throw std::runtime_error {"protocol-v3 ordered input operation failed"};
        }
        if (completion) {
          completion();
        }
      },
      supersedable
    );
    if (result == input_t::dispatcher_t::enqueue_result_e::closed) {
      BOOST_LOG(debug) << "Ignoring protocol-v3 input state after ordered dispatcher shutdown"sv;
      return false;
    }
    return true;
  }

  /**
   * @brief Seal a session dispatcher early so blocked control-stream producers wake for shutdown.
   *
   * @param input Shared stream input state to seal.
   */
  void begin_close(std::shared_ptr<input_t> &input) {
    if (input && input->dispatcher) {
      input->dispatcher->begin_close();
    }
  }

  /**
   * @brief Neutralize all state after the ordered packet fence is reached.
   *
   * @param input Session input state to neutralize.
   */
  void neutralize_input(input_t &input) {
    {
      std::lock_guard lock(platform_input_mutex);
      input.delayed_left_button.on_reset();
      for (int button = BUTTON_LEFT; button <= BUTTON_X2; ++button) {
        input.mouse_press[button] = false;
        if (input.mouse_platform_press[button]) {
          update_platform_mouse_locked(input, button, true);
        }
      }
      input.mouse_left_button_timeout = ENABLE_LEFT_BUTTON_DELAY;

      for (auto &[key, pressed] : input.key_press) {
        if (pressed) {
          update_platform_keyboard_locked(vk_from_kpid(key), true, flags_from_kpid(key));
          pressed = false;
        }
      }
    }
    input.key_press_repeat_id = 0;
    input.shortcutFlags = 0;
    input.left_alt_pressed = false;
    input.right_alt_pressed = false;

    for (auto &gamepad : input.gamepads) {
      disconnect_controller_timers(input, gamepad);
      if (gamepad.id >= 0) {
        gamepad.gamepad_state = {};
        gamepad.back_button_state = button_state_e::NONE;
        platf::gamepad_update(platf_input, gamepad.id, gamepad.gamepad_state);
      }
    }
    const auto registration = input.session_registration;
    input.session_registration = 0;
    input_session_gate.unregister_session(registration, []() {
#ifdef _WIN32
      // Shared Virtual HID reset is safe only after the final input session
      // has released every higher-level held-state contribution.
      platf::reset_input_session(platf_input);
#endif
    });
  }

  /**
   * @brief Log an ordered-dispatch failure and neutralize its session exactly once.
   *
   * @param input Session that failed closed.
   * @param failure Captured setup or injection exception.
   */
  void handle_input_dispatch_failure(input_t *input, std::exception_ptr failure) noexcept {
    try {
      try {
        if (failure) {
          std::rethrow_exception(failure);
        }
        BOOST_LOG(error) << "Ordered input dispatcher failed without an exception"sv;
      } catch (const std::exception &failure_error) {
        BOOST_LOG(error) << "Ordered input dispatcher failed closed: "sv << failure_error.what();
      } catch (...) {
        BOOST_LOG(error) << "Ordered input dispatcher failed closed with an unknown exception"sv;
      }
    } catch (...) {
      // Logging must not escape the dedicated thread failure boundary.
    }

    try {
      neutralize_input(*input);
    } catch (...) {
      try {
        BOOST_LOG(error) << "Ordered input dispatcher neutralization failed"sv;
      } catch (...) {
        // Logging must not escape the dedicated thread failure boundary.
      }
    }
  }

  /**
   * @brief Reset the object after all already-accepted packets, then join its consumer.
   */
  void reset(std::shared_ptr<input_t> &input) {
    auto *const raw_input = input.get();
    input->dispatcher->close_after_fence([raw_input]() {
      neutralize_input(*raw_input);
    });
  }

  /**
   * @brief RAII helper that runs shutdown cleanup when destroyed.
   */
  class deinit_t: public platf::deinit_t {
  public:
    /**
     * @brief Destroy the input subsystem deinitializer.
     */
    ~deinit_t() override {
      platf_input.reset();
    }
  };

  /**
   * @brief Initialize the platform input backend.
   */
  [[nodiscard]] std::unique_ptr<platf::deinit_t> init() {
    platf_input = platf::input();

    return std::make_unique<deinit_t>();
  }

  /**
   * @brief Probe connected gamepads and update input capability state.
   */
  bool probe_gamepads() {
    auto input = static_cast<platf::input_t *>(platf_input.get());
    const auto gamepads = platf::supported_gamepads(input);
    for (auto &gamepad : gamepads) {
      if (gamepad.is_enabled && gamepad.name != "auto") {
        return false;
      }
    }
    return true;
  }

  /**
   * @brief Allocate and initialize platform input state for a stream.
   */
  std::shared_ptr<input_t> alloc(safe::mail_t mail) {
    auto input = std::make_shared<input_t>(
      mail->event<input::touch_port_t>(mail::touch_port),
      mail->queue<platf::gamepad_feedback_msg_t>(mail::gamepad_feedback)
    );
    auto *const raw_input = input.get();
    input->session_registration = input_session_gate.register_session();
    input->dispatcher = std::make_unique<input_t::dispatcher_t>(
      [raw_input](std::vector<std::uint8_t> &&entry) {
        passthrough_next_message(raw_input, std::move(entry));
      },
      coalesce_mouse_motion,
      is_droppable_legacy_input_packet,
      configure_input_dispatch_thread,
      input_t::dispatcher_t::limits_t {
        .max_packets = 256,
        .max_timers = 64,
        .max_droppable_age = 4ms,
      },
      [raw_input](std::exception_ptr failure) {
        handle_input_dispatch_failure(raw_input, failure);
      },
      false
    );
    input->dispatcher->start();

    // Workaround to ensure new frames will be captured when a client connects.
    // Keep this synthetic injection on the same session consumer as client input.
    input->dispatcher->schedule([]() {
      std::lock_guard lock(platform_input_mutex);
      platf::move_mouse(platf_input, 1, 1);
      platf::move_mouse(platf_input, -1, -1);
    },
                                100ms);

    return input;
  }
}  // namespace input
