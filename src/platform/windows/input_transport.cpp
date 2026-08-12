/**
 * @file src/platform/windows/input_transport.cpp
 * @brief Windows `SendInput` keyboard and mouse transport.
 */

// local includes
#include "input_transport.h"

#include "keylayout.h"
#include "misc.h"
#include "src/config.h"

// standard includes
#include <algorithm>
#include <cmath>
#include <utility>

// moonlight-common-c includes
#include <moonlight-common-c/src/Input.h>
#include <moonlight-common-c/src/Limelight.h>

namespace platf::win_input {
  namespace {
    /**
     * @brief Production Win32 input call surface.
     */
    class system_win32_api_t final: public win32_api_t {
    public:
      UINT send_input(UINT count, INPUT *inputs, int size) override {
        return SendInput(count, inputs, size);
      }

      HDESK sync_thread_desktop() override {
        return syncThreadDesktop();
      }

      DWORD last_error() override {
        return GetLastError();
      }
    };

    /**
     * @brief Return the held-state bit for a Moonlight mouse button.
     * @param button Moonlight mouse button number.
     * @return Button bit, or zero when the number is invalid.
     */
    constexpr std::uint8_t button_bit(int button) noexcept {
      return button >= 1 && button <= 5 ? static_cast<std::uint8_t>(1U << (button - 1)) : 0;
    }

    /**
     * @brief Populate a keyboard `INPUT` record using existing Lumen semantics.
     * @param modcode Windows virtual-key code.
     * @param release `true` to release the key.
     * @param flags Moonlight keyboard flags.
     * @return Populated input record.
     */
    INPUT keyboard_input(std::uint16_t modcode, bool release, std::uint8_t flags) {
      INPUT input {};
      input.type = INPUT_KEYBOARD;
      auto &keyboard = input.ki;

      if (!(flags & SS_KBE_FLAG_NON_NORMALIZED)) {
        keyboard.wScan = VK_TO_SCANCODE_MAP[modcode & 0xFF];
      } else if (config::input.always_send_scancodes && modcode != VK_LWIN && modcode != VK_RWIN && modcode != VK_PAUSE) {
        keyboard.wScan = MapVirtualKey(modcode, MAPVK_VK_TO_VSC);
      }

      if (keyboard.wScan) {
        keyboard.dwFlags = KEYEVENTF_SCANCODE;
      } else {
        keyboard.wVk = modcode;
      }

      switch (modcode) {
        case VK_LWIN:
        case VK_RWIN:
        case VK_RMENU:
        case VK_RCONTROL:
        case VK_INSERT:
        case VK_DELETE:
        case VK_HOME:
        case VK_END:
        case VK_PRIOR:
        case VK_NEXT:
        case VK_UP:
        case VK_DOWN:
        case VK_LEFT:
        case VK_RIGHT:
        case VK_DIVIDE:
        case VK_APPS:
          keyboard.dwFlags |= KEYEVENTF_EXTENDEDKEY;
          break;
        default:
          break;
      }

      if (release) {
        keyboard.dwFlags |= KEYEVENTF_KEYUP;
      }

      return input;
    }
  }  // namespace

  send_input_transport_t::send_input_transport_t(std::shared_ptr<win32_api_t> api):
      api_(std::move(api)) {
  }

  send_input_transport_t::~send_input_transport_t() {
    neutralize();
  }

  backend_t send_input_transport_t::backend() const noexcept {
    return backend_t::send_input;
  }

  result_t send_input_transport_t::submit(INPUT input) {
    auto sent = api_->send_input(1, &input, sizeof(INPUT));
    if (sent == 1) {
      return {};
    }

    const auto status = api_->last_error();
    const auto desktop = api_->sync_thread_desktop();
    if (last_input_desktop_ != desktop) {
      last_input_desktop_ = desktop;
      sent = api_->send_input(1, &input, sizeof(INPUT));
      if (sent == 1) {
        return {};
      }
    }

    return {completion_t::rejected, status};
  }

  result_t send_input_transport_t::move_mouse(std::int32_t delta_x, std::int32_t delta_y) {
    std::lock_guard lock(mutex_);
    INPUT input {};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_MOVE;
    input.mi.dx = delta_x;
    input.mi.dy = delta_y;
    return submit(input);
  }

  result_t send_input_transport_t::absolute_mouse(float x, float y, std::int32_t source_width, std::int32_t source_height) {
    if (source_width <= 0 || source_height <= 0) {
      return {completion_t::rejected, ERROR_INVALID_PARAMETER};
    }

    std::lock_guard lock(mutex_);
    INPUT input {};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    input.mi.dx = std::lround(x * (65535.0f / static_cast<float>(source_width)));
    input.mi.dy = std::lround(y * (65535.0f / static_cast<float>(source_height)));
    return submit(input);
  }

  result_t send_input_transport_t::mouse_button(int button, bool release) {
    const auto bit = button_bit(button);
    if (!bit) {
      return {completion_t::rejected, ERROR_INVALID_PARAMETER};
    }

    std::lock_guard lock(mutex_);
    INPUT input {};
    input.type = INPUT_MOUSE;

    switch (button) {
      case 1:
        input.mi.dwFlags = release ? MOUSEEVENTF_LEFTUP : MOUSEEVENTF_LEFTDOWN;
        break;
      case 2:
        input.mi.dwFlags = release ? MOUSEEVENTF_MIDDLEUP : MOUSEEVENTF_MIDDLEDOWN;
        break;
      case 3:
        input.mi.dwFlags = release ? MOUSEEVENTF_RIGHTUP : MOUSEEVENTF_RIGHTDOWN;
        break;
      case 4:
      case 5:
        input.mi.dwFlags = release ? MOUSEEVENTF_XUP : MOUSEEVENTF_XDOWN;
        input.mi.mouseData = button == 4 ? XBUTTON1 : XBUTTON2;
        break;
      default:
        return {completion_t::rejected, ERROR_INVALID_PARAMETER};
    }

    const auto result = submit(input);
    if (result) {
      if (release) {
        held_buttons_ &= static_cast<std::uint8_t>(~bit);
      } else {
        held_buttons_ |= bit;
      }
    }
    return result;
  }

  result_t send_input_transport_t::vertical_scroll(std::int32_t distance) {
    std::lock_guard lock(mutex_);
    INPUT input {};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_WHEEL;
    input.mi.mouseData = static_cast<DWORD>(distance);
    return submit(input);
  }

  result_t send_input_transport_t::horizontal_scroll(std::int32_t distance) {
    std::lock_guard lock(mutex_);
    INPUT input {};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_HWHEEL;
    input.mi.mouseData = static_cast<DWORD>(distance);
    return submit(input);
  }

  result_t send_input_transport_t::keyboard(std::uint16_t modcode, bool release, std::uint8_t flags) {
    std::lock_guard lock(mutex_);
    const auto result = submit(keyboard_input(modcode, release, flags));
    if (result) {
      if (release) {
        held_keys_.erase(modcode);
      } else {
        held_keys_[modcode] = flags;
      }
    }
    return result;
  }

  result_t send_input_transport_t::unicode(const char *utf8, int size) {
    if (!utf8 || size <= 0) {
      return {completion_t::rejected, ERROR_INVALID_PARAMETER};
    }

    std::vector<WCHAR> wide(static_cast<std::size_t>(size));
    const auto chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, size, wide.data(), size);
    if (chars <= 0) {
      return {completion_t::rejected, GetLastError()};
    }

    std::lock_guard lock(mutex_);
    for (int index = 0; index < chars; ++index) {
      INPUT input {};
      input.type = INPUT_KEYBOARD;
      input.ki.wScan = wide[index];
      input.ki.dwFlags = KEYEVENTF_UNICODE;
      auto result = submit(input);
      if (!result) {
        return result;
      }
      input.ki.dwFlags |= KEYEVENTF_KEYUP;
      result = submit(input);
      if (!result) {
        return result;
      }
    }

    return {};
  }

  result_t send_input_transport_t::reset_session() {
    return neutralize();
  }

  result_t send_input_transport_t::neutralize() {
    std::lock_guard lock(mutex_);
    result_t aggregate {};

    for (const auto &[modcode, flags] : held_keys_) {
      const auto result = submit(keyboard_input(modcode, true, flags));
      if (!result && aggregate) {
        aggregate = result;
      }
    }
    held_keys_.clear();

    for (int button = 1; button <= 5; ++button) {
      const auto bit = button_bit(button);
      if (!(held_buttons_ & bit)) {
        continue;
      }

      INPUT input {};
      input.type = INPUT_MOUSE;
      switch (button) {
        case 1:
          input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
          break;
        case 2:
          input.mi.dwFlags = MOUSEEVENTF_MIDDLEUP;
          break;
        case 3:
          input.mi.dwFlags = MOUSEEVENTF_RIGHTUP;
          break;
        case 4:
        case 5:
          input.mi.dwFlags = MOUSEEVENTF_XUP;
          input.mi.mouseData = button == 4 ? XBUTTON1 : XBUTTON2;
          break;
        default:
          break;
      }

      const auto result = submit(input);
      if (!result && aggregate) {
        aggregate = result;
      }
    }
    held_buttons_ = 0;
    return aggregate;
  }

  std::unique_ptr<send_input_transport_t> make_send_input_transport() {
    return std::make_unique<send_input_transport_t>(std::make_shared<system_win32_api_t>());
  }
}  // namespace platf::win_input
