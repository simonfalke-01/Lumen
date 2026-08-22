/**
 * @file src/platform/windows/virtual_hid_input.cpp
 * @brief Lean Lumen Virtual HID application transport implementation.
 */

// local includes
#define INITGUID
#include "virtual_hid_input.h"
#undef INITGUID

#include "keylayout.h"
#include "src/config.h"
#include "src/logging.h"

// platform includes
#include <SetupAPI.h>

// standard includes
#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

// moonlight-common-c includes
#include <moonlight-common-c/src/Input.h>
#include <moonlight-common-c/src/Limelight.h>

namespace platf::win_input {
  namespace {
    using namespace std::literals;

    /** @brief Production synchronous IOCTL channel. */
    class system_virtual_hid_channel_t final: public virtual_hid_channel_t {
    public:
      ~system_virtual_hid_channel_t() override {
        close();
      }

      channel_result_t open() override {
        if (handle_ != INVALID_HANDLE_VALUE) {
          return {};
        }

        const auto devices = SetupDiGetClassDevsW(
          &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
          nullptr,
          nullptr,
          DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        );
        if (devices == INVALID_HANDLE_VALUE) {
          return {false, GetLastError()};
        }

        DWORD result_status = ERROR_FILE_NOT_FOUND;
        for (DWORD index = 0;; ++index) {
          SP_DEVICE_INTERFACE_DATA interface_data {};
          interface_data.cbSize = sizeof(interface_data);
          if (!SetupDiEnumDeviceInterfaces(
                devices,
                nullptr,
                &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
                index,
                &interface_data
              )) {
            const auto status = GetLastError();
            if (status != ERROR_NO_MORE_ITEMS) {
              result_status = status;
            }
            break;
          }

          DWORD detail_size = 0;
          SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, nullptr, 0, &detail_size, nullptr);
          if (detail_size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            continue;
          }
          std::vector<std::byte> detail_buffer(detail_size);
          auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(detail_buffer.data());
          detail->cbSize = sizeof(*detail);
          if (!SetupDiGetDeviceInterfaceDetailW(
                devices,
                &interface_data,
                detail,
                detail_size,
                nullptr,
                nullptr
              )) {
            result_status = GetLastError();
            continue;
          }

          handle_ = CreateFileW(
            detail->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
          );
          if (handle_ != INVALID_HANDLE_VALUE) {
            break;
          }
          result_status = GetLastError();
        }
        SetupDiDestroyDeviceInfoList(devices);
        return handle_ == INVALID_HANDLE_VALUE ? channel_result_t {false, result_status} : channel_result_t {};
      }

      channel_result_t get_info(LUMEN_VHID_GET_INFO_RESPONSE &response) override {
        return ioctl(IOCTL_LUMEN_VHID_GET_INFO, nullptr, 0, &response, sizeof(response));
      }

      channel_result_t claim() override {
        return ioctl(IOCTL_LUMEN_VHID_CLAIM, nullptr, 0, nullptr, 0);
      }

      channel_result_t submit(const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request) override {
        return ioctl(IOCTL_LUMEN_VHID_SUBMIT_REPORT, &request, sizeof(request), nullptr, 0);
      }

      channel_result_t reset_and_release() override {
        return ioctl(IOCTL_LUMEN_VHID_RESET_AND_RELEASE, nullptr, 0, nullptr, 0);
      }

      void close() noexcept override {
        if (handle_ != INVALID_HANDLE_VALUE) {
          CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
        }
      }

    private:
      /**
       * @brief Perform one exact synchronous DeviceIoControl operation.
       * @param code Control code.
       * @param input Optional input buffer.
       * @param input_size Input buffer size.
       * @param output Optional output buffer.
       * @param output_size Output buffer size.
       * @return Channel result.
       */
      channel_result_t ioctl(
        DWORD code,
        const void *input,
        DWORD input_size,
        void *output,
        DWORD output_size
      ) {
        if (handle_ == INVALID_HANDLE_VALUE) {
          return {false, ERROR_INVALID_HANDLE};
        }
        DWORD transferred = 0;
        if (!DeviceIoControl(
              handle_,
              code,
              const_cast<void *>(input),
              input_size,
              output,
              output_size,
              &transferred,
              nullptr
            )) {
          return {false, GetLastError()};
        }
        if (transferred != output_size) {
          return {false, ERROR_INVALID_DATA};
        }
        return {};
      }

      HANDLE handle_ {INVALID_HANDLE_VALUE};  ///< Secured driver interface handle.
    };

    /**
     * @brief Map a virtual key directly to a HID keyboard-page usage.
     * @param key Windows virtual key.
     * @return HID usage, or no value when unsupported.
     */
    std::optional<std::uint8_t> direct_key_usage(std::uint16_t key) {
      if (key >= 'A' && key <= 'Z') {
        return static_cast<std::uint8_t>(0x04 + key - 'A');
      }
      if (key >= '1' && key <= '9') {
        return static_cast<std::uint8_t>(0x1E + key - '1');
      }
      if (key == '0') {
        return 0x27;
      }
      if (key >= VK_F1 && key <= VK_F12) {
        return static_cast<std::uint8_t>(0x3A + key - VK_F1);
      }
      if (key >= VK_F13 && key <= VK_F24) {
        return static_cast<std::uint8_t>(0x68 + key - VK_F13);
      }
      if (key >= VK_NUMPAD1 && key <= VK_NUMPAD9) {
        return static_cast<std::uint8_t>(0x59 + key - VK_NUMPAD1);
      }

      switch (key) {
        case VK_SHIFT:
        case VK_LSHIFT:
          return 0xE1;
        case VK_RSHIFT:
          return 0xE5;
        case VK_CONTROL:
        case VK_LCONTROL:
          return 0xE0;
        case VK_RCONTROL:
          return 0xE4;
        case VK_MENU:
        case VK_LMENU:
          return 0xE2;
        case VK_RMENU:
          return 0xE6;
        case VK_LWIN:
          return 0xE3;
        case VK_RWIN:
          return 0xE7;
        case VK_RETURN:
          return 0x28;
        case VK_ESCAPE:
          return 0x29;
        case VK_BACK:
          return 0x2A;
        case VK_TAB:
          return 0x2B;
        case VK_SPACE:
          return 0x2C;
        case VK_OEM_MINUS:
          return 0x2D;
        case VK_OEM_PLUS:
          return 0x2E;
        case VK_OEM_4:
          return 0x2F;
        case VK_OEM_6:
          return 0x30;
        case VK_OEM_5:
          return 0x31;
        case VK_OEM_1:
          return 0x33;
        case VK_OEM_7:
          return 0x34;
        case VK_OEM_3:
          // Set 1 calls this physical key 0x29, but 0x29 on the HID
          // Keyboard/Keypad page is Escape. Grave/Tilde is HID usage 0x35.
          return 0x35;
        case VK_OEM_COMMA:
          return 0x36;
        case VK_OEM_PERIOD:
          return 0x37;
        case VK_OEM_2:
          return 0x38;
        case VK_CAPITAL:
          return 0x39;
        case VK_SNAPSHOT:
          return 0x46;
        case VK_SCROLL:
          return 0x47;
        case VK_PAUSE:
          return 0x48;
        case VK_INSERT:
          return 0x49;
        case VK_HOME:
          return 0x4A;
        case VK_PRIOR:
          return 0x4B;
        case VK_DELETE:
          return 0x4C;
        case VK_END:
          return 0x4D;
        case VK_NEXT:
          return 0x4E;
        case VK_RIGHT:
          return 0x4F;
        case VK_LEFT:
          return 0x50;
        case VK_DOWN:
          return 0x51;
        case VK_UP:
          return 0x52;
        case VK_NUMLOCK:
          return 0x53;
        case VK_DIVIDE:
          return 0x54;
        case VK_MULTIPLY:
          return 0x55;
        case VK_SUBTRACT:
          return 0x56;
        case VK_ADD:
          return 0x57;
        case VK_NUMPAD0:
          return 0x62;
        case VK_DECIMAL:
          return 0x63;
        case VK_OEM_102:
          return 0x64;
        case VK_APPS:
          return 0x65;
        case VK_SEPARATOR:
          return 0x9F;
        default:
          return std::nullopt;
      }
    }

    /**
     * @brief Map a Moonlight mouse button constant to its HID report bit.
     *
     * @param button Moonlight mouse button constant.
     * @return HID button bit, or zero when invalid.
     */
    constexpr std::uint8_t mouse_button_bit(int button) noexcept {
      switch (button) {
        case BUTTON_LEFT:
          return 0x01;
        case BUTTON_MIDDLE:
          return 0x04;
        case BUTTON_RIGHT:
          return 0x02;
        case BUTTON_X1:
          return 0x08;
        case BUTTON_X2:
          return 0x10;
        default:
          return 0;
      }
    }

    /**
     * @brief Build the stable identity of one keyboard transition stream.
     * @param modcode Windows virtual-key code.
     * @param flags Moonlight keyboard packet flags.
     * @return Key identity preserving both the code and mapping mode.
     */
    constexpr std::uint32_t key_transition_id(std::uint16_t modcode, std::uint8_t flags) noexcept {
      return static_cast<std::uint32_t>(modcode) | (static_cast<std::uint32_t>(flags) << 16U);
    }
  }  // namespace

  std::optional<std::uint8_t> map_scan_code_to_hid_usage(UINT scan_code) {
    if (scan_code > 0xFFFFU) {
      return std::nullopt;
    }
    const auto code = static_cast<std::uint8_t>(scan_code & 0xFFU);
    const auto prefix = static_cast<std::uint8_t>((scan_code >> 8U) & 0xFFU);

    if (prefix == 0xE0) {
      switch (code) {
        case 0x1C:
          return 0x58;
        case 0x1D:
          return 0xE4;
        case 0x35:
          return 0x54;
        case 0x37:
          return 0x46;
        case 0x38:
          return 0xE6;
        case 0x47:
          return 0x4A;
        case 0x48:
          return 0x52;
        case 0x49:
          return 0x4B;
        case 0x4B:
          return 0x50;
        case 0x4D:
          return 0x4F;
        case 0x4F:
          return 0x4D;
        case 0x50:
          return 0x51;
        case 0x51:
          return 0x4E;
        case 0x52:
          return 0x49;
        case 0x53:
          return 0x4C;
        case 0x5B:
          return 0xE3;
        case 0x5C:
          return 0xE7;
        case 0x5D:
          return 0x65;
        default:
          return std::nullopt;
      }
    }
    if (prefix != 0 || code == 0) {
      return std::nullopt;
    }

    // Set 1 reuses these codes for E0-prefixed navigation keys and their
    // unprefixed keypad counterparts. Resolve the physical keypad keys before
    // consulting the legacy VK-to-scan-code table, which cannot store prefixes.
    switch (code) {
      case 0x29:
        return 0x35;
      case 0x35:
        return 0x38;
      case 0x47:
        return 0x5F;
      case 0x48:
        return 0x60;
      case 0x49:
        return 0x61;
      case 0x4A:
        return 0x56;
      case 0x4B:
        return 0x5C;
      case 0x4C:
        return 0x5D;
      case 0x4D:
        return 0x5E;
      case 0x4E:
        return 0x57;
      case 0x4F:
        return 0x59;
      case 0x50:
        return 0x5A;
      case 0x51:
        return 0x5B;
      case 0x52:
        return 0x62;
      case 0x53:
        return 0x63;
      case 0x5B:
      case 0x5C:
      case 0x5D:
        return std::nullopt;
      default:
        break;
    }

    for (std::uint16_t key = 0; key < VK_TO_SCANCODE_MAP.size(); ++key) {
      if (VK_TO_SCANCODE_MAP[key] == code) {
        if (const auto usage = direct_key_usage(key)) {
          return usage;
        }
      }
    }
    return std::nullopt;
  }

  std::optional<std::uint16_t> map_key_to_consumer_usage(std::uint16_t modcode) {
    switch (modcode) {
      case VK_BROWSER_BACK:
        return 0x0224;
      case VK_BROWSER_FORWARD:
        return 0x0225;
      case VK_BROWSER_REFRESH:
        return 0x0227;
      case VK_BROWSER_STOP:
        return 0x0226;
      case VK_BROWSER_SEARCH:
        return 0x0221;
      case VK_BROWSER_FAVORITES:
        return 0x022A;
      case VK_BROWSER_HOME:
        return 0x0223;
      case VK_VOLUME_MUTE:
        return 0x00E2;
      case VK_VOLUME_DOWN:
        return 0x00EA;
      case VK_VOLUME_UP:
        return 0x00E9;
      case VK_MEDIA_NEXT_TRACK:
        return 0x00B5;
      case VK_MEDIA_PREV_TRACK:
        return 0x00B6;
      case VK_MEDIA_STOP:
        return 0x00B7;
      case VK_MEDIA_PLAY_PAUSE:
        return 0x00CD;
      case VK_LAUNCH_MAIL:
        return 0x018A;
      case VK_LAUNCH_MEDIA_SELECT:
        return 0x0183;
      case VK_LAUNCH_APP1:
        return 0x0194;
      case VK_LAUNCH_APP2:
        return 0x0192;
      default:
        return std::nullopt;
    }
  }

  std::optional<std::uint8_t> map_key_to_hid_usage(
    std::uint16_t modcode,
    std::uint8_t flags,
    bool always_send_scancodes
  ) {
    if (flags & SS_KBE_FLAG_NON_NORMALIZED) {
      if (!always_send_scancodes) {
        return std::nullopt;
      }
      if (modcode == VK_LWIN || modcode == VK_RWIN || modcode == VK_PAUSE) {
        return direct_key_usage(modcode);
      }
      const auto scan = MapVirtualKeyW(modcode, MAPVK_VK_TO_VSC_EX);
      return scan ? map_scan_code_to_hid_usage(scan) : std::nullopt;
    }
    return direct_key_usage(modcode);
  }

  virtual_hid_transport_t::virtual_hid_transport_t(
    std::shared_ptr<virtual_hid_channel_t> channel,
    std::unique_ptr<send_input_transport_t> fallback
  ):
      channel_(std::move(channel)),
      fallback_(std::move(fallback)) {
    acknowledged_keyboard_.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
  }

  virtual_hid_transport_t::~virtual_hid_transport_t() {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::virtual_hid || backend_.load() == backend_t::fail_closed) {
      const auto reset = channel_->reset_and_release();
      channel_->close();
      if (reset) {
        fallback_->neutralize();
      }
    }
  }

  bool virtual_hid_transport_t::initialize() {
    std::lock_guard lock(mutex_);
    if (backend_.load() != backend_t::probing) {
      return backend_.load() == backend_t::virtual_hid;
    }

    auto result = channel_->open();
    if (!result) {
      set_failure("interface discovery/open", result.status);
      backend_.store(backend_t::send_input);
      return false;
    }

    LUMEN_VHID_GET_INFO_RESPONSE info {};
    result = channel_->get_info(info);
    if (!result || info.abi_version != LUMEN_VHID_ABI_VERSION || info.ready != 1) {
      set_failure("driver info", result ? ERROR_REVISION_MISMATCH : result.status);
      channel_->close();
      backend_.store(backend_t::send_input);
      return false;
    }

    result = channel_->claim();
    if (!result) {
      set_failure("exclusive claim", result.status);
      channel_->close();
      backend_.store(backend_t::send_input);
      return false;
    }

    backend_.store(backend_t::virtual_hid);
    return true;
  }

  const std::string &virtual_hid_transport_t::failure_stage() const noexcept {
    return failure_stage_;
  }

  DWORD virtual_hid_transport_t::failure_status() const noexcept {
    return failure_status_;
  }

  LUMEN_VHID_KEYBOARD_REPORT virtual_hid_transport_t::acknowledged_keyboard_report() const {
    std::lock_guard lock(mutex_);
    return acknowledged_keyboard_;
  }

  std::uint8_t virtual_hid_transport_t::acknowledged_mouse_buttons() const {
    std::lock_guard lock(mutex_);
    return acknowledged_buttons_;
  }

  backend_t virtual_hid_transport_t::backend() const noexcept {
    return backend_.load();
  }

  LUMEN_VHID_KEYBOARD_REPORT virtual_hid_transport_t::keyboard_report() const {
    LUMEN_VHID_KEYBOARD_REPORT report {};
    report.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
    for (const auto &[transition_id, usage] : held_keys_) {
      static_cast<void>(transition_id);
      if (usage >= 0xE0 && usage <= 0xE7) {
        report.modifiers |= static_cast<std::uint8_t>(1U << (usage - 0xE0));
      } else if (usage / 8 < LUMEN_VHID_NKRO_BITMAP_SIZE) {
        report.key_bitmap[usage / 8] |= static_cast<std::uint8_t>(1U << (usage % 8));
      }
    }
    return report;
  }

  LUMEN_VHID_CONSUMER_REPORT virtual_hid_transport_t::consumer_report() const {
    LUMEN_VHID_CONSUMER_REPORT report {};
    report.report_id = LUMEN_VHID_REPORT_ID_CONSUMER;
    std::size_t index = 0;
    for (const auto &[transition_id, usage] : held_consumers_) {
      static_cast<void>(transition_id);
      if (index == LUMEN_VHID_CONSUMER_USAGE_COUNT) {
        break;
      }
      report.usages[index++] = usage;
    }
    return report;
  }

  result_t virtual_hid_transport_t::submit_report(
    const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request,
    const char *stage
  ) {
    const auto result = channel_->submit(request);
    if (result) {
      accepted_virtual_input_ = true;
      return {};
    }

    set_failure(stage, result.status);
    if (accepted_virtual_input_) {
      backend_.store(backend_t::fail_closed);
      BOOST_LOG(error)
        << "Lumen Virtual HID failed closed (stage="sv << stage
        << ", status="sv << result.status << ')';
      return {completion_t::ambiguous, result.status};
    }

    channel_->close();
    backend_.store(backend_t::send_input);
    BOOST_LOG(warning)
      << "Windows keyboard and mouse backend: SendInput fallback before accepted Virtual HID input (stage="sv
      << stage << ", status="sv << result.status << ')';
    return {completion_t::rejected, result.status};
  }

  result_t virtual_hid_transport_t::submit_wheel_detents(
    std::int64_t detents,
    bool horizontal,
    const char *stage
  ) {
    while (detents != 0) {
      const auto segment = std::clamp<std::int64_t>(
        detents,
        std::numeric_limits<std::int16_t>::min(),
        std::numeric_limits<std::int16_t>::max()
      );
      LUMEN_VHID_SUBMIT_REPORT_REQUEST request {};
      request.report_kind = LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE;
      request.report.relative_mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
      request.report.relative_mouse.buttons = held_buttons_;
      if (horizontal) {
        request.report.relative_mouse.horizontal_wheel = static_cast<std::int16_t>(segment);
      } else {
        request.report.relative_mouse.vertical_wheel = static_cast<std::int16_t>(segment);
      }
      const auto result = submit_report(request, stage);
      if (!result) {
        return result;
      }
      acknowledged_buttons_ = held_buttons_;
      detents -= segment;
    }
    return {};
  }

  result_t virtual_hid_transport_t::submit_fallback_wheel_units(std::int64_t units, bool horizontal) {
    while (units != 0) {
      const auto segment = std::clamp<std::int64_t>(
        units,
        std::numeric_limits<std::int32_t>::min(),
        std::numeric_limits<std::int32_t>::max()
      );
      const auto result = horizontal ?
                            fallback_->horizontal_scroll(static_cast<std::int32_t>(segment)) :
                            fallback_->vertical_scroll(static_cast<std::int32_t>(segment));
      if (!result) {
        return result;
      }
      units -= segment;
    }
    return {};
  }

  result_t virtual_hid_transport_t::move_mouse(std::int32_t delta_x, std::int32_t delta_y) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->move_mouse(delta_x, delta_y);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    std::int64_t remaining_x = delta_x;
    std::int64_t remaining_y = delta_y;
    bool submit_zero = remaining_x == 0 && remaining_y == 0;
    do {
      const auto segment_x = std::clamp<std::int64_t>(
        remaining_x,
        std::numeric_limits<std::int16_t>::min(),
        std::numeric_limits<std::int16_t>::max()
      );
      const auto segment_y = std::clamp<std::int64_t>(
        remaining_y,
        std::numeric_limits<std::int16_t>::min(),
        std::numeric_limits<std::int16_t>::max()
      );
      LUMEN_VHID_SUBMIT_REPORT_REQUEST request {};
      request.report_kind = LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE;
      request.report.relative_mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
      request.report.relative_mouse.buttons = held_buttons_;
      request.report.relative_mouse.x = static_cast<std::int16_t>(segment_x);
      request.report.relative_mouse.y = static_cast<std::int16_t>(segment_y);
      const auto result = submit_report(request, "relative mouse report");
      if (!result) {
        return backend_.load() == backend_t::send_input ? fallback_->move_mouse(delta_x, delta_y) : result;
      }
      acknowledged_buttons_ = held_buttons_;
      remaining_x -= segment_x;
      remaining_y -= segment_y;
      submit_zero = false;
    } while (remaining_x != 0 || remaining_y != 0 || submit_zero);
    return {};
  }

  result_t virtual_hid_transport_t::absolute_mouse(
    float x,
    float y,
    std::int32_t source_width,
    std::int32_t source_height
  ) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::fail_closed) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }
    return fallback_->absolute_mouse(x, y, source_width, source_height);
  }

  result_t virtual_hid_transport_t::mouse_button(int button, bool release) {
    const auto bit = mouse_button_bit(button);
    if (!bit) {
      return {completion_t::rejected, ERROR_INVALID_PARAMETER};
    }

    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->mouse_button(button, release);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    const auto previous = held_buttons_;
    if (release) {
      held_buttons_ &= static_cast<std::uint8_t>(~bit);
    } else {
      held_buttons_ |= bit;
    }
    LUMEN_VHID_SUBMIT_REPORT_REQUEST request {};
    request.report_kind = LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE;
    request.report.relative_mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
    request.report.relative_mouse.buttons = held_buttons_;
    const auto result = submit_report(request, "mouse button report");
    if (!result && backend_.load() == backend_t::send_input) {
      held_buttons_ = previous;
      return fallback_->mouse_button(button, release);
    }
    if (result) {
      acknowledged_buttons_ = held_buttons_;
    }
    return result;
  }

  result_t virtual_hid_transport_t::vertical_scroll(std::int32_t distance) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->vertical_scroll(distance);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    const auto accumulated = static_cast<std::int64_t>(vertical_wheel_remainder_) + distance;
    vertical_wheel_remainder_ = static_cast<std::int32_t>(accumulated % WHEEL_DELTA);
    const auto result = submit_wheel_detents(accumulated / WHEEL_DELTA, false, "vertical wheel report");
    if (!result && backend_.load() == backend_t::send_input) {
      vertical_wheel_remainder_ = 0;
      return submit_fallback_wheel_units(accumulated, false);
    }
    return result;
  }

  result_t virtual_hid_transport_t::horizontal_scroll(std::int32_t distance) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->horizontal_scroll(distance);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    const auto accumulated = static_cast<std::int64_t>(horizontal_wheel_remainder_) + distance;
    horizontal_wheel_remainder_ = static_cast<std::int32_t>(accumulated % WHEEL_DELTA);
    const auto result = submit_wheel_detents(accumulated / WHEEL_DELTA, true, "horizontal wheel report");
    if (!result && backend_.load() == backend_t::send_input) {
      horizontal_wheel_remainder_ = 0;
      return submit_fallback_wheel_units(accumulated, true);
    }
    return result;
  }

  result_t virtual_hid_transport_t::keyboard(std::uint16_t modcode, bool release, std::uint8_t flags) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->keyboard(modcode, release, flags);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    const auto transition_id = key_transition_id(modcode, flags);
    if (release && fallback_keys_.contains(transition_id)) {
      const auto result = fallback_->keyboard(modcode, true, flags);
      if (result) {
        fallback_keys_.erase(transition_id);
      }
      return result;
    }

    if (const auto usage = map_key_to_consumer_usage(modcode)) {
      const auto previous = held_consumers_;
      if (release) {
        if (!held_consumers_.contains(transition_id)) {
          return {};
        }
        held_consumers_.erase(transition_id);
      } else if (!held_consumers_.contains(transition_id) && held_consumers_.size() >= LUMEN_VHID_CONSUMER_USAGE_COUNT) {
        const auto result = fallback_->keyboard(modcode, false, flags);
        if (result) {
          fallback_keys_.insert(transition_id);
        }
        return result;
      } else {
        held_consumers_[transition_id] = *usage;
      }
      LUMEN_VHID_SUBMIT_REPORT_REQUEST request {};
      request.report_kind = LUMEN_VHID_REPORT_KIND_CONSUMER;
      request.report.consumer = consumer_report();
      const auto result = submit_report(request, "consumer report");
      if (!result && backend_.load() == backend_t::send_input) {
        held_consumers_ = previous;
        return fallback_->keyboard(modcode, release, flags);
      }
      return result;
    }

    const auto previous = held_keys_;
    if (release) {
      if (!held_keys_.contains(transition_id)) {
        return {};
      }
      held_keys_.erase(transition_id);
    } else {
      const auto usage = map_key_to_hid_usage(modcode, flags, config::input.always_send_scancodes);
      if (usage) {
        held_keys_[transition_id] = *usage;
      } else {
        const auto result = fallback_->keyboard(modcode, false, flags);
        if (result) {
          fallback_keys_.insert(transition_id);
        }
        return result;
      }
    }

    LUMEN_VHID_SUBMIT_REPORT_REQUEST request {};
    request.report_kind = LUMEN_VHID_REPORT_KIND_KEYBOARD;
    request.report.keyboard = keyboard_report();
    const auto result = submit_report(request, "keyboard report");
    if (!result && backend_.load() == backend_t::send_input) {
      held_keys_ = previous;
      return fallback_->keyboard(modcode, release, flags);
    }
    if (result) {
      acknowledged_keyboard_ = request.report.keyboard;
    }
    return result;
  }

  result_t virtual_hid_transport_t::unicode(const char *utf8, int size) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::fail_closed) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }
    return fallback_->unicode(utf8, size);
  }

  result_t virtual_hid_transport_t::reset_session() {
    std::lock_guard lock(mutex_);
    vertical_wheel_remainder_ = 0;
    horizontal_wheel_remainder_ = 0;
    if (backend_.load() == backend_t::send_input) {
      return fallback_->reset_session();
    }
    if (backend_.load() == backend_t::virtual_hid) {
      return fallback_->neutralize();
    }
    if (backend_.load() != backend_t::fail_closed) {
      return {completion_t::rejected, ERROR_NOT_READY};
    }

    held_keys_.clear();
    held_consumers_.clear();
    fallback_keys_.clear();
    held_buttons_ = 0;
    const auto result = channel_->reset_and_release();
    if (!result) {
      set_failure("reset and release", result.status);
      backend_.store(backend_t::fail_closed);
      return {completion_t::ambiguous, result.status};
    }

    channel_->close();
    accepted_virtual_input_ = false;
    acknowledged_keyboard_ = {};
    acknowledged_keyboard_.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
    acknowledged_buttons_ = 0;
    backend_.store(backend_t::send_input);
    return fallback_->neutralize();
  }

  result_t virtual_hid_transport_t::neutralize() {
    std::lock_guard lock(mutex_);
    vertical_wheel_remainder_ = 0;
    horizontal_wheel_remainder_ = 0;
    if (backend_.load() == backend_t::send_input) {
      return fallback_->neutralize();
    }
    if (backend_.load() != backend_t::virtual_hid && backend_.load() != backend_t::fail_closed) {
      return {completion_t::rejected, ERROR_NOT_READY};
    }

    held_keys_.clear();
    held_consumers_.clear();
    fallback_keys_.clear();
    held_buttons_ = 0;
    const auto result = channel_->reset_and_release();
    channel_->close();
    if (!result) {
      backend_.store(backend_t::fail_closed);
      return {completion_t::ambiguous, result.status};
    }
    backend_.store(backend_t::send_input);
    return fallback_->neutralize();
  }

  void virtual_hid_transport_t::set_failure(const char *stage, DWORD status) {
    failure_stage_ = stage;
    failure_status_ = status;
  }

  std::unique_ptr<transport_t> make_preferred_input_transport() {
    if (config::input.windows_input_backend == "sendinput") {
      BOOST_LOG(info) << "Windows keyboard and mouse backend: SendInput (forced by configuration)"sv;
      return make_send_input_transport();
    }

    auto transport = std::make_unique<virtual_hid_transport_t>(
      std::make_shared<system_virtual_hid_channel_t>(),
      make_send_input_transport()
    );
    if (transport->initialize()) {
      BOOST_LOG(info) << "Windows keyboard and mouse backend: Lumen Virtual HID"sv;
    } else {
      BOOST_LOG(warning)
        << "Windows keyboard and mouse backend: SendInput fallback (stage="sv
        << transport->failure_stage() << ", status="sv << transport->failure_status() << ')';
    }
    return transport;
  }
}  // namespace platf::win_input
