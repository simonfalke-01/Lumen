/**
 * @file src/platform/windows/virtual_hid_input.cpp
 * @brief Lumen Virtual HID application transport implementation.
 */

// Define the device-interface GUID in this translation unit.
#include <initguid.h>

// local includes
#include "keylayout.h"
#include "src/config.h"
#include "src/logging.h"
#include "virtual_hid_input.h"

// platform includes
#include <SetupAPI.h>

// standard includes
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

// moonlight-common-c includes
#include <moonlight-common-c/src/Input.h>
#include <moonlight-common-c/src/Limelight.h>

namespace platf::win_input {
  namespace {
    using namespace std::literals;

    /**
     * @brief Populate a protocol message header.
     * @param operation Protocol operation identifier.
     * @param total_size Complete structure size.
     * @param protocol_minor Negotiated protocol minor version.
     * @return Populated message header.
     */
    LUMEN_VHID_MESSAGE_HEADER message_header(
      std::uint16_t operation,
      std::uint32_t total_size,
      std::uint16_t protocol_minor = LUMEN_VHID_PROTOCOL_MINOR
    ) {
      return {
        LUMEN_VHID_PROTOCOL_MAGIC,
        LUMEN_VHID_PROTOCOL_MAJOR,
        protocol_minor,
        sizeof(LUMEN_VHID_MESSAGE_HEADER),
        operation,
        total_size,
        0
      };
    }

    /**
     * @brief Convert a Win32 channel error to an ordering-safe completion class.
     * @param status Native Win32 status.
     * @return Classified channel result.
     */
    channel_result_t classify_channel_error(DWORD status) {
      switch (status) {
        case ERROR_DEVICE_NOT_CONNECTED:
        case ERROR_NO_SUCH_DEVICE:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_INVALID_HANDLE:
        case ERROR_TIMEOUT:
        case ERROR_SEM_TIMEOUT:
        case ERROR_OPERATION_ABORTED:
        case ERROR_IO_INCOMPLETE:
          return {channel_completion_t::ambiguous, status};
        default:
          return {channel_completion_t::definite_reject, status};
      }
    }

    /**
     * @brief Production SetupAPI and `DeviceIoControl` channel.
     */
    class system_virtual_hid_channel_t final: public virtual_hid_channel_t {
    public:
      ~system_virtual_hid_channel_t() override {
        cleanup();
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
          return classify_channel_error(GetLastError());
        }

        SP_DEVICE_INTERFACE_DATA interface_data {};
        interface_data.cbSize = sizeof(interface_data);
        if (!SetupDiEnumDeviceInterfaces(
              devices,
              nullptr,
              &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
              0,
              &interface_data
            )) {
          const auto status = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return classify_channel_error(status);
        }

        DWORD detail_size = 0;
        SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, nullptr, 0, &detail_size, nullptr);
        if (detail_size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
          const auto status = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return classify_channel_error(status ? status : ERROR_INVALID_DATA);
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
          const auto status = GetLastError();
          SetupDiDestroyDeviceInfoList(devices);
          return classify_channel_error(status);
        }

        handle_ = CreateFileW(
          detail->DevicePath,
          GENERIC_READ | GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          nullptr,
          OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
          nullptr
        );
        const auto status = handle_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        SetupDiDestroyDeviceInfoList(devices);
        return handle_ == INVALID_HANDLE_VALUE ? classify_channel_error(status) : channel_result_t {};
      }

      channel_result_t get_capabilities(
        const LUMEN_VHID_GET_CAPABILITIES_REQUEST &request,
        LUMEN_VHID_GET_CAPABILITIES_RESPONSE &response
      ) override {
        return ioctl(IOCTL_LUMEN_VHID_GET_PROTOCOL_CAPABILITIES, request, response);
      }

      channel_result_t claim(
        const LUMEN_VHID_CLAIM_SESSION_REQUEST &request,
        LUMEN_VHID_CLAIM_SESSION_RESPONSE &response
      ) override {
        return ioctl(IOCTL_LUMEN_VHID_CLAIM_INPUT_SESSION, request, response);
      }

      channel_result_t submit(
        const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request,
        LUMEN_VHID_SUBMIT_REPORT_RESPONSE &response
      ) override {
        return ioctl(IOCTL_LUMEN_VHID_SUBMIT_INPUT_REPORT, request, response);
      }

      channel_result_t reset(
        const LUMEN_VHID_SESSION_REQUEST &request,
        LUMEN_VHID_SESSION_RESPONSE &response
      ) override {
        return ioctl(IOCTL_LUMEN_VHID_RESET_INPUT_SESSION, request, response);
      }

      channel_result_t release(
        const LUMEN_VHID_SESSION_REQUEST &request,
        LUMEN_VHID_SESSION_RESPONSE &response
      ) override {
        return ioctl(IOCTL_LUMEN_VHID_RELEASE_INPUT_SESSION, request, response);
      }

      channel_result_t cleanup() override {
        if (handle_ == INVALID_HANDLE_VALUE) {
          return {};
        }

        const auto handle = std::exchange(handle_, INVALID_HANDLE_VALUE);
        const auto close_result = close_device_handle(handle);
        if (!close_result) {
          if (pending_) {
            static_cast<void>(pending_.release());
          }
          return close_result;
        }

        if (pending_) {
          // CloseHandle cancels all I/O issued by this file object. Give the I/O
          // manager a second bounded interval to retire the caller-owned buffers.
          // If a broken driver does not complete, retain the allocation permanently
          // rather than permit a late kernel write into freed user memory.
          if (WaitForSingleObject(pending_->overlapped.hEvent, ioctl_cancel_timeout_ms) == WAIT_OBJECT_0) {
            pending_.reset();
          } else {
            static_cast<void>(pending_.release());
          }
        }
        return {};
      }

    private:
      /**
       * @brief Heap-owned buffers retained until overlapped I/O is retired.
       */
      struct pending_io_t {
        /**
         * @brief Close the completion event.
         */
        ~pending_io_t() {
          if (overlapped.hEvent) {
            CloseHandle(overlapped.hEvent);
          }
        }

        OVERLAPPED overlapped {};  ///< Overlapped request state.
        std::array<std::byte, LUMEN_VHID_MAX_CONTROL_SIZE> input {};  ///< Stable request buffer.
        std::array<std::byte, LUMEN_VHID_MAX_CONTROL_SIZE> output {};  ///< Stable response buffer.
      };

      /**
       * @brief State owned by the bounded device-handle close worker.
       */
      struct close_context_t {
        HANDLE device_handle {INVALID_HANDLE_VALUE};  ///< Device handle to close.
        HANDLE completion_event {nullptr};  ///< Signals completion of `CloseHandle`.
        DWORD status {ERROR_SUCCESS};  ///< Close status.
      };

      /**
       * @brief Close a device handle outside the input serialization thread.
       * @param opaque Pointer to a `close_context_t`.
       * @return Thread exit status.
       */
      static DWORD WINAPI close_handle_worker(void *opaque) {
        auto *context = static_cast<close_context_t *>(opaque);
        if (!CloseHandle(context->device_handle)) {
          context->status = GetLastError();
        }
        SetEvent(context->completion_event);
        return 0;
      }

      /**
       * @brief Close a driver handle without permitting cleanup to hang indefinitely.
       * @param handle Driver handle.
       * @return Channel result.
       */
      static channel_result_t close_device_handle(HANDLE handle) {
        auto context = std::make_unique<close_context_t>();
        context->device_handle = handle;
        context->completion_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!context->completion_event) {
          const auto setup_status = GetLastError();
          if (CloseHandle(handle)) {
            return {};
          }
          const auto close_status = GetLastError();
          return {
            channel_completion_t::ambiguous,
            close_status ? close_status : setup_status
          };
        }

        const auto worker = CreateThread(nullptr, 0, close_handle_worker, context.get(), 0, nullptr);
        if (!worker) {
          const auto setup_status = GetLastError();
          CloseHandle(context->completion_event);
          if (CloseHandle(handle)) {
            return {};
          }
          const auto close_status = GetLastError();
          return {
            channel_completion_t::ambiguous,
            close_status ? close_status : setup_status
          };
        }

        const auto wait_result = WaitForSingleObject(context->completion_event, close_timeout_ms);
        if (wait_result != WAIT_OBJECT_0 ||
            WaitForSingleObject(worker, close_worker_settle_timeout_ms) != WAIT_OBJECT_0) {
          CloseHandle(worker);
          static_cast<void>(context.release());
          return {
            channel_completion_t::ambiguous,
            static_cast<DWORD>(wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED)
          };
        }

        CloseHandle(worker);
        CloseHandle(context->completion_event);
        return context->status == ERROR_SUCCESS ? channel_result_t {} : classify_channel_error(context->status);
      }

      /**
       * @brief Issue a fixed-size buffered protocol request.
       * @tparam Request Request structure type.
       * @tparam Response Response structure type.
       * @param code Control code.
       * @param request Input structure.
       * @param response Output structure.
       * @return Channel result.
       */
      template<class Request, class Response>
      channel_result_t ioctl(DWORD code, const Request &request, Response &response) {
        if (handle_ == INVALID_HANDLE_VALUE) {
          return {channel_completion_t::removed, ERROR_INVALID_HANDLE};
        }
        if (pending_) {
          return {channel_completion_t::ambiguous, ERROR_TIMEOUT};
        }

        auto pending = std::make_unique<pending_io_t>();
        pending->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!pending->overlapped.hEvent) {
          return classify_channel_error(GetLastError());
        }
        std::memcpy(pending->input.data(), &request, sizeof(request));

        const auto started = DeviceIoControl(
          handle_,
          code,
          pending->input.data(),
          sizeof(request),
          pending->output.data(),
          sizeof(response),
          nullptr,
          &pending->overlapped
        );
        const auto start_status = started ? ERROR_SUCCESS : GetLastError();
        if (!started && start_status != ERROR_IO_PENDING) {
          return classify_channel_error(start_status);
        }

        const auto wait_result = WaitForSingleObject(pending->overlapped.hEvent, ioctl_timeout_ms);
        if (wait_result != WAIT_OBJECT_0) {
          const auto wait_status = wait_result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
          CancelIoEx(handle_, &pending->overlapped);
          if (WaitForSingleObject(pending->overlapped.hEvent, ioctl_cancel_timeout_ms) != WAIT_OBJECT_0) {
            pending_ = std::move(pending);
          }
          return {channel_completion_t::ambiguous, wait_status};
        }

        DWORD returned = 0;
        if (!GetOverlappedResult(handle_, &pending->overlapped, &returned, FALSE)) {
          return classify_channel_error(GetLastError());
        }
        if (returned != sizeof(response)) {
          // The IOCTL completed successfully and may already have changed
          // driver/VHF state. A truncated acknowledgement is ambiguous.
          return {channel_completion_t::ambiguous, ERROR_INVALID_DATA};
        }
        std::memcpy(&response, pending->output.data(), sizeof(response));
        return {};
      }

      static constexpr DWORD ioctl_timeout_ms = 500;  ///< Per-request completion deadline.
      static constexpr DWORD ioctl_cancel_timeout_ms = 250;  ///< Cancellation drain deadline.
      static constexpr DWORD close_timeout_ms = 500;  ///< Driver cleanup deadline.
      static constexpr DWORD close_worker_settle_timeout_ms = 50;  ///< Worker retirement deadline.
      HANDLE handle_ {INVALID_HANDLE_VALUE};  ///< Open driver interface handle.
      std::unique_ptr<pending_io_t> pending_;  ///< Timed-out request retained for memory safety.
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
          return 0x85;
        case VK_SLEEP:
          return 0x82;
        default:
          return std::nullopt;
      }
    }

    /**
     * @brief Convert an active-layout Set 1 scan code to a HID keyboard usage.
     * @param scan_code Scan code returned by `MAPVK_VK_TO_VSC_EX`.
     * @return HID usage, or no value when the physical key is unsupported.
     */
    std::optional<std::uint8_t> scan_code_usage(UINT scan_code) {
      const auto code = static_cast<std::uint8_t>(scan_code & 0xFFU);
      const auto prefix = static_cast<std::uint8_t>((scan_code >> 8U) & 0xFFU);

      if (prefix == 0xE0) {
        switch (code) {
          case 0x1C:
            return 0x58;  // Keypad Enter
          case 0x1D:
            return 0xE4;  // Right Control
          case 0x35:
            return 0x54;  // Keypad Divide
          case 0x37:
            return 0x46;  // Print Screen
          case 0x38:
            return 0xE6;  // Right Alt
          case 0x47:
            return 0x4A;  // Home
          case 0x48:
            return 0x52;  // Up
          case 0x49:
            return 0x4B;  // Page Up
          case 0x4B:
            return 0x50;  // Left
          case 0x4D:
            return 0x4F;  // Right
          case 0x4F:
            return 0x4D;  // End
          case 0x50:
            return 0x51;  // Down
          case 0x51:
            return 0x4E;  // Page Down
          case 0x52:
            return 0x49;  // Insert
          case 0x53:
            return 0x4C;  // Delete
          case 0x5B:
            return 0xE3;  // Left GUI
          case 0x5C:
            return 0xE7;  // Right GUI
          case 0x5D:
            return 0x65;  // Application
          case 0x5F:
            return 0x82;  // System Sleep
          default:
            return std::nullopt;
        }
      }
      if (prefix != 0) {
        return std::nullopt;
      }

      switch (code) {
        case 0x47:
          return 0x5F;  // Keypad 7
        case 0x48:
          return 0x60;  // Keypad 8
        case 0x49:
          return 0x61;  // Keypad 9
        case 0x4A:
          return 0x56;  // Keypad Subtract
        case 0x4B:
          return 0x5C;  // Keypad 4
        case 0x4C:
          return 0x5D;  // Keypad 5
        case 0x4D:
          return 0x5E;  // Keypad 6
        case 0x4E:
          return 0x57;  // Keypad Add
        case 0x4F:
          return 0x59;  // Keypad 1
        case 0x50:
          return 0x5A;  // Keypad 2
        case 0x51:
          return 0x5B;  // Keypad 3
        case 0x52:
          return 0x62;  // Keypad 0
        case 0x53:
          return 0x63;  // Keypad Decimal
        default:
          break;
      }

      for (std::uint16_t key = 0; key < VK_TO_SCANCODE_MAP.size(); ++key) {
        if (VK_TO_SCANCODE_MAP[key] != code) {
          continue;
        }
        if (const auto usage = direct_key_usage(key)) {
          return usage;
        }
      }
      return std::nullopt;
    }

    /**
     * @brief Return the bitmap bit for a valid mouse button.
     * @param button Moonlight button number.
     * @return Button bit, or zero when invalid.
     */
    constexpr std::uint8_t mouse_button_bit(int button) noexcept {
      return button >= 1 && button <= 5 ? static_cast<std::uint8_t>(1U << (button - 1)) : 0;
    }
  }  // namespace

  std::optional<std::uint8_t> map_key_to_hid_usage(
    std::uint16_t modcode,
    std::uint8_t flags,
    bool always_send_scancodes
  ) {
    if (flags & SS_KBE_FLAG_NON_NORMALIZED) {
      if (!always_send_scancodes) {
        // The legacy path intentionally submits a virtual-key event here. HID
        // cannot reproduce that layout-dependent semantic safely, so request
        // a fenced whole-transport fallback before applying the transition.
        return std::nullopt;
      }
      if (modcode == VK_LWIN || modcode == VK_RWIN || modcode == VK_PAUSE) {
        return direct_key_usage(modcode);
      }
      // HID can express only physical keyboard usages. Resolve the requested
      // virtual key through the active layout first so OEM keys retain the old
      // SendInput virtual-key behavior on non-US hosts.
      const auto scan = MapVirtualKeyW(modcode, MAPVK_VK_TO_VSC_EX);
      if (!scan) {
        return std::nullopt;
      }
      return scan_code_usage(scan);
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
    if (backend_.load() == backend_t::virtual_hid || backend_.load() == backend_t::quiescing) {
      desired_keys_.clear();
      desired_buttons_ = 0;
      fence_and_release();
    } else if (backend_.load() == backend_t::send_input) {
      fallback_->neutralize();
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

    LUMEN_VHID_GET_CAPABILITIES_REQUEST capabilities_request {};
    capabilities_request.header = message_header(
      LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
      sizeof(capabilities_request)
    );
    LUMEN_VHID_GET_CAPABILITIES_RESPONSE capabilities_response {};
    result = channel_->get_capabilities(capabilities_request, capabilities_response);
    if (!result ||
        !lumen_vhid_validate_message_header(
          &capabilities_response.header,
          sizeof(capabilities_response),
          LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
          sizeof(capabilities_response)
        ) ||
        (capabilities_response.capabilities & LUMEN_VHID_CAP_REQUIRED) != LUMEN_VHID_CAP_REQUIRED ||
        (capabilities_response.required_capabilities & ~LUMEN_VHID_CAP_KNOWN_MASK) != 0 ||
        capabilities_response.max_control_size != LUMEN_VHID_MAX_CONTROL_SIZE ||
        capabilities_response.max_report_payload != LUMEN_VHID_MAX_REPORT_PAYLOAD ||
        capabilities_response.keyboard_report_size != sizeof(LUMEN_VHID_KEYBOARD_REPORT) ||
        capabilities_response.relative_mouse_report_size != sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT) ||
        capabilities_response.absolute_mouse_report_size != sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT)) {
      set_failure("capability handshake", result ? ERROR_REVISION_MISMATCH : result.status);
      channel_->cleanup();
      backend_.store(backend_t::send_input);
      return false;
    }

    protocol_minor_ = std::min<std::uint16_t>(
      LUMEN_VHID_PROTOCOL_MINOR,
      capabilities_response.header.protocol_minor
    );
    std::uint16_t negotiated_minor = 0;
    if (!lumen_vhid_negotiate_protocol(
          capabilities_response.header.protocol_major,
          protocol_minor_,
          LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
          LUMEN_VHID_CAP_REQUIRED,
          capabilities_response.capabilities,
          &negotiated_minor
        )) {
      set_failure("protocol negotiation", ERROR_REVISION_MISMATCH);
      channel_->cleanup();
      backend_.store(backend_t::send_input);
      return false;
    }
    protocol_minor_ = negotiated_minor;

    LUMEN_VHID_CLAIM_SESSION_REQUEST claim_request {};
    claim_request.header = message_header(
      LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
      sizeof(claim_request),
      protocol_minor_
    );
    claim_request.required_capabilities = LUMEN_VHID_CAP_REQUIRED;
    claim_request.optional_capabilities = LUMEN_VHID_CAP_OPTIONAL_MASK;
    LUMEN_VHID_CLAIM_SESSION_RESPONSE claim_response {};
    result = channel_->claim(claim_request, claim_response);
    if (!result ||
        !lumen_vhid_validate_message_header(
          &claim_response.header,
          sizeof(claim_response),
          LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
          sizeof(claim_response)
        ) ||
        claim_response.session_token == 0 ||
        (claim_response.granted_capabilities & LUMEN_VHID_CAP_REQUIRED) != LUMEN_VHID_CAP_REQUIRED) {
      set_failure("exclusive session claim", result ? ERROR_INVALID_DATA : result.status);
      const auto cleanup_result = channel_->cleanup();
      const auto safe_without_fence =
        result.completion == channel_completion_t::definite_reject ||
        result.completion == channel_completion_t::removed;
      backend_.store(safe_without_fence || cleanup_result ? backend_t::send_input : backend_t::fail_closed);
      return false;
    }

    session_token_ = claim_response.session_token;
    sequence_ = 0;
    const auto neutral_keyboard = keyboard_report();
    result = submit_report(
      LUMEN_VHID_DEVICE_KIND_KEYBOARD,
      LUMEN_VHID_REPORT_ID_KEYBOARD,
      &neutral_keyboard,
      sizeof(neutral_keyboard)
    );
    if (result) {
      LUMEN_VHID_RELATIVE_MOUSE_REPORT neutral_mouse {};
      neutral_mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
      result = submit_report(
        LUMEN_VHID_DEVICE_KIND_MOUSE,
        LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
        &neutral_mouse,
        sizeof(neutral_mouse)
      );
    }
    if (!result) {
      set_failure("neutral report", result.status);
      if (result.completion == channel_completion_t::removed) {
        channel_->cleanup();
        backend_.store(backend_t::send_input);
      } else {
        backend_.store(fence_and_release() ? backend_t::send_input : backend_t::fail_closed);
      }
      return false;
    }

    acknowledged_keyboard_ = neutral_keyboard;
    acknowledged_buttons_ = 0;
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
    for (const auto &[modcode, key] : desired_keys_) {
      static_cast<void>(modcode);
      if (key.usage >= 0xE0 && key.usage <= 0xE7) {
        report.modifiers |= static_cast<std::uint8_t>(1U << (key.usage - 0xE0));
      } else if (key.usage / 8 < LUMEN_VHID_NKRO_BITMAP_SIZE) {
        report.key_bitmap[key.usage / 8] |= static_cast<std::uint8_t>(1U << (key.usage % 8));
      }
    }
    return report;
  }

  channel_result_t virtual_hid_transport_t::submit_report(
    std::uint16_t device_kind,
    std::uint16_t report_id,
    const void *report,
    std::uint16_t report_size
  ) {
    if (sequence_ == std::numeric_limits<std::uint64_t>::max() ||
        report_size > LUMEN_VHID_MAX_REPORT_PAYLOAD ||
        !lumen_vhid_validate_report_metadata(device_kind, report_id, report_size)) {
      return {channel_completion_t::definite_reject, ERROR_INVALID_DATA};
    }

    const auto next_sequence = sequence_ + 1;
    LUMEN_VHID_SUBMIT_REPORT_REQUEST request {};
    request.header = message_header(
      LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
      sizeof(request),
      protocol_minor_
    );
    request.session_token = session_token_;
    request.sequence = next_sequence;
    request.device_kind = device_kind;
    request.report_id = report_id;
    request.payload_size = report_size;
    std::memcpy(request.payload, report, report_size);

    LUMEN_VHID_SUBMIT_REPORT_RESPONSE response {};
    auto result = channel_->submit(request, response);
    if (!result) {
      return result;
    }
    if (!lumen_vhid_validate_message_header(
          &response.header,
          sizeof(response),
          LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
          sizeof(response)
        ) ||
        response.session_token != session_token_ || response.accepted_sequence != next_sequence) {
      // DeviceIoControl succeeded, so the driver may already have submitted the
      // report to VHF. A malformed acknowledgement is therefore ambiguous and
      // its stateless delta must never be replayed through SendInput.
      return {channel_completion_t::ambiguous, ERROR_INVALID_DATA};
    }
    sequence_ = next_sequence;
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
      LUMEN_VHID_RELATIVE_MOUSE_REPORT report {};
      report.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
      report.buttons = desired_buttons_;
      report.x = static_cast<std::int16_t>(segment_x);
      report.y = static_cast<std::int16_t>(segment_y);
      const auto result = submit_report(
        LUMEN_VHID_DEVICE_KIND_MOUSE,
        LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
        &report,
        sizeof(report)
      );
      if (!result) {
        const auto replay_x = static_cast<std::int32_t>(remaining_x);
        const auto replay_y = static_cast<std::int32_t>(remaining_y);
        return failover(result, "relative mouse report", [this, replay_x, replay_y] {
          return fallback_->move_mouse(replay_x, replay_y);
        });
      }
      acknowledged_buttons_ = desired_buttons_;
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
    if (source_width <= 0 || source_height <= 0) {
      return {completion_t::rejected, ERROR_INVALID_PARAMETER};
    }

    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->absolute_mouse(x, y, source_width, source_height);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    const auto scaled_x = std::clamp<long>(
      std::lround(x * (65535.0f / static_cast<float>(source_width))),
      0,
      65535
    );
    const auto scaled_y = std::clamp<long>(
      std::lround(y * (65535.0f / static_cast<float>(source_height))),
      0,
      65535
    );
    LUMEN_VHID_ABSOLUTE_MOUSE_REPORT report {};
    report.report_id = LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE;
    report.buttons = desired_buttons_;
    report.x = static_cast<std::uint16_t>(scaled_x);
    report.y = static_cast<std::uint16_t>(scaled_y);
    const auto result = submit_report(
      LUMEN_VHID_DEVICE_KIND_MOUSE,
      LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE,
      &report,
      sizeof(report)
    );
    if (!result) {
      return failover(result, "absolute mouse report", [this, x, y, source_width, source_height] {
        return fallback_->absolute_mouse(x, y, source_width, source_height);
      });
    }
    acknowledged_buttons_ = desired_buttons_;
    return {};
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

    if (release) {
      desired_buttons_ &= static_cast<std::uint8_t>(~bit);
    } else {
      desired_buttons_ |= bit;
    }
    LUMEN_VHID_RELATIVE_MOUSE_REPORT report {};
    report.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
    report.buttons = desired_buttons_;
    const auto result = submit_report(
      LUMEN_VHID_DEVICE_KIND_MOUSE,
      LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
      &report,
      sizeof(report)
    );
    if (!result) {
      return failover(result, "mouse button report");
    }
    acknowledged_buttons_ = desired_buttons_;
    return {};
  }

  result_t virtual_hid_transport_t::vertical_scroll(std::int32_t distance) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->vertical_scroll(distance);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    std::int64_t remaining = distance;
    bool submit_zero = remaining == 0;
    do {
      const auto segment = std::clamp<std::int64_t>(
        remaining,
        std::numeric_limits<std::int16_t>::min(),
        std::numeric_limits<std::int16_t>::max()
      );
      LUMEN_VHID_RELATIVE_MOUSE_REPORT report {};
      report.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
      report.buttons = desired_buttons_;
      report.vertical_wheel = static_cast<std::int16_t>(segment);
      const auto result = submit_report(
        LUMEN_VHID_DEVICE_KIND_MOUSE,
        LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
        &report,
        sizeof(report)
      );
      if (!result) {
        const auto replay = static_cast<std::int32_t>(remaining);
        return failover(result, "vertical wheel report", [this, replay] {
          return fallback_->vertical_scroll(replay);
        });
      }
      acknowledged_buttons_ = desired_buttons_;
      remaining -= segment;
      submit_zero = false;
    } while (remaining != 0 || submit_zero);
    return {};
  }

  result_t virtual_hid_transport_t::horizontal_scroll(std::int32_t distance) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->horizontal_scroll(distance);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    std::int64_t remaining = distance;
    bool submit_zero = remaining == 0;
    do {
      const auto segment = std::clamp<std::int64_t>(
        remaining,
        std::numeric_limits<std::int16_t>::min(),
        std::numeric_limits<std::int16_t>::max()
      );
      LUMEN_VHID_RELATIVE_MOUSE_REPORT report {};
      report.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
      report.buttons = desired_buttons_;
      report.horizontal_wheel = static_cast<std::int16_t>(segment);
      const auto result = submit_report(
        LUMEN_VHID_DEVICE_KIND_MOUSE,
        LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE,
        &report,
        sizeof(report)
      );
      if (!result) {
        const auto replay = static_cast<std::int32_t>(remaining);
        return failover(result, "horizontal wheel report", [this, replay] {
          return fallback_->horizontal_scroll(replay);
        });
      }
      acknowledged_buttons_ = desired_buttons_;
      remaining -= segment;
      submit_zero = false;
    } while (remaining != 0 || submit_zero);
    return {};
  }

  result_t virtual_hid_transport_t::keyboard(std::uint16_t modcode, bool release, std::uint8_t flags) {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->keyboard(modcode, release, flags);
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    const auto usage = map_key_to_hid_usage(modcode, flags, config::input.always_send_scancodes);
    if (!usage) {
      return failover(
        {channel_completion_t::definite_reject, ERROR_NOT_SUPPORTED},
        "keyboard mapping",
        [this, modcode, release, flags] {
          return fallback_->keyboard(modcode, release, flags);
        }
      );
    }

    if (release) {
      desired_keys_.erase(modcode);
    } else {
      desired_keys_[modcode] = held_key_t {flags, *usage};
    }
    const auto report = keyboard_report();
    const auto result = submit_report(
      LUMEN_VHID_DEVICE_KIND_KEYBOARD,
      LUMEN_VHID_REPORT_ID_KEYBOARD,
      &report,
      sizeof(report)
    );
    if (!result) {
      return failover(result, "keyboard report");
    }
    acknowledged_keyboard_ = report;
    return {};
  }

  result_t virtual_hid_transport_t::unicode(const char *utf8, int size) {
    return fallback_->unicode(utf8, size);
  }

  result_t virtual_hid_transport_t::neutralize() {
    std::lock_guard lock(mutex_);
    if (backend_.load() == backend_t::send_input) {
      return fallback_->neutralize();
    }
    if (backend_.load() != backend_t::virtual_hid) {
      return {completion_t::ambiguous, ERROR_NOT_READY};
    }

    desired_keys_.clear();
    desired_buttons_ = 0;
    LUMEN_VHID_SESSION_REQUEST request {};
    request.header = message_header(
      LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
      sizeof(request),
      protocol_minor_
    );
    request.session_token = session_token_;
    LUMEN_VHID_SESSION_RESPONSE response {};
    const auto result = channel_->reset(request, response);
    if (!result ||
        !lumen_vhid_validate_message_header(
          &response.header,
          sizeof(response),
          LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
          sizeof(response)
        ) ||
        response.session_token == 0 || response.last_sequence != 0) {
      return failover(result ? channel_result_t {channel_completion_t::definite_reject, ERROR_INVALID_DATA} : result, "session reset");
    }

    session_token_ = response.session_token;
    sequence_ = 0;
    acknowledged_keyboard_ = keyboard_report();
    acknowledged_buttons_ = 0;
    return {};
  }

  result_t virtual_hid_transport_t::failover(
    channel_result_t failure,
    const char *stage,
    const std::function<result_t()> &definitely_rejected_delta
  ) {
    backend_.store(backend_t::quiescing);
    set_failure(stage, failure.status);

    bool fenced = false;
    if (failure.completion == channel_completion_t::removed) {
      channel_->cleanup();
      fenced = true;
    } else {
      fenced = fence_and_release();
    }
    if (!fenced) {
      backend_.store(backend_t::fail_closed);
      BOOST_LOG(error)
        << "Lumen Virtual HID transition failed closed (stage="sv << stage
        << ", status="sv << failure.status << ')';
      return {completion_t::ambiguous, failure.status};
    }

    backend_.store(backend_t::send_input);
    BOOST_LOG(warning)
      << "Lumen Virtual HID entered SendInput fallback after a fenced failure (stage="sv << stage
      << ", status="sv << failure.status << ')';
    auto result = replay_held_state();
    if (!result) {
      return result;
    }
    if (failure.completion == channel_completion_t::definite_reject && definitely_rejected_delta) {
      return definitely_rejected_delta();
    }
    return {};
  }

  result_t virtual_hid_transport_t::replay_held_state() {
    for (const auto &[modcode, key] : desired_keys_) {
      if (key.usage < 0xE0 || key.usage > 0xE7) {
        continue;
      }
      const auto result = fallback_->keyboard(modcode, false, key.flags);
      if (!result) {
        return result;
      }
    }
    for (const auto &[modcode, key] : desired_keys_) {
      if (key.usage >= 0xE0 && key.usage <= 0xE7) {
        continue;
      }
      const auto result = fallback_->keyboard(modcode, false, key.flags);
      if (!result) {
        return result;
      }
    }
    for (int button = 1; button <= 5; ++button) {
      if (!(desired_buttons_ & mouse_button_bit(button))) {
        continue;
      }
      const auto result = fallback_->mouse_button(button, false);
      if (!result) {
        return result;
      }
    }
    return {};
  }

  bool virtual_hid_transport_t::fence_and_release() {
    bool explicit_fence = false;
    LUMEN_VHID_SESSION_REQUEST reset_request {};
    reset_request.header = message_header(
      LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
      sizeof(reset_request),
      protocol_minor_
    );
    reset_request.session_token = session_token_;
    LUMEN_VHID_SESSION_RESPONSE reset_response {};
    const auto reset_result = channel_->reset(reset_request, reset_response);
    if (reset_result.completion == channel_completion_t::removed) {
      channel_->cleanup();
      session_token_ = 0;
      sequence_ = 0;
      return true;
    }
    if (reset_result &&
        lumen_vhid_validate_message_header(
          &reset_response.header,
          sizeof(reset_response),
          LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
          sizeof(reset_response)
        ) &&
        reset_response.session_token != 0 && reset_response.last_sequence == 0) {
      session_token_ = reset_response.session_token;
      sequence_ = 0;

      LUMEN_VHID_SESSION_REQUEST release_request {};
      release_request.header = message_header(
        LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION,
        sizeof(release_request),
        protocol_minor_
      );
      release_request.session_token = session_token_;
      LUMEN_VHID_SESSION_RESPONSE release_response {};
      const auto release_result = channel_->release(release_request, release_response);
      if (release_result.completion == channel_completion_t::removed) {
        channel_->cleanup();
        session_token_ = 0;
        sequence_ = 0;
        return true;
      }
      explicit_fence = release_result &&
                       lumen_vhid_validate_message_header(
                         &release_response.header,
                         sizeof(release_response),
                         LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION,
                         sizeof(release_response)
                       ) &&
                       release_response.session_token == session_token_;
    }

    const auto cleanup_result = channel_->cleanup();
    session_token_ = 0;
    sequence_ = 0;
    return explicit_fence || static_cast<bool>(cleanup_result);
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
    } else if (transport->backend() == backend_t::fail_closed) {
      BOOST_LOG(error)
        << "Windows keyboard and mouse backend failed closed during Virtual HID initialization (stage="sv
        << transport->failure_stage() << ", status="sv << transport->failure_status() << ')';
    } else {
      BOOST_LOG(warning)
        << "Windows keyboard and mouse backend: SendInput fallback (stage="sv
        << transport->failure_stage() << ", status="sv << transport->failure_status() << ')';
    }
    return transport;
  }
}  // namespace platf::win_input
