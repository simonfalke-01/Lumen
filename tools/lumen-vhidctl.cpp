/**
 * @file tools/lumen-vhidctl.cpp
 * @brief Installs, queries, and removes the Lumen Virtual HID driver package.
 */

#define WIN32_LEAN_AND_MEAN
#define INITGUID
// clang-format off
#include <windows.h>
#include "src/platform/windows/virtual_hid_protocol.h"
// clang-format on

#include <algorithm>
#include <array>
#include <cctype>
#include <cfgmgr32.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <devpkey.h>
#include <hidsdi.h>
#include <iomanip>
#include <iostream>
#include <optional>
#include <setupapi.h>
#include <shellapi.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

// lib includes
#include <ViGEm/Client.h>
#include <Xinput.h>

namespace {
  constexpr wchar_t kDeviceDescription[] = L"Lumen Virtual Input";
  constexpr DWORD kInstallFlagForce = 0x00000001;
  constexpr int kInterfaceWaitAttempts = 30;
  constexpr int kGamepadSmokeWaitAttempts = 300;
  constexpr int kXinputVisibilityWaitAttempts = 20;  ///< Best-effort XInput diagnostic wait, in 100 ms attempts.
  constexpr std::uint32_t kProtocolGeneration = 3;

  /** Stable process exit codes consumed by Windows packaging. */
  enum class exit_code : int {
    success = 0,
    mutation_failed = 1,
    absent = 2,
    inaccessible = 3,
    incompatible = 4,
    reboot_required = 3010,
  };

  /** Dynamically loaded NewDev update API signature. */
  using update_driver_fn = BOOL(WINAPI *)(HWND, LPCWSTR, LPCWSTR, DWORD, PBOOL);
  /** Dynamically loaded NewDev device-uninstall API signature. */
  using uninstall_device_fn = BOOL(WINAPI *)(HWND, HDEVINFO, PSP_DEVINFO_DATA, DWORD, PBOOL);
  /** Dynamically loaded NewDev uninstall API signature. */
  using uninstall_driver_fn = BOOL(WINAPI *)(HWND, LPCWSTR, DWORD, PBOOL);

  /** Resolve one dynamically loaded function without incompatible-function casts. */
  template<class Function>
  Function resolve_function(HMODULE module, const char *name) {
    const auto procedure = GetProcAddress(module, name);
    static_assert(sizeof(Function) == sizeof(procedure));
    Function function = nullptr;
    std::memcpy(&function, &procedure, sizeof(function));
    return function;
  }

  /** RAII wrapper for a SetupAPI device information set. */
  class device_info_set {
  public:
    /** Adopt a SetupAPI handle, including INVALID_HANDLE_VALUE. */
    explicit device_info_set(HDEVINFO handle) noexcept:
        handle_(handle) {}

    /** Device information sets have unique ownership. */
    device_info_set(const device_info_set &) = delete;
    device_info_set &operator=(const device_info_set &) = delete;

    /** Transfer ownership from another wrapper. */
    device_info_set(device_info_set &&other) noexcept:
        handle_(other.handle_) {
      other.handle_ = INVALID_HANDLE_VALUE;
    }

    /** Release the current set and transfer ownership from another wrapper. */
    device_info_set &operator=(device_info_set &&other) noexcept {
      if (this != &other) {
        if (handle_ != INVALID_HANDLE_VALUE) {
          SetupDiDestroyDeviceInfoList(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = INVALID_HANDLE_VALUE;
      }
      return *this;
    }

    /** Destroy the wrapped SetupAPI set. */
    ~device_info_set() {
      if (handle_ != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(handle_);
      }
    }

    /** Return the wrapped SetupAPI handle. */
    [[nodiscard]] HDEVINFO get() const noexcept {
      return handle_;
    }

    /** Return whether the wrapped handle was created successfully. */
    [[nodiscard]] bool valid() const noexcept {
      return handle_ != INVALID_HANDLE_VALUE;
    }

  private:
    HDEVINFO handle_ = INVALID_HANDLE_VALUE;
  };

  /** RAII wrapper for a loaded Windows module. */
  class module_handle {
  public:
    /** Adopt a module handle, including nullptr. */
    explicit module_handle(HMODULE handle) noexcept:
        handle_(handle) {}

    /** Loaded modules have unique ownership. */
    module_handle(const module_handle &) = delete;
    module_handle &operator=(const module_handle &) = delete;

    /** Release the loaded module. */
    ~module_handle() {
      if (handle_ != nullptr) {
        FreeLibrary(handle_);
      }
    }

    /** Return the wrapped module handle. */
    [[nodiscard]] HMODULE get() const noexcept {
      return handle_;
    }

  private:
    HMODULE handle_ = nullptr;
  };

  /** Exact root-device enumeration result. */
  struct device_enumeration {
    device_info_set set {INVALID_HANDLE_VALUE};
    std::vector<SP_DEVINFO_DATA> devices;
    DWORD error = ERROR_SUCCESS;
  };

  /** ConfigMgr diagnostic captured from the first unhealthy device node. */
  struct pnp_diagnostic {
    ULONG status = 0;  ///< Device-node status flags from CM_Get_DevNode_Status.
    ULONG problem = 0;  ///< Configuration Manager problem code.
    DWORD problem_status = 0;  ///< NTSTATUS value associated with the problem.
    CONFIGRET error = CR_SUCCESS;  ///< Last ConfigMgr traversal error.
    bool status_available = false;  ///< Whether status and problem contain valid values.
    bool problem_status_available = false;  ///< Whether problem_status contains a valid value.
  };

  /** Started HID collections published by the Lumen transport. */
  struct collection_inventory {
    unsigned keyboard_count = 0;
    unsigned mouse_count = 0;
    unsigned consumer_count = 0;
    DWORD error = ERROR_SUCCESS;

    /** Return whether every required Lumen HID collection is present. */
    [[nodiscard]] bool healthy() const noexcept {
      return keyboard_count == 1 && mouse_count == LUMEN_VHID_MOUSE_COLLECTION_COUNT && consumer_count == 1;
    }
  };

  /** Result of querying the SYSTEM-only control interface ABI. */
  enum class probe_state {
    compatible,
    absent,
    inaccessible,
    incompatible,
  };

  /** Machine-readable SYSTEM control-interface probe result. */
  struct probe_result {
    probe_state state = probe_state::absent;
    DWORD error = ERROR_SUCCESS;
    std::uint32_t abi_version = 0;
    std::uint32_t gamepad_abi_version = 0;
    std::uint32_t gamepad_capability_flags = 0;
    std::uint64_t supported_gamepad_profiles = 0;
    std::uint32_t max_gamepads = 0;
    std::uint32_t active_gamepads = 0;
  };

  /** Driver package generation selected by an exact supported class GUID. */
  enum class package_generation {
    current,
    legacy_007,
  };

  /** Escape a value for a single-line JSON string. */
  std::wstring json_escape(std::wstring_view value) {
    std::wostringstream output;
    for (const wchar_t ch : value) {
      switch (ch) {
        case L'\\':
          output << L"\\\\";
          break;
        case L'\"':
          output << L"\\\"";
          break;
        case L'\b':
          output << L"\\b";
          break;
        case L'\f':
          output << L"\\f";
          break;
        case L'\n':
          output << L"\\n";
          break;
        case L'\r':
          output << L"\\r";
          break;
        case L'\t':
          output << L"\\t";
          break;
        default:
          if (ch < 0x20) {
            wchar_t escaped[7] {};
            swprintf(escaped, std::size(escaped), L"\\u%04x", static_cast<unsigned>(ch));
            output << escaped;
          } else {
            output << ch;
          }
      }
    }
    return output.str();
  }

  /** Format a Win32 error without embedded line breaks. */
  std::wstring win32_message(DWORD error) {
    wchar_t *raw = nullptr;
    const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      0,
      reinterpret_cast<wchar_t *>(&raw),
      0,
      nullptr
    );
    std::wstring message = length != 0 && raw != nullptr ? std::wstring(raw, length) : L"unknown error";
    if (raw != nullptr) {
      LocalFree(raw);
    }
    for (wchar_t &ch : message) {
      if (ch == L'\r' || ch == L'\n' || ch == L'\t' || ch == L'\"') {
        ch = L' ';
      }
    }
    while (!message.empty() && message.back() == L' ') {
      message.pop_back();
    }
    return message;
  }

  /** Format a SetupAPI error when the system message table has no entry. */
  std::wstring setupapi_message(DWORD error) {
    struct known_setupapi_error {
      DWORD code;
      const wchar_t *message;
    };

    static constexpr known_setupapi_error known_errors[] = {
      {0xE0000219u, L"The installation failed because a function driver was not specified for this device instance."},
      {0xE0000231u, L"A device cannot be removed because one of its descendants vetoed the removal."},
    };
    for (const auto &known : known_errors) {
      if (known.code == error) {
        return known.message;
      }
    }
    return win32_message(error);
  }

  /** Translate privilege errors while preserving the operation-specific fallback. */
  exit_code error_code(exit_code fallback, DWORD error) {
    if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD) {
      return exit_code::inaccessible;
    }
    return fallback;
  }

  /** Normalize every mutating failure to the stable mutation failure exit. */
  exit_code mutation_error_code(DWORD) {
    return exit_code::mutation_failed;
  }

  /**
   * @brief Emit a stable machine-readable diagnostic and return its exit code.
   *
   * @param code Stable process exit code.
   * @param operation Operation that failed.
   * @param error Win32 or SetupAPI error associated with the failure.
   * @param pnp Optional diagnostic for an unhealthy PnP device node.
   * @return Numeric process exit code.
   */
  int fail(
    exit_code code,
    std::wstring_view operation,
    DWORD error,
    const pnp_diagnostic *pnp = nullptr
  ) {
    std::wcerr << L"result=error code=" << static_cast<int>(code)
               << L" operation=" << operation;
    if (error != ERROR_SUCCESS) {
      std::wcerr << L" win32=" << error
                 << L" hex=\"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << error
                 << std::dec << std::nouppercase << std::setfill(L' ')
                 << L"\" message=\"" << setupapi_message(error) << L'\"';
    }
    if (pnp != nullptr && pnp->status_available) {
      std::wcerr << L" cm_status=" << pnp->status
                 << L" cm_problem=" << pnp->problem;
      if (pnp->problem_status_available) {
        std::wcerr << L" problem_status=" << pnp->problem_status
                   << L" problem_status_hex=\"0x" << std::uppercase << std::hex << std::setw(8)
                   << std::setfill(L'0') << pnp->problem_status
                   << std::dec << std::nouppercase << std::setfill(L' ') << L'\"';
      }
    }
    if (pnp != nullptr && pnp->error != CR_SUCCESS) {
      std::wcerr << L" cm_error=" << pnp->error;
    }
    std::wcerr << L'\n';
    return static_cast<int>(code);
  }

  /** Compare a device hardware ID with Lumen's canonical root ID. */
  bool equals_hardware_id(const wchar_t *value) {
    return _wcsicmp(value, LUMEN_VHID_ROOT_HARDWARE_ID_W) == 0;
  }

  /** Check a SetupAPI device node for the exact canonical hardware ID. */
  bool device_has_hardware_id(HDEVINFO set, SP_DEVINFO_DATA &device) {
    DWORD required = 0;
    DWORD type = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, &type, nullptr, 0, &required);
    if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return false;
    }

    std::vector<BYTE> buffer(required + sizeof(wchar_t), 0);
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, &type, buffer.data(), required, nullptr)) {
      return false;
    }
    if (type != REG_MULTI_SZ && type != REG_SZ) {
      return false;
    }

    const auto *current = reinterpret_cast<const wchar_t *>(buffer.data());
    const auto *end = reinterpret_cast<const wchar_t *>(buffer.data() + required);
    while (current < end && *current != L'\0') {
      if (equals_hardware_id(current)) {
        return true;
      }
      current += wcslen(current) + 1;
    }
    return false;
  }

  /** Enumerate exact device nodes, optionally restricting the result to present nodes. */
  device_enumeration enumerate_devices(DWORD flags = DIGCF_ALLCLASSES) {
    device_enumeration result;
    result.set = device_info_set(SetupDiGetClassDevsW(nullptr, nullptr, nullptr, flags));
    if (!result.set.valid()) {
      result.error = GetLastError();
      return result;
    }

    for (DWORD index = 0;; ++index) {
      SP_DEVINFO_DATA device {};
      device.cbSize = sizeof(device);
      if (!SetupDiEnumDeviceInfo(result.set.get(), index, &device)) {
        const DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_ITEMS) {
          result.error = error;
        }
        break;
      }
      if (device_has_hardware_id(result.set.get(), device)) {
        result.devices.push_back(device);
      }
    }
    return result;
  }

  /**
   * @brief Query the kernel problem status associated with one unhealthy device node.
   *
   * @param device Device node to query.
   * @param diagnostic Diagnostic updated when the property is available and well-typed.
   */
  void query_problem_status(DEVINST device, pnp_diagnostic &diagnostic) {
    DEVPROPTYPE property_type = DEVPROP_TYPE_EMPTY;
    ULONG size = sizeof(diagnostic.problem_status);
    diagnostic.problem_status_available =
      CM_Get_DevNode_PropertyW(
        device,
        &DEVPKEY_Device_ProblemStatus,
        &property_type,
        reinterpret_cast<PBYTE>(&diagnostic.problem_status),
        &size,
        0
      ) == CR_SUCCESS &&
      property_type == DEVPROP_TYPE_NTSTATUS && size == sizeof(diagnostic.problem_status);
  }

  /**
   * @brief Verify that one device node started without a PnP problem.
   *
   * @param device Device node to inspect.
   * @param diagnostic Diagnostic populated when the node is unhealthy.
   * @return true if the node is started and has no PnP problem.
   */
  bool device_started(DEVINST device, pnp_diagnostic &diagnostic) {
    ULONG status = 0;
    ULONG problem = 0;
    diagnostic.error = CM_Get_DevNode_Status(&status, &problem, device, 0);
    if (diagnostic.error != CR_SUCCESS) {
      return false;
    }
    if ((status & DN_STARTED) != 0 && (status & DN_HAS_PROBLEM) == 0) {
      return true;
    }
    diagnostic.status = status;
    diagnostic.problem = problem;
    diagnostic.status_available = true;
    query_problem_status(device, diagnostic);
    return false;
  }

  /**
   * @brief Verify that every descendant of the Lumen root node started without a PnP problem.
   *
   * @param parent Parent whose descendants should be inspected.
   * @param diagnostic Diagnostic populated from the first unhealthy descendant.
   * @return true if every descendant is started and has no PnP problem.
   */
  bool descendants_started(DEVINST parent, pnp_diagnostic &diagnostic) {
    DEVINST child = 0;
    diagnostic.error = CM_Get_Child(&child, parent, 0);
    if (diagnostic.error == CR_NO_SUCH_DEVNODE) {
      diagnostic.error = CR_SUCCESS;
      return true;
    }
    if (diagnostic.error != CR_SUCCESS) {
      return false;
    }

    for (;;) {
      if (!device_started(child, diagnostic) || !descendants_started(child, diagnostic)) {
        return false;
      }
      DEVINST sibling = 0;
      diagnostic.error = CM_Get_Sibling(&sibling, child, 0);
      if (diagnostic.error == CR_NO_SUCH_DEVNODE) {
        diagnostic.error = CR_SUCCESS;
        return true;
      }
      if (diagnostic.error != CR_SUCCESS) {
        return false;
      }
      child = sibling;
    }
  }

  /**
   * @brief Verify that the Lumen root and all of its descendants started successfully.
   *
   * @param root Root device node to inspect.
   * @param diagnostic Diagnostic populated from the first unhealthy device node.
   * @return true if the complete device tree started without a PnP problem.
   */
  bool device_tree_started(DEVINST root, pnp_diagnostic &diagnostic) {
    return device_started(root, diagnostic) && descendants_started(root, diagnostic);
  }

  /** Read the top-level HID capabilities for a Lumen collection. */
  bool get_lumen_collection_caps(HANDLE handle, HIDP_CAPS &capabilities) {
    HIDD_ATTRIBUTES attributes {};
    attributes.Size = sizeof(attributes);
    if (!HidD_GetAttributes(handle, &attributes) ||
        attributes.VendorID != LUMEN_VHID_VENDOR_ID ||
        attributes.ProductID != LUMEN_VHID_PRODUCT_ID ||
        attributes.VersionNumber != LUMEN_VHID_VERSION_NUMBER) {
      return false;
    }

    PHIDP_PREPARSED_DATA preparsed_data = nullptr;
    if (!HidD_GetPreparsedData(handle, &preparsed_data)) {
      return false;
    }
    const auto status = HidP_GetCaps(preparsed_data, &capabilities);
    HidD_FreePreparsedData(preparsed_data);
    return status == HIDP_STATUS_SUCCESS;
  }

  /** Inventory every started Lumen HID top-level collection. */
  collection_inventory find_present_collections() {
    collection_inventory result;
    GUID hid_guid {};
    HidD_GetHidGuid(&hid_guid);
    device_info_set set(SetupDiGetClassDevsW(&hid_guid, nullptr, nullptr, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT));
    if (!set.valid()) {
      result.error = GetLastError();
      return result;
    }

    for (DWORD index = 0;; ++index) {
      SP_DEVICE_INTERFACE_DATA interface_data {};
      interface_data.cbSize = sizeof(interface_data);
      if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &hid_guid, index, &interface_data)) {
        const DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_ITEMS) {
          result.error = error;
        }
        return result;
      }

      DWORD required = 0;
      SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, nullptr, 0, &required, nullptr);
      if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        continue;
      }

      std::vector<BYTE> buffer(required, 0);
      auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(buffer.data());
      detail->cbSize = sizeof(*detail);
      if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr, nullptr)) {
        continue;
      }

      const auto probe = CreateFileW(
        detail->DevicePath,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
      );
      if (probe == INVALID_HANDLE_VALUE) {
        continue;
      }
      HIDP_CAPS capabilities {};
      const auto matches = get_lumen_collection_caps(probe, capabilities);
      CloseHandle(probe);
      if (!matches) {
        continue;
      }
      if (capabilities.UsagePage == HID_USAGE_PAGE_GENERIC &&
          capabilities.Usage == HID_USAGE_GENERIC_KEYBOARD) {
        ++result.keyboard_count;
      } else if (capabilities.UsagePage == HID_USAGE_PAGE_GENERIC &&
                 capabilities.Usage == HID_USAGE_GENERIC_MOUSE) {
        ++result.mouse_count;
      } else if (capabilities.UsagePage == 0x0c && capabilities.Usage == 0x01) {
        ++result.consumer_count;
      }
    }
  }

  /**
   * @brief Count present HID gamepad collections with one exact reported identity.
   *
   * @param vendor_id Expected HID vendor identifier.
   * @param product_id Expected HID product identifier.
   * @param version_number Expected HID version number.
   * @param error Receives an interface-enumeration error.
   * @return Number of matching present gamepad collections.
   */
  unsigned count_gamepad_collections(
    std::uint16_t vendor_id,
    std::uint16_t product_id,
    std::uint16_t version_number,
    DWORD &error
  ) {
    error = ERROR_SUCCESS;
    unsigned count = 0;
    GUID hid_guid {};
    HidD_GetHidGuid(&hid_guid);
    device_info_set set(SetupDiGetClassDevsW(&hid_guid, nullptr, nullptr, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT));
    if (!set.valid()) {
      error = GetLastError();
      return 0;
    }

    for (DWORD index = 0;; ++index) {
      SP_DEVICE_INTERFACE_DATA interface_data {};
      interface_data.cbSize = sizeof(interface_data);
      if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &hid_guid, index, &interface_data)) {
        const DWORD enumeration_error = GetLastError();
        if (enumeration_error != ERROR_NO_MORE_ITEMS) {
          error = enumeration_error;
        }
        return count;
      }

      DWORD required = 0;
      SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, nullptr, 0, &required, nullptr);
      if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        continue;
      }
      std::vector<BYTE> buffer(required, 0);
      auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(buffer.data());
      detail->cbSize = sizeof(*detail);
      if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr, nullptr)) {
        continue;
      }

      const HANDLE probe = CreateFileW(
        detail->DevicePath,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
      );
      if (probe == INVALID_HANDLE_VALUE) {
        continue;
      }
      HIDD_ATTRIBUTES attributes {};
      attributes.Size = sizeof(attributes);
      PHIDP_PREPARSED_DATA preparsed_data = nullptr;
      HIDP_CAPS capabilities {};
      const bool matches = HidD_GetAttributes(probe, &attributes) &&
                           attributes.VendorID == vendor_id &&
                           attributes.ProductID == product_id &&
                           attributes.VersionNumber == version_number &&
                           HidD_GetPreparsedData(probe, &preparsed_data) &&
                           HidP_GetCaps(preparsed_data, &capabilities) == HIDP_STATUS_SUCCESS &&
                           capabilities.UsagePage == HID_USAGE_PAGE_GENERIC &&
                           (capabilities.Usage == HID_USAGE_GENERIC_GAMEPAD ||
                            capabilities.Usage == HID_USAGE_GENERIC_JOYSTICK);
      if (preparsed_data != nullptr) {
        HidD_FreePreparsedData(preparsed_data);
      }
      CloseHandle(probe);
      if (matches) {
        ++count;
      }
    }
  }

  /**
   * @brief Open one present HID gamepad or joystick collection with an exact identity.
   *
   * @param vendor_id Expected HID vendor identifier.
   * @param product_id Expected HID product identifier.
   * @param version_number Expected HID version number.
   * @param overlapped Whether the handle will be used for overlapped I/O.
   * @param error Receives a Win32 enumeration or open error.
   * @return Writable HID handle, or INVALID_HANDLE_VALUE when no match is present.
   */
  HANDLE open_gamepad_collection(
    std::uint16_t vendor_id,
    std::uint16_t product_id,
    std::uint16_t version_number,
    bool overlapped,
    DWORD &error
  ) {
    error = ERROR_FILE_NOT_FOUND;
    GUID hid_guid {};
    HidD_GetHidGuid(&hid_guid);
    device_info_set set(SetupDiGetClassDevsW(&hid_guid, nullptr, nullptr, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT));
    if (!set.valid()) {
      error = GetLastError();
      return INVALID_HANDLE_VALUE;
    }

    for (DWORD index = 0;; ++index) {
      SP_DEVICE_INTERFACE_DATA interface_data {};
      interface_data.cbSize = sizeof(interface_data);
      if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &hid_guid, index, &interface_data)) {
        const auto enumeration_error = GetLastError();
        if (enumeration_error != ERROR_NO_MORE_ITEMS) {
          error = enumeration_error;
        }
        return INVALID_HANDLE_VALUE;
      }
      DWORD required = 0;
      SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, nullptr, 0, &required, nullptr);
      if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        continue;
      }
      std::vector<BYTE> buffer(required, 0);
      auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(buffer.data());
      detail->cbSize = sizeof(*detail);
      if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr, nullptr)) {
        continue;
      }

      const HANDLE candidate = CreateFileW(
        detail->DevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        overlapped ? FILE_FLAG_OVERLAPPED : FILE_ATTRIBUTE_NORMAL,
        nullptr
      );
      if (candidate == INVALID_HANDLE_VALUE) {
        continue;
      }
      HIDD_ATTRIBUTES attributes {};
      attributes.Size = sizeof(attributes);
      PHIDP_PREPARSED_DATA preparsed_data = nullptr;
      HIDP_CAPS capabilities {};
      const bool matches = HidD_GetAttributes(candidate, &attributes) &&
                           attributes.VendorID == vendor_id &&
                           attributes.ProductID == product_id &&
                           attributes.VersionNumber == version_number &&
                           HidD_GetPreparsedData(candidate, &preparsed_data) &&
                           HidP_GetCaps(preparsed_data, &capabilities) == HIDP_STATUS_SUCCESS &&
                           capabilities.UsagePage == HID_USAGE_PAGE_GENERIC &&
                           (capabilities.Usage == HID_USAGE_GENERIC_GAMEPAD ||
                            capabilities.Usage == HID_USAGE_GENERIC_JOYSTICK);
      if (preparsed_data != nullptr) {
        HidD_FreePreparsedData(preparsed_data);
      }
      if (matches) {
        error = ERROR_SUCCESS;
        return candidate;
      }
      CloseHandle(candidate);
    }
  }

  /**
   * @brief Open the single present SYSTEM-only Lumen control interface.
   *
   * @param error Receives the Win32 error when the interface cannot be opened.
   * @return An open device handle, or INVALID_HANDLE_VALUE on failure.
   */
  HANDLE open_control_device(DWORD &error) {
    device_info_set set(SetupDiGetClassDevsW(
      &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
      nullptr,
      nullptr,
      DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
    ));
    if (!set.valid()) {
      error = GetLastError();
      return INVALID_HANDLE_VALUE;
    }
    SP_DEVICE_INTERFACE_DATA interface_data {};
    interface_data.cbSize = sizeof(interface_data);
    if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID, 0, &interface_data)) {
      error = GetLastError();
      return INVALID_HANDLE_VALUE;
    }
    DWORD required = 0;
    SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, nullptr, 0, &required, nullptr);
    if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
      error = GetLastError();
      if (error == ERROR_SUCCESS) {
        error = ERROR_INVALID_DATA;
      }
      return INVALID_HANDLE_VALUE;
    }
    std::vector<BYTE> detail_buffer(required, 0);
    auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(detail_buffer.data());
    detail->cbSize = sizeof(*detail);
    if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr, nullptr)) {
      error = GetLastError();
      return INVALID_HANDLE_VALUE;
    }
    const HANDLE device = CreateFileW(
      detail->DevicePath,
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr
    );
    if (device == INVALID_HANDLE_VALUE) {
      error = GetLastError();
      return INVALID_HANDLE_VALUE;
    }
    error = ERROR_SUCCESS;
    return device;
  }

  /** @brief Return every dynamic-gamepad capability required by Lumen. */
  constexpr std::uint32_t required_gamepad_capabilities() {
    return LUMEN_VHID_GAMEPAD_CAPABILITY_OUTPUT_REPORTS |
           LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS |
           LUMEN_VHID_GAMEPAD_CAPABILITY_OWNER_CLEANUP |
           LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS;
  }

  /** @brief Return the exact non-XInput profile set required by Lumen. */
  constexpr std::uint64_t required_gamepad_profiles() {
    return LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_GENERIC) |
           LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE) |
           LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES) |
           LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE) |
           LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO) |
           LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4);
  }

  /** @brief Query static and dynamic ABI readiness when the SYSTEM-only interface ACL permits it. */
  probe_result query_protocol() {
    probe_result result;
    DWORD open_error = ERROR_SUCCESS;
    const HANDLE device = open_control_device(open_error);
    if (device == INVALID_HANDLE_VALUE) {
      result.error = open_error;
      result.state = open_error == ERROR_NO_MORE_ITEMS ? probe_state::absent :
                     open_error == ERROR_ACCESS_DENIED ? probe_state::inaccessible :
                                                         probe_state::incompatible;
      return result;
    }

    LUMEN_VHID_GET_INFO_RESPONSE response {};
    DWORD returned = 0;
    const bool ok = DeviceIoControl(
                      device,
                      IOCTL_LUMEN_VHID_GET_INFO,
                      nullptr,
                      0,
                      &response,
                      sizeof(response),
                      &returned,
                      nullptr
                    ) != FALSE;
    result.error = ok ? ERROR_SUCCESS : GetLastError();

    if (!ok) {
      CloseHandle(device);
      result.state = result.error == ERROR_ACCESS_DENIED ? probe_state::inaccessible : probe_state::incompatible;
      return result;
    }
    if (returned != sizeof(response) || response.abi_version != LUMEN_VHID_ABI_VERSION || response.ready != 1) {
      CloseHandle(device);
      result.error = ERROR_REVISION_MISMATCH;
      result.state = probe_state::incompatible;
      return result;
    }

    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE gamepad {};
    returned = 0;
    const bool gamepad_ok = DeviceIoControl(
                              device,
                              IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES,
                              nullptr,
                              0,
                              &gamepad,
                              sizeof(gamepad),
                              &returned,
                              nullptr
                            ) != FALSE;
    result.error = gamepad_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    const auto required_profiles = required_gamepad_profiles();
    if (!gamepad_ok ||
        returned != sizeof(gamepad) ||
        gamepad.version != LUMEN_VHID_GAMEPAD_ABI_VERSION ||
        gamepad.size != sizeof(gamepad) ||
        gamepad.base_abi_version != LUMEN_VHID_ABI_VERSION ||
        (gamepad.capability_flags & required_gamepad_capabilities()) != required_gamepad_capabilities() ||
        (gamepad.supported_profiles & required_profiles) != required_profiles ||
        (gamepad.supported_profiles &
         LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED)) != 0 ||
        gamepad.max_devices == 0 ||
        gamepad.max_devices > LUMEN_VHID_MAX_GAMEPADS ||
        gamepad.active_devices > gamepad.max_devices ||
        gamepad.max_input_report_size == 0 ||
        gamepad.max_output_report_size == 0 ||
        gamepad.max_input_report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
        gamepad.max_output_report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE) {
      if (result.error == ERROR_SUCCESS) {
        result.error = ERROR_REVISION_MISMATCH;
      }
      result.state = probe_state::incompatible;
      return result;
    }
    result.state = probe_state::compatible;
    result.abi_version = response.abi_version;
    result.gamepad_abi_version = gamepad.version;
    result.gamepad_capability_flags = gamepad.capability_flags;
    result.supported_gamepad_profiles = gamepad.supported_profiles;
    result.max_gamepads = gamepad.max_devices;
    result.active_gamepads = gamepad.active_devices;
    return result;
  }

  /** Read a bounded driver INF into memory. */
  bool read_file(const std::wstring &path, std::vector<BYTE> &bytes, DWORD &error) {
    HANDLE file = CreateFileW(
      path.c_str(),
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
      error = GetLastError();
      return false;
    }

    LARGE_INTEGER size {};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024) {
      error = GetLastError();
      if (error == ERROR_SUCCESS) {
        error = ERROR_FILE_TOO_LARGE;
      }
      CloseHandle(file);
      return false;
    }

    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = bytes.empty() || ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (!ok || static_cast<size_t>(read) != bytes.size()) {
      if (error == ERROR_SUCCESS) {
        error = ERROR_READ_FAULT;
      }
      return false;
    }
    return true;
  }

  /** Find one case-insensitive ASCII token in ANSI/UTF-8 or UTF-16LE bytes. */
  bool contains_inf_token(const std::vector<BYTE> &source, std::string_view token) {
    std::vector<BYTE> lower(source);
    for (BYTE &byte : lower) {
      if (byte >= 'A' && byte <= 'Z') {
        byte = static_cast<BYTE>(byte - 'A' + 'a');
      }
    }

    std::string narrow(token);
    std::transform(narrow.begin(), narrow.end(), narrow.begin(), [](unsigned char ch) {
      return static_cast<char>(std::tolower(ch));
    });
    if (std::search(lower.begin(), lower.end(), narrow.begin(), narrow.end()) != lower.end()) {
      return true;
    }

    std::vector<BYTE> utf16;
    utf16.reserve(narrow.size() * 2);
    for (const char ch : narrow) {
      utf16.push_back(static_cast<BYTE>(ch));
      utf16.push_back(0);
    }
    return std::search(lower.begin(), lower.end(), utf16.begin(), utf16.end()) != lower.end();
  }

  /** Validate the exact current or 0.0.7 Lumen driver-package identity. */
  std::optional<package_generation> lumen_inf_generation(const std::wstring &path, DWORD &error) {
    std::vector<BYTE> bytes;
    if (!read_file(path, bytes, error) ||
        !contains_inf_token(bytes, LUMEN_VHID_ROOT_HARDWARE_ID_A) ||
        !contains_inf_token(bytes, "LumenProvider = \"simonfalke\"") ||
        !contains_inf_token(bytes, "UmdfService = \"LumenVirtualHid\"")) {
      return std::nullopt;
    }
    if (contains_inf_token(bytes, "{5c4c3332-344d-483c-8739-259e934c9cc8}")) {
      return package_generation::current;
    }
    if (contains_inf_token(bytes, "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}")) {
      return package_generation::legacy_007;
    }
    return std::nullopt;
  }

  /** Return whether an INF has either exact supported Lumen package identity. */
  bool inf_has_lumen_identity(const std::wstring &path, DWORD &error) {
    return lumen_inf_generation(path, error).has_value();
  }

  /** Resolve a command-line path without requiring it to exist yet. */
  std::optional<std::wstring> absolute_path(const wchar_t *path, DWORD &error) {
    const DWORD required = GetFullPathNameW(path, 0, nullptr, nullptr);
    if (required == 0) {
      error = GetLastError();
      return std::nullopt;
    }

    std::wstring result(required, L'\0');
    const DWORD written = GetFullPathNameW(path, required, result.data(), nullptr);
    if (written == 0 || written >= required) {
      error = GetLastError();
      return std::nullopt;
    }
    result.resize(written);
    error = ERROR_SUCCESS;
    return result;
  }

  /** Remove one newly-created exact node with the documented NewDev API. */
  bool remove_device(HDEVINFO set, SP_DEVINFO_DATA &device, bool &reboot_required, DWORD &error) {
    module_handle newdev(LoadLibraryExW(L"newdev.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
    if (newdev.get() == nullptr) {
      error = GetLastError();
      return false;
    }
    const auto uninstall_device = resolve_function<uninstall_device_fn>(newdev.get(), "DiUninstallDevice");
    if (uninstall_device == nullptr) {
      error = ERROR_PROC_NOT_FOUND;
      return false;
    }
    BOOL reboot = FALSE;
    if (!uninstall_device(nullptr, set, &device, 0, &reboot)) {
      error = GetLastError();
      return false;
    }
    reboot_required = reboot_required || reboot != FALSE;
    error = ERROR_SUCCESS;
    return true;
  }

  /** Create and register the root-enumerated device before binding its driver. */
  bool create_root_device(
    const GUID &class_guid,
    const wchar_t *class_name,
    device_info_set &set,
    SP_DEVINFO_DATA &device,
    DWORD &error
  ) {
    set = device_info_set(SetupDiCreateDeviceInfoList(&class_guid, nullptr));
    if (!set.valid()) {
      error = GetLastError();
      return false;
    }

    device = {};
    device.cbSize = sizeof(device);
    if (!SetupDiCreateDeviceInfoW(
          set.get(),
          class_name,
          &class_guid,
          kDeviceDescription,
          nullptr,
          DICD_GENERATE_ID,
          &device
        )) {
      error = GetLastError();
      return false;
    }

    constexpr wchar_t hardware_ids[] = LUMEN_VHID_ROOT_HARDWARE_ID_W L"\0";
    if (!SetupDiSetDeviceRegistryPropertyW(
          set.get(),
          &device,
          SPDRP_HARDWAREID,
          reinterpret_cast<const BYTE *>(hardware_ids),
          sizeof(hardware_ids)
        ) ||
        !SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set.get(), &device)) {
      error = GetLastError();
      return false;
    }
    error = ERROR_SUCCESS;
    return true;
  }

  /** Locate OEM driver-store INFs containing the exact Lumen hardware ID. */
  std::vector<std::wstring> find_driver_packages(DWORD &error) {
    std::vector<std::wstring> result;
    std::array<wchar_t, MAX_PATH> windows_directory {};
    const UINT length = GetWindowsDirectoryW(windows_directory.data(), static_cast<UINT>(windows_directory.size()));
    if (length == 0 || static_cast<size_t>(length) >= windows_directory.size()) {
      error = GetLastError();
      return result;
    }

    const std::wstring inf_directory = std::wstring(windows_directory.data(), length) + L"\\INF\\";
    WIN32_FIND_DATAW data {};
    HANDLE find = FindFirstFileW((inf_directory + L"oem*.inf").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
      error = GetLastError();
      if (error == ERROR_FILE_NOT_FOUND) {
        error = ERROR_SUCCESS;
      }
      return result;
    }

    do {
      const std::wstring path = inf_directory + data.cFileName;
      DWORD read_error = ERROR_SUCCESS;
      if (inf_has_lumen_identity(path, read_error)) {
        result.push_back(path);
      }
    } while (FindNextFileW(find, &data));

    const DWORD find_error = GetLastError();
    FindClose(find);
    error = find_error == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : find_error;
    return result;
  }

  /** Convert a probe state to its stable JSON label. */
  const wchar_t *probe_state_name(probe_state state) {
    switch (state) {
      case probe_state::compatible:
        return L"compatible";
      case probe_state::absent:
        return L"absent";
      case probe_state::inaccessible:
        return L"inaccessible";
      case probe_state::incompatible:
        return L"incompatible";
    }
    return L"incompatible";
  }

  /** Convert a probe result to its stable public exit code. */
  exit_code probe_exit_code(probe_state state) {
    switch (state) {
      case probe_state::compatible:
        return exit_code::success;
      case probe_state::absent:
        return exit_code::absent;
      case probe_state::inaccessible:
        return exit_code::inaccessible;
      case probe_state::incompatible:
        return exit_code::incompatible;
    }
    return exit_code::incompatible;
  }

  /** Report whether the root topology is installed, absent, or unhealthy. */
  int status(bool json) {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      const exit_code code = error_code(exit_code::incompatible, devices.error);
      if (json) {
        std::wcout << L"{\"state\":\"unhealthy\",\"reason\":\"enumeration-failed\",\"win32\":"
                   << devices.error << L"}\n";
        return static_cast<int>(code);
      }
      return fail(code, L"enumerate-devices", devices.error);
    }
    if (devices.devices.empty()) {
      if (json) {
        std::wcout << L"{\"state\":\"absent\",\"hardwareId\":\""
                   << json_escape(LUMEN_VHID_ROOT_HARDWARE_ID_W) << L"\"}\n";
      } else {
        std::wcout << L"state=absent hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\"\n";
      }
      return static_cast<int>(exit_code::absent);
    }

    bool started = false;
    bool children_started = false;
    ULONG problem = 0;
    ULONG device_status = 0;
    CONFIGRET child_error = CR_SUCCESS;
    for (const SP_DEVINFO_DATA &device : devices.devices) {
      if (CM_Get_DevNode_Status(&device_status, &problem, device.DevInst, 0) == CR_SUCCESS &&
          (device_status & DN_STARTED) != 0) {
        pnp_diagnostic diagnostic;
        started = true;
        children_started = descendants_started(device.DevInst, diagnostic);
        if (!children_started) {
          problem = diagnostic.problem;
          child_error = diagnostic.error;
        }
        break;
      }
    }

    const collection_inventory collections = find_present_collections();
    if (collections.error != ERROR_SUCCESS) {
      const exit_code code = error_code(exit_code::incompatible, collections.error);
      if (json) {
        std::wcout << L"{\"state\":\"unhealthy\",\"reason\":\"interface-enumeration-failed\",\"win32\":"
                   << collections.error << L"}\n";
        return static_cast<int>(code);
      }
      return fail(code, L"enumerate-interface", collections.error);
    }
    if (!started || !children_started || !collections.healthy()) {
      const wchar_t *reason = !started          ? L"device-not-started" :
                              !children_started ? L"child-not-started" :
                                                  L"collection-not-started";
      if (json) {
        std::wcout << L"{\"state\":\"unhealthy\",\"reason\":\"" << reason
                   << L"\",\"rootDevices\":" << devices.devices.size()
                   << L",\"keyboards\":" << collections.keyboard_count
                   << L",\"mice\":" << collections.mouse_count
                   << L",\"consumers\":" << collections.consumer_count
                   << L",\"cmStatus\":" << device_status << L",\"cmProblem\":" << problem << L"}\n";
      } else {
        std::wcout << L"state=unhealthy reason=" << reason
                   << L" hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\""
                   << L" cm_status=" << device_status << L" cm_problem=" << problem
                   << L" cm_error=" << child_error
                   << L" keyboards=" << collections.keyboard_count
                   << L" mice=" << collections.mouse_count
                   << L" consumers=" << collections.consumer_count << L'\n';
      }
      return static_cast<int>(exit_code::incompatible);
    }
    const probe_result control = query_protocol();
    if (json) {
      std::wcout << L"{\"state\":\"installed\",\"rootDevices\":" << devices.devices.size()
                 << L",\"keyboards\":" << collections.keyboard_count
                 << L",\"mice\":" << collections.mouse_count
                 << L",\"consumers\":" << collections.consumer_count
                 << L",\"control\":\"" << probe_state_name(control.state) << L"\"";
      if (control.state == probe_state::compatible) {
        std::wcout << L",\"protocolGeneration\":" << kProtocolGeneration
                   << L",\"abiVersion\":" << control.abi_version
                   << L",\"gamepadAbiVersion\":" << control.gamepad_abi_version
                   << L",\"gamepadCapabilityFlags\":" << control.gamepad_capability_flags
                   << L",\"supportedGamepadProfiles\":" << control.supported_gamepad_profiles
                   << L",\"maxGamepads\":" << control.max_gamepads
                   << L",\"activeGamepads\":" << control.active_gamepads;
      }
      if (control.error != ERROR_SUCCESS) {
        std::wcout << L",\"controlWin32\":" << control.error;
      }
      std::wcout << L"}\n";
    } else {
      std::wcout << L"state=installed hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W
                 << L"\" keyboards=" << collections.keyboard_count
                 << L" mice=" << collections.mouse_count
                 << L" consumers=" << collections.consumer_count
                 << L" control=" << probe_state_name(control.state);
      if (control.state == probe_state::compatible) {
        std::wcout << L" protocol_generation=" << kProtocolGeneration
                   << L" abi=" << control.abi_version
                   << L" gamepad_abi=" << control.gamepad_abi_version
                   << L" gamepad_capabilities=" << control.gamepad_capability_flags
                   << L" supported_gamepad_profiles=" << control.supported_gamepad_profiles
                   << L" max_gamepads=" << control.max_gamepads
                   << L" active_gamepads=" << control.active_gamepads;
      }
      if (control.error != ERROR_SUCCESS) {
        std::wcout << L" control_win32=" << control.error;
      }
      std::wcout << L'\n';
    }
    return static_cast<int>(exit_code::success);
  }

  /** Probe the SYSTEM-only control interface using Sunshine's exact GET_INFO ABI. */
  int probe(bool json) {
    const probe_result result = query_protocol();

    if (json) {
      std::wcout << L"{\"state\":\"" << probe_state_name(result.state) << L"\"";
      if (result.state == probe_state::compatible) {
        std::wcout << L",\"protocolGeneration\":" << kProtocolGeneration
                   << L",\"abiVersion\":" << result.abi_version
                   << L",\"gamepadAbiVersion\":" << result.gamepad_abi_version
                   << L",\"gamepadCapabilityFlags\":" << result.gamepad_capability_flags
                   << L",\"supportedGamepadProfiles\":" << result.supported_gamepad_profiles
                   << L",\"maxGamepads\":" << result.max_gamepads
                   << L",\"activeGamepads\":" << result.active_gamepads;
      }
      if (result.error != ERROR_SUCCESS) {
        std::wcout << L",\"win32\":" << result.error;
      }
      std::wcout << L"}\n";
    } else {
      std::wcout << L"state=" << probe_state_name(result.state);
      if (result.state == probe_state::compatible) {
        std::wcout << L" protocol_generation=" << kProtocolGeneration
                   << L" abi=" << result.abi_version
                   << L" gamepad_abi=" << result.gamepad_abi_version
                   << L" gamepad_capabilities=" << result.gamepad_capability_flags
                   << L" supported_gamepad_profiles=" << result.supported_gamepad_profiles
                   << L" max_gamepads=" << result.max_gamepads
                   << L" active_gamepads=" << result.active_gamepads;
      }
      if (result.error != ERROR_SUCCESS) {
        std::wcout << L" win32=" << result.error;
      }
      std::wcout << L'\n';
    }
    return static_cast<int>(probe_exit_code(result.state));
  }

  /**
   * @brief Determine whether the helper is running as the LocalSystem account.
   *
   * @param error Receives a Win32 query error, or ERROR_SUCCESS for a definitive result.
   * @return true only when the process token user is the well-known LocalSystem SID.
   */
  bool running_as_local_system(DWORD &error) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
      error = GetLastError();
      return false;
    }
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      error = GetLastError();
      CloseHandle(token);
      return false;
    }
    std::vector<BYTE> token_buffer(required, 0);
    if (!GetTokenInformation(token, TokenUser, token_buffer.data(), required, &required)) {
      error = GetLastError();
      CloseHandle(token);
      return false;
    }
    CloseHandle(token);

    std::array<BYTE, SECURITY_MAX_SID_SIZE> system_sid {};
    DWORD system_sid_size = static_cast<DWORD>(system_sid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_sid.data(), &system_sid_size)) {
      error = GetLastError();
      return false;
    }
    const auto *token_user = reinterpret_cast<const TOKEN_USER *>(token_buffer.data());
    error = ERROR_SUCCESS;
    return EqualSid(token_user->User.Sid, system_sid.data()) != FALSE;
  }

  /**
   * @brief Create one dynamic gamepad profile and validate the complete response.
   *
   * @param device Open owning control-interface handle.
   * @param client_device_id Stable smoke-test device identifier.
   * @param profile Built-in dynamic-gamepad profile.
   * @param created Receives the authenticated gamepad response.
   * @param error Receives a Win32 or response-validation error.
   * @return true only when creation and response validation both succeed.
   */
  bool create_gamepad(
    HANDLE device,
    std::uint64_t client_device_id,
    std::uint32_t profile,
    LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &created,
    DWORD &error
  ) {
    LUMEN_VHID_GAMEPAD_CREATE_REQUEST request {};
    request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    request.size = sizeof(request);
    request.client_device_id = client_device_id;
    request.profile = profile;
    DWORD returned = 0;
    const bool ok = DeviceIoControl(
                      device,
                      IOCTL_LUMEN_VHID_GAMEPAD_CREATE,
                      &request,
                      sizeof(request),
                      &created,
                      sizeof(created),
                      &returned,
                      nullptr
                    ) != FALSE;
    error = ok ? ERROR_SUCCESS : GetLastError();
    const bool token_present = std::any_of(
      std::begin(created.handle.session_token),
      std::end(created.handle.session_token),
      [](std::uint8_t value) {
        return value != 0;
      }
    );
    const bool valid = ok &&
                       returned == sizeof(created) &&
                       created.version == LUMEN_VHID_GAMEPAD_ABI_VERSION &&
                       created.size == sizeof(created) &&
                       created.handle.device_id != 0 &&
                       created.handle.generation != 0 &&
                       token_present &&
                       created.profile == profile &&
                       created.input_report_size != 0 &&
                       created.input_report_size <= LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
    if (!valid && error == ERROR_SUCCESS) {
      error = ERROR_INVALID_DATA;
    }
    return valid;
  }

  /**
   * @brief Submit one exact neutral input report for a created gamepad.
   *
   * @param device Open owning control-interface handle.
   * @param created Created gamepad metadata.
   * @param error Receives the Win32 result.
   * @return `true` when the driver accepts the neutral report.
   */
  bool submit_neutral_gamepad(
    HANDLE device,
    const LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &created,
    DWORD &error
  ) {
    LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST request {};
    request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    request.size = sizeof(request);
    request.handle = created.handle;
    request.report_size = created.input_report_size;
    if (created.input_report_id != 0) {
      request.report[0] = created.input_report_id;
    }
    DWORD returned = 0;
    const bool ok = DeviceIoControl(
                      device,
                      IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT,
                      &request,
                      sizeof(request),
                      nullptr,
                      0,
                      &returned,
                      nullptr
                    ) != FALSE;
    error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
  }

  /**
   * @brief Wait for an exact number of present collections for one created identity.
   *
   * @param created Created gamepad identity.
   * @param expected Expected number of matching HID collections.
   * @param error Receives an enumeration or timeout error.
   * @return `true` when the collection count reaches the expected value.
   */
  bool wait_for_gamepad_count(
    const LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &created,
    unsigned expected,
    DWORD &error
  ) {
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      const auto count = count_gamepad_collections(
        created.vendor_id,
        created.product_id,
        created.version_number,
        error
      );
      if (error != ERROR_SUCCESS) {
        return false;
      }
      if (count == expected) {
        return true;
      }
      Sleep(100);
    }
    error = ERROR_NOT_READY;
    return false;
  }

  /**
   * @brief Round-trip Generic input and PID output through the enumerated HID collection.
   *
   * @param device Open owning control-interface handle.
   * @param created Created Generic PID gamepad metadata.
   * @param operation Receives the exact failed I/O stage.
   * @param error Receives the first Win32 or validation error.
   * @return `true` when both HID directions return the exact distinctive reports.
   */
  bool round_trip_generic_io(
    HANDLE device,
    const LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &created,
    const wchar_t *&operation,
    DWORD &error
  ) {
    operation = L"open-generic-input";
    HANDLE hid = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      hid = open_gamepad_collection(
        created.vendor_id,
        created.product_id,
        created.version_number,
        true,
        error
      );
      if (hid != INVALID_HANDLE_VALUE) {
        break;
      }
      if (error != ERROR_FILE_NOT_FOUND) {
        return false;
      }
      Sleep(100);
    }
    if (hid == INVALID_HANDLE_VALUE) {
      error = ERROR_NOT_READY;
      return false;
    }

    operation = L"validate-generic-metadata";
    if (created.input_report_size != 9u || created.input_report_id != 0x01u) {
      CloseHandle(hid);
      error = ERROR_INVALID_DATA;
      return false;
    }
    std::array<std::uint8_t, 9> input_report {
      0x01u,
      0x01u,
      0x00u,
      0x20u,
      0xe0u,
      0x90u,
      0x70u,
      0xffu,
      0xffu,
    };
    std::array<std::uint8_t, 9> observed_input {};
    OVERLAPPED input_read {};
    operation = L"create-generic-input-event";
    input_read.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (input_read.hEvent == nullptr) {
      error = GetLastError();
      CloseHandle(hid);
      return false;
    }
    DWORD input_bytes = 0;
    operation = L"start-generic-input-read";
    const bool read_started = ReadFile(
                                hid,
                                observed_input.data(),
                                static_cast<DWORD>(observed_input.size()),
                                &input_bytes,
                                &input_read
                              ) != FALSE;
    error = read_started ? ERROR_SUCCESS : GetLastError();
    if (!read_started && error != ERROR_IO_PENDING) {
      CloseHandle(input_read.hEvent);
      CloseHandle(hid);
      return false;
    }

    LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST submit {};
    submit.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    submit.size = sizeof(submit);
    submit.handle = created.handle;
    submit.report_size = static_cast<std::uint32_t>(input_report.size());
    std::copy(input_report.begin(), input_report.end(), submit.report);
    DWORD returned = 0;
    operation = L"submit-distinctive-generic-input";
    if (!DeviceIoControl(
          device,
          IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT,
          &submit,
          sizeof(submit),
          nullptr,
          0,
          &returned,
          nullptr
        )) {
      error = GetLastError();
      CancelIoEx(hid, &input_read);
      DWORD ignored = 0;
      static_cast<void>(GetOverlappedResult(hid, &input_read, &ignored, TRUE));
      CloseHandle(input_read.hEvent);
      CloseHandle(hid);
      return false;
    }
    operation = L"receive-distinctive-generic-input";
    const auto wait = WaitForSingleObject(input_read.hEvent, 5000u);
    const bool input_ok = wait == WAIT_OBJECT_0 &&
                          GetOverlappedResult(hid, &input_read, &input_bytes, FALSE) != FALSE &&
                          input_bytes == input_report.size() &&
                          observed_input == input_report;
    if (!input_ok) {
      error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
      CancelIoEx(hid, &input_read);
      DWORD ignored = 0;
      static_cast<void>(GetOverlappedResult(hid, &input_read, &ignored, TRUE));
      CloseHandle(input_read.hEvent);
      CloseHandle(hid);
      return false;
    }
    CloseHandle(input_read.hEvent);
    CloseHandle(hid);
    operation = L"open-generic-output";
    hid = open_gamepad_collection(
      created.vendor_id,
      created.product_id,
      created.version_number,
      false,
      error
    );
    if (hid == INVALID_HANDLE_VALUE) {
      return false;
    }

    LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST read_request {};
    read_request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    read_request.size = sizeof(read_request);
    read_request.handle = created.handle;
    operation = L"drain-generic-output";
    for (;;) {
      LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE pending {};
      returned = 0;
      const bool read_ok = DeviceIoControl(
                             device,
                             IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT,
                             &read_request,
                             sizeof(read_request),
                             &pending,
                             sizeof(pending),
                             &returned,
                             nullptr
                           ) != FALSE;
      error = read_ok ? ERROR_SUCCESS : GetLastError();
      if (!read_ok && error == ERROR_NO_MORE_ITEMS) {
        break;
      }
      const bool valid = read_ok &&
                         returned == sizeof(pending) &&
                         pending.version == LUMEN_VHID_GAMEPAD_ABI_VERSION &&
                         pending.size == sizeof(pending) &&
                         pending.handle.device_id == created.handle.device_id &&
                         pending.handle.generation == created.handle.generation &&
                         std::equal(
                           std::begin(pending.handle.session_token),
                           std::end(pending.handle.session_token),
                           std::begin(created.handle.session_token)
                         ) &&
                         pending.report_size != 0 &&
                         pending.report_size <= LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
      if (!valid) {
        if (error == ERROR_SUCCESS) {
          error = ERROR_INVALID_DATA;
        }
        CloseHandle(hid);
        return false;
      }
    }

    std::array<std::uint8_t, 22> output_report {};
    output_report[0] = 0x1du;  // Generic PID Device Gain.
    output_report[1] = 0x7fu;
    DWORD output_bytes = 0;
    operation = L"write-generic-pid-output";
    const bool write_ok = WriteFile(
                            hid,
                            output_report.data(),
                            static_cast<DWORD>(output_report.size()),
                            &output_bytes,
                            nullptr
                          ) != FALSE &&
                          output_bytes == output_report.size();
    error = write_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(hid);
    if (!write_ok) {
      return false;
    }

    operation = L"read-generic-pid-output";
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE response {};
      returned = 0;
      const bool read_ok = DeviceIoControl(
                             device,
                             IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT,
                             &read_request,
                             sizeof(read_request),
                             &response,
                             sizeof(response),
                             &returned,
                             nullptr
                           ) != FALSE;
      error = read_ok ? ERROR_SUCCESS : GetLastError();
      if (!read_ok && error == ERROR_NO_MORE_ITEMS) {
        Sleep(10);
        continue;
      }
      const bool well_formed = read_ok &&
                               returned == sizeof(response) &&
                               response.version == LUMEN_VHID_GAMEPAD_ABI_VERSION &&
                               response.size == sizeof(response) &&
                               response.handle.device_id == created.handle.device_id &&
                               response.handle.generation == created.handle.generation &&
                               std::equal(
                                 std::begin(response.handle.session_token),
                                 std::end(response.handle.session_token),
                                 std::begin(created.handle.session_token)
                               ) &&
                               response.report_size != 0 &&
                               response.report_size <= LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
      if (!well_formed) {
        if (error == ERROR_SUCCESS) {
          error = ERROR_INVALID_DATA;
        }
        return false;
      }
      const bool exact_pid_gain = response.report_size >= 2u &&
                                  response.report_size <= output_report.size() &&
                                  response.report[0] == output_report[0] &&
                                  response.report[1] == output_report[1] &&
                                  std::all_of(
                                    response.report + 2,
                                    response.report + response.report_size,
                                    [](std::uint8_t value) {
                                      return value == 0;
                                    }
                                  );
      if (exact_pid_gain) {
        return true;
      }
    }
    error = ERROR_TIMEOUT;
    return false;
  }

  /**
   * @brief Verify that one authenticated request is rejected.
   *
   * @param device Control-interface handle used for the negative request.
   * @param control_code IOCTL expected to reject the request.
   * @param request Request bytes.
   * @param request_size Request byte count.
   * @param error Receives ERROR_SUCCESS after an access-denied rejection, the
   * unexpected rejection error, or ERROR_INVALID_ACCESS after acceptance.
   * @return true only when DeviceIoControl rejects the request with ERROR_ACCESS_DENIED.
   */
  bool authenticated_request_rejected(
    HANDLE device,
    DWORD control_code,
    void *request,
    DWORD request_size,
    DWORD &error
  ) {
    DWORD returned = 0;
    if (DeviceIoControl(
          device,
          control_code,
          request,
          request_size,
          nullptr,
          0,
          &returned,
          nullptr
        )) {
      error = ERROR_INVALID_ACCESS;
      return false;
    }
    error = GetLastError();
    if (error != ERROR_ACCESS_DENIED) {
      return false;
    }
    error = ERROR_SUCCESS;
    return true;
  }

  /**
   * @brief Destroy one authenticated dynamic gamepad.
   *
   * @param device Open Lumen control-interface handle.
   * @param handle Exact gamepad identity and session token.
   * @param error Receives the Win32 result.
   * @return true when the driver accepted the destroy request.
   */
  bool destroy_gamepad(HANDLE device, const LUMEN_VHID_GAMEPAD_HANDLE &handle, DWORD &error) {
    LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST request {};
    request.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    request.size = sizeof(request);
    request.handle = handle;
    DWORD returned = 0;
    const bool ok = DeviceIoControl(
                      device,
                      IOCTL_LUMEN_VHID_GAMEPAD_DESTROY,
                      &request,
                      sizeof(request),
                      nullptr,
                      0,
                      &returned,
                      nullptr
                    ) != FALSE;
    error = ok ? ERROR_SUCCESS : GetLastError();
    return ok;
  }

  /**
   * @brief Report one dynamic-gamepad smoke failure in the requested format.
   *
   * @param json Whether to emit JSON.
   * @param operation Stable operation that failed.
   * @param error Win32 failure code.
   * @return The stable mutation-failed process exit code.
   */
  int report_gamepad_smoke_failure(bool json, const wchar_t *operation, DWORD error) {
    if (json) {
      std::wcout << L"{\"state\":\"failed\",\"operation\":\"" << operation
                 << L"\",\"win32\":" << error << L"}\n";
    } else {
      std::wcout << L"state=failed operation=" << operation << L" win32=" << error << L'\n';
    }
    return static_cast<int>(exit_code::mutation_failed);
  }

  /**
   * @brief Validate the retained Xbox 360 path through ViGEmBus.
   *
   * @param json Whether to emit JSON.
   * @return A stable helper exit code.
   */
  int smoke_vigem(bool json) {
    PVIGEM_CLIENT client = nullptr;
    VIGEM_ERROR status = VIGEM_ERROR_BUS_NOT_FOUND;
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      auto *candidate = vigem_alloc();
      if (candidate == nullptr) {
        return report_gamepad_smoke_failure(json, L"allocate-vigem-client", ERROR_NOT_ENOUGH_MEMORY);
      }
      status = vigem_connect(candidate);
      if (VIGEM_SUCCESS(status)) {
        client = candidate;
        break;
      }
      vigem_free(candidate);
      Sleep(100);
    }
    if (client == nullptr) {
      return report_gamepad_smoke_failure(json, L"connect-vigem", static_cast<DWORD>(status));
    }
    auto *target = vigem_target_x360_alloc();
    if (target == nullptr) {
      vigem_disconnect(client);
      vigem_free(client);
      return report_gamepad_smoke_failure(json, L"allocate-x360", ERROR_NOT_ENOUGH_MEMORY);
    }
    status = vigem_target_add(client, target);
    if (!VIGEM_SUCCESS(status)) {
      vigem_target_free(target);
      vigem_disconnect(client);
      vigem_free(client);
      return report_gamepad_smoke_failure(json, L"attach-x360", static_cast<DWORD>(status));
    }

    XUSB_REPORT report {};
    XUSB_REPORT_INIT(&report);
    report.wButtons = XUSB_GAMEPAD_A | XUSB_GAMEPAD_Y;
    report.bLeftTrigger = 37u;
    report.bRightTrigger = 211u;
    report.sThumbLX = 1234;
    report.sThumbLY = -2345;
    report.sThumbRX = 4567;
    report.sThumbRY = -5678;
    status = vigem_target_x360_update(client, target, report);
    ULONG user_index = XUSER_MAX_COUNT;
    VIGEM_ERROR user_index_status = VIGEM_ERROR_TARGET_UNINITIALIZED;
    bool xinput_api_visible = false;
    if (VIGEM_SUCCESS(status)) {
      for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
        user_index_status = vigem_target_x360_get_user_index(client, target, &user_index);
        if (VIGEM_SUCCESS(user_index_status)) {
          break;
        }
        Sleep(100);
      }
      if (VIGEM_SUCCESS(user_index_status) && user_index < XUSER_MAX_COUNT) {
        for (int attempt = 0; attempt < kXinputVisibilityWaitAttempts; ++attempt) {
          XINPUT_STATE state {};
          if (XInputGetState(user_index, &state) == ERROR_SUCCESS &&
              state.Gamepad.wButtons == report.wButtons &&
              state.Gamepad.bLeftTrigger == report.bLeftTrigger &&
              state.Gamepad.bRightTrigger == report.bRightTrigger &&
              state.Gamepad.sThumbLX == report.sThumbLX &&
              state.Gamepad.sThumbLY == report.sThumbLY &&
              state.Gamepad.sThumbRX == report.sThumbRX &&
              state.Gamepad.sThumbRY == report.sThumbRY) {
            xinput_api_visible = true;
            break;
          }
          Sleep(100);
        }
      }
    }

    if (vigem_target_is_attached(target)) {
      static_cast<void>(vigem_target_remove(client, target));
    }
    vigem_target_free(target);
    vigem_disconnect(client);
    vigem_free(client);
    if (!VIGEM_SUCCESS(status)) {
      return report_gamepad_smoke_failure(json, L"submit-x360", static_cast<DWORD>(status));
    }
    if (!VIGEM_SUCCESS(user_index_status)) {
      return report_gamepad_smoke_failure(json, L"verify-xusb-user-index", static_cast<DWORD>(user_index_status));
    }
    if (user_index >= XUSER_MAX_COUNT) {
      return report_gamepad_smoke_failure(json, L"verify-xusb-user-index", ERROR_INVALID_DATA);
    }

    if (json) {
      std::wcout << L"{\"state\":\"passed\",\"backend\":\"vigem\",\"profile\":\"x360\",\"userIndex\":"
                 << user_index << L",\"xinputApiVisible\":" << (xinput_api_visible ? L"true" : L"false") << L"}\n";
    } else {
      std::wcout << L"state=passed backend=vigem profile=x360 user_index=" << user_index
                 << L" xinput_api_visible=" << (xinput_api_visible ? L"true" : L"false") << L'\n';
    }
    return static_cast<int>(exit_code::success);
  }

  /**
   * @brief Exercise the complete SYSTEM-only dynamic-gamepad lifecycle.
   *
   * Creates, enumerates, submits to, and destroys every supported VHF profile.
   * Generic PID must return a distinctive input report through HID and an exact
   * HID output report through the authenticated queue. The smoke also verifies
   * handle and file ownership, owner-file cleanup, the maximum-device bound,
   * and removal of every dynamic HID collection.
   *
   * @param json Whether to emit JSON.
   * @return A stable helper exit code.
   */
  int smoke_gamepad(bool json) {
    DWORD error = ERROR_SUCCESS;
    if (!running_as_local_system(error)) {
      return report_gamepad_smoke_failure(
        json,
        L"require-local-system",
        error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error
      );
    }

    const probe_result before = query_protocol();
    if (before.state != probe_state::compatible) {
      return report_gamepad_smoke_failure(
        json,
        L"query-capabilities",
        before.error == ERROR_SUCCESS ? ERROR_REVISION_MISMATCH : before.error
      );
    }
    if (before.active_gamepads != 0) {
      return report_gamepad_smoke_failure(json, L"require-idle-runtime", ERROR_BUSY);
    }

    const HANDLE device = open_control_device(error);
    if (device == INVALID_HANDLE_VALUE) {
      return report_gamepad_smoke_failure(json, L"open-control-interface", error);
    }

    constexpr std::array<std::uint32_t, 6> profiles {
      LUMEN_VHID_GAMEPAD_PROFILE_GENERIC,
      LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE,
      LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES,
      LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE,
      LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO,
      LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4,
    };
    for (std::size_t index = 0; index < profiles.size(); ++index) {
      LUMEN_VHID_GAMEPAD_CREATE_RESPONSE profile_device {};
      if (!create_gamepad(
            device,
            UINT64_C(0x4c554d5000000000) + index,
            profiles[index],
            profile_device,
            error
          )) {
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"create-profile", error);
      }
      if (!wait_for_gamepad_count(profile_device, 1, error) ||
          !submit_neutral_gamepad(device, profile_device, error)) {
        DWORD ignored = ERROR_SUCCESS;
        destroy_gamepad(device, profile_device.handle, ignored);
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"validate-profile", error);
      }
      if (!destroy_gamepad(device, profile_device.handle, error) ||
          !wait_for_gamepad_count(profile_device, 0, error)) {
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"destroy-profile", error);
      }
    }

    std::vector<LUMEN_VHID_GAMEPAD_HANDLE> handles;
    handles.reserve(LUMEN_VHID_MAX_GAMEPADS);
    const auto cleanup = [&]() {
      DWORD ignored = ERROR_SUCCESS;
      for (auto handle = handles.rbegin(); handle != handles.rend(); ++handle) {
        destroy_gamepad(device, *handle, ignored);
      }
      handles.clear();
    };

    LUMEN_VHID_GAMEPAD_CREATE_RESPONSE created {};
    if (!create_gamepad(
          device,
          UINT64_C(0x4c554d454e534d4b),
          LUMEN_VHID_GAMEPAD_PROFILE_GENERIC,
          created,
          error
        )) {
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"create-gamepad", error);
    }
    handles.push_back(created.handle);

    bool enumerated = false;
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      const unsigned gamepad_count = count_gamepad_collections(
        created.vendor_id,
        created.product_id,
        created.version_number,
        error
      );
      if (error != ERROR_SUCCESS) {
        cleanup();
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"enumerate-gamepad", error);
      }
      if (gamepad_count == 1) {
        enumerated = true;
        break;
      }
      Sleep(100);
    }
    if (!enumerated) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"enumerate-gamepad", ERROR_NOT_READY);
    }

    LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST submit {};
    submit.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    submit.size = sizeof(submit);
    submit.handle = created.handle;
    submit.report_size = created.input_report_size;
    if (created.input_report_id != 0) {
      submit.report[0] = created.input_report_id;
    }

    auto invalid_token = submit;
    invalid_token.handle.session_token[0] ^= 0xff;
    if (!authenticated_request_rejected(
          device,
          IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT,
          &invalid_token,
          sizeof(invalid_token),
          error
        )) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"reject-mutated-token", error);
    }

    auto invalid_device = submit;
    ++invalid_device.handle.device_id;
    if (!authenticated_request_rejected(
          device,
          IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT,
          &invalid_device,
          sizeof(invalid_device),
          error
        )) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"reject-mutated-device", error);
    }

    const HANDLE second_device = open_control_device(error);
    if (second_device == INVALID_HANDLE_VALUE) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"open-second-control-interface", error);
    }
    if (!authenticated_request_rejected(
          second_device,
          IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT,
          &submit,
          sizeof(submit),
          error
        )) {
      CloseHandle(second_device);
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"reject-cross-file-submit", error);
    }
    LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST cross_file_destroy {};
    cross_file_destroy.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    cross_file_destroy.size = sizeof(cross_file_destroy);
    cross_file_destroy.handle = created.handle;
    if (!authenticated_request_rejected(
          second_device,
          IOCTL_LUMEN_VHID_GAMEPAD_DESTROY,
          &cross_file_destroy,
          sizeof(cross_file_destroy),
          error
        )) {
      CloseHandle(second_device);
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"reject-cross-file-destroy", error);
    }

    LUMEN_VHID_GAMEPAD_CREATE_RESPONSE cleanup_probe {};
    if (!create_gamepad(
          second_device,
          UINT64_C(0x4c554d454e434c4e),
          LUMEN_VHID_GAMEPAD_PROFILE_GENERIC,
          cleanup_probe,
          error
        )) {
      CloseHandle(second_device);
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"create-cleanup-probe", error);
    }
    CloseHandle(second_device);
    bool owner_cleanup = false;
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      const probe_result cleanup_state = query_protocol();
      const unsigned gamepad_count = count_gamepad_collections(
        created.vendor_id,
        created.product_id,
        created.version_number,
        error
      );
      if (error != ERROR_SUCCESS) {
        cleanup();
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"verify-owner-cleanup", error);
      }
      if (cleanup_state.state == probe_state::compatible &&
          cleanup_state.active_gamepads == 1 &&
          gamepad_count == 1) {
        owner_cleanup = true;
        break;
      }
      Sleep(100);
    }
    if (!owner_cleanup) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"verify-owner-cleanup", ERROR_NOT_READY);
    }

    const wchar_t *io_operation = L"round-trip-generic-hid";
    if (!round_trip_generic_io(device, created, io_operation, error)) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, io_operation, error);
    }

    for (std::uint32_t index = 1; index < before.max_gamepads; ++index) {
      LUMEN_VHID_GAMEPAD_CREATE_RESPONSE additional {};
      if (!create_gamepad(
            device,
            UINT64_C(0x4c554d454e000000) + index,
            LUMEN_VHID_GAMEPAD_PROFILE_GENERIC,
            additional,
            error
          )) {
        cleanup();
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"fill-gamepad-capacity", error);
      }
      handles.push_back(additional.handle);
    }
    const probe_result at_capacity = query_protocol();
    if (at_capacity.state != probe_state::compatible || at_capacity.active_gamepads != before.max_gamepads) {
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"verify-gamepad-capacity", ERROR_INVALID_DATA);
    }
    LUMEN_VHID_GAMEPAD_CREATE_RESPONSE overflow {};
    if (create_gamepad(
          device,
          UINT64_C(0x4c554d454effffff),
          LUMEN_VHID_GAMEPAD_PROFILE_GENERIC,
          overflow,
          error
        )) {
      handles.push_back(overflow.handle);
      cleanup();
      CloseHandle(device);
      return report_gamepad_smoke_failure(json, L"reject-gamepad-overflow", ERROR_INVALID_ACCESS);
    }

    for (auto handle = handles.rbegin(); handle != handles.rend(); ++handle) {
      if (!destroy_gamepad(device, *handle, error)) {
        CloseHandle(device);
        return report_gamepad_smoke_failure(json, L"destroy-gamepad", error);
      }
    }
    handles.clear();
    CloseHandle(device);

    probe_result after;
    for (int attempt = 0; attempt < kGamepadSmokeWaitAttempts; ++attempt) {
      after = query_protocol();
      const unsigned gamepad_count = count_gamepad_collections(
        created.vendor_id,
        created.product_id,
        created.version_number,
        error
      );
      if (error != ERROR_SUCCESS) {
        return report_gamepad_smoke_failure(json, L"verify-gamepad-removed", error);
      }
      if (after.state == probe_state::compatible && after.active_gamepads == 0 && gamepad_count == 0) {
        if (json) {
          std::wcout << L"{\"state\":\"passed\",\"protocolGeneration\":" << kProtocolGeneration
                     << L",\"gamepadAbiVersion\":" << after.gamepad_abi_version
                     << L",\"profile\":\"generic\",\"enumerated\":true"
                     << L",\"tokenRejected\":true,\"deviceRejected\":true,\"crossFileRejected\":true"
                     << L",\"ownerCleanup\":true,\"profilesValidated\":" << profiles.size()
                     << L",\"capacity\":" << before.max_gamepads
                     << L",\"overflowRejected\":true,\"submitted\":true"
                     << L",\"input\":\"received\",\"output\":\"received\""
                     << L",\"destroyed\":true,\"activeGamepads\":" << after.active_gamepads << L"}\n";
        } else {
          std::wcout << L"state=passed protocol_generation=" << kProtocolGeneration
                     << L" gamepad_abi=" << after.gamepad_abi_version
                     << L" profile=generic enumerated=true token_rejected=true device_rejected=true"
                     << L" cross_file_rejected=true owner_cleanup=true profiles_validated=" << profiles.size()
                     << L" capacity=" << before.max_gamepads
                     << L" overflow_rejected=true submitted=true input=received output=received"
                     << L" destroyed=true active_gamepads=" << after.active_gamepads << L'\n';
        }
        return static_cast<int>(exit_code::success);
      }
      Sleep(100);
    }
    return report_gamepad_smoke_failure(
      json,
      L"verify-destroyed",
      after.error == ERROR_SUCCESS ? ERROR_NOT_READY : after.error
    );
  }

  /** Idempotently create the root node and force-bind the supplied driver INF. */
  int install_or_update(const wchar_t *inf_argument) {
    DWORD error = ERROR_SUCCESS;
    const auto inf_path = absolute_path(inf_argument, error);
    if (!inf_path) {
      return fail(mutation_error_code(error), L"resolve-inf", error);
    }
    const DWORD attributes = GetFileAttributesW(inf_path->c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
      return fail(mutation_error_code(error), L"validate-inf", error);
    }
    const auto generation = lumen_inf_generation(*inf_path, error);
    if (!generation) {
      return fail(mutation_error_code(error), L"validate-inf-identity", error);
    }

    GUID class_guid {};
    std::array<wchar_t, MAX_CLASS_NAME_LEN> class_name {};
    DWORD required = 0;
    if (!SetupDiGetINFClassW(
          inf_path->c_str(),
          &class_guid,
          class_name.data(),
          static_cast<DWORD>(class_name.size()),
          &required
        )) {
      error = GetLastError();
      return fail(mutation_error_code(error), L"read-inf-class", error);
    }

    auto existing = enumerate_devices(DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (existing.error != ERROR_SUCCESS) {
      return fail(mutation_error_code(existing.error), L"enumerate-devices", existing.error);
    }

    bool created = false;
    device_info_set created_set(INVALID_HANDLE_VALUE);
    SP_DEVINFO_DATA created_device {};
    if (existing.devices.empty()) {
      if (!create_root_device(class_guid, class_name.data(), created_set, created_device, error)) {
        return fail(mutation_error_code(error), L"create-root-device", error);
      }
      created = true;
    }

    module_handle newdev(LoadLibraryExW(L"newdev.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
    if (newdev.get() == nullptr) {
      error = GetLastError();
      if (created) {
        bool ignored_reboot = false;
        DWORD ignored_error = ERROR_SUCCESS;
        remove_device(created_set.get(), created_device, ignored_reboot, ignored_error);
      }
      return fail(mutation_error_code(error), L"load-newdev", error);
    }
    const auto update_driver = resolve_function<update_driver_fn>(newdev.get(), "UpdateDriverForPlugAndPlayDevicesW");
    if (update_driver == nullptr) {
      error = ERROR_PROC_NOT_FOUND;
      if (created) {
        bool ignored_reboot = false;
        DWORD ignored_error = ERROR_SUCCESS;
        remove_device(created_set.get(), created_device, ignored_reboot, ignored_error);
      }
      return fail(exit_code::mutation_failed, L"resolve-update-driver", error);
    }

    BOOL reboot = FALSE;
    if (!update_driver(nullptr, LUMEN_VHID_ROOT_HARDWARE_ID_W, inf_path->c_str(), kInstallFlagForce, &reboot)) {
      error = GetLastError();
      if (created) {
        bool ignored_reboot = false;
        DWORD ignored_error = ERROR_SUCCESS;
        remove_device(created_set.get(), created_device, ignored_reboot, ignored_error);
      }
      return fail(mutation_error_code(error), L"install-or-update-driver", error);
    }

    if (!reboot) {
      pnp_diagnostic last_pnp_diagnostic;
      for (int attempt = 0; attempt < kInterfaceWaitAttempts; ++attempt) {
        auto installed_devices = enumerate_devices(DIGCF_ALLCLASSES | DIGCF_PRESENT);
        pnp_diagnostic diagnostic;
        const bool children_started = installed_devices.error == ERROR_SUCCESS &&
                                      installed_devices.devices.size() == 1 &&
                                      device_tree_started(installed_devices.devices[0].DevInst, diagnostic);
        if (diagnostic.status_available || diagnostic.error != CR_SUCCESS) {
          last_pnp_diagnostic = diagnostic;
        }
        if (*generation == package_generation::legacy_007 && children_started) {
          std::wcout << L"result=success action=install-or-update hardware_id=\""
                     << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" package=legacy-0.0.7\n";
          return static_cast<int>(exit_code::success);
        }
        const collection_inventory collections = find_present_collections();
        const probe_result control_probe = query_protocol();
        if (*generation == package_generation::current &&
            collections.healthy() && children_started && control_probe.state == probe_state::compatible) {
          std::wcout << L"result=success action=install-or-update hardware_id=\""
                     << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" protocol_generation="
                     << kProtocolGeneration << L" base_abi=" << LUMEN_VHID_ABI_VERSION
                     << L" gamepad_abi=" << LUMEN_VHID_GAMEPAD_ABI_VERSION << L'\n';
          return static_cast<int>(exit_code::success);
        }
        if (*generation == package_generation::current && collections.error != ERROR_SUCCESS) {
          return fail(mutation_error_code(collections.error), L"verify-interface", collections.error);
        }
        if (installed_devices.error != ERROR_SUCCESS) {
          return fail(mutation_error_code(installed_devices.error), L"verify-devices", installed_devices.error);
        }
        if (*generation == package_generation::current && control_probe.state == probe_state::inaccessible) {
          return fail(exit_code::mutation_failed, L"verify-control-interface", control_probe.error);
        }
        Sleep(100);
      }
      return fail(exit_code::mutation_failed, L"verify-interface", ERROR_NOT_READY, &last_pnp_diagnostic);
    }

    std::wcout << L"result=reboot-required action=install-or-update hardware_id=\""
               << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" protocol_generation="
               << kProtocolGeneration << L" base_abi=" << LUMEN_VHID_ABI_VERSION
               << L" gamepad_abi=" << LUMEN_VHID_GAMEPAD_ABI_VERSION << L'\n';
    return static_cast<int>(exit_code::reboot_required);
  }

  /** Return whether exact Lumen roots and driver-store packages are both absent. */
  bool uninstall_post_state_absent(DWORD &error) {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      error = devices.error;
      return false;
    }
    const auto packages = find_driver_packages(error);
    return error == ERROR_SUCCESS && devices.devices.empty() && packages.empty();
  }

  /** Remove exact Lumen roots and packages once, using the documented NewDev sequence. */
  bool uninstall_once(bool &reboot, size_t &device_count, size_t &package_count, DWORD &error) {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      error = devices.error;
      return false;
    }

    module_handle newdev(LoadLibraryExW(L"newdev.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
    if (newdev.get() == nullptr) {
      error = GetLastError();
      return false;
    }
    const auto uninstall_device = resolve_function<uninstall_device_fn>(newdev.get(), "DiUninstallDevice");
    const auto uninstall_driver = resolve_function<uninstall_driver_fn>(newdev.get(), "DiUninstallDriverW");
    if (uninstall_device == nullptr || uninstall_driver == nullptr) {
      error = ERROR_PROC_NOT_FOUND;
      return false;
    }

    device_count += devices.devices.size();
    for (SP_DEVINFO_DATA &device : devices.devices) {
      BOOL device_reboot = FALSE;
      if (!uninstall_device(nullptr, devices.set.get(), &device, 0, &device_reboot)) {
        error = GetLastError();
        return false;
      }
      reboot = reboot || device_reboot != FALSE;
    }

    auto remaining_devices = enumerate_devices();
    if (remaining_devices.error != ERROR_SUCCESS) {
      error = remaining_devices.error;
      return false;
    }
    if (!remaining_devices.devices.empty()) {
      error = ERROR_NOT_READY;
      return false;
    }

    const auto packages = find_driver_packages(error);
    if (error != ERROR_SUCCESS) {
      return false;
    }
    package_count += packages.size();
    for (const std::wstring &package : packages) {
      BOOL package_reboot = FALSE;
      if (!uninstall_driver(nullptr, package.c_str(), 0, &package_reboot)) {
        error = GetLastError();
        return false;
      }
      reboot = reboot || package_reboot != FALSE;
    }
    error = ERROR_SUCCESS;
    return true;
  }

  /** Idempotently remove exact present and non-present roots with one bounded retry. */
  int uninstall() {
    bool reboot = false;
    size_t devices_removed = 0;
    size_t packages_removed = 0;
    DWORD error = ERROR_SUCCESS;
    for (int attempt = 0; attempt < 2; ++attempt) {
      if (uninstall_once(reboot, devices_removed, packages_removed, error)) {
        DWORD post_error = ERROR_SUCCESS;
        if (uninstall_post_state_absent(post_error)) {
          std::wcout << L"result=" << (reboot ? L"reboot-required" : L"success")
                     << L" action=uninstall devices_removed=" << devices_removed
                     << L" packages_removed=" << packages_removed << L'\n';
          return static_cast<int>(reboot ? exit_code::reboot_required : exit_code::success);
        }
        error = post_error == ERROR_SUCCESS ? ERROR_NOT_READY : post_error;
      } else if (error == 0xE0000231) {
        DWORD post_error = ERROR_SUCCESS;
        if (uninstall_post_state_absent(post_error)) {
          std::wcout << L"result=success action=uninstall devices_removed=" << devices_removed
                     << L" packages_removed=" << packages_removed << L'\n';
          return static_cast<int>(exit_code::success);
        }
        if (post_error != ERROR_SUCCESS) {
          error = post_error;
        }
      }
      if (attempt == 0) {
        Sleep(250);
      }
    }
    if (reboot) {
      std::wcout << L"result=reboot-required action=uninstall devices_removed=" << devices_removed
                 << L" packages_removed=" << packages_removed << L'\n';
      return static_cast<int>(exit_code::reboot_required);
    }
    return fail(mutation_error_code(error), L"uninstall", error);
  }

  /** Print the command and stable exit-code contract. */
  int usage() {
    std::wcerr << L"usage: lumen-vhidctl status [--json] | probe [--json] | "
                  L"smoke-gamepad [--json] | "
                  L"smoke-vigem [--json] | "
                  L"install-or-update <inf-path> | uninstall\n"
                  L"exit_codes: success=0 mutation_failed=1 absent=2 inaccessible=3 "
                  L"incompatible=4 reboot_required=3010\n";
    return static_cast<int>(exit_code::mutation_failed);
  }
}  // namespace

/** Parse the Unicode command line and dispatch one management operation. */
int main() {
  int argument_count = 0;
  wchar_t **arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
  if (arguments == nullptr) {
    return fail(exit_code::mutation_failed, L"parse-command-line", GetLastError());
  }

  int result = static_cast<int>(exit_code::mutation_failed);
  if (argument_count == 2 && _wcsicmp(arguments[1], L"status") == 0) {
    result = status(false);
  } else if (argument_count == 3 && _wcsicmp(arguments[1], L"status") == 0 &&
             _wcsicmp(arguments[2], L"--json") == 0) {
    result = status(true);
  } else if (argument_count == 2 && _wcsicmp(arguments[1], L"probe") == 0) {
    result = probe(false);
  } else if (argument_count == 3 && _wcsicmp(arguments[1], L"probe") == 0 &&
             _wcsicmp(arguments[2], L"--json") == 0) {
    result = probe(true);
  } else if (argument_count == 2 && _wcsicmp(arguments[1], L"smoke-gamepad") == 0) {
    result = smoke_gamepad(false);
  } else if (argument_count == 3 && _wcsicmp(arguments[1], L"smoke-gamepad") == 0 &&
             _wcsicmp(arguments[2], L"--json") == 0) {
    result = smoke_gamepad(true);
  } else if (argument_count == 2 && _wcsicmp(arguments[1], L"smoke-vigem") == 0) {
    result = smoke_vigem(false);
  } else if (argument_count == 3 && _wcsicmp(arguments[1], L"smoke-vigem") == 0 &&
             _wcsicmp(arguments[2], L"--json") == 0) {
    result = smoke_vigem(true);
  } else if (argument_count == 3 && _wcsicmp(arguments[1], L"install-or-update") == 0) {
    result = install_or_update(arguments[2]);
  } else if (argument_count == 2 && _wcsicmp(arguments[1], L"uninstall") == 0) {
    result = uninstall();
  } else {
    result = usage();
  }

  LocalFree(arguments);
  return result;
}
