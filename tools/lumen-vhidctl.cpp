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

namespace {
  constexpr wchar_t kDeviceDescription[] = L"Lumen Virtual HID Keyboard and Mouse";
  constexpr DWORD kInstallFlagForce = 0x00000001;
  constexpr int kInterfaceWaitAttempts = 30;

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

  /** Query ABI readiness when the SYSTEM-only control interface ACL permits it. */
  probe_result query_protocol() {
    probe_result result;
    device_info_set set(SetupDiGetClassDevsW(
      &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
      nullptr,
      nullptr,
      DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
    ));
    if (!set.valid()) {
      result.error = GetLastError();
      result.state = result.error == ERROR_ACCESS_DENIED ? probe_state::inaccessible : probe_state::incompatible;
      return result;
    }
    SP_DEVICE_INTERFACE_DATA interface_data {};
    interface_data.cbSize = sizeof(interface_data);
    if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID, 0, &interface_data)) {
      result.error = GetLastError();
      result.state = result.error == ERROR_NO_MORE_ITEMS ? probe_state::absent : probe_state::incompatible;
      return result;
    }
    DWORD required = 0;
    SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, nullptr, 0, &required, nullptr);
    if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
      result.error = GetLastError();
      result.state = probe_state::incompatible;
      return result;
    }
    std::vector<BYTE> detail_buffer(required, 0);
    auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(detail_buffer.data());
    detail->cbSize = sizeof(*detail);
    if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr, nullptr)) {
      result.error = GetLastError();
      result.state = probe_state::incompatible;
      return result;
    }
    HANDLE device = CreateFileW(
      detail->DevicePath,
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr
    );
    if (device == INVALID_HANDLE_VALUE) {
      result.error = GetLastError();
      result.state = result.error == ERROR_ACCESS_DENIED ? probe_state::inaccessible : probe_state::incompatible;
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
    CloseHandle(device);

    if (!ok) {
      result.state = result.error == ERROR_ACCESS_DENIED ? probe_state::inaccessible : probe_state::incompatible;
      return result;
    }
    if (returned != sizeof(response) || response.abi_version != LUMEN_VHID_ABI_VERSION || response.ready != 1) {
      result.error = ERROR_REVISION_MISMATCH;
      result.state = probe_state::incompatible;
      return result;
    }
    result.state = probe_state::compatible;
    result.abi_version = response.abi_version;
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
    if (json) {
      std::wcout << L"{\"state\":\"installed\",\"rootDevices\":" << devices.devices.size()
                 << L",\"keyboards\":" << collections.keyboard_count
                 << L",\"mice\":" << collections.mouse_count
                 << L",\"consumers\":" << collections.consumer_count << L"}\n";
    } else {
      std::wcout << L"state=installed hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W
                 << L"\" keyboards=" << collections.keyboard_count
                 << L" mice=" << collections.mouse_count
                 << L" consumers=" << collections.consumer_count << L'\n';
    }
    return static_cast<int>(exit_code::success);
  }

  /** Probe the SYSTEM-only control interface using Sunshine's exact GET_INFO ABI. */
  int probe(bool json) {
    const probe_result result = query_protocol();

    if (json) {
      std::wcout << L"{\"state\":\"" << probe_state_name(result.state) << L"\"";
      if (result.state == probe_state::compatible) {
        std::wcout << L",\"abiVersion\":" << result.abi_version;
      }
      if (result.error != ERROR_SUCCESS) {
        std::wcout << L",\"win32\":" << result.error;
      }
      std::wcout << L"}\n";
    } else {
      std::wcout << L"state=" << probe_state_name(result.state);
      if (result.error != ERROR_SUCCESS) {
        std::wcout << L" win32=" << result.error;
      }
      std::wcout << L'\n';
    }
    return static_cast<int>(probe_exit_code(result.state));
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
                     << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" protocol="
                     << LUMEN_VHID_ABI_VERSION << L'\n';
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
               << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" protocol="
               << LUMEN_VHID_ABI_VERSION << L'\n';
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
