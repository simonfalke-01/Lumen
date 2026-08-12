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
#include <cwchar>
#include <iostream>
#include <optional>
#include <setupapi.h>
#include <shellapi.h>
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
    not_installed = 1,
    usage = 2,
    invalid_inf = 3,
    access_denied = 4,
    setup_api_failure = 5,
    device_failure = 6,
    driver_store_failure = 7,
    reboot_required = 3010,
  };

  /** Dynamically loaded NewDev update API signature. */
  using update_driver_fn = BOOL(WINAPI *)(HWND, LPCWSTR, LPCWSTR, DWORD, PBOOL);
  /** Dynamically loaded NewDev uninstall API signature. */
  using uninstall_driver_fn = BOOL(WINAPI *)(HWND, LPCWSTR, DWORD, PBOOL);

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

  /** Published Lumen driver interface lookup result. */
  struct interface_info {
    std::wstring path;
    DWORD error = ERROR_SUCCESS;
  };

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

  /** Translate privilege errors while preserving the operation-specific fallback. */
  exit_code error_code(exit_code fallback, DWORD error) {
    if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD) {
      return exit_code::access_denied;
    }
    return fallback;
  }

  /** Emit a stable machine-readable diagnostic and return its exit code. */
  int fail(exit_code code, std::wstring_view operation, DWORD error) {
    std::wcerr << L"result=error code=" << static_cast<int>(code)
               << L" operation=" << operation;
    if (error != ERROR_SUCCESS) {
      std::wcerr << L" win32=" << error << L" message=\"" << win32_message(error) << L'\"';
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

  /** Find the present device interface published by the exact Lumen root node. */
  interface_info find_present_interface() {
    interface_info result;
    device_info_set set(SetupDiGetClassDevsW(
      &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
      nullptr,
      nullptr,
      DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
    ));
    if (!set.valid()) {
      result.error = GetLastError();
      return result;
    }

    for (DWORD index = 0;; ++index) {
      SP_DEVICE_INTERFACE_DATA interface_data {};
      interface_data.cbSize = sizeof(interface_data);
      if (!SetupDiEnumDeviceInterfaces(set.get(), nullptr, &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID, index, &interface_data)) {
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
      SP_DEVINFO_DATA device {};
      device.cbSize = sizeof(device);
      if (!SetupDiGetDeviceInterfaceDetailW(set.get(), &interface_data, detail, required, nullptr, &device)) {
        continue;
      }
      if (device_has_hardware_id(set.get(), device)) {
        result.path = detail->DevicePath;
        return result;
      }
    }
  }

  /** Query protocol and capability metadata when the interface ACL permits it. */
  std::wstring protocol_query(const std::wstring &path) {
    HANDLE device = CreateFileW(
      path.c_str(),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr
    );
    if (device == INVALID_HANDLE_VALUE) {
      const DWORD error = GetLastError();
      if (error == ERROR_ACCESS_DENIED) {
        return L"query=access-denied";
      }
      return L"query=unavailable query_win32=" + std::to_wstring(error);
    }

    LUMEN_VHID_GET_CAPABILITIES_REQUEST request {};
    request.header.magic = LUMEN_VHID_PROTOCOL_MAGIC;
    request.header.protocol_major = LUMEN_VHID_PROTOCOL_MAJOR;
    request.header.protocol_minor = LUMEN_VHID_PROTOCOL_MINOR;
    request.header.header_size = sizeof(request.header);
    request.header.operation = LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES;
    request.header.total_size = sizeof(request);

    LUMEN_VHID_GET_CAPABILITIES_RESPONSE response {};
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
      device,
      IOCTL_LUMEN_VHID_GET_PROTOCOL_CAPABILITIES,
      &request,
      sizeof(request),
      &response,
      sizeof(response),
      &returned,
      nullptr
    );
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);

    if (!ok) {
      return L"query=failed query_win32=" + std::to_wstring(error);
    }
    if (!lumen_vhid_validate_message_header(
          &response.header,
          returned,
          LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
          sizeof(response)
        )) {
      return L"query=incompatible";
    }

    wchar_t capabilities[32] {};
    swprintf(capabilities, std::size(capabilities), L"0x%016llx", static_cast<unsigned long long>(response.capabilities));
    return L"query=ok driver_protocol=" + std::to_wstring(response.header.protocol_major) + L'.' +
           std::to_wstring(response.header.protocol_minor) + L" capabilities=" + capabilities;
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

  /** Find the canonical hardware ID in ANSI/UTF-8 or UTF-16LE INF bytes. */
  bool contains_hardware_id(const std::vector<BYTE> &source) {
    constexpr std::string_view hardware_id = LUMEN_VHID_ROOT_HARDWARE_ID_A;
    std::vector<BYTE> lower(source);
    for (BYTE &byte : lower) {
      if (byte >= 'A' && byte <= 'Z') {
        byte = static_cast<BYTE>(byte - 'A' + 'a');
      }
    }

    std::string narrow(hardware_id);
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

  /** Validate that an INF is specifically for the Lumen root device. */
  bool inf_contains_hardware_id(const std::wstring &path, DWORD &error) {
    std::vector<BYTE> bytes;
    return read_file(path, bytes, error) && contains_hardware_id(bytes);
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

  /** Remove one exact device node and report any restart requirement. */
  bool remove_device(HDEVINFO set, SP_DEVINFO_DATA &device, bool &reboot_required, DWORD &error) {
    SP_REMOVEDEVICE_PARAMS params {};
    params.ClassInstallHeader.cbSize = sizeof(params.ClassInstallHeader);
    params.ClassInstallHeader.InstallFunction = DIF_REMOVE;
    params.Scope = DI_REMOVEDEVICE_GLOBAL;
    params.HwProfile = 0;
    if (!SetupDiSetClassInstallParamsW(
          set,
          &device,
          &params.ClassInstallHeader,
          sizeof(params)
        ) ||
        !SetupDiCallClassInstaller(DIF_REMOVE, set, &device)) {
      error = GetLastError();
      return false;
    }

    SP_DEVINSTALL_PARAMS_W install_params {};
    install_params.cbSize = sizeof(install_params);
    if (SetupDiGetDeviceInstallParamsW(set, &device, &install_params)) {
      reboot_required = reboot_required || (install_params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) != 0;
    }
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
      if (inf_contains_hardware_id(path, read_error)) {
        result.push_back(path);
      }
    } while (FindNextFileW(find, &data));

    const DWORD find_error = GetLastError();
    FindClose(find);
    error = find_error == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : find_error;
    return result;
  }

  /** Report whether the root node is started and its interface is published. */
  int status() {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      const exit_code code = error_code(exit_code::setup_api_failure, devices.error);
      return fail(code, L"enumerate-devices", devices.error);
    }
    if (devices.devices.empty()) {
      std::wcout << L"state=absent hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W
                 << L"\" protocol=" << LUMEN_VHID_PROTOCOL_MAJOR << L'.' << LUMEN_VHID_PROTOCOL_MINOR << L'\n';
      return static_cast<int>(exit_code::not_installed);
    }

    bool started = false;
    ULONG problem = 0;
    ULONG device_status = 0;
    for (const SP_DEVINFO_DATA &device : devices.devices) {
      if (CM_Get_DevNode_Status(&device_status, &problem, device.DevInst, 0) == CR_SUCCESS &&
          (device_status & DN_STARTED) != 0) {
        started = true;
        break;
      }
    }

    const interface_info interface = find_present_interface();
    if (interface.error != ERROR_SUCCESS) {
      const exit_code code = error_code(exit_code::setup_api_failure, interface.error);
      return fail(code, L"enumerate-interface", interface.error);
    }
    if (!started || interface.path.empty()) {
      std::wcout << L"state=absent reason=" << (!started ? L"device-not-started" : L"interface-not-published")
                 << L" hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\""
                 << L" cm_status=" << device_status << L" cm_problem=" << problem
                 << L" protocol=" << LUMEN_VHID_PROTOCOL_MAJOR << L'.' << LUMEN_VHID_PROTOCOL_MINOR << L'\n';
      return static_cast<int>(exit_code::not_installed);
    }

    std::wcout << L"state=installed hardware_id=\"" << LUMEN_VHID_ROOT_HARDWARE_ID_W
               << L"\" interface=\"" << interface.path << L"\" protocol="
               << LUMEN_VHID_PROTOCOL_MAJOR << L'.' << LUMEN_VHID_PROTOCOL_MINOR << L' '
               << protocol_query(interface.path) << L'\n';
    return static_cast<int>(exit_code::success);
  }

  /** Idempotently create the root node and force-bind the supplied driver INF. */
  int install_or_update(const wchar_t *inf_argument) {
    DWORD error = ERROR_SUCCESS;
    const auto inf_path = absolute_path(inf_argument, error);
    if (!inf_path) {
      return fail(error_code(exit_code::invalid_inf, error), L"resolve-inf", error);
    }
    const DWORD attributes = GetFileAttributesW(inf_path->c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
      return fail(error_code(exit_code::invalid_inf, error), L"validate-inf", error);
    }
    if (!inf_contains_hardware_id(*inf_path, error)) {
      return fail(error_code(exit_code::invalid_inf, error), L"validate-hardware-id", error);
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
      return fail(error_code(exit_code::invalid_inf, error), L"read-inf-class", error);
    }

    auto existing = enumerate_devices(DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (existing.error != ERROR_SUCCESS) {
      return fail(error_code(exit_code::setup_api_failure, existing.error), L"enumerate-devices", existing.error);
    }

    bool created = false;
    device_info_set created_set(INVALID_HANDLE_VALUE);
    SP_DEVINFO_DATA created_device {};
    if (existing.devices.empty()) {
      if (!create_root_device(class_guid, class_name.data(), created_set, created_device, error)) {
        return fail(error_code(exit_code::device_failure, error), L"create-root-device", error);
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
      return fail(error_code(exit_code::setup_api_failure, error), L"load-newdev", error);
    }
    const auto update_driver = reinterpret_cast<update_driver_fn>(GetProcAddress(newdev.get(), "UpdateDriverForPlugAndPlayDevicesW"));
    if (update_driver == nullptr) {
      error = ERROR_PROC_NOT_FOUND;
      if (created) {
        bool ignored_reboot = false;
        DWORD ignored_error = ERROR_SUCCESS;
        remove_device(created_set.get(), created_device, ignored_reboot, ignored_error);
      }
      return fail(exit_code::setup_api_failure, L"resolve-update-driver", error);
    }

    BOOL reboot = FALSE;
    if (!update_driver(nullptr, LUMEN_VHID_ROOT_HARDWARE_ID_W, inf_path->c_str(), kInstallFlagForce, &reboot)) {
      error = GetLastError();
      if (created) {
        bool ignored_reboot = false;
        DWORD ignored_error = ERROR_SUCCESS;
        remove_device(created_set.get(), created_device, ignored_reboot, ignored_error);
      }
      return fail(error_code(exit_code::driver_store_failure, error), L"install-or-update-driver", error);
    }

    if (!reboot) {
      for (int attempt = 0; attempt < kInterfaceWaitAttempts; ++attempt) {
        const interface_info interface = find_present_interface();
        if (!interface.path.empty()) {
          std::wcout << L"result=success action=install-or-update hardware_id=\""
                     << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" protocol="
                     << LUMEN_VHID_PROTOCOL_MAJOR << L'.' << LUMEN_VHID_PROTOCOL_MINOR << L'\n';
          return static_cast<int>(exit_code::success);
        }
        if (interface.error != ERROR_SUCCESS) {
          return fail(error_code(exit_code::setup_api_failure, interface.error), L"verify-interface", interface.error);
        }
        Sleep(100);
      }
      return fail(exit_code::device_failure, L"verify-interface", ERROR_NOT_READY);
    }

    std::wcout << L"result=reboot-required action=install-or-update hardware_id=\""
               << LUMEN_VHID_ROOT_HARDWARE_ID_W << L"\" protocol="
               << LUMEN_VHID_PROTOCOL_MAJOR << L'.' << LUMEN_VHID_PROTOCOL_MINOR << L'\n';
    return static_cast<int>(exit_code::reboot_required);
  }

  /** Idempotently remove exact Lumen root nodes and matching OEM packages. */
  int uninstall() {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      return fail(error_code(exit_code::setup_api_failure, devices.error), L"enumerate-devices", devices.error);
    }

    bool reboot = false;
    for (SP_DEVINFO_DATA &device : devices.devices) {
      DWORD error = ERROR_SUCCESS;
      if (!remove_device(devices.set.get(), device, reboot, error)) {
        return fail(error_code(exit_code::device_failure, error), L"remove-root-device", error);
      }
    }

    DWORD error = ERROR_SUCCESS;
    const auto packages = find_driver_packages(error);
    if (error != ERROR_SUCCESS) {
      return fail(error_code(exit_code::driver_store_failure, error), L"enumerate-driver-store", error);
    }
    if (!packages.empty()) {
      module_handle newdev(LoadLibraryExW(L"newdev.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
      if (newdev.get() == nullptr) {
        error = GetLastError();
        return fail(error_code(exit_code::driver_store_failure, error), L"load-newdev", error);
      }
      const auto uninstall_driver = reinterpret_cast<uninstall_driver_fn>(GetProcAddress(newdev.get(), "DiUninstallDriverW"));
      if (uninstall_driver == nullptr) {
        return fail(exit_code::driver_store_failure, L"resolve-uninstall-driver", ERROR_PROC_NOT_FOUND);
      }

      for (const std::wstring &package : packages) {
        BOOL package_reboot = FALSE;
        if (!uninstall_driver(nullptr, package.c_str(), 0, &package_reboot)) {
          error = GetLastError();
          if (error != ERROR_FILE_NOT_FOUND) {
            return fail(error_code(exit_code::driver_store_failure, error), L"remove-driver-package", error);
          }
        }
        reboot = reboot || package_reboot != FALSE;
      }
    }

    std::wcout << L"result=" << (reboot ? L"reboot-required" : L"success")
               << L" action=uninstall devices_removed=" << devices.devices.size()
               << L" packages_removed=" << packages.size() << L'\n';
    return static_cast<int>(reboot ? exit_code::reboot_required : exit_code::success);
  }

  /** Print the command and stable exit-code contract. */
  int usage() {
    std::wcerr << L"usage: lumen-vhidctl status | install-or-update <inf-path> | uninstall\n"
                  L"exit_codes: success=0 not_installed=1 usage=2 invalid_inf=3 access_denied=4 "
                  L"setup_api_failure=5 device_failure=6 driver_store_failure=7 reboot_required=3010\n";
    return static_cast<int>(exit_code::usage);
  }
}  // namespace

/** Parse the Unicode command line and dispatch one management operation. */
int main() {
  int argument_count = 0;
  wchar_t **arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
  if (arguments == nullptr) {
    return fail(exit_code::usage, L"parse-command-line", GetLastError());
  }

  int result = static_cast<int>(exit_code::usage);
  if (argument_count == 2 && _wcsicmp(arguments[1], L"status") == 0) {
    result = status();
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
