/**
 * @file tools/lumen-vddctl.cpp
 * @brief Creates, binds, and verifies the Lumen Virtual Display root device.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>
#include <cfgmgr32.h>
#include <cstring>
#include <cwchar>
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
  constexpr wchar_t kHardwareId[] = L"ROOT\\LumenVirtualDisplay";
  constexpr wchar_t kDeviceDescription[] = L"Lumen Virtual Display";
  constexpr GUID kDisplayClassGuid {
    0x4d36e968,
    0xe325,
    0x11ce,
    {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
  };
  constexpr DWORD kInstallFlagForce = 0x00000001;
  constexpr int kReadyWaitAttempts = 300;
  constexpr DWORD kReadyWaitIntervalMs = 100;

  /** Stable process exit codes consumed by the Windows installer. */
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

  /** Resolve one dynamically loaded function without an incompatible cast. */
  template<class Function>
  Function resolve_function(HMODULE module, const char *name) {
    const auto procedure = GetProcAddress(module, name);
    static_assert(sizeof(Function) == sizeof(procedure));
    Function function = nullptr;
    std::memcpy(&function, &procedure, sizeof(function));
    return function;
  }

  /** Unique owner for a SetupAPI device information set. */
  class device_info_set {
  public:
    /** Adopt a SetupAPI handle, including INVALID_HANDLE_VALUE. */
    explicit device_info_set(HDEVINFO handle) noexcept:
        handle_(handle) {}

    device_info_set(const device_info_set &) = delete;
    device_info_set &operator=(const device_info_set &) = delete;

    /** Transfer ownership from another wrapper. */
    device_info_set(device_info_set &&other) noexcept:
        handle_(other.handle_) {
      other.handle_ = INVALID_HANDLE_VALUE;
    }

    /** Release the current set and take ownership from another wrapper. */
    device_info_set &operator=(device_info_set &&other) noexcept {
      if (this != &other) {
        if (valid()) {
          SetupDiDestroyDeviceInfoList(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = INVALID_HANDLE_VALUE;
      }
      return *this;
    }

    /** Destroy the owned SetupAPI set. */
    ~device_info_set() {
      if (valid()) {
        SetupDiDestroyDeviceInfoList(handle_);
      }
    }

    /** Return the owned handle. */
    [[nodiscard]] HDEVINFO get() const noexcept {
      return handle_;
    }

    /** Return whether the handle is valid. */
    [[nodiscard]] bool valid() const noexcept {
      return handle_ != INVALID_HANDLE_VALUE;
    }

  private:
    HDEVINFO handle_ = INVALID_HANDLE_VALUE;  ///< Owned SetupAPI set.
  };

  /** Unique owner for a loaded Windows module. */
  class module_handle {
  public:
    /** Adopt one module handle. */
    explicit module_handle(HMODULE handle) noexcept:
        handle_(handle) {}

    module_handle(const module_handle &) = delete;
    module_handle &operator=(const module_handle &) = delete;

    /** Release the module. */
    ~module_handle() {
      if (handle_ != nullptr) {
        FreeLibrary(handle_);
      }
    }

    /** Return the loaded module. */
    [[nodiscard]] HMODULE get() const noexcept {
      return handle_;
    }

  private:
    HMODULE handle_ = nullptr;  ///< Owned module.
  };

  /** Exact root-device enumeration result. */
  struct device_enumeration {
    device_info_set set {INVALID_HANDLE_VALUE};  ///< Owning device set.
    std::vector<SP_DEVINFO_DATA> devices;  ///< Exact hardware-ID matches.
    DWORD error = ERROR_SUCCESS;  ///< Enumeration error.
  };

  /** Format a Win32 error without line breaks. */
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
    for (wchar_t &character : message) {
      if (character == L'\r' || character == L'\n' || character == L'\t' || character == L'\"') {
        character = L' ';
      }
    }
    while (!message.empty() && message.back() == L' ') {
      message.pop_back();
    }
    return message;
  }

  /** Map access failures while preserving the operation-specific fallback. */
  exit_code error_code(exit_code fallback, DWORD error) {
    return error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD ?
             exit_code::inaccessible :
             fallback;
  }

  /** Emit one machine-readable failure. */
  int fail(exit_code code, std::wstring_view operation, DWORD error) {
    std::wcerr << L"result=error code=" << static_cast<int>(code)
               << L" operation=" << operation;
    if (error != ERROR_SUCCESS) {
      std::wcerr << L" win32=" << error
                 << L" hex=\"0x" << std::uppercase << std::hex << std::setw(8)
                 << std::setfill(L'0') << error << std::dec << std::nouppercase
                 << std::setfill(L' ') << L"\" message=\"" << win32_message(error) << L'\"';
    }
    std::wcerr << L'\n';
    return static_cast<int>(code);
  }

  /** Return whether one MULTI_SZ property contains the exact hardware ID. */
  bool contains_hardware_id(const std::vector<BYTE> &property) {
    if (property.size() < sizeof(wchar_t) * 2 || property.size() % sizeof(wchar_t) != 0) {
      return false;
    }
    const auto *current = reinterpret_cast<const wchar_t *>(property.data());
    const auto *end = reinterpret_cast<const wchar_t *>(property.data() + property.size());
    while (current < end && *current != L'\0') {
      const size_t remaining = static_cast<size_t>(end - current);
      const size_t length = wcsnlen(current, remaining);
      if (length == remaining) {
        return false;
      }
      if (_wcsicmp(current, kHardwareId) == 0) {
        return true;
      }
      current += length + 1;
    }
    return false;
  }

  /** Return whether a SetupAPI node has the exact Lumen display hardware ID. */
  bool device_has_hardware_id(HDEVINFO set, SP_DEVINFO_DATA &device) {
    DWORD required = 0;
    DWORD type = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, &type, nullptr, 0, &required);
    if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return false;
    }
    std::vector<BYTE> property(required);
    if (!SetupDiGetDeviceRegistryPropertyW(
          set,
          &device,
          SPDRP_HARDWAREID,
          &type,
          property.data(),
          static_cast<DWORD>(property.size()),
          nullptr
        ) || type != REG_MULTI_SZ) {
      return false;
    }
    return contains_hardware_id(property);
  }

  /** Enumerate present nodes with the exact Lumen display hardware ID. */
  device_enumeration enumerate_devices() {
    device_enumeration result;
    result.set = device_info_set(SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT));
    if (!result.set.valid()) {
      result.error = GetLastError();
      return result;
    }
    for (DWORD index = 0;; ++index) {
      SP_DEVINFO_DATA device {};
      device.cbSize = sizeof(device);
      if (!SetupDiEnumDeviceInfo(result.set.get(), index, &device)) {
        result.error = GetLastError() == ERROR_NO_MORE_ITEMS ? ERROR_SUCCESS : GetLastError();
        break;
      }
      if (device_has_hardware_id(result.set.get(), device)) {
        result.devices.push_back(device);
      }
    }
    return result;
  }

  /** Return whether one exact node is present, started, and problem-free. */
  bool exact_device_healthy(DWORD &error, ULONG &status, ULONG &problem, size_t &count) {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      error = devices.error;
      return false;
    }
    count = devices.devices.size();
    if (count != 1) {
      error = count == 0 ? ERROR_NOT_FOUND : ERROR_DUPLICATE_TAG;
      return false;
    }
    const CONFIGRET result = CM_Get_DevNode_Status(&status, &problem, devices.devices[0].DevInst, 0);
    if (result != CR_SUCCESS) {
      error = ERROR_GEN_FAILURE;
      return false;
    }
    error = ERROR_SUCCESS;
    return (status & DN_STARTED) != 0 && problem == 0;
  }

  /** Resolve an INF argument to one absolute path. */
  std::optional<std::wstring> absolute_path(const wchar_t *argument, DWORD &error) {
    const DWORD required = GetFullPathNameW(argument, 0, nullptr, nullptr);
    if (required == 0) {
      error = GetLastError();
      return std::nullopt;
    }
    std::wstring result(required, L'\0');
    const DWORD written = GetFullPathNameW(argument, required, result.data(), nullptr);
    if (written == 0 || written >= required) {
      error = written == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
      return std::nullopt;
    }
    result.resize(written);
    error = ERROR_SUCCESS;
    return result;
  }

  /** Validate that an INF is the AMD64 Lumen Display-class package. */
  bool validate_inf(const std::wstring &path, GUID &class_guid, std::wstring &class_name, DWORD &error) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
      return false;
    }
    std::array<wchar_t, MAX_CLASS_NAME_LEN> buffer {};
    DWORD required = 0;
    if (!SetupDiGetINFClassW(path.c_str(), &class_guid, buffer.data(), buffer.size(), &required)) {
      error = GetLastError();
      return false;
    }
    if (!IsEqualGUID(class_guid, kDisplayClassGuid)) {
      error = ERROR_INVALID_CLASS;
      return false;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
      error = GetLastError();
      return false;
    }
    LARGE_INTEGER size {};
    const bool size_valid = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= 1024 * 1024;
    std::string contents(size_valid ? static_cast<size_t>(size.QuadPart) : 0, '\0');
    DWORD read = 0;
    const bool read_valid = size_valid && ReadFile(file, contents.data(), static_cast<DWORD>(contents.size()), &read, nullptr) &&
                            read == contents.size();
    const DWORD read_error = read_valid ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (!read_valid) {
      error = read_error == ERROR_SUCCESS ? ERROR_INVALID_DATA : read_error;
      return false;
    }
    std::transform(contents.begin(), contents.end(), contents.begin(), [](unsigned char character) {
      return static_cast<char>(std::tolower(character));
    });
    if (contents.find("root\\lumenvirtualdisplay") == std::string::npos ||
        contents.find("ntamd64") == std::string::npos) {
      error = ERROR_INVALID_DATA;
      return false;
    }
    class_name.assign(buffer.data());
    error = ERROR_SUCCESS;
    return true;
  }

  /** Create and register the Lumen root device before binding the INF. */
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
    constexpr wchar_t hardware_ids[] = L"ROOT\\LumenVirtualDisplay\0";
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

  /** Remove one newly created node after a failed driver bind. */
  bool remove_created_device(HDEVINFO set, SP_DEVINFO_DATA &device, DWORD &error) {
    module_handle newdev(LoadLibraryExW(L"newdev.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
    if (newdev.get() == nullptr) {
      error = GetLastError();
      return false;
    }
    const auto uninstall = resolve_function<uninstall_device_fn>(newdev.get(), "DiUninstallDevice");
    if (uninstall == nullptr) {
      error = ERROR_PROC_NOT_FOUND;
      return false;
    }
    BOOL reboot = FALSE;
    if (!uninstall(nullptr, set, &device, 0, &reboot)) {
      error = GetLastError();
      return false;
    }
    error = ERROR_SUCCESS;
    return true;
  }

  /** Report the exact root-device health. */
  int status() {
    DWORD error = ERROR_SUCCESS;
    ULONG status_flags = 0;
    ULONG problem = 0;
    size_t count = 0;
    const bool healthy = exact_device_healthy(error, status_flags, problem, count);
    std::wcout << L"state=" << (healthy ? L"installed" : (count == 0 ? L"absent" : L"unhealthy"))
               << L" hardware_id=\"" << kHardwareId << L"\" roots=" << count
               << L" cm_status=" << status_flags << L" cm_problem=" << problem << L'\n';
    if (healthy) {
      return static_cast<int>(exit_code::success);
    }
    if (count == 0 && error == ERROR_NOT_FOUND) {
      return static_cast<int>(exit_code::absent);
    }
    return static_cast<int>(error_code(exit_code::incompatible, error));
  }

  /** Idempotently create the root node and force-bind the supplied INF. */
  int install_or_update(const wchar_t *inf_argument) {
    DWORD error = ERROR_SUCCESS;
    const auto inf_path = absolute_path(inf_argument, error);
    if (!inf_path) {
      return fail(exit_code::mutation_failed, L"resolve-inf", error);
    }
    GUID class_guid {};
    std::wstring class_name;
    if (!validate_inf(*inf_path, class_guid, class_name, error)) {
      return fail(exit_code::mutation_failed, L"validate-inf", error);
    }
    SYSTEM_INFO system_info {};
    GetNativeSystemInfo(&system_info);
    if (system_info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
      return fail(exit_code::mutation_failed, L"validate-native-architecture", ERROR_BAD_ENVIRONMENT);
    }

    auto existing = enumerate_devices();
    if (existing.error != ERROR_SUCCESS || existing.devices.size() > 1) {
      return fail(
        exit_code::mutation_failed,
        L"enumerate-devices",
        existing.error != ERROR_SUCCESS ? existing.error : ERROR_DUPLICATE_TAG
      );
    }
    bool created = false;
    device_info_set created_set(INVALID_HANDLE_VALUE);
    SP_DEVINFO_DATA created_device {};
    if (existing.devices.empty()) {
      if (!create_root_device(class_guid, class_name.c_str(), created_set, created_device, error)) {
        return fail(error_code(exit_code::mutation_failed, error), L"create-root-device", error);
      }
      created = true;
    }

    module_handle newdev(LoadLibraryExW(L"newdev.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
    const auto update = newdev.get() == nullptr ?
                          nullptr :
                          resolve_function<update_driver_fn>(newdev.get(), "UpdateDriverForPlugAndPlayDevicesW");
    if (update == nullptr) {
      error = newdev.get() == nullptr ? GetLastError() : ERROR_PROC_NOT_FOUND;
      if (created) {
        DWORD ignored = ERROR_SUCCESS;
        remove_created_device(created_set.get(), created_device, ignored);
      }
      return fail(exit_code::mutation_failed, L"resolve-update-driver", error);
    }

    BOOL reboot = FALSE;
    if (!update(nullptr, kHardwareId, inf_path->c_str(), kInstallFlagForce, &reboot)) {
      error = GetLastError();
      if (created) {
        DWORD ignored = ERROR_SUCCESS;
        remove_created_device(created_set.get(), created_device, ignored);
      }
      return fail(error_code(exit_code::mutation_failed, error), L"install-or-update-driver", error);
    }
    if (reboot) {
      std::wcout << L"result=reboot-required action=install-or-update hardware_id=\""
                 << kHardwareId << L"\" created=" << (created ? 1 : 0) << L'\n';
      return static_cast<int>(exit_code::reboot_required);
    }

    ULONG last_status = 0;
    ULONG last_problem = 0;
    size_t last_count = 0;
    for (int attempt = 0; attempt < kReadyWaitAttempts; ++attempt) {
      if (exact_device_healthy(error, last_status, last_problem, last_count)) {
        std::wcout << L"result=success action=install-or-update hardware_id=\""
                   << kHardwareId << L"\" created=" << (created ? 1 : 0) << L'\n';
        return static_cast<int>(exit_code::success);
      }
      Sleep(kReadyWaitIntervalMs);
    }
    std::wcerr << L"root_count=" << last_count << L" cm_status=" << last_status
               << L" cm_problem=" << last_problem << L'\n';
    return fail(exit_code::mutation_failed, L"verify-started-device", error);
  }

  /** Print the public command and exit-code contract. */
  int usage() {
    std::wcerr << L"usage: lumen-vddctl status | install-or-update <inf-path>\n"
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
    result = status();
  } else if (argument_count == 3 && _wcsicmp(arguments[1], L"install-or-update") == 0) {
    result = install_or_update(arguments[2]);
  } else {
    result = usage();
  }
  LocalFree(arguments);
  return result;
}
