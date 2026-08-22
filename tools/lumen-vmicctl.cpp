/**
 * @file tools/lumen-vmicctl.cpp
 * @brief Installs, verifies, and removes the Lumen Virtual Microphone driver.
 */

#define WIN32_LEAN_AND_MEAN
#define INITGUID
// clang-format off
#include <windows.h>
#include "src/platform/windows/virtual_microphone_protocol.h"
// clang-format on

#include <algorithm>
#include <array>
#include <cctype>
#include <cfgmgr32.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <mmdeviceapi.h>
#include <optional>
#include <propsys.h>
#include <propvarutil.h>
#include <setupapi.h>
#include <shellapi.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

// MinGW's functiondiscoverykeys_devpkey.h is order-sensitive. Define the one
// documented property key this standalone helper consumes.
DEFINE_PROPERTYKEY(PKEY_Device_FriendlyName, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 14);

namespace {
  constexpr wchar_t kDeviceDescription[] = L"Lumen Virtual Microphone";
  constexpr wchar_t kEndpointFriendlyName[] = L"Lumen Virtual Microphone";
  constexpr DWORD kInstallFlagForce = 0x00000001;
  constexpr int kReadyWaitAttempts = 100;

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
  /** Dynamically loaded NewDev driver-package uninstall API signature. */
  using uninstall_driver_fn = BOOL(WINAPI *)(HWND, LPCWSTR, DWORD, PBOOL);

  /** Resolve one dynamically loaded function without an incompatible function cast. */
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

    /** Return whether the wrapped handle is valid. */
    [[nodiscard]] bool valid() const noexcept {
      return handle_ != INVALID_HANDLE_VALUE;
    }

  private:
    HDEVINFO handle_ = INVALID_HANDLE_VALUE;  ///< Owned SetupAPI set.
  };

  /** Unique owner for a loaded Windows module. */
  class module_handle {
  public:
    /** Adopt a module handle, including nullptr. */
    explicit module_handle(HMODULE handle) noexcept:
        handle_(handle) {}

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
    HMODULE handle_ = nullptr;  ///< Owned module.
  };

  /** Exact root-device enumeration result. */
  struct device_enumeration {
    device_info_set set {INVALID_HANDLE_VALUE};  ///< Owning device set.
    std::vector<SP_DEVINFO_DATA> devices;  ///< Exact matching roots.
    DWORD error = ERROR_SUCCESS;  ///< Enumeration error.
  };

  /** ConfigMgr diagnostic captured from the first unhealthy node. */
  struct pnp_diagnostic {
    ULONG status = 0;  ///< Device-node status flags.
    ULONG problem = 0;  ///< Device-node problem code.
    CONFIGRET error = CR_SUCCESS;  ///< ConfigMgr query result.
    bool available = false;  ///< Whether status and problem are valid.
  };

  /** Control-device ABI probe state. */
  enum class probe_state {
    compatible,
    absent,
    inaccessible,
    incompatible,
  };

  /** Exact control-device probe result. */
  struct probe_result {
    probe_state state = probe_state::absent;  ///< Classified readiness.
    DWORD error = ERROR_SUCCESS;  ///< Win32 failure, if any.
    LUMEN_VMIC_QUERY_ABI_RESPONSE abi {};  ///< Returned ABI when available.
  };

  /** Active Core Audio capture-endpoint inventory. */
  struct endpoint_inventory {
    unsigned matching_count = 0;  ///< Endpoints with the exact friendly name.
    HRESULT error = S_OK;  ///< COM/Core Audio failure.

    /** Return whether exactly one active endpoint is present. */
    [[nodiscard]] bool healthy() const noexcept {
      return SUCCEEDED(error) && matching_count == 1;
    }
  };

  /** Escape one value for a single-line JSON string. */
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

  /** Map access failures while preserving an operation-specific fallback. */
  exit_code error_code(exit_code fallback, DWORD error) {
    return error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD ?
             exit_code::inaccessible :
             fallback;
  }

  /** Emit a stable machine-readable diagnostic and return its exit code. */
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
                 << L"\" message=\"" << win32_message(error) << L'\"';
    }
    if (pnp != nullptr && pnp->available) {
      std::wcerr << L" cm_status=" << pnp->status << L" cm_problem=" << pnp->problem;
    }
    if (pnp != nullptr && pnp->error != CR_SUCCESS) {
      std::wcerr << L" cm_error=" << pnp->error;
    }
    std::wcerr << L'\n';
    return static_cast<int>(code);
  }

  /** Compare a hardware identifier with Lumen's canonical microphone root. */
  bool equals_hardware_id(const wchar_t *value) {
    return _wcsicmp(value, LUMEN_VMIC_ROOT_HARDWARE_ID_W) == 0;
  }

  /** Check one SetupAPI node for the exact canonical hardware ID. */
  bool device_has_hardware_id(HDEVINFO set, SP_DEVINFO_DATA &device) {
    DWORD required = 0;
    DWORD type = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, &type, nullptr, 0, &required);
    if (required == 0 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return false;
    }

    std::vector<BYTE> buffer(required + sizeof(wchar_t), 0);
    if (!SetupDiGetDeviceRegistryPropertyW(set, &device, SPDRP_HARDWAREID, &type, buffer.data(), required, nullptr) ||
        (type != REG_MULTI_SZ && type != REG_SZ)) {
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

  /** Enumerate exact device nodes, optionally restricting to present nodes. */
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

  /** Verify one node and every descendant started without a PnP problem. */
  bool device_tree_started(DEVINST device, pnp_diagnostic &diagnostic) {
    ULONG status = 0;
    ULONG problem = 0;
    diagnostic.error = CM_Get_DevNode_Status(&status, &problem, device, 0);
    if (diagnostic.error != CR_SUCCESS) {
      return false;
    }
    if ((status & DN_STARTED) == 0 || (status & DN_HAS_PROBLEM) != 0) {
      diagnostic.status = status;
      diagnostic.problem = problem;
      diagnostic.available = true;
      return false;
    }

    DEVINST child = 0;
    diagnostic.error = CM_Get_Child(&child, device, 0);
    if (diagnostic.error == CR_NO_SUCH_DEVNODE) {
      diagnostic.error = CR_SUCCESS;
      return true;
    }
    if (diagnostic.error != CR_SUCCESS) {
      return false;
    }
    for (;;) {
      if (!device_tree_started(child, diagnostic)) {
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

  /** Count exact active Core Audio capture endpoints. */
  endpoint_inventory find_capture_endpoint() {
    endpoint_inventory result;
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool uninitialize = SUCCEEDED(initialized);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) {
      result.error = initialized;
      return result;
    }

    IMMDeviceEnumerator *enumerator = nullptr;
    IMMDeviceCollection *devices = nullptr;
    result.error = CoCreateInstance(
      CLSID_MMDeviceEnumerator,
      nullptr,
      CLSCTX_INPROC_SERVER,
      IID_IMMDeviceEnumerator,
      reinterpret_cast<void **>(&enumerator)
    );
    if (SUCCEEDED(result.error)) {
      result.error = enumerator->EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE, &devices);
    }

    UINT count = 0;
    if (SUCCEEDED(result.error)) {
      result.error = devices->GetCount(&count);
    }
    for (UINT index = 0; SUCCEEDED(result.error) && index < count; ++index) {
      IMMDevice *device = nullptr;
      IPropertyStore *properties = nullptr;
      PROPVARIANT name;
      PropVariantInit(&name);
      HRESULT current = devices->Item(index, &device);
      if (SUCCEEDED(current)) {
        current = device->OpenPropertyStore(STGM_READ, &properties);
      }
      if (SUCCEEDED(current)) {
        current = properties->GetValue(PKEY_Device_FriendlyName, &name);
      }
      if (SUCCEEDED(current) && name.vt == VT_LPWSTR && name.pwszVal != nullptr &&
          _wcsicmp(name.pwszVal, kEndpointFriendlyName) == 0) {
        ++result.matching_count;
      }
      PropVariantClear(&name);
      if (properties != nullptr) {
        properties->Release();
      }
      if (device != nullptr) {
        device->Release();
      }
      if (FAILED(current)) {
        result.error = current;
      }
    }

    if (devices != nullptr) {
      devices->Release();
    }
    if (enumerator != nullptr) {
      enumerator->Release();
    }
    if (uninitialize) {
      CoUninitialize();
    }
    return result;
  }

  /** Query and validate the exact control-device ABI. */
  probe_result query_protocol() {
    probe_result result;
    const HANDLE device = CreateFileW(
      LUMEN_VMIC_CONTROL_DEVICE_PATH_W,
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      nullptr
    );
    if (device == INVALID_HANDLE_VALUE) {
      result.error = GetLastError();
      if (result.error == ERROR_FILE_NOT_FOUND || result.error == ERROR_PATH_NOT_FOUND) {
        result.state = probe_state::absent;
      } else if (result.error == ERROR_ACCESS_DENIED || result.error == ERROR_PRIVILEGE_NOT_HELD) {
        result.state = probe_state::inaccessible;
      } else {
        result.state = probe_state::incompatible;
      }
      return result;
    }

    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(
      device,
      IOCTL_LUMEN_VMIC_QUERY_ABI,
      nullptr,
      0,
      &result.abi,
      sizeof(result.abi),
      &returned,
      nullptr
    );
    result.error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) {
      result.state = result.error == ERROR_ACCESS_DENIED ? probe_state::inaccessible : probe_state::incompatible;
      return result;
    }
    if (returned != sizeof(result.abi) ||
        result.abi.abi_version != LUMEN_VMIC_ABI_VERSION ||
        result.abi.sample_rate_hz != LUMEN_VMIC_SAMPLE_RATE_HZ ||
        result.abi.channel_count != LUMEN_VMIC_CHANNEL_COUNT ||
        result.abi.bits_per_sample != LUMEN_VMIC_BITS_PER_SAMPLE ||
        result.abi.max_write_frames != LUMEN_VMIC_MAX_WRITE_FRAMES) {
      result.error = ERROR_REVISION_MISMATCH;
      result.state = probe_state::incompatible;
      return result;
    }
    result.state = probe_state::compatible;
    return result;
  }

  /** Read a bounded driver INF into memory. */
  bool read_file(const std::wstring &path, std::vector<BYTE> &bytes, DWORD &error) {
    const HANDLE file = CreateFileW(
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

  /** Validate the exact Lumen x64 virtual-microphone INF identity. */
  bool inf_has_lumen_identity(const std::wstring &path, DWORD &error) {
    std::vector<BYTE> bytes;
    return read_file(path, bytes, error) &&
           contains_inf_token(bytes, LUMEN_VMIC_ROOT_HARDWARE_ID_A) &&
           contains_inf_token(bytes, "LumenProvider = \"simonfalke\"") &&
           contains_inf_token(bytes, "AddService = LumenVirtualMicrophone") &&
           contains_inf_token(bytes, "ServiceBinary = %13%\\LumenVirtualMicrophone.sys") &&
           contains_inf_token(bytes, "CatalogFile = LumenVirtualMicrophone.cat") &&
           contains_inf_token(bytes, "NTamd64");
  }

  /** Resolve one command-line path to an absolute path. */
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

  /** Remove one exact root node using the documented NewDev API. */
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

  /** Create and register the canonical root device before binding its driver. */
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
    constexpr wchar_t hardware_ids[] = LUMEN_VMIC_ROOT_HARDWARE_ID_W L"\0";
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

  /** Locate OEM driver-store INFs with the exact Lumen microphone identity. */
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

  /** Convert a probe state to its stable output label. */
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

  /** Convert a probe state to its stable exit code. */
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

  /** Report whether the exact root, endpoint, and control ABI are healthy. */
  int status(bool json) {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      return fail(error_code(exit_code::incompatible, devices.error), L"enumerate-devices", devices.error);
    }
    if (devices.devices.empty()) {
      if (json) {
        std::wcout << L"{\"state\":\"absent\",\"hardwareId\":\""
                   << json_escape(LUMEN_VMIC_ROOT_HARDWARE_ID_W) << L"\"}\n";
      } else {
        std::wcout << L"state=absent hardware_id=\"" << LUMEN_VMIC_ROOT_HARDWARE_ID_W << L"\"\n";
      }
      return static_cast<int>(exit_code::absent);
    }

    pnp_diagnostic diagnostic;
    const bool root_healthy = devices.devices.size() == 1 &&
                              device_tree_started(devices.devices[0].DevInst, diagnostic);
    const endpoint_inventory endpoints = find_capture_endpoint();
    const probe_result control = query_protocol();
    const bool healthy = root_healthy && endpoints.healthy() && control.state == probe_state::compatible;
    if (json) {
      std::wcout << L"{\"state\":\"" << (healthy ? L"installed" : L"unhealthy")
                 << L"\",\"rootDevices\":" << devices.devices.size()
                 << L",\"captureEndpoints\":" << endpoints.matching_count
                 << L",\"control\":\"" << probe_state_name(control.state) << L"\"";
      if (control.state == probe_state::compatible) {
        std::wcout << L",\"abiVersion\":" << control.abi.abi_version;
      }
      std::wcout << L"}\n";
    } else {
      std::wcout << L"state=" << (healthy ? L"installed" : L"unhealthy")
                 << L" hardware_id=\"" << LUMEN_VMIC_ROOT_HARDWARE_ID_W << L"\""
                 << L" roots=" << devices.devices.size()
                 << L" capture_endpoints=" << endpoints.matching_count
                 << L" control=" << probe_state_name(control.state) << L'\n';
    }
    if (healthy) {
      return static_cast<int>(exit_code::success);
    }
    if (control.state == probe_state::inaccessible) {
      return static_cast<int>(exit_code::inaccessible);
    }
    if (FAILED(endpoints.error)) {
      return fail(exit_code::incompatible, L"enumerate-capture-endpoint", static_cast<DWORD>(endpoints.error));
    }
    if (!root_healthy) {
      return fail(exit_code::incompatible, L"verify-device-tree", ERROR_NOT_READY, &diagnostic);
    }
    return static_cast<int>(exit_code::incompatible);
  }

  /** Probe the exact SYSTEM-only control ABI. */
  int probe(bool json) {
    const probe_result result = query_protocol();
    if (json) {
      std::wcout << L"{\"state\":\"" << probe_state_name(result.state) << L"\"";
      if (result.state == probe_state::compatible) {
        std::wcout << L",\"abiVersion\":" << result.abi.abi_version
                   << L",\"sampleRate\":" << result.abi.sample_rate_hz
                   << L",\"channels\":" << result.abi.channel_count
                   << L",\"bitsPerSample\":" << result.abi.bits_per_sample
                   << L",\"maxWriteFrames\":" << result.abi.max_write_frames;
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

  /** Idempotently create the canonical root and force-bind the supplied INF. */
  int install_or_update(const wchar_t *inf_argument) {
    DWORD error = ERROR_SUCCESS;
    const auto inf_path = absolute_path(inf_argument, error);
    if (!inf_path) {
      return fail(exit_code::mutation_failed, L"resolve-inf", error);
    }
    const DWORD attributes = GetFileAttributesW(inf_path->c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
      error = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
      return fail(exit_code::mutation_failed, L"validate-inf", error);
    }
    if (!inf_has_lumen_identity(*inf_path, error)) {
      return fail(exit_code::mutation_failed, L"validate-inf-identity", error);
    }

    SYSTEM_INFO system_info {};
    GetNativeSystemInfo(&system_info);
    if (system_info.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
      return fail(exit_code::mutation_failed, L"validate-native-architecture", ERROR_BAD_ENVIRONMENT);
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
      return fail(exit_code::mutation_failed, L"read-inf-class", GetLastError());
    }

    auto existing = enumerate_devices(DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (existing.error != ERROR_SUCCESS) {
      return fail(exit_code::mutation_failed, L"enumerate-devices", existing.error);
    }
    bool created = false;
    device_info_set created_set(INVALID_HANDLE_VALUE);
    SP_DEVINFO_DATA created_device {};
    if (existing.devices.empty()) {
      if (!create_root_device(class_guid, class_name.data(), created_set, created_device, error)) {
        return fail(exit_code::mutation_failed, L"create-root-device", error);
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
      return fail(exit_code::mutation_failed, L"load-newdev", error);
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
    if (!update_driver(nullptr, LUMEN_VMIC_ROOT_HARDWARE_ID_W, inf_path->c_str(), kInstallFlagForce, &reboot)) {
      error = GetLastError();
      if (created) {
        bool ignored_reboot = false;
        DWORD ignored_error = ERROR_SUCCESS;
        remove_device(created_set.get(), created_device, ignored_reboot, ignored_error);
      }
      return fail(exit_code::mutation_failed, L"install-or-update-driver", error);
    }

    if (!reboot) {
      pnp_diagnostic last_diagnostic;
      for (int attempt = 0; attempt < kReadyWaitAttempts; ++attempt) {
        auto installed = enumerate_devices(DIGCF_ALLCLASSES | DIGCF_PRESENT);
        pnp_diagnostic diagnostic;
        const bool tree_started = installed.error == ERROR_SUCCESS && installed.devices.size() == 1 &&
                                  device_tree_started(installed.devices[0].DevInst, diagnostic);
        if (diagnostic.available || diagnostic.error != CR_SUCCESS) {
          last_diagnostic = diagnostic;
        }
        const endpoint_inventory endpoints = find_capture_endpoint();
        const probe_result control = query_protocol();
        if (tree_started && endpoints.healthy() && control.state == probe_state::compatible) {
          std::wcout << L"result=success action=install-or-update hardware_id=\""
                     << LUMEN_VMIC_ROOT_HARDWARE_ID_W << L"\" protocol="
                     << LUMEN_VMIC_ABI_VERSION << L" capture_endpoints=1\n";
          return static_cast<int>(exit_code::success);
        }
        if (installed.error != ERROR_SUCCESS) {
          return fail(exit_code::mutation_failed, L"verify-devices", installed.error);
        }
        if (FAILED(endpoints.error)) {
          return fail(exit_code::mutation_failed, L"verify-capture-endpoint", static_cast<DWORD>(endpoints.error));
        }
        if (control.state == probe_state::inaccessible) {
          return fail(exit_code::mutation_failed, L"verify-control-abi", control.error);
        }
        Sleep(100);
      }
      return fail(exit_code::mutation_failed, L"verify-driver-readiness", ERROR_NOT_READY, &last_diagnostic);
    }

    std::wcout << L"result=reboot-required action=install-or-update hardware_id=\""
               << LUMEN_VMIC_ROOT_HARDWARE_ID_W << L"\" protocol=" << LUMEN_VMIC_ABI_VERSION << L'\n';
    return static_cast<int>(exit_code::reboot_required);
  }

  /** Return whether exact roots and exact driver-store packages are absent. */
  bool uninstall_post_state_absent(DWORD &error) {
    auto devices = enumerate_devices();
    if (devices.error != ERROR_SUCCESS) {
      error = devices.error;
      return false;
    }
    const auto packages = find_driver_packages(error);
    return error == ERROR_SUCCESS && devices.devices.empty() && packages.empty();
  }

  /** Remove exact roots and packages once using documented NewDev APIs. */
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
    auto remaining = enumerate_devices();
    if (remaining.error != ERROR_SUCCESS || !remaining.devices.empty()) {
      error = remaining.error == ERROR_SUCCESS ? ERROR_NOT_READY : remaining.error;
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

  /** Idempotently remove exact present/non-present roots and packages. */
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
    return fail(exit_code::mutation_failed, L"uninstall", error);
  }

  /** Print the public command and exit-code contract. */
  int usage() {
    std::wcerr << L"usage: lumen-vmicctl status [--json] | probe [--json] | "
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
