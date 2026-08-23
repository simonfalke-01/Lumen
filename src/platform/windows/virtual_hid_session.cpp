/**
 * @file src/platform/windows/virtual_hid_session.cpp
 * @brief User-mode dynamic VHF session definitions.
 */

// local includes
#define INITGUID
#include "virtual_hid_session.h"
#undef INITGUID

#include "src/logging.h"

// standard includes
#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <utility>
#include <vector>

#if defined(_WIN32)
// platform includes
// Windows.h must precede SetupAPI.h for MinGW-UCRT64 declarations.
// clang-format off
  #include <Windows.h>
  #include <SetupAPI.h>
// clang-format on
#endif

namespace platf::win_gamepad {
  namespace {
    using namespace std::chrono_literals;

#if defined(_WIN32)
    /**
     * @brief Return whether a Win32 failure means the control channel is gone.
     *
     * @param status Win32 error returned by DeviceIoControl.
     * @return `true` when reopening the device is required.
     */
    bool terminal_transport_error(DWORD status) {
      switch (status) {
        case ERROR_INVALID_HANDLE:
        case ERROR_DEVICE_NOT_CONNECTED:
        case ERROR_GEN_FAILURE:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_NOT_READY:
        case ERROR_OPERATION_ABORTED:
          return true;
        default:
          return false;
      }
    }

    /**
     * @brief Production synchronous DeviceIoControl channel.
     */
    class system_gamepad_channel_t final: public gamepad_channel_t {
    public:
      /**
       * @brief Close the driver interface on destruction.
       */
      ~system_gamepad_channel_t() override {
        close();
      }

      channel_result_t open() override {
        std::lock_guard lock(mutex_);
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
          return failure(GetLastError());
        }

        DWORD last_status = ERROR_FILE_NOT_FOUND;
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
              last_status = status;
            }
            break;
          }

          DWORD detail_size = 0;
          SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, nullptr, 0, &detail_size, nullptr);
          if (detail_size < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
            continue;
          }
          std::vector<std::byte> buffer(detail_size);
          auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(buffer.data());
          detail->cbSize = sizeof(*detail);
          if (!SetupDiGetDeviceInterfaceDetailW(
                devices,
                &interface_data,
                detail,
                detail_size,
                nullptr,
                nullptr
              )) {
            last_status = GetLastError();
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
          last_status = GetLastError();
        }
        SetupDiDestroyDeviceInfoList(devices);
        return handle_ == INVALID_HANDLE_VALUE ? failure(last_status) : channel_result_t {};
      }

      channel_result_t capabilities(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE &response) override {
        return ioctl(IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES, nullptr, 0, &response, sizeof(response));
      }

      channel_result_t create(
        const LUMEN_VHID_GAMEPAD_CREATE_REQUEST &request,
        LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &response
      ) override {
        return ioctl(IOCTL_LUMEN_VHID_GAMEPAD_CREATE, &request, sizeof(request), &response, sizeof(response));
      }

      channel_result_t submit(const LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST &request) override {
        return ioctl(IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT, &request, sizeof(request), nullptr, 0);
      }

      channel_result_t destroy(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) override {
        return ioctl(IOCTL_LUMEN_VHID_GAMEPAD_DESTROY, &request, sizeof(request), nullptr, 0);
      }

      channel_result_t read_output(
        const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request,
        LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE &response
      ) override {
        auto result = ioctl(IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT, &request, sizeof(request), &response, sizeof(response));
        if (result.status == channel_status_e::failure && result.native_status == ERROR_NO_MORE_ITEMS) {
          result.status = channel_status_e::no_data;
        }
        return result;
      }

      channel_result_t reset(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) override {
        return ioctl(IOCTL_LUMEN_VHID_GAMEPAD_RESET_RUNTIME, &request, sizeof(request), nullptr, 0);
      }

      void close() noexcept override {
        std::lock_guard lock(mutex_);
        if (handle_ != INVALID_HANDLE_VALUE) {
          CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
        }
      }

    private:
      /**
       * @brief Create a failed channel result.
       *
       * @param status Win32 error value.
       * @return Failed channel result.
       */
      static channel_result_t failure(DWORD status) {
        return {channel_status_e::failure, status};
      }

      /**
       * @brief Execute one exact synchronous METHOD_BUFFERED request.
       *
       * @param code IOCTL code.
       * @param input Optional input buffer.
       * @param input_size Exact input size.
       * @param output Optional output buffer.
       * @param output_size Exact expected output size.
       * @return Exact channel result.
       */
      channel_result_t ioctl(
        DWORD code,
        const void *input,
        DWORD input_size,
        void *output,
        DWORD output_size
      ) {
        std::lock_guard lock(mutex_);
        if (handle_ == INVALID_HANDLE_VALUE) {
          return {channel_status_e::closed, ERROR_INVALID_HANDLE};
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
          const auto status = GetLastError();
          if (terminal_transport_error(status)) {
            CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
            return {channel_status_e::closed, status};
          }
          return failure(status);
        }
        if (transferred != output_size) {
          return failure(ERROR_INVALID_DATA);
        }
        return {};
      }

      std::mutex mutex_;  ///< Serializes synchronous operations on one file.
      HANDLE handle_ {INVALID_HANDLE_VALUE};  ///< Secured Lumen driver interface.
    };
#endif

    /**
     * @brief Convert a channel failure into a stable short diagnostic.
     *
     * @param operation Operation name.
     * @param result Channel result.
     * @return Diagnostic string.
     */
    std::string diagnostic(std::string_view operation, const channel_result_t &result) {
      return std::string {operation} + " failed with native status " + std::to_string(result.native_status);
    }

  }  // namespace

  virtual_hid_session_t::virtual_hid_session_t(std::shared_ptr<gamepad_channel_t> channel):
      channel_ {std::move(channel)} {
  }

  virtual_hid_session_t::~virtual_hid_session_t() {
    available_.store(false);
    {
      std::lock_guard lock(mutex_);
      stop_output_ = true;
      for (auto &[device_id, route] : routes_) {
        static_cast<void>(device_id);
        route.closing = true;
        route.callback = {};
      }
    }
    wake_.notify_all();
    if (output_thread_.joinable()) {
      output_thread_.request_stop();
      output_thread_.join();
    }

    std::vector<session_device_t> devices;
    {
      std::lock_guard lock(mutex_);
      devices.reserve(routes_.size());
      for (const auto &[device_id, route] : routes_) {
        static_cast<void>(device_id);
        devices.push_back(route.device);
      }
      routes_.clear();
    }
    if (channel_) {
      for (const auto &device : devices) {
        static_cast<void>(channel_->reset(authenticated_request(device.handle)));
        static_cast<void>(channel_->destroy(authenticated_request(device.handle)));
      }
      channel_->close();
    }
  }

  bool virtual_hid_session_t::initialize() {
    if (!channel_) {
      std::lock_guard lock(mutex_);
      failure_ = "dynamic-gamepad channel is null";
      return false;
    }
    if (available_.load()) {
      return true;
    }
    if (output_thread_.joinable()) {
      std::lock_guard lock(mutex_);
      failure_ = "dynamic-gamepad session cannot be reinitialized after channel loss";
      return false;
    }

    auto result = channel_->open();
    if (!result) {
      std::lock_guard lock(mutex_);
      failure_ = diagnostic("driver open", result);
      return false;
    }

    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE capabilities {};
    result = channel_->capabilities(capabilities);
    const std::uint32_t required_flags =
      LUMEN_VHID_GAMEPAD_CAPABILITY_OUTPUT_REPORTS |
      LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS |
      LUMEN_VHID_GAMEPAD_CAPABILITY_OWNER_CLEANUP |
      LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS;
    if (!result ||
        capabilities.version != LUMEN_VHID_GAMEPAD_ABI_VERSION ||
        capabilities.size != sizeof(capabilities) ||
        capabilities.base_abi_version != LUMEN_VHID_ABI_VERSION ||
        capabilities.max_devices == 0 ||
        capabilities.max_devices > LUMEN_VHID_MAX_GAMEPADS ||
        capabilities.max_input_report_size == 0 ||
        capabilities.max_output_report_size == 0 ||
        capabilities.max_input_report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
        capabilities.max_output_report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
        (capabilities.capability_flags & required_flags) != required_flags) {
      std::lock_guard lock(mutex_);
      failure_ = result ? "driver returned an incompatible dynamic-gamepad capability response" : diagnostic("capability query", result);
      channel_->close();
      return false;
    }

    {
      std::lock_guard lock(mutex_);
      capabilities_ = capabilities;
      failure_.clear();
      stop_output_ = false;
    }
    available_.store(true);
    output_thread_ = std::jthread([this](std::stop_token) {
      output_loop();
    });
    return true;
  }

  bool virtual_hid_session_t::available() const noexcept {
    return available_.load();
  }

  LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE virtual_hid_session_t::capabilities() const {
    std::lock_guard lock(mutex_);
    return capabilities_;
  }

  session_create_result_t virtual_hid_session_t::create(
    std::uint64_t client_device_id,
    std::uint32_t profile,
    output_callback_t callback
  ) {
    if (!available_.load()) {
      return {
        .success = false,
        .became_visible = false,
        .device = {},
        .native_status = 0,
        .error = "dynamic-gamepad session is unavailable",
      };
    }
    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE caps;
    {
      std::lock_guard lock(mutex_);
      caps = capabilities_;
    }
    if (profile >= LUMEN_VHID_GAMEPAD_PROFILE_COUNT ||
        profile == LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED ||
        (caps.supported_profiles & LUMEN_VHID_GAMEPAD_PROFILE_BIT(profile)) == 0) {
      return {
        .success = false,
        .became_visible = false,
        .device = {},
        .native_status = 0,
        .error = "requested dynamic-gamepad profile is unsupported",
      };
    }

    const LUMEN_VHID_GAMEPAD_CREATE_REQUEST request {
      .version = LUMEN_VHID_GAMEPAD_ABI_VERSION,
      .size = sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST),
      .client_device_id = client_device_id,
      .profile = profile,
      .reserved = 0,
    };
    LUMEN_VHID_GAMEPAD_CREATE_RESPONSE response {};
    const auto result = channel_->create(request, response);
    if (!result) {
      return {
        .success = false,
        .became_visible = false,
        .device = {},
        .native_status = result.native_status,
        .error = diagnostic("gamepad create", result),
      };
    }

    session_create_result_t created {
      .success = false,
      .became_visible = true,
      .device = {
        .handle = response.handle,
        .profile = response.profile,
        .feature_flags = response.feature_flags,
        .vendor_id = response.vendor_id,
        .product_id = response.product_id,
        .version_number = response.version_number,
        .input_report_id = response.input_report_id,
        .input_report_size = response.input_report_size,
        .output_report_size = response.output_report_size,
      },
      .native_status = 0,
      .error = {},
    };
    const bool valid =
      response.version == LUMEN_VHID_GAMEPAD_ABI_VERSION &&
      response.size == sizeof(response) &&
      response.handle.device_id != 0 &&
      response.handle.generation != 0 &&
      std::any_of(
        std::begin(response.handle.session_token),
        std::end(response.handle.session_token),
        [](std::uint8_t value) {
          return value != 0;
        }
      ) &&
      response.profile == profile &&
      response.input_report_size > 0 &&
      response.input_report_size <= caps.max_input_report_size &&
      response.output_report_size <= caps.max_output_report_size;
    if (!valid) {
      static_cast<void>(channel_->destroy(authenticated_request(response.handle)));
      created.error = "driver returned invalid dynamic-gamepad creation metadata";
      return created;
    }

    {
      std::lock_guard lock(mutex_);
      if (stop_output_ || routes_.contains(response.handle.device_id)) {
        static_cast<void>(channel_->destroy(authenticated_request(response.handle)));
        created.error = "driver returned a duplicate or closing dynamic-gamepad identity";
        return created;
      }
      routes_.emplace(
        response.handle.device_id,
        output_route_t {.device = created.device, .callback = std::move(callback)}
      );
    }
    wake_.notify_all();
    created.success = true;
    return created;
  }

  channel_result_t virtual_hid_session_t::submit(
    const session_device_t &device,
    std::span<const std::uint8_t> report
  ) {
    if (!available_.load() || report.empty() || report.size() > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
        report.size() != device.input_report_size) {
      return {channel_status_e::failure, 87};  // ERROR_INVALID_PARAMETER
    }
    {
      std::lock_guard lock(mutex_);
      const auto route = routes_.find(device.handle.device_id);
      if (route == routes_.end() || route->second.closing || !same_handle(route->second.device.handle, device.handle)) {
        return {channel_status_e::closed, 6};  // ERROR_INVALID_HANDLE
      }
    }

    LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST request {
      .version = LUMEN_VHID_GAMEPAD_ABI_VERSION,
      .size = sizeof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST),
      .handle = device.handle,
      .report_size = static_cast<std::uint32_t>(report.size()),
      .reserved = 0,
      .report = {},
    };
    std::copy(report.begin(), report.end(), request.report);
    return channel_->submit(request);
  }

  channel_result_t virtual_hid_session_t::destroy(const session_device_t &device) noexcept {
    {
      std::unique_lock lock(mutex_);
      const auto route = routes_.find(device.handle.device_id);
      if (route == routes_.end() || !same_handle(route->second.device.handle, device.handle)) {
        return {channel_status_e::closed, 6};  // ERROR_INVALID_HANDLE
      }
      route->second.closing = true;
      route->second.callback = {};
      const auto device_id = device.handle.device_id;
      const auto handle = device.handle;
      wake_.wait(lock, [this, device_id, &handle] {
        const auto current = routes_.find(device_id);
        return current == routes_.end() || !same_handle(current->second.device.handle, handle) ||
               current->second.in_flight == 0;
      });
    }

    const auto result = channel_->destroy(authenticated_request(device.handle));
    {
      std::lock_guard lock(mutex_);
      const auto route = routes_.find(device.handle.device_id);
      if (route != routes_.end() && same_handle(route->second.device.handle, device.handle)) {
        routes_.erase(route);
      }
    }
    wake_.notify_all();
    return result;
  }

  channel_result_t virtual_hid_session_t::reset(const session_device_t &device) noexcept {
    {
      std::lock_guard lock(mutex_);
      const auto route = routes_.find(device.handle.device_id);
      if (route == routes_.end() || route->second.closing || !same_handle(route->second.device.handle, device.handle)) {
        return {channel_status_e::closed, 6};  // ERROR_INVALID_HANDLE
      }
    }
    return channel_->reset(authenticated_request(device.handle));
  }

  std::string virtual_hid_session_t::failure() const {
    std::lock_guard lock(mutex_);
    return failure_;
  }

  void virtual_hid_session_t::output_loop() {
    while (true) {
      std::vector<session_device_t> devices;
      {
        std::unique_lock lock(mutex_);
        wake_.wait(lock, [this] {
          return stop_output_ || !routes_.empty();
        });
        if (stop_output_) {
          return;
        }
        devices.reserve(routes_.size());
        for (const auto &[device_id, route] : routes_) {
          static_cast<void>(device_id);
          if (!route.closing) {
            devices.push_back(route.device);
          }
        }
      }

      bool consumed = false;
      for (const auto &device : devices) {
        LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE response {};
        const auto read = channel_->read_output(authenticated_request(device.handle), response);
        if (read.status == channel_status_e::no_data) {
          continue;
        }
        if (!read) {
          if (read.status == channel_status_e::closed) {
            available_.store(false);
            {
              std::lock_guard lock(mutex_);
              failure_ = diagnostic("driver output channel", read);
              stop_output_ = true;
            }
            wake_.notify_all();
            return;
          }
          continue;
        }
        consumed = true;
        if (response.version != LUMEN_VHID_GAMEPAD_ABI_VERSION ||
            response.size != sizeof(response) ||
            response.report_size == 0 ||
            response.report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
            !same_handle(response.handle, device.handle)) {
          continue;
        }

        output_callback_t callback;
        session_device_t routed_device;
        {
          std::lock_guard lock(mutex_);
          auto route = routes_.find(response.handle.device_id);
          if (route == routes_.end() || route->second.closing ||
              !same_handle(route->second.device.handle, response.handle) || !route->second.callback) {
            continue;
          }
          ++route->second.in_flight;
          callback = route->second.callback;
          routed_device = route->second.device;
        }

        std::string callback_error;
        try {
          callback(routed_device, {response.report, response.report_size});
        } catch (const std::exception &error) {
          callback_error = std::string {"dynamic-gamepad output callback failed: "} + error.what();
        } catch (...) {
          callback_error = "dynamic-gamepad output callback failed with an unknown exception";
        }
        {
          std::lock_guard lock(mutex_);
          auto route = routes_.find(response.handle.device_id);
          if (route != routes_.end() && same_handle(route->second.device.handle, response.handle) && route->second.in_flight > 0) {
            --route->second.in_flight;
            if (!callback_error.empty()) {
              route->second.callback = {};
              failure_ = callback_error;
            }
          }
        }
        if (!callback_error.empty()) {
          BOOST_LOG(error) << callback_error;
        }
        wake_.notify_all();
      }

      if (!consumed) {
        std::unique_lock lock(mutex_);
        wake_.wait_for(lock, 4ms, [this] {
          return stop_output_;
        });
      }
    }
  }

  LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST virtual_hid_session_t::authenticated_request(
    const LUMEN_VHID_GAMEPAD_HANDLE &handle
  ) {
    return {
      .version = LUMEN_VHID_GAMEPAD_ABI_VERSION,
      .size = sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST),
      .handle = handle,
    };
  }

  bool virtual_hid_session_t::same_handle(
    const LUMEN_VHID_GAMEPAD_HANDLE &left,
    const LUMEN_VHID_GAMEPAD_HANDLE &right
  ) noexcept {
    return left.device_id == right.device_id &&
           left.generation == right.generation &&
           std::memcmp(left.session_token, right.session_token, sizeof(left.session_token)) == 0;
  }

  std::shared_ptr<gamepad_channel_t> make_system_gamepad_channel() {
#if defined(_WIN32)
    return std::make_shared<system_gamepad_channel_t>();
#else
    return {};
#endif
  }

}  // namespace platf::win_gamepad
