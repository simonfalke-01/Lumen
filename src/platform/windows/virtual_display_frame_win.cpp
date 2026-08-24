/**
 * @file src/platform/windows/virtual_display_frame_win.cpp
 * @brief Concrete Windows IOCTL, D3D11 import, fence, and slot-lifetime implementation.
 */

#if defined(_WIN32)

  // standard includes
  #include <algorithm>
  #include <atomic>
  #include <charconv>
  #include <cstdint>
  #include <limits>
  #include <mutex>
  #include <optional>
  #include <string>
  #include <string_view>
  #include <thread>
  #include <utility>
  #include <vector>

  // platform includes
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <d3d11_4.h>
  #include <dxgi1_6.h>
  #include <SetupAPI.h>
  #include <Windows.h>
  #include <wrl/client.h>

  // local includes
  #include "display.h"
  #include "fused_d3d11_policy.h"
  #include "src/logging.h"
  #include "src/utility.h"
  #include "src/video.h"
  #include "utf_utils.h"
  #include "virtual_display_driver/LumenVirtualDisplayProtocol.h"
  #include "virtual_display_driver/LumenVirtualDisplayGuids.h"
  #include "virtual_display_frame.h"

using Microsoft::WRL::ComPtr;
using namespace std::chrono_literals;
using namespace std::literals;

namespace platf::virtual_display {
  namespace {
    std::atomic_bool runtime_quarantined {false};  ///< Process-wide sticky direct-frame failure state.
    constexpr auto runtime_gate_env = "LUMEN_EXPERIMENTAL_VDD_DIRECT_FRAME";  ///< Explicit direct-frame enable gate.
    constexpr auto hardware_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_HARDWARE_VALIDATED";  ///< RTX 4060 acknowledgement.
    constexpr auto driver_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_VALIDATED_DRIVER";  ///< Exact validated UMD version.
    constexpr auto model_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_MODEL";  ///< Exact adapter description.
    constexpr auto luid_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_ADAPTER_LUID";  ///< Exact packed adapter LUID.
    constexpr auto device_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_DEVICE_ID";  ///< Exact PCI device ID.
    constexpr auto subsystem_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_SUBSYSTEM_ID";  ///< Exact PCI subsystem ID.
    constexpr auto revision_gate_env = "LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_REVISION";  ///< Exact PCI revision.

    /** @brief Pack a Windows LUID without changing its signed high-part bits. */
    std::uint64_t packed_luid(const LUID &luid) noexcept {
      return static_cast<std::uint64_t>(static_cast<std::uint32_t>(luid.HighPart)) << 32 |
             static_cast<std::uint64_t>(luid.LowPart);
    }

    /** @brief Convert a nonnegative QPC delta to nanoseconds without overflow. */
    std::optional<std::uint64_t> qpc_duration_ns(std::int64_t start, std::int64_t end) noexcept {
      LARGE_INTEGER frequency {};
      if (start <= 0 || end < start || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) {
        return std::nullopt;
      }
      const auto delta = static_cast<std::uint64_t>(end - start);
      const auto seconds = delta / static_cast<std::uint64_t>(frequency.QuadPart);
      const auto remainder = delta % static_cast<std::uint64_t>(frequency.QuadPart);
      if (seconds > std::numeric_limits<std::uint64_t>::max() / 1'000'000'000ULL) {
        return std::nullopt;
      }
      return seconds * 1'000'000'000ULL +
             remainder * 1'000'000'000ULL / static_cast<std::uint64_t>(frequency.QuadPart);
    }

    /** @brief Read one complete environment value. */
    std::optional<std::string> environment_value(const char *name) {
      const auto required = GetEnvironmentVariableA(name, nullptr, 0);
      if (required == 0) {
        return std::nullopt;
      }
      std::string value(required, '\0');
      const auto written = GetEnvironmentVariableA(name, value.data(), required);
      if (written == 0 || written >= required) {
        return std::nullopt;
      }
      value.resize(written);
      return value;
    }

    /** @brief Parse a complete unsigned decimal value. */
    std::optional<std::uint64_t> decimal_u64(std::string_view value) {
      std::uint64_t parsed = 0;
      const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed, 10);
      return result.ec == std::errc {} && result.ptr == value.data() + value.size() ?
               std::optional {parsed} :
               std::nullopt;
    }

    /** @brief Map one Win32 device-IO failure into the stable frame contract. */
    frame_io_e frame_error(const DWORD error) noexcept {
      switch (error) {
        case ERROR_NOT_READY:
        case ERROR_NO_MORE_ITEMS:
        case ERROR_RETRY:
          return frame_io_e::empty;
        case ERROR_REVISION_MISMATCH:
        case ERROR_INVALID_STATE:
          return frame_io_e::stale_generation;
        case ERROR_INVALID_DATA:
        case ERROR_INVALID_PARAMETER:
          return frame_io_e::invalid_data;
        case ERROR_NOT_SUPPORTED:
          return frame_io_e::unsupported;
        default:
          return frame_io_e::transport_error;
      }
    }

    /** @brief Open exactly one secured Lumen VDD device interface. */
    HANDLE open_device_interface() {
      HDEVINFO devices = SetupDiGetClassDevsW(
        &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
        nullptr,
        nullptr,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
      );
      if (devices == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
      }
      auto destroy_devices = util::fail_guard([&]() {
        SetupDiDestroyDeviceInfoList(devices);
      });

      SP_DEVICE_INTERFACE_DATA interface_data {sizeof(interface_data)};
      if (!SetupDiEnumDeviceInterfaces(
            devices,
            nullptr,
            &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
            0,
            &interface_data
          )) {
        return INVALID_HANDLE_VALUE;
      }
      SP_DEVICE_INTERFACE_DATA duplicate {sizeof(duplicate)};
      if (SetupDiEnumDeviceInterfaces(
            devices,
            nullptr,
            &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
            1,
            &duplicate
          ) ||
          GetLastError() != ERROR_NO_MORE_ITEMS) {
        SetLastError(ERROR_DUP_NAME);
        return INVALID_HANDLE_VALUE;
      }

      DWORD required = 0;
      SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, nullptr, 0, &required, nullptr);
      if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
        return INVALID_HANDLE_VALUE;
      }
      std::vector<std::byte> storage(required);
      auto *detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W *>(storage.data());
      detail->cbSize = sizeof(*detail);
      if (!SetupDiGetDeviceInterfaceDetailW(
            devices,
            &interface_data,
            detail,
            required,
            nullptr,
            nullptr
          )) {
        return INVALID_HANDLE_VALUE;
      }
      return CreateFileW(
        detail->DevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
      );
    }
  }  // namespace

  /** @brief Concrete production state hidden from the platform-neutral video configuration. */
  class frame_source_t::impl_t {
  public:
    explicit impl_t(const stream_selection_t &selection):
        generation {selection.generation},
        mode {selection.selected_mode} {
    }

    ~impl_t() {
      stop();
      if (availability_event != nullptr) {
        CloseHandle(std::exchange(availability_event, nullptr));
      }
      if (cancel_event != nullptr) {
        CloseHandle(std::exchange(cancel_event, nullptr));
      }
    }

    frame_io_e initialize(const std::chrono::milliseconds timeout) {
      if (runtime_quarantined.load(std::memory_order_acquire)) {
        return frame_io_e::unsupported;
      }
      const auto runtime_gate = environment_value(runtime_gate_env);
      const auto hardware_gate = environment_value(hardware_gate_env);
      const auto model_gate = environment_value(model_gate_env);
      const auto driver_gate = environment_value(driver_gate_env);
      const auto luid_gate = environment_value(luid_gate_env);
      const auto device_gate = environment_value(device_gate_env);
      const auto subsystem_gate = environment_value(subsystem_gate_env);
      const auto revision_gate = environment_value(revision_gate_env);
      const auto expected_driver = driver_gate ? decimal_u64(*driver_gate) : std::nullopt;
      const auto expected_luid = luid_gate ? decimal_u64(*luid_gate) : std::nullopt;
      const auto expected_device = device_gate ? decimal_u64(*device_gate) : std::nullopt;
      const auto expected_subsystem = subsystem_gate ? decimal_u64(*subsystem_gate) : std::nullopt;
      const auto expected_revision = revision_gate ? decimal_u64(*revision_gate) : std::nullopt;
      if (!runtime_gate || *runtime_gate != "1" || !hardware_gate || *hardware_gate != "RTX4060" ||
          !model_gate || !expected_driver || !expected_luid || !expected_device || !expected_subsystem ||
          !expected_revision || *expected_device > std::numeric_limits<std::uint32_t>::max() ||
          *expected_subsystem > std::numeric_limits<std::uint32_t>::max() ||
          *expected_revision > std::numeric_limits<std::uint8_t>::max() ||
          !::video::active_encoder_is_nvenc()) {
        return frame_io_e::unsupported;
      }

      device_handle = open_device_interface();
      if (device_handle == INVALID_HANDLE_VALUE) {
        return frame_error(GetLastError());
      }

      LUMEN_VDD_QUERY_ABI_RESPONSE abi {};
      const auto abi_status = ioctl(IOCTL_LUMEN_VDD_QUERY_ABI, nullptr, 0, &abi, sizeof(abi));
      if (abi_status != frame_io_e::ok || abi.abi_version != LUMEN_VDD_ABI_VERSION ||
          (abi.capability_flags & LUMEN_VDD_CAP_DIRECT_FRAME_V1) == 0) {
        stop();
        return abi_status == frame_io_e::ok ? frame_io_e::unsupported : abi_status;
      }

      cancel_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (cancel_event == nullptr) {
        stop();
        return frame_io_e::transport_error;
      }
      const LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST event_request {
        generation,
        GetCurrentProcessId(),
        0,
      };
      LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE event_response {};
      const auto event_status = ioctl(
        IOCTL_LUMEN_VDD_OPEN_FRAME_EVENT,
        &event_request,
        sizeof(event_request),
        &event_response,
        sizeof(event_response)
      );
      if (event_status != frame_io_e::ok || event_response.generation != generation ||
          event_response.event_handle == 0 || event_response.reserved != 0) {
        if (event_response.event_handle != 0) {
          CloseHandle(reinterpret_cast<HANDLE>(event_response.event_handle));
        }
        stop();
        return event_status == frame_io_e::ok ? frame_io_e::invalid_data : event_status;
      }
      availability_event = reinterpret_cast<HANDLE>(event_response.event_handle);

      const auto deadline = std::chrono::steady_clock::now() + std::max(timeout, 0ms);
      LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE response {};
      while (true) {
        const LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST request {
          generation,
          GetCurrentProcessId(),
          0,
        };
        const auto status = ioctl(
          IOCTL_LUMEN_VDD_OPEN_FRAME_CHANNEL,
          &request,
          sizeof(request),
          &response,
          sizeof(response)
        );
        if (status == frame_io_e::ok) {
          break;
        }
        if (status != frame_io_e::empty) {
          stop();
          return status;
        }
        const auto wait_status = wait_for_availability(deadline);
        if (wait_status != frame_io_e::ok) {
          stop();
          return wait_status;
        }
      }

      if (response.slot_count != LUMEN_VDD_FRAME_SLOT_COUNT ||
          response.texture_format != LUMEN_VDD_FRAME_FORMAT_BGRA8 ||
          !std::ranges::all_of(response.reserved, [](const std::uint64_t value) {
            return value == 0;
          })) {
        close_response_handles(response);
        stop();
        return frame_io_e::invalid_data;
      }
      resources = {
        response.generation,
        response.adapter_luid,
        response.width,
        response.height,
        frame_format_e::bgra8,
        response.slot_count,
        {
          static_cast<std::uintptr_t>(response.texture_handles[0]),
          static_cast<std::uintptr_t>(response.texture_handles[1]),
        },
        {
          static_cast<std::uintptr_t>(response.fence_handles[0]),
          static_cast<std::uintptr_t>(response.fence_handles[1]),
        },
      };
      if (!valid_frame_resources(resources, generation, mode)) {
        close_response_handles(response);
        stop();
        return frame_io_e::invalid_data;
      }

      ComPtr<IDXGIFactory1> factory;
      if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) {
        close_response_handles(response);
        stop();
        return frame_io_e::unsupported;
      }
      for (UINT index = 0;; ++index) {
        ComPtr<IDXGIAdapter1> candidate;
        if (factory->EnumAdapters1(index, &candidate) == DXGI_ERROR_NOT_FOUND) {
          break;
        }
        DXGI_ADAPTER_DESC1 description {};
        if (SUCCEEDED(candidate->GetDesc1(&description)) &&
            packed_luid(description.AdapterLuid) == resources.adapter_luid) {
          if (adapter) {
            close_response_handles(response);
            stop();
            return frame_io_e::invalid_data;
          }
          adapter = std::move(candidate);
        }
      }

      DXGI_ADAPTER_DESC1 description {};
      LARGE_INTEGER driver_version {};
      const auto probe = platf::dxgi::encoder_probe_device_identity();
      if (!adapter || FAILED(adapter->GetDesc1(&description)) || description.VendorId != 0x10de ||
          resources.adapter_luid != *expected_luid || description.DeviceId != *expected_device ||
          description.SubSysId != *expected_subsystem || description.Revision != *expected_revision ||
          utf_utils::to_utf8(description.Description) != *model_gate ||
          FAILED(adapter->CheckInterfaceSupport(IID_IDXGIDevice, &driver_version)) ||
          static_cast<std::uint64_t>(driver_version.QuadPart) != *expected_driver || !probe ||
          probe->adapter_luid != resources.adapter_luid ||
          probe->vendor_id != description.VendorId || probe->device_id != description.DeviceId ||
          probe->subsystem_id != description.SubSysId || probe->revision != description.Revision ||
          probe->driver_version != static_cast<std::uint64_t>(driver_version.QuadPart)) {
        close_response_handles(response);
        stop();
        return frame_io_e::unsupported;
      }

      const D3D_FEATURE_LEVEL levels[] {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
      D3D_FEATURE_LEVEL selected {};
      if (FAILED(D3D11CreateDevice(
            adapter.Get(),
            D3D_DRIVER_TYPE_UNKNOWN,
            nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            levels,
            ARRAYSIZE(levels),
            D3D11_SDK_VERSION,
            &device,
            &selected,
            &context
          )) ||
          FAILED(device.As(&device1)) || FAILED(device.As(&device5)) ||
          FAILED(context.As(&context4))) {
        close_response_handles(response);
        stop();
        return frame_io_e::unsupported;
      }
      ComPtr<ID3D11Multithread> multithread;
      if (FAILED(context.As(&multithread))) {
        close_response_handles(response);
        stop();
        return frame_io_e::unsupported;
      }
      multithread->SetMultithreadProtected(TRUE);

      auto close_import_handles = util::fail_guard([&]() {
        close_response_handles(response);
      });
      for (std::size_t slot = 0; slot < direct_frame_slot_count; ++slot) {
        if (FAILED(device1->OpenSharedResource1(
              reinterpret_cast<HANDLE>(resources.texture_handles[slot]),
              IID_PPV_ARGS(&textures[slot])
            )) ||
            FAILED(device5->OpenSharedFence(
              reinterpret_cast<HANDLE>(resources.fence_handles[slot]),
              IID_PPV_ARGS(&fences[slot])
            ))) {
          stop();
          return frame_io_e::unsupported;
        }
        D3D11_TEXTURE2D_DESC texture_desc {};
        textures[slot]->GetDesc(&texture_desc);
        if (texture_desc.Width != resources.width || texture_desc.Height != resources.height ||
            texture_desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM ||
            texture_desc.MipLevels != 1 || texture_desc.ArraySize != 1 ||
            texture_desc.SampleDesc.Count != 1) {
          stop();
          return frame_io_e::invalid_data;
        }
      }
      healthy = true;
      return frame_io_e::ok;
    }

    frame_acquire_result_t acquire(
      const std::chrono::milliseconds timeout,
      const std::shared_ptr<frame_source_t> &source
    ) {
      const auto deadline = std::chrono::steady_clock::now() + std::max(timeout, 0ms);
      while (true) {
        {
          std::lock_guard lock(mutex);
          if (!healthy) {
            return {frame_io_e::stopped, {}};
          }
          const LUMEN_VDD_DEQUEUE_FRAME_REQUEST request {generation};
          LUMEN_VDD_DEQUEUE_FRAME_RESPONSE response {};
          const auto status = ioctl(
            IOCTL_LUMEN_VDD_DEQUEUE_FRAME,
            &request,
            sizeof(request),
            &response,
            sizeof(response)
          );
          if (status == frame_io_e::ok) {
            const frame_descriptor_t frame {
              response.generation,
              response.sequence,
              response.producer_fence_value,
              response.capture_qpc,
              response.producer_signal_qpc,
              response.slot,
            };
            if (response.reserved != 0 || !valid_frame_descriptor(frame, resources) ||
                frame.sequence <= last_sequence || in_use[frame.slot] ||
                frame.producer_fence_value <= last_fence[frame.slot]) {
              fail_locked(true);
              return {frame_io_e::invalid_data, {}};
            }
            if (FAILED(context4->Wait(fences[frame.slot].Get(), frame.producer_fence_value))) {
              fail_locked(true);
              return {frame_io_e::unsupported, {}};
            }
            LARGE_INTEGER host_wait_qpc {};
            QueryPerformanceCounter(&host_wait_qpc);
            const auto driver_copy_ns = qpc_duration_ns(frame.capture_qpc, frame.producer_signal_qpc);
            const auto host_wait_ns = qpc_duration_ns(frame.producer_signal_qpc, host_wait_qpc.QuadPart);
            if (driver_copy_ns && host_wait_ns) {
              auto &telemetry = platf::dxgi::fused_d3d11::telemetry();
              telemetry.record_vdd_driver_copy(frame.generation, *driver_copy_ns);
              telemetry.record_vdd_host_wait(frame.generation, *host_wait_ns);
            }
            in_use[frame.slot] = true;
            leased_sequence[frame.slot] = frame.sequence;
            last_sequence = frame.sequence;
            last_fence[frame.slot] = frame.producer_fence_value;
            return {
              frame_io_e::ok,
              std::shared_ptr<frame_lease_t> {
                new frame_lease_t(source, frame, textures[frame.slot].Get())
              },
            };
          }
          if (status != frame_io_e::empty) {
            fail_locked(true);
            return {status, {}};
          }
        }
        const auto wait_status = wait_for_availability(deadline);
        if (wait_status != frame_io_e::ok) {
          return {wait_status, {}};
        }
      }
    }

    void release(const frame_descriptor_t &frame) noexcept {
      std::lock_guard lock(mutex);
      if (!healthy || frame.generation != generation || frame.slot >= direct_frame_slot_count ||
          !in_use[frame.slot] || leased_sequence[frame.slot] != frame.sequence ||
          last_fence[frame.slot] != frame.producer_fence_value) {
        fail_locked(true);
        return;
      }
      const auto consumer_fence = frame.producer_fence_value + 1;
      if (FAILED(context4->Signal(fences[frame.slot].Get(), consumer_fence))) {
        fail_locked(true);
        return;
      }
      const LUMEN_VDD_RELEASE_FRAME_REQUEST request {
        frame.generation,
        frame.sequence,
        frame.producer_fence_value,
        consumer_fence,
        frame.slot,
        0,
      };
      if (ioctl(IOCTL_LUMEN_VDD_RELEASE_FRAME, &request, sizeof(request), nullptr, 0) != frame_io_e::ok) {
        fail_locked(true);
        return;
      }
      in_use[frame.slot] = false;
      leased_sequence[frame.slot] = 0;
    }

    void stop() noexcept {
      std::lock_guard lock(mutex);
      fail_locked(false);
    }

    frame_io_e wait_for_availability(const std::chrono::steady_clock::time_point deadline) const noexcept {
      if (availability_event == nullptr || cancel_event == nullptr) {
        return frame_io_e::stopped;
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return frame_io_e::timeout;
      }
      const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      const auto timeout_ms = static_cast<DWORD>(std::clamp<std::int64_t>(
        remaining.count() + 1,
        1,
        static_cast<std::int64_t>(INFINITE - 1)
      ));
      const HANDLE waits[] {availability_event, cancel_event};
      const auto result = WaitForMultipleObjects(2, waits, FALSE, timeout_ms);
      if (result == WAIT_OBJECT_0) {
        return frame_io_e::ok;
      }
      if (result == WAIT_OBJECT_0 + 1) {
        return frame_io_e::stopped;
      }
      return result == WAIT_TIMEOUT ? frame_io_e::timeout : frame_io_e::transport_error;
    }

    frame_io_e ioctl(
      const DWORD code,
      const void *input,
      const DWORD input_size,
      void *output,
      const DWORD output_size
    ) const noexcept {
      if (device_handle == INVALID_HANDLE_VALUE) {
        return frame_io_e::stopped;
      }
      DWORD transferred = 0;
      if (!DeviceIoControl(
            device_handle,
            code,
            const_cast<void *>(input),
            input_size,
            output,
            output_size,
            &transferred,
            nullptr
          )) {
        return frame_error(GetLastError());
      }
      return transferred == output_size ? frame_io_e::ok : frame_io_e::invalid_data;
    }

    static void close_response_handles(const LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE &response) noexcept {
      for (std::size_t slot = 0; slot < LUMEN_VDD_FRAME_SLOT_COUNT; ++slot) {
        if (response.texture_handles[slot] != 0) {
          CloseHandle(reinterpret_cast<HANDLE>(response.texture_handles[slot]));
        }
        if (response.fence_handles[slot] != 0) {
          CloseHandle(reinterpret_cast<HANDLE>(response.fence_handles[slot]));
        }
      }
    }

    void fail_locked(bool quarantine) noexcept {
      if (quarantine) {
        runtime_quarantined.store(true, std::memory_order_release);
      }
      healthy = false;
      if (cancel_event != nullptr) {
        SetEvent(cancel_event);
      }
      if (device_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(std::exchange(device_handle, INVALID_HANDLE_VALUE));
      }
    }

    std::uint64_t generation {};  ///< Exact active driver generation.
    mode_t mode;  ///< Exact selected mode.
    mutable std::mutex mutex;  ///< Serializes IOCTLs and slot ownership.
    HANDLE device_handle {INVALID_HANDLE_VALUE};  ///< Concrete secured VDD device interface.
    HANDLE availability_event {};  ///< Driver-published resource/frame availability event.
    HANDLE cancel_event {};  ///< Host cancellation event for bounded waits.
    frame_resources_t resources;  ///< Validated imported resource metadata.
    ComPtr<IDXGIAdapter1> adapter;  ///< Exact IddCx render adapter.
    ComPtr<ID3D11Device> device;  ///< Import and conversion device.
    ComPtr<ID3D11Device1> device1;  ///< Shared texture import interface.
    ComPtr<ID3D11Device5> device5;  ///< Shared fence import interface.
    ComPtr<ID3D11DeviceContext> context;  ///< Multithread-protected immediate context.
    ComPtr<ID3D11DeviceContext4> context4;  ///< Fence wait/signal interface.
    std::array<ComPtr<ID3D11Texture2D>, direct_frame_slot_count> textures;  ///< Imported slots.
    std::array<ComPtr<ID3D11Fence>, direct_frame_slot_count> fences;  ///< Imported slot fences.
    std::array<bool, direct_frame_slot_count> in_use {};  ///< Host-owned slots.
    std::array<std::uint64_t, direct_frame_slot_count> leased_sequence {};  ///< Exact active slot sequences.
    std::array<std::uint64_t, direct_frame_slot_count> last_fence {};  ///< Last producer value per slot.
    std::uint64_t last_sequence {};  ///< Last globally dequeued sequence.
    bool healthy {};  ///< Sticky direct-path health.
  };

  frame_lease_t::frame_lease_t(
    std::shared_ptr<frame_source_t> source,
    frame_descriptor_t descriptor,
    void *native_texture
  ):
      source_ {std::move(source)},
      descriptor_ {descriptor},
      native_texture_ {native_texture} {
  }

  frame_lease_t::~frame_lease_t() {
    if (source_) {
      source_->release(descriptor_);
    }
  }

  const frame_descriptor_t &frame_lease_t::descriptor() const noexcept {
    return descriptor_;
  }

  void *frame_lease_t::native_texture() const noexcept {
    return native_texture_;
  }

  frame_source_t::frame_source_t(std::unique_ptr<impl_t> impl):
      impl_ {std::move(impl)} {
  }

  frame_source_t::~frame_source_t() = default;

  frame_acquire_result_t frame_source_t::acquire(const std::chrono::milliseconds timeout) {
    return impl_ ? impl_->acquire(timeout, shared_from_this()) : frame_acquire_result_t {};
  }

  void frame_source_t::stop() noexcept {
    if (impl_) {
      impl_->stop();
    }
  }

  bool frame_source_t::healthy() const noexcept {
    std::lock_guard lock(impl_->mutex);
    return impl_->healthy;
  }

  frame_resources_t frame_source_t::resources() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->resources;
  }

  void *frame_source_t::native_device() const noexcept {
    std::lock_guard lock(impl_->mutex);
    return impl_->healthy ? impl_->device.Get() : nullptr;
  }

  void *frame_source_t::native_context() const noexcept {
    std::lock_guard lock(impl_->mutex);
    return impl_->healthy ? impl_->context.Get() : nullptr;
  }

  void *frame_source_t::native_adapter() const noexcept {
    std::lock_guard lock(impl_->mutex);
    return impl_->healthy ? impl_->adapter.Get() : nullptr;
  }

  void frame_source_t::release(const frame_descriptor_t &frame) noexcept {
    if (impl_) {
      impl_->release(frame);
    }
  }

  std::shared_ptr<frame_source_t> make_system_frame_source(
    const stream_selection_t &selection,
    const std::chrono::milliseconds timeout
  ) {
    auto impl = std::make_unique<frame_source_t::impl_t>(selection);
    if (impl->initialize(timeout) != frame_io_e::ok) {
      return {};
    }
    auto source = std::shared_ptr<frame_source_t> {new frame_source_t(std::move(impl))};
    BOOST_LOG(info) << "Lumen VDD direct-frame one-copy path enabled for generation "sv
                    << selection.generation << "; two persistent shared texture/fence slots"sv;
    return source;
  }

  void quarantine_direct_frame_runtime() noexcept {
    runtime_quarantined.store(true, std::memory_order_release);
  }

  bool direct_frame_runtime_quarantined() noexcept {
    return runtime_quarantined.load(std::memory_order_acquire);
  }
}  // namespace platf::virtual_display

#endif
