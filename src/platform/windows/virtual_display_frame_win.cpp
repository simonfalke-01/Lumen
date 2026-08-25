/**
 * @file src/platform/windows/virtual_display_frame_win.cpp
 * @brief Concrete Windows IOCTL, D3D11 import, fence, and slot-lifetime implementation.
 */

#if defined(_WIN32)

  // standard includes
  #include <algorithm>
  #include <atomic>
#include <cmath>
  #include <cstdint>
#include <cstring>
  #include <limits>
  #include <mutex>
  #include <optional>
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
  #include "virtual_display_driver/LumenVirtualDisplayProtocol.h"
  #include "virtual_display_driver/LumenVirtualDisplayGuids.h"
  #include "virtual_display_driver/LumenDirectFrameSlotPolicy.h"
  #include "virtual_display_frame.h"
  #include "virtual_display_status.h"

using Microsoft::WRL::ComPtr;
using namespace std::chrono_literals;
using namespace std::literals;

namespace platf::virtual_display {
  namespace {
    std::atomic_bool runtime_quarantined {false};  ///< Process-wide sticky direct-frame failure state.

    /** @brief Pack a Windows LUID without changing its signed high-part bits. */
    std::uint64_t packed_luid(const LUID &luid) noexcept {
      return static_cast<std::uint64_t>(static_cast<std::uint32_t>(luid.HighPart)) << 32 |
             static_cast<std::uint64_t>(luid.LowPart);
    }

    /** @brief Pack a process creation FILETIME for PID-reuse-safe source validation. */
    std::uint64_t packed_process_creation_time(HANDLE process) noexcept {
      FILETIME creation {};
      FILETIME exit {};
      FILETIME kernel {};
      FILETIME user {};
      if (process == nullptr || !GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        return 0;
      }
      return static_cast<std::uint64_t>(creation.dwHighDateTime) << 32U | creation.dwLowDateTime;
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

    frame_hdr10_metadata_t frame_hdr10_metadata(const LUMEN_VDD_HDR10_METADATA &metadata) noexcept {
      return {
        {metadata.red_primary[0], metadata.red_primary[1]},
        {metadata.green_primary[0], metadata.green_primary[1]},
        {metadata.blue_primary[0], metadata.blue_primary[1]},
        {metadata.white_point[0], metadata.white_point[1]},
        metadata.maximum_mastering_luminance,
        metadata.minimum_mastering_luminance,
        metadata.maximum_content_light_level,
        metadata.maximum_frame_average_light_level,
      };
    }

    std::optional<frame_color_metadata_t> frame_color_metadata(
      const std::uint32_t color_space,
      const std::uint32_t sdr_white_level_nits,
      const std::uint32_t hdr_metadata_type,
      const std::uint32_t reserved,
      const LUMEN_VDD_HDR10_METADATA &metadata,
      const dynamic_range_e dynamic_range,
      const frame_format_e format
    ) noexcept {
      if (reserved != 0 || color_space < LUMEN_VDD_COLOR_SPACE_SRGB ||
          color_space > LUMEN_VDD_COLOR_SPACE_HDR10 || hdr_metadata_type > LUMEN_VDD_HDR_METADATA_NEW) {
        return std::nullopt;
      }
      const frame_color_metadata_t converted {
        static_cast<frame_color_space_e>(color_space),
        sdr_white_level_nits,
        static_cast<hdr_metadata_type_e>(hdr_metadata_type),
        frame_hdr10_metadata(metadata),
      };
      return valid_frame_color_metadata(converted, dynamic_range, format) ?
               std::optional {converted} :
               std::nullopt;
    }

    bool zero_bytes(const std::uint8_t *data, const std::size_t size) noexcept {
      return std::all_of(data, data + size, [](const std::uint8_t value) {
        return value == 0;
      });
    }

    std::shared_ptr<const color_transform_t> color_transform(
      const LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE &response
    ) {
      auto transform = std::make_shared<color_transform_t>();
      transform->generation = response.generation;
      transform->version = response.transform_version;
      if (response.gamma_ramp_type == LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT) {
        if (response.payload_size != 0 ||
            !zero_bytes(response.payload.storage, sizeof(response.payload.storage))) {
          return {};
        }
        transform->type = color_transform_type_e::default_;
        transform->payload = std::monostate {};
      } else if (response.gamma_ramp_type == LUMEN_VDD_GAMMA_RAMP_TYPE_RGB256X3X16) {
        if (response.payload_size != sizeof(response.payload.rgb256x3x16) ||
            !zero_bytes(
              response.payload.storage + response.payload_size,
              sizeof(response.payload.storage) - response.payload_size
            )) {
          return {};
        }
        color_transform_rgb256_t payload;
        std::ranges::copy(response.payload.rgb256x3x16.red, payload.red.begin());
        std::ranges::copy(response.payload.rgb256x3x16.green, payload.green.begin());
        std::ranges::copy(response.payload.rgb256x3x16.blue, payload.blue.begin());
        transform->type = color_transform_type_e::rgb256x3x16;
        transform->payload = std::move(payload);
      } else if (response.gamma_ramp_type == LUMEN_VDD_GAMMA_RAMP_TYPE_3X4_COLORSPACE_TRANSFORM) {
        const auto &input = response.payload.transform_3x4;
        if (response.payload_size != sizeof(input) || input.matrix_enabled > 1 || input.lut_enabled > 1) {
          return {};
        }
        color_transform_3x4_t payload;
        payload.matrix_enabled = input.matrix_enabled != 0;
        std::memcpy(payload.color_matrix_3x4.data(), input.color_matrix_3x4, sizeof(input.color_matrix_3x4));
        payload.scalar_multiplier = input.scalar_multiplier;
        payload.lut_enabled = input.lut_enabled != 0;
        for (std::size_t index = 0; index < color_transform_lut_entry_count; ++index) {
          payload.lookup_table_1d[index] = {
            input.lookup_table_1d[index].red,
            input.lookup_table_1d[index].green,
            input.lookup_table_1d[index].blue,
          };
        }
        transform->type = color_transform_type_e::colorspace_3x4;
        transform->payload = std::move(payload);
      } else {
        return {};
      }
      return prepare_color_transform(*transform) ? transform : std::shared_ptr<const color_transform_t> {};
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

  direct_frame_handle_identity_e compare_direct_frame_handle_identity(
    const std::uintptr_t first,
    const std::uintptr_t second
  ) noexcept {
    using compare_object_handles_fn = BOOL(WINAPI *)(HANDLE, HANDLE);
    static const auto compare_handles = []() -> compare_object_handles_fn {
      const auto kernel32 = GetModuleHandleW(L"kernel32.dll");
      return kernel32 == nullptr ?
               nullptr :
               reinterpret_cast<compare_object_handles_fn>(GetProcAddress(kernel32, "CompareObjectHandles"));
    }();

    if (first == 0 || second == 0 || compare_handles == nullptr) {
      return direct_frame_handle_identity_e::unavailable_or_error;
    }
    if (first == second) {
      return direct_frame_handle_identity_e::alias;
    }

    SetLastError(ERROR_SUCCESS);
    if (compare_handles(reinterpret_cast<HANDLE>(first), reinterpret_cast<HANDLE>(second))) {
      return direct_frame_handle_identity_e::alias;
    }
    return GetLastError() == ERROR_NOT_SAME_OBJECT ?
             direct_frame_handle_identity_e::distinct :
             direct_frame_handle_identity_e::unavailable_or_error;
  }

  /** @brief Concrete production state hidden from the platform-neutral video configuration. */
  class frame_source_t::impl_t {
  public:
    explicit impl_t(const stream_selection_t &selection):
        generation {selection.generation},
        mode {selection.selected_mode} {
      if (selection.render_adapter) {
        frozen_probe_identity = direct_frame_adapter_identity_t {
          selection.render_adapter->adapter_luid,
          selection.render_adapter->vendor_id,
          selection.render_adapter->device_id,
          selection.render_adapter->subsystem_id,
          selection.render_adapter->revision,
          selection.render_adapter->driver_version,
        };
      }
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
      const bool nvenc_active = ::video::active_encoder_is_nvenc();
      if (runtime_quarantined.load(std::memory_order_acquire) || !nvenc_active) {
        return frame_io_e::unsupported;
      }

      device_handle = open_device_interface();
      if (device_handle == INVALID_HANDLE_VALUE) {
        return frame_error(GetLastError());
      }

      LUMEN_VDD_QUERY_ABI_RESPONSE abi {};
      const auto abi_status = ioctl(IOCTL_LUMEN_VDD_QUERY_ABI, nullptr, 0, &abi, sizeof(abi));
      const std::uint32_t required_capabilities = LUMEN_VDD_CAP_DIRECT_FRAME_V1 |
                                                  LUMEN_VDD_CAP_FRAME_METADATA_V2 |
                                                  LUMEN_VDD_CAP_COLOR_TRANSFORM_V1 |
                                                  (mode.dynamic_range == dynamic_range_e::hdr10 ?
                                                     LUMEN_VDD_CAP_HDR10 |
                                                       LUMEN_VDD_CAP_10BIT |
                                                       LUMEN_VDD_CAP_DIRECT_FRAME_FP16 :
                                                     LUMEN_VDD_CAP_SDR8);
      if (abi_status != frame_io_e::ok || abi.abi_version != LUMEN_VDD_ABI_VERSION ||
          (abi.capability_flags & required_capabilities) != required_capabilities) {
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
          event_response.source_process_id == 0 || event_response.source_reserved != 0 ||
          event_response.source_process_creation_time == 0 || event_response.event_handle == 0 ||
          event_response.reserved != 0 ||
          !bind_source_process(
            event_response.source_process_id,
            event_response.source_process_creation_time
          ) ||
          !duplicate_source_handle(event_response.event_handle, availability_event)) {
        stop();
        return event_status == frame_io_e::ok ? frame_io_e::invalid_data : event_status;
      }

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

      if (response.generation != generation || response.source_process_id != source_process_id ||
          response.source_reserved != 0 || response.source_process_creation_time != source_process_creation_time ||
          response.slot_count != LUMEN_VDD_FRAME_SLOT_COUNT ||
          (response.texture_format != LUMEN_VDD_FRAME_FORMAT_BGRA8 &&
           response.texture_format != LUMEN_VDD_FRAME_FORMAT_RGBA16_FLOAT) ||
          response.color_transform_version == 0 || response.reserved != 0) {
        stop();
        return frame_io_e::invalid_data;
      }
      if (!duplicate_response_handles(response)) {
        stop();
        return frame_io_e::transport_error;
      }
      const auto format = response.texture_format == LUMEN_VDD_FRAME_FORMAT_RGBA16_FLOAT ?
                            frame_format_e::rgba16_float :
                            frame_format_e::bgra8;
      const auto initial_color_metadata = frame_color_metadata(
        response.initial_surface_color_space,
        response.initial_sdr_white_level_nits,
        response.initial_hdr_metadata_type,
        response.initial_metadata_reserved,
        response.initial_hdr10_metadata,
        mode.dynamic_range,
        format
      );
      if (!initial_color_metadata) {
        close_response_handles(response);
        stop();
        return frame_io_e::invalid_data;
      }
      resources = {
        response.generation,
        response.adapter_luid,
        response.width,
        response.height,
        format,
        mode.dynamic_range,
        response.slot_count,
        {
          static_cast<std::uintptr_t>(response.texture_handles[0]),
          static_cast<std::uintptr_t>(response.texture_handles[1]),
        },
        {
          static_cast<std::uintptr_t>(response.fence_handles[0]),
          static_cast<std::uintptr_t>(response.fence_handles[1]),
        },
        response.color_transform_version,
        *initial_color_metadata,
      };
      if (!valid_frame_resources(resources, generation, mode)) {
        close_response_handles(response);
        stop();
        return frame_io_e::invalid_data;
      }
      if (!resolve_color_transform(response.color_transform_version)) {
        close_response_handles(response);
        stop();
        return frame_io_e::invalid_data;
      }
      const auto texture_identity = compare_direct_frame_handle_identity(
        resources.texture_handles[0],
        resources.texture_handles[1]
      );
      const auto fence_identity = compare_direct_frame_handle_identity(
        resources.fence_handles[0],
        resources.fence_handles[1]
      );
      if (texture_identity == direct_frame_handle_identity_e::alias ||
          fence_identity == direct_frame_handle_identity_e::alias) {
        runtime_quarantined.store(true, std::memory_order_release);
        close_response_handles(response);
        stop();
        return frame_io_e::invalid_data;
      }
      if (texture_identity == direct_frame_handle_identity_e::unavailable_or_error ||
          fence_identity == direct_frame_handle_identity_e::unavailable_or_error) {
        BOOST_LOG(warning)
          << "Windows cannot compare one or more VDD shared kernel-handle types; "sv
             "relying on driver-side resource identity validation"sv;
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
      if (!adapter || FAILED(adapter->GetDesc1(&description)) ||
          FAILED(adapter->CheckInterfaceSupport(IID_IDXGIDevice, &driver_version))) {
        close_response_handles(response);
        stop();
        return frame_io_e::unsupported;
      }
      const direct_frame_adapter_identity_t imported_identity {
        packed_luid(description.AdapterLuid),
        description.VendorId,
        description.DeviceId,
        description.SubSysId,
        description.Revision,
        static_cast<std::uint64_t>(driver_version.QuadPart),
      };
      if (resources.adapter_luid != imported_identity.adapter_luid ||
          !valid_direct_frame_adapter_binding(nvenc_active, imported_identity, frozen_probe_identity)) {
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
            FAILED(textures[slot].As(&keyed_mutexes[slot])) ||
            FAILED(device5->OpenSharedFence(
              reinterpret_cast<HANDLE>(resources.fence_handles[slot]),
              IID_PPV_ARGS(&fences[slot])
            ))) {
          stop();
          return frame_io_e::unsupported;
        }
        D3D11_TEXTURE2D_DESC texture_desc {};
        textures[slot]->GetDesc(&texture_desc);
        const auto expected_texture_format = resources.format == frame_format_e::rgba16_float ?
                                               DXGI_FORMAT_R16G16B16A16_FLOAT :
                                               DXGI_FORMAT_B8G8R8A8_UNORM;
        if (texture_desc.Width != resources.width || texture_desc.Height != resources.height ||
            texture_desc.Format != expected_texture_format ||
            texture_desc.MipLevels != 1 || texture_desc.ArraySize != 1 ||
            texture_desc.SampleDesc.Count != 1 || texture_desc.Usage != D3D11_USAGE_DEFAULT ||
            (texture_desc.BindFlags & D3D11_BIND_SHADER_RESOURCE) == 0 ||
            texture_desc.CPUAccessFlags != 0 ||
            (texture_desc.MiscFlags &
             (D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX)) !=
              (D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX)) {
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
            const auto color_metadata = frame_color_metadata(
              response.surface_color_space,
              response.sdr_white_level_nits,
              response.hdr_metadata_type,
              response.metadata_reserved,
              response.hdr10_metadata,
              resources.dynamic_range,
              resources.format
            );
            if (!color_metadata) {
              fail_locked(true);
              return {frame_io_e::invalid_data, {}};
            }
            const frame_descriptor_t frame {
              response.generation,
              response.sequence,
              response.producer_fence_value,
              response.capture_qpc,
              response.producer_signal_qpc,
              response.slot,
              response.color_transform_version,
              *color_metadata,
            };
            if (response.reserved != 0 || !valid_frame_descriptor(frame, resources) ||
                frame.sequence <= last_sequence || in_use[frame.slot] ||
                frame.producer_fence_value <= last_fence[frame.slot]) {
              fail_locked(true);
              return {frame_io_e::invalid_data, {}};
            }
            auto transform = resolve_color_transform(frame.color_transform_version);
            if (!transform) {
              fail_locked(true);
              return {frame_io_e::invalid_data, {}};
            }
            if (keyed_mutexes[frame.slot]->AcquireSync(
                  lumen::vdd::frame::host_acquire_key(frame.producer_fence_value),
                  0
                ) != S_OK) {
              fail_locked(true);
              return {frame_io_e::unsupported, {}};
            }
            keyed_owned[frame.slot] = true;
            if (FAILED(context4->Wait(fences[frame.slot].Get(), frame.producer_fence_value))) {
              static_cast<void>(keyed_mutexes[frame.slot]->ReleaseSync(
                lumen::vdd::frame::producer_return_key(frame.producer_fence_value)
              ));
              keyed_owned[frame.slot] = false;
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
                new frame_lease_t(source, frame, textures[frame.slot].Get(), std::move(transform))
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
      const auto consumer_fence = lumen::vdd::frame::producer_return_key(frame.producer_fence_value);
      if (FAILED(context4->Signal(fences[frame.slot].Get(), consumer_fence))) {
        static_cast<void>(keyed_mutexes[frame.slot]->ReleaseSync(consumer_fence));
        keyed_owned[frame.slot] = false;
        fail_locked(true);
        return;
      }
      if (keyed_mutexes[frame.slot]->ReleaseSync(consumer_fence) != S_OK) {
        fail_locked(true);
        return;
      }
      keyed_owned[frame.slot] = false;
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

    std::shared_ptr<const color_transform_t> resolve_color_transform(const std::uint64_t version) {
      if (auto cached = color_transforms.find(generation, version)) {
        return cached;
      }
      try {
        const LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST request {generation, version};
        auto response = std::make_unique<LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE>();
        if (ioctl(
              IOCTL_LUMEN_VDD_QUERY_COLOR_TRANSFORM,
              &request,
              sizeof(request),
              response.get(),
              sizeof(*response)
            ) != frame_io_e::ok ||
            response->generation != generation || response->transform_version != version) {
          return {};
        }
        auto parsed = color_transform(*response);
        if (!parsed || !color_transforms.commit(parsed)) {
          return {};
        }
        return parsed;
      } catch (...) {
        return {};
      }
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

    bool bind_source_process(const std::uint32_t process_id, const std::uint64_t creation_time) noexcept {
      if (source_process != nullptr) {
        return process_id == source_process_id && creation_time == source_process_creation_time &&
               WaitForSingleObject(source_process, 0) == WAIT_TIMEOUT;
      }
      HANDLE process = OpenProcess(PROCESS_DUP_HANDLE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
      if (process == nullptr || WaitForSingleObject(process, 0) != WAIT_TIMEOUT ||
          packed_process_creation_time(process) != creation_time) {
        if (process != nullptr) {
          CloseHandle(process);
        }
        return false;
      }
      source_process = process;
      source_process_id = process_id;
      source_process_creation_time = creation_time;
      return true;
    }

    bool duplicate_source_handle(const std::uint64_t raw_source, HANDLE &duplicate) const noexcept {
      duplicate = nullptr;
      return source_process != nullptr && raw_source != 0 && WaitForSingleObject(source_process, 0) == WAIT_TIMEOUT &&
             DuplicateHandle(
               source_process,
               reinterpret_cast<HANDLE>(raw_source),
               GetCurrentProcess(),
               &duplicate,
               0,
               FALSE,
               DUPLICATE_SAME_ACCESS
             );
    }

    bool duplicate_response_handles(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE &response) const noexcept {
      std::array<HANDLE, LUMEN_VDD_FRAME_SLOT_COUNT * 2> duplicates {};
      std::size_t count = 0;
      const auto close_partial = [&]() {
        for (std::size_t index = 0; index < count; ++index) {
          CloseHandle(duplicates[index]);
        }
      };
      for (std::size_t slot = 0; slot < LUMEN_VDD_FRAME_SLOT_COUNT; ++slot) {
        if (!duplicate_source_handle(response.texture_handles[slot], duplicates[count])) {
          close_partial();
          return false;
        }
        ++count;
      }
      for (std::size_t slot = 0; slot < LUMEN_VDD_FRAME_SLOT_COUNT; ++slot) {
        if (!duplicate_source_handle(response.fence_handles[slot], duplicates[count])) {
          close_partial();
          return false;
        }
        ++count;
      }
      for (std::size_t slot = 0; slot < LUMEN_VDD_FRAME_SLOT_COUNT; ++slot) {
        response.texture_handles[slot] = reinterpret_cast<std::uint64_t>(duplicates[slot]);
        response.fence_handles[slot] = reinterpret_cast<std::uint64_t>(
          duplicates[LUMEN_VDD_FRAME_SLOT_COUNT + slot]
        );
      }
      return true;
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
      report_direct_frame_stopped(generation, quarantine);
      for (std::size_t slot = 0; slot < direct_frame_slot_count; ++slot) {
        if (keyed_owned[slot] && keyed_mutexes[slot] && last_fence[slot] != std::numeric_limits<std::uint64_t>::max()) {
          static_cast<void>(keyed_mutexes[slot]->ReleaseSync(
            lumen::vdd::frame::producer_return_key(last_fence[slot])
          ));
          keyed_owned[slot] = false;
        }
      }
      if (cancel_event != nullptr) {
        SetEvent(cancel_event);
      }
      if (device_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(std::exchange(device_handle, INVALID_HANDLE_VALUE));
      }
      if (source_process != nullptr) {
        CloseHandle(std::exchange(source_process, nullptr));
      }
      color_transforms.clear();
    }

    std::uint64_t generation {};  ///< Exact active driver generation.
    mode_t mode;  ///< Exact selected mode.
    std::optional<direct_frame_adapter_identity_t> frozen_probe_identity;  ///< Encoder identity frozen at selection.
    mutable std::mutex mutex;  ///< Serializes IOCTLs and slot ownership.
    HANDLE device_handle {INVALID_HANDLE_VALUE};  ///< Concrete secured VDD device interface.
    HANDLE source_process {};  ///< Validated live WUDFHost source for reverse handle duplication.
    std::uint32_t source_process_id {};  ///< Exact source PID retained with its process handle.
    std::uint64_t source_process_creation_time {};  ///< Exact source creation FILETIME preventing PID reuse.
    HANDLE availability_event {};  ///< Driver-published resource/frame availability event.
    HANDLE cancel_event {};  ///< Host cancellation event for bounded waits.
    frame_resources_t resources;  ///< Validated imported resource metadata.
    color_transform_cache_t color_transforms;  ///< Driver-matched current and previous immutable transforms.
    ComPtr<IDXGIAdapter1> adapter;  ///< Exact IddCx render adapter.
    ComPtr<ID3D11Device> device;  ///< Import and conversion device.
    ComPtr<ID3D11Device1> device1;  ///< Shared texture import interface.
    ComPtr<ID3D11Device5> device5;  ///< Shared fence import interface.
    ComPtr<ID3D11DeviceContext> context;  ///< Multithread-protected immediate context.
    ComPtr<ID3D11DeviceContext4> context4;  ///< Fence wait/signal interface.
    std::array<ComPtr<ID3D11Texture2D>, direct_frame_slot_count> textures;  ///< Imported slots.
    std::array<ComPtr<IDXGIKeyedMutex>, direct_frame_slot_count> keyed_mutexes;  ///< Imported ownership handoffs.
    std::array<ComPtr<ID3D11Fence>, direct_frame_slot_count> fences;  ///< Imported slot fences.
    std::array<bool, direct_frame_slot_count> in_use {};  ///< Host-owned slots.
    std::array<bool, direct_frame_slot_count> keyed_owned {};  ///< Host currently owns each keyed mutex.
    std::array<std::uint64_t, direct_frame_slot_count> leased_sequence {};  ///< Exact active slot sequences.
    std::array<std::uint64_t, direct_frame_slot_count> last_fence {};  ///< Last producer value per slot.
    std::uint64_t last_sequence {};  ///< Last globally dequeued sequence.
    bool healthy {};  ///< Sticky direct-path health.
  };

  frame_lease_t::frame_lease_t(
    std::shared_ptr<frame_source_t> source,
    frame_descriptor_t descriptor,
    void *native_texture,
    std::shared_ptr<const color_transform_t> color_transform
  ):
      source_ {std::move(source)},
      descriptor_ {descriptor},
      native_texture_ {native_texture},
      color_transform_ {std::move(color_transform)} {
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

  const std::shared_ptr<const color_transform_t> &frame_lease_t::color_transform() const noexcept {
    return color_transform_;
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
      impl.reset();
      report_direct_frame_fallback(selection.generation);
      return {};
    }
    auto source = std::shared_ptr<frame_source_t> {new frame_source_t(std::move(impl))};
    report_direct_frame_bound(selection.generation);
    BOOST_LOG(info) << "Lumen VDD direct-frame one-copy path enabled for generation "sv
                    << selection.generation << "; two persistent shared texture/fence slots"sv;
    return source;
  }

  void quarantine_direct_frame_runtime() noexcept {
    runtime_quarantined.store(true, std::memory_order_release);
    report_direct_frame_quarantined();
  }

  bool direct_frame_runtime_quarantined() noexcept {
    return runtime_quarantined.load(std::memory_order_acquire);
  }
}  // namespace platf::virtual_display

#endif
