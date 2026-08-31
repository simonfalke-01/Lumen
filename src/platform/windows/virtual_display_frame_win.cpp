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
#include <sstream>
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
  #include "fused_d3d11_policy.h"
  #include "src/logging.h"
  #include "src/utility.h"
  #include "src/video.h"
  #include "virtual_display_driver/LumenVirtualDisplayProtocol.h"
  #include "virtual_display_driver/LumenVirtualDisplayGuids.h"
  #include "virtual_display_driver/LumenDirectFrameSlotPolicy.h"
  #include "virtual_display_frame.h"
  #include "virtual_display_process_access.h"
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
    std::uint64_t packed_process_creation_time(HANDLE process, DWORD *native_status = nullptr) noexcept {
      if (native_status != nullptr) {
        *native_status = ERROR_SUCCESS;
      }
      FILETIME creation {};
      FILETIME exit {};
      FILETIME kernel {};
      FILETIME user {};
      if (process == nullptr || !GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        if (native_status != nullptr) {
          *native_status = process == nullptr ? ERROR_INVALID_HANDLE : GetLastError();
        }
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
      auto semantic_error = frame_transport_error_e::other;
      switch (error) {
        case ERROR_NOT_READY:
          semantic_error = frame_transport_error_e::not_ready;
          break;
        case ERROR_NO_MORE_ITEMS:
          semantic_error = frame_transport_error_e::no_more_items;
          break;
        case ERROR_RETRY:
          semantic_error = frame_transport_error_e::retry;
          break;
        case ERROR_REVISION_MISMATCH:
          semantic_error = frame_transport_error_e::revision_mismatch;
          break;
        case ERROR_INVALID_STATE:
          semantic_error = frame_transport_error_e::invalid_state;
          break;
        case ERROR_INVALID_DATA:
          semantic_error = frame_transport_error_e::invalid_data;
          break;
        case ERROR_INVALID_PARAMETER:
          semantic_error = frame_transport_error_e::invalid_parameter;
          break;
        case ERROR_NOT_SUPPORTED:
          semantic_error = frame_transport_error_e::not_supported;
          break;
        default:
          break;
      }
      return frame_io_from_transport_error(semantic_error);
    }

    /** @brief Open exactly one secured Lumen VDD device interface. */
    HANDLE open_device_interface(DWORD &native_status) {
      native_status = ERROR_SUCCESS;
      HDEVINFO devices = SetupDiGetClassDevsW(
        &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
        nullptr,
        nullptr,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
      );
      if (devices == INVALID_HANDLE_VALUE) {
        native_status = GetLastError();
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
        native_status = GetLastError();
        return INVALID_HANDLE_VALUE;
      }
      SP_DEVICE_INTERFACE_DATA duplicate {sizeof(duplicate)};
      const auto duplicate_found = SetupDiEnumDeviceInterfaces(
        devices,
        nullptr,
        &GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY,
        1,
        &duplicate
      );
      const auto duplicate_status = duplicate_found ? ERROR_SUCCESS : GetLastError();
      if (duplicate_found || duplicate_status != ERROR_NO_MORE_ITEMS) {
        native_status = duplicate_found ? ERROR_DUP_NAME : duplicate_status;
        return INVALID_HANDLE_VALUE;
      }

      DWORD required = 0;
      SetupDiGetDeviceInterfaceDetailW(devices, &interface_data, nullptr, 0, &required, nullptr);
      if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)) {
        native_status = GetLastError();
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
        native_status = GetLastError();
        return INVALID_HANDLE_VALUE;
      }
      const auto handle = CreateFileW(
        detail->DevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
        nullptr
      );
      if (handle == INVALID_HANDLE_VALUE) {
        native_status = GetLastError();
      }
      return handle;
    }

    /** @brief Render one complete stable direct-frame initialization diagnostic. */
    std::string direct_frame_init_diagnostic_text(const direct_frame_init_diagnostic_t &diagnostic) {
      std::ostringstream output;
      output << "stage=" << direct_frame_init_stage_label(diagnostic.stage)
             << ", domain=" << direct_frame_native_domain_label(diagnostic.domain)
             << ", result=" << direct_frame_init_result_label(diagnostic.result)
             << ", native_status=" << diagnostic.native_status
             << ", generation=" << diagnostic.generation
             << ", abi=" << diagnostic.abi_version
             << ", expected_abi=" << diagnostic.expected_abi_version
             << ", capabilities=" << diagnostic.capability_flags
             << ", required_capabilities=" << diagnostic.required_capabilities
             << ", expected_adapter_luid=" << diagnostic.expected_adapter_luid
             << ", selection_preference_submitted=" << diagnostic.selection_preference_submitted
             << ", resource_adapter_luid=" << diagnostic.resource_adapter_luid
             << ", publisher_process_id=" << diagnostic.publisher_process_id
             << ", publisher_process_creation_time=" << diagnostic.publisher_process_creation_time
             << ", handle_kind=" << direct_frame_handle_kind_label(diagnostic.handle_kind)
             << ", handle_slot=" << diagnostic.handle_slot
             << ", adapter_enumeration_status=" << diagnostic.adapter_enumeration_status
             << ", adapter_description_status=" << diagnostic.adapter_description_status
             << ", state_query=" << direct_frame_state_query_label(diagnostic.state_query)
             << ", state_query_domain=" << direct_frame_native_domain_label(diagnostic.state_query_domain)
             << ", state_query_result=" << direct_frame_init_result_label(diagnostic.state_query_result)
             << ", state_query_native_status=" << diagnostic.state_query_native_status
             << ", driver_state_available=" << diagnostic.driver_state_available
             << ", driver_generation=" << diagnostic.driver_state.generation
             << ", driver_last_generation=" << diagnostic.driver_state.last_generation
             << ", preferred_adapter_luid=" << diagnostic.driver_state.preferred_adapter_luid
             << ", assigned_adapter_luid=" << diagnostic.driver_state.assigned_adapter_luid
             << ", observed_preference_submitted=" << diagnostic.driver_state.preference_submitted
             << ", monitor_started=" << diagnostic.driver_state.monitor_started;
      return output.str();
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
        mode {selection.selected_mode},
        selection_preference_submitted {selection.render_adapter_preference_submitted} {
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

    frame_io_e initialize(
      const std::chrono::milliseconds timeout,
      direct_frame_init_diagnostic_t &diagnostic
    ) {
      diagnostic = {};
      record_direct_frame_initialization_result(
        diagnostic,
        direct_frame_init_stage_e::precondition,
        frame_io_e::unsupported,
        direct_frame_native_domain_e::logical,
        0
      );
      diagnostic.state_query = direct_frame_state_query_e::not_attempted;
      diagnostic.state_query_result = frame_io_e::stopped;
      diagnostic.handle_slot = direct_frame_no_handle_slot;
      diagnostic.generation = generation;
      diagnostic.expected_abi_version = LUMEN_VDD_ABI_VERSION;
      diagnostic.expected_adapter_luid = frozen_probe_identity ? frozen_probe_identity->adapter_luid : 0;
      diagnostic.selection_preference_submitted = selection_preference_submitted;
      bool state_snapshot_permitted = false;
      const auto fail = [&](const direct_frame_init_stage_e stage,
                            const frame_io_e result,
                            const direct_frame_native_domain_e domain,
                            const std::uint32_t native_status = 0,
                            const direct_frame_handle_kind_e handle_kind = direct_frame_handle_kind_e::none,
                            const std::uint32_t handle_slot = direct_frame_no_handle_slot) {
        record_direct_frame_initialization_result(
          diagnostic,
          stage,
          result,
          domain,
          native_status,
          handle_kind,
          handle_slot
        );
        if (state_snapshot_permitted) {
          snapshot_driver_state(diagnostic);
        }
        stop();
        return result;
      };

      diagnostic.required_capabilities = LUMEN_VDD_CAP_DIRECT_FRAME_V1 |
                                         LUMEN_VDD_CAP_FRAME_METADATA_V2 |
                                         LUMEN_VDD_CAP_COLOR_TRANSFORM_V1 |
                                         (mode.dynamic_range == dynamic_range_e::hdr10 ?
                                            LUMEN_VDD_CAP_HDR10 |
                                              LUMEN_VDD_CAP_10BIT |
                                              LUMEN_VDD_CAP_DIRECT_FRAME_FP16 :
                                            LUMEN_VDD_CAP_SDR8);
      const bool nvenc_active = ::video::active_encoder_is_nvenc();
      if (runtime_quarantined.load(std::memory_order_acquire) || !nvenc_active) {
        return fail(
          direct_frame_init_stage_e::precondition,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::logical
        );
      }

      DWORD native_status = ERROR_SUCCESS;
      device_handle = open_device_interface(native_status);
      if (device_handle == INVALID_HANDLE_VALUE) {
        const auto result = frame_error(native_status);
        return fail(
          direct_frame_init_stage_e::device_interface_open,
          result,
          direct_frame_native_domain_e::win32,
          native_status
        );
      }

      LUMEN_VDD_QUERY_ABI_RESPONSE abi {};
      const auto abi_status = ioctl(
        IOCTL_LUMEN_VDD_QUERY_ABI,
        nullptr,
        0,
        &abi,
        sizeof(abi),
        &native_status
      );
      diagnostic.abi_version = abi.abi_version;
      diagnostic.capability_flags = abi.capability_flags;
      if (abi_status != frame_io_e::ok) {
        return fail(
          direct_frame_init_stage_e::abi_query,
          abi_status,
          native_status == ERROR_SUCCESS ?
            direct_frame_native_domain_e::logical :
            direct_frame_native_domain_e::win32,
          native_status
        );
      }
      const auto abi_contract = validate_frame_abi_contract(
        abi_status,
        abi.abi_version,
        LUMEN_VDD_ABI_VERSION,
        abi.capability_flags,
        diagnostic.required_capabilities
      );
      if (abi_contract != frame_io_e::ok) {
        return fail(
          direct_frame_init_stage_e::abi_contract,
          abi_contract,
          direct_frame_native_domain_e::logical
        );
      }
      state_snapshot_permitted = true;
      snapshot_driver_state(diagnostic);

      cancel_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
      if (cancel_event == nullptr) {
        native_status = GetLastError();
        return fail(
          direct_frame_init_stage_e::cancel_event_create,
          frame_io_e::transport_error,
          direct_frame_native_domain_e::win32,
          native_status
        );
      }
      const auto host_process_id = GetCurrentProcessId();
      const auto host_process_creation_time = packed_process_creation_time(GetCurrentProcess(), &native_status);
      if (host_process_id == 0 || host_process_creation_time == 0) {
        return fail(
          direct_frame_init_stage_e::publisher_identity,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::win32,
          native_status
        );
      }
      std::uint32_t process_access_status = ERROR_SUCCESS;
      if (!grant_umdf_process_access(process_access_status)) {
        native_status = static_cast<DWORD>(process_access_status);
        return fail(
          direct_frame_init_stage_e::publisher_process_open,
          frame_io_e::transport_error,
          direct_frame_native_domain_e::win32,
          native_status
        );
      }
      const LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST event_request {
        generation,
        host_process_id,
        0,
      };
      LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE event_response {};
      const auto event_status = ioctl(
        IOCTL_LUMEN_VDD_OPEN_FRAME_EVENT,
        &event_request,
        sizeof(event_request),
        &event_response,
        sizeof(event_response),
        &native_status
      );
      const frame_channel_source_identity_t event_source {
        event_response.generation,
        event_response.source_process_id,
        event_response.source_reserved,
        event_response.source_process_creation_time,
        event_response.reserved,
      };
      diagnostic.publisher_process_id = event_source.process_id;
      diagnostic.publisher_process_creation_time = event_source.process_creation_time;
      if (event_status != frame_io_e::ok) {
        return fail(
          direct_frame_init_stage_e::frame_event_query,
          event_status,
          native_status == ERROR_SUCCESS ?
            direct_frame_native_domain_e::logical :
            direct_frame_native_domain_e::win32,
          native_status
        );
      }
      availability_event = reinterpret_cast<HANDLE>(event_response.event_handle);
      if (!valid_frame_channel_source_identity(
            event_source,
            generation,
            host_process_id,
            host_process_creation_time
          )) {
        return fail(
          direct_frame_init_stage_e::publisher_identity,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::logical
        );
      }
      if (event_response.event_handle == 0) {
        return fail(
          direct_frame_init_stage_e::frame_event_duplicate,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::logical,
          0,
          direct_frame_handle_kind_e::availability_event
        );
      }

      const auto deadline = std::chrono::steady_clock::now() + std::max(timeout, 0ms);
      LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE response {};
      while (true) {
        const LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST request {
          generation,
          host_process_id,
          0,
        };
        const auto status = ioctl(
          IOCTL_LUMEN_VDD_OPEN_FRAME_CHANNEL,
          &request,
          sizeof(request),
          &response,
          sizeof(response),
          &native_status
        );
        if (status == frame_io_e::ok) {
          break;
        }
        if (status != frame_io_e::empty) {
          return fail(
            direct_frame_init_stage_e::frame_channel_query,
            status,
            native_status == ERROR_SUCCESS ?
              direct_frame_native_domain_e::logical :
              direct_frame_native_domain_e::win32,
            native_status
          );
        }
        const auto wait_status = wait_for_availability(deadline, &diagnostic);
        if (wait_status != frame_io_e::ok) {
          snapshot_driver_state(diagnostic);
          stop();
          return wait_status;
        }
      }

      const frame_channel_source_identity_t channel_source {
        response.generation,
        response.source_process_id,
        response.source_reserved,
        response.source_process_creation_time,
        response.reserved,
      };
      if (!valid_frame_channel_source_identity(
            channel_source,
            generation,
            host_process_id,
            host_process_creation_time
          ) ||
          channel_source != event_source ||
          response.slot_count != LUMEN_VDD_FRAME_SLOT_COUNT ||
          (response.texture_format != LUMEN_VDD_FRAME_FORMAT_BGRA8 &&
           response.texture_format != LUMEN_VDD_FRAME_FORMAT_RGBA16_FLOAT) ||
          response.color_transform_version == 0) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::frame_channel_contract,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::logical
        );
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
        return fail(
          direct_frame_init_stage_e::initial_color_metadata,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::logical
        );
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
      diagnostic.resource_adapter_luid = resources.adapter_luid;
      if (!valid_frame_resources(resources, generation, mode)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::resource_contract,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::logical
        );
      }
      if (!resolve_color_transform(response.color_transform_version, &diagnostic)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::color_transform,
          frame_io_e::invalid_data,
          diagnostic.domain,
          diagnostic.native_status
        );
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
        return fail(
          direct_frame_init_stage_e::handle_identity,
          frame_io_e::invalid_data,
          direct_frame_native_domain_e::logical,
          0,
          texture_identity == direct_frame_handle_identity_e::alias ?
            direct_frame_handle_kind_e::texture :
            direct_frame_handle_kind_e::fence,
          1
        );
      }
      if (texture_identity == direct_frame_handle_identity_e::unavailable_or_error ||
          fence_identity == direct_frame_handle_identity_e::unavailable_or_error) {
        BOOST_LOG(warning)
          << "Windows cannot compare one or more VDD shared kernel-handle types; "sv
             "relying on driver-side resource identity validation"sv;
      }

      ComPtr<IDXGIFactory1> factory;
      auto hresult = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
      if (FAILED(hresult)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::dxgi_factory,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::hresult,
          static_cast<std::uint32_t>(hresult)
        );
      }
      HRESULT adapter_description_failure = S_OK;
      bool described_adapter = false;
      for (UINT index = 0;; ++index) {
        ComPtr<IDXGIAdapter1> candidate;
        hresult = factory->EnumAdapters1(index, &candidate);
        if (hresult == DXGI_ERROR_NOT_FOUND) {
          break;
        }
        if (FAILED(hresult)) {
          diagnostic.adapter_enumeration_status = static_cast<std::uint32_t>(hresult);
          close_response_handles(response);
          return fail(
            direct_frame_init_stage_e::adapter_enumeration,
            frame_io_e::unsupported,
            direct_frame_native_domain_e::hresult,
            static_cast<std::uint32_t>(hresult)
          );
        }
        DXGI_ADAPTER_DESC1 description {};
        const auto description_status = candidate->GetDesc1(&description);
        if (FAILED(description_status)) {
          if (SUCCEEDED(adapter_description_failure)) {
            adapter_description_failure = description_status;
            diagnostic.adapter_description_status = static_cast<std::uint32_t>(description_status);
          }
          continue;
        }
        described_adapter = true;
        if (packed_luid(description.AdapterLuid) == resources.adapter_luid) {
          if (adapter) {
            close_response_handles(response);
            return fail(
              direct_frame_init_stage_e::adapter_enumeration,
              frame_io_e::invalid_data,
              direct_frame_native_domain_e::logical
            );
          }
          adapter = std::move(candidate);
        }
      }

      DXGI_ADAPTER_DESC1 description {};
      LARGE_INTEGER driver_version {};
      if (!adapter) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::adapter_enumeration,
          frame_io_e::unsupported,
          !described_adapter && FAILED(adapter_description_failure) ?
            direct_frame_native_domain_e::hresult :
            direct_frame_native_domain_e::logical,
          !described_adapter && FAILED(adapter_description_failure) ?
            static_cast<std::uint32_t>(adapter_description_failure) :
            0
        );
      }
      hresult = adapter->GetDesc1(&description);
      if (FAILED(hresult)) {
        diagnostic.adapter_description_status = static_cast<std::uint32_t>(hresult);
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::adapter_identity,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::hresult,
          static_cast<std::uint32_t>(hresult)
        );
      }
      hresult = adapter->CheckInterfaceSupport(IID_IDXGIDevice, &driver_version);
      if (FAILED(hresult)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::adapter_identity,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::hresult,
          static_cast<std::uint32_t>(hresult)
        );
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
        return fail(
          direct_frame_init_stage_e::adapter_identity,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::logical
        );
      }

      const D3D_FEATURE_LEVEL levels[] {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
      D3D_FEATURE_LEVEL selected {};
      hresult = D3D11CreateDevice(
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
      );
      if (FAILED(hresult)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::d3d11_device,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::hresult,
          static_cast<std::uint32_t>(hresult)
        );
      }
      hresult = device.As(&device1);
      if (SUCCEEDED(hresult)) {
        hresult = device.As(&device5);
      }
      if (SUCCEEDED(hresult)) {
        hresult = context.As(&context4);
      }
      if (FAILED(hresult)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::d3d11_device,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::hresult,
          static_cast<std::uint32_t>(hresult)
        );
      }
      ComPtr<ID3D11Multithread> multithread;
      hresult = context.As(&multithread);
      if (FAILED(hresult)) {
        close_response_handles(response);
        return fail(
          direct_frame_init_stage_e::multithread_context,
          frame_io_e::unsupported,
          direct_frame_native_domain_e::hresult,
          static_cast<std::uint32_t>(hresult)
        );
      }
      multithread->SetMultithreadProtected(TRUE);

      auto close_import_handles = util::fail_guard([&]() {
        close_response_handles(response);
      });
      for (std::size_t slot = 0; slot < direct_frame_slot_count; ++slot) {
        hresult = device1->OpenSharedResource1(
          reinterpret_cast<HANDLE>(resources.texture_handles[slot]),
          IID_PPV_ARGS(&textures[slot])
        );
        if (SUCCEEDED(hresult)) {
          hresult = textures[slot].As(&keyed_mutexes[slot]);
        }
        if (FAILED(hresult)) {
          return fail(
            direct_frame_init_stage_e::texture_import,
            frame_io_e::unsupported,
            direct_frame_native_domain_e::hresult,
            static_cast<std::uint32_t>(hresult),
            direct_frame_handle_kind_e::texture,
            static_cast<std::uint32_t>(slot)
          );
        }
        hresult = device5->OpenSharedFence(
          reinterpret_cast<HANDLE>(resources.fence_handles[slot]),
          IID_PPV_ARGS(&fences[slot])
        );
        if (FAILED(hresult)) {
          return fail(
            direct_frame_init_stage_e::fence_import,
            frame_io_e::unsupported,
            direct_frame_native_domain_e::hresult,
            static_cast<std::uint32_t>(hresult),
            direct_frame_handle_kind_e::fence,
            static_cast<std::uint32_t>(slot)
          );
        }
        D3D11_TEXTURE2D_DESC texture_desc {};
        textures[slot]->GetDesc(&texture_desc);
        const frame_texture_descriptor_t descriptor {
          texture_desc.Width,
          texture_desc.Height,
          texture_desc.Format == DXGI_FORMAT_R16G16B16A16_FLOAT ?
            frame_format_e::rgba16_float :
            frame_format_e::bgra8,
          texture_desc.MipLevels,
          texture_desc.ArraySize,
          texture_desc.SampleDesc.Count,
          texture_desc.Usage == D3D11_USAGE_DEFAULT,
          (texture_desc.BindFlags & D3D11_BIND_SHADER_RESOURCE) != 0,
          texture_desc.CPUAccessFlags == 0,
          (texture_desc.MiscFlags & D3D11_RESOURCE_MISC_SHARED_NTHANDLE) != 0,
          (texture_desc.MiscFlags & D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX) != 0,
        };
        const auto expected_texture_format = resources.format == frame_format_e::rgba16_float ?
                                               DXGI_FORMAT_R16G16B16A16_FLOAT :
                                               DXGI_FORMAT_B8G8R8A8_UNORM;
        if (texture_desc.Format != expected_texture_format ||
            !valid_frame_texture_descriptor(descriptor, resources)) {
          return fail(
            direct_frame_init_stage_e::texture_contract,
            frame_io_e::invalid_data,
            direct_frame_native_domain_e::logical,
            0,
            direct_frame_handle_kind_e::texture,
            static_cast<std::uint32_t>(slot)
          );
        }
      }
      healthy = true;
      snapshot_driver_state(diagnostic);
      record_direct_frame_initialization_result(
        diagnostic,
        direct_frame_init_stage_e::ready,
        frame_io_e::ok,
        direct_frame_native_domain_e::none,
        0
      );
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

    std::shared_ptr<const color_transform_t> resolve_color_transform(
      const std::uint64_t version,
      direct_frame_init_diagnostic_t *diagnostic = nullptr
    ) {
      if (auto cached = color_transforms.find(generation, version)) {
        return cached;
      }
      try {
        const LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST request {generation, version};
        auto response = std::make_unique<LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE>();
        DWORD native_status = ERROR_SUCCESS;
        const auto status = ioctl(
          IOCTL_LUMEN_VDD_QUERY_COLOR_TRANSFORM,
          &request,
          sizeof(request),
          response.get(),
          sizeof(*response),
          &native_status
        );
        if (status != frame_io_e::ok) {
          if (diagnostic != nullptr) {
            diagnostic->domain = native_status == ERROR_SUCCESS ?
                                   direct_frame_native_domain_e::logical :
                                   direct_frame_native_domain_e::win32;
            diagnostic->native_status = native_status;
          }
          return {};
        }
        if (response->generation != generation || response->transform_version != version) {
          if (diagnostic != nullptr) {
            diagnostic->domain = direct_frame_native_domain_e::logical;
            diagnostic->native_status = 0;
          }
          return {};
        }
        auto parsed = color_transform(*response);
        if (!parsed || !color_transforms.commit(parsed)) {
          if (diagnostic != nullptr) {
            diagnostic->domain = direct_frame_native_domain_e::logical;
            diagnostic->native_status = 0;
          }
          return {};
        }
        return parsed;
      } catch (...) {
        if (diagnostic != nullptr) {
          diagnostic->domain = direct_frame_native_domain_e::logical;
          diagnostic->native_status = 0;
        }
        return {};
      }
    }

    frame_io_e wait_for_availability(
      const std::chrono::steady_clock::time_point deadline,
      direct_frame_init_diagnostic_t *diagnostic = nullptr
    ) const noexcept {
      const auto record = [&](const frame_io_e result,
                              const direct_frame_native_domain_e domain,
                              const std::uint32_t native_status) {
        if (diagnostic != nullptr) {
          record_direct_frame_initialization_result(
            *diagnostic,
            direct_frame_init_stage_e::frame_channel_wait,
            result,
            domain,
            native_status
          );
        }
        return result;
      };
      if (availability_event == nullptr || cancel_event == nullptr) {
        return record(frame_io_e::stopped, direct_frame_native_domain_e::logical, 0);
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return record(frame_io_e::timeout, direct_frame_native_domain_e::wait, WAIT_TIMEOUT);
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
        return record(frame_io_e::stopped, direct_frame_native_domain_e::wait, result);
      }
      if (result == WAIT_TIMEOUT) {
        return record(frame_io_e::timeout, direct_frame_native_domain_e::wait, result);
      }
      if (result == WAIT_FAILED) {
        return record(
          frame_io_e::transport_error,
          direct_frame_native_domain_e::win32,
          GetLastError()
        );
      }
      return record(frame_io_e::transport_error, direct_frame_native_domain_e::wait, result);
    }

    frame_io_e ioctl(
      const DWORD code,
      const void *input,
      const DWORD input_size,
      void *output,
      const DWORD output_size,
      DWORD *native_status = nullptr
    ) const noexcept {
      if (native_status != nullptr) {
        *native_status = ERROR_SUCCESS;
      }
      if (device_handle == INVALID_HANDLE_VALUE) {
        if (native_status != nullptr) {
          *native_status = ERROR_INVALID_HANDLE;
        }
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
        const auto error = GetLastError();
        if (native_status != nullptr) {
          *native_status = error;
        }
        return frame_error(error);
      }
      return transferred == output_size ? frame_io_e::ok : frame_io_e::invalid_data;
    }

    void snapshot_driver_state(direct_frame_init_diagnostic_t &diagnostic) const noexcept {
      LUMEN_VDD_QUERY_STATE_RESPONSE response {};
      DWORD native_status = ERROR_SUCCESS;
      const auto status = ioctl(
        IOCTL_LUMEN_VDD_QUERY_STATE,
        nullptr,
        0,
        &response,
        sizeof(response),
        &native_status
      );
      const direct_frame_driver_state_snapshot_t snapshot {
        response.generation,
        response.last_generation,
        response.preferred_render_adapter_luid,
        response.assigned_render_adapter_luid,
        response.owner_process_id,
        response.monitor_started,
        response.render_adapter_preference_submitted,
        response.reserved,
      };
      record_direct_frame_driver_state_query(
        diagnostic,
        status,
        status == frame_io_e::ok ?
          direct_frame_native_domain_e::none :
          (native_status == ERROR_SUCCESS ?
             direct_frame_native_domain_e::logical :
             direct_frame_native_domain_e::win32),
        native_status,
        snapshot
      );
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
      color_transforms.clear();
    }

    std::uint64_t generation {};  ///< Exact active driver generation.
    mode_t mode;  ///< Exact selected mode.
    std::optional<direct_frame_adapter_identity_t> frozen_probe_identity;  ///< Encoder identity frozen at selection.
    bool selection_preference_submitted {};  ///< Prepared-mode adapter-preference fact.
    mutable std::mutex mutex;  ///< Serializes IOCTLs and slot ownership.
    HANDLE device_handle {INVALID_HANDLE_VALUE};  ///< Concrete secured VDD device interface.
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
    direct_frame_init_diagnostic_t diagnostic;
    if (impl->initialize(timeout, diagnostic) != frame_io_e::ok) {
      BOOST_LOG(error) << "Lumen VDD direct-frame initialization failed: "sv
                       << direct_frame_init_diagnostic_text(diagnostic);
      impl.reset();
      report_direct_frame_initialization_failure(selection.generation);
      return {};
    }
    auto source = std::shared_ptr<frame_source_t> {new frame_source_t(std::move(impl))};
    report_direct_frame_bound(selection.generation);
    BOOST_LOG(info) << "Lumen VDD direct-frame one-copy path enabled for generation "sv
                    << selection.generation << "; two persistent shared texture/fence slots; "sv
                    << direct_frame_init_diagnostic_text(diagnostic);
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
