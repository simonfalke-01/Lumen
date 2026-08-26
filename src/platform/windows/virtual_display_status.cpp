/**
 * @file src/platform/windows/virtual_display_status.cpp
 * @brief Read-only Lumen virtual-display status implementation.
 */

#include "virtual_display_status.h"

#include <algorithm>
#include <mutex>
#include <vector>

#if defined(_WIN32)
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <Windows.h>
  #include <cfgmgr32.h>
  #include <SetupAPI.h>
#endif

namespace platf::virtual_display {
  namespace {
    /** @brief Mutable process-local source state fenced by its exact VDD generation. */
    struct tracked_direct_frame_status_t {
      std::uint64_t generation {};
      bool bound {};
      bool quarantined {};
      bool fallback {};
    };

    std::mutex direct_frame_status_mutex;  ///< Protects the exact direct-frame generation state.
    tracked_direct_frame_status_t direct_frame_status;  ///< Current direct source or its active failure.

#if defined(_WIN32)
    constexpr wchar_t lumen_vdd_hardware_id[] = L"ROOT\\LUMENVIRTUALDISPLAY";

    /** @brief Device-node facts gathered without starting, stopping, or reconfiguring the driver. */
    struct device_probe_t {
      bool installed {};  ///< At least one matching present device node exists.
      bool healthy {};  ///< A matching node is started without a Configuration Manager problem.
      bool status_available {};  ///< Configuration Manager returned device-node state.
      std::optional<std::uint32_t> problem;  ///< Exact Windows problem code, when nonzero.
    };

    /** @brief Return whether a device exposes the exact Lumen root hardware identifier. */
    bool is_lumen_vdd(HDEVINFO devices, SP_DEVINFO_DATA &device) {
      DWORD required_size = 0;
      DWORD property_type = 0;
      SetupDiGetDeviceRegistryPropertyW(
        devices,
        &device,
        SPDRP_HARDWAREID,
        &property_type,
        nullptr,
        0,
        &required_size
      );
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required_size < sizeof(wchar_t) * 2U) {
        return false;
      }
      std::vector<wchar_t> storage(
        (required_size + sizeof(wchar_t) - 1U) / sizeof(wchar_t),
        L'\0'
      );
      if (!SetupDiGetDeviceRegistryPropertyW(
            devices,
            &device,
            SPDRP_HARDWAREID,
            &property_type,
            reinterpret_cast<PBYTE>(storage.data()),
            required_size,
            nullptr
          ) ||
          property_type != REG_MULTI_SZ) {
        return false;
      }
      const auto *hardware_id = storage.data();
      const auto *const end = storage.data() + storage.size();
      while (hardware_id < end && *hardware_id != L'\0') {
        const auto terminator = std::find(hardware_id, end, L'\0');
        if (terminator == end) {
          return false;
        }
        const auto length = static_cast<std::size_t>(terminator - hardware_id);
        if (CompareStringOrdinal(
              hardware_id,
              static_cast<int>(length),
              lumen_vdd_hardware_id,
              static_cast<int>(sizeof(lumen_vdd_hardware_id) / sizeof(wchar_t) - 1U),
              TRUE
            ) == CSTR_EQUAL) {
          return true;
        }
        hardware_id += length + 1U;
      }
      return false;
    }

    /** @brief Enumerate present device nodes and read the exact Lumen VDD problem. */
    device_probe_t query_device_probe() {
      device_probe_t result;
      const HDEVINFO devices = SetupDiGetClassDevsW(
        nullptr,
        nullptr,
        nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT
      );
      if (devices == INVALID_HANDLE_VALUE) {
        return result;
      }
      for (DWORD index = 0;; ++index) {
        SP_DEVINFO_DATA device {sizeof(device)};
        if (!SetupDiEnumDeviceInfo(devices, index, &device)) {
          break;
        }
        if (!is_lumen_vdd(devices, device)) {
          continue;
        }
        result.installed = true;
        ULONG node_status = 0;
        ULONG problem = 0;
        if (CM_Get_DevNode_Status(&node_status, &problem, device.DevInst, 0) != CR_SUCCESS) {
          continue;
        }
        result.status_available = true;
        const bool healthy = (node_status & DN_STARTED) != 0 &&
                             (node_status & DN_HAS_PROBLEM) == 0 && problem == 0;
        if (healthy) {
          result.healthy = true;
          result.problem.reset();
          break;
        }
        if (!result.problem && problem != 0) {
          result.problem = static_cast<std::uint32_t>(problem);
        }
      }
      SetupDiDestroyDeviceInfoList(devices);
      return result;
    }
#endif
  }  // namespace

  void report_direct_frame_bound(const std::uint64_t generation) noexcept {
    if (generation == 0) {
      return;
    }
    std::lock_guard lock(direct_frame_status_mutex);
    direct_frame_status = {generation, true, false, false};
  }

  void report_direct_frame_fallback(const std::uint64_t generation) noexcept {
    if (generation == 0) {
      return;
    }
    std::lock_guard lock(direct_frame_status_mutex);
    direct_frame_status = {generation, false, false, true};
  }

  void report_direct_frame_stopped(
    const std::uint64_t generation,
    const bool quarantined
  ) noexcept {
    if (generation == 0) {
      return;
    }
    std::lock_guard lock(direct_frame_status_mutex);
    if (direct_frame_status.generation != generation) {
      return;
    }
    if (quarantined) {
      direct_frame_status.bound = false;
      direct_frame_status.quarantined = true;
      direct_frame_status.fallback = false;
    } else if (!direct_frame_status.quarantined) {
      direct_frame_status = {};
    }
  }

  void report_direct_frame_quarantined() noexcept {
    std::lock_guard lock(direct_frame_status_mutex);
    if (direct_frame_status.generation != 0) {
      direct_frame_status.bound = false;
      direct_frame_status.quarantined = true;
      direct_frame_status.fallback = false;
    }
  }

  direct_frame_generation_status_t direct_frame_status_for_generation(
    const std::uint64_t generation
  ) noexcept {
    if (generation == 0) {
      return {};
    }
    std::lock_guard lock(direct_frame_status_mutex);
    if (direct_frame_status.generation != generation) {
      return {};
    }
    return {
      direct_frame_status.bound,
      direct_frame_status.quarantined,
      direct_frame_status.fallback,
    };
  }

  system_status_t query_system_status() {
    system_status_t status;

#if defined(_WIN32)
    const auto device = query_device_probe();
    status.installed = device.installed;
    status.device_healthy = device.healthy;
    status.device_problem = device.problem;

    const auto channel = make_system_control_channel();
    if (!channel) {
      status.diagnostic = "Lumen Virtual Display is unavailable.";
      return status;
    }
    const auto opened = channel->open();
    if (!opened) {
      status.diagnostic = !status.installed ?
                            "Lumen Virtual Display is not installed." :
                          status.device_problem ?
                            "Windows reports a problem with Lumen Virtual Display." :
                            "The Lumen Virtual Display control channel is unavailable.";
      return status;
    }
    status.installed = true;

    mode_limits_t limits;
    const auto limits_result = channel->query_limits(limits);
    if (!limits_result) {
      channel->close();
      status.diagnostic = "The installed Lumen Virtual Display driver is incompatible with this build.";
      return status;
    }
    status.compatible = true;

    driver_state_t driver_state;
    const auto state_result = channel->query_state(driver_state);
    channel->close();
    if (!state_result) {
      status.diagnostic = "Lumen could not read the virtual display state.";
      return status;
    }
    if (!device.status_available) {
      status.device_healthy = true;
    }

    if (driver_state.generation != 0 && driver_state.monitor_started) {
      if (!driver_state.delivery_policy) {
        status.diagnostic = "Lumen could not read the virtual display policy.";
        return status;
      }
      status.active = active_display_status_t {
        driver_state.generation,
        driver_state.mode,
        *driver_state.delivery_policy,
      };
      const auto direct_frame = direct_frame_status_for_generation(driver_state.generation);
      status.direct_frame_quarantined = direct_frame.quarantined;
      status.direct_frame_bound = direct_frame.bound && !direct_frame.quarantined;
      status.fallback = direct_frame.fallback && !status.direct_frame_quarantined;
    }

    const auto capture_path = classify_capture_path(
      status.active.has_value(),
      {status.direct_frame_bound, status.direct_frame_quarantined, status.fallback}
    );
    if (!status.device_healthy) {
      status.diagnostic = status.device_problem ?
                            "Windows reports a problem with Lumen Virtual Display." :
                            "Lumen Virtual Display is installed but not started.";
    } else {
      switch (capture_path) {
        case capture_path_status_e::quarantined:
          status.diagnostic = "Direct-frame capture stopped after a runtime failure. Restart Lumen before retrying.";
          break;
        case capture_path_status_e::fallback:
          status.diagnostic = "The virtual display is active through desktop capture.";
          break;
        case capture_path_status_e::direct:
          status.diagnostic = "Direct-frame capture is active.";
          break;
        case capture_path_status_e::unavailable:
          status.diagnostic = "The virtual display is active, but no capture path is bound.";
          break;
        case capture_path_status_e::inactive:
          status.diagnostic = "Ready.";
          break;
      }
    }
#else
    status.diagnostic = "Lumen Virtual Display is available only on Windows.";
#endif
    return status;
  }
}  // namespace platf::virtual_display
