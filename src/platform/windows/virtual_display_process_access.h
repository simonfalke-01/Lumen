/**
 * @file src/platform/windows/virtual_display_process_access.h
 * @brief Narrow process-access grant used by the UMDF direct-frame transfer.
 */
#pragma once

#include <cstdint>

namespace platf::virtual_display {
  /**
   * @brief Grant Local Service only the process rights required for ABI handle transfer.
   *
   * @param native_status Receives ERROR_SUCCESS or the failing Win32 status.
   * @return true when the process DACL was updated.
   */
  bool grant_umdf_process_access(std::uint32_t &native_status) noexcept;
}
