/**
 * @file src/platform/windows/virtual_display_process_access_win.cpp
 * @brief Windows process DACL grant for UMDF direct-frame handle transfer.
 */

#if defined(_WIN32)

  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <Windows.h>
  #include <sddl.h>

  #include "virtual_display_process_access.h"

namespace platf::virtual_display {
  bool grant_umdf_process_access(std::uint32_t &native_status) noexcept {
    native_status = ERROR_SUCCESS;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    constexpr wchar_t transfer_sddl[] =
      L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x00101040;;;LS)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          transfer_sddl,
          SDDL_REVISION_1,
          &descriptor,
          nullptr
        )) {
      native_status = GetLastError();
      return false;
    }
    const auto applied = SetKernelObjectSecurity(
      GetCurrentProcess(),
      DACL_SECURITY_INFORMATION,
      descriptor
    );
    native_status = applied ? ERROR_SUCCESS : GetLastError();
    LocalFree(descriptor);
    return applied != FALSE;
  }
}

#endif
