/**
 * @file src/platform/windows/virtual_display_driver/LumenVirtualDisplayGuids.h
 * @brief Shared Windows interface identities for the Lumen Virtual Display.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_GUIDS_H
#define LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_GUIDS_H

#include <guiddef.h>

/** Exact control and direct-frame device-interface identity. */
inline constexpr GUID GUID_DEVINTERFACE_LUMEN_VIRTUAL_DISPLAY {
  0x6e93b112,
  0xa4ad,
  0x4a14,
  {0x94, 0x01, 0x8d, 0xbd, 0x78, 0xa8, 0xfe, 0x77},
};

#endif  // LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_GUIDS_H
