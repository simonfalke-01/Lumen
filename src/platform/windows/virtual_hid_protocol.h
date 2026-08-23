/**
 * @file virtual_hid_protocol.h
 * @brief Lean C ABI shared by the Lumen VHF source driver and its client.
 *
 * Copyright (C) 2026 LizardByte
 *
 * This file is part of Lumen.
 *
 * Lumen is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 */

#ifndef LUMEN_PLATFORM_WINDOWS_VIRTUAL_HID_PROTOCOL_H
#define LUMEN_PLATFORM_WINDOWS_VIRTUAL_HID_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  #include <guiddef.h>
#endif

#ifndef CTL_CODE
  #define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef FILE_DEVICE_UNKNOWN
  #define FILE_DEVICE_UNKNOWN 0x00000022u
#endif
#ifndef METHOD_BUFFERED
  #define METHOD_BUFFERED 0u
#endif
#ifndef FILE_READ_DATA
  #define FILE_READ_DATA 0x0001u
#endif
#ifndef FILE_WRITE_DATA
  #define FILE_WRITE_DATA 0x0002u
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/** Report-control device-interface GUID: {AEC36F6E-3BB9-47C6-BF3C-11A562DD4840}. */
#if defined(_WIN32)
  DEFINE_GUID(GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID, 0xaec36f6e, 0x3bb9, 0x47c6, 0xbf, 0x3c, 0x11, 0xa5, 0x62, 0xdd, 0x48, 0x40);
#endif

/** Canonical root-enumerated hardware identifier used by the driver package. */
#define LUMEN_VHID_ROOT_HARDWARE_ID_A "ROOT\\LumenVirtualHid"
/** Wide-character form of the canonical root hardware identifier. */
#define LUMEN_VHID_ROOT_HARDWARE_ID_W L"ROOT\\LumenVirtualHid"
/** Narrow-character driver service and binary base name. */
#define LUMEN_VHID_DRIVER_SERVICE_NAME_A "LumenVirtualHid"
/** Wide-character driver service and binary base name. */
#define LUMEN_VHID_DRIVER_SERVICE_NAME_W L"LumenVirtualHid"

/** Exact driver/client ABI version. */
#define LUMEN_VHID_ABI_VERSION 2u
/** Separately negotiated dynamic-gamepad extension ABI version. */
#define LUMEN_VHID_GAMEPAD_ABI_VERSION 1u
/** Number of keyboard bitmap bytes covering usages 00-DF. */
#define LUMEN_VHID_NKRO_BITMAP_SIZE 28u
/** Number of simultaneously pressed Consumer Control usages. */
#define LUMEN_VHID_CONSUMER_USAGE_COUNT 4u
/** Number of Mouse top-level collections published by ABI v2. */
#define LUMEN_VHID_MOUSE_COLLECTION_COUNT 2u
/** Maximum number of concurrent dynamic VHF gamepads. */
#define LUMEN_VHID_MAX_GAMEPADS 16u
/** Bytes in an unguessable per-gamepad session token. */
#define LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE 32u
/** Largest complete dynamic-gamepad input or output report. */
#define LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE 256u

/** @name Built-in dynamic-gamepad profiles
 *
 * Values intentionally match libvirtualhid revision 15a37d34. Xbox 360 is
 * reserved because Windows XInput compatibility remains ViGEm-backed.
 * @{ */
#define LUMEN_VHID_GAMEPAD_PROFILE_GENERIC 0u
#define LUMEN_VHID_GAMEPAD_PROFILE_XBOX_360_RESERVED 1u
#define LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE 2u
#define LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES 3u
#define LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE 4u
#define LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO 5u
#define LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4 6u
#define LUMEN_VHID_GAMEPAD_PROFILE_COUNT 7u
/** @} */

/** Return the supported-profile bit corresponding to a built-in profile. */
#define LUMEN_VHID_GAMEPAD_PROFILE_BIT(profile) (UINT64_C(1) << (profile))

/** @name Dynamic-gamepad profile capabilities
 * @{ */
#define LUMEN_VHID_GAMEPAD_FEATURE_RUMBLE 0x00000001u
#define LUMEN_VHID_GAMEPAD_FEATURE_MOTION 0x00000002u
#define LUMEN_VHID_GAMEPAD_FEATURE_TOUCHPAD 0x00000004u
#define LUMEN_VHID_GAMEPAD_FEATURE_RGB_LED 0x00000008u
#define LUMEN_VHID_GAMEPAD_FEATURE_BATTERY 0x00000010u
#define LUMEN_VHID_GAMEPAD_FEATURE_ADAPTIVE_TRIGGERS 0x00000020u
/** @} */

/** @name Dynamic-gamepad extension capabilities
 * @{ */
#define LUMEN_VHID_GAMEPAD_CAPABILITY_OUTPUT_REPORTS 0x00000001u
#define LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS 0x00000002u
#define LUMEN_VHID_GAMEPAD_CAPABILITY_OWNER_CLEANUP 0x00000004u
#define LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS 0x00000008u
/** @} */

/** @name Fixed HID identity
 * @{ */
#define LUMEN_VHID_VENDOR_ID 0x4c42u
#define LUMEN_VHID_PRODUCT_ID 0x0001u
#define LUMEN_VHID_VERSION_NUMBER 0x0001u
/** @} */

/** @name Report kinds
 * @{ */
#define LUMEN_VHID_REPORT_KIND_KEYBOARD 1u
#define LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE 2u
#define LUMEN_VHID_REPORT_KIND_CONSUMER 3u
#define LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE 4u
/** @} */

/** @name HID report identifiers
 * @{ */
#define LUMEN_VHID_REPORT_ID_KEYBOARD 1u
#define LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE 2u
#define LUMEN_VHID_REPORT_ID_CONSUMER 3u
#define LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE 4u
/** @} */

/** @name SYSTEM-only METHOD_BUFFERED control codes
 * @{ */
#define IOCTL_LUMEN_VHID_GET_INFO \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_CLAIM \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_SUBMIT_REPORT \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_RESET_AND_RELEASE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_GAMEPAD_CREATE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_GAMEPAD_DESTROY \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_GAMEPAD_RESET_RUNTIME \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
  /** @} */

#pragma pack(push, 1)

  /** Exact response returned by IOCTL_LUMEN_VHID_GET_INFO. */
  typedef struct LUMEN_VHID_GET_INFO_RESPONSE {
    uint32_t abi_version;  ///< LUMEN_VHID_ABI_VERSION.
    uint32_t ready;  ///< One only while VHF is started and accepting reports.
  } LUMEN_VHID_GET_INFO_RESPONSE;

  /** Complete NKRO keyboard input report, including its report ID. */
  typedef struct LUMEN_VHID_KEYBOARD_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_KEYBOARD.
    uint8_t modifiers;  ///< E0-E7 modifier usages as bits zero through seven.
    uint8_t key_bitmap[LUMEN_VHID_NKRO_BITMAP_SIZE];  ///< Usage bits 00-DF.
  } LUMEN_VHID_KEYBOARD_REPORT;

  /** Complete five-button relative mouse input report, including its report ID. */
  typedef struct LUMEN_VHID_RELATIVE_MOUSE_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE.
    uint8_t buttons;  ///< Complete buttons 1-5 snapshot; high bits must be zero.
    int16_t x;  ///< Relative horizontal delta.
    int16_t y;  ///< Relative vertical delta.
    int16_t vertical_wheel;  ///< Relative vertical HID wheel detents.
    int16_t horizontal_wheel;  ///< Relative Consumer AC Pan HID detents.
  } LUMEN_VHID_RELATIVE_MOUSE_REPORT;

  /** Complete five-button absolute mouse input report, including its report ID. */
  typedef struct LUMEN_VHID_ABSOLUTE_MOUSE_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE.
    uint8_t buttons;  ///< Complete buttons 1-5 snapshot; high bits must be zero.
    uint16_t x;  ///< Absolute horizontal coordinate normalized to 0-65535.
    uint16_t y;  ///< Absolute vertical coordinate normalized to 0-65535.
    int16_t vertical_wheel;  ///< Relative vertical HID wheel detents.
    int16_t horizontal_wheel;  ///< Relative Consumer AC Pan HID detents.
  } LUMEN_VHID_ABSOLUTE_MOUSE_REPORT;

  /** Complete Consumer Control input report, including its report ID. */
  typedef struct LUMEN_VHID_CONSUMER_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_CONSUMER.
    uint16_t usages[LUMEN_VHID_CONSUMER_USAGE_COUNT];  ///< Active Consumer usages; zero pads unused slots.
  } LUMEN_VHID_CONSUMER_REPORT;

  /** Exact input accepted by IOCTL_LUMEN_VHID_SUBMIT_REPORT. */
  typedef struct LUMEN_VHID_SUBMIT_REPORT_REQUEST {
    uint32_t report_kind;  ///< One LUMEN_VHID_REPORT_KIND_* value.

    union {
      LUMEN_VHID_KEYBOARD_REPORT keyboard;  ///< NKRO keyboard state.
      LUMEN_VHID_RELATIVE_MOUSE_REPORT relative_mouse;  ///< Relative pointer state and deltas.
      LUMEN_VHID_CONSUMER_REPORT consumer;  ///< Consumer Control usage array.
      LUMEN_VHID_ABSOLUTE_MOUSE_REPORT absolute_mouse;  ///< Absolute pointer state, coordinates, and wheels.
    } report;  ///< Complete report selected by report_kind.
  } LUMEN_VHID_SUBMIT_REPORT_REQUEST;

  /** Opaque authenticated identity of one dynamic gamepad generation. */
  typedef struct LUMEN_VHID_GAMEPAD_HANDLE {
    uint64_t device_id;  ///< Driver-assigned identifier, never zero.
    uint64_t generation;  ///< Monotonic generation preventing stale-slot reuse.
    uint8_t session_token[LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE];  ///< Driver-generated random bearer token.
  } LUMEN_VHID_GAMEPAD_HANDLE;

  /** Exact response returned by IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES. */
  typedef struct LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE {
    uint32_t version;  ///< LUMEN_VHID_GAMEPAD_ABI_VERSION.
    uint32_t size;  ///< sizeof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE).
    uint32_t base_abi_version;  ///< LUMEN_VHID_ABI_VERSION for the static collections.
    uint32_t capability_flags;  ///< LUMEN_VHID_GAMEPAD_CAPABILITY_* bitmap.
    uint64_t supported_profiles;  ///< LUMEN_VHID_GAMEPAD_PROFILE_BIT values.
    uint32_t max_devices;  ///< LUMEN_VHID_MAX_GAMEPADS.
    uint32_t active_devices;  ///< Snapshot of currently live dynamic gamepads.
    uint32_t max_input_report_size;  ///< LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE.
    uint32_t max_output_report_size;  ///< LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE.
  } LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE;

  /** Exact input accepted by IOCTL_LUMEN_VHID_GAMEPAD_CREATE. */
  typedef struct LUMEN_VHID_GAMEPAD_CREATE_REQUEST {
    uint32_t version;  ///< LUMEN_VHID_GAMEPAD_ABI_VERSION.
    uint32_t size;  ///< sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST).
    uint64_t client_device_id;  ///< Stable caller identifier used for profile identity data.
    uint32_t profile;  ///< One supported LUMEN_VHID_GAMEPAD_PROFILE_* value.
    uint32_t reserved;  ///< Must be zero.
  } LUMEN_VHID_GAMEPAD_CREATE_REQUEST;

  /** Exact output returned by IOCTL_LUMEN_VHID_GAMEPAD_CREATE. */
  typedef struct LUMEN_VHID_GAMEPAD_CREATE_RESPONSE {
    uint32_t version;  ///< LUMEN_VHID_GAMEPAD_ABI_VERSION.
    uint32_t size;  ///< sizeof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE).
    LUMEN_VHID_GAMEPAD_HANDLE handle;  ///< Authenticated handle for all later operations.
    uint32_t profile;  ///< Effective built-in profile.
    uint32_t feature_flags;  ///< LUMEN_VHID_GAMEPAD_FEATURE_* bitmap.
    uint16_t vendor_id;  ///< Advertised HID vendor identifier.
    uint16_t product_id;  ///< Advertised HID product identifier.
    uint16_t version_number;  ///< Advertised HID version number.
    uint8_t input_report_id;  ///< Primary input report ID; zero means unnumbered.
    uint8_t reserved0;  ///< Zero.
    uint32_t input_report_size;  ///< Exact accepted complete input report size.
    uint32_t output_report_size;  ///< Largest expected output report size.
  } LUMEN_VHID_GAMEPAD_CREATE_RESPONSE;

  /** Header common to authenticated destroy, read, and reset operations. */
  typedef struct LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST {
    uint32_t version;  ///< LUMEN_VHID_GAMEPAD_ABI_VERSION.
    uint32_t size;  ///< sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST).
    LUMEN_VHID_GAMEPAD_HANDLE handle;  ///< Exact current device identity and token.
  } LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST;

  /** Exact input accepted by IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT. */
  typedef struct LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST {
    uint32_t version;  ///< LUMEN_VHID_GAMEPAD_ABI_VERSION.
    uint32_t size;  ///< sizeof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST).
    LUMEN_VHID_GAMEPAD_HANDLE handle;  ///< Exact current device identity and token.
    uint32_t report_size;  ///< Valid bytes in report; must match the profile.
    uint32_t reserved;  ///< Must be zero.
    uint8_t report[LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE];  ///< Complete HID input report.
  } LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST;

  /** Exact output returned by IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT. */
  typedef struct LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE {
    uint32_t version;  ///< LUMEN_VHID_GAMEPAD_ABI_VERSION.
    uint32_t size;  ///< sizeof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE).
    LUMEN_VHID_GAMEPAD_HANDLE handle;  ///< Device generation that produced the event.
    uint32_t report_size;  ///< Valid bytes in report.
    uint32_t reserved;  ///< Zero.
    uint8_t report[LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE];  ///< Complete HID output or feature report.
  } LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE;

#pragma pack(pop)

#define LUMEN_VHID_STATIC_ASSERT(expression, name) \
  typedef char lumen_vhid_static_assert_##name[(expression) ? 1 : -1]

  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GET_INFO_RESPONSE) == 8, get_info_response_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_GET_INFO_RESPONSE, ready) == 4, ready_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_KEYBOARD_REPORT) == 30, keyboard_report_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT) == 10, relative_mouse_report_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT) == 10, absolute_mouse_report_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT, x) == 2, absolute_mouse_x_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_CONSUMER_REPORT) == 9, consumer_report_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_SUBMIT_REPORT_REQUEST, report) == 4, submit_report_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_SUBMIT_REPORT_REQUEST) == 34, submit_report_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_HANDLE) == 48, gamepad_handle_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_GAMEPAD_HANDLE, session_token) == 16, gamepad_token_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE) == 40, gamepad_capabilities_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST) == 24, gamepad_create_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE) == 80, gamepad_create_response_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE, handle) == 8, gamepad_create_handle_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST) == 56, gamepad_authenticated_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST) == 320, gamepad_submit_request_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST, report) == 64, gamepad_submit_report_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE) == 320, gamepad_output_response_size);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GET_INFO & 3u) == METHOD_BUFFERED, get_info_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_CLAIM & 3u) == METHOD_BUFFERED, claim_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_SUBMIT_REPORT & 3u) == METHOD_BUFFERED, submit_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_RESET_AND_RELEASE & 3u) == METHOD_BUFFERED, reset_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES & 3u) == METHOD_BUFFERED, gamepad_capabilities_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GAMEPAD_CREATE & 3u) == METHOD_BUFFERED, gamepad_create_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GAMEPAD_DESTROY & 3u) == METHOD_BUFFERED, gamepad_destroy_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT & 3u) == METHOD_BUFFERED, gamepad_submit_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT & 3u) == METHOD_BUFFERED, gamepad_read_output_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GAMEPAD_RESET_RUNTIME & 3u) == METHOD_BUFFERED, gamepad_reset_runtime_ioctl_buffered);

#undef LUMEN_VHID_STATIC_ASSERT

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* LUMEN_PLATFORM_WINDOWS_VIRTUAL_HID_PROTOCOL_H */
