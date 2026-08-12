/**
 * @file virtual_hid_protocol.h
 * @brief Stable, bounded C ABI shared by the Lumen VHF driver and its client.
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

#if defined(_KERNEL_MODE)
  typedef UCHAR uint8_t;
  typedef SHORT int16_t;
  typedef USHORT uint16_t;
  typedef ULONG uint32_t;
  typedef ULONGLONG uint64_t;
  #ifndef UINT16_MAX
    #define UINT16_MAX 0xffffu
  #endif
  #ifndef UINT64_MAX
    #define UINT64_MAX 0xffffffffffffffffULL
  #endif
  #ifndef UINT64_C
    #define UINT64_C(value) value##ULL
  #endif
  #ifndef SIZE_MAX
    #define SIZE_MAX ((size_t) -1)
  #endif
#else
  #include <stdint.h>
#endif

#if defined(_WIN32) || defined(_KERNEL_MODE)
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
#if defined(_WIN32) || defined(_KERNEL_MODE)
  DEFINE_GUID(GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID, 0xaec36f6e, 0x3bb9, 0x47c6, 0xbf, 0x3c, 0x11, 0xa5, 0x62, 0xdd, 0x48, 0x40);
#endif

/** Protocol framing magic (the ASCII bytes `LHID` in little-endian order). */
#define LUMEN_VHID_PROTOCOL_MAGIC 0x4449484cu
/** Required protocol major version. */
#define LUMEN_VHID_PROTOCOL_MAJOR 1u
/** Current protocol minor version. */
#define LUMEN_VHID_PROTOCOL_MINOR 0u

/** Canonical root-enumerated hardware identifier used by the driver package. */
#define LUMEN_VHID_ROOT_HARDWARE_ID_A "ROOT\\LumenVirtualHid"
/** Wide-character form of the canonical root hardware identifier. */
#define LUMEN_VHID_ROOT_HARDWARE_ID_W L"ROOT\\LumenVirtualHid"
/** Narrow-character kernel service and binary base name. */
#define LUMEN_VHID_DRIVER_SERVICE_NAME_A "LumenVirtualHid"
/** Wide-character kernel service and binary base name. */
#define LUMEN_VHID_DRIVER_SERVICE_NAME_W L"LumenVirtualHid"

/** Maximum complete input or output control buffer in bytes. */
#define LUMEN_VHID_MAX_CONTROL_SIZE 4096u
/** Maximum bounded report-payload storage in a submit request. */
#define LUMEN_VHID_MAX_REPORT_PAYLOAD 512u
/** Number of keyboard bitmap bytes covering usages 00-DF. */
#define LUMEN_VHID_NKRO_BITMAP_SIZE 28u

/** @name Wire operation identifiers
 * @{ */
#define LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES 1u
#define LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION 2u
#define LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT 3u
#define LUMEN_VHID_OPERATION_RESET_INPUT_SESSION 4u
#define LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION 5u
/** @} */

/** @name Minimum compatible minor version for each operation
 * @{ */
#define LUMEN_VHID_MIN_MINOR_GET_PROTOCOL_CAPABILITIES 0u
#define LUMEN_VHID_MIN_MINOR_CLAIM_INPUT_SESSION 0u
#define LUMEN_VHID_MIN_MINOR_SUBMIT_INPUT_REPORT 0u
#define LUMEN_VHID_MIN_MINOR_RESET_INPUT_SESSION 0u
#define LUMEN_VHID_MIN_MINOR_RELEASE_INPUT_SESSION 0u
/** @} */

/** @name Device-kind identifiers
 * @{ */
#define LUMEN_VHID_DEVICE_KIND_KEYBOARD 1u
#define LUMEN_VHID_DEVICE_KIND_MOUSE 2u
/** @} */

/** @name HID report identifiers
 * @{ */
#define LUMEN_VHID_REPORT_ID_KEYBOARD 1u
#define LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE 2u
#define LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE 3u
/** @} */

/** @name Capability bits
 * @{ */
#define LUMEN_VHID_CAP_KEYBOARD_NKRO (UINT64_C(1) << 0)
#define LUMEN_VHID_CAP_MOUSE_RELATIVE (UINT64_C(1) << 1)
#define LUMEN_VHID_CAP_MOUSE_ABSOLUTE (UINT64_C(1) << 2)
#define LUMEN_VHID_CAP_MOUSE_BUTTONS_5 (UINT64_C(1) << 3)
#define LUMEN_VHID_CAP_WHEEL_VERTICAL (UINT64_C(1) << 4)
#define LUMEN_VHID_CAP_WHEEL_HORIZONTAL (UINT64_C(1) << 5)
#define LUMEN_VHID_CAP_EXCLUSIVE_SESSION (UINT64_C(1) << 6)
#define LUMEN_VHID_CAP_CONTIGUOUS_SEQUENCE (UINT64_C(1) << 7)
#define LUMEN_VHID_CAP_SYNCHRONOUS_FENCE (UINT64_C(1) << 8)
/** @} */

/** Mask containing every capability understood by this protocol version. */
#define LUMEN_VHID_CAP_KNOWN_MASK \
  (LUMEN_VHID_CAP_KEYBOARD_NKRO | LUMEN_VHID_CAP_MOUSE_RELATIVE | \
   LUMEN_VHID_CAP_MOUSE_ABSOLUTE | LUMEN_VHID_CAP_MOUSE_BUTTONS_5 | \
   LUMEN_VHID_CAP_WHEEL_VERTICAL | LUMEN_VHID_CAP_WHEEL_HORIZONTAL | \
   LUMEN_VHID_CAP_EXCLUSIVE_SESSION | LUMEN_VHID_CAP_CONTIGUOUS_SEQUENCE | \
   LUMEN_VHID_CAP_SYNCHRONOUS_FENCE)

/** Capabilities required before the complete keyboard/mouse transport activates. */
#define LUMEN_VHID_CAP_REQUIRED LUMEN_VHID_CAP_KNOWN_MASK
/** Unknown bits in an optional-capability field may be ignored. */
#define LUMEN_VHID_CAP_OPTIONAL_MASK UINT64_C(0)

/** @name SYSTEM-only METHOD_BUFFERED control codes
 * @{ */
#define IOCTL_LUMEN_VHID_GET_PROTOCOL_CAPABILITIES \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_CLAIM_INPUT_SESSION \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_SUBMIT_INPUT_REPORT \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_RESET_INPUT_SESSION \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VHID_RELEASE_INPUT_SESSION \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

  /** @} */

  /** Common fixed-size header at the beginning of every request and response. */
  typedef struct LUMEN_VHID_MESSAGE_HEADER {
    uint32_t magic;  ///< Must equal LUMEN_VHID_PROTOCOL_MAGIC.
    uint16_t protocol_major;  ///< Exact protocol major version.
    uint16_t protocol_minor;  ///< Offered or negotiated protocol minor version.
    uint16_t header_size;  ///< Exact size of LUMEN_VHID_MESSAGE_HEADER.
    uint16_t operation;  ///< Operation corresponding to the enclosing IOCTL.
    uint32_t total_size;  ///< Exact complete buffer size for this operation.
    uint32_t flags;  ///< Reserved; must be zero.
  } LUMEN_VHID_MESSAGE_HEADER;

  /** Capability-discovery request. */
  typedef struct LUMEN_VHID_GET_CAPABILITIES_REQUEST {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Validated request header.
  } LUMEN_VHID_GET_CAPABILITIES_REQUEST;

  /** Driver protocol, capability, limit, and report-layout response. */
  typedef struct LUMEN_VHID_GET_CAPABILITIES_RESPONSE {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Negotiated response header.
    uint32_t reserved0;  ///< Reserved; zero.
    uint64_t capabilities;  ///< Capabilities provided by this driver.
    uint64_t required_capabilities;  ///< Complete transport activation requirements.
    uint32_t max_control_size;  ///< Maximum complete control buffer.
    uint32_t max_report_payload;  ///< Maximum embedded report storage.
    uint16_t keyboard_report_size;  ///< Exact keyboard report size.
    uint16_t relative_mouse_report_size;  ///< Exact relative report size.
    uint16_t absolute_mouse_report_size;  ///< Exact absolute report size.
    uint16_t min_minor_get_capabilities;  ///< Minimum discovery-operation minor.
    uint16_t min_minor_claim;  ///< Minimum claim-operation minor.
    uint16_t min_minor_submit;  ///< Minimum submit-operation minor.
    uint16_t min_minor_reset;  ///< Minimum reset-operation minor.
    uint16_t min_minor_release;  ///< Minimum release-operation minor.
    uint32_t reserved1;  ///< Reserved; zero.
    uint32_t reserved2;  ///< Reserved; zero.
  } LUMEN_VHID_GET_CAPABILITIES_RESPONSE;

  /** Atomic exclusive-writer claim request. */
  typedef struct LUMEN_VHID_CLAIM_SESSION_REQUEST {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Validated request header.
    uint32_t reserved0;  ///< Reserved; must be zero.
    uint64_t required_capabilities;  ///< Capabilities the client cannot operate without.
    uint64_t optional_capabilities;  ///< Optional bits; unknown bits may be ignored.
  } LUMEN_VHID_CLAIM_SESSION_REQUEST;

  /** Exclusive claim result and newly allocated generation token. */
  typedef struct LUMEN_VHID_CLAIM_SESSION_RESPONSE {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Negotiated response header.
    uint32_t reserved0;  ///< Reserved; zero.
    uint64_t session_token;  ///< Nonzero generation token tied to the open file.
    uint64_t granted_capabilities;  ///< Capabilities active for this session.
  } LUMEN_VHID_CLAIM_SESSION_RESPONSE;

  /** Reset or release request for an owned generation. */
  typedef struct LUMEN_VHID_SESSION_REQUEST {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Validated request header.
    uint32_t reserved0;  ///< Reserved; must be zero.
    uint64_t session_token;  ///< Exact current (or idempotently retired) token.
  } LUMEN_VHID_SESSION_REQUEST;

  /** Synchronous reset/release fence acknowledgement. */
  typedef struct LUMEN_VHID_SESSION_RESPONSE {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Negotiated response header.
    uint32_t reserved0;  ///< Reserved; zero.
    uint64_t session_token;  ///< New reset token or released token.
    uint64_t last_sequence;  ///< Reset zero or final released sequence.
  } LUMEN_VHID_SESSION_RESPONSE;

  /** Fixed, bounded request containing one complete HID state report. */
  typedef struct LUMEN_VHID_SUBMIT_REPORT_REQUEST {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Validated request header.
    uint32_t reserved0;  ///< Reserved; must be zero.
    uint64_t session_token;  ///< Exact current generation token.
    uint64_t sequence;  ///< Exact nonzero previous-plus-one sequence.
    uint16_t device_kind;  ///< Keyboard or mouse device-kind identifier.
    uint16_t report_id;  ///< Report ID duplicated in payload byte zero.
    uint16_t payload_size;  ///< Exact known report size, never a trusted bound.
    uint16_t reserved1;  ///< Reserved; must be zero.
    uint8_t payload[LUMEN_VHID_MAX_REPORT_PAYLOAD];  ///< Bounded report storage.
  } LUMEN_VHID_SUBMIT_REPORT_REQUEST;

  /** Acknowledgement proving VHF accepted exactly one sequence. */
  typedef struct LUMEN_VHID_SUBMIT_REPORT_RESPONSE {
    LUMEN_VHID_MESSAGE_HEADER header;  ///< Negotiated response header.
    uint32_t reserved0;  ///< Reserved; zero.
    uint64_t session_token;  ///< Current generation token.
    uint64_t accepted_sequence;  ///< Sequence accepted by VHF.
  } LUMEN_VHID_SUBMIT_REPORT_RESPONSE;

  /** Complete NKRO keyboard input report, including report ID byte zero. */
  typedef struct LUMEN_VHID_KEYBOARD_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_KEYBOARD.
    uint8_t modifiers;  ///< E0-E7 modifier usages as bits zero through seven.
    uint8_t key_bitmap[LUMEN_VHID_NKRO_BITMAP_SIZE];  ///< Usage bits 00-DF.
  } LUMEN_VHID_KEYBOARD_REPORT;

  /** Complete five-button relative mouse report with edge/delta fields. */
  typedef struct LUMEN_VHID_RELATIVE_MOUSE_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE.
    uint8_t buttons;  ///< Complete buttons 1-5 snapshot; high bits are zero.
    int16_t x;  ///< Relative horizontal delta.
    int16_t y;  ///< Relative vertical delta.
    int16_t vertical_wheel;  ///< Vertical wheel delta.
    int16_t horizontal_wheel;  ///< Consumer AC Pan delta.
  } LUMEN_VHID_RELATIVE_MOUSE_REPORT;

  /** Complete five-button absolute mouse report with 0-65535 coordinates. */
  typedef struct LUMEN_VHID_ABSOLUTE_MOUSE_REPORT {
    uint8_t report_id;  ///< LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE.
    uint8_t buttons;  ///< Complete buttons 1-5 snapshot; high bits are zero.
    uint16_t x;  ///< Absolute normalized horizontal coordinate.
    uint16_t y;  ///< Absolute normalized vertical coordinate.
    int16_t vertical_wheel;  ///< Vertical wheel delta.
    int16_t horizontal_wheel;  ///< Consumer AC Pan delta.
  } LUMEN_VHID_ABSOLUTE_MOUSE_REPORT;

  /**
   * Return the minimum compatible minor version for an operation.
   * @param operation Wire operation identifier.
   * @return Minimum minor version, or UINT16_MAX for an unknown operation.
   */
  static inline uint16_t lumen_vhid_operation_minimum_minor(uint16_t operation) {
    switch (operation) {
      case LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES:
        return LUMEN_VHID_MIN_MINOR_GET_PROTOCOL_CAPABILITIES;
      case LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION:
        return LUMEN_VHID_MIN_MINOR_CLAIM_INPUT_SESSION;
      case LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT:
        return LUMEN_VHID_MIN_MINOR_SUBMIT_INPUT_REPORT;
      case LUMEN_VHID_OPERATION_RESET_INPUT_SESSION:
        return LUMEN_VHID_MIN_MINOR_RESET_INPUT_SESSION;
      case LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION:
        return LUMEN_VHID_MIN_MINOR_RELEASE_INPUT_SESSION;
      default:
        return UINT16_MAX;
    }
  }

  /**
   * Add two buffer sizes without wrapping.
   * @param left Left operand.
   * @param right Right operand.
   * @param result Receives the sum on success.
   * @return Nonzero on success; zero on null output or overflow.
   */
  static inline int lumen_vhid_checked_add_size(size_t left, size_t right, size_t *result) {
    if (result == NULL || left > SIZE_MAX - right) {
      return 0;
    }
    *result = left + right;
    return 1;
  }

  /**
   * Validate exact fixed framing before an operation accesses embedded fields.
   * @param header Candidate header in a previously length-checked buffer.
   * @param received_size Complete received buffer size.
   * @param expected_operation Operation selected by the IOCTL.
   * @param expected_size Exact fixed request size for that operation.
   * @return Nonzero only when every framing invariant holds.
   */
  static inline int lumen_vhid_validate_message_header(const LUMEN_VHID_MESSAGE_HEADER *header, size_t received_size, uint16_t expected_operation, size_t expected_size) {
    uint16_t minimum_minor;
    if (header == NULL || received_size > LUMEN_VHID_MAX_CONTROL_SIZE ||
        received_size != expected_size || expected_size < sizeof(*header)) {
      return 0;
    }
    if (header->magic != LUMEN_VHID_PROTOCOL_MAGIC ||
        header->protocol_major != LUMEN_VHID_PROTOCOL_MAJOR ||
        header->header_size != sizeof(*header) || header->operation != expected_operation ||
        header->total_size != received_size || header->flags != 0) {
      return 0;
    }
    minimum_minor = lumen_vhid_operation_minimum_minor(expected_operation);
    return minimum_minor != UINT16_MAX && header->protocol_minor >= minimum_minor;
  }

  /**
   * Negotiate the lower minor version and verify required capabilities.
   * @param client_major Client major version, which must match exactly.
   * @param client_minor Client minor version.
   * @param operation Operation whose minimum minor version applies.
   * @param required_capabilities Capabilities required by the client.
   * @param driver_capabilities Capabilities advertised by the driver.
   * @param negotiated_minor Receives the compatible lower minor version.
   * @return Nonzero if the version and capability contract is compatible.
   */
  static inline int lumen_vhid_negotiate_protocol(uint16_t client_major, uint16_t client_minor, uint16_t operation, uint64_t required_capabilities, uint64_t driver_capabilities, uint16_t *negotiated_minor) {
    uint16_t lower_minor;
    uint16_t minimum_minor = lumen_vhid_operation_minimum_minor(operation);
    if (negotiated_minor == NULL || client_major != LUMEN_VHID_PROTOCOL_MAJOR ||
        minimum_minor == UINT16_MAX || (required_capabilities & ~driver_capabilities) != 0) {
      return 0;
    }
    lower_minor = client_minor;
    if (lower_minor > LUMEN_VHID_PROTOCOL_MINOR) {
      lower_minor = LUMEN_VHID_PROTOCOL_MINOR;
    }
    if (lower_minor < minimum_minor) {
      return 0;
    }
    *negotiated_minor = lower_minor;
    return 1;
  }

  /**
   * Check the exact non-wrapping session sequence rule.
   * @param last_sequence Last accepted sequence (zero immediately after claim).
   * @param exhausted Nonzero after accepting UINT64_MAX.
   * @param sequence Candidate sequence.
   * @return Nonzero only for the exact nonzero next sequence.
   */
  static inline int lumen_vhid_is_next_sequence(uint64_t last_sequence, int exhausted, uint64_t sequence) {
    return !exhausted && last_sequence != UINT64_MAX && sequence != 0 &&
           sequence == last_sequence + UINT64_C(1);
  }

  /**
   * Verify that a device kind, report ID, and embedded size form a known tuple.
   * @param device_kind Keyboard or mouse kind.
   * @param report_id Candidate report identifier.
   * @param payload_size Candidate embedded report size.
   * @return Nonzero only for a defined exact report tuple.
   */
  static inline int lumen_vhid_validate_report_metadata(uint16_t device_kind, uint16_t report_id, uint16_t payload_size) {
    if (device_kind == LUMEN_VHID_DEVICE_KIND_KEYBOARD) {
      return report_id == LUMEN_VHID_REPORT_ID_KEYBOARD &&
             payload_size == sizeof(LUMEN_VHID_KEYBOARD_REPORT);
    }
    if (device_kind != LUMEN_VHID_DEVICE_KIND_MOUSE) {
      return 0;
    }
    if (report_id == LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE) {
      return payload_size == sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT);
    }
    if (report_id == LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE) {
      return payload_size == sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT);
    }
    return 0;
  }

#define LUMEN_VHID_STATIC_ASSERT(expression, name) \
  typedef char lumen_vhid_static_assert_##name[(expression) ? 1 : -1]

  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_MESSAGE_HEADER) == 20, message_header_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_MESSAGE_HEADER, total_size) == 12, total_size_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GET_CAPABILITIES_REQUEST) == 20, get_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_GET_CAPABILITIES_RESPONSE) == 72, get_response_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_CLAIM_SESSION_REQUEST) == 40, claim_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_CLAIM_SESSION_RESPONSE) == 40, claim_response_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_SESSION_REQUEST) == 32, session_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_SESSION_RESPONSE) == 40, session_response_size);
  LUMEN_VHID_STATIC_ASSERT(offsetof(LUMEN_VHID_SUBMIT_REPORT_REQUEST, payload) == 48, payload_offset);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_SUBMIT_REPORT_REQUEST) == 560, submit_request_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_SUBMIT_REPORT_RESPONSE) == 40, submit_response_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_KEYBOARD_REPORT) == 30, keyboard_report_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT) == 10, relative_report_size);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT) == 10, absolute_report_size);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_GET_PROTOCOL_CAPABILITIES & 3u) == METHOD_BUFFERED, get_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_CLAIM_INPUT_SESSION & 3u) == METHOD_BUFFERED, claim_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_SUBMIT_INPUT_REPORT & 3u) == METHOD_BUFFERED, submit_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_RESET_INPUT_SESSION & 3u) == METHOD_BUFFERED, reset_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT((IOCTL_LUMEN_VHID_RELEASE_INPUT_SESSION & 3u) == METHOD_BUFFERED, release_ioctl_buffered);
  LUMEN_VHID_STATIC_ASSERT(sizeof(LUMEN_VHID_SUBMIT_REPORT_REQUEST) <= LUMEN_VHID_MAX_CONTROL_SIZE, submit_under_control_limit);

#undef LUMEN_VHID_STATIC_ASSERT

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* LUMEN_PLATFORM_WINDOWS_VIRTUAL_HID_PROTOCOL_H */
