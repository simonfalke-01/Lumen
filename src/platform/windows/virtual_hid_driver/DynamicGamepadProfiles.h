/**
 * @file DynamicGamepadProfiles.h
 * @brief Fixed built-in VHF gamepad profile descriptors and identities.
 */

#ifndef LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_PROFILES_H
#define LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_PROFILES_H

#include "../virtual_hid_protocol.h"

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

  /** Immutable descriptor and HID identity for one approved built-in profile. */
  typedef struct LUMEN_VHID_GAMEPAD_PROFILE {
    uint32_t kind;  ///< LUMEN_VHID_GAMEPAD_PROFILE_* value.
    uint32_t feature_flags;  ///< LUMEN_VHID_GAMEPAD_FEATURE_* bitmap.
    uint16_t vendor_id;  ///< Advertised HID vendor identifier.
    uint16_t product_id;  ///< Advertised HID product identifier.
    uint16_t version_number;  ///< Advertised HID version number.
    uint8_t input_report_id;  ///< Primary input report ID, or zero for unnumbered reports.
    uint8_t reserved;  ///< Zero.
    uint32_t input_report_size;  ///< Exact complete input report size.
    uint32_t output_report_size;  ///< Maximum expected host output report size.
    const uint8_t *report_descriptor;  ///< Trusted static HID report descriptor.
    size_t report_descriptor_size;  ///< Descriptor size in bytes.
  } LUMEN_VHID_GAMEPAD_PROFILE;

  /**
   * @brief Look up one trusted built-in dynamic-gamepad profile.
   *
   * Xbox 360 intentionally returns null because XInput devices remain on the
   * ViGEm backend. Callers can never upload arbitrary report descriptors.
   *
   * @param kind LUMEN_VHID_GAMEPAD_PROFILE_* value.
   * @return Immutable profile metadata, or null when unsupported.
   */
  const LUMEN_VHID_GAMEPAD_PROFILE *LumenVhidGamepadProfileLookup(uint32_t kind);

  /**
   * @brief Return the exact supported built-in profile bitmap.
   *
   * @return LUMEN_VHID_GAMEPAD_PROFILE_BIT values accepted by lookup.
   */
  uint64_t LumenVhidGamepadSupportedProfiles(void);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_PROFILES_H */
