/**
 * @file DynamicGamepadValidation.h
 * @brief Portable validation primitives for the dynamic-gamepad ABI.
 */

#ifndef LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_VALIDATION_H
#define LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_VALIDATION_H

#include "DynamicGamepadProfiles.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Validate an exact versioned fixed-POD request header.
 *
 * @param version Supplied extension version.
 * @param size Supplied structure size.
 * @param expected_size Exact structure size for the operation.
 * @return Nonzero only for the current extension version and exact size.
 */
static inline int LumenVhidGamepadValidHeader(uint32_t version, uint32_t size, size_t expected_size) {
  return version == LUMEN_VHID_GAMEPAD_ABI_VERSION && size == expected_size;
}

/**
 * @brief Validate all portable fields of a create request.
 *
 * @param request Candidate fixed create request.
 * @return Nonzero for an exact header, zero reserved field, and supported profile.
 */
static inline int LumenVhidGamepadValidCreateRequest(const LUMEN_VHID_GAMEPAD_CREATE_REQUEST *request) {
  return request != NULL &&
         LumenVhidGamepadValidHeader(request->version, request->size, sizeof(*request)) &&
         request->reserved == 0u && LumenVhidGamepadProfileLookup(request->profile) != NULL;
}

/**
 * @brief Validate portable framing for one submit-report request.
 *
 * Profile-specific exact size and report ID validation occurs after handle
 * authentication selects the effective trusted profile.
 *
 * @param request Candidate fixed submit request.
 * @return Nonzero for an exact header, zero reserved field, and bounded size.
 */
static inline int LumenVhidGamepadValidSubmitRequestHeader(
  const LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST *request
) {
  return request != NULL &&
         LumenVhidGamepadValidHeader(request->version, request->size, sizeof(*request)) &&
         request->reserved == 0u && request->report_size != 0u &&
         request->report_size <= LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
}

/**
 * @brief Compare two fixed session tokens without data-dependent early exit.
 *
 * @param left First token.
 * @param right Second token.
 * @return Nonzero only when every byte matches.
 */
static inline int LumenVhidGamepadTokenEqual(const uint8_t *left, const uint8_t *right) {
  uint8_t difference = 0u;
  size_t index;

  if (left == NULL || right == NULL) {
    return 0;
  }
  for (index = 0u; index < LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE; ++index) {
    difference = (uint8_t) (difference | (uint8_t) (left[index] ^ right[index]));
  }
  return difference == 0u;
}

/**
 * @brief Validate one complete report against a trusted built-in profile.
 *
 * @param profile Effective profile.
 * @param report Complete input report.
 * @param report_size Number of report bytes.
 * @return Nonzero only for the profile's exact size and primary report ID.
 */
static inline int LumenVhidGamepadValidInputReport(
  const LUMEN_VHID_GAMEPAD_PROFILE *profile,
  const uint8_t *report,
  size_t report_size
) {
  if (profile == NULL || report == NULL || report_size != profile->input_report_size ||
      report_size == 0u || report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE) {
    return 0;
  }
  return profile->input_report_id == 0u || report[0] == profile->input_report_id;
}

#endif /* LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_VALIDATION_H */
