/**
 * @file tools/lumen-msica-ownership.h
 * @brief Portable exact-one-owner selection used by the MSI custom action.
 */
#pragma once

#include <stddef.h>
#include <wchar.h>

#define LUMEN_VDD_PRODUCT_CODE_LENGTH 38u
#define LUMEN_VDD_PRODUCT_CODE_CAPACITY 39u

typedef enum lumen_vdd_owner_selection_result {
  LUMEN_VDD_OWNER_SELECTION_OK = 0,
  LUMEN_VDD_OWNER_SELECTION_INVALID = 1,
  LUMEN_VDD_OWNER_SELECTION_AMBIGUOUS = 2,
} lumen_vdd_owner_selection_result;

typedef struct lumen_vdd_owner_selection {
  unsigned int count;
  wchar_t product_code[LUMEN_VDD_PRODUCT_CODE_CAPACITY];
} lumen_vdd_owner_selection;

/** Retain exactly one normalized related ProductCode and reject ambiguity. */
static inline lumen_vdd_owner_selection_result lumen_vdd_owner_selection_add(
  lumen_vdd_owner_selection *selection,
  const wchar_t *product_code
) {
  if (selection == NULL || product_code == NULL ||
      wcslen(product_code) != LUMEN_VDD_PRODUCT_CODE_LENGTH) {
    return LUMEN_VDD_OWNER_SELECTION_INVALID;
  }
  if (selection->count != 0u) {
    return LUMEN_VDD_OWNER_SELECTION_AMBIGUOUS;
  }
  wmemcpy(
    selection->product_code,
    product_code,
    LUMEN_VDD_PRODUCT_CODE_LENGTH
  );
  selection->product_code[LUMEN_VDD_PRODUCT_CODE_LENGTH] = L'\0';
  selection->count = 1u;
  return LUMEN_VDD_OWNER_SELECTION_OK;
}
