/** Portable hostile fixture for exact-one related MSI ProductCode ownership. */
#include <stdio.h>
#include <wchar.h>

#include "../../tools/lumen-msica-ownership.h"

#define CHECK(condition, message) \
  do { \
    if (!(condition)) { \
      fputs("FAIL: " message "\n", stderr); \
      return 1; \
    } \
  } while (0)

int main(void) {
  static const wchar_t first[] = L"{11111111-1111-1111-1111-111111111111}";
  static const wchar_t second[] = L"{22222222-2222-2222-2222-222222222222}";
  lumen_vdd_owner_selection selection = {0};

  CHECK(selection.count == 0u, "a feature-absent upgrade must select no owner");
  CHECK(
    lumen_vdd_owner_selection_add(&selection, first) == LUMEN_VDD_OWNER_SELECTION_OK,
    "one related feature owner must be admitted"
  );
  CHECK(selection.count == 1u, "exactly one owner must be retained");
  CHECK(wcscmp(selection.product_code, first) == 0, "the exact ProductCode must be retained");
  CHECK(
    lumen_vdd_owner_selection_add(&selection, second) == LUMEN_VDD_OWNER_SELECTION_AMBIGUOUS,
    "multiple related feature owners must fail closed"
  );
  CHECK(selection.count == 1u, "ambiguity must not replace the first owner");
  CHECK(wcscmp(selection.product_code, first) == 0, "ambiguity must preserve diagnostic identity");

  selection = (lumen_vdd_owner_selection) {0};
  CHECK(
    lumen_vdd_owner_selection_add(&selection, L"not-a-product-code") ==
      LUMEN_VDD_OWNER_SELECTION_INVALID,
    "malformed ProductCodes must be rejected"
  );
  CHECK(selection.count == 0u, "invalid input must not mutate selection");

  puts("PASS: exact-one related MSI VDD owner selection");
  return 0;
}
