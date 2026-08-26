/**
 * @file tools/lumen-msica.c
 * @brief Bridges persisted driver reboot state into Windows Installer.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <msi.h>
#include <msiquery.h>
#include <strsafe.h>
#include <wchar.h>
#include <wctype.h>

#include "lumen-msica-ownership.h"

#define LUMEN_UPGRADE_CODE L"{89721553-C582-4D70-8BBF-1E6C5431C8D5}"
#define LUMEN_VDD_FEATURE L"CM_C_virtual_display_driver"

static void log_message(MSIHANDLE installation, const wchar_t *message);

/** Read one complete MSI property into process-heap storage. */
static UINT read_property(MSIHANDLE installation, const wchar_t *name, wchar_t **value) {
  DWORD length = 0;
  wchar_t empty = L'\0';
  UINT result = MsiGetPropertyW(installation, name, &empty, &length);
  wchar_t *buffer;
  DWORD capacity;
  if (result != ERROR_MORE_DATA && result != ERROR_SUCCESS) {
    return result;
  }
  buffer = (wchar_t *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((SIZE_T) length + 1u) * sizeof(wchar_t));
  if (buffer == NULL) {
    return ERROR_OUTOFMEMORY;
  }
  capacity = length + 1u;
  result = MsiGetPropertyW(installation, name, buffer, &capacity);
  if (result != ERROR_SUCCESS) {
    HeapFree(GetProcessHeap(), 0, buffer);
    return result;
  }
  *value = buffer;
  return ERROR_SUCCESS;
}

/** Return whether text is one normalized uppercase braced product GUID. */
static BOOL normalized_product_code(const wchar_t *product_code) {
  size_t index;
  if (product_code == NULL || wcslen(product_code) != 38u ||
      product_code[0] != L'{' || product_code[37] != L'}') {
    return FALSE;
  }
  for (index = 1; index < 37u; ++index) {
    const wchar_t character = product_code[index];
    if (index == 9u || index == 14u || index == 19u || index == 24u) {
      if (character != L'-') {
        return FALSE;
      }
    } else if (!((character >= L'0' && character <= L'9') ||
                 (character >= L'A' && character <= L'F'))) {
      return FALSE;
    }
  }
  return TRUE;
}

/** Return whether one detected ProductCode belongs to Lumen's UpgradeCode. */
static BOOL related_lumen_product(const wchar_t *product_code, UINT *error) {
  DWORD index;
  for (index = 0;; ++index) {
    wchar_t related[39];
    const UINT result = MsiEnumRelatedProductsW(LUMEN_UPGRADE_CODE, 0, index, related);
    if (result == ERROR_NO_MORE_ITEMS) {
      *error = ERROR_SUCCESS;
      return FALSE;
    }
    if (result != ERROR_SUCCESS) {
      *error = result;
      return FALSE;
    }
    if (_wcsicmp(related, product_code) == 0) {
      *error = ERROR_SUCCESS;
      return TRUE;
    }
  }
}

/** Convert a normalized braced ProductCode to its 32-character key token. */
static BOOL product_token(const wchar_t *product_code, wchar_t token[33]) {
  size_t input_index;
  size_t output_index = 0;
  if (!normalized_product_code(product_code)) {
    return FALSE;
  }
  for (input_index = 1; input_index < 37; ++input_index) {
    const wchar_t character = product_code[input_index];
    if (character == L'-') {
      continue;
    }
    if (!iswxdigit(character) || output_index >= 32u) {
      return FALSE;
    }
    token[output_index++] = (wchar_t) towupper(character);
  }
  token[output_index] = L'\0';
  return output_index == 32u;
}

/**
 * @brief Resolve whether a replaced Lumen MSI owns an installed VDD feature.
 *
 * The result is written to LUMEN_UPGRADE_OWNED_VDD for deferred setup. Every
 * detected product is checked against Lumen's permanent UpgradeCode before its
 * feature state is trusted.
 *
 * @param installation Unrestricted immediate Windows Installer handle.
 * @return ERROR_SUCCESS on success or an MSI/Win32 error on invalid state.
 */
__declspec(dllexport) UINT __stdcall LumenResolveUpgradeVddOwnership(MSIHANDLE installation) {
  wchar_t *detected = NULL;
  wchar_t *cursor;
  lumen_vdd_owner_selection owner = {0};
  UINT result = read_property(installation, L"WIX_UPGRADE_DETECTED", &detected);
  if (result != ERROR_SUCCESS) {
    return result;
  }
  result = MsiSetPropertyW(installation, L"LUMEN_UPGRADE_OWNED_VDD", L"0");
  if (result == ERROR_SUCCESS) {
    result = MsiSetPropertyW(installation, L"LUMEN_UPGRADE_VDD_OWNER_PRODUCT", L"");
  }
  if (result != ERROR_SUCCESS || detected[0] == L'\0') {
    HeapFree(GetProcessHeap(), 0, detected);
    return result;
  }

  cursor = detected;
  while (*cursor != L'\0') {
    wchar_t product_code[39];
    wchar_t *separator = wcschr(cursor, L';');
    const size_t length = separator == NULL ? wcslen(cursor) : (size_t) (separator - cursor);
    INSTALLSTATE feature_state;
    UINT related_error = ERROR_SUCCESS;
    if (length != 38u) {
      HeapFree(GetProcessHeap(), 0, detected);
      return ERROR_INVALID_DATA;
    }
    memcpy(product_code, cursor, length * sizeof(wchar_t));
    product_code[length] = L'\0';
    if (!normalized_product_code(product_code)) {
      HeapFree(GetProcessHeap(), 0, detected);
      return ERROR_INVALID_DATA;
    }
    if (!related_lumen_product(product_code, &related_error)) {
      HeapFree(GetProcessHeap(), 0, detected);
      return related_error == ERROR_SUCCESS ? ERROR_INVALID_DATA : related_error;
    }

    feature_state = MsiQueryFeatureStateW(product_code, LUMEN_VDD_FEATURE);
    if (feature_state == INSTALLSTATE_LOCAL) {
      const lumen_vdd_owner_selection_result selection_result =
        lumen_vdd_owner_selection_add(&owner, product_code);
      if (selection_result == LUMEN_VDD_OWNER_SELECTION_AMBIGUOUS) {
        log_message(installation, L"Multiple replaced Lumen products claim Virtual Display ownership; refusing an ambiguous transfer.");
        HeapFree(GetProcessHeap(), 0, detected);
        return ERROR_INVALID_DATA;
      }
      if (selection_result != LUMEN_VDD_OWNER_SELECTION_OK) {
        HeapFree(GetProcessHeap(), 0, detected);
        return ERROR_INVALID_DATA;
      }
    } else if (feature_state != INSTALLSTATE_UNKNOWN &&
        feature_state != INSTALLSTATE_ABSENT &&
        feature_state != INSTALLSTATE_ADVERTISED) {
      HeapFree(GetProcessHeap(), 0, detected);
      return ERROR_INVALID_DATA;
    }
    if (separator == NULL) {
      break;
    }
    cursor = separator + 1;
    if (*cursor == L'\0') {
      HeapFree(GetProcessHeap(), 0, detected);
      return ERROR_INVALID_DATA;
    }
  }
  if (owner.count == 1u) {
    result = MsiSetPropertyW(installation, L"LUMEN_UPGRADE_OWNED_VDD", L"1");
    if (result == ERROR_SUCCESS) {
      result = MsiSetPropertyW(installation, L"LUMEN_UPGRADE_VDD_OWNER_PRODUCT", owner.product_code);
    }
    if (result == ERROR_SUCCESS) {
      log_message(installation, L"Exactly one replaced Lumen product owns Virtual Display; explicit ownership transfer is enabled.");
    }
  }
  HeapFree(GetProcessHeap(), 0, detected);
  return result;
}

/** Emit one informational record to the MSI log. */
static void log_message(MSIHANDLE installation, const wchar_t *message) {
  MSIHANDLE record = MsiCreateRecord(1);
  if (record != 0) {
    MsiRecordSetStringW(record, 0, L"Lumen: [1]");
    MsiRecordSetStringW(record, 1, message);
    MsiProcessMessage(installation, INSTALLMESSAGE_INFO, record);
    MsiCloseHandle(record);
  }
}

/**
 * @brief Read a protected pending-driver marker into an MSI property.
 *
 * @param installation Unrestricted immediate Windows Installer handle.
 * @return ERROR_SUCCESS on success or an MSI/Win32 error on invalid state.
 */
__declspec(dllexport) UINT __stdcall LumenReadPendingDriverReboot(MSIHANDLE installation) {
  wchar_t *product_code = NULL;
  wchar_t *remove = NULL;
  const wchar_t *transaction;
  wchar_t token[33];
  wchar_t key_path[256];
  HKEY key = NULL;
  DWORD pending = 0;
  DWORD type = 0;
  DWORD size = sizeof(pending);
  LONG registry_result;
  UINT result = read_property(installation, L"ProductCode", &product_code);
  if (result != ERROR_SUCCESS) {
    return result;
  }
  result = read_property(installation, L"REMOVE", &remove);
  if (result != ERROR_SUCCESS) {
    HeapFree(GetProcessHeap(), 0, product_code);
    return result;
  }
  transaction = wcscmp(remove, L"ALL") == 0 ? L"uninstall" : L"install";
  if (!product_token(product_code, token) ||
      FAILED(StringCchPrintfW(
        key_path,
        256u,
        L"SOFTWARE\\Lumen\\Installer\\PendingReboot\\%ls\\%ls",
        token,
        transaction
      ))) {
    HeapFree(GetProcessHeap(), 0, remove);
    HeapFree(GetProcessHeap(), 0, product_code);
    return ERROR_INVALID_DATA;
  }
  HeapFree(GetProcessHeap(), 0, remove);
  HeapFree(GetProcessHeap(), 0, product_code);

  registry_result = RegOpenKeyExW(
    HKEY_LOCAL_MACHINE,
    key_path,
    0,
    KEY_QUERY_VALUE | KEY_WOW64_64KEY,
    &key
  );
  if (registry_result == ERROR_FILE_NOT_FOUND || registry_result == ERROR_PATH_NOT_FOUND) {
    return MsiSetPropertyW(installation, L"LUMEN_DRIVER_REBOOT_REQUIRED", L"0");
  }
  if (registry_result != ERROR_SUCCESS) {
    return (UINT) registry_result;
  }
  registry_result = RegQueryValueExW(
    key,
    L"Pending",
    NULL,
    &type,
    (BYTE *) &pending,
    &size
  );
  RegCloseKey(key);
  if (registry_result != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(pending)) {
    return registry_result == ERROR_SUCCESS ? ERROR_INVALID_DATA : (UINT) registry_result;
  }
  if (pending == 0) {
    return MsiSetPropertyW(installation, L"LUMEN_DRIVER_REBOOT_REQUIRED", L"0");
  }
  result = MsiSetPropertyW(installation, L"LUMEN_DRIVER_REBOOT_REQUIRED", L"1");
  if (result == ERROR_SUCCESS) {
    log_message(installation, L"Driver completion requires a restart; ScheduleReboot is enabled.");
  }
  return result;
}
