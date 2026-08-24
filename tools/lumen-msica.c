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

/** Convert a normalized braced ProductCode to its 32-character key token. */
static BOOL product_token(const wchar_t *product_code, wchar_t token[33]) {
  size_t input_index;
  size_t output_index = 0;
  if (product_code == NULL || wcslen(product_code) != 38u ||
      product_code[0] != L'{' || product_code[37] != L'}') {
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
