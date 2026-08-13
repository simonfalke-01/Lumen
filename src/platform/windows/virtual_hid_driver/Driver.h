/**
 * @file Driver.h
 * @brief KMDF/VHF driver declarations and per-device session state.
 */

#ifndef LUMEN_VIRTUAL_HID_DRIVER_H
#define LUMEN_VIRTUAL_HID_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include <vhf.h>

#include "../virtual_hid_protocol.h"

/** Per-open state used to reject cleanup races and make release idempotent. */
typedef struct LUMEN_VHID_FILE_CONTEXT {
  volatile LONG closing;  /**< Nonzero once cleanup begins. */
  uint64_t last_released_token;  /**< Token accepted by an idempotent release retry. */
  uint64_t last_released_sequence;  /**< Final sequence returned by a release retry. */
} LUMEN_VHID_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_FILE_CONTEXT, LumenVhidGetFileContext);

/** Per-device persistent VHF and exclusive-session state. */
typedef struct LUMEN_VHID_DEVICE_CONTEXT {
  WDFWAITLOCK session_lock;  /**< Serializes VHF calls, sessions, and cleanup. */
  VHFHANDLE vhf_handle;  /**< Persistent VHF source handle while hardware is prepared. */
  WDFFILEOBJECT owner_file;  /**< Open file that exclusively owns both collections. */
  uint64_t next_session_token;  /**< Monotonically increasing token source. */
  uint64_t session_token;  /**< Current owner generation token. */
  uint64_t retired_session_token;  /**< Last token accepted for reset retry. */
  uint64_t last_sequence;  /**< Last exact sequence accepted by VHF. */
  BOOLEAN session_exhausted;  /**< True after accepting terminal UINT64_MAX. */
  BOOLEAN stopping;  /**< Blocks control work during PnP teardown/startup. */
  volatile LONG rejection_logged;  /**< One-shot guard for bounded rejection logging. */
  uint8_t mouse_buttons;  /**< Last complete five-button state. */
  uint16_t absolute_x;  /**< Last absolute X retained for neutralization. */
  uint16_t absolute_y;  /**< Last absolute Y retained for neutralization. */
} LUMEN_VHID_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_DEVICE_CONTEXT, LumenVhidGetDeviceContext);

/** Initialize the KMDF driver object. */
DRIVER_INITIALIZE DriverEntry;
/** Create one secured root-enumerated function device and its control queue. */
EVT_WDF_DRIVER_DEVICE_ADD LumenVhidEvtDeviceAdd;
/** Create and start the persistent VHF child topology. */
EVT_WDF_DEVICE_PREPARE_HARDWARE LumenVhidEvtDevicePrepareHardware;
/** Neutralize input, release ownership, and synchronously delete VHF. */
EVT_WDF_DEVICE_RELEASE_HARDWARE LumenVhidEvtDeviceReleaseHardware;
/** Validate and execute one fixed METHOD_BUFFERED protocol request. */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LumenVhidEvtIoDeviceControl;
/** Drain the file's synchronous work, neutralize, and release its claim. */
EVT_WDF_FILE_CLEANUP LumenVhidEvtFileCleanup;

#endif /* LUMEN_VIRTUAL_HID_DRIVER_H */
