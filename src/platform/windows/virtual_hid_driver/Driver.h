/**
 * @file Driver.h
 * @brief UMDF 2 HID minidriver declarations and per-device session state.
 */

#ifndef LUMEN_VIRTUAL_HID_DRIVER_H
#define LUMEN_VIRTUAL_HID_DRIVER_H

#include <windows.h>
#include <wdf.h>
#include <hidport.h>

#include "../virtual_hid_protocol.h"

/** Per-open state that binds ownership and the SET/GET response pair. */
typedef struct LUMEN_VHID_FILE_CONTEXT {
  BOOLEAN closing;  /**< True once file cleanup starts. */
} LUMEN_VHID_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_FILE_CONTEXT, LumenVhidGetFileContext);

/** Per-device HID queues, feature response, and global writer-session state. */
typedef struct LUMEN_VHID_DEVICE_CONTEXT {
  WDFDEVICE device;  /**< Owning UMDF device. */
  WDFWAITLOCK session_lock;  /**< Serializes feature operations and input fences. */
  WDFQUEUE input_reads;  /**< Pending composite HIDClass input read requests. */
  HID_DESCRIPTOR hid_descriptor;  /**< Static HID descriptor returned to HIDClass. */
  HID_DEVICE_ATTRIBUTES hid_attributes;  /**< Stable VID, PID, and revision. */
  uint8_t feature_response[LUMEN_VHID_FEATURE_PAYLOAD_SIZE];  /**< Last exact response. */
  size_t feature_response_size;  /**< Bytes valid at the start of feature_response. */
  WDFFILEOBJECT response_file;  /**< File entitled to consume the stored response. */
  ULONGLONG response_started_ms;  /**< Monotonic time used to expire abandoned responses. */
  WDFFILEOBJECT owner_file;  /**< File owning the active input-session token. */
  uint64_t next_session_token;  /**< Monotonically increasing token source. */
  uint64_t session_token;  /**< Current global session token, or zero. */
  uint64_t retired_session_token;  /**< Token accepted by an idempotent reset retry. */
  uint64_t last_released_token;  /**< Token accepted by an idempotent release retry. */
  uint64_t last_released_sequence;  /**< Final sequence for the released token. */
  uint64_t last_sequence;  /**< Last input sequence synchronously delivered. */
  ULONGLONG last_activity_ms;  /**< Monotonic activity time for abandoned-session recovery. */
  BOOLEAN session_exhausted;  /**< True after accepting terminal UINT64_MAX. */
  uint8_t mouse_buttons;  /**< Last complete five-button state. */
  uint16_t absolute_x;  /**< Last absolute X coordinate. */
  uint16_t absolute_y;  /**< Last absolute Y coordinate. */
} LUMEN_VHID_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_DEVICE_CONTEXT, LumenVhidGetDeviceContext);

/** Initialize the UMDF 2 driver object. */
DRIVER_INITIALIZE DriverEntry;
/** Create the HID minidriver filter device and its queues. */
EVT_WDF_DRIVER_DEVICE_ADD LumenVhidEvtDeviceAdd;
/** Handle HID descriptor, input, and vendor feature requests. */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LumenVhidEvtIoDeviceControl;
/** Neutralize and release any input session owned by a closing HID handle. */
EVT_WDF_FILE_CLEANUP LumenVhidEvtFileCleanup;

#endif /* LUMEN_VIRTUAL_HID_DRIVER_H */
