/**
 * @file Driver.h
 * @brief UMDF 2.15 VHF source-driver declarations and device state.
 */

#ifndef LUMEN_VIRTUAL_HID_DRIVER_H
#define LUMEN_VIRTUAL_HID_DRIVER_H

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <ntstatus.h>
#include <wdf.h>

/* VHF requires the NT and WDF declarations above. */
#include "../virtual_hid_protocol.h"

#include <vhf.h>

/** Per-open marker used to ensure requests originate from framework-owned files. */
typedef struct LUMEN_VHID_FILE_CONTEXT {
  BOOLEAN closing;  ///< True after file cleanup begins.
} LUMEN_VHID_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_FILE_CONTEXT, LumenVhidGetFileContext);

/** Per-device VHF transport and exact open-file ownership state. */
typedef struct LUMEN_VHID_DEVICE_CONTEXT {
  WDFDEVICE device;  ///< Owning UMDF device.
  WDFIOTARGET local_target;  ///< Open local target that supplies VHF's UMDF handle.
  VHFHANDLE vhf_handle;  ///< Started virtual HID device, or NULL when unavailable.
  WDFWAITLOCK state_lock;  ///< Serializes ownership, report submission, and VHF reset.
  WDFFILEOBJECT owner_file;  ///< Exact framework file that currently owns submission.
  BOOLEAN ready;  ///< True only while vhf_handle has started successfully.
} LUMEN_VHID_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_DEVICE_CONTEXT, LumenVhidGetDeviceContext);

/** Initialize the UMDF 2 driver object. */
DRIVER_INITIALIZE DriverEntry;
/** Create the VHF source device, control interface, and default I/O queue. */
EVT_WDF_DRIVER_DEVICE_ADD LumenVhidEvtDeviceAdd;
/** Dispatch the four exact METHOD_BUFFERED control operations. */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LumenVhidEvtIoDeviceControl;
/** Reset VHF and release ownership held by a closing file. */
EVT_WDF_FILE_CLEANUP LumenVhidEvtFileCleanup;
/** Synchronously delete VHF when its UMDF parent device is destroyed. */
EVT_WDF_OBJECT_CONTEXT_CLEANUP LumenVhidEvtDeviceCleanup;

#endif /* LUMEN_VIRTUAL_HID_DRIVER_H */
