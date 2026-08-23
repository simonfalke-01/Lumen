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
#include "DynamicGamepad.h"
#include "ReportQueue.h"

#include <vhf.h>

/** Per-open marker used to ensure requests originate from framework-owned files. */
typedef struct LUMEN_VHID_FILE_CONTEXT {
  BOOLEAN closing;  ///< True after file cleanup begins.
} LUMEN_VHID_FILE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_FILE_CONTEXT, LumenVhidGetFileContext);

/** Per-device VHF transport, input queue, and exact open-file ownership state. */
typedef struct LUMEN_VHID_DEVICE_CONTEXT {
  WDFDEVICE device;  ///< Owning UMDF device.
  WDFIOTARGET local_target;  ///< PrepareHardware-owned local target supplying VHF's UMDF handle.
  VHFHANDLE vhf_handle;  ///< Started virtual HID device, or NULL when unavailable.
  WDFWAITLOCK state_lock;  ///< Serializes ownership, queue state, submission grants, and VHF reset.
  WDFFILEOBJECT owner_file;  ///< Exact framework file that currently owns submission.
  BOOLEAN ready;  ///< True only while vhf_handle has started successfully.
  BOOLEAN shutting_down;  ///< True while callbacks and new submissions must drain or stop.
  BOOLEAN vhf_ready_for_input_report;  ///< One outstanding VHF readiness grant.
  BOOLEAN input_submission_active;  ///< True only across one unlocked VhfReadReportSubmit call.
  BOOLEAN has_in_flight_report;  ///< True while VHF may reference in_flight_report bytes.
  LUMEN_VHID_REPORT_QUEUE pending_reports;  ///< Ordered bounded reports awaiting a readiness grant.
  LUMEN_VHID_QUEUED_REPORT in_flight_report;  ///< Stable storage retained until the next callback.
  HANDLE submissions_drained_event;  ///< Manual-reset event signaled when no submit call is active.
  HANDLE reports_drained_event;  ///< Manual-reset event signaled after VHF consumes all queued reports.
  uint64_t next_gamepad_device_id;  ///< Next nonzero dynamic-gamepad identifier.
  uint64_t next_gamepad_generation;  ///< Next nonzero stale-handle generation.
  LUMEN_VHID_DYNAMIC_GAMEPAD gamepads[LUMEN_VHID_MAX_GAMEPADS];  ///< Isolated fixed dynamic-gamepad slots.
} LUMEN_VHID_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(LUMEN_VHID_DEVICE_CONTEXT, LumenVhidGetDeviceContext);

/** Initialize the UMDF 2 driver object. */
DRIVER_INITIALIZE DriverEntry;
/** Create the source device, register PnP callbacks, interface, and I/O queue. */
EVT_WDF_DRIVER_DEVICE_ADD LumenVhidEvtDeviceAdd;
/** Open the local target and start VHF after the PnP stack is prepared. */
EVT_WDF_DEVICE_PREPARE_HARDWARE LumenVhidEvtDevicePrepareHardware;
/** Stop VHF and close the local target before hardware resources are released. */
EVT_WDF_DEVICE_RELEASE_HARDWARE LumenVhidEvtDeviceReleaseHardware;
/** Dispatch the static ABI and additive dynamic-gamepad operations. */
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL LumenVhidEvtIoDeviceControl;
/** Reset VHF and release ownership held by a closing file. */
EVT_WDF_FILE_CLEANUP LumenVhidEvtFileCleanup;
/** Synchronously delete VHF when its UMDF parent device is destroyed. */
EVT_WDF_OBJECT_CONTEXT_CLEANUP LumenVhidEvtDeviceCleanup;
/** Release the previous report buffer and consume one new VHF readiness grant. */
EVT_VHF_READY_FOR_NEXT_READ_REPORT LumenVhidEvtVhfReadyForNextReadReport;

#endif /* LUMEN_VIRTUAL_HID_DRIVER_H */
