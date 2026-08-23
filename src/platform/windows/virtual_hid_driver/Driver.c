/**
 * @file Driver.c
 * @brief Root-enumerated UMDF 2.15 VHF source driver for Lumen input injection.
 */

#include "Driver.h"

#include "HidDescriptors.h"

#include <limits.h>

/** Maximum time allowed for queued neutral reports to reach VHF during reset. */
#define LUMEN_VHID_NEUTRAL_DRAIN_TIMEOUT_MS 1000u

/** Stop and synchronously delete the current VHF instance. */
static VOID LumenVhidDeleteVhf(LUMEN_VHID_DEVICE_CONTEXT *context);

/** Concrete definition for the control device-interface GUID. */
const GUID GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID = {
  0xaec36f6e,
  0x3bb9,
  0x47c6,
  {0xbf, 0x3c, 0x11, 0xa5, 0x62, 0xdd, 0x48, 0x40}
};

/**
 * Verify that a request has a non-null file object created for this device.
 *
 * @param device Device that owns the request queue.
 * @param request Candidate request.
 * @param file_object Receives the validated file object.
 * @return STATUS_SUCCESS for a live, known file; an access error otherwise.
 */
static NTSTATUS LumenVhidGetKnownFileObject(WDFDEVICE device, WDFREQUEST request, WDFFILEOBJECT *file_object) {
  WDFFILEOBJECT candidate;
  LUMEN_VHID_FILE_CONTEXT *file_context;

  if (file_object == NULL) {
    return STATUS_INVALID_PARAMETER;
  }
  candidate = WdfRequestGetFileObject(request);
  if (candidate == NULL || WdfFileObjectGetDevice(candidate) != device) {
    return STATUS_ACCESS_DENIED;
  }
  file_context = LumenVhidGetFileContext(candidate);
  if (file_context == NULL || file_context->closing) {
    return STATUS_FILE_CLOSED;
  }
  *file_object = candidate;
  return STATUS_SUCCESS;
}

/**
 * Create and start the virtual HID child using the already-open local target.
 *
 * @param context Device state whose VHF handle is currently null.
 * @return Status from local-target validation, VhfCreate, or VhfStart.
 */
static NTSTATUS LumenVhidCreateAndStart(LUMEN_VHID_DEVICE_CONTEXT *context) {
  VHF_CONFIG config;
  HANDLE local_handle;
  NTSTATUS status;

  if (context == NULL || context->local_target == NULL || context->vhf_handle != NULL) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  local_handle = WdfIoTargetWdmGetTargetFileHandle(context->local_target);
  if (local_handle == NULL || local_handle == INVALID_HANDLE_VALUE) {
    return STATUS_INVALID_HANDLE;
  }

  VHF_CONFIG_INIT(&config, local_handle, LumenVhidReportDescriptorLength, (PUCHAR) LumenVhidReportDescriptor);
  config.VhfClientContext = context;
  config.VendorID = LUMEN_VHID_VENDOR_ID;
  config.ProductID = LUMEN_VHID_PRODUCT_ID;
  config.VersionNumber = LUMEN_VHID_VERSION_NUMBER;
  config.EvtVhfReadyForNextReadReport = LumenVhidEvtVhfReadyForNextReadReport;

  context->shutting_down = FALSE;
  context->vhf_ready_for_input_report = FALSE;
  context->input_submission_active = FALSE;
  context->has_in_flight_report = FALSE;
  LumenVhidReportQueueClear(&context->pending_reports);
  SetEvent(context->submissions_drained_event);
  SetEvent(context->reports_drained_event);

  status = VhfCreate(&config, &context->vhf_handle);
  if (!NT_SUCCESS(status)) {
    context->vhf_handle = NULL;
    context->ready = FALSE;
    context->shutting_down = TRUE;
    return status;
  }
  status = VhfStart(context->vhf_handle);
  if (!NT_SUCCESS(status)) {
    LumenVhidDeleteVhf(context);
    return status;
  }
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    LumenVhidDeleteVhf(context);
    return status;
  }
  context->ready = TRUE;
  WdfWaitLockRelease(context->state_lock);
  return STATUS_SUCCESS;
}

/**
 * Update both manual-reset drain events while state_lock is held.
 *
 * @param context Locked device state.
 */
static VOID LumenVhidUpdateDrainEventsLocked(LUMEN_VHID_DEVICE_CONTEXT *context) {
  if (context->submissions_drained_event != NULL) {
    if (context->input_submission_active) {
      ResetEvent(context->submissions_drained_event);
    } else {
      SetEvent(context->submissions_drained_event);
    }
  }
  if (context->reports_drained_event != NULL) {
    if (context->input_submission_active || context->has_in_flight_report || context->pending_reports.count != 0u) {
      ResetEvent(context->reports_drained_event);
    } else {
      SetEvent(context->reports_drained_event);
    }
  }
}

/**
 * Stop VHF after preventing new submissions and draining any active API call.
 *
 * No state lock is held across VhfDelete or the drain wait. VhfDelete's
 * synchronous form drains the readiness callback before in-flight bytes are
 * released.
 *
 * @param context Device state whose VHF instance should be deleted.
 */
static VOID LumenVhidDeleteVhf(LUMEN_VHID_DEVICE_CONTEXT *context) {
  VHFHANDLE vhf_handle;
  NTSTATUS status;

  if (context == NULL) {
    return;
  }
  if (context->state_lock == NULL) {
    context->ready = FALSE;
    context->shutting_down = TRUE;
    context->owner_file = NULL;
    if (context->vhf_handle != NULL) {
      VhfDelete(context->vhf_handle, TRUE);
      context->vhf_handle = NULL;
    }
    return;
  }

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  context->ready = FALSE;
  context->shutting_down = TRUE;
  context->vhf_ready_for_input_report = FALSE;
  context->owner_file = NULL;
  LumenVhidReportQueueClear(&context->pending_reports);
  vhf_handle = context->vhf_handle;
  context->vhf_handle = NULL;
  LumenVhidUpdateDrainEventsLocked(context);
  WdfWaitLockRelease(context->state_lock);

  if (context->submissions_drained_event != NULL) {
    (void) WaitForSingleObject(context->submissions_drained_event, INFINITE);
  }
  if (vhf_handle != NULL) {
    VhfDelete(vhf_handle, TRUE);
  }

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (NT_SUCCESS(status)) {
    context->input_submission_active = FALSE;
    context->has_in_flight_report = FALSE;
    ZeroMemory(&context->in_flight_report, sizeof(context->in_flight_report));
    LumenVhidUpdateDrainEventsLocked(context);
    WdfWaitLockRelease(context->state_lock);
  }
}

/**
 * Stop VHF and delete the local target created during PrepareHardware.
 *
 * The function is idempotent so device cleanup can defensively call it after
 * the normal ReleaseHardware path.
 *
 * @param context Device state to return to its unprepared state.
 */
static VOID LumenVhidStopAndCloseTarget(LUMEN_VHID_DEVICE_CONTEXT *context) {
  if (context == NULL) {
    return;
  }

  LumenVhidDeleteVhf(context);
  if (context->local_target != NULL) {
    WdfIoTargetClose(context->local_target);
    WdfObjectDelete(context->local_target);
    context->local_target = NULL;
  }
}

/**
 * Submit at most one queued report for each readiness grant.
 *
 * The report is copied into persistent device-context storage before the lock
 * is released. The callback releases that storage only after VHF confirms it
 * no longer references the bytes. Failed reports return to the front of the
 * ordered queue.
 *
 * @param context Device state with a started VHF handle and pending queue.
 * @return First VhfReadReportSubmit error, or STATUS_SUCCESS.
 */
static NTSTATUS LumenVhidSubmitNext(LUMEN_VHID_DEVICE_CONTEXT *context) {
  HID_XFER_PACKET packet;
  VHFHANDLE vhf_handle;
  NTSTATUS status;
  NTSTATUS lock_status;

  for (;;) {
    lock_status = WdfWaitLockAcquire(context->state_lock, NULL);
    if (!NT_SUCCESS(lock_status)) {
      return lock_status;
    }
    if (context->shutting_down || !context->ready || context->vhf_handle == NULL ||
        !context->vhf_ready_for_input_report || context->input_submission_active ||
        context->pending_reports.count == 0u) {
      WdfWaitLockRelease(context->state_lock);
      return STATUS_SUCCESS;
    }

    /* A grant received during the prior API call also releases those bytes. */
    context->has_in_flight_report = FALSE;
    if (!LumenVhidReportQueuePop(&context->pending_reports, &context->in_flight_report)) {
      WdfWaitLockRelease(context->state_lock);
      return STATUS_SUCCESS;
    }
    context->has_in_flight_report = TRUE;
    context->vhf_ready_for_input_report = FALSE;
    context->input_submission_active = TRUE;
    vhf_handle = context->vhf_handle;
    LumenVhidUpdateDrainEventsLocked(context);
    WdfWaitLockRelease(context->state_lock);

    ZeroMemory(&packet, sizeof(packet));
    packet.reportBuffer = context->in_flight_report.bytes;
    packet.reportBufferLen = (ULONG) context->in_flight_report.size;
    packet.reportId = packet.reportBuffer[0];
    status = VhfReadReportSubmit(vhf_handle, &packet);

    lock_status = WdfWaitLockAcquire(context->state_lock, NULL);
    if (!NT_SUCCESS(lock_status)) {
      return lock_status;
    }
    context->input_submission_active = FALSE;
    if (!NT_SUCCESS(status)) {
      context->has_in_flight_report = FALSE;
      (void) LumenVhidReportQueuePushFront(&context->pending_reports, &context->in_flight_report);
    } else if (context->vhf_ready_for_input_report) {
      /* A callback that raced the API call already released these bytes. */
      context->has_in_flight_report = FALSE;
    }
    LumenVhidUpdateDrainEventsLocked(context);
    if (!NT_SUCCESS(status) || !context->vhf_ready_for_input_report) {
      WdfWaitLockRelease(context->state_lock);
      return status;
    }
    WdfWaitLockRelease(context->state_lock);
  }
}

/**
 * Validate and queue one ABI report request while state_lock is held.
 *
 * @param context Started VHF device state.
 * @param input Exact packed submit request copied from the caller.
 * @return Validation, capacity, or device-state status.
 */
static NTSTATUS LumenVhidQueueRequestLocked(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  const LUMEN_VHID_SUBMIT_REPORT_REQUEST *input
) {
  const void *report;
  size_t report_size;

  if (context->shutting_down || !context->ready || context->vhf_handle == NULL) {
    return STATUS_DEVICE_NOT_READY;
  }
  switch (input->report_kind) {
    case LUMEN_VHID_REPORT_KIND_KEYBOARD:
      if (input->report.keyboard.report_id != LUMEN_VHID_REPORT_ID_KEYBOARD) {
        return STATUS_INVALID_PARAMETER;
      }
      report = &input->report.keyboard;
      report_size = sizeof(input->report.keyboard);
      break;

    case LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE:
      if (input->report.relative_mouse.report_id != LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE ||
          (input->report.relative_mouse.buttons & 0xe0u) != 0) {
        return STATUS_INVALID_PARAMETER;
      }
      report = &input->report.relative_mouse;
      report_size = sizeof(input->report.relative_mouse);
      break;

    case LUMEN_VHID_REPORT_KIND_CONSUMER:
      if (input->report.consumer.report_id != LUMEN_VHID_REPORT_ID_CONSUMER) {
        return STATUS_INVALID_PARAMETER;
      }
      report = &input->report.consumer;
      report_size = sizeof(input->report.consumer);
      break;

    case LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE:
      if (input->report.absolute_mouse.report_id != LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE ||
          (input->report.absolute_mouse.buttons & 0xe0u) != 0) {
        return STATUS_INVALID_PARAMETER;
      }
      report = &input->report.absolute_mouse;
      report_size = sizeof(input->report.absolute_mouse);
      break;

    default:
      return STATUS_INVALID_PARAMETER;
  }

  if (!LumenVhidReportQueuePush(&context->pending_reports, input->report_kind, report, report_size)) {
    return STATUS_BUFFER_OVERFLOW;
  }
  LumenVhidUpdateDrainEventsLocked(context);
  return STATUS_SUCCESS;
}

/**
 * Queue neutral state for every collection and wait briefly for VHF to drain.
 *
 * All reports are queued together so their report-ID transitions remain
 * ordered. Teardown continues after the bounded wait because deleting the HID
 * device itself also releases host input state.
 *
 * @param context Started VHF device state.
 * @return Queue, submission, or bounded drain status.
 */
static NTSTATUS LumenVhidSubmitNeutralState(LUMEN_VHID_DEVICE_CONTEXT *context) {
  LUMEN_VHID_KEYBOARD_REPORT keyboard;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT mouse;
  LUMEN_VHID_ABSOLUTE_MOUSE_REPORT absolute_mouse;
  LUMEN_VHID_CONSUMER_REPORT consumer;
  NTSTATUS status;
  DWORD wait_status;

  ZeroMemory(&keyboard, sizeof(keyboard));
  keyboard.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
  ZeroMemory(&mouse, sizeof(mouse));
  mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
  ZeroMemory(&absolute_mouse, sizeof(absolute_mouse));
  absolute_mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE;
  ZeroMemory(&consumer, sizeof(consumer));
  consumer.report_id = LUMEN_VHID_REPORT_ID_CONSUMER;

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  LumenVhidReportQueueClear(&context->pending_reports);
  if (!LumenVhidReportQueueAppend(&context->pending_reports, &keyboard, sizeof(keyboard)) ||
      !LumenVhidReportQueueAppend(&context->pending_reports, &mouse, sizeof(mouse)) ||
      !LumenVhidReportQueueAppend(&context->pending_reports, &absolute_mouse, sizeof(absolute_mouse)) ||
      !LumenVhidReportQueueAppend(&context->pending_reports, &consumer, sizeof(consumer))) {
    LumenVhidReportQueueClear(&context->pending_reports);
    LumenVhidUpdateDrainEventsLocked(context);
    WdfWaitLockRelease(context->state_lock);
    return STATUS_BUFFER_OVERFLOW;
  }
  LumenVhidUpdateDrainEventsLocked(context);
  WdfWaitLockRelease(context->state_lock);

  status = LumenVhidSubmitNext(context);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  wait_status = WaitForSingleObject(context->reports_drained_event, LUMEN_VHID_NEUTRAL_DRAIN_TIMEOUT_MS);
  return wait_status == WAIT_OBJECT_0 ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
}

/**
 * Neutralize, synchronously delete, recreate, and release the current owner.
 *
 * The caller must have verified exact ownership. Ownership is cleared even when
 * recreation fails so a closing file can never remain stored in device state.
 * GET_INFO exposes any resulting not-ready state.
 *
 * @param context Device state whose ownership and VHF instance are reset.
 * @return First neutralization error, or the VHF recreation status.
 */
static NTSTATUS LumenVhidResetAndRelease(LUMEN_VHID_DEVICE_CONTEXT *context) {
  NTSTATUS neutral_status;
  NTSTATUS create_status;

  neutral_status = LumenVhidSubmitNeutralState(context);
  LumenVhidDeleteVhf(context);
  create_status = LumenVhidCreateAndStart(context);

  if (!NT_SUCCESS(create_status)) {
    return create_status;
  }
  if (neutral_status == STATUS_IO_TIMEOUT) {
    return STATUS_SUCCESS;
  }
  return neutral_status;
}

VOID LumenVhidEvtVhfReadyForNextReadReport(PVOID vhf_client_context) {
  LUMEN_VHID_DEVICE_CONTEXT *context = (LUMEN_VHID_DEVICE_CONTEXT *) vhf_client_context;
  BOOLEAN submit_next = FALSE;
  NTSTATUS status;

  if (context == NULL) {
    return;
  }
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  if (!context->shutting_down && context->vhf_handle != NULL) {
    /* The grant confirms VHF no longer references the prior report bytes. */
    if (!context->input_submission_active) {
      context->has_in_flight_report = FALSE;
    }
    context->vhf_ready_for_input_report = TRUE;
    LumenVhidUpdateDrainEventsLocked(context);
    submit_next = !context->input_submission_active && context->pending_reports.count != 0u;
  }
  WdfWaitLockRelease(context->state_lock);

  if (submit_next) {
    (void) LumenVhidSubmitNext(context);
  }
}

/**
 * Handle the ABI readiness probe.
 *
 * @param context Device state protected by state_lock.
 * @param request Current request with exactly eight output bytes.
 * @return Buffer retrieval or copy status.
 */
static NTSTATUS LumenVhidHandleGetInfo(LUMEN_VHID_DEVICE_CONTEXT *context, WDFREQUEST request) {
  LUMEN_VHID_GET_INFO_RESPONSE response;
  void *output;
  size_t output_size;
  NTSTATUS status;

  status = WdfRequestRetrieveOutputBuffer(request, sizeof(response), &output, &output_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (output_size != sizeof(response)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  response.abi_version = LUMEN_VHID_ABI_VERSION;
  response.ready = context->ready ? 1u : 0u;
  CopyMemory(output, &response, sizeof(response));
  WdfRequestSetInformation(request, sizeof(response));
  return STATUS_SUCCESS;
}

/**
 * Dispatch the static ABI and additive dynamic-gamepad control operations.
 *
 * @param queue Default device queue.
 * @param request Current METHOD_BUFFERED request.
 * @param output_buffer_length Exact output-buffer byte count.
 * @param input_buffer_length Exact input-buffer byte count.
 * @param io_control_code Custom control code.
 */
VOID LumenVhidEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t output_buffer_length, size_t input_buffer_length, ULONG io_control_code) {
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_SUBMIT_REPORT_REQUEST local_input;
  const void *input;
  size_t input_size;
  WDFFILEOBJECT file_object;
  BOOLEAN gamepad_handled;
  NTSTATUS status;

  status = LumenVhidGetKnownFileObject(device, request, &file_object);
  if (!NT_SUCCESS(status)) {
    WdfRequestComplete(request, status);
    return;
  }

  status = LumenVhidGamepadDispatchIoctl(
    context,
    request,
    file_object,
    output_buffer_length,
    input_buffer_length,
    io_control_code,
    &gamepad_handled
  );
  if (gamepad_handled) {
    WdfRequestCompleteWithInformation(
      request,
      status,
      NT_SUCCESS(status) ? WdfRequestGetInformation(request) : 0
    );
    return;
  }

  switch (io_control_code) {
    case IOCTL_LUMEN_VHID_GET_INFO:
      if (input_buffer_length != 0 ||
          output_buffer_length != sizeof(LUMEN_VHID_GET_INFO_RESPONSE)) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
      }
      status = WdfWaitLockAcquire(context->state_lock, NULL);
      if (NT_SUCCESS(status)) {
        status = LumenVhidHandleGetInfo(context, request);
        WdfWaitLockRelease(context->state_lock);
      }
      break;

    case IOCTL_LUMEN_VHID_CLAIM:
      if (input_buffer_length != 0 || output_buffer_length != 0) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
      }
      status = WdfWaitLockAcquire(context->state_lock, NULL);
      if (NT_SUCCESS(status)) {
        if (!context->ready) {
          status = STATUS_DEVICE_NOT_READY;
        } else if (context->owner_file == NULL || context->owner_file == file_object) {
          context->owner_file = file_object;
          status = STATUS_SUCCESS;
        } else {
          status = STATUS_DEVICE_BUSY;
        }
        WdfWaitLockRelease(context->state_lock);
      }
      break;

    case IOCTL_LUMEN_VHID_SUBMIT_REPORT:
      if (input_buffer_length != sizeof(local_input) || output_buffer_length != 0) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
      }
      status = WdfRequestRetrieveInputBuffer(request, sizeof(local_input), (void **) &input, &input_size);
      if (!NT_SUCCESS(status)) {
        break;
      }
      if (input_size != sizeof(local_input)) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
      }
      CopyMemory(&local_input, input, sizeof(local_input));
      status = WdfWaitLockAcquire(context->state_lock, NULL);
      if (NT_SUCCESS(status)) {
        if (context->owner_file != file_object) {
          status = STATUS_ACCESS_DENIED;
        } else {
          status = LumenVhidQueueRequestLocked(context, &local_input);
        }
        WdfWaitLockRelease(context->state_lock);
      }
      if (NT_SUCCESS(status)) {
        status = LumenVhidSubmitNext(context);
      }
      break;

    case IOCTL_LUMEN_VHID_RESET_AND_RELEASE:
      if (input_buffer_length != 0 || output_buffer_length != 0) {
        status = STATUS_INVALID_BUFFER_SIZE;
        break;
      }
      status = WdfWaitLockAcquire(context->state_lock, NULL);
      if (NT_SUCCESS(status)) {
        if (context->owner_file != file_object) {
          status = STATUS_ACCESS_DENIED;
        }
        WdfWaitLockRelease(context->state_lock);
      }
      if (NT_SUCCESS(status)) {
        status = LumenVhidResetAndRelease(context);
      }
      break;

    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }

  WdfRequestCompleteWithInformation(request, status, NT_SUCCESS(status) ? WdfRequestGetInformation(request) : 0);
}

VOID LumenVhidEvtFileCleanup(WDFFILEOBJECT file_object) {
  WDFDEVICE device = WdfFileObjectGetDevice(file_object);
  LUMEN_VHID_DEVICE_CONTEXT *context;
  LUMEN_VHID_FILE_CONTEXT *file_context;
  BOOLEAN reset_owner = FALSE;
  NTSTATUS status;

  if (device == NULL) {
    return;
  }
  file_context = LumenVhidGetFileContext(file_object);
  file_context->closing = TRUE;
  context = LumenVhidGetDeviceContext(device);
  LumenVhidGamepadCleanupFile(context, file_object);
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  if (context->owner_file == file_object) {
    if (!context->ready || context->vhf_handle == NULL) {
      context->owner_file = NULL;
    } else {
      reset_owner = TRUE;
    }
  }
  WdfWaitLockRelease(context->state_lock);
  if (reset_owner) {
    (void) LumenVhidResetAndRelease(context);
  }
}

VOID LumenVhidEvtDeviceCleanup(WDFOBJECT device_object) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device_object);

  LumenVhidGamepadUninitialize(context);
  LumenVhidStopAndCloseTarget(context);
  if (context->reports_drained_event != NULL) {
    CloseHandle(context->reports_drained_event);
    context->reports_drained_event = NULL;
  }
  if (context->submissions_drained_event != NULL) {
    CloseHandle(context->submissions_drained_event);
    context->submissions_drained_event = NULL;
  }
}

NTSTATUS LumenVhidEvtDevicePrepareHardware(WDFDEVICE device, WDFCMRESLIST resources_raw, WDFCMRESLIST resources_translated) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  WDF_OBJECT_ATTRIBUTES target_attributes;
  WDF_IO_TARGET_OPEN_PARAMS open_params;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(resources_raw);
  UNREFERENCED_PARAMETER(resources_translated);

  if (context->local_target != NULL || context->vhf_handle != NULL) {
    return STATUS_INVALID_DEVICE_STATE;
  }

  WDF_OBJECT_ATTRIBUTES_INIT(&target_attributes);
  target_attributes.ParentObject = device;
  status = WdfIoTargetCreate(device, &target_attributes, &context->local_target);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  WDF_IO_TARGET_OPEN_PARAMS_INIT_OPEN_BY_FILE(&open_params, NULL);
  status = WdfIoTargetOpen(context->local_target, &open_params);
  if (!NT_SUCCESS(status)) {
    LumenVhidStopAndCloseTarget(context);
    return status;
  }

  status = LumenVhidCreateAndStart(context);
  if (!NT_SUCCESS(status)) {
    LumenVhidStopAndCloseTarget(context);
  }
  return status;
}

NTSTATUS LumenVhidEvtDeviceReleaseHardware(WDFDEVICE device, WDFCMRESLIST resources_translated) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);

  UNREFERENCED_PARAMETER(resources_translated);

  LumenVhidGamepadReleaseHardware(context);
  LumenVhidStopAndCloseTarget(context);
  return STATUS_SUCCESS;
}

NTSTATUS LumenVhidEvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init) {
  WDF_FILEOBJECT_CONFIG file_config;
  WDF_OBJECT_ATTRIBUTES file_attributes;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  WDF_OBJECT_ATTRIBUTES child_attributes;
  WDF_PNPPOWER_EVENT_CALLBACKS pnp_callbacks;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDFDEVICE device;
  LUMEN_VHID_DEVICE_CONTEXT *context;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(driver);

  WDF_FILEOBJECT_CONFIG_INIT(&file_config, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, LumenVhidEvtFileCleanup);
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&file_attributes, LUMEN_VHID_FILE_CONTEXT);
  file_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &file_attributes);

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp_callbacks);
  pnp_callbacks.EvtDevicePrepareHardware = LumenVhidEvtDevicePrepareHardware;
  pnp_callbacks.EvtDeviceReleaseHardware = LumenVhidEvtDeviceReleaseHardware;
  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_callbacks);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, LUMEN_VHID_DEVICE_CONTEXT);
  device_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  device_attributes.EvtCleanupCallback = LumenVhidEvtDeviceCleanup;
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  context = LumenVhidGetDeviceContext(device);
  context->device = device;

  WDF_OBJECT_ATTRIBUTES_INIT(&child_attributes);
  child_attributes.ParentObject = device;
  status = WdfWaitLockCreate(&child_attributes, &context->state_lock);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  context->submissions_drained_event = CreateEventW(NULL, TRUE, TRUE, NULL);
  if (context->submissions_drained_event == NULL) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  context->reports_drained_event = CreateEventW(NULL, TRUE, TRUE, NULL);
  if (context->reports_drained_event == NULL) {
    CloseHandle(context->submissions_drained_event);
    context->submissions_drained_event = NULL;
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  status = LumenVhidGamepadInitialize(context);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchSequential);
  queue_config.EvtIoDeviceControl = LumenVhidEvtIoDeviceControl;
  return WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, NULL);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
  WDF_DRIVER_CONFIG config;
  WDF_OBJECT_ATTRIBUTES attributes;

  WDF_DRIVER_CONFIG_INIT(&config, LumenVhidEvtDeviceAdd);
  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
  attributes.ExecutionLevel = WdfExecutionLevelPassive;
  return WdfDriverCreate(driver_object, registry_path, &attributes, &config, WDF_NO_HANDLE);
}
