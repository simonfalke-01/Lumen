/**
 * @file Driver.c
 * @brief Root-enumerated UMDF 2.15 VHF source driver for Lumen input injection.
 */

#include "Driver.h"

#include "HidDescriptors.h"

#include <limits.h>

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
 * The VHF ready-for-read callback is deliberately omitted, selecting VHF's
 * default input-report buffering policy.
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
  config.VendorID = LUMEN_VHID_VENDOR_ID;
  config.ProductID = LUMEN_VHID_PRODUCT_ID;
  config.VersionNumber = LUMEN_VHID_VERSION_NUMBER;

  status = VhfCreate(&config, &context->vhf_handle);
  if (!NT_SUCCESS(status)) {
    context->vhf_handle = NULL;
    context->ready = FALSE;
    return status;
  }
  status = VhfStart(context->vhf_handle);
  if (!NT_SUCCESS(status)) {
    VhfDelete(context->vhf_handle, TRUE);
    context->vhf_handle = NULL;
    context->ready = FALSE;
    return status;
  }
  context->ready = TRUE;
  return STATUS_SUCCESS;
}

/**
 * Submit one complete input report through VHF.
 *
 * @param context Device state with a started VHF handle.
 * @param report Complete HID report including report ID.
 * @param report_size Exact number of bytes in report.
 * @return Status returned by VhfReadReportSubmit.
 */
static NTSTATUS LumenVhidSubmitBytes(LUMEN_VHID_DEVICE_CONTEXT *context, const void *report, size_t report_size) {
  HID_XFER_PACKET packet;

  if (context == NULL || !context->ready || context->vhf_handle == NULL) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  if (report == NULL || report_size == 0 || report_size > ULONG_MAX) {
    return STATUS_INVALID_PARAMETER;
  }
  ZeroMemory(&packet, sizeof(packet));
  packet.reportBuffer = (PUCHAR) report;
  packet.reportBufferLen = (ULONG) report_size;
  packet.reportId = packet.reportBuffer[0];
  return VhfReadReportSubmit(context->vhf_handle, &packet);
}

/**
 * Validate and submit one ABI report request.
 *
 * @param context Started VHF device state.
 * @param input Exact packed submit request copied from the caller.
 * @return Validation error or VHF submission status.
 */
static NTSTATUS LumenVhidSubmitRequest(LUMEN_VHID_DEVICE_CONTEXT *context, const LUMEN_VHID_SUBMIT_REPORT_REQUEST *input) {
  switch (input->report_kind) {
    case LUMEN_VHID_REPORT_KIND_KEYBOARD:
      if (input->report.keyboard.report_id != LUMEN_VHID_REPORT_ID_KEYBOARD) {
        return STATUS_INVALID_PARAMETER;
      }
      return LumenVhidSubmitBytes(context, &input->report.keyboard, sizeof(input->report.keyboard));

    case LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE:
      if (input->report.relative_mouse.report_id != LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE ||
          (input->report.relative_mouse.buttons & 0xe0u) != 0) {
        return STATUS_INVALID_PARAMETER;
      }
      return LumenVhidSubmitBytes(context, &input->report.relative_mouse, sizeof(input->report.relative_mouse));

    case LUMEN_VHID_REPORT_KIND_CONSUMER:
      if (input->report.consumer.report_id != LUMEN_VHID_REPORT_ID_CONSUMER) {
        return STATUS_INVALID_PARAMETER;
      }
      return LumenVhidSubmitBytes(context, &input->report.consumer, sizeof(input->report.consumer));

    default:
      return STATUS_INVALID_PARAMETER;
  }
}

/**
 * Submit neutral state for every collection.
 *
 * All reports are attempted so VHF receives as much neutral state as possible.
 *
 * @param context Started VHF device state.
 * @return First failed submission status, or STATUS_SUCCESS.
 */
static NTSTATUS LumenVhidSubmitNeutralState(LUMEN_VHID_DEVICE_CONTEXT *context) {
  LUMEN_VHID_KEYBOARD_REPORT keyboard;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT mouse;
  LUMEN_VHID_CONSUMER_REPORT consumer;
  NTSTATUS first_status = STATUS_SUCCESS;
  NTSTATUS status;

  ZeroMemory(&keyboard, sizeof(keyboard));
  keyboard.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
  status = LumenVhidSubmitBytes(context, &keyboard, sizeof(keyboard));
  if (!NT_SUCCESS(status)) {
    first_status = status;
  }

  ZeroMemory(&mouse, sizeof(mouse));
  mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
  status = LumenVhidSubmitBytes(context, &mouse, sizeof(mouse));
  if (NT_SUCCESS(first_status) && !NT_SUCCESS(status)) {
    first_status = status;
  }

  ZeroMemory(&consumer, sizeof(consumer));
  consumer.report_id = LUMEN_VHID_REPORT_ID_CONSUMER;
  status = LumenVhidSubmitBytes(context, &consumer, sizeof(consumer));
  if (NT_SUCCESS(first_status) && !NT_SUCCESS(status)) {
    first_status = status;
  }
  return first_status;
}

/**
 * Neutralize, synchronously delete, recreate, and release the current owner.
 *
 * The caller must hold state_lock and must have verified exact ownership.
 * Ownership is cleared even when recreation fails so a closing file can never
 * remain stored in device state. GET_INFO exposes any resulting not-ready state.
 *
 * @param context Device state protected by state_lock.
 * @return First neutralization error, or the VHF recreation status.
 */
static NTSTATUS LumenVhidResetAndRelease(LUMEN_VHID_DEVICE_CONTEXT *context) {
  NTSTATUS neutral_status;
  NTSTATUS create_status;

  neutral_status = LumenVhidSubmitNeutralState(context);
  context->ready = FALSE;
  context->owner_file = NULL;
  VhfDelete(context->vhf_handle, TRUE);
  context->vhf_handle = NULL;
  create_status = LumenVhidCreateAndStart(context);

  if (!NT_SUCCESS(create_status)) {
    return create_status;
  }
  return neutral_status;
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
 * Dispatch the four exact custom control operations.
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
  NTSTATUS status;

  status = LumenVhidGetKnownFileObject(device, request, &file_object);
  if (!NT_SUCCESS(status)) {
    WdfRequestComplete(request, status);
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
          status = LumenVhidSubmitRequest(context, &local_input);
        }
        WdfWaitLockRelease(context->state_lock);
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
        } else {
          status = LumenVhidResetAndRelease(context);
        }
        WdfWaitLockRelease(context->state_lock);
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
  NTSTATUS status;

  if (device == NULL) {
    return;
  }
  file_context = LumenVhidGetFileContext(file_object);
  file_context->closing = TRUE;
  context = LumenVhidGetDeviceContext(device);
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  if (context->owner_file == file_object && context->ready && context->vhf_handle != NULL) {
    (void) LumenVhidResetAndRelease(context);
  } else if (context->owner_file == file_object) {
    context->owner_file = NULL;
  }
  WdfWaitLockRelease(context->state_lock);
}

VOID LumenVhidEvtDeviceCleanup(WDFOBJECT device_object) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device_object);

  if (context->vhf_handle != NULL) {
    context->ready = FALSE;
    VhfDelete(context->vhf_handle, TRUE);
    context->vhf_handle = NULL;
  }
  context->owner_file = NULL;
}

NTSTATUS LumenVhidEvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init) {
  WDF_FILEOBJECT_CONFIG file_config;
  WDF_OBJECT_ATTRIBUTES file_attributes;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  WDF_OBJECT_ATTRIBUTES child_attributes;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDF_IO_TARGET_OPEN_PARAMS open_params;
  WDFDEVICE device;
  LUMEN_VHID_DEVICE_CONTEXT *context;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(driver);

  WDF_FILEOBJECT_CONFIG_INIT(&file_config, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, LumenVhidEvtFileCleanup);
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&file_attributes, LUMEN_VHID_FILE_CONTEXT);
  file_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &file_attributes);

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
  status = WdfIoTargetCreate(device, &child_attributes, &context->local_target);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  WDF_IO_TARGET_OPEN_PARAMS_INIT_OPEN_BY_FILE(&open_params, NULL);
  status = WdfIoTargetOpen(context->local_target, &open_params);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = LumenVhidCreateAndStart(context);
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
