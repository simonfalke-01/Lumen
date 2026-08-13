/**
 * @file Driver.c
 * @brief Root-enumerated KMDF source driver backed by Virtual HID Framework.
 */

#include <initguid.h>

#include "Driver.h"
#include "HidDescriptors.h"

#define LUMEN_VHID_TRACE_INFO(message) \
  KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "LumenVirtualHid: %s\n", message))
#define LUMEN_VHID_TRACE_STATUS(message, status) \
  KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
             "LumenVirtualHid: %s (0x%08X)\n", message, (ULONG) (status)))

static VOID LumenVhidFillResponseHeader(LUMEN_VHID_MESSAGE_HEADER *header,
                                        uint16_t operation,
                                        uint16_t negotiated_minor,
                                        uint32_t total_size) {
  RtlZeroMemory(header, sizeof(*header));
  header->magic = LUMEN_VHID_PROTOCOL_MAGIC;
  header->protocol_major = LUMEN_VHID_PROTOCOL_MAJOR;
  header->protocol_minor = negotiated_minor;
  header->header_size = (uint16_t) sizeof(*header);
  header->operation = operation;
  header->total_size = total_size;
}

static uint16_t LumenVhidNegotiatedMinor(uint16_t client_minor) {
  return client_minor < LUMEN_VHID_PROTOCOL_MINOR ? client_minor : LUMEN_VHID_PROTOCOL_MINOR;
}

static NTSTATUS LumenVhidAllocateSessionToken(LUMEN_VHID_DEVICE_CONTEXT *context,
                                              uint64_t *session_token) {
  if (context->next_session_token == UINT64_MAX || session_token == NULL) {
    return STATUS_INTEGER_OVERFLOW;
  }
  ++context->next_session_token;
  *session_token = context->next_session_token;
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidSubmitRawReport(VHFHANDLE vhf_handle,
                                         UCHAR report_id,
                                         PVOID report_buffer,
                                         ULONG report_size) {
  HID_XFER_PACKET packet;
  if (vhf_handle == NULL || report_buffer == NULL || report_size == 0) {
    return STATUS_DEVICE_NOT_READY;
  }
  RtlZeroMemory(&packet, sizeof(packet));
  packet.reportBuffer = (PUCHAR) report_buffer;
  packet.reportBufferLen = report_size;
  packet.reportId = report_id;
  return VhfReadReportSubmit(vhf_handle, &packet);
}

/* Caller holds session_lock. Every collection is attempted even after failure. */
static NTSTATUS LumenVhidSubmitNeutralState(LUMEN_VHID_DEVICE_CONTEXT *context) {
  LUMEN_VHID_KEYBOARD_REPORT keyboard;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT relative_mouse;
  NTSTATUS status;
  NTSTATUS first_failure = STATUS_SUCCESS;

  RtlZeroMemory(&keyboard, sizeof(keyboard));
  keyboard.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
  status = LumenVhidSubmitRawReport(context->vhf_handle, keyboard.report_id,
                                   &keyboard, (ULONG) sizeof(keyboard));
  if (!NT_SUCCESS(status)) {
    first_failure = status;
  }

  RtlZeroMemory(&relative_mouse, sizeof(relative_mouse));
  relative_mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
  status = LumenVhidSubmitRawReport(context->vhf_handle, relative_mouse.report_id,
                                   &relative_mouse, (ULONG) sizeof(relative_mouse));
  if (!NT_SUCCESS(status) && NT_SUCCESS(first_failure)) {
    first_failure = status;
  }

  /* An absolute report is intentionally omitted: coordinates are stateful and
   * no absolute value is neutral. The relative button snapshot releases the
   * single logical mouse without moving the cursor. */
  context->mouse_buttons = 0;
  return first_failure;
}

static VOID LumenVhidReleaseOwnerLocked(LUMEN_VHID_DEVICE_CONTEXT *context,
                                        WDFFILEOBJECT file_object,
                                        uint64_t released_token) {
  LUMEN_VHID_FILE_CONTEXT *file_context;
  if (file_object != NULL) {
    file_context = LumenVhidGetFileContext(file_object);
    file_context->last_released_token = released_token;
    file_context->last_released_sequence = context->last_sequence;
  }
  context->owner_file = NULL;
  context->session_token = 0;
  context->retired_session_token = 0;
  context->last_sequence = 0;
  context->session_exhausted = FALSE;
  context->mouse_buttons = 0;
}

static NTSTATUS LumenVhidValidateRequestBuffer(WDFREQUEST request,
                                               size_t input_length,
                                               size_t expected_input_length,
                                               size_t output_length,
                                               size_t expected_output_length,
                                               PVOID *input_buffer,
                                               PVOID *output_buffer) {
  NTSTATUS status;
  if (input_buffer == NULL || output_buffer == NULL ||
      input_length != expected_input_length || output_length != expected_output_length ||
      input_length > LUMEN_VHID_MAX_CONTROL_SIZE ||
      output_length > LUMEN_VHID_MAX_CONTROL_SIZE) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  status = WdfRequestRetrieveInputBuffer(request, expected_input_length, input_buffer, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  return WdfRequestRetrieveOutputBuffer(request, expected_output_length, output_buffer, NULL);
}

static NTSTATUS LumenVhidHandleGetCapabilities(WDFREQUEST request,
                                               size_t input_length,
                                               size_t output_length,
                                               size_t *information) {
  LUMEN_VHID_GET_CAPABILITIES_REQUEST local_request;
  LUMEN_VHID_GET_CAPABILITIES_REQUEST *input;
  LUMEN_VHID_GET_CAPABILITIES_RESPONSE *output;
  NTSTATUS status;

  status = LumenVhidValidateRequestBuffer(request, input_length, sizeof(*input),
                                          output_length, sizeof(*output),
                                          (PVOID *) &input, (PVOID *) &output);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  RtlCopyMemory(&local_request, input, sizeof(local_request));
  if (!lumen_vhid_validate_message_header(&local_request.header, sizeof(local_request),
                                          LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
                                          sizeof(local_request))) {
    return STATUS_REVISION_MISMATCH;
  }

  RtlZeroMemory(output, sizeof(*output));
  LumenVhidFillResponseHeader(&output->header,
                              LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
                              LumenVhidNegotiatedMinor(local_request.header.protocol_minor),
                              (uint32_t) sizeof(*output));
  output->capabilities = LUMEN_VHID_CAP_KNOWN_MASK;
  output->required_capabilities = LUMEN_VHID_CAP_REQUIRED;
  output->max_control_size = LUMEN_VHID_MAX_CONTROL_SIZE;
  output->max_report_payload = LUMEN_VHID_MAX_REPORT_PAYLOAD;
  output->keyboard_report_size = (uint16_t) sizeof(LUMEN_VHID_KEYBOARD_REPORT);
  output->relative_mouse_report_size = (uint16_t) sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT);
  output->absolute_mouse_report_size = (uint16_t) sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT);
  output->min_minor_get_capabilities = LUMEN_VHID_MIN_MINOR_GET_PROTOCOL_CAPABILITIES;
  output->min_minor_claim = LUMEN_VHID_MIN_MINOR_CLAIM_INPUT_SESSION;
  output->min_minor_submit = LUMEN_VHID_MIN_MINOR_SUBMIT_INPUT_REPORT;
  output->min_minor_reset = LUMEN_VHID_MIN_MINOR_RESET_INPUT_SESSION;
  output->min_minor_release = LUMEN_VHID_MIN_MINOR_RELEASE_INPUT_SESSION;
  *information = sizeof(*output);
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidHandleClaim(WDFDEVICE device,
                                     WDFFILEOBJECT file_object,
                                     WDFREQUEST request,
                                     size_t input_length,
                                     size_t output_length,
                                     size_t *information) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_FILE_CONTEXT *file_context;
  LUMEN_VHID_CLAIM_SESSION_REQUEST local_request;
  LUMEN_VHID_CLAIM_SESSION_REQUEST *input;
  LUMEN_VHID_CLAIM_SESSION_RESPONSE *output;
  NTSTATUS status;
  uint64_t token = 0;

  status = LumenVhidValidateRequestBuffer(request, input_length, sizeof(*input),
                                          output_length, sizeof(*output),
                                          (PVOID *) &input, (PVOID *) &output);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (file_object == NULL) {
    return STATUS_INVALID_HANDLE;
  }
  file_context = LumenVhidGetFileContext(file_object);
  if (InterlockedCompareExchange(&file_context->closing, 0, 0) != 0) {
    return STATUS_FILE_CLOSED;
  }

  RtlCopyMemory(&local_request, input, sizeof(local_request));
  if (!lumen_vhid_validate_message_header(&local_request.header, sizeof(local_request),
                                          LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
                                          sizeof(local_request)) ||
      local_request.reserved0 != 0 ||
      (local_request.required_capabilities & ~LUMEN_VHID_CAP_KNOWN_MASK) != 0) {
    return STATUS_INVALID_PARAMETER;
  }

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (InterlockedCompareExchange(&file_context->closing, 0, 0) != 0) {
    status = STATUS_FILE_CLOSED;
  } else if (context->stopping || context->vhf_handle == NULL) {
    status = STATUS_DEVICE_NOT_READY;
  } else if (context->owner_file == file_object) {
    token = context->session_token;
    status = STATUS_SUCCESS;
  } else if (context->owner_file != NULL) {
    status = STATUS_SHARING_VIOLATION;
  } else {
    status = LumenVhidAllocateSessionToken(context, &token);
    if (NT_SUCCESS(status)) {
      status = LumenVhidSubmitNeutralState(context);
    }
    if (NT_SUCCESS(status)) {
      context->owner_file = file_object;
      context->session_token = token;
      context->retired_session_token = 0;
      context->last_sequence = 0;
      context->session_exhausted = FALSE;
      file_context->last_released_token = 0;
      file_context->last_released_sequence = 0;
      LUMEN_VHID_TRACE_INFO("writer session claimed");
    }
  }

  if (NT_SUCCESS(status)) {
    RtlZeroMemory(output, sizeof(*output));
    LumenVhidFillResponseHeader(&output->header,
                                LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
                                LumenVhidNegotiatedMinor(local_request.header.protocol_minor),
                                (uint32_t) sizeof(*output));
    output->session_token = token;
    output->granted_capabilities = LUMEN_VHID_CAP_KNOWN_MASK;
    *information = sizeof(*output);
  }
  WdfWaitLockRelease(context->session_lock);
  return status;
}

static NTSTATUS LumenVhidSubmitValidatedReport(LUMEN_VHID_DEVICE_CONTEXT *context,
                                              const LUMEN_VHID_SUBMIT_REPORT_REQUEST *input) {
  NTSTATUS status;
  size_t payload_end;
  if (!lumen_vhid_checked_add_size(offsetof(LUMEN_VHID_SUBMIT_REPORT_REQUEST, payload),
                                   input->payload_size, &payload_end) ||
      payload_end > sizeof(*input)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  if (!lumen_vhid_validate_report_metadata(input->device_kind, input->report_id,
                                           input->payload_size) ||
      input->payload[0] != (uint8_t) input->report_id) {
    return STATUS_INVALID_PARAMETER;
  }

  if (input->report_id == LUMEN_VHID_REPORT_ID_KEYBOARD) {
    LUMEN_VHID_KEYBOARD_REPORT report;
    RtlCopyMemory(&report, input->payload, sizeof(report));
    return LumenVhidSubmitRawReport(context->vhf_handle, report.report_id,
                                   &report, (ULONG) sizeof(report));
  }
  if (input->report_id == LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE) {
    LUMEN_VHID_RELATIVE_MOUSE_REPORT report;
    RtlCopyMemory(&report, input->payload, sizeof(report));
    if ((report.buttons & 0xe0u) != 0) {
      return STATUS_INVALID_PARAMETER;
    }
    status = LumenVhidSubmitRawReport(context->vhf_handle, report.report_id,
                                     &report, (ULONG) sizeof(report));
    if (NT_SUCCESS(status)) {
      context->mouse_buttons = report.buttons;
    }
    return status;
  }
  if (input->report_id == LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE) {
    LUMEN_VHID_ABSOLUTE_MOUSE_REPORT report;
    RtlCopyMemory(&report, input->payload, sizeof(report));
    if ((report.buttons & 0xe0u) != 0) {
      return STATUS_INVALID_PARAMETER;
    }
    status = LumenVhidSubmitRawReport(context->vhf_handle, report.report_id,
                                     &report, (ULONG) sizeof(report));
    if (NT_SUCCESS(status)) {
      context->mouse_buttons = report.buttons;
      context->absolute_x = report.x;
      context->absolute_y = report.y;
    }
    return status;
  }
  return STATUS_INVALID_PARAMETER;
}

static NTSTATUS LumenVhidHandleSubmit(WDFDEVICE device,
                                      WDFFILEOBJECT file_object,
                                      WDFREQUEST request,
                                      size_t input_length,
                                      size_t output_length,
                                      size_t *information) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_FILE_CONTEXT *file_context;
  LUMEN_VHID_SUBMIT_REPORT_REQUEST local_request;
  LUMEN_VHID_SUBMIT_REPORT_REQUEST *input;
  LUMEN_VHID_SUBMIT_REPORT_RESPONSE *output;
  NTSTATUS status;

  status = LumenVhidValidateRequestBuffer(request, input_length, sizeof(*input),
                                          output_length, sizeof(*output),
                                          (PVOID *) &input, (PVOID *) &output);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (file_object == NULL) {
    return STATUS_INVALID_HANDLE;
  }
  file_context = LumenVhidGetFileContext(file_object);
  if (InterlockedCompareExchange(&file_context->closing, 0, 0) != 0) {
    return STATUS_FILE_CLOSED;
  }

  RtlCopyMemory(&local_request, input, sizeof(local_request));
  if (!lumen_vhid_validate_message_header(&local_request.header, sizeof(local_request),
                                          LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
                                          sizeof(local_request)) ||
      local_request.reserved0 != 0 || local_request.reserved1 != 0) {
    return STATUS_INVALID_PARAMETER;
  }

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (InterlockedCompareExchange(&file_context->closing, 0, 0) != 0) {
    status = STATUS_FILE_CLOSED;
  } else if (context->stopping || context->vhf_handle == NULL) {
    status = STATUS_DEVICE_NOT_READY;
  } else if (context->owner_file != file_object ||
             local_request.session_token == 0 ||
             local_request.session_token != context->session_token) {
    status = STATUS_ACCESS_DENIED;
  } else if (!lumen_vhid_is_next_sequence(context->last_sequence,
                                           context->session_exhausted,
                                           local_request.sequence)) {
    status = STATUS_INVALID_DEVICE_STATE;
  } else {
    status = LumenVhidSubmitValidatedReport(context, &local_request);
    if (NT_SUCCESS(status)) {
      context->last_sequence = local_request.sequence;
      context->session_exhausted = local_request.sequence == UINT64_MAX;
      RtlZeroMemory(output, sizeof(*output));
      LumenVhidFillResponseHeader(&output->header,
                                  LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
                                  LumenVhidNegotiatedMinor(local_request.header.protocol_minor),
                                  (uint32_t) sizeof(*output));
      output->session_token = context->session_token;
      output->accepted_sequence = context->last_sequence;
      *information = sizeof(*output);
    }
  }
  WdfWaitLockRelease(context->session_lock);
  return status;
}

static NTSTATUS LumenVhidHandleReset(WDFDEVICE device,
                                     WDFFILEOBJECT file_object,
                                     WDFREQUEST request,
                                     size_t input_length,
                                     size_t output_length,
                                     size_t *information) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_FILE_CONTEXT *file_context;
  LUMEN_VHID_SESSION_REQUEST local_request;
  LUMEN_VHID_SESSION_REQUEST *input;
  LUMEN_VHID_SESSION_RESPONSE *output;
  NTSTATUS status;
  uint64_t new_token = 0;

  status = LumenVhidValidateRequestBuffer(request, input_length, sizeof(*input),
                                          output_length, sizeof(*output),
                                          (PVOID *) &input, (PVOID *) &output);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (file_object == NULL) {
    return STATUS_INVALID_HANDLE;
  }
  file_context = LumenVhidGetFileContext(file_object);
  RtlCopyMemory(&local_request, input, sizeof(local_request));
  if (!lumen_vhid_validate_message_header(&local_request.header, sizeof(local_request),
                                          LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
                                          sizeof(local_request)) ||
      local_request.reserved0 != 0 || local_request.session_token == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (InterlockedCompareExchange(&file_context->closing, 0, 0) != 0) {
    status = STATUS_FILE_CLOSED;
  } else if (context->stopping || context->vhf_handle == NULL) {
    status = STATUS_DEVICE_NOT_READY;
  } else if (context->owner_file != file_object) {
    status = STATUS_ACCESS_DENIED;
  } else if (local_request.session_token == context->retired_session_token) {
    new_token = context->session_token;
    status = STATUS_SUCCESS;
  } else if (local_request.session_token != context->session_token) {
    status = STATUS_ACCESS_DENIED;
  } else if (context->next_session_token == UINT64_MAX) {
    status = STATUS_INTEGER_OVERFLOW;
  } else {
    status = LumenVhidSubmitNeutralState(context);
    if (NT_SUCCESS(status)) {
      context->retired_session_token = context->session_token;
      status = LumenVhidAllocateSessionToken(context, &new_token);
      if (NT_SUCCESS(status)) {
        context->session_token = new_token;
        context->last_sequence = 0;
        context->session_exhausted = FALSE;
        LUMEN_VHID_TRACE_INFO("writer session reset and neutralized");
      }
    }
  }

  if (NT_SUCCESS(status)) {
    RtlZeroMemory(output, sizeof(*output));
    LumenVhidFillResponseHeader(&output->header,
                                LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
                                LumenVhidNegotiatedMinor(local_request.header.protocol_minor),
                                (uint32_t) sizeof(*output));
    output->session_token = new_token;
    output->last_sequence = 0;
    *information = sizeof(*output);
  }
  WdfWaitLockRelease(context->session_lock);
  return status;
}

static NTSTATUS LumenVhidHandleRelease(WDFDEVICE device,
                                       WDFFILEOBJECT file_object,
                                       WDFREQUEST request,
                                       size_t input_length,
                                       size_t output_length,
                                       size_t *information) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_FILE_CONTEXT *file_context;
  LUMEN_VHID_SESSION_REQUEST local_request;
  LUMEN_VHID_SESSION_REQUEST *input;
  LUMEN_VHID_SESSION_RESPONSE *output;
  NTSTATUS status;
  uint64_t final_sequence = 0;

  status = LumenVhidValidateRequestBuffer(request, input_length, sizeof(*input),
                                          output_length, sizeof(*output),
                                          (PVOID *) &input, (PVOID *) &output);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (file_object == NULL) {
    return STATUS_INVALID_HANDLE;
  }
  file_context = LumenVhidGetFileContext(file_object);
  RtlCopyMemory(&local_request, input, sizeof(local_request));
  if (!lumen_vhid_validate_message_header(&local_request.header, sizeof(local_request),
                                          LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION,
                                          sizeof(local_request)) ||
      local_request.reserved0 != 0 || local_request.session_token == 0) {
    return STATUS_INVALID_PARAMETER;
  }

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (InterlockedCompareExchange(&file_context->closing, 0, 0) != 0) {
    status = STATUS_FILE_CLOSED;
  } else if (file_context->last_released_token == local_request.session_token) {
    final_sequence = file_context->last_released_sequence;
    status = STATUS_SUCCESS;
  } else if (context->owner_file != file_object ||
             context->session_token != local_request.session_token) {
    status = STATUS_ACCESS_DENIED;
  } else if (context->stopping || context->vhf_handle == NULL) {
    status = STATUS_DEVICE_NOT_READY;
  } else {
    final_sequence = context->last_sequence;
    status = LumenVhidSubmitNeutralState(context);
    if (NT_SUCCESS(status)) {
      LumenVhidReleaseOwnerLocked(context, file_object, local_request.session_token);
      LUMEN_VHID_TRACE_INFO("writer session neutralized and released");
    }
  }

  if (NT_SUCCESS(status)) {
    RtlZeroMemory(output, sizeof(*output));
    LumenVhidFillResponseHeader(&output->header,
                                LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION,
                                LumenVhidNegotiatedMinor(local_request.header.protocol_minor),
                                (uint32_t) sizeof(*output));
    output->session_token = local_request.session_token;
    output->last_sequence = final_sequence;
    *information = sizeof(*output);
  }
  WdfWaitLockRelease(context->session_lock);
  return status;
}

VOID LumenVhidEvtIoDeviceControl(WDFQUEUE queue,
                                 WDFREQUEST request,
                                 size_t output_buffer_length,
                                 size_t input_buffer_length,
                                 ULONG io_control_code) {
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  NTSTATUS status;
  size_t information = 0;

  if (input_buffer_length > LUMEN_VHID_MAX_CONTROL_SIZE ||
      output_buffer_length > LUMEN_VHID_MAX_CONTROL_SIZE ||
      (io_control_code & 3u) != METHOD_BUFFERED) {
    WdfRequestComplete(request, STATUS_INVALID_BUFFER_SIZE);
    return;
  }

  switch (io_control_code) {
    case IOCTL_LUMEN_VHID_GET_PROTOCOL_CAPABILITIES:
      status = LumenVhidHandleGetCapabilities(request, input_buffer_length,
                                              output_buffer_length, &information);
      break;
    case IOCTL_LUMEN_VHID_CLAIM_INPUT_SESSION:
      status = LumenVhidHandleClaim(device, file_object, request, input_buffer_length,
                                    output_buffer_length, &information);
      break;
    case IOCTL_LUMEN_VHID_SUBMIT_INPUT_REPORT:
      status = LumenVhidHandleSubmit(device, file_object, request, input_buffer_length,
                                     output_buffer_length, &information);
      break;
    case IOCTL_LUMEN_VHID_RESET_INPUT_SESSION:
      status = LumenVhidHandleReset(device, file_object, request, input_buffer_length,
                                    output_buffer_length, &information);
      break;
    case IOCTL_LUMEN_VHID_RELEASE_INPUT_SESSION:
      status = LumenVhidHandleRelease(device, file_object, request, input_buffer_length,
                                      output_buffer_length, &information);
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }

  if (!NT_SUCCESS(status)) {
    LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
    if (InterlockedCompareExchange(&context->rejection_logged, 1, 0) == 0) {
      LUMEN_VHID_TRACE_STATUS("control request rejected (further rejects suppressed)", status);
    }
  }
  WdfRequestCompleteWithInformation(request, status, information);
}

VOID LumenVhidEvtFileCleanup(WDFFILEOBJECT file_object) {
  WDFDEVICE device = WdfFileObjectGetDevice(file_object);
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_FILE_CONTEXT *file_context = LumenVhidGetFileContext(file_object);
  VHFHANDLE failed_vhf_handle = NULL;
  NTSTATUS status = STATUS_SUCCESS;

  InterlockedExchange(&file_context->closing, 1);
  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    LUMEN_VHID_TRACE_STATUS("file cleanup could not acquire session lock", status);
    WdfDeviceSetFailed(device, WdfDeviceFailedAttemptRestart);
    return;
  }
  if (context->owner_file == file_object) {
    if (context->vhf_handle != NULL && !context->stopping) {
      status = LumenVhidSubmitNeutralState(context);
      if (!NT_SUCCESS(status)) {
        /* A failed neutral report cannot leave a persistent stuck device.
         * Stop new writes and synchronously remove VHF as the stronger fence;
         * KMDF then restarts the root function device and recreates VHF. */
        context->stopping = TRUE;
        failed_vhf_handle = context->vhf_handle;
        context->vhf_handle = NULL;
      }
    }
    /* A closing file can never retain ownership, even if VHF is being removed. */
    LumenVhidReleaseOwnerLocked(context, file_object, context->session_token);
    if (NT_SUCCESS(status)) {
      LUMEN_VHID_TRACE_INFO("file cleanup neutralized and released writer");
    } else if (failed_vhf_handle == NULL) {
      LUMEN_VHID_TRACE_STATUS("file cleanup could not submit every neutral report", status);
    }
  }
  WdfWaitLockRelease(context->session_lock);

  if (failed_vhf_handle != NULL) {
    VhfDelete(failed_vhf_handle, TRUE);
    LUMEN_VHID_TRACE_STATUS("cleanup neutralization failed; VHF removed for restart", status);
    WdfDeviceSetFailed(device, WdfDeviceFailedAttemptRestart);
  }
}

NTSTATUS LumenVhidEvtDevicePrepareHardware(WDFDEVICE device,
                                           WDFCMRESLIST resources_raw,
                                           WDFCMRESLIST resources_translated) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  VHF_CONFIG vhf_config;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(resources_raw);
  UNREFERENCED_PARAMETER(resources_translated);

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (context->vhf_handle != NULL) {
    context->stopping = FALSE;
    WdfWaitLockRelease(context->session_lock);
    return STATUS_SUCCESS;
  }

  context->stopping = TRUE;
  VHF_CONFIG_INIT(&vhf_config,
                  WdfDeviceWdmGetDeviceObject(device),
                  LumenVhidReportDescriptorLength,
                  (PUCHAR) LumenVhidReportDescriptor);
  status = VhfCreate(&vhf_config, &context->vhf_handle);
  if (NT_SUCCESS(status)) {
    status = VhfStart(context->vhf_handle);
  }
  if (!NT_SUCCESS(status) && context->vhf_handle != NULL) {
    VhfDelete(context->vhf_handle, TRUE);
    context->vhf_handle = NULL;
  }
  context->stopping = !NT_SUCCESS(status);
  WdfWaitLockRelease(context->session_lock);

  if (NT_SUCCESS(status)) {
    LUMEN_VHID_TRACE_INFO("persistent VHF keyboard and mouse collections started");
  } else {
    LUMEN_VHID_TRACE_STATUS("VHF creation/start failed", status);
  }
  return status;
}

NTSTATUS LumenVhidEvtDeviceReleaseHardware(WDFDEVICE device,
                                           WDFCMRESLIST resources_translated) {
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  VHFHANDLE vhf_handle;
  NTSTATUS status;
  NTSTATUS neutral_status = STATUS_SUCCESS;

  UNREFERENCED_PARAMETER(resources_translated);

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  context->stopping = TRUE;
  if (context->vhf_handle != NULL && context->owner_file != NULL) {
    neutral_status = LumenVhidSubmitNeutralState(context);
  }
  if (context->owner_file != NULL) {
    LumenVhidReleaseOwnerLocked(context, context->owner_file, context->session_token);
  }
  vhf_handle = context->vhf_handle;
  context->vhf_handle = NULL;
  WdfWaitLockRelease(context->session_lock);

  if (vhf_handle != NULL) {
    VhfDelete(vhf_handle, TRUE);
    LUMEN_VHID_TRACE_INFO("VHF device deleted during PnP release");
  }
  if (!NT_SUCCESS(neutral_status)) {
    LUMEN_VHID_TRACE_STATUS("PnP release neutral report failed before VHF delete",
                            neutral_status);
  }
  /* Confirmed VHF deletion is the PnP quiescence fence. */
  return STATUS_SUCCESS;
}

NTSTATUS LumenVhidEvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init) {
  WDF_PNPPOWER_EVENT_CALLBACKS pnp_callbacks;
  WDF_FILEOBJECT_CONFIG file_config;
  WDF_OBJECT_ATTRIBUTES file_attributes;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  WDF_OBJECT_ATTRIBUTES lock_attributes;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDFDEVICE device;
  LUMEN_VHID_DEVICE_CONTEXT *context;
  DECLARE_CONST_UNICODE_STRING(system_only_sddl, L"D:P(A;;GA;;;SY)");
  NTSTATUS status;

  UNREFERENCED_PARAMETER(driver);

  WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_UNKNOWN);
  WdfDeviceInitSetCharacteristics(
    device_init,
    FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN,
    FALSE
  );
  WdfDeviceInitSetIoType(device_init, WdfDeviceIoBuffered);
  status = WdfDeviceInitAssignSDDLString(device_init, &system_only_sddl);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp_callbacks);
  pnp_callbacks.EvtDevicePrepareHardware = LumenVhidEvtDevicePrepareHardware;
  pnp_callbacks.EvtDeviceReleaseHardware = LumenVhidEvtDeviceReleaseHardware;
  WdfDeviceInitSetPnpPowerEventCallbacks(device_init, &pnp_callbacks);

  WDF_FILEOBJECT_CONFIG_INIT(&file_config,
                             WDF_NO_EVENT_CALLBACK,
                             WDF_NO_EVENT_CALLBACK,
                             LumenVhidEvtFileCleanup);
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&file_attributes, LUMEN_VHID_FILE_CONTEXT);
  file_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  file_attributes.SynchronizationScope = WdfSynchronizationScopeNone;
  WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &file_attributes);

  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, LUMEN_VHID_DEVICE_CONTEXT);
  device_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  device_attributes.SynchronizationScope = WdfSynchronizationScopeNone;
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  context = LumenVhidGetDeviceContext(device);
  RtlZeroMemory(context, sizeof(*context));
  context->stopping = TRUE;

  WDF_OBJECT_ATTRIBUTES_INIT(&lock_attributes);
  lock_attributes.ParentObject = device;
  status = WdfWaitLockCreate(&lock_attributes, &context->session_lock);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = WdfDeviceCreateDeviceInterface(device,
                                          &GUID_DEVINTERFACE_LUMEN_VIRTUAL_HID,
                                          NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
  queue_config.EvtIoDeviceControl = LumenVhidEvtIoDeviceControl;
  status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  LUMEN_VHID_TRACE_INFO("SYSTEM-only control interface published");
  return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
  WDF_DRIVER_CONFIG config;
  WDF_OBJECT_ATTRIBUTES attributes;
  NTSTATUS status;

  WDF_DRIVER_CONFIG_INIT(&config, LumenVhidEvtDeviceAdd);
  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
  attributes.ExecutionLevel = WdfExecutionLevelPassive;
  status = WdfDriverCreate(driver_object, registry_path, &attributes, &config,
                           WDF_NO_HANDLE);
  if (NT_SUCCESS(status)) {
    LUMEN_VHID_TRACE_INFO("driver started");
  } else {
    LUMEN_VHID_TRACE_STATUS("WdfDriverCreate failed", status);
  }
  return status;
}
