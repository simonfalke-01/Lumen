/**
 * @file Driver.c
 * @brief Root-enumerated UMDF 2 HID minidriver for Lumen input injection.
 */

#include "Driver.h"
#include "HidDescriptors.h"

#include <limits.h>

#define LUMEN_VHID_RESPONSE_LEASE_MS 5000ULL

/** UMDF-translated HID transfer packet using separately marshalled buffers. */
typedef struct LUMEN_VHID_TRANSFER_PACKET {
  BYTE *report_buffer;  /**< Complete report buffer, including its report ID. */
  ULONG report_buffer_length;  /**< Accessible report-buffer length. */
  BYTE report_id;  /**< Report identifier supplied by mshidumdf.sys. */
} LUMEN_VHID_TRANSFER_PACKET;

static void LumenVhidFillResponseHeader(LUMEN_VHID_MESSAGE_HEADER *header,
                                        uint16_t operation,
                                        uint16_t negotiated_minor,
                                        uint32_t total_size) {
  ZeroMemory(header, sizeof(*header));
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
  if (session_token == NULL || context->next_session_token == UINT64_MAX) {
    return STATUS_INTEGER_OVERFLOW;
  }
  ++context->next_session_token;
  *session_token = context->next_session_token;
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidCopyToRequest(WDFREQUEST request,
                                       const void *source,
                                       size_t source_size) {
  WDFMEMORY output_memory;
  size_t output_size;
  NTSTATUS status;

  if (source == NULL || source_size == 0) {
    return STATUS_INVALID_PARAMETER;
  }
  status = WdfRequestRetrieveOutputMemory(request, &output_memory);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  WdfMemoryGetBuffer(output_memory, &output_size);
  if (output_size < source_size) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  status = WdfMemoryCopyFromBuffer(output_memory, 0, (void *) source, source_size);
  if (NT_SUCCESS(status)) {
    WdfRequestSetInformation(request, source_size);
  }
  return status;
}

static NTSTATUS LumenVhidGetWritePacket(WDFREQUEST request,
                                        LUMEN_VHID_TRANSFER_PACKET *packet) {
  WDFMEMORY input_memory;
  WDFMEMORY output_memory;
  size_t input_size;
  size_t report_id_value;
  NTSTATUS status;

  if (packet == NULL) {
    return STATUS_INVALID_PARAMETER;
  }
  status = WdfRequestRetrieveOutputMemory(request, &output_memory);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  WdfMemoryGetBuffer(output_memory, &report_id_value);
  if (report_id_value > UINT8_MAX) {
    return STATUS_INVALID_PARAMETER;
  }
  status = WdfRequestRetrieveInputMemory(request, &input_memory);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  packet->report_buffer = (BYTE *) WdfMemoryGetBuffer(input_memory, &input_size);
  if (input_size > ULONG_MAX) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  packet->report_buffer_length = (ULONG) input_size;
  packet->report_id = (BYTE) report_id_value;
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidGetReadPacket(WDFREQUEST request,
                                       LUMEN_VHID_TRANSFER_PACKET *packet) {
  WDFMEMORY input_memory;
  WDFMEMORY output_memory;
  size_t input_size;
  size_t output_size;
  BYTE *input_buffer;
  NTSTATUS status;

  if (packet == NULL) {
    return STATUS_INVALID_PARAMETER;
  }
  status = WdfRequestRetrieveInputMemory(request, &input_memory);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  input_buffer = (BYTE *) WdfMemoryGetBuffer(input_memory, &input_size);
  if (input_size < sizeof(*input_buffer)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  status = WdfRequestRetrieveOutputMemory(request, &output_memory);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  packet->report_buffer = (BYTE *) WdfMemoryGetBuffer(output_memory, &output_size);
  if (output_size > ULONG_MAX) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  packet->report_buffer_length = (ULONG) output_size;
  packet->report_id = input_buffer[0];
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidCopyReportToPendingRequest(WDFREQUEST request,
                                                    const void *report,
                                                    size_t report_size) {
  WDFMEMORY output_memory;
  size_t output_size;
  NTSTATUS status;

  status = WdfRequestRetrieveOutputMemory(request, &output_memory);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  WdfMemoryGetBuffer(output_memory, &output_size);
  if (output_size < report_size) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  return WdfMemoryCopyFromBuffer(output_memory, 0, (void *) report, report_size);
}

static NTSTATUS LumenVhidCompleteOneReport(WDFQUEUE read_queue,
                                           const void *report,
                                           size_t report_size) {
  WDFREQUEST read_request;
  NTSTATUS status;

  status = WdfIoQueueRetrieveNextRequest(read_queue, &read_request);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = LumenVhidCopyReportToPendingRequest(read_request, report, report_size);
  WdfRequestCompleteWithInformation(read_request,
                                    status,
                                    NT_SUCCESS(status) ? report_size : 0);
  return status;
}

static NTSTATUS LumenVhidReturnRequestToQueue(WDFREQUEST request,
                                              WDFQUEUE queue,
                                              NTSTATUS original_status) {
  NTSTATUS status = WdfRequestForwardToIoQueue(request, queue);
  if (!NT_SUCCESS(status)) {
    WdfRequestComplete(request, status);
    return status;
  }
  return original_status;
}

/* Caller holds session_lock. Both neutral reports are prepared before either completes. */
static NTSTATUS LumenVhidSubmitNeutralState(LUMEN_VHID_DEVICE_CONTEXT *context) {
  LUMEN_VHID_KEYBOARD_REPORT keyboard;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT mouse;
  WDFREQUEST keyboard_request;
  WDFREQUEST mouse_request;
  NTSTATUS status;

  status = WdfIoQueueRetrieveNextRequest(context->input_reads, &keyboard_request);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = WdfIoQueueRetrieveNextRequest(context->input_reads, &mouse_request);
  if (!NT_SUCCESS(status)) {
    return LumenVhidReturnRequestToQueue(keyboard_request, context->input_reads, status);
  }

  ZeroMemory(&keyboard, sizeof(keyboard));
  keyboard.report_id = LUMEN_VHID_REPORT_ID_KEYBOARD;
  status = LumenVhidCopyReportToPendingRequest(keyboard_request, &keyboard, sizeof(keyboard));
  if (!NT_SUCCESS(status)) {
    (void) LumenVhidReturnRequestToQueue(mouse_request, context->input_reads, status);
    return LumenVhidReturnRequestToQueue(keyboard_request, context->input_reads, status);
  }

  ZeroMemory(&mouse, sizeof(mouse));
  mouse.report_id = LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE;
  status = LumenVhidCopyReportToPendingRequest(mouse_request, &mouse, sizeof(mouse));
  if (!NT_SUCCESS(status)) {
    (void) LumenVhidReturnRequestToQueue(keyboard_request, context->input_reads, status);
    return LumenVhidReturnRequestToQueue(mouse_request, context->input_reads, status);
  }

  WdfRequestCompleteWithInformation(keyboard_request, STATUS_SUCCESS, sizeof(keyboard));
  WdfRequestCompleteWithInformation(mouse_request, STATUS_SUCCESS, sizeof(mouse));
  context->mouse_buttons = 0;
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidSubmitValidatedReport(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  const LUMEN_VHID_SUBMIT_REPORT_REQUEST *input) {
  size_t payload_end;
  NTSTATUS status;

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
    CopyMemory(&report, input->payload, sizeof(report));
    return LumenVhidCompleteOneReport(context->input_reads, &report, sizeof(report));
  }
  if (input->report_id == LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE) {
    LUMEN_VHID_RELATIVE_MOUSE_REPORT report;
    CopyMemory(&report, input->payload, sizeof(report));
    if ((report.buttons & 0xe0u) != 0) {
      return STATUS_INVALID_PARAMETER;
    }
    status = LumenVhidCompleteOneReport(context->input_reads, &report, sizeof(report));
    if (NT_SUCCESS(status)) {
      context->mouse_buttons = report.buttons;
    }
    return status;
  }
  if (input->report_id == LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE) {
    LUMEN_VHID_ABSOLUTE_MOUSE_REPORT report;
    CopyMemory(&report, input->payload, sizeof(report));
    if ((report.buttons & 0xe0u) != 0) {
      return STATUS_INVALID_PARAMETER;
    }
    status = LumenVhidCompleteOneReport(context->input_reads, &report, sizeof(report));
    if (NT_SUCCESS(status)) {
      context->mouse_buttons = report.buttons;
      context->absolute_x = report.x;
      context->absolute_y = report.y;
    }
    return status;
  }
  return STATUS_INVALID_PARAMETER;
}

static NTSTATUS LumenVhidHandleGetCapabilities(
  const LUMEN_VHID_GET_CAPABILITIES_REQUEST *input,
  LUMEN_VHID_GET_CAPABILITIES_RESPONSE *output,
  size_t *output_size) {
  if (!lumen_vhid_validate_message_header(&input->header, sizeof(*input),
                                          LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
                                          sizeof(*input))) {
    return STATUS_REVISION_MISMATCH;
  }

  ZeroMemory(output, sizeof(*output));
  LumenVhidFillResponseHeader(&output->header,
                              LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
                              LumenVhidNegotiatedMinor(input->header.protocol_minor),
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
  *output_size = sizeof(*output);
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidHandleClaim(LUMEN_VHID_DEVICE_CONTEXT *context,
                                     WDFFILEOBJECT file_object,
                                     const LUMEN_VHID_CLAIM_SESSION_REQUEST *input,
                                     LUMEN_VHID_CLAIM_SESSION_RESPONSE *output,
                                     size_t *output_size) {
  uint64_t token;
  NTSTATUS status;

  if (!lumen_vhid_validate_message_header(&input->header, sizeof(*input),
                                          LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
                                          sizeof(*input)) ||
      input->reserved0 != 0 ||
      (input->required_capabilities & ~LUMEN_VHID_CAP_KNOWN_MASK) != 0) {
    return STATUS_INVALID_PARAMETER;
  }

  if (file_object != NULL && context->owner_file == file_object) {
    token = context->session_token;
  } else {
    if (context->owner_file != NULL) {
      status = LumenVhidSubmitNeutralState(context);
      if (!NT_SUCCESS(status)) {
        return status;
      }
    }
    status = LumenVhidAllocateSessionToken(context, &token);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    context->owner_file = file_object;
    context->session_token = token;
    context->retired_session_token = 0;
    context->last_sequence = 0;
    context->session_exhausted = FALSE;
  }
  context->last_activity_ms = GetTickCount64();

  ZeroMemory(output, sizeof(*output));
  LumenVhidFillResponseHeader(&output->header,
                              LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION,
                              LumenVhidNegotiatedMinor(input->header.protocol_minor),
                              (uint32_t) sizeof(*output));
  output->session_token = token;
  output->granted_capabilities = LUMEN_VHID_CAP_KNOWN_MASK;
  *output_size = sizeof(*output);
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidHandleSubmit(LUMEN_VHID_DEVICE_CONTEXT *context,
                                      WDFFILEOBJECT file_object,
                                      const LUMEN_VHID_SUBMIT_REPORT_REQUEST *input,
                                      LUMEN_VHID_SUBMIT_REPORT_RESPONSE *output,
                                      size_t *output_size) {
  NTSTATUS status;

  if (!lumen_vhid_validate_message_header(&input->header, sizeof(*input),
                                          LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
                                          sizeof(*input)) ||
      input->reserved0 != 0 || input->reserved1 != 0) {
    return STATUS_INVALID_PARAMETER;
  }
  if ((context->owner_file != NULL && context->owner_file != file_object) ||
      input->session_token == 0 || input->session_token != context->session_token) {
    return STATUS_ACCESS_DENIED;
  }
  if (!lumen_vhid_is_next_sequence(context->last_sequence,
                                   context->session_exhausted,
                                   input->sequence)) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  status = LumenVhidSubmitValidatedReport(context, input);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  context->last_sequence = input->sequence;
  context->session_exhausted = input->sequence == UINT64_MAX;
  context->last_activity_ms = GetTickCount64();
  ZeroMemory(output, sizeof(*output));
  LumenVhidFillResponseHeader(&output->header,
                              LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT,
                              LumenVhidNegotiatedMinor(input->header.protocol_minor),
                              (uint32_t) sizeof(*output));
  output->session_token = context->session_token;
  output->accepted_sequence = context->last_sequence;
  *output_size = sizeof(*output);
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidHandleReset(LUMEN_VHID_DEVICE_CONTEXT *context,
                                     WDFFILEOBJECT file_object,
                                     const LUMEN_VHID_SESSION_REQUEST *input,
                                     LUMEN_VHID_SESSION_RESPONSE *output,
                                     size_t *output_size) {
  uint64_t new_token;
  NTSTATUS status;

  if (!lumen_vhid_validate_message_header(&input->header, sizeof(*input),
                                          LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
                                          sizeof(*input)) ||
      input->reserved0 != 0 || input->session_token == 0) {
    return STATUS_INVALID_PARAMETER;
  }
  if (context->owner_file != NULL && context->owner_file != file_object) {
    return STATUS_ACCESS_DENIED;
  }
  if (input->session_token == context->retired_session_token && context->session_token != 0) {
    new_token = context->session_token;
  } else if (input->session_token != context->session_token) {
    return STATUS_ACCESS_DENIED;
  } else {
    if (context->next_session_token == UINT64_MAX) {
      return STATUS_INTEGER_OVERFLOW;
    }
    status = LumenVhidSubmitNeutralState(context);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    context->retired_session_token = context->session_token;
    status = LumenVhidAllocateSessionToken(context, &new_token);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    context->session_token = new_token;
    context->last_sequence = 0;
    context->session_exhausted = FALSE;
  }
  context->last_activity_ms = GetTickCount64();

  ZeroMemory(output, sizeof(*output));
  LumenVhidFillResponseHeader(&output->header,
                              LUMEN_VHID_OPERATION_RESET_INPUT_SESSION,
                              LumenVhidNegotiatedMinor(input->header.protocol_minor),
                              (uint32_t) sizeof(*output));
  output->session_token = new_token;
  *output_size = sizeof(*output);
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidHandleRelease(LUMEN_VHID_DEVICE_CONTEXT *context,
                                       WDFFILEOBJECT file_object,
                                       const LUMEN_VHID_SESSION_REQUEST *input,
                                       LUMEN_VHID_SESSION_RESPONSE *output,
                                       size_t *output_size) {
  uint64_t final_sequence;
  NTSTATUS status;

  if (!lumen_vhid_validate_message_header(&input->header, sizeof(*input),
                                          LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION,
                                          sizeof(*input)) ||
      input->reserved0 != 0 || input->session_token == 0) {
    return STATUS_INVALID_PARAMETER;
  }
  if (input->session_token == context->last_released_token &&
      (context->owner_file == file_object || context->owner_file == NULL || file_object == NULL)) {
    final_sequence = context->last_released_sequence;
  } else if (input->session_token != context->session_token) {
    return STATUS_ACCESS_DENIED;
  } else {
    final_sequence = context->last_sequence;
    status = LumenVhidSubmitNeutralState(context);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    context->last_released_token = context->session_token;
    context->last_released_sequence = final_sequence;
    context->owner_file = NULL;
    context->session_token = 0;
    context->retired_session_token = 0;
    context->last_sequence = 0;
    context->session_exhausted = FALSE;
    context->last_activity_ms = GetTickCount64();
  }

  ZeroMemory(output, sizeof(*output));
  LumenVhidFillResponseHeader(&output->header,
                              LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION,
                              LumenVhidNegotiatedMinor(input->header.protocol_minor),
                              (uint32_t) sizeof(*output));
  output->session_token = input->session_token;
  output->last_sequence = final_sequence;
  *output_size = sizeof(*output);
  return STATUS_SUCCESS;
}

static NTSTATUS LumenVhidDispatchProtocol(LUMEN_VHID_DEVICE_CONTEXT *context,
                                          WDFFILEOBJECT file_object,
                                          const uint8_t *request_payload,
                                          uint8_t *response_payload,
                                          size_t *response_size) {
  union {
    LUMEN_VHID_GET_CAPABILITIES_REQUEST get_capabilities;
    LUMEN_VHID_CLAIM_SESSION_REQUEST claim;
    LUMEN_VHID_SUBMIT_REPORT_REQUEST submit;
    LUMEN_VHID_SESSION_REQUEST session;
  } local_request;
  union {
    LUMEN_VHID_GET_CAPABILITIES_RESPONSE get_capabilities;
    LUMEN_VHID_CLAIM_SESSION_RESPONSE claim;
    LUMEN_VHID_SUBMIT_REPORT_RESPONSE submit;
    LUMEN_VHID_SESSION_RESPONSE session;
  } local_response;
  LUMEN_VHID_MESSAGE_HEADER header;
  NTSTATUS status;

  CopyMemory(&header, request_payload, sizeof(header));
  if (header.total_size > LUMEN_VHID_MAX_CONTROL_SIZE ||
      header.total_size < sizeof(header)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  ZeroMemory(&local_request, sizeof(local_request));
  ZeroMemory(&local_response, sizeof(local_response));
  switch (header.operation) {
    case LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES:
      CopyMemory(&local_request.get_capabilities,
                 request_payload,
                 sizeof(local_request.get_capabilities));
      status = LumenVhidHandleGetCapabilities(&local_request.get_capabilities,
                                              &local_response.get_capabilities,
                                              response_size);
      break;
    case LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION:
      CopyMemory(&local_request.claim, request_payload, sizeof(local_request.claim));
      status = LumenVhidHandleClaim(context,
                                    file_object,
                                    &local_request.claim,
                                    &local_response.claim,
                                    response_size);
      break;
    case LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT:
      CopyMemory(&local_request.submit, request_payload, sizeof(local_request.submit));
      status = LumenVhidHandleSubmit(context,
                                     file_object,
                                     &local_request.submit,
                                     &local_response.submit,
                                     response_size);
      break;
    case LUMEN_VHID_OPERATION_RESET_INPUT_SESSION:
      CopyMemory(&local_request.session, request_payload, sizeof(local_request.session));
      status = LumenVhidHandleReset(context,
                                    file_object,
                                    &local_request.session,
                                    &local_response.session,
                                    response_size);
      break;
    case LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION:
      CopyMemory(&local_request.session, request_payload, sizeof(local_request.session));
      status = LumenVhidHandleRelease(context,
                                      file_object,
                                      &local_request.session,
                                      &local_response.session,
                                      response_size);
      break;
    default:
      return STATUS_INVALID_DEVICE_REQUEST;
  }
  if (NT_SUCCESS(status)) {
    CopyMemory(response_payload, &local_response, *response_size);
  }
  return status;
}

static NTSTATUS LumenVhidSetFeature(LUMEN_VHID_DEVICE_CONTEXT *context,
                                    WDFREQUEST request) {
  LUMEN_VHID_TRANSFER_PACKET packet;
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  LUMEN_VHID_FILE_CONTEXT *file_context = NULL;
  uint8_t local_response[LUMEN_VHID_FEATURE_PAYLOAD_SIZE];
  size_t response_size = 0;
  NTSTATUS status;

  status = LumenVhidGetWritePacket(request, &packet);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (packet.report_id != LUMEN_VHID_FEATURE_REQUEST_REPORT_ID ||
      packet.report_buffer_length != LUMEN_VHID_FEATURE_REPORT_SIZE ||
      packet.report_buffer[0] != LUMEN_VHID_FEATURE_REQUEST_REPORT_ID) {
    return STATUS_INVALID_PARAMETER;
  }
  if (file_object != NULL) {
    file_context = LumenVhidGetFileContext(file_object);
  }
  if (file_context != NULL && file_context->closing) {
    return STATUS_FILE_CLOSED;
  }

  ZeroMemory(local_response, sizeof(local_response));
  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (context->feature_response_size != 0) {
    ULONGLONG age_ms = GetTickCount64() - context->response_started_ms;
    if (age_ms <= LUMEN_VHID_RESPONSE_LEASE_MS) {
      WdfWaitLockRelease(context->session_lock);
      return STATUS_DEVICE_BUSY;
    }
    context->response_file = NULL;
    context->feature_response_size = 0;
    ZeroMemory(context->feature_response, sizeof(context->feature_response));
  }
  status = LumenVhidDispatchProtocol(context,
                                     file_object,
                                     packet.report_buffer + 1,
                                     local_response,
                                     &response_size);
  if (NT_SUCCESS(status)) {
    CopyMemory(context->feature_response, local_response, response_size);
    if (response_size < sizeof(context->feature_response)) {
      ZeroMemory(context->feature_response + response_size,
                 sizeof(context->feature_response) - response_size);
    }
    context->feature_response_size = response_size;
    context->response_file = file_object;
    context->response_started_ms = GetTickCount64();
    WdfRequestSetInformation(request, LUMEN_VHID_FEATURE_REPORT_SIZE);
  }
  WdfWaitLockRelease(context->session_lock);
  return status;
}

static NTSTATUS LumenVhidGetFeature(LUMEN_VHID_DEVICE_CONTEXT *context,
                                    WDFREQUEST request) {
  LUMEN_VHID_TRANSFER_PACKET packet;
  WDFFILEOBJECT file_object = WdfRequestGetFileObject(request);
  NTSTATUS status;

  status = LumenVhidGetReadPacket(request, &packet);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (packet.report_id != LUMEN_VHID_FEATURE_RESPONSE_REPORT_ID ||
      packet.report_buffer_length < LUMEN_VHID_FEATURE_REPORT_SIZE) {
    return STATUS_INVALID_PARAMETER;
  }

  status = WdfWaitLockAcquire(context->session_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (context->feature_response_size == 0) {
    status = STATUS_DEVICE_NOT_READY;
  } else if (context->response_file != NULL && file_object != NULL &&
             context->response_file != file_object) {
    status = STATUS_ACCESS_DENIED;
  } else {
    ZeroMemory(packet.report_buffer, LUMEN_VHID_FEATURE_REPORT_SIZE);
    packet.report_buffer[0] = LUMEN_VHID_FEATURE_RESPONSE_REPORT_ID;
    CopyMemory(packet.report_buffer + 1,
               context->feature_response,
               context->feature_response_size);
    WdfRequestSetInformation(request, LUMEN_VHID_FEATURE_REPORT_SIZE);
    context->feature_response_size = 0;
    context->response_file = NULL;
    context->response_started_ms = 0;
    status = STATUS_SUCCESS;
  }
  WdfWaitLockRelease(context->session_lock);
  return status;
}

void LumenVhidEvtFileCleanup(WDFFILEOBJECT file_object) {
  WDFDEVICE device = WdfFileObjectGetDevice(file_object);
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  LUMEN_VHID_FILE_CONTEXT *file_context = LumenVhidGetFileContext(file_object);

  file_context->closing = TRUE;
  if (!NT_SUCCESS(WdfWaitLockAcquire(context->session_lock, NULL))) {
    return;
  }
  if (context->response_file == file_object) {
    context->response_file = NULL;
    context->feature_response_size = 0;
    ZeroMemory(context->feature_response, sizeof(context->feature_response));
  }
  if (context->owner_file == file_object) {
    (void) LumenVhidSubmitNeutralState(context);
    context->last_released_token = context->session_token;
    context->last_released_sequence = context->last_sequence;
    context->owner_file = NULL;
    context->session_token = 0;
    context->retired_session_token = 0;
    context->last_sequence = 0;
    context->session_exhausted = FALSE;
  }
  WdfWaitLockRelease(context->session_lock);
}

static NTSTATUS LumenVhidQueueReadReport(LUMEN_VHID_DEVICE_CONTEXT *context,
                                         WDFREQUEST request,
                                         size_t output_buffer_length,
                                         BOOLEAN *complete_request) {
  NTSTATUS status;

  if (output_buffer_length < sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  status = WdfRequestForwardToIoQueue(request, context->input_reads);
  if (NT_SUCCESS(status)) {
    *complete_request = FALSE;
  }
  return status;
}

void LumenVhidEvtIoDeviceControl(WDFQUEUE queue,
                                 WDFREQUEST request,
                                 size_t output_buffer_length,
                                 size_t input_buffer_length,
                                 ULONG io_control_code) {
  WDFDEVICE device = WdfIoQueueGetDevice(queue);
  LUMEN_VHID_DEVICE_CONTEXT *context = LumenVhidGetDeviceContext(device);
  BOOLEAN complete_request = TRUE;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(input_buffer_length);

  switch (io_control_code) {
    case IOCTL_HID_GET_DEVICE_DESCRIPTOR:
      status = LumenVhidCopyToRequest(request,
                                      &context->hid_descriptor,
                                      context->hid_descriptor.bLength);
      break;
    case IOCTL_HID_GET_DEVICE_ATTRIBUTES:
      status = LumenVhidCopyToRequest(request,
                                      &context->hid_attributes,
                                      sizeof(context->hid_attributes));
      break;
    case IOCTL_HID_GET_REPORT_DESCRIPTOR:
      status = LumenVhidCopyToRequest(request,
                                      LumenVhidReportDescriptor,
                                      LumenVhidReportDescriptorLength);
      break;
    case IOCTL_HID_READ_REPORT:
      status = LumenVhidQueueReadReport(context,
                                        request,
                                        output_buffer_length,
                                        &complete_request);
      break;
    case IOCTL_UMDF_HID_SET_FEATURE:
      status = LumenVhidSetFeature(context, request);
      break;
    case IOCTL_UMDF_HID_GET_FEATURE:
      status = LumenVhidGetFeature(context, request);
      break;
    case IOCTL_HID_ACTIVATE_DEVICE:
    case IOCTL_HID_DEACTIVATE_DEVICE:
      status = STATUS_SUCCESS;
      break;
    default:
      status = STATUS_NOT_IMPLEMENTED;
      break;
  }

  if (complete_request) {
    WdfRequestComplete(request, status);
  }
}

static NTSTATUS LumenVhidCreateManualQueue(WDFDEVICE device, WDFQUEUE *queue) {
  WDF_IO_QUEUE_CONFIG queue_config;
  WDF_OBJECT_ATTRIBUTES queue_attributes;

  WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
  WDF_OBJECT_ATTRIBUTES_INIT(&queue_attributes);
  queue_attributes.ParentObject = device;
  return WdfIoQueueCreate(device, &queue_config, &queue_attributes, queue);
}

NTSTATUS LumenVhidEvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT device_init) {
  WDF_FILEOBJECT_CONFIG file_config;
  WDF_OBJECT_ATTRIBUTES file_attributes;
  WDF_OBJECT_ATTRIBUTES device_attributes;
  WDF_OBJECT_ATTRIBUTES lock_attributes;
  WDF_IO_QUEUE_CONFIG queue_config;
  WDFDEVICE device;
  LUMEN_VHID_DEVICE_CONTEXT *context;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(driver);

  WdfFdoInitSetFilter(device_init);
  WDF_FILEOBJECT_CONFIG_INIT(&file_config,
                             WDF_NO_EVENT_CALLBACK,
                             WDF_NO_EVENT_CALLBACK,
                             LumenVhidEvtFileCleanup);
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&file_attributes, LUMEN_VHID_FILE_CONTEXT);
  file_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &file_attributes);
  WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&device_attributes, LUMEN_VHID_DEVICE_CONTEXT);
  device_attributes.ExecutionLevel = WdfExecutionLevelPassive;
  status = WdfDeviceCreate(&device_init, &device_attributes, &device);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  context = LumenVhidGetDeviceContext(device);
  context->device = device;
  context->hid_descriptor.bLength = sizeof(HID_DESCRIPTOR);
  context->hid_descriptor.bDescriptorType = HID_HID_DESCRIPTOR_TYPE;
  context->hid_descriptor.bcdHID = HID_REVISION;
  context->hid_descriptor.bCountry = 0;
  context->hid_descriptor.bNumDescriptors = 1;
  context->hid_descriptor.DescriptorList[0].bReportType = HID_REPORT_DESCRIPTOR_TYPE;
  context->hid_descriptor.DescriptorList[0].wReportLength = LumenVhidReportDescriptorLength;
  context->hid_attributes.Size = sizeof(HID_DEVICE_ATTRIBUTES);
  context->hid_attributes.VendorID = LUMEN_VHID_VENDOR_ID;
  context->hid_attributes.ProductID = LUMEN_VHID_PRODUCT_ID;
  context->hid_attributes.VersionNumber = LUMEN_VHID_VERSION_NUMBER;

  WDF_OBJECT_ATTRIBUTES_INIT(&lock_attributes);
  lock_attributes.ParentObject = device;
  status = WdfWaitLockCreate(&lock_attributes, &context->session_lock);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = LumenVhidCreateManualQueue(device, &context->input_reads);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config, WdfIoQueueDispatchParallel);
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
