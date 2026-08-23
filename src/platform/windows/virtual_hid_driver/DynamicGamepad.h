/**
 * @file DynamicGamepad.h
 * @brief Isolated per-file dynamic-gamepad VHF driver state and operations.
 */

#ifndef LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_H
#define LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_H

#include "DynamicGamepadProfiles.h"
#include "DynamicReportQueue.h"

#include <vhf.h>
#include <wdf.h>

struct LUMEN_VHID_DEVICE_CONTEXT;

/** Driver-side DirectInput PID feature handshake for one generic gamepad. */
typedef struct LUMEN_VHID_GENERIC_PID_STATE {
  BOOLEAN allocated[40];  ///< Device-managed effect-block allocation bitmap.
  uint8_t last_effect_block_index;  ///< Most recently allocated effect index.
  uint8_t load_status;  ///< PID block-load status.
  uint8_t state_effect_block_index;  ///< Currently playing effect index.
  uint8_t state_flags;  ///< PID device-state flags.
} LUMEN_VHID_GENERIC_PID_STATE;

/** Complete isolated lifetime and queues for one dynamic VHF child. */
typedef struct LUMEN_VHID_DYNAMIC_GAMEPAD {
  struct LUMEN_VHID_DEVICE_CONTEXT *parent_context;  ///< Stable parent driver context.
  const LUMEN_VHID_GAMEPAD_PROFILE *profile;  ///< Trusted built-in profile.
  WDFFILEOBJECT owner_file;  ///< Exact file that created this gamepad.
  WDFIOTARGET local_target;  ///< Per-gamepad local target supplying VHF's UMDF handle.
  VHFHANDLE vhf_handle;  ///< Per-gamepad VHF child, or null.
  LUMEN_VHID_GAMEPAD_HANDLE authenticated_handle;  ///< ID, generation, and random token.
  uint64_t client_device_id;  ///< Caller identity used for PlayStation pairing data.
  BOOLEAN occupied;  ///< Slot has an owner and cannot be reused.
  BOOLEAN ready;  ///< VHF child started successfully.
  BOOLEAN shutting_down;  ///< New reports and callbacks must stop.
  BOOLEAN vhf_ready_for_input_report;  ///< Exactly one VHF readiness grant is available.
  BOOLEAN input_submission_active;  ///< One VhfReadReportSubmit call is outside the lock.
  BOOLEAN has_in_flight_report;  ///< VHF may still reference in_flight_report bytes.
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE pending_input;  ///< Bounded input FIFO.
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE pending_output;  ///< Bounded host-output FIFO.
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT in_flight_report;  ///< Stable VHF-owned report bytes.
  LUMEN_VHID_GENERIC_PID_STATE generic_pid;  ///< Generic PID feature handshake state.
  HANDLE submissions_drained_event;  ///< Signaled when no submit call is active.
} LUMEN_VHID_DYNAMIC_GAMEPAD;

/**
 * @brief Initialize all fixed dynamic-gamepad slots and drain events.
 *
 * @param context Parent device state.
 * @return STATUS_SUCCESS or an allocation error.
 */
NTSTATUS LumenVhidGamepadInitialize(struct LUMEN_VHID_DEVICE_CONTEXT *context);

/**
 * @brief Destroy every dynamic child and close slot drain events.
 *
 * @param context Parent device state.
 */
VOID LumenVhidGamepadUninitialize(struct LUMEN_VHID_DEVICE_CONTEXT *context);

/**
 * @brief Destroy dynamic children while retaining reusable slot events.
 *
 * @param context Parent device state.
 */
VOID LumenVhidGamepadReleaseHardware(struct LUMEN_VHID_DEVICE_CONTEXT *context);

/**
 * @brief Destroy only gamepads created by one closing file.
 *
 * @param context Parent device state.
 * @param file_object Exact closing framework file.
 */
VOID LumenVhidGamepadCleanupFile(
  struct LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFFILEOBJECT file_object
);

/**
 * @brief Dispatch one additive dynamic-gamepad IOCTL.
 *
 * @param context Parent device state.
 * @param request Current METHOD_BUFFERED request.
 * @param file_object Validated request file.
 * @param output_buffer_length Exact output byte count.
 * @param input_buffer_length Exact input byte count.
 * @param io_control_code Candidate dynamic-gamepad control code.
 * @param handled Receives true when the code belongs to this extension.
 * @return Operation status; caller completes the request.
 */
NTSTATUS LumenVhidGamepadDispatchIoctl(
  struct LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT file_object,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code,
  BOOLEAN *handled
);

/** Release prior report bytes and consume one dynamic-child readiness grant. */
EVT_VHF_READY_FOR_NEXT_READ_REPORT LumenVhidGamepadEvtReadyForNextReadReport;
/** Return fixed PlayStation or generic PID feature data. */
EVT_VHF_ASYNC_OPERATION LumenVhidGamepadEvtGetFeature;
/** Accept supported feature writes and queue them for the owning file. */
EVT_VHF_ASYNC_OPERATION LumenVhidGamepadEvtSetFeature;
/** Queue host output and synthesize required Switch initialization replies. */
EVT_VHF_ASYNC_OPERATION LumenVhidGamepadEvtWriteReport;

#endif /* LUMEN_VIRTUAL_HID_DYNAMIC_GAMEPAD_H */
