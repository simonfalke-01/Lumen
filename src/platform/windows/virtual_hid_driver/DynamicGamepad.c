/**
 * @file DynamicGamepad.c
 * @brief Additive isolated dynamic-gamepad VHF implementation.
 *
 * Protocol behavior is derived from the approved libvirtualhid revision
 * 15a37d34, without its descriptor-upload, broker, licensing, keyboard, or
 * mouse paths.
 */

#include "Driver.h"
#include "DynamicGamepadValidation.h"

#include <bcrypt.h>
#include <limits.h>

/** Initial Generic PID state: actuators enabled and powered. */
#define LUMEN_VHID_GENERIC_PID_INITIAL_STATE 0x12u
/** Generic PID state bit set while an effect is playing. */
#define LUMEN_VHID_GENERIC_PID_EFFECT_PLAYING 0x20u
/** Generic PID state bit set while the device is paused. */
#define LUMEN_VHID_GENERIC_PID_PAUSED 0x01u

/** PlayStation feature payloads ported from libvirtualhid 15a37d34. */
static const uint8_t LumenVhidDualShock4Calibration[] = {
  0x02,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0xf4,
  0x01,
  0xf4,
  0x01,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x00,
  0x00
};
static const uint8_t LumenVhidDualShock4Pairing[] = {
  0x12,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00
};
static const uint8_t LumenVhidDualShock4Firmware[] = {
  0xa3,
  0x41,
  0x75,
  0x67,
  0x20,
  0x20,
  0x33,
  0x20,
  0x32,
  0x30,
  0x31,
  0x33,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x30,
  0x37,
  0x3a,
  0x30,
  0x31,
  0x3a,
  0x31,
  0x32,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x01,
  0x00,
  0x31,
  0x03,
  0x00,
  0x00,
  0x00,
  0x49,
  0x00,
  0x05,
  0x00,
  0x00,
  0x80,
  0x03,
  0x00
};
static const uint8_t LumenVhidDualSenseCalibration[] = {
  0x05,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0xf4,
  0x01,
  0xf4,
  0x01,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x10,
  0x27,
  0xf0,
  0xd8,
  0x0b,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00
};
static const uint8_t LumenVhidDualSensePairing[] = {
  0x09,
  0x74,
  0xe7,
  0xd6,
  0x3a,
  0x53,
  0x35,
  0x08,
  0x25,
  0x00,
  0x1e,
  0x00,
  0xee,
  0x74,
  0xd0,
  0xbc,
  0x00,
  0x00,
  0x00,
  0x00
};
static const uint8_t LumenVhidDualSenseFirmware[] = {
  0x20,
  0x4a,
  0x75,
  0x6c,
  0x20,
  0x20,
  0x34,
  0x20,
  0x32,
  0x30,
  0x32,
  0x35,
  0x31,
  0x30,
  0x3a,
  0x31,
  0x30,
  0x3a,
  0x33,
  0x32,
  0x03,
  0x00,
  0x04,
  0x00,
  0x10,
  0x13,
  0x00,
  0x00,
  0x2a,
  0x00,
  0x10,
  0x01,
  0x01,
  0xc8,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x30,
  0x06,
  0x00,
  0x00,
  0x3c,
  0x00,
  0x01,
  0x00,
  0x0a,
  0x00,
  0x02,
  0x00,
  0x06,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00
};

/** Reset profile-specific feature state. */
static VOID LumenVhidGamepadResetProtocolState(LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad) {
  ZeroMemory(&gamepad->generic_pid, sizeof(gamepad->generic_pid));
  gamepad->generic_pid.state_flags = LUMEN_VHID_GENERIC_PID_INITIAL_STATE;
}

/** Return the report number from a VHF feature packet. */
static uint8_t LumenVhidGamepadFeatureReportNumber(const HID_XFER_PACKET *packet) {
  if (packet->reportId != 0u) {
    return packet->reportId;
  }
  return packet->reportBufferLen == 0u ? 0u : packet->reportBuffer[0];
}

/** Copy one fixed feature payload into a zero-filled VHF output buffer. */
static NTSTATUS LumenVhidGamepadCopyFeaturePayload(
  HID_XFER_PACKET *packet,
  const uint8_t *payload,
  size_t payload_size
) {
  if (payload == NULL) {
    return STATUS_NOT_SUPPORTED;
  }
  if (packet->reportBufferLen < payload_size) {
    return STATUS_BUFFER_TOO_SMALL;
  }
  ZeroMemory(packet->reportBuffer, packet->reportBufferLen);
  CopyMemory(packet->reportBuffer, payload, payload_size);
  return STATUS_SUCCESS;
}

/** Fill pairing bytes with a deterministic locally administered identity. */
static VOID LumenVhidGamepadSetPairingIdentity(
  uint8_t *report,
  size_t report_size,
  uint64_t client_device_id
) {
  if (report_size < 7u) {
    return;
  }
  report[1] = (uint8_t) (client_device_id & 0xffu);
  report[2] = (uint8_t) ((client_device_id >> 8u) & 0xffu);
  report[3] = (uint8_t) ((client_device_id >> 16u) & 0xffu);
  report[4] = (uint8_t) ((client_device_id >> 24u) & 0xffu);
  report[5] = 0x00u;
  report[6] = 0x02u;
}

/** Return one fixed USB PlayStation feature report. */
static NTSTATUS LumenVhidGamepadCopyPlayStationFeature(
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad,
  HID_XFER_PACKET *packet
) {
  uint8_t pairing[sizeof(LumenVhidDualSensePairing)];
  const uint8_t *payload = NULL;
  size_t payload_size = 0u;
  uint8_t report_number = LumenVhidGamepadFeatureReportNumber(packet);

  if (gamepad->profile->kind == LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4) {
    switch (report_number) {
      case 0x02u:
        payload = LumenVhidDualShock4Calibration;
        payload_size = sizeof(LumenVhidDualShock4Calibration);
        break;
      case 0x12u:
        CopyMemory(pairing, LumenVhidDualShock4Pairing, sizeof(LumenVhidDualShock4Pairing));
        LumenVhidGamepadSetPairingIdentity(pairing, sizeof(LumenVhidDualShock4Pairing), gamepad->client_device_id);
        payload = pairing;
        payload_size = sizeof(LumenVhidDualShock4Pairing);
        break;
      case 0xa3u:
        payload = LumenVhidDualShock4Firmware;
        payload_size = sizeof(LumenVhidDualShock4Firmware);
        break;
      default:
        return STATUS_NOT_SUPPORTED;
    }
  } else if (gamepad->profile->kind == LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE) {
    switch (report_number) {
      case 0x05u:
        payload = LumenVhidDualSenseCalibration;
        payload_size = sizeof(LumenVhidDualSenseCalibration);
        break;
      case 0x09u:
        CopyMemory(pairing, LumenVhidDualSensePairing, sizeof(LumenVhidDualSensePairing));
        LumenVhidGamepadSetPairingIdentity(pairing, sizeof(LumenVhidDualSensePairing), gamepad->client_device_id);
        payload = pairing;
        payload_size = sizeof(LumenVhidDualSensePairing);
        break;
      case 0x20u:
        payload = LumenVhidDualSenseFirmware;
        payload_size = sizeof(LumenVhidDualSenseFirmware);
        break;
      default:
        return STATUS_NOT_SUPPORTED;
    }
  }
  return LumenVhidGamepadCopyFeaturePayload(packet, payload, payload_size);
}

/** Return the report payload after an optional leading report ID. */
static const uint8_t *LumenVhidGamepadPayload(
  uint8_t report_id,
  const uint8_t *report,
  size_t *report_size
) {
  if (*report_size != 0u && report[0] == report_id) {
    ++report;
    --*report_size;
  }
  return report;
}

/** Allocate one Generic PID effect block. */
static VOID LumenVhidGamepadGenericCreateEffect(
  LUMEN_VHID_GENERIC_PID_STATE *state,
  const uint8_t *payload,
  size_t payload_size
) {
  size_t index;

  if (payload_size == 0u || payload[0] < 1u || payload[0] > 12u) {
    state->last_effect_block_index = 0u;
    state->load_status = 3u;
    return;
  }
  for (index = 0u; index < sizeof(state->allocated) / sizeof(state->allocated[0]); ++index) {
    if (!state->allocated[index]) {
      state->allocated[index] = TRUE;
      state->last_effect_block_index = (uint8_t) (index + 1u);
      state->load_status = 1u;
      return;
    }
  }
  state->last_effect_block_index = 0u;
  state->load_status = 2u;
}

/** Free one Generic PID effect block. */
static VOID LumenVhidGamepadGenericFreeEffect(LUMEN_VHID_GENERIC_PID_STATE *state, uint8_t effect) {
  if (effect == 0u || effect > 40u) {
    return;
  }
  state->allocated[effect - 1u] = FALSE;
  if (state->state_effect_block_index == effect) {
    state->state_effect_block_index = 0u;
    state->state_flags = (uint8_t) (state->state_flags & ~LUMEN_VHID_GENERIC_PID_EFFECT_PLAYING);
  }
}

/** Apply one Generic PID device-control command. */
static VOID LumenVhidGamepadGenericDeviceControl(LUMEN_VHID_GENERIC_PID_STATE *state, uint8_t command) {
  switch (command) {
    case 1u:
      state->state_flags = (uint8_t) (state->state_flags | LUMEN_VHID_GENERIC_PID_INITIAL_STATE);
      break;
    case 2u:
      state->state_flags = (uint8_t) (state->state_flags & ~0x02u);
      break;
    case 3u:
      state->state_effect_block_index = 0u;
      state->state_flags = (uint8_t) (state->state_flags & ~LUMEN_VHID_GENERIC_PID_EFFECT_PLAYING);
      break;
    case 4u:
      ZeroMemory(state, sizeof(*state));
      state->state_flags = LUMEN_VHID_GENERIC_PID_INITIAL_STATE;
      break;
    case 5u:
      state->state_flags = (uint8_t) (state->state_flags | LUMEN_VHID_GENERIC_PID_PAUSED);
      break;
    case 6u:
      state->state_flags = (uint8_t) (state->state_flags & ~LUMEN_VHID_GENERIC_PID_PAUSED);
      break;
    default:
      break;
  }
}

/** Handle a supported Generic PID Set Feature transaction. */
static BOOLEAN LumenVhidGamepadHandleGenericSetFeature(
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad,
  const HID_XFER_PACKET *packet
) {
  const uint8_t report_id = LumenVhidGamepadFeatureReportNumber(packet);
  size_t payload_size = packet->reportBufferLen;
  const uint8_t *payload = LumenVhidGamepadPayload(report_id, packet->reportBuffer, &payload_size);

  switch (report_id) {
    case 0x11u:
      LumenVhidGamepadGenericCreateEffect(&gamepad->generic_pid, payload, payload_size);
      return TRUE;
    case 0x1bu:
      if (payload_size != 0u) {
        LumenVhidGamepadGenericFreeEffect(&gamepad->generic_pid, payload[0]);
      }
      return TRUE;
    case 0x1cu:
      if (payload_size != 0u) {
        LumenVhidGamepadGenericDeviceControl(&gamepad->generic_pid, payload[0]);
      }
      return TRUE;
    default:
      return FALSE;
  }
}

/** Apply Generic PID Output transactions that mutate device-managed state. */
static VOID LumenVhidGamepadHandleGenericOutput(
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad,
  const LUMEN_VHID_GAMEPAD_QUEUED_REPORT *output
) {
  uint8_t report_id;
  const uint8_t *payload;
  size_t payload_size;
  uint8_t effect;

  if (gamepad->profile->kind != LUMEN_VHID_GAMEPAD_PROFILE_GENERIC || output->size == 0u) {
    return;
  }
  report_id = output->bytes[0];
  payload_size = output->size;
  payload = LumenVhidGamepadPayload(report_id, output->bytes, &payload_size);
  switch (report_id) {
    case 0x1au:
      if (payload_size >= 2u) {
        effect = payload[0];
        if (effect != 0u && effect <= 40u &&
            gamepad->generic_pid.allocated[effect - 1u]) {
          gamepad->generic_pid.state_effect_block_index = effect;
          if (payload[1] == 1u || payload[1] == 2u) {
            gamepad->generic_pid.state_flags =
              (uint8_t) (gamepad->generic_pid.state_flags | LUMEN_VHID_GENERIC_PID_EFFECT_PLAYING);
          } else if (payload[1] == 3u) {
            gamepad->generic_pid.state_flags =
              (uint8_t) (gamepad->generic_pid.state_flags & ~LUMEN_VHID_GENERIC_PID_EFFECT_PLAYING);
          }
        }
      }
      break;
    case 0x1bu:
      if (payload_size != 0u) {
        LumenVhidGamepadGenericFreeEffect(&gamepad->generic_pid, payload[0]);
      }
      break;
    case 0x1cu:
      if (payload_size != 0u) {
        LumenVhidGamepadGenericDeviceControl(&gamepad->generic_pid, payload[0]);
      }
      break;
    default:
      break;
  }
}

/** Return a Generic PID feature report. Parent state_lock must be held. */
static NTSTATUS LumenVhidGamepadCopyGenericFeature(
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad,
  HID_XFER_PACKET *packet
) {
  uint8_t report[5];
  uint16_t available = 0xffffu;
  size_t index;
  size_t report_size;

  for (index = 0u; index < sizeof(gamepad->generic_pid.allocated) / sizeof(gamepad->generic_pid.allocated[0]); ++index) {
    if (gamepad->generic_pid.allocated[index]) {
      --available;
    }
  }
  ZeroMemory(report, sizeof(report));
  report[0] = LumenVhidGamepadFeatureReportNumber(packet);
  switch (report[0]) {
    case 0x11u:
      report_size = 4u;
      break;
    case 0x12u:
      report[1] = gamepad->generic_pid.last_effect_block_index;
      report[2] = gamepad->generic_pid.load_status;
      report[3] = (uint8_t) (available & 0xffu);
      report[4] = (uint8_t) (available >> 8u);
      report_size = 5u;
      break;
    case 0x13u:
      report[1] = 0xffu;
      report[2] = 0xffu;
      report[3] = 40u;
      report[4] = 0x01u;
      report_size = 5u;
      break;
    case 0x14u:
      report[1] = gamepad->generic_pid.state_effect_block_index;
      report[2] = gamepad->generic_pid.state_flags;
      report_size = 3u;
      break;
    default:
      return STATUS_NOT_SUPPORTED;
  }
  return LumenVhidGamepadCopyFeaturePayload(packet, report, report_size);
}

/** Copy a VHF host packet into a complete bounded output report. */
static BOOLEAN LumenVhidGamepadCopyOutputPacket(
  const HID_XFER_PACKET *packet,
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT *output
) {
  size_t prefix_size;
  size_t payload_size;

  if (packet == NULL || packet->reportBuffer == NULL) {
    return FALSE;
  }
  prefix_size = packet->reportId != 0u &&
                    (packet->reportBufferLen == 0u || packet->reportBuffer[0] != packet->reportId) ?
                  1u :
                  0u;
  payload_size = packet->reportBufferLen;
  if (payload_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE - prefix_size) {
    payload_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE - prefix_size;
  }
  if (prefix_size != 0u) {
    output->bytes[0] = packet->reportId;
  }
  if (payload_size != 0u) {
    CopyMemory(output->bytes + prefix_size, packet->reportBuffer, payload_size);
  }
  output->size = (uint32_t) (prefix_size + payload_size);
  return output->size != 0u;
}

/**
 * @brief Queue one host output while preserving a Generic PID reset boundary on overflow.
 *
 * @param gamepad Locked dynamic gamepad state.
 * @param output Complete output report.
 * @return True when the report or an overflow-reset sequence was queued.
 */
static BOOLEAN LumenVhidGamepadQueueOutputLocked(
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad,
  const LUMEN_VHID_GAMEPAD_QUEUED_REPORT *output
) {
  static const uint8_t generic_stop_all[] = {0x1cu, 0x03u};
  int result;

  if (gamepad->profile->kind != LUMEN_VHID_GAMEPAD_PROFILE_GENERIC) {
    return LumenVhidGamepadOutputQueuePushLatest(
             &gamepad->pending_output,
             output->bytes,
             output->size
           ) != 0;
  }
  result = LumenVhidGamepadOutputQueuePushWithResetOnOverflow(
    &gamepad->pending_output,
    generic_stop_all,
    sizeof(generic_stop_all),
    output->bytes,
    output->size
  );
  if (result == 2) {
    LumenVhidGamepadGenericDeviceControl(&gamepad->generic_pid, 3u);
  }
  return result != 0;
}

/** Update drain state for one gamepad while parent state_lock is held. */
static VOID LumenVhidGamepadUpdateDrainEventLocked(LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad) {
  if (gamepad->submissions_drained_event == NULL) {
    return;
  }
  if (gamepad->input_submission_active) {
    ResetEvent(gamepad->submissions_drained_event);
  } else {
    SetEvent(gamepad->submissions_drained_event);
  }
}

/** Submit queued dynamic input using exactly one VHF readiness grant. */
static NTSTATUS LumenVhidGamepadSubmitNext(LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad) {
  LUMEN_VHID_DEVICE_CONTEXT *context = gamepad->parent_context;
  HID_XFER_PACKET packet;
  VHFHANDLE vhf_handle;
  NTSTATUS status;
  NTSTATUS lock_status;

  for (;;) {
    lock_status = WdfWaitLockAcquire(context->state_lock, NULL);
    if (!NT_SUCCESS(lock_status)) {
      return lock_status;
    }
    if (!gamepad->occupied || gamepad->shutting_down || !gamepad->ready || gamepad->vhf_handle == NULL ||
        !gamepad->vhf_ready_for_input_report || gamepad->input_submission_active ||
        gamepad->pending_input.count == 0u) {
      WdfWaitLockRelease(context->state_lock);
      return STATUS_SUCCESS;
    }
    gamepad->has_in_flight_report = FALSE;
    if (!LumenVhidGamepadInputQueuePop(&gamepad->pending_input, &gamepad->in_flight_report)) {
      WdfWaitLockRelease(context->state_lock);
      return STATUS_SUCCESS;
    }
    gamepad->has_in_flight_report = TRUE;
    gamepad->vhf_ready_for_input_report = FALSE;
    gamepad->input_submission_active = TRUE;
    vhf_handle = gamepad->vhf_handle;
    LumenVhidGamepadUpdateDrainEventLocked(gamepad);
    WdfWaitLockRelease(context->state_lock);

    ZeroMemory(&packet, sizeof(packet));
    packet.reportBuffer = gamepad->in_flight_report.bytes;
    packet.reportBufferLen = gamepad->in_flight_report.size;
    packet.reportId = gamepad->profile->input_report_id == 0u ? 0u : packet.reportBuffer[0];
    status = VhfReadReportSubmit(vhf_handle, &packet);

    lock_status = WdfWaitLockAcquire(context->state_lock, NULL);
    if (!NT_SUCCESS(lock_status)) {
      return lock_status;
    }
    gamepad->input_submission_active = FALSE;
    if (!NT_SUCCESS(status)) {
      gamepad->has_in_flight_report = FALSE;
      (void) LumenVhidGamepadInputQueuePushFront(&gamepad->pending_input, &gamepad->in_flight_report);
    } else if (gamepad->vhf_ready_for_input_report) {
      gamepad->has_in_flight_report = FALSE;
    }
    LumenVhidGamepadUpdateDrainEventLocked(gamepad);
    if (!NT_SUCCESS(status) || !gamepad->vhf_ready_for_input_report) {
      WdfWaitLockRelease(context->state_lock);
      return status;
    }
    WdfWaitLockRelease(context->state_lock);
  }
}

/** Read one little-endian 32-bit value from a validated Switch report. */
static uint32_t LumenVhidGamepadReadU32(const uint8_t *report) {
  return (uint32_t) report[0] | ((uint32_t) report[1] << 8u) | ((uint32_t) report[2] << 16u) |
         ((uint32_t) report[3] << 24u);
}

/** Copy the overlap between requested SPI data and one fixed calibration block. */
static VOID LumenVhidGamepadCopySwitchSpiData(
  uint8_t *reply,
  uint32_t requested_address,
  uint8_t requested_size,
  uint32_t data_address,
  const uint8_t *data,
  size_t data_size
) {
  uint64_t requested_end = (uint64_t) requested_address + requested_size;
  uint64_t data_end = (uint64_t) data_address + data_size;
  uint64_t copy_begin = requested_address > data_address ? requested_address : data_address;
  uint64_t copy_end = requested_end < data_end ? requested_end : data_end;
  size_t source_offset;
  size_t destination_offset;
  size_t copy_size;

  if (copy_begin >= copy_end) {
    return;
  }
  source_offset = (size_t) (copy_begin - data_address);
  destination_offset = 20u + (size_t) (copy_begin - requested_address);
  if (destination_offset >= 64u) {
    return;
  }
  copy_size = (size_t) (copy_end - copy_begin);
  if (copy_size > 64u - destination_offset) {
    copy_size = 64u - destination_offset;
  }
  CopyMemory(reply + destination_offset, data + source_offset, copy_size);
}

/** Queue one already-generated Switch response and attempt submission. */
static VOID LumenVhidGamepadQueueSwitchReply(
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad,
  const LUMEN_VHID_GAMEPAD_QUEUED_REPORT *output
) {
  LUMEN_VHID_DEVICE_CONTEXT *context = gamepad->parent_context;
  uint8_t reply[64];
  static const uint8_t factory_stick_calibration[] = {
    0xff,
    0xf7,
    0x7f,
    0x00,
    0x08,
    0x80,
    0xff,
    0xf7,
    0x7f,
    0x00,
    0x08,
    0x80,
    0xff,
    0xf7,
    0x7f,
    0xff,
    0xf7,
    0x7f
  };
  static const uint8_t factory_imu_calibration[] = {
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x40,
    0x00,
    0x40,
    0x00,
    0x40,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x3b,
    0x34,
    0x3b,
    0x34,
    0x3b,
    0x34
  };
  uint8_t command;
  uint32_t spi_address;
  uint8_t spi_size;
  NTSTATUS status;

  if (gamepad->profile->kind != LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO || output->size == 0u) {
    return;
  }
  ZeroMemory(reply, sizeof(reply));
  if (output->bytes[0] == 0x80u) {
    if (output->size < 2u || output->bytes[1] == 0x04u) {
      return;
    }
    reply[0] = 0x81u;
    reply[1] = output->bytes[1];
    if (output->bytes[1] == 0x01u) {
      reply[3] = 0x03u;
      reply[4] = 0x01u;
      reply[5] = 0x00u;
      reply[6] = 0x00u;
      reply[7] = 0x00u;
      reply[8] = 0x00u;
      reply[9] = 0x02u;
    }
  } else if (output->bytes[0] == 0x01u && output->size >= 11u) {
    command = output->bytes[10];
    if (command == 0x10u && output->size < 16u) {
      return;
    }
    reply[0] = 0x21u;
    reply[1] = output->bytes[1];
    reply[2] = 0x81u;
    reply[7] = 0x08u;
    reply[8] = 0x80u;
    reply[10] = 0x08u;
    reply[11] = 0x80u;
    reply[13] = command == 0x10u ? 0x90u : (command == 0x02u ? 0x82u : 0x80u);
    reply[14] = command;
    if (command == 0x02u) {
      reply[15] = 0x04u;
      reply[16] = 0x33u;
      reply[17] = 0x03u;
      reply[18] = 0x02u;
      reply[19] = 0x02u;
      reply[20] = 0x00u;
      reply[21] = 0x00u;
      reply[22] = 0x00u;
      reply[23] = 0x00u;
      reply[24] = 0x01u;
      reply[25] = 0x01u;
    } else if (command == 0x10u) {
      CopyMemory(reply + 15u, output->bytes + 11u, 5u);
      spi_address = LumenVhidGamepadReadU32(output->bytes + 11u);
      spi_size = output->bytes[15u];
      LumenVhidGamepadCopySwitchSpiData(
        reply,
        spi_address,
        spi_size,
        0x603du,
        factory_stick_calibration,
        sizeof(factory_stick_calibration)
      );
      LumenVhidGamepadCopySwitchSpiData(
        reply,
        spi_address,
        spi_size,
        0x6020u,
        factory_imu_calibration,
        sizeof(factory_imu_calibration)
      );
    }
  } else {
    return;
  }

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  if (gamepad->occupied && !gamepad->shutting_down && gamepad->ready) {
    LUMEN_VHID_GAMEPAD_QUEUED_REPORT protocol_reply;

    ZeroMemory(&protocol_reply, sizeof(protocol_reply));
    CopyMemory(protocol_reply.bytes, reply, sizeof(reply));
    protocol_reply.size = (uint32_t) sizeof(reply);
    if (gamepad->pending_input.count >= LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY) {
      LUMEN_VHID_GAMEPAD_QUEUED_REPORT discarded;
      (void) LumenVhidGamepadInputQueuePop(&gamepad->pending_input, &discarded);
    }
    (void) LumenVhidGamepadInputQueuePushFront(&gamepad->pending_input, &protocol_reply);
  }
  WdfWaitLockRelease(context->state_lock);
  (void) LumenVhidGamepadSubmitNext(gamepad);
}

/** Create and open a private local target for one dynamic child. */
static NTSTATUS LumenVhidGamepadOpenTarget(LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad) {
  WDF_OBJECT_ATTRIBUTES attributes;
  WDF_IO_TARGET_OPEN_PARAMS open_params;
  NTSTATUS status;

  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
  attributes.ParentObject = gamepad->owner_file;
  status = WdfIoTargetCreate(gamepad->parent_context->device, &attributes, &gamepad->local_target);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  WDF_IO_TARGET_OPEN_PARAMS_INIT_OPEN_BY_FILE(&open_params, NULL);
  status = WdfIoTargetOpen(gamepad->local_target, &open_params);
  if (!NT_SUCCESS(status)) {
    WdfObjectDelete(gamepad->local_target);
    gamepad->local_target = NULL;
  }
  return status;
}

/** Create and start one profile-fixed per-gamepad VHF child. */
static NTSTATUS LumenVhidGamepadCreateVhf(LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad) {
  VHF_CONFIG config;
  HANDLE local_handle;
  NTSTATUS status;

  status = LumenVhidGamepadOpenTarget(gamepad);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  local_handle = WdfIoTargetWdmGetTargetFileHandle(gamepad->local_target);
  if (local_handle == NULL || local_handle == INVALID_HANDLE_VALUE) {
    return STATUS_INVALID_HANDLE;
  }
  if (gamepad->profile->report_descriptor_size > USHRT_MAX) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  VHF_CONFIG_INIT(
    &config,
    local_handle,
    (USHORT) gamepad->profile->report_descriptor_size,
    (PUCHAR) gamepad->profile->report_descriptor
  );
  config.VhfClientContext = gamepad;
  config.VendorID = gamepad->profile->vendor_id;
  config.ProductID = gamepad->profile->product_id;
  config.VersionNumber = gamepad->profile->version_number;
  config.EvtVhfReadyForNextReadReport = LumenVhidGamepadEvtReadyForNextReadReport;
  config.EvtVhfAsyncOperationGetFeature = LumenVhidGamepadEvtGetFeature;
  config.EvtVhfAsyncOperationSetFeature = LumenVhidGamepadEvtSetFeature;
  config.EvtVhfAsyncOperationWriteReport = LumenVhidGamepadEvtWriteReport;

  status = VhfCreate(&config, &gamepad->vhf_handle);
  if (!NT_SUCCESS(status)) {
    gamepad->vhf_handle = NULL;
    return status;
  }
  status = VhfStart(gamepad->vhf_handle);
  if (!NT_SUCCESS(status)) {
    VhfDelete(gamepad->vhf_handle, TRUE);
    gamepad->vhf_handle = NULL;
    return status;
  }
  status = WdfWaitLockAcquire(gamepad->parent_context->state_lock, NULL);
  if (NT_SUCCESS(status)) {
    gamepad->ready = TRUE;
    WdfWaitLockRelease(gamepad->parent_context->state_lock);
  }
  return status;
}

/** Stop and delete a child, optionally releasing its authenticated slot. */
static VOID LumenVhidGamepadDeleteVhf(LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad, BOOLEAN release_slot) {
  LUMEN_VHID_DEVICE_CONTEXT *context = gamepad->parent_context;
  VHFHANDLE vhf_handle;
  WDFIOTARGET local_target;
  HANDLE drain_event = gamepad->submissions_drained_event;
  NTSTATUS status;

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  if (!gamepad->occupied) {
    WdfWaitLockRelease(context->state_lock);
    return;
  }
  gamepad->ready = FALSE;
  gamepad->shutting_down = TRUE;
  gamepad->vhf_ready_for_input_report = FALSE;
  LumenVhidGamepadInputQueueClear(&gamepad->pending_input);
  LumenVhidGamepadOutputQueueClear(&gamepad->pending_output);
  vhf_handle = gamepad->vhf_handle;
  gamepad->vhf_handle = NULL;
  local_target = gamepad->local_target;
  gamepad->local_target = NULL;
  LumenVhidGamepadUpdateDrainEventLocked(gamepad);
  WdfWaitLockRelease(context->state_lock);

  if (drain_event != NULL) {
    (void) WaitForSingleObject(drain_event, INFINITE);
  }
  if (vhf_handle != NULL) {
    VhfDelete(vhf_handle, TRUE);
  }
  if (local_target != NULL) {
    WdfIoTargetClose(local_target);
    WdfObjectDelete(local_target);
  }

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (NT_SUCCESS(status)) {
    gamepad->input_submission_active = FALSE;
    gamepad->has_in_flight_report = FALSE;
    ZeroMemory(&gamepad->in_flight_report, sizeof(gamepad->in_flight_report));
    LumenVhidGamepadResetProtocolState(gamepad);
    if (release_slot) {
      gamepad->occupied = FALSE;
      gamepad->owner_file = NULL;
      gamepad->profile = NULL;
      gamepad->client_device_id = 0u;
      ZeroMemory(&gamepad->authenticated_handle, sizeof(gamepad->authenticated_handle));
    }
    LumenVhidGamepadUpdateDrainEventLocked(gamepad);
    WdfWaitLockRelease(context->state_lock);
  }
}

/** Return a record matching owner, ID, generation, and token. Lock must be held. */
static LUMEN_VHID_DYNAMIC_GAMEPAD *LumenVhidGamepadFindAuthenticatedLocked(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFFILEOBJECT owner_file,
  const LUMEN_VHID_GAMEPAD_HANDLE *handle
) {
  size_t index;

  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = &context->gamepads[index];
    if (gamepad->occupied && gamepad->owner_file == owner_file &&
        gamepad->authenticated_handle.device_id == handle->device_id &&
        gamepad->authenticated_handle.generation == handle->generation &&
        LumenVhidGamepadTokenEqual(gamepad->authenticated_handle.session_token, handle->session_token)) {
      return gamepad;
    }
  }
  return NULL;
}

/** Generate a nonzero system-random session token. */
static NTSTATUS LumenVhidGamepadGenerateToken(uint8_t *token) {
  NTSTATUS status;
  uint8_t any = 0u;
  size_t index;

  status = BCryptGenRandom(
    NULL,
    token,
    LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG
  );
  if (!NT_SUCCESS(status)) {
    return status;
  }
  for (index = 0u; index < LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE; ++index) {
    any = (uint8_t) (any | token[index]);
  }
  return any == 0u ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}

/** Handle the exact capabilities operation. */
static NTSTATUS LumenVhidGamepadHandleCapabilities(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request
) {
  LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE response;
  void *output;
  size_t output_size;
  size_t index;
  NTSTATUS status;

  status = WdfRequestRetrieveOutputBuffer(request, sizeof(response), &output, &output_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (output_size != sizeof(response)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  ZeroMemory(&response, sizeof(response));
  response.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
  response.size = (uint32_t) sizeof(response);
  response.base_abi_version = LUMEN_VHID_ABI_VERSION;
  response.capability_flags = LUMEN_VHID_GAMEPAD_CAPABILITY_OUTPUT_REPORTS |
                              LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS |
                              LUMEN_VHID_GAMEPAD_CAPABILITY_OWNER_CLEANUP |
                              LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS;
  response.supported_profiles = LumenVhidGamepadSupportedProfiles();
  response.max_devices = LUMEN_VHID_MAX_GAMEPADS;
  response.max_input_report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
  response.max_output_report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    if (context->gamepads[index].occupied) {
      ++response.active_devices;
    }
  }
  WdfWaitLockRelease(context->state_lock);
  CopyMemory(output, &response, sizeof(response));
  WdfRequestSetInformation(request, sizeof(response));
  return STATUS_SUCCESS;
}

/** Create a profile-fixed dynamic gamepad for one exact file. */
static NTSTATUS LumenVhidGamepadHandleCreate(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT owner_file
) {
  LUMEN_VHID_GAMEPAD_CREATE_REQUEST local_request;
  LUMEN_VHID_GAMEPAD_CREATE_RESPONSE response;
  const LUMEN_VHID_GAMEPAD_CREATE_REQUEST *input;
  const LUMEN_VHID_GAMEPAD_PROFILE *profile;
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = NULL;
  uint8_t token[LUMEN_VHID_GAMEPAD_SESSION_TOKEN_SIZE];
  void *output;
  size_t input_size;
  size_t output_size;
  size_t index;
  NTSTATUS status;

  status = WdfRequestRetrieveInputBuffer(request, sizeof(local_request), (void **) &input, &input_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (input_size != sizeof(local_request)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  CopyMemory(&local_request, input, sizeof(local_request));
  if (!LumenVhidGamepadValidCreateRequest(&local_request)) {
    return STATUS_INVALID_PARAMETER;
  }
  profile = LumenVhidGamepadProfileLookup(local_request.profile);
  if (profile == NULL) {
    return STATUS_NOT_SUPPORTED;
  }
  status = WdfRequestRetrieveOutputBuffer(request, sizeof(response), &output, &output_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (output_size != sizeof(response)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  status = LumenVhidGamepadGenerateToken(token);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    SecureZeroMemory(token, sizeof(token));
    return status;
  }
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    if (!context->gamepads[index].occupied) {
      gamepad = &context->gamepads[index];
      break;
    }
  }
  if (gamepad == NULL) {
    WdfWaitLockRelease(context->state_lock);
    SecureZeroMemory(token, sizeof(token));
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  gamepad->profile = profile;
  gamepad->owner_file = owner_file;
  gamepad->client_device_id = local_request.client_device_id;
  gamepad->occupied = TRUE;
  gamepad->ready = FALSE;
  gamepad->shutting_down = FALSE;
  gamepad->vhf_ready_for_input_report = FALSE;
  gamepad->input_submission_active = FALSE;
  gamepad->has_in_flight_report = FALSE;
  LumenVhidGamepadInputQueueClear(&gamepad->pending_input);
  LumenVhidGamepadOutputQueueClear(&gamepad->pending_output);
  LumenVhidGamepadResetProtocolState(gamepad);
  gamepad->authenticated_handle.device_id = context->next_gamepad_device_id++;
  if (gamepad->authenticated_handle.device_id == 0u) {
    gamepad->authenticated_handle.device_id = context->next_gamepad_device_id++;
  }
  gamepad->authenticated_handle.generation = context->next_gamepad_generation++;
  if (gamepad->authenticated_handle.generation == 0u) {
    gamepad->authenticated_handle.generation = context->next_gamepad_generation++;
  }
  CopyMemory(gamepad->authenticated_handle.session_token, token, sizeof(token));
  SecureZeroMemory(token, sizeof(token));
  WdfWaitLockRelease(context->state_lock);

  status = LumenVhidGamepadCreateVhf(gamepad);
  if (!NT_SUCCESS(status)) {
    LumenVhidGamepadDeleteVhf(gamepad, TRUE);
    return status;
  }
  ZeroMemory(&response, sizeof(response));
  response.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
  response.size = (uint32_t) sizeof(response);
  response.handle = gamepad->authenticated_handle;
  response.profile = profile->kind;
  response.feature_flags = profile->feature_flags;
  response.vendor_id = profile->vendor_id;
  response.product_id = profile->product_id;
  response.version_number = profile->version_number;
  response.input_report_id = profile->input_report_id;
  response.input_report_size = profile->input_report_size;
  response.output_report_size = profile->output_report_size;
  CopyMemory(output, &response, sizeof(response));
  WdfRequestSetInformation(request, sizeof(response));
  return STATUS_SUCCESS;
}

/** Retrieve and validate one authenticated fixed request. */
static NTSTATUS LumenVhidGamepadGetAuthenticatedRequest(
  WDFREQUEST request,
  LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST *local_request
) {
  const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST *input;
  size_t input_size;
  NTSTATUS status;

  status = WdfRequestRetrieveInputBuffer(request, sizeof(*local_request), (void **) &input, &input_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (input_size != sizeof(*local_request)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  CopyMemory(local_request, input, sizeof(*local_request));
  return LumenVhidGamepadValidHeader(local_request->version, local_request->size, sizeof(*local_request)) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

/** Destroy one exactly authenticated dynamic child. */
static NTSTATUS LumenVhidGamepadHandleDestroy(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT owner_file
) {
  LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST local_request;
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad;
  NTSTATUS status = LumenVhidGamepadGetAuthenticatedRequest(request, &local_request);

  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  gamepad = LumenVhidGamepadFindAuthenticatedLocked(context, owner_file, &local_request.handle);
  WdfWaitLockRelease(context->state_lock);
  if (gamepad == NULL) {
    return STATUS_ACCESS_DENIED;
  }
  LumenVhidGamepadDeleteVhf(gamepad, TRUE);
  return STATUS_SUCCESS;
}

/** Queue one exactly validated complete input report. */
static NTSTATUS LumenVhidGamepadHandleSubmit(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT owner_file
) {
  LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST local_request;
  const LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST *input;
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad;
  size_t input_size;
  NTSTATUS status;

  status = WdfRequestRetrieveInputBuffer(request, sizeof(local_request), (void **) &input, &input_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (input_size != sizeof(local_request)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  CopyMemory(&local_request, input, sizeof(local_request));
  if (!LumenVhidGamepadValidSubmitRequestHeader(&local_request)) {
    return STATUS_INVALID_PARAMETER;
  }
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  gamepad = LumenVhidGamepadFindAuthenticatedLocked(context, owner_file, &local_request.handle);
  if (gamepad == NULL) {
    status = STATUS_ACCESS_DENIED;
  } else if (!gamepad->ready || gamepad->shutting_down || gamepad->vhf_handle == NULL) {
    status = STATUS_DEVICE_NOT_READY;
  } else if (!LumenVhidGamepadValidInputReport(gamepad->profile, local_request.report, local_request.report_size)) {
    status = STATUS_INVALID_PARAMETER;
  } else if (!LumenVhidGamepadInputQueuePush(&gamepad->pending_input, local_request.report, local_request.report_size)) {
    status = STATUS_BUFFER_OVERFLOW;
  } else {
    status = STATUS_SUCCESS;
  }
  WdfWaitLockRelease(context->state_lock);
  if (NT_SUCCESS(status)) {
    status = LumenVhidGamepadSubmitNext(gamepad);
  }
  return status;
}

/** Return one queued output report without pending an unbounded request. */
static NTSTATUS LumenVhidGamepadHandleReadOutput(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT owner_file
) {
  LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST local_request;
  LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE response;
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT queued;
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad;
  void *output;
  size_t output_size;
  NTSTATUS status = LumenVhidGamepadGetAuthenticatedRequest(request, &local_request);

  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = WdfRequestRetrieveOutputBuffer(request, sizeof(response), &output, &output_size);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  if (output_size != sizeof(response)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  gamepad = LumenVhidGamepadFindAuthenticatedLocked(context, owner_file, &local_request.handle);
  if (gamepad == NULL) {
    status = STATUS_ACCESS_DENIED;
  } else if (!LumenVhidGamepadOutputQueuePop(&gamepad->pending_output, &queued)) {
    status = STATUS_NO_MORE_ENTRIES;
  } else {
    ZeroMemory(&response, sizeof(response));
    response.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
    response.size = (uint32_t) sizeof(response);
    response.handle = gamepad->authenticated_handle;
    response.report_size = queued.size;
    CopyMemory(response.report, queued.bytes, queued.size);
    CopyMemory(output, &response, sizeof(response));
    WdfRequestSetInformation(request, sizeof(response));
    status = STATUS_SUCCESS;
  }
  WdfWaitLockRelease(context->state_lock);
  return status;
}

/** Restart one child without invalidating its authenticated handle. */
static NTSTATUS LumenVhidGamepadHandleResetRuntime(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT owner_file
) {
  LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST local_request;
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad;
  NTSTATUS status = LumenVhidGamepadGetAuthenticatedRequest(request, &local_request);

  if (!NT_SUCCESS(status)) {
    return status;
  }
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  gamepad = LumenVhidGamepadFindAuthenticatedLocked(context, owner_file, &local_request.handle);
  WdfWaitLockRelease(context->state_lock);
  if (gamepad == NULL) {
    return STATUS_ACCESS_DENIED;
  }
  LumenVhidGamepadDeleteVhf(gamepad, FALSE);
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (NT_SUCCESS(status)) {
    gamepad->shutting_down = FALSE;
    WdfWaitLockRelease(context->state_lock);
  }
  if (NT_SUCCESS(status)) {
    status = LumenVhidGamepadCreateVhf(gamepad);
    if (!NT_SUCCESS(status)) {
      LumenVhidGamepadDeleteVhf(gamepad, FALSE);
    }
  }
  return status;
}

NTSTATUS LumenVhidGamepadInitialize(LUMEN_VHID_DEVICE_CONTEXT *context) {
  size_t index;

  if (context == NULL) {
    return STATUS_INVALID_PARAMETER;
  }
  context->next_gamepad_device_id = 1u;
  context->next_gamepad_generation = 1u;
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = &context->gamepads[index];
    gamepad->parent_context = context;
    LumenVhidGamepadResetProtocolState(gamepad);
  }
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = &context->gamepads[index];
    gamepad->submissions_drained_event = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (gamepad->submissions_drained_event == NULL) {
      LumenVhidGamepadUninitialize(context);
      return STATUS_INSUFFICIENT_RESOURCES;
    }
  }
  return STATUS_SUCCESS;
}

VOID LumenVhidGamepadReleaseHardware(LUMEN_VHID_DEVICE_CONTEXT *context) {
  size_t index;

  if (context == NULL) {
    return;
  }
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    LumenVhidGamepadDeleteVhf(&context->gamepads[index], TRUE);
  }
}

VOID LumenVhidGamepadUninitialize(LUMEN_VHID_DEVICE_CONTEXT *context) {
  size_t index;

  if (context == NULL) {
    return;
  }
  LumenVhidGamepadReleaseHardware(context);
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    if (context->gamepads[index].submissions_drained_event != NULL) {
      CloseHandle(context->gamepads[index].submissions_drained_event);
      context->gamepads[index].submissions_drained_event = NULL;
    }
  }
}

VOID LumenVhidGamepadCleanupFile(LUMEN_VHID_DEVICE_CONTEXT *context, WDFFILEOBJECT file_object) {
  size_t index;

  if (context == NULL || file_object == NULL) {
    return;
  }
  for (index = 0u; index < LUMEN_VHID_MAX_GAMEPADS; ++index) {
    BOOLEAN owned;
    NTSTATUS status = WdfWaitLockAcquire(context->state_lock, NULL);
    if (!NT_SUCCESS(status)) {
      return;
    }
    owned = context->gamepads[index].occupied && context->gamepads[index].owner_file == file_object;
    WdfWaitLockRelease(context->state_lock);
    if (owned) {
      LumenVhidGamepadDeleteVhf(&context->gamepads[index], TRUE);
    }
  }
}

NTSTATUS LumenVhidGamepadDispatchIoctl(
  LUMEN_VHID_DEVICE_CONTEXT *context,
  WDFREQUEST request,
  WDFFILEOBJECT file_object,
  size_t output_buffer_length,
  size_t input_buffer_length,
  ULONG io_control_code,
  BOOLEAN *handled
) {
  if (handled == NULL) {
    return STATUS_INVALID_PARAMETER;
  }
  *handled = TRUE;
  switch (io_control_code) {
    case IOCTL_LUMEN_VHID_GAMEPAD_GET_CAPABILITIES:
      if (input_buffer_length != 0u || output_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE)) {
        return STATUS_INVALID_BUFFER_SIZE;
      }
      return LumenVhidGamepadHandleCapabilities(context, request);

    case IOCTL_LUMEN_VHID_GAMEPAD_CREATE:
      if (input_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_CREATE_REQUEST) ||
          output_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_CREATE_RESPONSE)) {
        return STATUS_INVALID_BUFFER_SIZE;
      }
      return LumenVhidGamepadHandleCreate(context, request, file_object);

    case IOCTL_LUMEN_VHID_GAMEPAD_DESTROY:
      if (input_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST) || output_buffer_length != 0u) {
        return STATUS_INVALID_BUFFER_SIZE;
      }
      return LumenVhidGamepadHandleDestroy(context, request, file_object);

    case IOCTL_LUMEN_VHID_GAMEPAD_SUBMIT_REPORT:
      if (input_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST) || output_buffer_length != 0u) {
        return STATUS_INVALID_BUFFER_SIZE;
      }
      return LumenVhidGamepadHandleSubmit(context, request, file_object);

    case IOCTL_LUMEN_VHID_GAMEPAD_READ_OUTPUT:
      if (input_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST) ||
          output_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE)) {
        return STATUS_INVALID_BUFFER_SIZE;
      }
      return LumenVhidGamepadHandleReadOutput(context, request, file_object);

    case IOCTL_LUMEN_VHID_GAMEPAD_RESET_RUNTIME:
      if (input_buffer_length != sizeof(LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST) || output_buffer_length != 0u) {
        return STATUS_INVALID_BUFFER_SIZE;
      }
      return LumenVhidGamepadHandleResetRuntime(context, request, file_object);

    default:
      *handled = FALSE;
      return STATUS_INVALID_DEVICE_REQUEST;
  }
}

VOID LumenVhidGamepadEvtReadyForNextReadReport(PVOID vhf_client_context) {
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = (LUMEN_VHID_DYNAMIC_GAMEPAD *) vhf_client_context;
  LUMEN_VHID_DEVICE_CONTEXT *context;
  BOOLEAN submit_next = FALSE;
  NTSTATUS status;

  if (gamepad == NULL || gamepad->parent_context == NULL) {
    return;
  }
  context = gamepad->parent_context;
  status = WdfWaitLockAcquire(context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    return;
  }
  if (gamepad->occupied && !gamepad->shutting_down && gamepad->vhf_handle != NULL) {
    if (!gamepad->input_submission_active) {
      gamepad->has_in_flight_report = FALSE;
    }
    gamepad->vhf_ready_for_input_report = TRUE;
    submit_next = !gamepad->input_submission_active && gamepad->pending_input.count != 0u;
  }
  WdfWaitLockRelease(context->state_lock);
  if (submit_next) {
    (void) LumenVhidGamepadSubmitNext(gamepad);
  }
}

VOID LumenVhidGamepadEvtGetFeature(
  PVOID vhf_client_context,
  VHFOPERATIONHANDLE vhf_operation_handle,
  PVOID vhf_operation_context,
  PHID_XFER_PACKET hid_transfer_packet
) {
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = (LUMEN_VHID_DYNAMIC_GAMEPAD *) vhf_client_context;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(vhf_operation_context);
  if (gamepad == NULL || hid_transfer_packet == NULL || hid_transfer_packet->reportBuffer == NULL) {
    (void) VhfAsyncOperationComplete(vhf_operation_handle, STATUS_INVALID_PARAMETER);
    return;
  }
  status = WdfWaitLockAcquire(gamepad->parent_context->state_lock, NULL);
  if (NT_SUCCESS(status)) {
    if (!gamepad->occupied || gamepad->shutting_down) {
      status = STATUS_DEVICE_NOT_READY;
    } else if (gamepad->profile->kind == LUMEN_VHID_GAMEPAD_PROFILE_GENERIC) {
      status = LumenVhidGamepadCopyGenericFeature(gamepad, hid_transfer_packet);
    } else {
      status = LumenVhidGamepadCopyPlayStationFeature(gamepad, hid_transfer_packet);
    }
    WdfWaitLockRelease(gamepad->parent_context->state_lock);
  }
  (void) VhfAsyncOperationComplete(vhf_operation_handle, status);
}

VOID LumenVhidGamepadEvtSetFeature(
  PVOID vhf_client_context,
  VHFOPERATIONHANDLE vhf_operation_handle,
  PVOID vhf_operation_context,
  PHID_XFER_PACKET hid_transfer_packet
) {
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = (LUMEN_VHID_DYNAMIC_GAMEPAD *) vhf_client_context;
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT output;
  BOOLEAN supported = FALSE;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(vhf_operation_context);
  if (gamepad == NULL || hid_transfer_packet == NULL || hid_transfer_packet->reportBuffer == NULL ||
      !LumenVhidGamepadCopyOutputPacket(hid_transfer_packet, &output)) {
    (void) VhfAsyncOperationComplete(vhf_operation_handle, STATUS_INVALID_PARAMETER);
    return;
  }
  status = WdfWaitLockAcquire(gamepad->parent_context->state_lock, NULL);
  if (!NT_SUCCESS(status)) {
    (void) VhfAsyncOperationComplete(vhf_operation_handle, status);
    return;
  }
  if (gamepad->occupied && !gamepad->shutting_down) {
    if (gamepad->profile->kind == LUMEN_VHID_GAMEPAD_PROFILE_GENERIC) {
      supported = LumenVhidGamepadHandleGenericSetFeature(gamepad, hid_transfer_packet);
    } else if (gamepad->profile->kind == LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4 ||
               gamepad->profile->kind == LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE) {
      supported = TRUE;
    }
    if (supported) {
      supported = LumenVhidGamepadQueueOutputLocked(gamepad, &output);
    }
  }
  WdfWaitLockRelease(gamepad->parent_context->state_lock);
  (void) VhfAsyncOperationComplete(vhf_operation_handle, supported ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED);
}

VOID LumenVhidGamepadEvtWriteReport(
  PVOID vhf_client_context,
  VHFOPERATIONHANDLE vhf_operation_handle,
  PVOID vhf_operation_context,
  PHID_XFER_PACKET hid_transfer_packet
) {
  LUMEN_VHID_DYNAMIC_GAMEPAD *gamepad = (LUMEN_VHID_DYNAMIC_GAMEPAD *) vhf_client_context;
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT output;
  NTSTATUS status;

  UNREFERENCED_PARAMETER(vhf_operation_context);
  if (gamepad == NULL || hid_transfer_packet == NULL || hid_transfer_packet->reportBuffer == NULL ||
      !LumenVhidGamepadCopyOutputPacket(hid_transfer_packet, &output)) {
    (void) VhfAsyncOperationComplete(vhf_operation_handle, STATUS_INVALID_PARAMETER);
    return;
  }
  LumenVhidGamepadQueueSwitchReply(gamepad, &output);
  status = WdfWaitLockAcquire(gamepad->parent_context->state_lock, NULL);
  if (NT_SUCCESS(status)) {
    if (!gamepad->occupied || gamepad->shutting_down) {
      status = STATUS_DEVICE_NOT_READY;
    } else if (!LumenVhidGamepadQueueOutputLocked(gamepad, &output)) {
      status = STATUS_INVALID_PARAMETER;
    } else {
      LumenVhidGamepadHandleGenericOutput(gamepad, &output);
    }
    WdfWaitLockRelease(gamepad->parent_context->state_lock);
  }
  (void) VhfAsyncOperationComplete(vhf_operation_handle, status);
}
