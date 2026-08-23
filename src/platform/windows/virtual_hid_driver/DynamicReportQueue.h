/**
 * @file DynamicReportQueue.h
 * @brief Portable bounded queues for per-gamepad VHF input and output reports.
 */

#ifndef LUMEN_VIRTUAL_HID_DYNAMIC_REPORT_QUEUE_H
#define LUMEN_VIRTUAL_HID_DYNAMIC_REPORT_QUEUE_H

#include "../virtual_hid_protocol.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** Maximum pending input reports retained for one dynamic gamepad. */
#define LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY 64u
/** Recovery storage slot reserved for one failed VHF input submission. */
#define LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY (LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY + 1u)
/** Maximum host output events retained for one dynamic gamepad. */
#define LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY 32u

/** Owned complete HID report used by both dynamic queues. */
typedef struct LUMEN_VHID_GAMEPAD_QUEUED_REPORT {
  uint8_t bytes[LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE];  ///< Complete report including any report ID.
  uint32_t size;  ///< Number of valid report bytes.
} LUMEN_VHID_GAMEPAD_QUEUED_REPORT;

/** Fixed-capacity FIFO for reports waiting on VHF readiness. */
typedef struct LUMEN_VHID_GAMEPAD_INPUT_QUEUE {
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT reports[LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY];  ///< Owned ring storage.
  size_t head;  ///< Index of oldest report.
  size_t count;  ///< Number of queued reports.
} LUMEN_VHID_GAMEPAD_INPUT_QUEUE;

/** Fixed-capacity FIFO for reports produced by host HID consumers. */
typedef struct LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE {
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT reports[LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY];  ///< Owned ring storage.
  size_t head;  ///< Index of oldest report.
  size_t count;  ///< Number of queued reports.
} LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE;

/** @brief Clear one dynamic input queue. @param queue Queue to clear; null is ignored. */
static inline void LumenVhidGamepadInputQueueClear(LUMEN_VHID_GAMEPAD_INPUT_QUEUE *queue) {
  if (queue != NULL) {
    queue->head = 0u;
    queue->count = 0u;
  }
}

/**
 * @brief Append a complete report to a dynamic input FIFO.
 *
 * @param queue Destination queue.
 * @param report Complete report bytes.
 * @param report_size Exact report size.
 * @return Nonzero when accepted; zero for invalid input or a full queue.
 */
static inline int LumenVhidGamepadInputQueuePush(
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE *queue,
  const void *report,
  size_t report_size
) {
  size_t tail;

  if (queue == NULL || report == NULL || report_size == 0u ||
      report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
      queue->count >= LUMEN_VHID_GAMEPAD_INPUT_QUEUE_CAPACITY) {
    return 0;
  }
  tail = (queue->head + queue->count) % LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY;
  memcpy(queue->reports[tail].bytes, report, report_size);
  queue->reports[tail].size = (uint32_t) report_size;
  ++queue->count;
  return 1;
}

/**
 * @brief Pop the oldest dynamic input report.
 *
 * @param queue Source queue.
 * @param report Receives an owned copy.
 * @return Nonzero when a report was returned.
 */
static inline int LumenVhidGamepadInputQueuePop(
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE *queue,
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT *report
) {
  if (queue == NULL || report == NULL || queue->count == 0u) {
    return 0;
  }
  *report = queue->reports[queue->head];
  queue->head = (queue->head + 1u) % LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY;
  --queue->count;
  return 1;
}

/**
 * @brief Restore one failed VHF submission at the front of the input FIFO.
 *
 * @param queue Destination queue.
 * @param report Complete owned report.
 * @return Nonzero when restored into the reserved recovery slot.
 */
static inline int LumenVhidGamepadInputQueuePushFront(
  LUMEN_VHID_GAMEPAD_INPUT_QUEUE *queue,
  const LUMEN_VHID_GAMEPAD_QUEUED_REPORT *report
) {
  if (queue == NULL || report == NULL || report->size == 0u ||
      report->size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE ||
      queue->count >= LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY) {
    return 0;
  }
  queue->head = (queue->head + LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY - 1u) %
                LUMEN_VHID_GAMEPAD_INPUT_QUEUE_STORAGE_CAPACITY;
  queue->reports[queue->head] = *report;
  ++queue->count;
  return 1;
}

/** @brief Clear one dynamic output queue. @param queue Queue to clear; null is ignored. */
static inline void LumenVhidGamepadOutputQueueClear(LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE *queue) {
  if (queue != NULL) {
    queue->head = 0u;
    queue->count = 0u;
  }
}

/**
 * @brief Append host output while keeping the queue bounded.
 *
 * The oldest event is dropped when full so a stalled client cannot block VHF
 * callbacks and the most recent force-feedback state remains observable.
 *
 * @param queue Destination queue.
 * @param report Complete report bytes.
 * @param report_size Exact report size.
 * @return Nonzero when valid input was accepted.
 */
static inline int LumenVhidGamepadOutputQueuePushLatest(
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE *queue,
  const void *report,
  size_t report_size
) {
  size_t tail;

  if (queue == NULL || report == NULL || report_size == 0u ||
      report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE) {
    return 0;
  }
  if (queue->count == LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY) {
    queue->head = (queue->head + 1u) % LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY;
    --queue->count;
  }
  tail = (queue->head + queue->count) % LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY;
  memcpy(queue->reports[tail].bytes, report, report_size);
  queue->reports[tail].size = (uint32_t) report_size;
  ++queue->count;
  return 1;
}

/**
 * @brief Preserve an explicit reset boundary when an ordered output queue overflows.
 *
 * A full queue is cleared, then the reset report and current report are queued
 * in that order. Consumers can safely discard incomplete state accumulated
 * before the reset instead of interpreting a truncated force-feedback sequence.
 *
 * @param queue Destination queue.
 * @param reset_report Semantic reset report.
 * @param reset_report_size Exact reset-report size.
 * @param report Current complete report.
 * @param report_size Exact current-report size.
 * @return Two when overflow recovery ran, one for a normal append, or zero for invalid input.
 */
static inline int LumenVhidGamepadOutputQueuePushWithResetOnOverflow(
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE *queue,
  const void *reset_report,
  size_t reset_report_size,
  const void *report,
  size_t report_size
) {
  if (queue == NULL || reset_report == NULL || reset_report_size == 0u ||
      reset_report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE || report == NULL ||
      report_size == 0u || report_size > LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE) {
    return 0;
  }
  if (queue->count < LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY) {
    return LumenVhidGamepadOutputQueuePushLatest(queue, report, report_size);
  }
  LumenVhidGamepadOutputQueueClear(queue);
  if (!LumenVhidGamepadOutputQueuePushLatest(queue, reset_report, reset_report_size) ||
      !LumenVhidGamepadOutputQueuePushLatest(queue, report, report_size)) {
    LumenVhidGamepadOutputQueueClear(queue);
    return 0;
  }
  return 2;
}

/**
 * @brief Pop the oldest dynamic output report.
 *
 * @param queue Source queue.
 * @param report Receives an owned copy.
 * @return Nonzero when a report was returned.
 */
static inline int LumenVhidGamepadOutputQueuePop(
  LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE *queue,
  LUMEN_VHID_GAMEPAD_QUEUED_REPORT *report
) {
  if (queue == NULL || report == NULL || queue->count == 0u) {
    return 0;
  }
  *report = queue->reports[queue->head];
  queue->head = (queue->head + 1u) % LUMEN_VHID_GAMEPAD_OUTPUT_QUEUE_CAPACITY;
  --queue->count;
  return 1;
}

#endif /* LUMEN_VIRTUAL_HID_DYNAMIC_REPORT_QUEUE_H */
