/**
 * @file ReportQueue.h
 * @brief Portable bounded queue for readiness-driven VHF input reports.
 */

#ifndef LUMEN_VIRTUAL_HID_REPORT_QUEUE_H
#define LUMEN_VIRTUAL_HID_REPORT_QUEUE_H

#include "../virtual_hid_protocol.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** Maximum number of ordered reports retained until VHF grants readiness. */
#define LUMEN_VHID_REPORT_QUEUE_CAPACITY 64u
/** One recovery slot reserved for reinserting a failed in-flight submission. */
#define LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY (LUMEN_VHID_REPORT_QUEUE_CAPACITY + 1u)
/** Maximum packed input-report size accepted by the Lumen VHF descriptor. */
#define LUMEN_VHID_REPORT_QUEUE_MAX_REPORT_SIZE 64u

/** One owned copy of a complete HID input report. */
typedef struct LUMEN_VHID_QUEUED_REPORT {
  uint8_t bytes[LUMEN_VHID_REPORT_QUEUE_MAX_REPORT_SIZE];  ///< Complete report, including report ID.
  size_t size;  ///< Number of valid bytes in bytes.
} LUMEN_VHID_QUEUED_REPORT;

/** Fixed-capacity FIFO preserving accepted HID state transitions. */
typedef struct LUMEN_VHID_REPORT_QUEUE {
  LUMEN_VHID_QUEUED_REPORT reports[LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY];  ///< Owned FIFO storage.
  size_t head;  ///< Index of the oldest report.
  size_t count;  ///< Number of queued reports.
} LUMEN_VHID_REPORT_QUEUE;

/**
 * @brief Reset a report queue to the empty state.
 *
 * @param queue Queue to clear; null is ignored.
 */
static inline void LumenVhidReportQueueClear(LUMEN_VHID_REPORT_QUEUE *queue) {
  if (queue == NULL) {
    return;
  }
  queue->head = 0u;
  queue->count = 0u;
}

/**
 * @brief Return whether a signed sum fits in a 16-bit HID relative field.
 *
 * @param value Candidate accumulated value.
 * @return Nonzero when value is representable by int16_t.
 */
static inline int LumenVhidReportQueueFitsInt16(int32_t value) {
  return value >= INT16_MIN && value <= INT16_MAX;
}

/**
 * @brief Clamp one accumulated relative value to a signed 16-bit segment.
 *
 * @param value Accumulated relative value.
 * @return First lossless signed 16-bit segment.
 */
static inline int16_t LumenVhidReportQueueFirstSegment(int32_t value) {
  if (value > INT16_MAX) {
    return INT16_MAX;
  }
  if (value < INT16_MIN) {
    return INT16_MIN;
  }
  return (int16_t) value;
}

/**
 * @brief Append one already-validated report to the FIFO.
 *
 * @param queue Destination queue.
 * @param report Complete report bytes.
 * @param report_size Exact report size.
 * @return Nonzero on success; zero when full or invalid.
 */
static inline int LumenVhidReportQueueAppend(
  LUMEN_VHID_REPORT_QUEUE *queue,
  const void *report,
  size_t report_size
) {
  size_t tail;

  if (queue == NULL || report == NULL || report_size == 0u ||
      report_size > LUMEN_VHID_REPORT_QUEUE_MAX_REPORT_SIZE ||
      queue->count >= LUMEN_VHID_REPORT_QUEUE_CAPACITY) {
    return 0;
  }
  tail = (queue->head + queue->count) % LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY;
  memcpy(queue->reports[tail].bytes, report, report_size);
  queue->reports[tail].size = report_size;
  ++queue->count;
  return 1;
}

/**
 * @brief Coalesce an adjacent relative-mouse report without losing movement.
 *
 * Reports coalesce only when their complete button bitmap is identical. When
 * any accumulated axis exceeds int16_t, the sum is split into two ordered HID
 * reports. The queue is left unchanged if the required second slot is full.
 *
 * @param queue Queue whose newest entry may be updated.
 * @param report New relative-mouse report.
 * @return One when coalesced, zero when the caller must append normally, and
 * -1 when coalescing required another slot but the queue was full.
 */
static inline int LumenVhidReportQueueCoalesceRelativeMouse(
  LUMEN_VHID_REPORT_QUEUE *queue,
  const LUMEN_VHID_RELATIVE_MOUSE_REPORT *report
) {
  size_t tail;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT previous;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT incoming;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT first;
  LUMEN_VHID_RELATIVE_MOUSE_REPORT remainder;
  int32_t x;
  int32_t y;
  int32_t vertical_wheel;
  int32_t horizontal_wheel;
  int needs_remainder;

  if (queue == NULL || report == NULL || queue->count == 0u) {
    return 0;
  }
  tail = (queue->head + queue->count - 1u) % LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY;
  if (queue->reports[tail].size != sizeof(previous)) {
    return 0;
  }
  memcpy(&previous, queue->reports[tail].bytes, sizeof(previous));
  memcpy(&incoming, report, sizeof(incoming));
  if (previous.report_id != LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE ||
      incoming.report_id != LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE ||
      previous.buttons != incoming.buttons) {
    return 0;
  }

  x = (int32_t) previous.x + (int32_t) incoming.x;
  y = (int32_t) previous.y + (int32_t) incoming.y;
  vertical_wheel = (int32_t) previous.vertical_wheel + (int32_t) incoming.vertical_wheel;
  horizontal_wheel = (int32_t) previous.horizontal_wheel + (int32_t) incoming.horizontal_wheel;
  needs_remainder = !LumenVhidReportQueueFitsInt16(x) || !LumenVhidReportQueueFitsInt16(y) ||
                    !LumenVhidReportQueueFitsInt16(vertical_wheel) ||
                    !LumenVhidReportQueueFitsInt16(horizontal_wheel);
  if (needs_remainder && queue->count >= LUMEN_VHID_REPORT_QUEUE_CAPACITY) {
    return -1;
  }

  first = previous;
  first.x = LumenVhidReportQueueFirstSegment(x);
  first.y = LumenVhidReportQueueFirstSegment(y);
  first.vertical_wheel = LumenVhidReportQueueFirstSegment(vertical_wheel);
  first.horizontal_wheel = LumenVhidReportQueueFirstSegment(horizontal_wheel);
  memcpy(queue->reports[tail].bytes, &first, sizeof(first));
  if (!needs_remainder) {
    return 1;
  }

  remainder = previous;
  remainder.x = (int16_t) (x - (int32_t) first.x);
  remainder.y = (int16_t) (y - (int32_t) first.y);
  remainder.vertical_wheel = (int16_t) (vertical_wheel - (int32_t) first.vertical_wheel);
  remainder.horizontal_wheel = (int16_t) (horizontal_wheel - (int32_t) first.horizontal_wheel);
  return LumenVhidReportQueueAppend(queue, &remainder, sizeof(remainder)) ? 1 : -1;
}

/**
 * @brief Coalesce adjacent absolute motion while preserving wheel totals.
 *
 * Identical button state permits the newest absolute coordinates to replace
 * the prior coordinates. Relative wheel fields accumulate and split into two
 * ordered reports when their signed 16-bit range is exceeded.
 *
 * @param queue Queue whose newest entry may be updated.
 * @param report New absolute-mouse report.
 * @return One when coalesced, zero when the caller must append normally, and
 * -1 when coalescing required another slot but the queue was full.
 */
static inline int LumenVhidReportQueueCoalesceAbsoluteMouse(
  LUMEN_VHID_REPORT_QUEUE *queue,
  const LUMEN_VHID_ABSOLUTE_MOUSE_REPORT *report
) {
  size_t tail;
  LUMEN_VHID_ABSOLUTE_MOUSE_REPORT previous;
  LUMEN_VHID_ABSOLUTE_MOUSE_REPORT incoming;
  LUMEN_VHID_ABSOLUTE_MOUSE_REPORT first;
  LUMEN_VHID_ABSOLUTE_MOUSE_REPORT remainder;
  int32_t vertical_wheel;
  int32_t horizontal_wheel;
  int needs_remainder;

  if (queue == NULL || report == NULL || queue->count == 0u) {
    return 0;
  }
  tail = (queue->head + queue->count - 1u) % LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY;
  if (queue->reports[tail].size != sizeof(previous)) {
    return 0;
  }
  memcpy(&previous, queue->reports[tail].bytes, sizeof(previous));
  memcpy(&incoming, report, sizeof(incoming));
  if (previous.report_id != LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE ||
      incoming.report_id != LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE ||
      previous.buttons != incoming.buttons) {
    return 0;
  }

  vertical_wheel = (int32_t) previous.vertical_wheel + (int32_t) incoming.vertical_wheel;
  horizontal_wheel = (int32_t) previous.horizontal_wheel + (int32_t) incoming.horizontal_wheel;
  needs_remainder = !LumenVhidReportQueueFitsInt16(vertical_wheel) ||
                    !LumenVhidReportQueueFitsInt16(horizontal_wheel);
  if (needs_remainder && queue->count >= LUMEN_VHID_REPORT_QUEUE_CAPACITY) {
    return -1;
  }

  first = incoming;
  first.vertical_wheel = LumenVhidReportQueueFirstSegment(vertical_wheel);
  first.horizontal_wheel = LumenVhidReportQueueFirstSegment(horizontal_wheel);
  memcpy(queue->reports[tail].bytes, &first, sizeof(first));
  if (!needs_remainder) {
    return 1;
  }

  remainder = incoming;
  remainder.vertical_wheel = (int16_t) (vertical_wheel - (int32_t) first.vertical_wheel);
  remainder.horizontal_wheel = (int16_t) (horizontal_wheel - (int32_t) first.horizontal_wheel);
  return LumenVhidReportQueueAppend(queue, &remainder, sizeof(remainder)) ? 1 : -1;
}

/**
 * @brief Queue one complete validated HID input report.
 *
 * @param queue Destination FIFO.
 * @param report_kind LUMEN_VHID_REPORT_KIND_* value identifying report.
 * @param report Complete report bytes.
 * @param report_size Exact report size.
 * @return Nonzero when accepted; zero when invalid or full.
 */
static inline int LumenVhidReportQueuePush(
  LUMEN_VHID_REPORT_QUEUE *queue,
  uint32_t report_kind,
  const void *report,
  size_t report_size
) {
  int coalesced;

  if (report_kind == LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE &&
      report_size == sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT)) {
    coalesced = LumenVhidReportQueueCoalesceRelativeMouse(
      queue,
      (const LUMEN_VHID_RELATIVE_MOUSE_REPORT *) report
    );
    if (coalesced != 0) {
      return coalesced > 0;
    }
  } else if (report_kind == LUMEN_VHID_REPORT_KIND_ABSOLUTE_MOUSE &&
             report_size == sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT)) {
    coalesced = LumenVhidReportQueueCoalesceAbsoluteMouse(
      queue,
      (const LUMEN_VHID_ABSOLUTE_MOUSE_REPORT *) report
    );
    if (coalesced != 0) {
      return coalesced > 0;
    }
  }
  return LumenVhidReportQueueAppend(queue, report, report_size);
}

/**
 * @brief Remove the oldest queued report.
 *
 * @param queue Source FIFO.
 * @param report Receives an owned report copy.
 * @return Nonzero when a report was returned; zero when empty or invalid.
 */
static inline int LumenVhidReportQueuePop(
  LUMEN_VHID_REPORT_QUEUE *queue,
  LUMEN_VHID_QUEUED_REPORT *report
) {
  if (queue == NULL || report == NULL || queue->count == 0u) {
    return 0;
  }
  *report = queue->reports[queue->head];
  queue->head = (queue->head + 1u) % LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY;
  --queue->count;
  return 1;
}

/**
 * @brief Reinsert a failed in-flight submission at the front of the FIFO.
 *
 * The extra storage slot exists only for this recovery path. Normal producers
 * remain limited to LUMEN_VHID_REPORT_QUEUE_CAPACITY accepted pending reports.
 *
 * @param queue Destination FIFO.
 * @param report Owned report copy to restore.
 * @return Nonzero on success; zero for invalid input or exhausted recovery storage.
 */
static inline int LumenVhidReportQueuePushFront(
  LUMEN_VHID_REPORT_QUEUE *queue,
  const LUMEN_VHID_QUEUED_REPORT *report
) {
  if (queue == NULL || report == NULL || report->size == 0u ||
      report->size > LUMEN_VHID_REPORT_QUEUE_MAX_REPORT_SIZE ||
      queue->count >= LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY) {
    return 0;
  }
  queue->head = (queue->head + LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY - 1u) %
                LUMEN_VHID_REPORT_QUEUE_STORAGE_CAPACITY;
  queue->reports[queue->head] = *report;
  ++queue->count;
  return 1;
}

#endif /* LUMEN_VIRTUAL_HID_REPORT_QUEUE_H */
