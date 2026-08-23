/**
 * @file tests/unit/platform/windows/virtual_hid_report_queue_c_smoke.c
 * @brief Strict C compilation smoke test for the portable VHF report queue.
 */

#include <src/platform/windows/virtual_hid_driver/ReportQueue.h>

/**
 * @brief Exercise the public report-queue surface from a C translation unit.
 *
 * @return Zero when queue, dequeue, and recovery insertion succeed.
 */
int LumenVhidReportQueueCCompatibilitySmoke(void) {
  LUMEN_VHID_REPORT_QUEUE queue = {0};
  LUMEN_VHID_QUEUED_REPORT queued = {{0}, 0u};
  LUMEN_VHID_RELATIVE_MOUSE_REPORT mouse = {LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE, 0u, 1, 2, 0, 0};

  LumenVhidReportQueueClear(&queue);
  if (!LumenVhidReportQueuePush(&queue, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE, &mouse, sizeof(mouse)) ||
      !LumenVhidReportQueuePop(&queue, &queued) || !LumenVhidReportQueuePushFront(&queue, &queued)) {
    return 1;
  }
  return queue.count == 1u ? 0 : 1;
}
