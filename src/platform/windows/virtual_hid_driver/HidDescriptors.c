/**
 * @file HidDescriptors.c
 * @brief Four-collection VHF report descriptor for Lumen input injection.
 */

#include "HidDescriptors.h"

#include "../virtual_hid_protocol.h"

#include <limits.h>

/*
 * Report 1 is an eight-bit modifier state followed by 224 one-bit
 * Keyboard/Keypad usages (00-DF). Report 2 is a five-button relative mouse
 * with signed 16-bit X, Y, wheel, and AC Pan deltas. Report 3 is a Consumer
 * Control array containing up to four simultaneous 16-bit usages. Report 4 is
 * a separate five-button absolute mouse with unsigned 16-bit X and Y plus
 * signed 16-bit wheel and AC Pan deltas.
 */
const BYTE LumenVhidReportDescriptor[] = {
  /* NKRO keyboard top-level collection. */
  0x05,
  0x01, /* Usage Page (Generic Desktop) */
  0x09,
  0x06, /* Usage (Keyboard) */
  0xa1,
  0x01, /* Collection (Application) */
  0x85,
  LUMEN_VHID_REPORT_ID_KEYBOARD, /*   Report ID (1) */
  0x05,
  0x07, /*   Usage Page (Keyboard/Keypad) */
  0x19,
  0xe0, /*   Usage Minimum (Left Control) */
  0x29,
  0xe7, /*   Usage Maximum (Right GUI) */
  0x15,
  0x00, /*   Logical Minimum (0) */
  0x25,
  0x01, /*   Logical Maximum (1) */
  0x75,
  0x01, /*   Report Size (1) */
  0x95,
  0x08, /*   Report Count (8) */
  0x81,
  0x02, /*   Input (Data, Variable, Absolute) */
  0x19,
  0x00, /*   Usage Minimum (No event) */
  0x29,
  0xdf, /*   Usage Maximum (Reserved DF) */
  0x75,
  0x01, /*   Report Size (1) */
  0x96,
  0xe0,
  0x00, /*   Report Count (224) */
  0x81,
  0x02, /*   Input (Data, Variable, Absolute) */
  0xc0, /* End Collection */

  /* Relative mouse top-level collection. */
  0x05,
  0x01, /* Usage Page (Generic Desktop) */
  0x09,
  0x02, /* Usage (Mouse) */
  0xa1,
  0x01, /* Collection (Application) */
  0x09,
  0x01, /*   Usage (Pointer) */
  0xa1,
  0x00, /*   Collection (Physical) */
  0x85,
  LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE, /*     Report ID (2) */
  0x05,
  0x09, /*     Usage Page (Button) */
  0x19,
  0x01, /*     Usage Minimum (Button 1) */
  0x29,
  0x05, /*     Usage Maximum (Button 5) */
  0x15,
  0x00, /*     Logical Minimum (0) */
  0x25,
  0x01, /*     Logical Maximum (1) */
  0x75,
  0x01, /*     Report Size (1) */
  0x95,
  0x05, /*     Report Count (5) */
  0x81,
  0x02, /*     Input (Data, Variable, Absolute) */
  0x75,
  0x03, /*     Report Size (3) */
  0x95,
  0x01, /*     Report Count (1) */
  0x81,
  0x03, /*     Input (Constant, Variable, Absolute) */
  0x05,
  0x01, /*     Usage Page (Generic Desktop) */
  0x09,
  0x30, /*     Usage (X) */
  0x09,
  0x31, /*     Usage (Y) */
  0x09,
  0x38, /*     Usage (Wheel) */
  0x16,
  0x00,
  0x80, /*     Logical Minimum (-32768) */
  0x26,
  0xff,
  0x7f, /*     Logical Maximum (32767) */
  0x75,
  0x10, /*     Report Size (16) */
  0x95,
  0x03, /*     Report Count (3) */
  0x81,
  0x06, /*     Input (Data, Variable, Relative) */
  0x05,
  0x0c, /*     Usage Page (Consumer) */
  0x0a,
  0x38,
  0x02, /*     Usage (AC Pan) */
  0x16,
  0x00,
  0x80, /*     Logical Minimum (-32768) */
  0x26,
  0xff,
  0x7f, /*     Logical Maximum (32767) */
  0x75,
  0x10, /*     Report Size (16) */
  0x95,
  0x01, /*     Report Count (1) */
  0x81,
  0x06, /*     Input (Data, Variable, Relative) */
  0xc0, /*   End Collection (Pointer Physical) */
  0xc0, /* End Collection (Application) */

  /* Absolute mouse top-level collection. */
  0x05,
  0x01, /* Usage Page (Generic Desktop) */
  0x09,
  0x02, /* Usage (Mouse) */
  0xa1,
  0x01, /* Collection (Application) */
  0x09,
  0x01, /*   Usage (Pointer) */
  0xa1,
  0x00, /*   Collection (Physical) */
  0x85,
  LUMEN_VHID_REPORT_ID_MOUSE_ABSOLUTE, /*     Report ID (4) */
  0x05,
  0x09, /*     Usage Page (Button) */
  0x19,
  0x01, /*     Usage Minimum (Button 1) */
  0x29,
  0x05, /*     Usage Maximum (Button 5) */
  0x15,
  0x00, /*     Logical Minimum (0) */
  0x25,
  0x01, /*     Logical Maximum (1) */
  0x75,
  0x01, /*     Report Size (1) */
  0x95,
  0x05, /*     Report Count (5) */
  0x81,
  0x02, /*     Input (Data, Variable, Absolute) */
  0x75,
  0x03, /*     Report Size (3) */
  0x95,
  0x01, /*     Report Count (1) */
  0x81,
  0x03, /*     Input (Constant, Variable, Absolute) */
  0x05,
  0x01, /*     Usage Page (Generic Desktop) */
  0x09,
  0x30, /*     Usage (X) */
  0x09,
  0x31, /*     Usage (Y) */
  0x15,
  0x00, /*     Logical Minimum (0) */
  0x27,
  0xff,
  0xff,
  0x00,
  0x00, /*     Logical Maximum (65535) */
  0x75,
  0x10, /*     Report Size (16) */
  0x95,
  0x02, /*     Report Count (2) */
  0x81,
  0x02, /*     Input (Data, Variable, Absolute) */
  0x09,
  0x38, /*     Usage (Wheel) */
  0x16,
  0x00,
  0x80, /*     Logical Minimum (-32768) */
  0x26,
  0xff,
  0x7f, /*     Logical Maximum (32767) */
  0x75,
  0x10, /*     Report Size (16) */
  0x95,
  0x01, /*     Report Count (1) */
  0x81,
  0x06, /*     Input (Data, Variable, Relative) */
  0x05,
  0x0c, /*     Usage Page (Consumer) */
  0x0a,
  0x38,
  0x02, /*     Usage (AC Pan) */
  0x16,
  0x00,
  0x80, /*     Logical Minimum (-32768) */
  0x26,
  0xff,
  0x7f, /*     Logical Maximum (32767) */
  0x75,
  0x10, /*     Report Size (16) */
  0x95,
  0x01, /*     Report Count (1) */
  0x81,
  0x06, /*     Input (Data, Variable, Relative) */
  0xc0, /*   End Collection (Pointer Physical) */
  0xc0, /* End Collection (Application) */

  /* Consumer Control top-level collection. */
  0x05,
  0x0c, /* Usage Page (Consumer) */
  0x09,
  0x01, /* Usage (Consumer Control) */
  0xa1,
  0x01, /* Collection (Application) */
  0x85,
  LUMEN_VHID_REPORT_ID_CONSUMER, /*   Report ID (3) */
  0x15,
  0x00, /*   Logical Minimum (0) */
  0x26,
  0xff,
  0x0f, /*   Logical Maximum (4095) */
  0x19,
  0x00, /*   Usage Minimum (Unassigned) */
  0x2a,
  0xff,
  0x0f, /*   Usage Maximum (4095) */
  0x75,
  0x10, /*   Report Size (16) */
  0x95,
  LUMEN_VHID_CONSUMER_USAGE_COUNT, /* Report Count (4) */
  0x81,
  0x00, /*   Input (Data, Array, Absolute) */
  0xc0 /* End Collection */
};

const USHORT LumenVhidReportDescriptorLength = (USHORT) sizeof(LumenVhidReportDescriptor);

typedef char lumen_vhid_descriptor_fits_ushort[(sizeof(LumenVhidReportDescriptor) <= USHRT_MAX) ? 1 : -1];
