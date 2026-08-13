/**
 * @file HidDescriptors.c
 * @brief Composite NKRO keyboard and relative/absolute mouse descriptor.
 */

#include "HidDescriptors.h"

/*
 * Keyboard report 1 is an eight-bit modifier state followed by 224 one-bit
 * Keyboard/Keypad usages (00-DF). Mouse reports 2 and 3 live in one mouse
 * top-level collection so their complete five-button state belongs to one
 * logical mouse while relative and absolute coordinate semantics remain
 * unambiguous.
 */
const UCHAR LumenVhidReportDescriptor[] = {
  /* NKRO keyboard top-level collection. */
  0x05, 0x01,        /* Usage Page (Generic Desktop) */
  0x09, 0x06,        /* Usage (Keyboard) */
  0xa1, 0x01,        /* Collection (Application) */
  0x85, 0x01,        /*   Report ID (1) */
  0x05, 0x07,        /*   Usage Page (Keyboard/Keypad) */
  0x19, 0xe0,        /*   Usage Minimum (Left Control) */
  0x29, 0xe7,        /*   Usage Maximum (Right GUI) */
  0x15, 0x00,        /*   Logical Minimum (0) */
  0x25, 0x01,        /*   Logical Maximum (1) */
  0x75, 0x01,        /*   Report Size (1) */
  0x95, 0x08,        /*   Report Count (8) */
  0x81, 0x02,        /*   Input (Data, Variable, Absolute) */
  0x19, 0x00,        /*   Usage Minimum (No event) */
  0x29, 0xdf,        /*   Usage Maximum (Reserved DF) */
  0x75, 0x01,        /*   Report Size (1) */
  0x96, 0xe0, 0x00,  /*   Report Count (224) */
  0x81, 0x02,        /*   Input (Data, Variable, Absolute) */
  0xc0,              /* End Collection */

  /* One mouse top-level collection with relative and absolute report IDs. */
  0x05, 0x01,        /* Usage Page (Generic Desktop) */
  0x09, 0x02,        /* Usage (Mouse) */
  0xa1, 0x01,        /* Collection (Application) */
  0x09, 0x01,        /*   Usage (Pointer) */
  0xa1, 0x00,        /*   Collection (Physical) */

  0x85, 0x02,        /*     Report ID (2, relative) */
  0x05, 0x09,        /*     Usage Page (Button) */
  0x19, 0x01,        /*     Usage Minimum (Button 1) */
  0x29, 0x05,        /*     Usage Maximum (Button 5) */
  0x15, 0x00,        /*     Logical Minimum (0) */
  0x25, 0x01,        /*     Logical Maximum (1) */
  0x75, 0x01,        /*     Report Size (1) */
  0x95, 0x05,        /*     Report Count (5) */
  0x81, 0x02,        /*     Input (Data, Variable, Absolute) */
  0x75, 0x03,        /*     Report Size (3) */
  0x95, 0x01,        /*     Report Count (1) */
  0x81, 0x03,        /*     Input (Constant, Variable, Absolute) */
  0x05, 0x01,        /*     Usage Page (Generic Desktop) */
  0x09, 0x30,        /*     Usage (X) */
  0x09, 0x31,        /*     Usage (Y) */
  0x09, 0x38,        /*     Usage (Wheel) */
  0x16, 0x00, 0x80,  /*     Logical Minimum (-32768) */
  0x26, 0xff, 0x7f,  /*     Logical Maximum (32767) */
  0x75, 0x10,        /*     Report Size (16) */
  0x95, 0x03,        /*     Report Count (3) */
  0x81, 0x06,        /*     Input (Data, Variable, Relative) */
  0x05, 0x0c,        /*     Usage Page (Consumer) */
  0x0a, 0x38, 0x02,  /*     Usage (AC Pan) */
  0x16, 0x00, 0x80,  /*     Logical Minimum (-32768) */
  0x26, 0xff, 0x7f,  /*     Logical Maximum (32767) */
  0x75, 0x10,        /*     Report Size (16) */
  0x95, 0x01,        /*     Report Count (1) */
  0x81, 0x06,        /*     Input (Data, Variable, Relative) */

  0x85, 0x03,        /*     Report ID (3, absolute) */
  0x05, 0x09,        /*     Usage Page (Button) */
  0x19, 0x01,        /*     Usage Minimum (Button 1) */
  0x29, 0x05,        /*     Usage Maximum (Button 5) */
  0x15, 0x00,        /*     Logical Minimum (0) */
  0x25, 0x01,        /*     Logical Maximum (1) */
  0x75, 0x01,        /*     Report Size (1) */
  0x95, 0x05,        /*     Report Count (5) */
  0x81, 0x02,        /*     Input (Data, Variable, Absolute) */
  0x75, 0x03,        /*     Report Size (3) */
  0x95, 0x01,        /*     Report Count (1) */
  0x81, 0x03,        /*     Input (Constant, Variable, Absolute) */
  0x05, 0x01,        /*     Usage Page (Generic Desktop) */
  0x09, 0x30,        /*     Usage (X) */
  0x09, 0x31,        /*     Usage (Y) */
  0x15, 0x00,        /*     Logical Minimum (0) */
  0x27, 0xff, 0xff, 0x00, 0x00, /* Logical Maximum (65535) */
  0x75, 0x10,        /*     Report Size (16) */
  0x95, 0x02,        /*     Report Count (2) */
  0x81, 0x02,        /*     Input (Data, Variable, Absolute) */
  0x09, 0x38,        /*     Usage (Wheel) */
  0x16, 0x00, 0x80,  /*     Logical Minimum (-32768) */
  0x26, 0xff, 0x7f,  /*     Logical Maximum (32767) */
  0x75, 0x10,        /*     Report Size (16) */
  0x95, 0x01,        /*     Report Count (1) */
  0x81, 0x06,        /*     Input (Data, Variable, Relative) */
  0x05, 0x0c,        /*     Usage Page (Consumer) */
  0x0a, 0x38, 0x02,  /*     Usage (AC Pan) */
  0x16, 0x00, 0x80,  /*     Logical Minimum (-32768) */
  0x26, 0xff, 0x7f,  /*     Logical Maximum (32767) */
  0x75, 0x10,        /*     Report Size (16) */
  0x95, 0x01,        /*     Report Count (1) */
  0x81, 0x06,        /*     Input (Data, Variable, Relative) */
  0xc0,              /*   End Collection (Physical) */
  0xc0               /* End Collection (Application) */
};

const USHORT LumenVhidReportDescriptorLength = (USHORT) sizeof(LumenVhidReportDescriptor);
