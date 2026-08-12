/**
 * @file HidDescriptors.h
 * @brief HID descriptors for the UMDF keyboard, mouse, and control collections.
 */

#ifndef LUMEN_VIRTUAL_HID_DESCRIPTORS_H
#define LUMEN_VIRTUAL_HID_DESCRIPTORS_H

#include <windows.h>

/** Composite NKRO keyboard, mouse, and vendor-control report descriptor. */
extern const BYTE LumenVhidReportDescriptor[];
/** Descriptor byte count returned to HIDClass. */
extern const USHORT LumenVhidReportDescriptorLength;

#endif /* LUMEN_VIRTUAL_HID_DESCRIPTORS_H */
