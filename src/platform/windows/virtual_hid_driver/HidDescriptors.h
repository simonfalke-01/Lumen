/**
 * @file HidDescriptors.h
 * @brief HID descriptor for the keyboard, mouse, and Consumer Control collections.
 */

#ifndef LUMEN_VIRTUAL_HID_DESCRIPTORS_H
#define LUMEN_VIRTUAL_HID_DESCRIPTORS_H

#include <windows.h>

/** Composite NKRO keyboard, relative mouse, and Consumer Control report descriptor. */
extern const BYTE LumenVhidReportDescriptor[];
/** Descriptor byte count supplied to VHF. */
extern const USHORT LumenVhidReportDescriptorLength;

#endif /* LUMEN_VIRTUAL_HID_DESCRIPTORS_H */
