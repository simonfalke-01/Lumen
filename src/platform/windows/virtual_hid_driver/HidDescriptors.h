/**
 * @file HidDescriptors.h
 * @brief HID report descriptor exported by the persistent VHF source device.
 */

#ifndef LUMEN_VIRTUAL_HID_DESCRIPTORS_H
#define LUMEN_VIRTUAL_HID_DESCRIPTORS_H

#include <ntddk.h>

/** Composite NKRO keyboard and single logical mouse report descriptor. */
extern const UCHAR LumenVhidReportDescriptor[];
/** Descriptor byte count passed to VHF_CONFIG_INIT. */
extern const USHORT LumenVhidReportDescriptorLength;

#endif /* LUMEN_VIRTUAL_HID_DESCRIPTORS_H */
