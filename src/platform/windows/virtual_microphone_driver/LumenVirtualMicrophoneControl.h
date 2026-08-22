/**
 * @file LumenVirtualMicrophoneControl.h
 * @brief Kernel control-device declarations for the virtual microphone FIFO.
 */

#ifndef LUMEN_VIRTUAL_MICROPHONE_CONTROL_H
#define LUMEN_VIRTUAL_MICROPHONE_CONTROL_H

#include <ntddk.h>

#include "../virtual_microphone_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize the LocalSystem-only control device and bounded PCM FIFO. */
NTSTATUS LumenVirtualMicrophoneControlInitialize(PDRIVER_OBJECT driver_object);
/** Tear down the symbolic link, control device, and PCM storage. */
void LumenVirtualMicrophoneControlShutdown(void);

/**
 * Test whether a WDM dispatch target is the secured microphone control device.
 *
 * @param device_object Candidate WDM device object.
 * @return TRUE only for the control device created by this module.
 */
BOOLEAN LumenVirtualMicrophoneControlOwnsDevice(PDEVICE_OBJECT device_object);

/**
 * Read frames for a future WaveRT capture stream, padding underflow with silence.
 *
 * @param output Destination for signed 16-bit mono PCM.
 * @param frame_count Exact number of frames requested by WaveRT.
 * @return Number of queued frames copied before silence padding.
 */
size_t LumenVirtualMicrophoneControlReadFrames(int16_t *output, size_t frame_count);

/** Dispatch CREATE and CLOSE requests for the control device. */
DRIVER_DISPATCH LumenVirtualMicrophoneControlCreateClose;
/** Release an owned writer lease when its file handle is cleaned up. */
DRIVER_DISPATCH LumenVirtualMicrophoneControlCleanup;
/** Dispatch the five METHOD_BUFFERED control ABI operations. */
DRIVER_DISPATCH LumenVirtualMicrophoneControlDeviceControl;
/** Reject unsupported IRP major functions. */
DRIVER_DISPATCH LumenVirtualMicrophoneControlUnsupported;

#ifdef __cplusplus
}
#endif

#endif /* LUMEN_VIRTUAL_MICROPHONE_CONTROL_H */
