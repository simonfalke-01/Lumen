/**
 * @file LumenVirtualMicrophoneControl.c
 * @brief LocalSystem-only WDM control device and synchronized PCM transport.
 */

#include "LumenVirtualMicrophoneControl.h"

#include "LumenPcmRing.h"

#include <wdmsec.h>

/** Pool tag "LVMc" used for the FIFO allocation. */
#define LUMEN_VMIC_POOL_TAG 'cMVL'
/** Bounded 200 ms FIFO capacity at the fixed 48 kHz sample rate. */
#define LUMEN_VMIC_FIFO_CAPACITY_FRAMES 9600u

/** Per-control-device state stored in the WDM device extension. */
typedef struct LUMEN_VMIC_DEVICE_EXTENSION {
  KSPIN_LOCK lock;  ///< Serializes ownership, generation, FIFO, and counters.
  PFILE_OBJECT owner_file;  ///< Exact file object holding the writer lease.
  lumen_vmic_uint64_t generation;  ///< Active caller-selected generation, or zero.
  lumen_vmic_uint64_t stale_writes;  ///< Saturating count of stale WRITE_PCM attempts.
  lumen_pcm_int16_t *fifo_storage;  ///< Nonpaged backing storage for the PCM FIFO.
  LUMEN_PCM_RING fifo;  ///< Bounded, newest-data-wins PCM FIFO.
} LUMEN_VMIC_DEVICE_EXTENSION;

/** Single control device used by both the writer ABI and WaveRT stream. */
static PDEVICE_OBJECT g_lumen_vmic_control_device = NULL;

/** Kernel device name. */
static UNICODE_STRING g_lumen_vmic_device_name = RTL_CONSTANT_STRING(L"\\Device\\LumenVirtualMicrophoneControl");
/** Stable user-mode path exposed as \\.\LumenVirtualMicrophone. */
static UNICODE_STRING g_lumen_vmic_symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\Global\\LumenVirtualMicrophone");
/** LocalSystem-only discretionary ACL. */
static UNICODE_STRING g_lumen_vmic_sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)");
/** Device-class GUID passed to IoCreateDeviceSecure. */
static const GUID g_lumen_vmic_control_class = {
  0x4fe067ea,
  0x8ec2,
  0x42fc,
  {0x82, 0x7b, 0x14, 0x84, 0xf0, 0xd4, 0x21, 0x0e}
};

/**
 * Saturating increment for stale-write accounting.
 *
 * @param extension Device state protected by extension->lock.
 */
static void LumenVirtualMicrophoneCountStaleWrite(LUMEN_VMIC_DEVICE_EXTENSION *extension) {
  if (extension->stale_writes != UINT64_MAX) {
    ++extension->stale_writes;
  }
}

/**
 * Complete an IRP synchronously.
 *
 * @param irp IRP to complete.
 * @param status Completion status.
 * @param information Bytes returned to the caller.
 * @return status.
 */
static NTSTATUS LumenVirtualMicrophoneComplete(PIRP irp, NTSTATUS status, ULONG_PTR information) {
  irp->IoStatus.Status = status;
  irp->IoStatus.Information = information;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return status;
}

/**
 * Validate exact writer ownership and generation while holding the spin lock.
 *
 * @param extension Locked device state.
 * @param file_object Requesting file object.
 * @param generation Generation supplied by the caller.
 * @return STATUS_SUCCESS when the lease matches, or STATUS_REVISION_MISMATCH.
 */
static NTSTATUS LumenVirtualMicrophoneValidateOwner(
  const LUMEN_VMIC_DEVICE_EXTENSION *extension,
  PFILE_OBJECT file_object,
  lumen_vmic_uint64_t generation
) {
  if (extension->owner_file == NULL || extension->owner_file != file_object || generation == 0u ||
      generation != extension->generation) {
    return STATUS_REVISION_MISMATCH;
  }
  return STATUS_SUCCESS;
}

/**
 * Return the immutable protocol and PCM format.
 *
 * @param buffer METHOD_BUFFERED system buffer.
 * @param input_length Caller input length.
 * @param output_length Caller output length.
 * @param information Receives response byte count.
 * @return Operation status.
 */
static NTSTATUS LumenVirtualMicrophoneQueryAbi(
  void *buffer,
  ULONG input_length,
  ULONG output_length,
  ULONG_PTR *information
) {
  LUMEN_VMIC_QUERY_ABI_RESPONSE response;

  if (buffer == NULL || input_length != 0u || output_length != sizeof(response)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  response.abi_version = LUMEN_VMIC_ABI_VERSION;
  response.sample_rate_hz = LUMEN_VMIC_SAMPLE_RATE_HZ;
  response.channel_count = LUMEN_VMIC_CHANNEL_COUNT;
  response.bits_per_sample = LUMEN_VMIC_BITS_PER_SAMPLE;
  response.max_write_frames = LUMEN_VMIC_MAX_WRITE_FRAMES;
  RtlCopyMemory(buffer, &response, sizeof(response));
  *information = sizeof(response);
  return STATUS_SUCCESS;
}

/**
 * Open the exclusive writer stream while holding the state lock.
 *
 * Repeating OPEN_STREAM with the same file, generation, and format is
 * idempotent. Every other attempt while occupied returns STATUS_DEVICE_BUSY.
 * A newly opened stream never inherits PCM from a prior owner.
 *
 * @param extension Locked device state.
 * @param file_object Requesting file object.
 * @param buffer METHOD_BUFFERED input buffer.
 * @param input_length Caller input length.
 * @param output_length Caller output length.
 * @return Operation status.
 */
static NTSTATUS LumenVirtualMicrophoneOpenStream(
  LUMEN_VMIC_DEVICE_EXTENSION *extension,
  PFILE_OBJECT file_object,
  const void *buffer,
  ULONG input_length,
  ULONG output_length
) {
  LUMEN_VMIC_OPEN_STREAM_REQUEST request;

  if (buffer == NULL || input_length != sizeof(request) || output_length != 0u) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  RtlCopyMemory(&request, buffer, sizeof(request));
  if (request.requested_generation == 0u || request.sample_rate_hz != LUMEN_VMIC_SAMPLE_RATE_HZ ||
      request.channel_count != LUMEN_VMIC_CHANNEL_COUNT || request.bits_per_sample != LUMEN_VMIC_BITS_PER_SAMPLE) {
    return STATUS_INVALID_PARAMETER;
  }
  if (extension->owner_file != NULL) {
    if (extension->owner_file == file_object && extension->generation == request.requested_generation) {
      return STATUS_SUCCESS;
    }
    return STATUS_DEVICE_BUSY;
  }

  LumenPcmRingClear(&extension->fifo);
  extension->owner_file = file_object;
  extension->generation = request.requested_generation;
  return STATUS_SUCCESS;
}

/**
 * Write one bounded PCM packet while holding the state lock.
 *
 * @param extension Locked device state.
 * @param file_object Requesting file object.
 * @param buffer METHOD_BUFFERED request buffer.
 * @param input_length Exact fixed request byte count.
 * @param output_length Caller output length.
 * @return Operation status.
 */
static NTSTATUS LumenVirtualMicrophoneWritePcm(
  LUMEN_VMIC_DEVICE_EXTENSION *extension,
  PFILE_OBJECT file_object,
  const void *buffer,
  ULONG input_length,
  ULONG output_length
) {
  const LUMEN_VMIC_WRITE_PCM_REQUEST *request;
  NTSTATUS status;

  if (buffer == NULL || input_length != sizeof(*request) || output_length != 0u) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  request = (const LUMEN_VMIC_WRITE_PCM_REQUEST *) buffer;
  status = LumenVirtualMicrophoneValidateOwner(extension, file_object, request->generation);
  if (!NT_SUCCESS(status)) {
    LumenVirtualMicrophoneCountStaleWrite(extension);
    return status;
  }
  if (request->frame_count == 0u || request->frame_count > LUMEN_VMIC_MAX_WRITE_FRAMES) {
    return STATUS_INVALID_PARAMETER;
  }
  if (LumenPcmRingSubmit(&extension->fifo, request->samples, request->frame_count) != request->frame_count) {
    return STATUS_INTERNAL_ERROR;
  }
  return STATUS_SUCCESS;
}

/**
 * Empty queued PCM while retaining the writer lease and generation.
 *
 * @param extension Locked device state.
 * @param file_object Requesting file object.
 * @param buffer METHOD_BUFFERED request buffer.
 * @param input_length Exact request byte count.
 * @param output_length Caller output length.
 * @return Operation status.
 */
static NTSTATUS LumenVirtualMicrophoneReset(
  LUMEN_VMIC_DEVICE_EXTENSION *extension,
  PFILE_OBJECT file_object,
  const void *buffer,
  ULONG input_length,
  ULONG output_length
) {
  LUMEN_VMIC_RESET_REQUEST request;
  NTSTATUS status;

  if (buffer == NULL || input_length != sizeof(request) || output_length != 0u) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  RtlCopyMemory(&request, buffer, sizeof(request));
  status = LumenVirtualMicrophoneValidateOwner(extension, file_object, request.generation);
  if (!NT_SUCCESS(status)) {
    return status;
  }
  LumenPcmRingReset(&extension->fifo);
  return STATUS_SUCCESS;
}

/**
 * Return FIFO and lifetime counters while holding the state lock.
 *
 * @param extension Locked device state.
 * @param buffer METHOD_BUFFERED system buffer.
 * @param input_length Caller input length.
 * @param output_length Caller output length.
 * @param information Receives response byte count.
 * @return Operation status.
 */
static NTSTATUS LumenVirtualMicrophoneQueryStats(
  const LUMEN_VMIC_DEVICE_EXTENSION *extension,
  void *buffer,
  ULONG input_length,
  ULONG output_length,
  ULONG_PTR *information
) {
  LUMEN_VMIC_QUERY_STATS_RESPONSE response;

  if (buffer == NULL || input_length != 0u || output_length != sizeof(response)) {
    return STATUS_INVALID_BUFFER_SIZE;
  }
  response.generation = extension->owner_file != NULL ? extension->generation : 0u;
  response.accepted_frames = extension->fifo.counters.submitted_frames;
  response.stale_writes = extension->stale_writes;
  response.overflow_drops = extension->fifo.counters.dropped_frames;
  response.underflow_samples = extension->fifo.counters.silence_frames;
  response.resets = extension->fifo.counters.reset_count;
  response.current_fill_frames = (lumen_vmic_uint32_t) extension->fifo.queued_frames;
  response.capacity_frames = (lumen_vmic_uint32_t) extension->fifo.capacity_frames;
  RtlCopyMemory(buffer, &response, sizeof(response));
  *information = sizeof(response);
  return STATUS_SUCCESS;
}

NTSTATUS LumenVirtualMicrophoneControlCreateClose(PDEVICE_OBJECT device_object, PIRP irp) {
  UNREFERENCED_PARAMETER(device_object);
  return LumenVirtualMicrophoneComplete(irp, STATUS_SUCCESS, 0u);
}

NTSTATUS LumenVirtualMicrophoneControlCleanup(PDEVICE_OBJECT device_object, PIRP irp) {
  LUMEN_VMIC_DEVICE_EXTENSION *extension = (LUMEN_VMIC_DEVICE_EXTENSION *) device_object->DeviceExtension;
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  KIRQL old_irql;

  KeAcquireSpinLock(&extension->lock, &old_irql);
  if (extension->owner_file == stack->FileObject) {
    LumenPcmRingReset(&extension->fifo);
    extension->owner_file = NULL;
    extension->generation = 0u;
  }
  KeReleaseSpinLock(&extension->lock, old_irql);
  return LumenVirtualMicrophoneComplete(irp, STATUS_SUCCESS, 0u);
}

NTSTATUS LumenVirtualMicrophoneControlDeviceControl(PDEVICE_OBJECT device_object, PIRP irp) {
  LUMEN_VMIC_DEVICE_EXTENSION *extension = (LUMEN_VMIC_DEVICE_EXTENSION *) device_object->DeviceExtension;
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
  void *buffer = irp->AssociatedIrp.SystemBuffer;
  const ULONG input_length = stack->Parameters.DeviceIoControl.InputBufferLength;
  const ULONG output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;
  ULONG_PTR information = 0u;
  KIRQL old_irql;
  NTSTATUS status;

  KeAcquireSpinLock(&extension->lock, &old_irql);
  switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_LUMEN_VMIC_QUERY_ABI:
      status = LumenVirtualMicrophoneQueryAbi(buffer, input_length, output_length, &information);
      break;

    case IOCTL_LUMEN_VMIC_OPEN_STREAM:
      status = LumenVirtualMicrophoneOpenStream(extension, stack->FileObject, buffer, input_length, output_length);
      break;

    case IOCTL_LUMEN_VMIC_WRITE_PCM:
      status = LumenVirtualMicrophoneWritePcm(extension, stack->FileObject, buffer, input_length, output_length);
      break;

    case IOCTL_LUMEN_VMIC_RESET:
      status = LumenVirtualMicrophoneReset(extension, stack->FileObject, buffer, input_length, output_length);
      break;

    case IOCTL_LUMEN_VMIC_QUERY_STATS:
      status = LumenVirtualMicrophoneQueryStats(extension, buffer, input_length, output_length, &information);
      break;

    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
  }
  KeReleaseSpinLock(&extension->lock, old_irql);
  return LumenVirtualMicrophoneComplete(irp, status, NT_SUCCESS(status) ? information : 0u);
}

NTSTATUS LumenVirtualMicrophoneControlUnsupported(PDEVICE_OBJECT device_object, PIRP irp) {
  UNREFERENCED_PARAMETER(device_object);
  return LumenVirtualMicrophoneComplete(irp, STATUS_INVALID_DEVICE_REQUEST, 0u);
}

lumen_pcm_size_t LumenVirtualMicrophoneControlReadFrames(
  lumen_vmic_int16_t *output,
  lumen_pcm_size_t frame_count
) {
  LUMEN_VMIC_DEVICE_EXTENSION *extension;
  KIRQL old_irql;
  lumen_pcm_size_t copied_frames;

  if (g_lumen_vmic_control_device == NULL || output == NULL || frame_count == 0u) {
    return 0u;
  }
  extension = (LUMEN_VMIC_DEVICE_EXTENSION *) g_lumen_vmic_control_device->DeviceExtension;
  KeAcquireSpinLock(&extension->lock, &old_irql);
  copied_frames = LumenPcmRingRead(&extension->fifo, output, frame_count);
  KeReleaseSpinLock(&extension->lock, old_irql);
  return copied_frames;
}

NTSTATUS LumenVirtualMicrophoneControlInitialize(PDRIVER_OBJECT driver_object) {
  PDEVICE_OBJECT device_object = NULL;
  LUMEN_VMIC_DEVICE_EXTENSION *extension;
  const SIZE_T storage_bytes = (SIZE_T) LUMEN_VMIC_FIFO_CAPACITY_FRAMES * sizeof(lumen_vmic_int16_t);
  NTSTATUS status;

  if (driver_object == NULL || g_lumen_vmic_control_device != NULL) {
    return STATUS_INVALID_DEVICE_STATE;
  }
  status = IoCreateDeviceSecure(
    driver_object,
    sizeof(LUMEN_VMIC_DEVICE_EXTENSION),
    &g_lumen_vmic_device_name,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &g_lumen_vmic_sddl,
    &g_lumen_vmic_control_class,
    &device_object
  );
  if (!NT_SUCCESS(status)) {
    return status;
  }

  extension = (LUMEN_VMIC_DEVICE_EXTENSION *) device_object->DeviceExtension;
  RtlZeroMemory(extension, sizeof(*extension));
  KeInitializeSpinLock(&extension->lock);
  extension->fifo_storage = (lumen_pcm_int16_t *) ExAllocatePool2(
    POOL_FLAG_NON_PAGED,
    storage_bytes,
    LUMEN_VMIC_POOL_TAG
  );
  if (extension->fifo_storage == NULL) {
    IoDeleteDevice(device_object);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  if (!LumenPcmRingInitialize(&extension->fifo, extension->fifo_storage, LUMEN_VMIC_FIFO_CAPACITY_FRAMES)) {
    ExFreePoolWithTag(extension->fifo_storage, LUMEN_VMIC_POOL_TAG);
    IoDeleteDevice(device_object);
    return STATUS_INTERNAL_ERROR;
  }

  device_object->Flags |= DO_BUFFERED_IO;
  status = IoCreateSymbolicLink(&g_lumen_vmic_symbolic_link, &g_lumen_vmic_device_name);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(extension->fifo_storage, LUMEN_VMIC_POOL_TAG);
    IoDeleteDevice(device_object);
    return status;
  }
  device_object->Flags &= ~DO_DEVICE_INITIALIZING;
  g_lumen_vmic_control_device = device_object;
  return STATUS_SUCCESS;
}

void LumenVirtualMicrophoneControlShutdown(void) {
  LUMEN_VMIC_DEVICE_EXTENSION *extension;
  PDEVICE_OBJECT device_object = g_lumen_vmic_control_device;

  if (device_object == NULL) {
    return;
  }
  g_lumen_vmic_control_device = NULL;
  IoDeleteSymbolicLink(&g_lumen_vmic_symbolic_link);
  extension = (LUMEN_VMIC_DEVICE_EXTENSION *) device_object->DeviceExtension;
  if (extension->fifo_storage != NULL) {
    ExFreePoolWithTag(extension->fifo_storage, LUMEN_VMIC_POOL_TAG);
    extension->fifo_storage = NULL;
  }
  IoDeleteDevice(device_object);
}

BOOLEAN LumenVirtualMicrophoneControlOwnsDevice(PDEVICE_OBJECT device_object) {
  return device_object != NULL && device_object == g_lumen_vmic_control_device;
}
