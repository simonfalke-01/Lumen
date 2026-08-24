/**
 * @file virtual_microphone_protocol.h
 * @brief Fixed C ABI shared by the Lumen virtual microphone driver and host.
 *
 * Copyright (C) 2026 LizardByte
 *
 * This file is part of Lumen.
 *
 * Lumen is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 */

#ifndef LUMEN_PLATFORM_WINDOWS_VIRTUAL_MICROPHONE_PROTOCOL_H
#define LUMEN_PLATFORM_WINDOWS_VIRTUAL_MICROPHONE_PROTOCOL_H

#if defined(LUMEN_VMIC_KERNEL)
  #include <ntddk.h>
typedef UINT8 lumen_vmic_uint8_t;
typedef UINT16 lumen_vmic_uint16_t;
typedef UINT32 lumen_vmic_uint32_t;
typedef UINT64 lumen_vmic_uint64_t;
typedef INT16 lumen_vmic_int16_t;
  #define LUMEN_VMIC_OFFSETOF(type, member) FIELD_OFFSET(type, member)
#else
  #include <stddef.h>
  #include <stdint.h>
typedef uint8_t lumen_vmic_uint8_t;
typedef uint16_t lumen_vmic_uint16_t;
typedef uint32_t lumen_vmic_uint32_t;
typedef uint64_t lumen_vmic_uint64_t;
typedef int16_t lumen_vmic_int16_t;
  #define LUMEN_VMIC_OFFSETOF(type, member) offsetof(type, member)
#endif

#ifndef CTL_CODE
  #define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef FILE_DEVICE_UNKNOWN
  #define FILE_DEVICE_UNKNOWN 0x00000022u
#endif
#ifndef METHOD_BUFFERED
  #define METHOD_BUFFERED 0u
#endif
#ifndef FILE_READ_DATA
  #define FILE_READ_DATA 0x0001u
#endif
#ifndef FILE_WRITE_DATA
  #define FILE_WRITE_DATA 0x0002u
#endif

#if defined(__cplusplus)
extern "C" {
#endif

/** Exact root-enumerated hardware identifier used by the driver package. */
#define LUMEN_VMIC_ROOT_HARDWARE_ID_A "ROOT\\LumenVirtualMicrophone"
/** Wide-character form of the exact root hardware identifier. */
#define LUMEN_VMIC_ROOT_HARDWARE_ID_W L"ROOT\\LumenVirtualMicrophone"
/** Narrow-character driver service and binary base name. */
#define LUMEN_VMIC_DRIVER_SERVICE_NAME_A "LumenVirtualMicrophone"
/** Wide-character driver service and binary base name. */
#define LUMEN_VMIC_DRIVER_SERVICE_NAME_W L"LumenVirtualMicrophone"
/** LocalSystem-only control device path opened by the Lumen service. */
#define LUMEN_VMIC_CONTROL_DEVICE_PATH_W L"\\\\.\\LumenVirtualMicrophone"

/** Exact driver/client ABI version. */
#define LUMEN_VMIC_ABI_VERSION 1u
/** Only PCM sample rate accepted by the driver. */
#define LUMEN_VMIC_SAMPLE_RATE_HZ 48000u
/** Only interleaved PCM channel count accepted by the driver. */
#define LUMEN_VMIC_CHANNEL_COUNT 1u
/** Only PCM sample width accepted by the driver. */
#define LUMEN_VMIC_BITS_PER_SAMPLE 16u
/** Maximum frames accepted by one buffered write operation. */
#define LUMEN_VMIC_MAX_WRITE_FRAMES 960u

/** @name SYSTEM-only METHOD_BUFFERED control codes
 * @{ */
#define IOCTL_LUMEN_VMIC_QUERY_ABI \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VMIC_OPEN_STREAM \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VMIC_WRITE_PCM \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VMIC_RESET \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_LUMEN_VMIC_QUERY_STATS \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
  /** @} */

#pragma pack(push, 4)

  /** Exact response returned by IOCTL_LUMEN_VMIC_QUERY_ABI. */
  typedef struct LUMEN_VMIC_QUERY_ABI_RESPONSE {
    lumen_vmic_uint32_t abi_version;  ///< LUMEN_VMIC_ABI_VERSION.
    lumen_vmic_uint32_t sample_rate_hz;  ///< LUMEN_VMIC_SAMPLE_RATE_HZ.
    lumen_vmic_uint16_t channel_count;  ///< LUMEN_VMIC_CHANNEL_COUNT.
    lumen_vmic_uint16_t bits_per_sample;  ///< LUMEN_VMIC_BITS_PER_SAMPLE.
    lumen_vmic_uint32_t max_write_frames;  ///< LUMEN_VMIC_MAX_WRITE_FRAMES.
  } LUMEN_VMIC_QUERY_ABI_RESPONSE;

  /** Exact input accepted by IOCTL_LUMEN_VMIC_OPEN_STREAM. */
  typedef struct LUMEN_VMIC_OPEN_STREAM_REQUEST {
    lumen_vmic_uint64_t requested_generation;  ///< Non-secret generation selected by the host.
    lumen_vmic_uint32_t sample_rate_hz;  ///< Must be LUMEN_VMIC_SAMPLE_RATE_HZ.
    lumen_vmic_uint16_t channel_count;  ///< Must be LUMEN_VMIC_CHANNEL_COUNT.
    lumen_vmic_uint16_t bits_per_sample;  ///< Must be LUMEN_VMIC_BITS_PER_SAMPLE.
  } LUMEN_VMIC_OPEN_STREAM_REQUEST;

  /** Exact fixed-size input accepted by IOCTL_LUMEN_VMIC_WRITE_PCM. */
  typedef struct LUMEN_VMIC_WRITE_PCM_REQUEST {
    lumen_vmic_uint64_t generation;  ///< Active stream generation.
    lumen_vmic_uint32_t frame_count;  ///< Valid mono samples in the trailing array.
    lumen_vmic_int16_t samples[LUMEN_VMIC_MAX_WRITE_FRAMES];  ///< Signed little-endian mono PCM.
  } LUMEN_VMIC_WRITE_PCM_REQUEST;

  /** Exact input accepted by IOCTL_LUMEN_VMIC_RESET. */
  typedef struct LUMEN_VMIC_RESET_REQUEST {
    lumen_vmic_uint64_t generation;  ///< Active stream generation being reset.
  } LUMEN_VMIC_RESET_REQUEST;

  /** Exact response returned by IOCTL_LUMEN_VMIC_QUERY_STATS. */
  typedef struct LUMEN_VMIC_QUERY_STATS_RESPONSE {
    lumen_vmic_uint64_t generation;  ///< Active generation, or zero when no stream is open.
    lumen_vmic_uint64_t accepted_frames;  ///< PCM frames admitted to the bounded FIFO.
    lumen_vmic_uint64_t stale_writes;  ///< Writes rejected for a generation mismatch.
    lumen_vmic_uint64_t overflow_drops;  ///< Oldest frames discarded to preserve live latency.
    lumen_vmic_uint64_t underflow_samples;  ///< Silence samples emitted while the FIFO was empty.
    lumen_vmic_uint64_t resets;  ///< Completed FIFO and generation resets.
    lumen_vmic_uint32_t current_fill_frames;  ///< Frames currently buffered for capture.
    lumen_vmic_uint32_t capacity_frames;  ///< Maximum bounded FIFO capacity in frames.
  } LUMEN_VMIC_QUERY_STATS_RESPONSE;

#pragma pack(pop)

/** Byte count preceding samples in the fixed-size write request. */
#define LUMEN_VMIC_WRITE_PCM_HEADER_SIZE 12u
/** Maximum byte count accepted by IOCTL_LUMEN_VMIC_WRITE_PCM. */
#define LUMEN_VMIC_MAX_WRITE_PCM_REQUEST_SIZE sizeof(LUMEN_VMIC_WRITE_PCM_REQUEST)

#define LUMEN_VMIC_STATIC_ASSERT(expression, name) \
  typedef char lumen_vmic_static_assert_##name[(expression) ? 1 : -1]

  LUMEN_VMIC_STATIC_ASSERT(sizeof(LUMEN_VMIC_QUERY_ABI_RESPONSE) == 16, query_abi_response_size);
  LUMEN_VMIC_STATIC_ASSERT(LUMEN_VMIC_OFFSETOF(LUMEN_VMIC_QUERY_ABI_RESPONSE, max_write_frames) == 12, max_write_frames_offset);
  LUMEN_VMIC_STATIC_ASSERT(sizeof(LUMEN_VMIC_OPEN_STREAM_REQUEST) == 16, open_stream_request_size);
  LUMEN_VMIC_STATIC_ASSERT(LUMEN_VMIC_OFFSETOF(LUMEN_VMIC_OPEN_STREAM_REQUEST, sample_rate_hz) == 8, open_stream_format_offset);
  LUMEN_VMIC_STATIC_ASSERT(
    LUMEN_VMIC_OFFSETOF(LUMEN_VMIC_WRITE_PCM_REQUEST, samples) == LUMEN_VMIC_WRITE_PCM_HEADER_SIZE,
    write_pcm_header_size
  );
  LUMEN_VMIC_STATIC_ASSERT(sizeof(LUMEN_VMIC_WRITE_PCM_REQUEST) == 1932, write_pcm_request_size);
  LUMEN_VMIC_STATIC_ASSERT(sizeof(LUMEN_VMIC_RESET_REQUEST) == 8, reset_request_size);
  LUMEN_VMIC_STATIC_ASSERT(sizeof(LUMEN_VMIC_QUERY_STATS_RESPONSE) == 56, query_stats_response_size);
  LUMEN_VMIC_STATIC_ASSERT(LUMEN_VMIC_OFFSETOF(LUMEN_VMIC_QUERY_STATS_RESPONSE, current_fill_frames) == 48, current_fill_offset);
  LUMEN_VMIC_STATIC_ASSERT((IOCTL_LUMEN_VMIC_QUERY_ABI & 3u) == METHOD_BUFFERED, query_abi_ioctl_buffered);
  LUMEN_VMIC_STATIC_ASSERT((IOCTL_LUMEN_VMIC_OPEN_STREAM & 3u) == METHOD_BUFFERED, open_stream_ioctl_buffered);
  LUMEN_VMIC_STATIC_ASSERT((IOCTL_LUMEN_VMIC_WRITE_PCM & 3u) == METHOD_BUFFERED, write_pcm_ioctl_buffered);
  LUMEN_VMIC_STATIC_ASSERT((IOCTL_LUMEN_VMIC_RESET & 3u) == METHOD_BUFFERED, reset_ioctl_buffered);
  LUMEN_VMIC_STATIC_ASSERT((IOCTL_LUMEN_VMIC_QUERY_STATS & 3u) == METHOD_BUFFERED, query_stats_ioctl_buffered);

#undef LUMEN_VMIC_STATIC_ASSERT
#undef LUMEN_VMIC_OFFSETOF

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* LUMEN_PLATFORM_WINDOWS_VIRTUAL_MICROPHONE_PROTOCOL_H */
