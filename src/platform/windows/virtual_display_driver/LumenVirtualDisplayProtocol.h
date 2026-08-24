/**
 * @file src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h
 * @brief Fixed C ABI shared by the Lumen IddCx driver and host service.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_PROTOCOL_H
#define LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_PROTOCOL_H

#include <stdint.h>

/** Platform-independent values used to encode the private buffered IOCTLs. */
#define LUMEN_VDD_FILE_DEVICE_VIDEO 0x00000023u
#define LUMEN_VDD_METHOD_BUFFERED 0u
#define LUMEN_VDD_FILE_READ_DATA 0x0001u
#define LUMEN_VDD_FILE_WRITE_DATA 0x0002u
#define LUMEN_VDD_CTL_CODE(DeviceType, Function, Method, Access) \
  (((DeviceType) << 16u) | ((Access) << 14u) | ((Function) << 2u) | (Method))

#if defined(__cplusplus)
extern "C" {
#endif

/** Fixed driver ABI version. */
#define LUMEN_VDD_ABI_VERSION 3u
/** Maximum supported width in the baseline SDR driver. */
#define LUMEN_VDD_MAX_WIDTH 8192u
/** Maximum supported height in the baseline SDR driver. */
#define LUMEN_VDD_MAX_HEIGHT 8192u
/** Maximum rational component accepted at the trust boundary. */
#define LUMEN_VDD_MAX_RATIONAL_COMPONENT 1000000000u
/** Driver capability: exact dynamic target-mode update. */
#define LUMEN_VDD_CAP_DYNAMIC_MODES 0x00000001u
/** Driver capability: SDR 8-bit surfaces. */
#define LUMEN_VDD_CAP_SDR8 0x00000002u
/** Driver capability: two persistent shared BGRA8 textures with per-slot D3D11 fences. */
#define LUMEN_VDD_CAP_DIRECT_FRAME_V1 0x00000004u
/** Driver capability: HDR10 through IddCx 1.10 UpdateModes2. */
#define LUMEN_VDD_CAP_HDR10 0x00000008u
/** Driver capability: 10-bit swap-chain surfaces. */
#define LUMEN_VDD_CAP_10BIT 0x00000010u
/** Driver capability: configured VDD surface format is preserved exactly. */
#define LUMEN_VDD_CAP_LOSSLESS 0x00000020u
/** Driver capability: explicit validated visually-lossless conversion. */
#define LUMEN_VDD_CAP_VISUALLY_LOSSLESS 0x00000040u

/** Dynamic range values in the fixed control ABI. */
#define LUMEN_VDD_DYNAMIC_RANGE_SDR 0u
#define LUMEN_VDD_DYNAMIC_RANGE_HDR10 1u
/** Host session policy values in the fixed control ABI. */
#define LUMEN_VDD_POLICY_LATENCY 1u
#define LUMEN_VDD_POLICY_QUALITY 2u
/** Fidelity values in the fixed control ABI. */
#define LUMEN_VDD_FIDELITY_LOSSLESS 1u
#define LUMEN_VDD_FIDELITY_VISUALLY_LOSSLESS 2u
/** Fixed number of persistent direct-frame slots. */
#define LUMEN_VDD_FRAME_SLOT_COUNT 2u
/** Direct-frame texture format: DXGI_FORMAT_B8G8R8A8_UNORM. */
#define LUMEN_VDD_FRAME_FORMAT_BGRA8 1u

/** Private IOCTL function numbers. */
#define LUMEN_VDD_IOCTL_INDEX 0x900u
#define IOCTL_LUMEN_VDD_QUERY_ABI LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 0u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA)
#define IOCTL_LUMEN_VDD_QUERY_STATE LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 1u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA)
#define IOCTL_LUMEN_VDD_PREPARE_MODE LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 2u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA | LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_START_MONITOR LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 3u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_STOP_MONITOR LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 4u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_RECOVER_STALE LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 5u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_OPEN_FRAME_CHANNEL LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 6u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA | LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_DEQUEUE_FRAME LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 7u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA | LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_RELEASE_FRAME LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 8u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_WRITE_DATA)
#define IOCTL_LUMEN_VDD_OPEN_FRAME_EVENT LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 9u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA | LUMEN_VDD_FILE_WRITE_DATA)

#pragma pack(push, 1)

  /** Exact display mode passed across the driver boundary. */
  typedef struct LUMEN_VDD_MODE {
    uint32_t width;  ///< Active width.
    uint32_t height;  ///< Active height.
    uint32_t refresh_numerator;  ///< Exact hertz numerator.
    uint32_t refresh_denominator;  ///< Exact hertz denominator.
    uint8_t dynamic_range;  ///< LUMEN_VDD_DYNAMIC_RANGE_*.
    uint8_t bits_per_channel;  ///< 8 or 10.
    uint8_t delivery_policy;  ///< LUMEN_VDD_POLICY_*.
    uint8_t minimum_fidelity;  ///< LUMEN_VDD_FIDELITY_*.
  } LUMEN_VDD_MODE;

  /** Fixed ABI and practical driver capability response. */
  typedef struct LUMEN_VDD_QUERY_ABI_RESPONSE {
    uint32_t abi_version;  ///< Must equal LUMEN_VDD_ABI_VERSION.
    uint32_t capability_flags;  ///< LUMEN_VDD_CAP_*.
    uint32_t minimum_width;  ///< Minimum even width.
    uint32_t maximum_width;  ///< Maximum even width.
    uint32_t minimum_height;  ///< Minimum even height.
    uint32_t maximum_height;  ///< Maximum even height.
    uint32_t minimum_refresh_numerator;  ///< Minimum refresh numerator.
    uint32_t minimum_refresh_denominator;  ///< Minimum refresh denominator.
    uint32_t maximum_refresh_numerator;  ///< Maximum refresh numerator.
    uint32_t maximum_refresh_denominator;  ///< Maximum refresh denominator.
    uint64_t maximum_pixels;  ///< Maximum active pixels.
    uint64_t maximum_pixel_rate;  ///< Maximum active pixels per second.
  } LUMEN_VDD_QUERY_ABI_RESPONSE;

  /** Current exclusive driver generation. */
  typedef struct LUMEN_VDD_QUERY_STATE_RESPONSE {
    uint64_t generation;  ///< Current generation or zero.
    uint32_t owner_process_id;  ///< Requestor that claimed generation.
    uint32_t monitor_started;  ///< One when present.
    LUMEN_VDD_MODE mode;  ///< Current exact mode.
    uint64_t last_generation;  ///< Highest generation admitted since driver start.
  } LUMEN_VDD_QUERY_STATE_RESPONSE;

  /** Prepare an exact mode for a new or idempotent generation. */
  typedef struct LUMEN_VDD_PREPARE_MODE_REQUEST {
    uint64_t generation;  ///< Nonzero strictly newer generation, or exact idempotent retry.
    uint32_t owner_process_id;  ///< Calling service PID.
    uint32_t reserved;  ///< Must be zero.
    LUMEN_VDD_MODE mode;  ///< Exact requested mode.
  } LUMEN_VDD_PREPARE_MODE_REQUEST;

  /** Driver-selected mode and stable connector identifier. */
  typedef struct LUMEN_VDD_PREPARE_MODE_RESPONSE {
    LUMEN_VDD_MODE mode;  ///< Exact mode exposed by IddCx.
    uint8_t fidelity;  ///< LUMEN_VDD_FIDELITY_*.
    uint8_t reserved[7];  ///< Must be zero.
    char connector_id_utf8[128];  ///< NUL-terminated stable connector ID.
  } LUMEN_VDD_PREPARE_MODE_RESPONSE;

  /** Generation-only start, stop, or recovery request. */
  typedef struct LUMEN_VDD_GENERATION_REQUEST {
    uint64_t generation;  ///< Exact generation.
  } LUMEN_VDD_GENERATION_REQUEST;

  /** Open the direct-frame channel for the exact owning process and generation. */
  typedef struct LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST {
    uint64_t generation;  ///< Exact active generation.
    uint32_t owner_process_id;  ///< Must equal the real IOCTL requestor and prepared owner.
    uint32_t reserved;  ///< Must be zero.
  } LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST;

  /** Two persistent driver-owned texture/fence pairs duplicated into the owner process. */
  typedef struct LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE {
    uint64_t generation;  ///< Exact active generation.
    uint64_t adapter_luid;  ///< Packed render-adapter LUID used by the IddCx swap chain.
    uint32_t width;  ///< Exact texture width.
    uint32_t height;  ///< Exact texture height.
    uint32_t texture_format;  ///< LUMEN_VDD_FRAME_FORMAT_*.
    uint32_t slot_count;  ///< Must equal LUMEN_VDD_FRAME_SLOT_COUNT.
    uint64_t texture_handles[LUMEN_VDD_FRAME_SLOT_COUNT];  ///< Owner-process NT handles for shared textures.
    uint64_t fence_handles[LUMEN_VDD_FRAME_SLOT_COUNT];  ///< Owner-process NT handles for shared D3D11 fences.
    uint64_t reserved[2];  ///< Must be zero.
  } LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE;

  /** Driver-published auto-reset event duplicated into the exact owner process. */
  typedef struct LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE {
    uint64_t generation;  ///< Exact active generation.
    uint64_t event_handle;  ///< Owner-process handle signaled for resource/frame availability.
    uint64_t reserved;  ///< Must be zero.
  } LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE;

  /** Nonblocking dequeue request for one exact generation. */
  typedef struct LUMEN_VDD_DEQUEUE_FRAME_REQUEST {
    uint64_t generation;  ///< Exact active generation.
  } LUMEN_VDD_DEQUEUE_FRAME_REQUEST;

  /** One driver-copied frame leased to the host until release. */
  typedef struct LUMEN_VDD_DEQUEUE_FRAME_RESPONSE {
    uint64_t generation;  ///< Exact active generation.
    uint64_t sequence;  ///< Strictly increasing nonzero frame sequence.
    uint64_t producer_fence_value;  ///< Per-slot odd fence value signaled after CopyResource.
    int64_t capture_qpc;  ///< QueryPerformanceCounter sampled after IddCx acquisition.
    int64_t producer_signal_qpc;  ///< QPC sampled after the producer fence signal was submitted.
    uint32_t slot;  ///< Slot index below LUMEN_VDD_FRAME_SLOT_COUNT.
    uint32_t reserved;  ///< Must be zero.
  } LUMEN_VDD_DEQUEUE_FRAME_RESPONSE;

  /** Release one exact leased frame after conversion and NVENC completion. */
  typedef struct LUMEN_VDD_RELEASE_FRAME_REQUEST {
    uint64_t generation;  ///< Exact active generation.
    uint64_t sequence;  ///< Exact dequeued sequence.
    uint64_t producer_fence_value;  ///< Exact producer value returned at dequeue.
    uint64_t consumer_fence_value;  ///< Must equal producer_fence_value + 1.
    uint32_t slot;  ///< Exact dequeued slot.
    uint32_t reserved;  ///< Must be zero.
  } LUMEN_VDD_RELEASE_FRAME_REQUEST;

#pragma pack(pop)

#define LUMEN_VDD_STATIC_ASSERT(expression, name) typedef char lumen_vdd_static_assert_##name[(expression) ? 1 : -1]
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_MODE) == 20, mode_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_QUERY_ABI_RESPONSE) == 56, query_abi_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_QUERY_STATE_RESPONSE) == 44, query_state_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_PREPARE_MODE_REQUEST) == 36, prepare_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_PREPARE_MODE_RESPONSE) == 156, prepare_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_GENERATION_REQUEST) == 8, generation_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST) == 16, open_frame_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE) == 80, open_frame_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE) == 24, open_frame_event_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_DEQUEUE_FRAME_REQUEST) == 8, dequeue_frame_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_DEQUEUE_FRAME_RESPONSE) == 48, dequeue_frame_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_RELEASE_FRAME_REQUEST) == 40, release_frame_request_size);
  LUMEN_VDD_STATIC_ASSERT((IOCTL_LUMEN_VDD_PREPARE_MODE & 3u) == LUMEN_VDD_METHOD_BUFFERED, prepare_is_buffered);
#undef LUMEN_VDD_STATIC_ASSERT

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_PROTOCOL_H */
