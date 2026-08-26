/**
 * @file src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h
 * @brief Fixed C ABI shared by the Lumen IddCx driver and host service.
 */
#ifndef LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_PROTOCOL_H
#define LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_PROTOCOL_H

#include "../../../protocol_common/start_mode_limits.h"

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
#define LUMEN_VDD_ABI_VERSION 5u
/** Minimum supported width shared with protocol-v3 START admission. */
#define LUMEN_VDD_MIN_WIDTH LUMEN_START_MODE_MIN_WIDTH
/** Maximum supported width shared with protocol-v3 START admission. */
#define LUMEN_VDD_MAX_WIDTH LUMEN_START_MODE_MAX_WIDTH
/** Minimum supported height shared with protocol-v3 START admission. */
#define LUMEN_VDD_MIN_HEIGHT LUMEN_START_MODE_MIN_HEIGHT
/** Maximum supported height shared with protocol-v3 START admission. */
#define LUMEN_VDD_MAX_HEIGHT LUMEN_START_MODE_MAX_HEIGHT
/** Minimum supported refresh rate shared with protocol-v3 START admission. */
#define LUMEN_VDD_MIN_REFRESH_HZ LUMEN_START_MODE_MIN_REFRESH_HZ
/** Maximum supported refresh rate shared with protocol-v3 START admission. */
#define LUMEN_VDD_MAX_REFRESH_HZ LUMEN_START_MODE_MAX_REFRESH_HZ
/** Maximum rational component accepted at the trust boundary. */
#define LUMEN_VDD_MAX_RATIONAL_COMPONENT LUMEN_START_MODE_MAX_RATIONAL_COMPONENT
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
/** Driver capability: runtime IddCx render-adapter preference submission. */
#define LUMEN_VDD_CAP_RENDER_ADAPTER_PREFERENCE 0x00000080u
/** Driver capability: shared DXGI_FORMAT_R16G16B16A16_FLOAT direct frames. */
#define LUMEN_VDD_CAP_DIRECT_FRAME_FP16 0x00000100u
/** Driver capability: resolved color-space, white-level, and HDR10 frame metadata. */
#define LUMEN_VDD_CAP_FRAME_METADATA_V2 0x00000200u
/** Driver capability: immutable versioned gamma/color-transform queries. */
#define LUMEN_VDD_CAP_COLOR_TRANSFORM_V1 0x00000400u

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
/** Direct-frame texture format: DXGI_FORMAT_R16G16B16A16_FLOAT. */
#define LUMEN_VDD_FRAME_FORMAT_RGBA16_FLOAT 2u

/** Stable surface color-space values resolved from IddCx metadata. */
#define LUMEN_VDD_COLOR_SPACE_SRGB 1u
#define LUMEN_VDD_COLOR_SPACE_SCRGB 2u
#define LUMEN_VDD_COLOR_SPACE_HDR10 3u

/** Stable HDR10 metadata source types. Metadata is resolved for every nonzero type. */
#define LUMEN_VDD_HDR_METADATA_NONE 0u
#define LUMEN_VDD_HDR_METADATA_DEFAULT 1u
#define LUMEN_VDD_HDR_METADATA_UNCHANGED 2u
#define LUMEN_VDD_HDR_METADATA_NEW 3u

/** Stable gamma-ramp payload types. */
#define LUMEN_VDD_GAMMA_RAMP_TYPE_DEFAULT 1u
#define LUMEN_VDD_GAMMA_RAMP_TYPE_RGB256X3X16 2u
#define LUMEN_VDD_GAMMA_RAMP_TYPE_3X4_COLORSPACE_TRANSFORM 3u
/** Fixed number of entries in an IddCx 3x4 color-space-transform LUT. */
#define LUMEN_VDD_COLOR_TRANSFORM_LUT_ENTRY_COUNT 4096u
/** Fixed bytes reserved for the largest immutable transform payload. */
#define LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD_SIZE 49212u

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
#define IOCTL_LUMEN_VDD_QUERY_COLOR_TRANSFORM LUMEN_VDD_CTL_CODE(LUMEN_VDD_FILE_DEVICE_VIDEO, LUMEN_VDD_IOCTL_INDEX + 10u, LUMEN_VDD_METHOD_BUFFERED, LUMEN_VDD_FILE_READ_DATA | LUMEN_VDD_FILE_WRITE_DATA)

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

  /** Exact HDR10 mastering-display and content-light metadata. */
  typedef struct LUMEN_VDD_HDR10_METADATA {
    uint16_t red_primary[2];  ///< CIE1931 red X/Y normalized to 50,000.
    uint16_t green_primary[2];  ///< CIE1931 green X/Y normalized to 50,000.
    uint16_t blue_primary[2];  ///< CIE1931 blue X/Y normalized to 50,000.
    uint16_t white_point[2];  ///< CIE1931 white X/Y normalized to 50,000.
    uint16_t maximum_mastering_luminance;  ///< Whole nits.
    uint16_t minimum_mastering_luminance;  ///< Nits normalized to 10,000.
    uint16_t maximum_content_light_level;  ///< Whole nits.
    uint16_t maximum_frame_average_light_level;  ///< Whole nits.
  } LUMEN_VDD_HDR10_METADATA;

  /** Exact legacy 256-entry per-channel gamma table. */
  typedef struct LUMEN_VDD_GAMMA_RAMP_RGB256X3X16 {
    uint16_t red[256];  ///< Red channel values.
    uint16_t green[256];  ///< Green channel values.
    uint16_t blue[256];  ///< Blue channel values.
  } LUMEN_VDD_GAMMA_RAMP_RGB256X3X16;

  /** One floating-point RGB LUT entry. */
  typedef struct LUMEN_VDD_RGB_FLOAT {
    float red;  ///< Red component.
    float green;  ///< Green component.
    float blue;  ///< Blue component.
  } LUMEN_VDD_RGB_FLOAT;

  /** Exact IddCx 3x4 matrix/scalar/LUT color transform with normalized BOOL fields. */
  typedef struct LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM {
    uint32_t matrix_enabled;  ///< Exactly zero or one.
    float color_matrix_3x4[3][4];  ///< Row-major 3x4 matrix.
    float scalar_multiplier;  ///< Scalar applied to every matrix element.
    uint32_t lut_enabled;  ///< Exactly zero or one.
    LUMEN_VDD_RGB_FLOAT lookup_table_1d[LUMEN_VDD_COLOR_TRANSFORM_LUT_ENTRY_COUNT];  ///< Exact 4096-entry LUT.
  } LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM;

  /** Fixed-size storage for any supported immutable gamma/color-transform payload. */
  typedef union LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD {
    LUMEN_VDD_GAMMA_RAMP_RGB256X3X16 rgb256x3x16;  ///< Type LUMEN_VDD_GAMMA_RAMP_TYPE_RGB256X3X16.
    LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM transform_3x4;  ///< Type LUMEN_VDD_GAMMA_RAMP_TYPE_3X4_COLORSPACE_TRANSFORM.
    uint8_t storage[LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD_SIZE];  ///< Stable fixed response extent.
  } LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD;

  /** Query one exact immutable transform version for the active generation. */
  typedef struct LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST {
    uint64_t generation;  ///< Exact active generation.
    uint64_t transform_version;  ///< Exact nonzero descriptor/open-channel version.
  } LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST;

  /** Fixed-size immutable transform response. */
  typedef struct LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE {
    uint64_t generation;  ///< Exact active generation.
    uint64_t transform_version;  ///< Exact immutable version, starting with DEFAULT version 1.
    uint32_t gamma_ramp_type;  ///< LUMEN_VDD_GAMMA_RAMP_*.
    uint32_t payload_size;  ///< Zero, 1536, or 49212 according to gamma_ramp_type.
    LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD payload;  ///< Exact copied OS payload; unused bytes are zero.
  } LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE;

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
    uint64_t preferred_render_adapter_luid;  ///< Exact packed encoder adapter requested for this generation.
    uint64_t assigned_render_adapter_luid;  ///< Exact packed adapter from the most recent swap-chain assignment.
    uint32_t render_adapter_preference_submitted;  ///< One when IddCx accepted the preference API call.
    uint32_t reserved;  ///< Must be zero.
  } LUMEN_VDD_QUERY_STATE_RESPONSE;

  /** Prepare an exact mode for a new or idempotent generation. */
  typedef struct LUMEN_VDD_PREPARE_MODE_REQUEST {
    uint64_t generation;  ///< Nonzero strictly newer generation, or exact idempotent retry.
    uint32_t owner_process_id;  ///< Calling service PID.
    uint32_t reserved;  ///< Must be zero.
    uint64_t preferred_render_adapter_luid;  ///< Nonzero packed LUID from the active encoder probe.
    LUMEN_VDD_MODE mode;  ///< Exact requested mode.
  } LUMEN_VDD_PREPARE_MODE_REQUEST;

  /** Driver-selected mode and stable connector identifier. */
  typedef struct LUMEN_VDD_PREPARE_MODE_RESPONSE {
    LUMEN_VDD_MODE mode;  ///< Exact mode exposed by IddCx.
    uint8_t fidelity;  ///< LUMEN_VDD_FIDELITY_*.
    uint8_t render_adapter_preference_submitted;  ///< One when the runtime preference API was called.
    uint8_t reserved[6];  ///< Must be zero.
    uint64_t preferred_render_adapter_luid;  ///< Exact requested packed LUID.
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

  /** Two persistent driver-owned texture/fence pairs published for authorized reverse duplication. */
  typedef struct LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE {
    uint64_t generation;  ///< Exact active generation.
    uint64_t adapter_luid;  ///< Packed render-adapter LUID used by the IddCx swap chain.
    uint32_t source_process_id;  ///< WUDFHost process that owns the raw unnamed handles.
    uint32_t source_reserved;  ///< Must be zero.
    uint64_t source_process_creation_time;  ///< Exact packed FILETIME preventing PID-reuse confusion.
    uint32_t width;  ///< Exact texture width.
    uint32_t height;  ///< Exact texture height.
    uint32_t texture_format;  ///< LUMEN_VDD_FRAME_FORMAT_*.
    uint32_t slot_count;  ///< Must equal LUMEN_VDD_FRAME_SLOT_COUNT.
    uint64_t texture_handles[LUMEN_VDD_FRAME_SLOT_COUNT];  ///< Raw WUDFHost NT handles for shared textures.
    uint64_t fence_handles[LUMEN_VDD_FRAME_SLOT_COUNT];  ///< Raw WUDFHost NT handles for shared D3D11 fences.
    uint64_t color_transform_version;  ///< Current immutable transform version, starting with DEFAULT version 1.
    uint32_t initial_surface_color_space;  ///< Initial LUMEN_VDD_COLOR_SPACE_* for encoder creation.
    uint32_t initial_sdr_white_level_nits;  ///< Initial committed IddCx SDR white level.
    uint32_t initial_hdr_metadata_type;  ///< Resolved initial LUMEN_VDD_HDR_METADATA_*.
    uint32_t initial_metadata_reserved;  ///< Must be zero.
    LUMEN_VDD_HDR10_METADATA initial_hdr10_metadata;  ///< Resolved initial/default metadata; zero for SDR.
    uint64_t reserved;  ///< Must be zero.
  } LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE;

  /** Driver-published auto-reset event exposed for authorized reverse duplication. */
  typedef struct LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE {
    uint64_t generation;  ///< Exact active generation.
    uint32_t source_process_id;  ///< WUDFHost process that owns the raw unnamed event handle.
    uint32_t source_reserved;  ///< Must be zero.
    uint64_t source_process_creation_time;  ///< Exact packed FILETIME preventing PID-reuse confusion.
    uint64_t event_handle;  ///< Raw WUDFHost handle duplicated by the authorized caller.
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
    uint64_t color_transform_version;  ///< Exact immutable transform retained by this slot lease.
    uint32_t surface_color_space;  ///< LUMEN_VDD_COLOR_SPACE_*.
    uint32_t sdr_white_level_nits;  ///< IddCx SDR white level copied for this frame.
    uint32_t hdr_metadata_type;  ///< LUMEN_VDD_HDR_METADATA_*; nonzero types carry resolved metadata.
    uint32_t metadata_reserved;  ///< Must be zero.
    LUMEN_VDD_HDR10_METADATA hdr10_metadata;  ///< Resolved effective HDR10 metadata when hdr_metadata_type is nonzero.
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
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_HDR10_METADATA) == 24, hdr10_metadata_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_GAMMA_RAMP_RGB256X3X16) == 1536, gamma_rgb256_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_RGB_FLOAT) == 12, rgb_float_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_GAMMA_RAMP_3X4_COLORSPACE_TRANSFORM) == 49212, gamma_transform_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_COLOR_TRANSFORM_PAYLOAD) == 49212, color_transform_payload_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_QUERY_COLOR_TRANSFORM_REQUEST) == 16, query_color_transform_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_QUERY_COLOR_TRANSFORM_RESPONSE) == 49236, query_color_transform_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_QUERY_ABI_RESPONSE) == 56, query_abi_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_QUERY_STATE_RESPONSE) == 68, query_state_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_PREPARE_MODE_REQUEST) == 44, prepare_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_PREPARE_MODE_RESPONSE) == 164, prepare_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_GENERATION_REQUEST) == 8, generation_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_REQUEST) == 16, open_frame_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_OPEN_FRAME_CHANNEL_RESPONSE) == 136, open_frame_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_OPEN_FRAME_EVENT_RESPONSE) == 40, open_frame_event_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_DEQUEUE_FRAME_REQUEST) == 8, dequeue_frame_request_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_DEQUEUE_FRAME_RESPONSE) == 96, dequeue_frame_response_size);
  LUMEN_VDD_STATIC_ASSERT(sizeof(LUMEN_VDD_RELEASE_FRAME_REQUEST) == 40, release_frame_request_size);
  LUMEN_VDD_STATIC_ASSERT((IOCTL_LUMEN_VDD_PREPARE_MODE & 3u) == LUMEN_VDD_METHOD_BUFFERED, prepare_is_buffered);
  LUMEN_VDD_STATIC_ASSERT((IOCTL_LUMEN_VDD_QUERY_COLOR_TRANSFORM & 3u) == LUMEN_VDD_METHOD_BUFFERED, query_color_transform_is_buffered);
#undef LUMEN_VDD_STATIC_ASSERT

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* LUMEN_PLATFORM_WINDOWS_VIRTUAL_DISPLAY_PROTOCOL_H */
