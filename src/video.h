/**
 * @file src/video.h
 * @brief Declarations for video.
 */
#pragma once

// standard includes
#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// local includes
#include "encoder_probe_cache.h"
#include "input.h"
#include "platform/common.h"
#include "stream_policy.h"
#include "thread_safe.h"
#include "video_colorspace.h"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
}

struct AVPacket;

namespace platf::virtual_display {
  class frame_source_t;
}

namespace video {

  class egress_queue_t;
  using input_watermark_t = std::pair<std::uint64_t, std::uint64_t>;  ///< Applied state and edge sampled at capture acquisition.

  /**
   * @brief Encoding configuration requested by a remote client.
   */
  struct config_t {
    int width;  ///< Video width in pixels.
    int height;  ///< Video height in pixels.
    int framerate;  ///< Requested framerate used in the per-frame bitrate budget.
    int framerateX100;  ///< Optional NTSC-style framerate value, e.g. 59.94 as 5994.
    int bitrate;  ///< Video bitrate in kilobits for the requested framerate.
    int slicesPerFrame;  ///< Number of slices per frame.
    int numRefFrames;  ///< Maximum number of reference frames.
    int encoderCscMode;  ///< Requested color range and SDR colorspace; HDR always uses BT.2020 and ST2084.
    int videoFormat;  ///< Video codec format: 0 = H.264, 1 = HEVC, 2 = AV1.
    int dynamicRange;  ///< Encoding color depth: 0 = 8-bit, 1 = 10-bit.
    int chromaSamplingType;  ///< Chroma sampling type: 0 = 4:2:0, 1 = 4:4:4.
    int enableIntraRefresh;  ///< Intra refresh setting: 0 = disabled, 1 = enabled.
    std::string output_name;  ///< Per-session capture output, or empty for the configured default.
    std::shared_ptr<const stream_policy::EffectiveStreamPolicy> optimization_policy;  ///< Immutable resolved session policy.
    stream_policy::ClientProtocol client_protocol {stream_policy::ClientProtocol::vanilla};  ///< Exact negotiated client family.
    bool virtual_display_active {};  ///< An exact Lumen VDD generation owns `output_name` for this session.
    bool virtual_display_direct_required {};  ///< Reject capture if the active VDD direct-frame path cannot stay healthy.
    std::uint64_t virtual_display_generation {};  ///< Exact active VDD generation retained across direct-source failure.
    bool virtual_display_desktop_fallback_permitted {};  ///< Whether optional SDR may publish fallback after DDA/WGC succeeds.
    std::shared_ptr<platf::virtual_display::frame_source_t> virtual_display_frame_source;  ///< Production VDD direct-frame source, or empty for DDA/WGC.
    std::function<std::pair<std::uint64_t, std::uint64_t>()> capture_input_watermark;  ///< Applied input watermark sampled at capture submission.
  };

  namespace amf {

    /**
     * @brief Enumerates supported coder options for the AMF encoder.
     */
    enum class coder_e : int {
      auto_ = 0,  ///< Select the coder based on the H.264 profile.
      cabac = 1,  ///< CABAC entropy coding.
      cavlc = 2,  ///< CAVLC entropy coding.
    };

  }  // namespace amf

  /**
   * @brief Select the effective FFmpeg H.264 profile for an encoder configuration.
   *
   * @param encoder_name FFmpeg encoder name selected for the stream.
   * @param config Encoding configuration requested by the remote client.
   * @param amd_coder Configured AMF entropy-coder value.
   * @return FFmpeg H.264 profile applied to the codec context.
   */
  int select_h264_profile(std::string_view encoder_name, const config_t &config, int amd_coder);

  /**
   * @brief Map an FFmpeg hardware device type to Sunshine's memory type.
   *
   * @param type FFmpeg hardware device type reported by the encoder backend.
   * @return Sunshine memory type used by the capture and encode pipeline.
   */
  platf::mem_type_e map_base_dev_type(AVHWDeviceType type);
  /**
   * @brief Map an FFmpeg pixel format to Sunshine's pixel format enum.
   *
   * @param fmt FFmpeg pixel format to convert.
   * @return Sunshine pixel format used by display and encoder backends.
   */
  platf::pix_fmt_e map_pix_fmt(AVPixelFormat fmt);

  /**
   * @brief Release an FFmpeg codec context.
   *
   * @param ctx Codec context allocated by FFmpeg.
   */
  void free_ctx(AVCodecContext *ctx);
  /**
   * @brief Release an FFmpeg frame allocated by the capture or conversion backend.
   *
   * @param frame Video or graphics frame being processed.
   */
  void free_frame(AVFrame *frame);
  /**
   * @brief Release a backend buffer allocated for capture or conversion.
   *
   * @param ref FFmpeg buffer reference to unref and free.
   */
  void free_buffer(AVBufferRef *ref);

  /**
   * @brief Owning pointer for an FFmpeg codec context.
   */
  using avcodec_ctx_t = util::safe_ptr<AVCodecContext, free_ctx>;
  /**
   * @brief Owning pointer for an FFmpeg frame.
   */
  using avcodec_frame_t = util::safe_ptr<AVFrame, free_frame>;
  /**
   * @brief Owning pointer for an FFmpeg buffer reference.
   */
  using avcodec_buffer_t = util::safe_ptr<AVBufferRef, free_buffer>;
  /**
   * @brief Owning pointer for an FFmpeg software-scaling context.
   */
  using sws_t = util::safe_ptr<SwsContext, sws_freeContext>;

  /**
   * @brief Per-session capture envelope preserving the input watermark at submission.
   */
  struct captured_frame_t {
    std::shared_ptr<platf::img_t> image;  ///< Captured image shared with the encoder.
    std::uint64_t applied_input_state_sequence {};  ///< State watermark sampled at capture submission.
    std::uint64_t applied_input_edge_id {};  ///< Edge watermark sampled at capture submission.
  };

  /** @brief Shared event transporting per-session capture envelopes to encode threads. */
  using img_event_t = std::shared_ptr<safe::event_t<captured_frame_t>>;

  /**
   * @brief FFmpeg software encode device used when no hardware frames are required.
   */
  class avcodec_software_encode_device_t: public platf::avcodec_encode_device_t {
  public:
    /**
     * @brief Convert a captured image into the encoder input representation.
     *
     * @param img Image or frame object to read from or populate.
     * @return Conversion status.
     */
    int convert(platf::img_t &img) override;

    /**
     * @brief Attach frame resources used by the next conversion or encode operation.
     * @note Takes ownership of `in_frame`.
     *
     * @param in_frame Video or graphics frame being processed.
     * @param hw_frames_ctx FFmpeg hardware frames context associated with the frame.
     * @return Status from updating frame.
     */
    int set_frame(AVFrame *in_frame, AVBufferRef *hw_frames_ctx) override;

    /**
     * @brief Apply the configured colorspace metadata to the active frame.
     */
    void apply_colorspace() override;

    /**
     * @brief Initialize FFmpeg software encoding for the requested codec.
     *
     * @param in_width Input width.
     * @param in_height Input height.
     * @param in_frame Video or graphics frame being processed.
     * @param format Pixel format used by the encoder.
     * @param hardware Whether the frame is backed by hardware resources.
     * @return 0 on success; nonzero or negative platform status on failure.
     */
    int init(int in_width, int in_height, AVFrame *in_frame, AVPixelFormat format, bool hardware);

  private:
    /**
     * @brief Fill aspect-ratio padding in the destination frame with black pixels.
     */
    void prefill();

    /**
     * @brief Recreate the software scaler for the given source format.
     *
     * @param src_format Pixel format of the captured frames.
     * @return 0 on success; nonzero on failure.
     */
    int reinit_sws(AVPixelFormat src_format);

    avcodec_frame_t hw_frame;  ///< Owning frame reference when the encoder uses hardware frames.
    avcodec_frame_t sw_frame;  ///< Software frame used as the conversion destination.
    avcodec_frame_t sws_input_frame;  ///< Software scaler input frame.
    avcodec_frame_t sws_output_frame;  ///< Software scaler output frame.
    sws_t sws;  ///< Software scaler used for CPU-side pixel conversion.
    AVPixelFormat sws_src_format {AV_PIX_FMT_BGR0};  ///< Source format used to initialize the scaler.
    int offsetW;  ///< Horizontal destination offset in pixels.
    int offsetH;  ///< Vertical destination offset in pixels.
  };

  /**
   * @brief Pixel formats supported by one encoder backend.
   */
  struct encoder_platform_formats_t {
    virtual ~encoder_platform_formats_t() = default;
    platf::mem_type_e dev_type;  ///< Platform memory type required by this encoder.
    platf::pix_fmt_e pix_fmt_8bit;  ///< 8-bit 4:2:0 input format accepted by this encoder.
    platf::pix_fmt_e pix_fmt_10bit;  ///< 10-bit 4:2:0 input format accepted by this encoder.
    platf::pix_fmt_e pix_fmt_yuv444_8bit;  ///< 8-bit 4:4:4 input format accepted by this encoder.
    platf::pix_fmt_e pix_fmt_yuv444_10bit;  ///< 10-bit 4:4:4 input format accepted by this encoder.
  };

  /**
   * @brief AVCodec-specific pixel formats supported by a platform.
   */
  struct encoder_platform_formats_avcodec: encoder_platform_formats_t {
    /**
     * @brief Callback that prepares an FFmpeg hardware input buffer for the encode device.
     */
    using init_buffer_function_t = std::function<util::Either<avcodec_buffer_t, int>(platf::avcodec_encode_device_t *)>;

    /**
     * @brief Construct AVCodec platform format mappings.
     *
     * @param avcodec_base_dev_type Base AVCodec hardware device type.
     * @param avcodec_derived_dev_type Derived AVCodec hardware device type.
     * @param avcodec_dev_pix_fmt AVCodec device pixel format.
     * @param avcodec_pix_fmt_8bit AVCodec 8-bit pixel format.
     * @param avcodec_pix_fmt_10bit AVCodec 10-bit pixel format.
     * @param avcodec_pix_fmt_yuv444_8bit AVCodec 8-bit YUV444 pixel format.
     * @param avcodec_pix_fmt_yuv444_10bit AVCodec 10-bit YUV444 pixel format.
     * @param init_avcodec_hardware_input_buffer_function Hardware input buffer initialization callback.
     */
    encoder_platform_formats_avcodec(
      const AVHWDeviceType &avcodec_base_dev_type,
      const AVHWDeviceType &avcodec_derived_dev_type,
      const AVPixelFormat &avcodec_dev_pix_fmt,
      const AVPixelFormat &avcodec_pix_fmt_8bit,
      const AVPixelFormat &avcodec_pix_fmt_10bit,
      const AVPixelFormat &avcodec_pix_fmt_yuv444_8bit,
      const AVPixelFormat &avcodec_pix_fmt_yuv444_10bit,
      const init_buffer_function_t &init_avcodec_hardware_input_buffer_function
    ):
        avcodec_base_dev_type {avcodec_base_dev_type},
        avcodec_derived_dev_type {avcodec_derived_dev_type},
        avcodec_dev_pix_fmt {avcodec_dev_pix_fmt},
        avcodec_pix_fmt_8bit {avcodec_pix_fmt_8bit},
        avcodec_pix_fmt_10bit {avcodec_pix_fmt_10bit},
        avcodec_pix_fmt_yuv444_8bit {avcodec_pix_fmt_yuv444_8bit},
        avcodec_pix_fmt_yuv444_10bit {avcodec_pix_fmt_yuv444_10bit},
        init_avcodec_hardware_input_buffer {init_avcodec_hardware_input_buffer_function} {
      dev_type = map_base_dev_type(avcodec_base_dev_type);
      pix_fmt_8bit = map_pix_fmt(avcodec_pix_fmt_8bit);
      pix_fmt_10bit = map_pix_fmt(avcodec_pix_fmt_10bit);
      pix_fmt_yuv444_8bit = map_pix_fmt(avcodec_pix_fmt_yuv444_8bit);
      pix_fmt_yuv444_10bit = map_pix_fmt(avcodec_pix_fmt_yuv444_10bit);
    }

    AVHWDeviceType avcodec_base_dev_type;  ///< FFmpeg device type used to create the primary hardware context.
    AVHWDeviceType avcodec_derived_dev_type;  ///< FFmpeg device type derived from the primary hardware context.
    AVPixelFormat avcodec_dev_pix_fmt;  ///< FFmpeg hardware-device pixel format for frames handed to the encoder.
    AVPixelFormat avcodec_pix_fmt_8bit;  ///< FFmpeg 8-bit 4:2:0 software pixel format for this encoder.
    AVPixelFormat avcodec_pix_fmt_10bit;  ///< FFmpeg 10-bit 4:2:0 software pixel format for this encoder.
    AVPixelFormat avcodec_pix_fmt_yuv444_8bit;  ///< FFmpeg 8-bit 4:4:4 software pixel format for this encoder.
    AVPixelFormat avcodec_pix_fmt_yuv444_10bit;  ///< FFmpeg 10-bit 4:4:4 software pixel format for this encoder.

    init_buffer_function_t init_avcodec_hardware_input_buffer;  ///< Backend hook that allocates or imports hardware frames for FFmpeg.
  };

  /**
   * @brief NVENC-specific pixel formats supported by a platform.
   */
  struct encoder_platform_formats_nvenc: encoder_platform_formats_t {
    /**
     * @brief Construct NVENC platform format mappings.
     *
     * @param dev_type Platform memory type.
     * @param pix_fmt_8bit Platform 8-bit pixel format.
     * @param pix_fmt_10bit Platform 10-bit pixel format.
     * @param pix_fmt_yuv444_8bit Platform 8-bit YUV444 pixel format.
     * @param pix_fmt_yuv444_10bit Platform 10-bit YUV444 pixel format.
     */
    encoder_platform_formats_nvenc(
      const platf::mem_type_e &dev_type,
      const platf::pix_fmt_e &pix_fmt_8bit,
      const platf::pix_fmt_e &pix_fmt_10bit,
      const platf::pix_fmt_e &pix_fmt_yuv444_8bit,
      const platf::pix_fmt_e &pix_fmt_yuv444_10bit
    ) {
      encoder_platform_formats_t::dev_type = dev_type;
      encoder_platform_formats_t::pix_fmt_8bit = pix_fmt_8bit;
      encoder_platform_formats_t::pix_fmt_10bit = pix_fmt_10bit;
      encoder_platform_formats_t::pix_fmt_yuv444_8bit = pix_fmt_yuv444_8bit;
      encoder_platform_formats_t::pix_fmt_yuv444_10bit = pix_fmt_yuv444_10bit;
    }
  };

  /**
   * @brief Encoder name and feature flags advertised by Sunshine.
   */
  struct encoder_t {
    std::string_view name;  ///< Encoder name used in logs, configuration, and capability probes.

    /**
     * @brief Capability flags that describe which stream modes an encoder supports.
     */
    enum flag_e {
      PASSED,  ///< Indicates the encoder is supported.
      REF_FRAMES_RESTRICT,  ///< Set maximum reference frames.
      DYNAMIC_RANGE,  ///< HDR support.
      YUV444,  ///< YUV 4:4:4 support.
      DYNAMIC_RANGE_YUV444,  ///< YUV 4:4:4 HDR support.
      VUI_PARAMETERS,  ///< AMD encoder with VAAPI doesn't add VUI parameters to SPS.
      MAX_FLAGS  ///< Maximum number of flags.
    };

    /**
     * @brief Convert an encoder capability flag to its diagnostic string.
     *
     * @param flag Feature flag to name.
     * @return Stable string used in logs and probe output.
     */
    static std::string_view from_flag(flag_e flag) {
#ifndef DOXYGEN
  #define _CONVERT(x) \
    case flag_e::x: \
      return std::string_view(#x)
#endif
      switch (flag) {
        _CONVERT(PASSED);
        _CONVERT(REF_FRAMES_RESTRICT);
        _CONVERT(DYNAMIC_RANGE);
        _CONVERT(YUV444);
        _CONVERT(DYNAMIC_RANGE_YUV444);
        _CONVERT(VUI_PARAMETERS);
        _CONVERT(MAX_FLAGS);
      }
#undef _CONVERT

      return {"unknown"};
    }

    /**
     * @brief Runtime encoder option exposed to configuration parsing.
     */
    struct option_t {
      KITTY_DEFAULT_CONSTR_MOVE(option_t)
      /**
       * @brief Copy an encoder option descriptor.
       */
      option_t(const option_t &) = default;

      std::string name;  ///< Encoder command-line option name.
      std::variant<int, int *, std::optional<int> *, std::function<int()>, std::string, std::string *, std::function<const std::string(const config_t &)>> value;  ///< Literal, pointer, or callback that supplies the option value.

      /**
       * @brief Store a named encoder option and its value source.
       *
       * @param name Human-readable name to assign.
       * @param value Literal value, pointer, or callback used to resolve the option.
       */
      option_t(std::string &&name, decltype(value) &&value):
          name {std::move(name)},
          value {std::move(value)} {
      }
    };

    const std::unique_ptr<const encoder_platform_formats_t> platform_formats;  ///< Platform-specific memory and pixel formats accepted by the encoder.

    /**
     * @brief Codec capabilities for AV1, HEVC, or H.264.
     */
    struct codec_t {
      std::vector<option_t> common_options;  ///< Options applied to every encode mode for this codec.
      std::vector<option_t> sdr_options;  ///< Options applied to SDR 4:2:0 streams.
      std::vector<option_t> hdr_options;  ///< Options applied to HDR 4:2:0 streams.
      std::vector<option_t> sdr444_options;  ///< Options applied to SDR 4:4:4 streams.
      std::vector<option_t> hdr444_options;  ///< Options applied to HDR 4:4:4 streams.
      std::vector<option_t> fallback_options;  ///< Options used when the preferred mode cannot be selected.

      std::string name;  ///< Codec name passed to the encoder backend.
      std::bitset<MAX_FLAGS> capabilities;  ///< Capability flags supported by this codec on the encoder.

      /**
       * @brief Test whether a codec capability is enabled.
       *
       * @param flag Feature flag to test or modify.
       * @return True when the requested video flag is set.
       */
      bool operator[](flag_e flag) const {
        return capabilities[(std::size_t) flag];
      }

      /**
       * @brief Return a mutable reference to a codec capability flag.
       *
       * @param flag Feature flag to test or modify.
       * @return Mutable bitset reference for the requested capability.
       */
      std::bitset<MAX_FLAGS>::reference operator[](flag_e flag) {
        return capabilities[(std::size_t) flag];
      }
    };

    codec_t av1;  ///< AV1 codec capability and option set.
    codec_t hevc;  ///< HEVC codec capability and option set.
    codec_t h264;  ///< H.264 codec capability and option set.

    /**
     * @brief Select the codec descriptor requested by a stream configuration.
     *
     * @param config Configuration values to apply.
     * @return Codec descriptor for H.264, HEVC, or AV1.
     */
    const codec_t &codec_from_config(const config_t &config) const {
      switch (config.videoFormat) {
        default:
          BOOST_LOG(error) << "Unknown video format " << config.videoFormat << ", falling back to H.264";
          // fallthrough
        case 0:
          return h264;
        case 1:
          return hevc;
        case 2:
          return av1;
      }
    }

    uint32_t flags;  ///< Encoder flags advertised to clients through GameStream capability responses.
  };

  /**
   * @brief Encoder session state shared by capture and encoding threads.
   */
  struct encode_session_t {
    virtual ~encode_session_t() = default;

    /**
     * @brief Convert a captured frame into the encoder's required input representation.
     *
     * @param img Captured image supplied by the platform display backend.
     * @return Zero when the frame was converted or imported successfully.
     */
    virtual int convert(platf::img_t &img) = 0;

    /**
     * @brief Mark the frame as a request for an IDR frame.
     */
    virtual void request_idr_frame() = 0;

    /**
     * @brief Mark the frame as a request for a normal inter frame.
     */
    virtual void request_normal_frame() = 0;

    /**
     * @brief Mark the frame range whose references must be invalidated.
     *
     * @param first_frame First frame.
     * @param last_frame Last frame.
     */
    virtual void invalidate_ref_frames(int64_t first_frame, int64_t last_frame) = 0;

    /**
     * @brief Attempt reference invalidation without ever converting failure into an IDR request.
     *
     * @param first_frame First lost frame.
     * @param last_frame Last lost frame.
     * @return True only when native reference invalidation was accepted.
     */
    virtual bool try_invalidate_ref_frames_without_idr(int64_t first_frame, int64_t last_frame) = 0;

    /**
     * @brief Apply a new LSP encoder target at the next frame boundary without requesting IDR.
     *
     * @param bits_per_second Positive encoded source-media target.
     * @return True only when the active encoder accepted the new rate.
     */
    virtual bool reconfigure_bitrate(std::uint32_t bits_per_second) = 0;
  };

  // encoders
  extern encoder_t software;

#if !defined(__APPLE__)
  extern encoder_t nvenc;  // available for windows and linux
#endif

#ifdef _WIN32
  extern encoder_t amdvce;
  extern encoder_t quicksync;
  extern encoder_t mediafoundation;
#endif

#if defined(__linux__) || defined(linux) || defined(__linux) || defined(__FreeBSD__)
  extern encoder_t vaapi;
#endif

#ifdef __APPLE__
  extern encoder_t videotoolbox;
#endif

  /**
   * @brief Encoded packet wrapper used by the streaming pipeline.
   */
  struct packet_raw_t {
    virtual ~packet_raw_t() = default;

    /**
     * @brief Report whether this packet starts an IDR frame.
     *
     * @return True when this frame is an IDR frame.
     */
    virtual bool is_idr() = 0;

    /**
     * @brief Return the frame index associated with this encoded packet.
     *
     * @return Monotonic frame index assigned to this frame.
     */
    virtual int64_t frame_index() = 0;

    /**
     * @brief Return writable access to the encoded packet bytes.
     *
     * @return Pointer to the first byte of encoded frame data.
     */
    virtual uint8_t *data() = 0;

    /**
     * @brief Return the encoded payload length.
     *
     * @return Size of the encoded frame payload in bytes.
     */
    virtual size_t data_size() = 0;

    /**
     * @brief Packet byte-range replacement descriptor.
     */
    struct replace_t {
      std::string_view old;  ///< Byte sequence to find in the encoded packet.
      std::string_view _new;  ///< Byte sequence that replaces `old` before transmission.

      KITTY_DEFAULT_CONSTR_MOVE(replace_t)

      /**
       * @brief Store an encoded-byte replacement rule.
       *
       * @param old Byte sequence to replace in encoded packets.
       * @param _new Replacement byte sequence inserted into encoded packets.
       */
      replace_t(std::string_view old, std::string_view _new) noexcept:
          old {std::move(old)},
          _new {std::move(_new)} {
      }
    };

    std::vector<replace_t> *replacements = nullptr;  ///< Optional encoded-byte substitutions applied before packetization.
    void *channel_data = nullptr;  ///< Platform or protocol state carried with this packet.
    bool after_ref_frame_invalidation = false;  ///< Whether the frame follows reference-frame invalidation.
    std::uint64_t reference_invalidation_generation = 0;  ///< Exact accepted LSP invalidation generation, or zero.
    std::optional<std::chrono::steady_clock::time_point> frame_timestamp;  ///< Capture timestamp associated with the frame.
    std::optional<std::chrono::steady_clock::time_point> encoder_submit_timestamp;  ///< Actual encoder submission time.
    std::uint64_t applied_input_state_sequence {};  ///< Input state watermark sampled at capture submission.
    std::uint64_t applied_input_edge_id {};  ///< Input edge watermark sampled at capture submission.
  };

  /** @brief Generation-qualified local encoder reference-invalidation request. */
  struct reference_invalidation_request_t {
    std::uint64_t generation {};  ///< Nonzero sender-local request generation.
    std::int64_t first_frame {};  ///< First encoder frame index to invalidate.
    std::int64_t last_frame {};  ///< Last encoder frame index to invalidate.
  };

  /** @brief Terminal result for one local encoder reference-invalidation request. */
  struct reference_invalidation_result_t {
    std::uint64_t generation {};  ///< Exact request generation being completed.
    std::int64_t first_frame {};  ///< First requested encoder frame index.
    std::int64_t last_frame {};  ///< Last requested encoder frame index.
    bool succeeded {};  ///< Whether the encoder accepted the complete invalidation range.
  };

  /**
   * @brief Match one terminal invalidation result to its exact generation and frame range.
   *
   * @param request Outstanding sender request.
   * @param result Encoder terminal result.
   * @return True only for the exact nonzero generation and unchanged inclusive range.
   */
  [[nodiscard]] constexpr bool reference_invalidation_result_matches(
    const reference_invalidation_request_t &request,
    const reference_invalidation_result_t &result
  ) noexcept {
    return request.generation != 0 && request.generation == result.generation &&
           request.first_frame == result.first_frame && request.last_frame == result.last_frame;
  }

  /**
   * @brief Merge a concurrently requested inclusive range into one not-yet-published request.
   *
   * The existing request generation is retained. Callers use this only for the single queued
   * request behind an already published generation, so replaceable mailbox delivery cannot lose
   * either range.
   *
   * @param pending Initialized queued request to extend.
   * @param first_frame Additional first inclusive frame index.
   * @param last_frame Additional last inclusive frame index.
   * @return True when the additional range was valid and merged.
   */
  [[nodiscard]] constexpr bool coalesce_reference_invalidation_range(
    reference_invalidation_request_t &pending,
    const std::int64_t first_frame,
    const std::int64_t last_frame
  ) noexcept {
    if (pending.first_frame > pending.last_frame || first_frame > last_frame) {
      return false;
    }
    pending.first_frame = std::min(pending.first_frame, first_frame);
    pending.last_frame = std::max(pending.last_frame, last_frame);
    return true;
  }

  /**
   * @brief AVCodec packet wrapper with codec-specific metadata.
   */
  struct packet_raw_avcodec: packet_raw_t {
    packet_raw_avcodec() {
      av_packet = av_packet_alloc();
    }

    ~packet_raw_avcodec() {
      av_packet_free(&this->av_packet);
    }

    /**
     * @brief Report whether the FFmpeg packet is marked as a key frame.
     *
     * @return True when this frame is an IDR frame.
     */
    bool is_idr() override {
      return av_packet->flags & AV_PKT_FLAG_KEY;
    }

    /**
     * @brief Return the FFmpeg packet PTS used as Sunshine's frame index.
     *
     * @return Monotonic frame index assigned to this frame.
     */
    int64_t frame_index() override {
      return av_packet->pts;
    }

    /**
     * @brief Return writable access to the FFmpeg packet payload.
     *
     * @return Pointer to the first encoded byte in the FFmpeg packet.
     */
    uint8_t *data() override {
      return av_packet->data;
    }

    /**
     * @brief Return the FFmpeg packet payload length.
     *
     * @return Size of the encoded frame payload in bytes.
     */
    size_t data_size() override {
      return av_packet->size;
    }

    AVPacket *av_packet;  ///< FFmpeg packet that owns encoded data and frame metadata.
  };

  /**
   * @brief Generic encoded packet bytes and metadata.
   */
  struct packet_raw_generic: packet_raw_t {
    /**
     * @brief Wrap generic encoded frame bytes in Sunshine packet metadata.
     *
     * @param frame_data Encoded frame bytes produced by a non-FFmpeg encoder.
     * @param frame_index Monotonic frame index assigned to the encoded frame.
     * @param idr Whether the packet begins an IDR frame.
     */
    packet_raw_generic(std::vector<uint8_t> &&frame_data, int64_t frame_index, bool idr):
        frame_data {std::move(frame_data)},
        index {frame_index},
        idr {idr} {
    }

    /**
     * @brief Report whether the generic packet starts an IDR frame.
     *
     * @return True when this frame is an IDR frame.
     */
    bool is_idr() override {
      return idr;
    }

    /**
     * @brief Return the stored frame index for this generic packet.
     *
     * @return Monotonic frame index assigned to this frame.
     */
    int64_t frame_index() override {
      return index;
    }

    /**
     * @brief Return writable access to the generic packet payload.
     *
     * @return Pointer to the first encoded byte in `frame_data`.
     */
    uint8_t *data() override {
      return frame_data.data();
    }

    /**
     * @brief Return the generic packet payload length.
     *
     * @return Size of the encoded frame payload in bytes.
     */
    size_t data_size() override {
      return frame_data.size();
    }

    std::vector<uint8_t> frame_data;  ///< Encoded frame bytes owned by this packet.
    int64_t index;  ///< Monotonic frame index assigned to this packet.
    bool idr;  ///< Whether the packet belongs to an IDR frame.
  };

  /**
   * @brief Owning pointer to an encoded packet abstraction.
   */
  using packet_t = std::unique_ptr<packet_raw_t>;

  /**
   * @brief Materialize one encoded access unit into caller-owned LSP frame storage.
   *
   * Required key-frame SPS/VPS substitutions are applied without allocating or changing the
   * encoder-owned packet. The output never contains legacy transport framing.
   *
   * @param packet Encoded frame and optional codec-byte replacement rules.
   * @param destination Fixed caller-owned complete-access-unit storage.
   * @param bytes_written Receives the populated leading byte count.
   * @return True only when the complete transformed access unit fits and every replacement matches.
   */
  bool materialize_lsp_access_unit(
    packet_raw_t &packet,
    std::span<std::uint8_t> destination,
    std::size_t &bytes_written
  ) noexcept;

  /**
   * @brief Raw HDR metadata fields parsed from the display backend.
   */
  struct hdr_info_raw_t {
    /**
     * @brief Initialize HDR metadata with only the enabled state.
     *
     * @param enabled Whether the feature should be enabled.
     */
    explicit hdr_info_raw_t(bool enabled):
        enabled {enabled},
        metadata {} {};
    /**
     * @brief Initialize HDR metadata with display metadata from the backend.
     *
     * @param enabled Whether the feature should be enabled.
     * @param metadata Output structure populated with HDR metadata.
     */
    explicit hdr_info_raw_t(bool enabled, const SS_HDR_METADATA &metadata):
        enabled {enabled},
        metadata {metadata} {};

    bool enabled;  ///< Whether HDR mode should be enabled.
    SS_HDR_METADATA metadata;  ///< Display HDR metadata forwarded to the encoder and client.
  };

  /**
   * @brief Owning pointer to optional HDR metadata for a captured display.
   */
  using hdr_info_t = std::unique_ptr<hdr_info_raw_t>;

  extern int active_hevc_mode;
  extern int active_av1_mode;
  extern bool last_encoder_probe_supported_ref_frames_invalidation;
  extern std::array<bool, 3> last_encoder_probe_supported_yuv444_for_codec;  // 0 - H.264, 1 - HEVC, 2 - AV1

  /**
   * @brief Return lossless support only while the committed encoder identity generation is current.
   * @param video_format 0 H.264, 1 HEVC, or 2 AV1.
   * @return True only for the final native NVENC backend and exact current adapter/output/driver identity.
   */
  [[nodiscard]] bool current_nvenc_lossless_capability(int video_format);

  /**
   * @brief Read authoritative HDR metadata from the active capture display.
   *
   * @param config Exact selected capture/codec configuration.
   * @return Host display metadata only when the active display is HDR and reports it.
   */
  [[nodiscard]] std::optional<SS_HDR_METADATA> active_hdr_metadata(const config_t &config);

  /**
   * @brief Report whether the committed active encoder backend is native NVENC.
   *
   * @return True only while the current probe generation selects NVENC.
   */
  [[nodiscard]] bool active_encoder_is_nvenc();

  /** @brief Hardware and recovery capability for one first-slice SDR codec. */
  struct lsp_sdr_encoder_capability_t {
    bool supported {};  ///< Exact codec passed the committed encoder probe.
    bool hardware {};  ///< Selected encoder is not the software fallback.
    bool verified_low_delay {};  ///< Hardware tuple passed Lumen's no-B-frame low-delay probe.
    bool reference_invalidation {};  ///< Native reference invalidation is available without forcing IDR.
  };

  /**
   * @brief Query the committed encoder proof for SDR H.264 or HEVC LSP selection.
   *
   * @param video_format Zero for H.264 or one for HEVC.
   * @return Exact committed capability; all fields false for an unsupported value or stale probe.
   */
  [[nodiscard]] lsp_sdr_encoder_capability_t active_lsp_sdr_encoder_capability(int video_format) noexcept;

  /**
   * @brief Return the exact device identity from the committed active encoder probe generation.
   * @return Frozen adapter/output/driver identity only while the chosen probe cache is current.
   */
  [[nodiscard]] std::optional<encoder_probe_device_identity_t> active_encoder_probe_device_identity();

  /**
   * @brief Extract the decoder initialization bytes from one encoded key frame.
   *
   * H.264 and HEVC return Annex-B parameter-set NAL units. AV1 returns the
   * complete low-overhead sequence-header OBU. Empty output means the key frame
   * did not contain the exact initialization required by a decoder.
   *
   * @param access_unit Encoded key-frame bytes.
   * @param video_format 0 H.264, 1 HEVC, or 2 AV1.
   * @return Bounded codec initialization bytes, or an empty vector on failure.
   */
  [[nodiscard]] std::vector<std::uint8_t> extract_codec_initialization(
    std::span<const std::uint8_t> access_unit,
    int video_format
  );

  /**
   * @brief Produce exact decoder initialization for the active encoder tuple.
   *
   * The first exact adapter/driver/output/configuration tuple performs one bounded
   * dummy-frame key-frame encode before decoder initialization is published. Repeated
   * sessions reuse only an identity-bound initialization entry and otherwise fail
   * closed, so a cache hit never creates a throwaway encoder.
   *
   * @param config Exact negotiated stream configuration.
   * @return Codec initialization bytes, or std::nullopt when probing fails.
   */
  [[nodiscard]] std::optional<std::vector<std::uint8_t>> codec_initialization(
    const config_t &config
  );

  /**
   * @brief Capture and encode video for one registered streaming session.
   *
   * @param mail Session mailbox carrying shutdown and encoder-recovery events.
   * @param config Video capture and encode configuration.
   * @param channel_data Opaque session identity stored on encoded packets.
   * @param egress Per-session scheduler receiving encoded frames.
   */
  void capture(
    safe::mail_t mail,
    config_t config,
    void *channel_data,
    egress_queue_t &egress
  );

  /**
   * @brief Validate encoder before it is used.
   *
   * @param encoder Encoder configuration or encoder instance.
   * @param expect_failure Expect failure.
   * @return True when encoder validation matches `expect_failure`.
   */
  bool validate_encoder(encoder_t &encoder, bool expect_failure);

  /**
   * @brief Probe encoders and select the preferred encoder.
   * This is called once at startup and each time a stream is launched to
   * ensure the best encoder is selected. Encoder availability can change
   * at runtime due to all sorts of things from driver updates to eGPUs.
   *
   * @warning This is only safe to call when there is no client actively streaming.
   * @return 0 when a usable encoder is selected; nonzero when probing fails.
   */
  int probe_encoders();

  // Several NTSC standard refresh rates are hardcoded here, because their
  // true rate requires a denominator of 1001. ffmpeg's av_d2q() would assume it could
  // reduce 29.97 to 2997/100 but this would be slightly wrong. We also include
  // support for 23.976 film in case someone wants to stream a film at the perfect
  // framerate.
  /**
   * @brief Convert a framerate stored as hundredths of Hz to an FFmpeg rational.
   *
   * @param framerateX100 Framerate multiplied by 100, such as 5994 for 59.94 Hz.
   * @return Rational frame rate preserving NTSC fractional rates when applicable.
   */
  inline AVRational framerateX100_to_rational(const int framerateX100) {
    if (framerateX100 % 2997 == 0) {
      // Multiples of NTSC 29.97 e.g. 59.94, 119.88
      return AVRational {(framerateX100 / 2997) * 30000, 1001};
    }
    switch (framerateX100) {
      case 2397:  // the other weird NTSC framerate, assume these want 23.976 film
      case 2398:
        return AVRational {24000, 1001};
      default:
        // any other fractional rate can be reduced by ffmpeg. Max is set to 1 << 26 based on docs:
        // "rational numbers with |num| <= 1<<26 && |den| <= 1<<26 can be recovered exactly from their double representation"
        return av_d2q((double) framerateX100 / 100.0f, 1 << 26);
    }
  }

  /**
   * @brief Requested framerate as an exact rational.
   * Uses the exact fractional rate when the client provided an X100 value,
   * otherwise the integer framerate over 1.
   *
   * @param config Stream configuration carrying the requested framerate.
   * @return Requested frame rate as a rational.
   */
  inline AVRational framerate_to_rational(const config_t &config) {
    if (config.framerateX100 > 0) {
      return framerateX100_to_rational(config.framerateX100);
    }
    return AVRational {config.framerate, 1};
  }

  /**
   * @brief Exact nominal encoded bits per frame for NVENC custom VBV sizing.
   * @param config Stream bitrate and exact refresh rational.
   * @return Floor of bitrate divided by exact refresh, saturated to uint32.
   */
  [[nodiscard]] inline std::uint32_t vbv_frame_size_bits(const config_t &config) noexcept {
    const auto fps = framerate_to_rational(config);
    if (config.bitrate <= 0 || fps.num <= 0 || fps.den <= 0) {
      return 0;
    }
    const auto scaled_bitrate = static_cast<std::uint64_t>(config.bitrate) * 1000U;
    const auto numerator = static_cast<std::uint64_t>(fps.num);
    const auto denominator = static_cast<std::uint64_t>(fps.den);
    const auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max());
    const auto whole = scaled_bitrate / numerator;
    if (whole > maximum / denominator) {
      return std::numeric_limits<std::uint32_t>::max();
    }
    const auto integral = whole * denominator;
    const auto fractional = (scaled_bitrate % numerator) * denominator / numerator;
    if (integral > maximum - fractional) {
      return std::numeric_limits<std::uint32_t>::max();
    }
    return static_cast<std::uint32_t>(integral + fractional);
  }

  /**
   * @brief Capture frame interval for the requested framerate.
   * Uses the exact fractional rate when the client provided an X100 value.
   *
   * @param config Stream configuration carrying the requested framerate.
   * @return Duration of a single frame interval in nanoseconds.
   */
  inline std::chrono::nanoseconds capture_frame_interval(const config_t &config) {
    const AVRational fps = framerate_to_rational(config);
    return std::chrono::nanoseconds {(static_cast<int64_t>(fps.den) * 1'000'000'000LL) / fps.num};
  }

  /**
   * @brief Bounded wait used to establish a new capture pacing group.
   *
   * A missed cadence must not fall back to the historical fixed 200 ms wait at
   * high refresh rates. Static-content duplication runs independently, so the
   * capture backend only needs one requested frame interval to resynchronize.
   *
   * @param numerator Requested frames-per-second numerator.
   * @param denominator Requested frames-per-second denominator.
   * @return Whole-millisecond wait clamped to 1..200 ms.
   */
  [[nodiscard]] inline std::chrono::milliseconds capture_resynchronization_timeout(
    const std::uint64_t numerator,
    const std::uint64_t denominator
  ) noexcept {
    if (numerator == 0 || denominator == 0 ||
        denominator > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / 1'000'000'000ULL) {
      return std::chrono::milliseconds {200};
    }
    const auto interval = std::chrono::nanoseconds {
      static_cast<std::int64_t>(denominator * 1'000'000'000ULL / numerator)
    };
    return std::clamp(
      std::chrono::duration_cast<std::chrono::milliseconds>(interval),
      std::chrono::milliseconds {1},
      std::chrono::milliseconds {200}
    );
  }

  /** @brief Remaining wait until an absolute target-rate encode deadline. */
  [[nodiscard]] inline std::chrono::steady_clock::duration target_encode_wait(
    const std::chrono::steady_clock::time_point deadline,
    const std::chrono::steady_clock::time_point now
  ) noexcept {
    return deadline > now ? deadline - now : std::chrono::steady_clock::duration::zero();
  }

  /**
   * @brief Advance an absolute encode deadline past completed work without drift.
   * @param deadline Prior target deadline.
   * @param interval Exact requested frame interval.
   * @param now Time after the preceding encode completed.
   * @return First target deadline strictly later than `now`.
   */
  [[nodiscard]] inline std::chrono::steady_clock::time_point advance_target_encode_deadline(
    std::chrono::steady_clock::time_point deadline,
    const std::chrono::steady_clock::duration interval,
    const std::chrono::steady_clock::time_point now
  ) noexcept {
    if (interval <= std::chrono::steady_clock::duration::zero()) {
      return now;
    }
    do {
      deadline += interval;
    } while (deadline <= now);
    return deadline;
  }

  /** @brief Capture-thread action after a backend requests display reinitialization. */
  enum class capture_reinitialization_e {
    retry,  ///< Recreate the capture display and continue the session.
    terminate  ///< End the capture because its required direct source was lost.
  };

  /**
   * @brief Decide whether a capture backend may be recreated after source loss.
   *
   * Required Lumen VDD sessions and every active HDR VDD are generation-bound.
   * Recreating their display would either spin on the stopped source or cross
   * into an invalid DDA/WGC fallback.
   *
   * @param config Active stream configuration.
   * @return Retry for ordinary/optional SDR capture, or terminate for required or active HDR VDD capture.
   */
  [[nodiscard]] constexpr capture_reinitialization_e capture_reinitialization_action(
    const config_t &config
  ) noexcept {
    const bool active_hdr_vdd = config.virtual_display_active && config.dynamicRange != 0;
    return config.virtual_display_direct_required || active_hdr_vdd ?
             capture_reinitialization_e::terminate :
             capture_reinitialization_e::retry;
  }

  /**
   * @brief Return the bounded display-open attempt count for one capture path.
   * @param config Active stream configuration.
   * @return One attempt for generation-bound required/HDR VDD capture, otherwise two.
   */
  [[nodiscard]] constexpr int display_initialization_attempts(const config_t &config) noexcept {
    return capture_reinitialization_action(config) == capture_reinitialization_e::terminate ? 1 : 2;
  }
}  // namespace video
