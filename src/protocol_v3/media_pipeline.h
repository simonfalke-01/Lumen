/**
 * @file src/protocol_v3/media_pipeline.h
 * @brief Per-session protocol-v3 media packetization and input routing.
 */

#pragma once

#include "quic_server.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>

namespace lumen::protocol_v3::media {
  inline constexpr std::uint32_t maximum_deadline_miss_microseconds = 1'000'000;  ///< Wire/reporting bound.

  /** @brief Exact negotiated Opus tuple used by audio or microphone media. */
  struct OpusTuple {
    std::uint32_t sample_rate {48'000};  ///< Negotiated sample rate.
    std::uint16_t frame_samples {960};  ///< Integral samples in one Opus frame.
    std::uint8_t channels {2};  ///< Negotiated channel count.
    std::uint8_t layout {1};  ///< Protocol layout identifier.
    std::uint8_t streams {1};  ///< Opus stream count.
    std::uint8_t coupled_streams {1};  ///< Opus coupled-stream count.
    std::array<std::uint8_t, 8> mapping {0, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  ///< Exact channel map.
    std::uint32_t bitrate_bps {128'000};  ///< Selected encoder bitrate.
  };

  /** @brief Exact selected static mastering and content-light metadata. */
  struct StaticHDRMetadata {
    std::array<std::uint16_t, 6> display_primaries {};  ///< R/G/B x/y code values.
    std::array<std::uint16_t, 2> white_point {};  ///< White-point x/y code values.
    std::uint32_t maximum_mastering_luminance {};  ///< 0.0001-nit units.
    std::uint32_t minimum_mastering_luminance {};  ///< 0.0001-nit units.
    std::uint16_t maximum_content_light_level {};  ///< MaxCLL in nits.
    std::uint16_t maximum_frame_average_light_level {};  ///< MaxFALL in nits.
  };

  /** @brief Immutable media policy selected by one successful START. */
  struct NegotiatedMediaConfig {
    std::array<std::uint8_t, 16> session_id {};  ///< Active v3 session identifier.
    quic_server::Profile profile {quic_server::Profile::quality};  ///< Per-session transport mode.
    std::uint16_t semantic_datagram_bytes {quic_server::maximum_semantic_datagram_bytes};  ///< Current send cap.
    std::uint32_t video_bitrate_kbps {100'000};  ///< Negotiated per-session bitrate.
    std::uint32_t width {1920};  ///< Selected even capture width.
    std::uint32_t height {1080};  ///< Selected even capture height.
    std::uint32_t refresh_numerator {60};  ///< Selected rational refresh numerator.
    std::uint32_t refresh_denominator {1};  ///< Selected rational refresh denominator.
    std::uint8_t codec_id {1};  ///< 1 H.264, 2 HEVC, or 3 AV1.
    std::uint8_t matrix_code {1};  ///< Selected H.273 matrix code.
    std::uint8_t bit_depth {8};  ///< Selected bit depth.
    std::uint8_t chroma_layout {1};  ///< 1 4:2:0, 2 4:4:4, or 3 RGB.
    std::uint8_t primaries {1};  ///< Selected H.273 primaries code.
    std::uint8_t transfer {1};  ///< 1 SDR, 2 PQ, or 3 HLG.
    std::uint8_t range {};  ///< 0 limited or 1 full.
    std::uint8_t codec_flags {};  ///< RFI and host-lossless proof flags.
    std::uint8_t fidelity {1};  ///< Lossy, visually lossless, or codec lossless.
    std::optional<StaticHDRMetadata> static_hdr_metadata;  ///< Exact selected static HDR metadata.
    std::uint32_t video_generation {1};  ///< Acknowledged video configuration.
    std::uint32_t audio_generation {1};  ///< Acknowledged audio configuration.
    std::uint32_t microphone_generation {1};  ///< Acknowledged microphone configuration.
    std::uint32_t input_generation {1};  ///< Current input authority generation.
    OpusTuple audio;  ///< Host-audio tuple.
    bool host_audio {};  ///< Whether captured audio also remains audible on the host.
    OpusTuple microphone {.channels = 1, .coupled_streams = 0, .mapping = {0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, .bitrate_bps = 64'000};  ///< Client microphone tuple.
    bool microphone_enabled {};  ///< Whether channel 4 was negotiated.
    bool fec_enabled {};  ///< Must remain false in protocol-v3 phase one.
  };

  /** @brief Completed encoder access unit at the v3 packetizer boundary. */
  struct EncodedVideoFrame {
    std::uint64_t frame_id {};  ///< Nonzero display access-unit identifier.
    std::uint64_t capture_time_microseconds {};  ///< Host monotonic capture time.
    std::optional<std::uint32_t> encoder_submit_delta_microseconds;  ///< Capture-to-submit delta, or unavailable.
    std::uint32_t encoder_complete_delta_microseconds {};  ///< Capture-to-complete delta.
    std::uint64_t applied_input_state_sequence {};  ///< Causal input watermark at capture submit.
    std::uint64_t applied_input_edge_id {};  ///< Causal edge watermark at capture submit.
    std::shared_ptr<const void> storage;  ///< Stable encoded access-unit owner retained through QUIC completion.
    std::span<const std::uint8_t> bytes;  ///< Complete encoded elementary-stream access unit within `storage`.
    std::function<void()> request_recovery;  ///< Nonblocking IDR/RFI request after asynchronous transport cancellation.
    bool key_frame {};  ///< Whether the frame is independently decodable.
    bool discardable {};  ///< Whether loss may discard this frame without reference damage.
    bool static_hdr_metadata {};  ///< Whether acknowledged static HDR metadata applies.
  };

  /** @brief One encoded host-audio packet at the v3 packetizer boundary. */
  struct EncodedAudioPacket {
    std::uint64_t capture_time_microseconds {};  ///< Host monotonic capture time.
    std::uint64_t first_sample_position {};  ///< Exact 48 kHz first-sample position.
    std::span<const std::uint8_t> opus;  ///< One Opus packet; may be empty for DTX or END.
    bool dtx {};  ///< Packet represents codec DTX.
    bool discontinuity {};  ///< Decoder state discontinuity.
    bool end {};  ///< Final packet of the generation.
  };

  /** @brief Validated complete input state and edge batch. */
  struct InputBatch {
    std::uint64_t state_sequence {};  ///< ULM3 object identifier.
    std::uint64_t sample_time_microseconds {};  ///< Client-local sample time.
    std::uint64_t newest_edge_id {};  ///< Highest represented edge identifier.
    std::span<const std::uint8_t> state_block;  ///< Complete format-two state block.
    std::span<const std::uint8_t> edge_records;  ///< Zero or more format-two edge records.
  };

  /** @brief Validated microphone packet using the negotiated exact tuple. */
  struct MicrophonePacket {
    std::uint64_t capture_time_microseconds {};  ///< Client monotonic capture time.
    std::uint64_t first_sample_position {};  ///< Exact first-sample position.
    std::uint32_t generation {};  ///< Acknowledged microphone generation.
    std::uint8_t flags {};  ///< DTX, discontinuity, and END flags.
    std::span<const std::uint8_t> opus;  ///< One Opus packet, possibly empty for DTX/END.
  };

  /** @brief Validated video feedback from the client decoder. */
  struct VideoFeedback {
    std::uint64_t affected_frame_id {};  ///< ULM3 object identifier.
    std::uint64_t last_reassembled_frame_id {};  ///< Latest completely reassembled frame.
    std::uint64_t last_decoded_frame_id {};  ///< Latest successfully decoded frame.
    std::uint8_t action {};  ///< Complete, loss, decode failure, IDR, or RFI.
    std::uint32_t deadline_miss_microseconds {};  ///< Client presentation deadline miss.
    std::span<const std::uint8_t> loss_ranges;  ///< Exact sorted four-byte loss ranges.
  };

  /** @brief Host-to-client input acknowledgement carrying the capture watermark. */
  struct InputAcknowledgement {
    std::uint64_t host_receive_time_microseconds {};  ///< Host receive timestamp.
    std::uint64_t applied_state_sequence {};  ///< Newest continuous state applied.
    std::uint64_t applied_edge_id {};  ///< Highest contiguous edge applied.
    std::uint64_t received_edge_bitmap {};  ///< Prior received-edge bitmap.
    std::uint64_t captured_frame_id {};  ///< Newest captured frame carrying the watermark.
  };

  /** @brief Host input resynchronization request. */
  struct InputResynchronization {
    std::uint64_t object_id {};  ///< Latest accepted state sequence.
    std::uint64_t expected_edge_id {};  ///< Expected next edge identifier.
    std::uint8_t reason {};  ///< Edge pressure, host reset, or authority transfer.
  };

  /** @brief Authenticated host controller-output command for one live controller instance. */
  struct ControllerFeedback {
    std::uint32_t input_generation {};  ///< Current input authority generation.
    std::uint32_t controller_generation {};  ///< Nonzero instance generation for the controller slot.
    std::uint8_t controller_id {};  ///< Client-relative controller identifier, 0...15.
    std::uint8_t command {};  ///< Rumble, trigger rumble, motion rate, LED, or adaptive triggers.
    std::uint16_t low_frequency {};  ///< Main low-frequency or left-trigger motor strength.
    std::uint16_t high_frequency {};  ///< Main high-frequency or right-trigger motor strength.
    std::uint16_t report_rate_hz {};  ///< Requested motion sampling rate; zero disables it.
    std::uint8_t motion_type {};  ///< Moonlight acceleration or gyroscope type.
    std::uint8_t red {};  ///< RGB LED red channel.
    std::uint8_t green {};  ///< RGB LED green channel.
    std::uint8_t blue {};  ///< RGB LED blue channel.
    std::uint8_t adaptive_flags {};  ///< DualSense left/right effect-valid flags.
    std::uint8_t adaptive_left_type {};  ///< DualSense left effect type.
    std::uint8_t adaptive_right_type {};  ///< DualSense right effect type.
    std::array<std::uint8_t, 10> adaptive_left {};  ///< Exact left effect payload.
    std::array<std::uint8_t, 10> adaptive_right {};  ///< Exact right effect payload.
  };

  /** @brief Typed media publication result. */
  enum class PublishResult {
    accepted,  ///< Every record was accepted by the transport queue.
    detached,  ///< Media remains active while no connection authority is bound.
    stopped,  ///< Session is terminal and rejects new media.
    invalid,  ///< Input violated the negotiated tuple or generation.
    path_too_small,  ///< Current path cannot carry the negotiated semantic record.
    backpressured,  ///< Bounded transport admission rejected the publication.
  };

  /** @brief Typed incoming DATAGRAM routing result. */
  enum class ReceiveResult {
    accepted,  ///< Record was validated and synchronously consumed.
    ignored,  ///< Stale generation or post-stop record was ignored.
    malformed,  ///< Kind-specific payload validation failed.
    forbidden,  ///< Record conflicts with negotiated permissions or tuple.
  };

  /** @brief Connection-local QUIC enqueue and negotiated-policy boundary. */
  class TransportSink {
  public:
    virtual ~TransportSink() = default;
    virtual bool update_policy(
      std::uint64_t connection_id,
      quic_server::Profile profile,
      std::uint64_t video_bitrate_kbps
    ) noexcept = 0;
    virtual quic_server::EnqueueResult enqueue(
      std::uint64_t connection_id,
      quic_server::Packet packet
    ) = 0;
    virtual quic_server::EnqueueResult enqueue_video_frame(
      std::uint64_t connection_id,
      std::shared_ptr<const quic_server::LazyVideoFrame> frame
    ) = 0;
  };

  /** @brief Synchronous host input consumer; implementations retain no spans. */
  class InputSink {
  public:
    virtual ~InputSink() = default;
    virtual bool submit(const InputBatch &batch) = 0;
    virtual void reset() noexcept = 0;
  };

  /** @brief Synchronous host virtual-microphone consumer; implementations retain no spans. */
  class MicrophoneSink {
  public:
    virtual ~MicrophoneSink() = default;
    virtual bool submit(const MicrophonePacket &packet) = 0;
    virtual void stop() noexcept = 0;
  };

  /** @brief Synchronous encoder recovery-feedback consumer. */
  class VideoFeedbackSink {
  public:
    virtual ~VideoFeedbackSink() = default;
    virtual void submit(const VideoFeedback &feedback) = 0;
  };

  /** @brief Bounded live telemetry and causal watermark snapshot. */
  struct TelemetrySnapshot {
    std::uint64_t video_frames {};  ///< Published encoded video frames.
    std::uint64_t video_fragments {};  ///< Published video fragments.
    std::uint64_t audio_packets {};  ///< Published host-audio packets.
    std::uint64_t input_batches {};  ///< Applied client input batches.
    std::uint64_t microphone_packets {};  ///< Applied microphone packets.
    std::uint64_t feedback_packets {};  ///< Consumed video feedback packets.
    std::uint64_t deadline_samples {};  ///< Complete/decode-failure feedback carrying deadline evidence.
    std::uint64_t deadline_misses {};  ///< Deadline samples with a positive miss.
    std::uint64_t consecutive_deadline_misses {};  ///< Current positive-miss run.
    std::uint32_t latest_deadline_miss_microseconds {};  ///< Latest complete/failure miss, including zero.
    std::uint32_t peak_deadline_miss_microseconds {};  ///< Largest bounded miss observed.
    std::uint64_t backpressure_drops {};  ///< Rejected bounded publications.
    std::uint64_t latest_input_state {};  ///< Latest applied input watermark.
    std::uint64_t latest_input_edge {};  ///< Latest applied edge watermark.
    std::uint64_t latest_captured_frame {};  ///< Latest frame carrying those watermarks.
  };

  /**
   * @brief One START-owned v3 media generation.
   *
   * The object owns no capture, encoder, audio device, or application. Their
   * production owners call the publication methods and synchronously consume
   * routed input. `stop()` is an idempotent barrier against later callbacks.
   */
  class SessionPipeline {
  public:
    SessionPipeline(
      NegotiatedMediaConfig config,
      TransportSink &transport,
      InputSink &input,
      MicrophoneSink &microphone,
      VideoFeedbackSink &feedback
    );

    /** @brief Bind the authenticated QUIC connection and install its policy. */
    bool bind_connection(std::uint64_t connection_id) noexcept;

    /** @brief Detach transport routing without stopping capture/media ownership. */
    void detach_connection() noexcept;

    /** @brief Update the live QUIC DATAGRAM send maximum after migration. */
    void update_datagram_maximum(std::uint16_t maximum_bytes) noexcept;

    /** @brief Fragment and publish one completed encoder access unit. */
    PublishResult submit_video(const EncodedVideoFrame &frame);

    /** @brief Frame and publish one host Opus packet. */
    PublishResult submit_audio(const EncodedAudioPacket &packet);

    /** @brief Publish one input acknowledgement. */
    PublishResult submit_input_acknowledgement(const InputAcknowledgement &acknowledgement);

    /** @brief Publish one input resynchronization request. */
    PublishResult submit_input_resynchronization(const InputResynchronization &request);

    /** @brief Publish one controller feedback command from the production platform queue. */
    PublishResult submit_controller_feedback(const ControllerFeedback &feedback);

    /** @brief Validate and synchronously route one client DATAGRAM. */
    ReceiveResult receive(const quic_server::DatagramRecord &record);

    /** @brief Stop routing, neutralize input, and stop microphone consumption once. */
    void stop() noexcept;

    /** @brief Return bounded counters and the latest causal watermark. */
    TelemetrySnapshot snapshot() const noexcept;

    /** @brief Return the immutable START selection. */
    const NegotiatedMediaConfig &config() const noexcept;

  private:
    struct ReplayWindow {
      bool permits(std::uint64_t sequence) const noexcept;
      void commit(std::uint64_t sequence) noexcept;
      void reset() noexcept;
      std::array<std::uint64_t, 16> bitmap {};
      std::uint64_t highest {};
      bool initialized {};
    };

    PublishResult publish(
      quic_server::Lane lane,
      std::uint8_t channel,
      std::uint8_t kind,
      std::uint8_t flags,
      std::uint64_t sequence,
      std::uint64_t object_id,
      std::span<const std::uint8_t> payload,
      bool replaceable
    );

    NegotiatedMediaConfig config_;
    TransportSink &transport_;
    InputSink &input_;
    MicrophoneSink &microphone_;
    VideoFeedbackSink &feedback_;
    mutable std::mutex mutex_;
    std::uint64_t connection_id_ {};
    std::uint16_t datagram_maximum_ {};
    std::uint64_t next_video_sequence_ {1};
    std::uint64_t next_audio_sequence_ {1};
    std::uint64_t next_input_sequence_ {1};
    std::uint64_t highest_input_state_object_ {};
    std::uint64_t highest_input_edge_id_ {};
    ReplayWindow input_receive_window_;
    ReplayWindow microphone_receive_window_;
    ReplayWindow feedback_receive_window_;
    bool running_ {true};
    TelemetrySnapshot telemetry_;
  };
}  // namespace lumen::protocol_v3::media
