/**
 * @file src/audio.h
 * @brief Declarations for audio capture and encoding.
 */
#pragma once

// local includes
#include "platform/common.h"
#include "thread_safe.h"
#include "utility.h"

#include <atomic>
#include <bitset>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace audio {
  /**
   * @brief Supported Opus channel layouts advertised to GameStream clients.
   */
  enum stream_config_e : int {
    STEREO,  ///< Stereo
    HIGH_STEREO,  ///< High stereo
    SURROUND51,  ///< Surround 5.1
    HIGH_SURROUND51,  ///< High surround 5.1
    SURROUND71,  ///< Surround 7.1
    HIGH_SURROUND71,  ///< High surround 7.1
    MAX_STREAM_CONFIG  ///< Maximum audio stream configuration
  };

  /**
   * @brief Static Opus encoder layout for one advertised audio mode.
   */
  struct opus_stream_config_t {
    std::int32_t sampleRate;  ///< Opus sample rate in hertz.
    int channelCount;  ///< Number of audio channels in the Opus layout.
    int streams;  ///< Number of Opus streams in the layout.
    int coupledStreams;  ///< Number of stereo-coupled Opus streams.
    const std::uint8_t *mapping;  ///< Channel mapping table passed to the Opus encoder.
    int bitrate;  ///< Target bitrate in bits per second.
  };

  /**
   * @brief Custom Opus channel layout supplied by configuration.
   */
  struct stream_params_t {
    int channelCount;  ///< Number of audio channels in the Opus layout.
    int streams;  ///< Number of Opus streams in the custom layout.
    int coupledStreams;  ///< Number of stereo-coupled Opus streams.
    std::uint8_t mapping[8];  ///< Channel mapping table for up to eight speakers.
  };

  extern opus_stream_config_t stream_configs[MAX_STREAM_CONFIG];

  /**
   * @brief Audio capture and encoder settings for a stream.
   */
  struct config_t {
    /**
     * @brief Boolean audio feature flags.
     */
    enum flags_e : int {
      HIGH_QUALITY,  ///< High quality audio
      HOST_AUDIO,  ///< Host audio
      CUSTOM_SURROUND_PARAMS,  ///< Custom surround parameters
      CONTINUOUS_AUDIO,  ///< Continuous audio
      INBAND_FEC,  ///< Enable negotiated Opus in-band forward error correction.
      DTX,  ///< Enable negotiated Opus discontinuous transmission.
      MAX_FLAGS  ///< Maximum number of flags
    };

    int packetDuration;  ///< Packet duration in milliseconds requested by the client.
    int channels;  ///< Number of audio channels requested by the client.
    int mask;  ///< Speaker mask describing the requested channel layout.

    stream_params_t customStreamParams;  ///< Custom Opus layout used when CUSTOM_SURROUND_PARAMS is enabled.

    std::bitset<MAX_FLAGS> flags;  ///< Enabled audio feature flags.
    int bitrate {};  ///< Exact negotiated total Opus bitrate, or zero for legacy tier selection.
    std::uint32_t captureQueueFrames {};  ///< Optional PCM queue bound; zero retains the legacy 120 ms-derived default.
    std::uint16_t frameSamples {};  ///< Exact negotiated 48 kHz frame samples; zero derives the legacy millisecond duration.
  };

  /** @brief Captured interleaved PCM plus its exact source timeline metadata. */
  struct captured_frame_t {
    std::vector<float> samples;  ///< Complete interleaved PCM frame.
    std::uint64_t sample_position {};  ///< Exact first-sample position at 48 kHz.
    std::uint32_t gap_frames {};  ///< Captured frames missing immediately before this frame.
    bool discontinuity {};  ///< Whether capture reinitialization invalidated prior continuity.
  };

  using sample_queue_t = std::shared_ptr<safe::queue_t<captured_frame_t>>;  ///< Captured PCM queue shared with the encoder.
  using pcm_slab_queue_t = std::shared_ptr<safe::queue_t<std::vector<float>>>;  ///< Reusable capture PCM storage.

  /**
   * @brief Select one built-in validated Opus layout without legacy fallback behavior.
   *
   * This strict selector is intended for authenticated native-protocol negotiation. Existing
   * GameStream parsing retains its current internal fallback behavior.
   *
   * @param channels Requested channel count; supported values are 2, 6, and 8.
   * @param high_quality Whether to select the corresponding high-bitrate layout.
   * @return Stable built-in stream configuration, or no value for an unsupported channel count.
   */
  [[nodiscard]] std::optional<opus_stream_config_t> select_opus_stream_config(
    int channels,
    bool high_quality
  ) noexcept;

  /**
   * @brief Shared audio device state used while streams are active.
   */
  struct audio_ctx_t {
    // We want to change the sink for the first stream only
    std::unique_ptr<std::atomic_bool> sink_flag;  ///< Tracks whether the capture sink was already switched.

    std::unique_ptr<platf::audio_control_t> control;  ///< Platform audio-control implementation.

    bool restore_sink;  ///< Whether Lumen should restore the original sink when capture ends.
    platf::sink_t sink;  ///< Original sink captured before Lumen switched devices.
  };

  /**
   * @brief Byte buffer used for encoded audio packet payloads.
   */
  using buffer_t = util::buffer_t<std::uint8_t>;

  /**
   * @brief Encoded audio packet ready for a protocol-specific destination.
   */
  struct packet_t {
    buffer_t payload;  ///< Encoded Opus packet.
    std::uint64_t sample_position {};  ///< Exact 48 kHz first-sample position.
    bool discontinuity {};  ///< Reset/flush decoder before this packet.
  };

  /**
   * @brief Typed lifetime and backpressure boundary for encoded audio packets.
   */
  class AudioPacketDestination {
  public:
    /** @brief Maximum fixed Opus output bytes offered to a zero-allocation destination. */
    inline static constexpr std::size_t maximum_encoded_packet_bytes = 1'400;

    /** @brief Destination-owned writable Opus slab lease. */
    struct packet_write_lease_t {
      std::span<std::uint8_t> storage;  ///< Writable setup-allocated codec output storage.
      std::uint64_t token {};  ///< Nonzero destination-specific slot incarnation.

      /** @brief Return whether storage and token name one live reservation. */
      [[nodiscard]] explicit operator bool() const noexcept {
        return !storage.empty() && token != 0;
      }
    };

    /**
     * @brief Result of offering one packet to the protocol-owned destination.
     */
    enum class enqueue_result_e : std::uint8_t {
      enqueued,  ///< The destination accepted ownership of the packet.
      closed,  ///< The destination is closing or no longer exists.
      backpressure  ///< The bounded destination queue has no remaining capacity.
    };

    virtual ~AudioPacketDestination() = default;

    /** @brief Return whether this destination requires fixed-slab transfer with no heap fallback. */
    [[nodiscard]] virtual bool requires_fixed_packet_storage() const noexcept {
      return false;
    }

    /**
     * @brief Return whether captured timeline gaps should be encoded as silence before fresh PCM.
     *
     * Legacy transports preserve their established continuous-timeline behavior. Low-latency
     * destinations may return `false` to discard elapsed audio and publish the current frame with
     * a discontinuity instead of allowing silence backfill to occupy their bounded send queue.
     *
     * @return `true` to encode silence for every captured gap frame.
     */
    [[nodiscard]] virtual bool fill_capture_gaps_with_silence() const noexcept {
      return true;
    }

    /**
     * @brief Reserve destination-owned codec output storage without allocation.
     *
     * Legacy destinations may return no value and receive the ordinary move-owned packet fallback.
     *
     * @return Writable fixed slab lease, or no value when unsupported or backpressured.
     */
    [[nodiscard]] virtual std::optional<packet_write_lease_t> acquire_packet_storage() noexcept {
      return std::nullopt;
    }

    /**
     * @brief Commit bytes written into a destination-owned packet lease.
     *
     * @param lease Exact live lease returned by `acquire_packet_storage()`.
     * @param payload_bytes Populated leading Opus bytes.
     * @param sample_position Exact 48 kHz first-sample position.
     * @param discontinuity Whether the decoder timeline must reset before this packet.
     * @return Exact destination admission result.
     */
    [[nodiscard]] virtual enqueue_result_e commit_packet_storage(
      const packet_write_lease_t &lease,
      std::size_t payload_bytes,
      std::uint64_t sample_position,
      bool discontinuity
    ) noexcept {
      (void) lease;
      (void) payload_bytes;
      (void) sample_position;
      (void) discontinuity;
      return enqueue_result_e::backpressure;
    }

    /**
     * @brief Release an uncommitted destination-owned packet lease.
     *
     * @param lease Exact live lease returned by `acquire_packet_storage()`.
     */
    virtual void cancel_packet_storage(const packet_write_lease_t &lease) noexcept {
      (void) lease;
    }

    /**
     * @brief Offer one encoded packet without blocking the encoder thread.
     * @param packet Encoded Opus packet whose ownership transfers on success.
     * @return Exact destination admission result.
     */
    [[nodiscard]] virtual enqueue_result_e enqueue(packet_t packet) = 0;

    /**
     * @brief Stop accepting packets and wake any destination consumer.
     */
    virtual void close() noexcept = 0;
  };

  /**
   * @brief Non-owning destination reference retained by capture and encode workers.
   */
  using packet_destination_t = std::weak_ptr<AudioPacketDestination>;

  /**
   * @brief Encode captured PCM and publish Opus packets to one weak protocol destination.
   *
   * @param samples Captured PCM queue.
   * @param free_pcm_slabs Reusable PCM storage returned after each consumed frame; may be empty in tests.
   * @param config Negotiated encoder configuration.
   * @param destination Weak protocol-owned destination.
   * @param encoding Set false when the encoder worker exits.
   */
  void encodeThread(
    sample_queue_t samples,
    pcm_slab_queue_t free_pcm_slabs,
    config_t config,
    packet_destination_t destination,
    const std::shared_ptr<std::atomic_bool> &encoding
  );

  /**
   * @brief Shared mailbox reference to the global audio context.
   */
  using audio_ctx_ref_t = safe::shared_t<audio_ctx_t>::ptr_t;

  /**
   * @brief Capture, encode, and publish audio packets for a stream.
   *
   * @param mail Mailbox used to publish encoded audio packets.
   * @param config Audio capture and encoder settings.
   * @param destination Weak protocol-owned destination for encoded Opus packets.
   */
  void capture(safe::mail_t mail, config_t config, packet_destination_t destination);

  /**
   * @brief Get the reference to the audio context.
   * @returns A shared pointer reference to audio context.
   * @note Aside from the configuration purposes, it can be used to extend the
   *       audio sink lifetime to capture sink earlier and restore it later.
   *
   * @examples
   * audio_ctx_ref_t audio = get_audio_ctx_ref()
   * @examples_end
   */
  audio_ctx_ref_t get_audio_ctx_ref();

  /**
   * @brief Check if the audio sink held by audio context is available.
   * @returns True if available (and can probably be restored), false otherwise.
   * @note Useful for delaying the release of audio context shared pointer (which
   *       tries to restore original sink).
   *
   * @examples
   * audio_ctx_ref_t audio = get_audio_ctx_ref()
   * if (audio.get()) {
   *     return is_audio_ctx_sink_available(*audio.get());
   * }
   * return false;
   * @examples_end
   * @param ctx Native context object used by the operation or callback.
   */
  bool is_audio_ctx_sink_available(const audio_ctx_t &ctx);
}  // namespace audio
