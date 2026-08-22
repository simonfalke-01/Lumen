/**
 * @file src/client_microphone.h
 * @brief Portable receive, jitter-buffer, and decode support for client microphone audio.
 */
#pragma once

// standard includes
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace client_microphone {
  constexpr std::uint32_t SAMPLE_RATE = 48000;  ///< Opus microphone sample rate in hertz.
  constexpr std::uint8_t CHANNEL_COUNT = 1;  ///< Number of channels in the microphone stream.
  constexpr std::chrono::milliseconds FRAME_DURATION {20};  ///< Duration of one microphone frame.
  constexpr std::size_t SAMPLES_PER_FRAME = 960;  ///< Number of mono samples in one microphone frame.
  constexpr std::size_t JITTER_TARGET_FRAMES = 3;  ///< Number of frames covered by the target playout delay.
  constexpr std::size_t MAX_QUEUED_PACKETS = 6;  ///< Hard maximum number of packets held for playout.
  constexpr std::size_t MAX_CATCH_UP_FRAMES = 3;  ///< Maximum number of frames emitted by one poll call.
  constexpr std::chrono::milliseconds JITTER_WINDOW {60};  ///< Initial packet reordering and playout delay.
  constexpr std::chrono::milliseconds INACTIVITY_TIMEOUT {500};  ///< Time without packets before state is flushed.
  constexpr std::size_t MAX_OPUS_PAYLOAD_SIZE = 1275;  ///< Maximum accepted Opus packet size in bytes.
  static_assert(JITTER_WINDOW == FRAME_DURATION * JITTER_TARGET_FRAMES);

  /**
   * @brief Monotonic clock used by the externally driven playout scheduler.
   */
  using clock_t = std::chrono::steady_clock;

  /**
   * @brief Authenticated content carried by one microphone packet.
   */
  enum class packet_kind_e {
    opus,  ///< Packet contains one encoded 20 ms Opus frame.
    silence  ///< Packet explicitly represents one authenticated silent frame.
  };

  /**
   * @brief One encoded microphone packet received from a client.
   */
  struct packet_t {
    std::uint64_t generation;  ///< Session generation that owns the packet.
    std::uint64_t sequence;  ///< Monotonic packet sequence number for the RTSP session.
    std::uint32_t timestamp;  ///< Wrapping 48 kHz sample timestamp for the frame.
    packet_kind_e kind {packet_kind_e::opus};  ///< Authenticated packet content type.
    std::vector<std::uint8_t> payload;  ///< Opus packet bytes.
  };

  /**
   * @brief Result of offering a packet to the bounded jitter buffer.
   */
  enum class submit_result_e {
    accepted,  ///< Packet was accepted for playout.
    inactive,  ///< Receiver has not started a generation.
    wrong_generation,  ///< Packet belongs to a stale or future generation.
    invalid_payload,  ///< Packet has no encoded payload.
    payload_too_large,  ///< Packet exceeds the Opus payload bound.
    timestamp_discontinuity,  ///< Timestamp does not match the sequence-derived sample position.
    duplicate,  ///< Packet sequence is already queued.
    late,  ///< Packet sequence has already passed its playout deadline.
    too_far_ahead,  ///< Packet is outside the six-packet storage window.
    queue_full  ///< Packet could not fit in the bounded queue.
  };

  /**
   * @brief Per-generation counters for microphone receive behavior.
   */
  struct statistics_t {
    std::uint64_t accepted_packets {};  ///< Packets admitted to the jitter buffer.
    std::uint64_t duplicate_packets {};  ///< Duplicate packets rejected before decode.
    std::uint64_t late_packets {};  ///< Packets rejected after their playout position passed.
    std::uint64_t wrong_generation_packets {};  ///< Packets rejected for a generation mismatch.
    std::uint64_t invalid_payload_packets {};  ///< Empty or oversized payloads rejected.
    std::uint64_t timestamp_discontinuity_packets {};  ///< Packets rejected for an unexpected sample timestamp.
    std::uint64_t out_of_window_packets {};  ///< Packets rejected beyond the bounded sequence window.
    std::uint64_t decoded_frames {};  ///< Ordinary Opus frames decoded and delivered.
    std::uint64_t fec_frames {};  ///< Missing frames recovered from in-band Opus FEC.
    std::uint64_t plc_frames {};  ///< Missing or invalid frames replaced with Opus PLC.
    std::uint64_t silence_frames {};  ///< Authenticated silence and queue-underrun frames delivered.
    std::uint64_t skipped_playout_frames {};  ///< Stale frame positions skipped to preserve live latency.
    std::uint64_t decode_errors {};  ///< Decoder calls that did not produce one complete frame.
    std::uint64_t sink_errors {};  ///< Complete frames rejected by the platform sink.
    std::uint64_t inactivity_flushes {};  ///< Jitter states flushed after the inactivity timeout.
  };

  /**
   * @brief Decoder boundary used by the jitter-buffer core.
   *
   * Implementations receive fixed-size output storage for one 48 kHz mono,
   * 20 ms PCM frame. Negative return values represent decoder errors.
   */
  class decoder_t {
  public:
    /**
     * @brief Destroy the decoder implementation.
     */
    virtual ~decoder_t() = default;

    /**
     * @brief Clear codec history at a generation boundary.
     *
     * @return Zero on success or a negative codec error code.
     */
    virtual int reset() = 0;

    /**
     * @brief Decode an encoded Opus packet.
     *
     * @param payload Encoded Opus packet bytes.
     * @param use_fec Whether to decode the preceding lost frame using in-band FEC.
     * @param output Storage for decoded signed 16-bit mono samples.
     * @return Number of decoded samples per channel or a negative codec error code.
     */
    virtual int decode(
      std::span<const std::uint8_t> payload,
      bool use_fec,
      std::span<std::int16_t> output
    ) = 0;

    /**
     * @brief Generate packet-loss concealment for one missing frame.
     *
     * @param output Storage for concealed signed 16-bit mono samples.
     * @return Number of decoded samples per channel or a negative codec error code.
     */
    virtual int conceal(std::span<std::int16_t> output) = 0;
  };

  /**
   * @brief Fixed-format libopus decoder for client microphone packets.
   */
  class opus_decoder_t final: public decoder_t {
  public:
    /**
     * @brief Create a 48 kHz mono Opus decoder.
     *
     * @throws std::runtime_error If libopus cannot create the decoder.
     */
    opus_decoder_t();

    /**
     * @brief Destroy the libopus decoder.
     */
    ~opus_decoder_t() override;

    opus_decoder_t(const opus_decoder_t &) = delete;
    opus_decoder_t &operator=(const opus_decoder_t &) = delete;

    /**
     * @brief Move ownership of a libopus decoder.
     *
     * @param other Decoder whose native state is transferred.
     */
    opus_decoder_t(opus_decoder_t &&) noexcept;

    /**
     * @brief Replace this decoder with another decoder's native state.
     *
     * @param other Decoder whose native state is transferred.
     * @return Reference to the assigned decoder.
     */
    opus_decoder_t &operator=(opus_decoder_t &&) noexcept;

    /**
     * @copydoc decoder_t::reset()
     */
    int reset() override;

    /**
     * @copydoc decoder_t::decode()
     */
    int decode(
      std::span<const std::uint8_t> payload,
      bool use_fec,
      std::span<std::int16_t> output
    ) override;

    /**
     * @copydoc decoder_t::conceal()
     */
    int conceal(std::span<std::int16_t> output) override;

  private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;  ///< Opaque libopus decoder state.
  };

  /**
   * @brief Platform injection boundary for decoded client microphone PCM.
   *
   * Implementations may connect this interface to a virtual capture device or
   * another operating-system-specific microphone injection backend. All calls
   * are made by the caller-owned receive thread; implementations need not add
   * an internal scheduling thread.
   */
  class sink_t {
  public:
    /**
     * @brief Destroy the platform sink implementation.
     */
    virtual ~sink_t() = default;

    /**
     * @brief Begin accepting PCM for a new stream generation.
     *
     * @param generation Session generation that will own subsequent frames.
     * @param sample_rate PCM sample rate in hertz.
     * @param channels Number of interleaved PCM channels.
     * @return `true` when the platform endpoint is ready for frames.
     */
    virtual bool begin(std::uint64_t generation, std::uint32_t sample_rate, std::uint8_t channels) = 0;

    /**
     * @brief Deliver one decoded PCM frame to the platform endpoint.
     *
     * @param generation Session generation that owns the frame.
     * @param samples Signed 16-bit interleaved PCM samples.
     * @return `true` when the complete frame was accepted.
     */
    virtual bool write(std::uint64_t generation, std::span<const std::int16_t> samples) = 0;

    /**
     * @brief End a previously started stream generation.
     *
     * @param generation Session generation being ended.
     */
    virtual void end(std::uint64_t generation) = 0;
  };

  /**
   * @brief Bounded sequence-aware receiver for client microphone media.
   *
   * The receiver is deliberately externally clocked. Callers submit packet
   * arrival times and invoke `poll()` from their existing event loop, which
   * makes playout deterministic and avoids hidden sleeps or worker threads.
   * The class is not thread-safe; callers must serialize its methods.
   */
  class receiver_t {
  public:
    /**
     * @brief Construct a receiver with injected decoder and platform sink.
     *
     * @param decoder Decoder used for ordinary, FEC, and PLC frames.
     * @param sink Platform endpoint that receives decoded PCM.
     * @throws std::invalid_argument If `decoder` is null.
     */
    receiver_t(std::unique_ptr<decoder_t> decoder, sink_t &sink);

    /**
     * @brief Stop the active generation and destroy the receiver.
     */
    ~receiver_t();

    receiver_t(const receiver_t &) = delete;
    receiver_t &operator=(const receiver_t &) = delete;
    receiver_t(receiver_t &&) = delete;
    receiver_t &operator=(receiver_t &&) = delete;

    /**
     * @brief Reset all codec and jitter state and begin a new generation.
     *
     * @param generation Unique identifier for the new media generation.
     * @param now Current event-loop time used for deterministic scheduling.
     * @return `true` when both the decoder and platform sink started.
     */
    bool reset(std::uint64_t generation, clock_t::time_point now);

    /**
     * @brief Stop the active generation and discard all queued packets.
     */
    void stop();

    /**
     * @brief Offer one encoded packet to the bounded jitter buffer.
     *
     * @param packet Packet and owning generation.
     * @param now Packet arrival time from the caller's event loop.
     * @return Detailed admission result.
     */
    submit_result_e submit(packet_t packet, clock_t::time_point now);

    /**
     * @brief Produce every due frame up to the per-call catch-up bound.
     *
     * Missing frames use FEC from the following queued packet when available,
     * then fall back to decoder-provided PLC. A single call emits no more than
     * `MAX_CATCH_UP_FRAMES` frames even after a large clock jump. Polling at or
     * beyond `INACTIVITY_TIMEOUT` after the last packet flushes media state and
     * switches the active generation to silence until valid media resumes or
     * the protocol supplies an explicit reset.
     *
     * @param now Current event-loop time.
     * @return Number of complete frames accepted by the platform sink.
     */
    std::size_t poll(clock_t::time_point now);

    /**
     * @brief Determine whether a generation is currently active.
     *
     * @return `true` after a successful reset and before stop.
     */
    bool active() const;

    /**
     * @brief Get the active generation identifier.
     *
     * @return Current generation, including the most recent failed start.
     */
    std::uint64_t generation() const;

    /**
     * @brief Get the number of encoded packets currently buffered.
     *
     * @return Queue size, always at most `MAX_QUEUED_PACKETS`.
     */
    std::size_t queued_packets() const;

    /**
     * @brief Get the counters for the current generation.
     *
     * @return Immutable statistics snapshot.
     */
    const statistics_t &statistics() const;

  private:
    struct impl_t;
    std::unique_ptr<impl_t> impl_;  ///< Receiver implementation and bounded packet storage.
  };
}  // namespace client_microphone
