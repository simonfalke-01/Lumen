/**
 * @file src/client_microphone.cpp
 * @brief Definitions for portable client microphone receive and decode support.
 */

// standard includes
#include <algorithm>
#include <array>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

// lib includes
#include <opus/opus.h>

// local includes
#include "client_microphone.h"

namespace client_microphone {
  namespace {
    std::mutex writer_mutex;  ///< Serializes cross-protocol writer arbitration.
    std::optional<writer_owner_t> writer_owner;  ///< Exact tagged owner of the single writer.
  }  // namespace

  writer_owner_t writer_owner_t::legacy(const std::uint32_t launch_session_id) {
    return {writer_protocol_e::legacy, launch_session_id};
  }

  writer_owner_t writer_owner_t::protocol_v3(const std::uint64_t connection_id) {
    return {writer_protocol_e::protocol_v3, connection_id};
  }

  bool claim_writer(const writer_owner_t owner) {
    if (owner.id == 0) {
      return false;
    }
    std::lock_guard lock {writer_mutex};
    if (!writer_owner) {
      writer_owner = owner;
    }
    return writer_owner == owner;
  }

  void release_writer(const writer_owner_t owner) {
    std::lock_guard lock {writer_mutex};
    if (writer_owner == owner) {
      writer_owner.reset();
    }
  }

  /**
   * @brief Return the bounded signed distance between monotonic packet sequences.
   *
   * @param sequence Sequence being compared.
   * @param origin Sequence used as the comparison origin.
   * @return Positive distance for a newer sequence and negative distance for an older sequence.
   */
  static std::int64_t sequence_distance(std::uint64_t sequence, std::uint64_t origin) {
    if (sequence >= origin) {
      const auto distance = sequence - origin;
      return distance > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ?
               std::numeric_limits<std::int64_t>::max() :
               static_cast<std::int64_t>(distance);
    }

    const auto distance = origin - sequence;
    return distance > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ?
             std::numeric_limits<std::int64_t>::min() :
             -static_cast<std::int64_t>(distance);
  }

  /**
   * @brief Opaque ownership for the native libopus decoder.
   */
  struct opus_decoder_t::impl_t {
    OpusDecoder *decoder {};  ///< Native libopus decoder instance.

    /**
     * @brief Destroy the native libopus decoder when present.
     */
    ~impl_t() {
      if (decoder != nullptr) {
        opus_decoder_destroy(decoder);
      }
    }
  };

  opus_decoder_t::opus_decoder_t():
      impl_(std::make_unique<impl_t>()) {
    int error = OPUS_OK;
    impl_->decoder = opus_decoder_create(SAMPLE_RATE, CHANNEL_COUNT, &error);
    if (error != OPUS_OK || impl_->decoder == nullptr) {
      throw std::runtime_error(std::string {"Unable to create client microphone Opus decoder: "} + opus_strerror(error));
    }
  }

  opus_decoder_t::~opus_decoder_t() = default;
  opus_decoder_t::opus_decoder_t(opus_decoder_t &&) noexcept = default;
  opus_decoder_t &opus_decoder_t::operator=(opus_decoder_t &&) noexcept = default;

  int opus_decoder_t::reset() {
    return opus_decoder_ctl(impl_->decoder, OPUS_RESET_STATE);
  }

  int opus_decoder_t::decode(
    std::span<const std::uint8_t> payload,
    bool use_fec,
    std::span<std::int16_t> output
  ) {
    if (payload.empty() || payload.size() > MAX_OPUS_PAYLOAD_SIZE || output.size() < SAMPLES_PER_FRAME) {
      return OPUS_BAD_ARG;
    }

    return opus_decode(
      impl_->decoder,
      payload.data(),
      static_cast<opus_int32>(payload.size()),
      output.data(),
      static_cast<int>(SAMPLES_PER_FRAME),
      use_fec ? 1 : 0
    );
  }

  int opus_decoder_t::conceal(std::span<std::int16_t> output) {
    if (output.size() < SAMPLES_PER_FRAME) {
      return OPUS_BAD_ARG;
    }

    return opus_decode(
      impl_->decoder,
      nullptr,
      0,
      output.data(),
      static_cast<int>(SAMPLES_PER_FRAME),
      0
    );
  }

  /**
   * @brief Encoded packet stored in the bounded jitter window.
   */
  struct queued_packet_t {
    std::uint64_t sequence;  ///< Monotonic packet sequence number.
    std::uint32_t timestamp;  ///< Wrapping sample timestamp validated against the sequence.
    packet_kind_e kind;  ///< Authenticated content represented by the packet.
    std::vector<std::uint8_t> payload;  ///< Validated encoded Opus packet bytes.
  };

  /**
   * @brief Internal receiver state hidden from platform consumers.
   */
  struct receiver_t::impl_t {
    std::unique_ptr<decoder_t> decoder;  ///< Injected Opus decoder boundary.
    sink_t &sink;  ///< Borrowed platform sink that outlives the receiver.
    std::vector<queued_packet_t> packets;  ///< Bounded encoded packet storage.
    statistics_t stats;  ///< Counters for the active generation.
    clock_t::time_point next_playout {};  ///< Deadline for the next decoded frame.
    clock_t::time_point last_packet {};  ///< Arrival time of the most recently accepted packet.
    std::uint64_t generation {};  ///< Current media generation identifier.
    std::uint64_t expected_sequence {};  ///< Sequence assigned to the next playout frame.
    std::uint32_t expected_timestamp {};  ///< Sample timestamp assigned to the next playout frame.
    bool active {};  ///< Whether decoder and sink initialization succeeded.
    bool scheduled {};  ///< Whether the first packet established a playout deadline.
    bool played {};  ///< Whether the first playout deadline has passed.
    bool inactivity_flushed {};  ///< Whether the current no-packet interval was already flushed.

    /**
     * @brief Construct internal state around injected dependencies.
     *
     * @param decoder Decoder owned by the receiver.
     * @param sink Platform sink borrowed by the receiver.
     */
    impl_t(std::unique_ptr<decoder_t> decoder, sink_t &sink):
        decoder(std::move(decoder)),
        sink(sink) {
      packets.reserve(MAX_QUEUED_PACKETS);
    }

    /**
     * @brief Locate a queued packet by exact monotonic sequence number.
     *
     * @param sequence Sequence to locate.
     * @return Iterator to the packet or `packets.end()`.
     */
    auto find(std::uint64_t sequence) {
      return std::find_if(packets.begin(), packets.end(), [sequence](const queued_packet_t &packet) {
        return packet.sequence == sequence;
      });
    }

    /**
     * @brief Decode or conceal the frame at the current expected sequence.
     *
     * @return `true` when the platform sink accepted a complete PCM frame.
     */
    bool render_frame() {
      std::array<std::int16_t, SAMPLES_PER_FRAME> pcm {};
      auto decoded_samples = -1;
      auto used_fec = false;
      auto used_plc = false;
      auto used_silence = false;

      if (const auto current = find(expected_sequence); current != packets.end()) {
        if (current->kind == packet_kind_e::silence) {
          used_silence = true;
          decoded_samples = static_cast<int>(SAMPLES_PER_FRAME);
        } else {
          decoded_samples = decoder->decode(current->payload, false, pcm);
        }
        packets.erase(current);
      } else if (const auto next = find(expected_sequence + 1U); next != packets.end()) {
        if (next->kind == packet_kind_e::opus) {
          used_fec = true;
          decoded_samples = decoder->decode(next->payload, true, pcm);
        } else {
          used_plc = true;
          decoded_samples = decoder->conceal(pcm);
        }
      } else if (packets.empty()) {
        used_silence = true;
        decoded_samples = static_cast<int>(SAMPLES_PER_FRAME);
      } else {
        used_plc = true;
        decoded_samples = decoder->conceal(pcm);
      }

      if (decoded_samples != static_cast<int>(SAMPLES_PER_FRAME)) {
        ++stats.decode_errors;
        if (used_plc) {
          return false;
        }

        used_fec = false;
        used_plc = true;
        decoded_samples = decoder->conceal(pcm);
        if (decoded_samples != static_cast<int>(SAMPLES_PER_FRAME)) {
          ++stats.decode_errors;
          return false;
        }
      }

      if (used_fec) {
        ++stats.fec_frames;
      } else if (used_plc) {
        ++stats.plc_frames;
      } else if (used_silence) {
        ++stats.silence_frames;
      } else {
        ++stats.decoded_frames;
      }

      if (!sink.write(generation, pcm)) {
        ++stats.sink_errors;
        return false;
      }

      return true;
    }
  };

  receiver_t::receiver_t(std::unique_ptr<decoder_t> decoder, sink_t &sink) {
    if (!decoder) {
      throw std::invalid_argument("Client microphone receiver requires a decoder");
    }

    impl_ = std::make_unique<impl_t>(std::move(decoder), sink);
  }

  receiver_t::~receiver_t() {
    stop();
  }

  bool receiver_t::reset(std::uint64_t generation, clock_t::time_point now) {
    stop();

    impl_->generation = generation;
    impl_->stats = {};
    impl_->packets.clear();
    impl_->last_packet = now;
    impl_->scheduled = false;
    impl_->played = false;
    impl_->inactivity_flushed = false;

    if (impl_->decoder->reset() < 0) {
      return false;
    }

    if (!impl_->sink.begin(generation, SAMPLE_RATE, CHANNEL_COUNT)) {
      return false;
    }

    impl_->active = true;
    return true;
  }

  void receiver_t::stop() {
    if (impl_ == nullptr || !impl_->active) {
      return;
    }

    impl_->sink.end(impl_->generation);
    impl_->packets.clear();
    impl_->scheduled = false;
    impl_->played = false;
    impl_->inactivity_flushed = false;
    impl_->active = false;
  }

  submit_result_e receiver_t::submit(packet_t packet, clock_t::time_point now) {
    if (!impl_->active) {
      return submit_result_e::inactive;
    }
    if (packet.generation != impl_->generation) {
      ++impl_->stats.wrong_generation_packets;
      return submit_result_e::wrong_generation;
    }
    if (packet.kind == packet_kind_e::opus && packet.payload.empty()) {
      ++impl_->stats.invalid_payload_packets;
      return submit_result_e::invalid_payload;
    }
    if (packet.kind == packet_kind_e::silence && !packet.payload.empty()) {
      ++impl_->stats.invalid_payload_packets;
      return submit_result_e::invalid_payload;
    }
    if (packet.payload.size() > MAX_OPUS_PAYLOAD_SIZE) {
      ++impl_->stats.invalid_payload_packets;
      return submit_result_e::payload_too_large;
    }
    if (impl_->find(packet.sequence) != impl_->packets.end()) {
      ++impl_->stats.duplicate_packets;
      return submit_result_e::duplicate;
    }

    if (!impl_->scheduled) {
      impl_->expected_sequence = packet.sequence;
      impl_->expected_timestamp = packet.timestamp;
      impl_->next_playout = now + JITTER_WINDOW;
      impl_->last_packet = now;
      impl_->scheduled = true;
    } else {
      const auto distance = sequence_distance(packet.sequence, impl_->expected_sequence);
      if (distance < 0) {
        if (impl_->played || distance < -static_cast<std::int64_t>(MAX_QUEUED_PACKETS - 1U)) {
          ++impl_->stats.late_packets;
          return submit_result_e::late;
        }

        const auto expected_timestamp = impl_->expected_timestamp -
                                        static_cast<std::uint32_t>(-distance) *
                                          static_cast<std::uint32_t>(SAMPLES_PER_FRAME);
        if (packet.timestamp != expected_timestamp) {
          ++impl_->stats.timestamp_discontinuity_packets;
          return submit_result_e::timestamp_discontinuity;
        }

        impl_->expected_sequence = packet.sequence;
        impl_->expected_timestamp = packet.timestamp;
        const auto first_outside_window = std::remove_if(
          impl_->packets.begin(),
          impl_->packets.end(),
          [&](const queued_packet_t &queued) {
            return sequence_distance(queued.sequence, impl_->expected_sequence) >=
                   static_cast<std::int64_t>(MAX_QUEUED_PACKETS);
          }
        );
        impl_->packets.erase(first_outside_window, impl_->packets.end());
      } else if (distance >= static_cast<std::int64_t>(MAX_QUEUED_PACKETS)) {
        ++impl_->stats.out_of_window_packets;
        return submit_result_e::too_far_ahead;
      } else {
        const auto expected_timestamp = impl_->expected_timestamp +
                                        static_cast<std::uint32_t>(distance) *
                                          static_cast<std::uint32_t>(SAMPLES_PER_FRAME);
        if (packet.timestamp != expected_timestamp) {
          ++impl_->stats.timestamp_discontinuity_packets;
          return submit_result_e::timestamp_discontinuity;
        }
      }
    }

    if (impl_->packets.size() >= MAX_QUEUED_PACKETS) {
      ++impl_->stats.out_of_window_packets;
      return submit_result_e::queue_full;
    }

    impl_->packets.push_back({packet.sequence, packet.timestamp, packet.kind, std::move(packet.payload)});
    impl_->last_packet = now;
    impl_->inactivity_flushed = false;
    ++impl_->stats.accepted_packets;
    return submit_result_e::accepted;
  }

  std::size_t receiver_t::poll(clock_t::time_point now) {
    if (!impl_->active || !impl_->scheduled) {
      return 0;
    }

    if (!impl_->inactivity_flushed && now - impl_->last_packet >= INACTIVITY_TIMEOUT) {
      impl_->packets.clear();
      impl_->next_playout = now;
      impl_->inactivity_flushed = true;
      ++impl_->stats.inactivity_flushes;
      static_cast<void>(impl_->decoder->reset());
    }
    if (now < impl_->next_playout) {
      return 0;
    }

    const auto frames_due = static_cast<std::uint64_t>((now - impl_->next_playout) / FRAME_DURATION) + 1U;
    if (frames_due > MAX_CATCH_UP_FRAMES) {
      const auto skipped = frames_due - MAX_CATCH_UP_FRAMES;
      impl_->expected_sequence += skipped;
      impl_->expected_timestamp += static_cast<std::uint32_t>(skipped * SAMPLES_PER_FRAME);
      impl_->next_playout += FRAME_DURATION * static_cast<std::int64_t>(skipped);
      impl_->stats.skipped_playout_frames += skipped;

      const auto first_current_packet = std::remove_if(
        impl_->packets.begin(),
        impl_->packets.end(),
        [&](const queued_packet_t &packet) {
          return sequence_distance(packet.sequence, impl_->expected_sequence) < 0;
        }
      );
      impl_->packets.erase(first_current_packet, impl_->packets.end());
    }

    std::size_t delivered = 0;
    std::size_t processed = 0;
    while (now >= impl_->next_playout && processed < MAX_CATCH_UP_FRAMES) {
      impl_->played = true;
      if (impl_->render_frame()) {
        ++delivered;
      }
      ++impl_->expected_sequence;
      impl_->expected_timestamp += static_cast<std::uint32_t>(SAMPLES_PER_FRAME);
      impl_->next_playout += FRAME_DURATION;
      ++processed;
    }

    return delivered;
  }

  std::optional<clock_t::time_point> receiver_t::next_poll_time() const {
    if (!impl_->active || !impl_->scheduled) {
      return std::nullopt;
    }
    return impl_->next_playout;
  }

  bool receiver_t::active() const {
    return impl_->active;
  }

  std::uint64_t receiver_t::generation() const {
    return impl_->generation;
  }

  std::size_t receiver_t::queued_packets() const {
    return impl_->packets.size();
  }

  const statistics_t &receiver_t::statistics() const {
    return impl_->stats;
  }

  /** @brief Synchronized receiver state and independently clocked playout worker. */
  struct clocked_receiver_t::impl_t {
    receiver_t receiver;  ///< Serialized jitter receiver and sink lifecycle.
    mutable std::mutex mutex;  ///< Protects receiver state and shutdown state.
    std::condition_variable changed;  ///< Wakes the worker when a deadline or lifecycle changes.
    std::uint64_t revision {};  ///< Monotonic state-change counter used by worker waits.
    bool shut_down {};  ///< Whether `shutdown_worker()` permanently closed this wrapper.
    std::jthread worker;  ///< Independent monotonic playout worker; declared last to start after state initialization.

    impl_t(std::unique_ptr<decoder_t> decoder, sink_t &sink):
        receiver(std::move(decoder), sink),
        worker([this](const std::stop_token token) {
          run(token);
        }) {
    }

    ~impl_t() {
      shutdown_worker();
    }

    /** @brief Notify the playout worker after changing receiver state under `mutex`. */
    void notify_change() {
      ++revision;
      changed.notify_all();
    }

    /** @brief Wait for exact receiver deadlines and poll independently of packet arrival. */
    void run(const std::stop_token token) {
      std::unique_lock lock {mutex};
      auto observed_revision = revision;
      while (!token.stop_requested()) {
        if (const auto deadline = receiver.next_poll_time()) {
          changed.wait_until(lock, *deadline, [&]() {
            return token.stop_requested() || revision != observed_revision;
          });
        } else {
          changed.wait(lock, [&]() {
            return token.stop_requested() || revision != observed_revision;
          });
        }

        if (token.stop_requested()) {
          break;
        }
        if (revision != observed_revision) {
          observed_revision = revision;
          continue;
        }

        receiver.poll(clock_t::now());
      }
    }

    /** @brief Idempotently request worker stop, join it, and stop the sink generation. */
    void shutdown_worker() {
      {
        std::lock_guard lock {mutex};
        if (shut_down) {
          return;
        }
        shut_down = true;
        worker.request_stop();
        notify_change();
      }
      if (worker.joinable()) {
        worker.join();
      }
      std::lock_guard lock {mutex};
      receiver.stop();
    }
  };

  clocked_receiver_t::clocked_receiver_t(std::unique_ptr<decoder_t> decoder, sink_t &sink):
      impl_(std::make_unique<impl_t>(std::move(decoder), sink)) {
  }

  clocked_receiver_t::~clocked_receiver_t() = default;

  bool clocked_receiver_t::reset(const std::uint64_t generation) {
    std::lock_guard lock {impl_->mutex};
    if (impl_->shut_down) {
      return false;
    }
    const auto started = impl_->receiver.reset(generation, clock_t::now());
    impl_->notify_change();
    return started;
  }

  submit_result_e clocked_receiver_t::submit(packet_t packet) {
    std::lock_guard lock {impl_->mutex};
    if (impl_->shut_down) {
      return submit_result_e::inactive;
    }
    const auto result = impl_->receiver.submit(std::move(packet), clock_t::now());
    if (result == submit_result_e::accepted) {
      impl_->notify_change();
    }
    return result;
  }

  void clocked_receiver_t::stop() {
    std::lock_guard lock {impl_->mutex};
    if (impl_->shut_down) {
      return;
    }
    impl_->receiver.stop();
    impl_->notify_change();
  }

  void clocked_receiver_t::shutdown() {
    impl_->shutdown_worker();
  }

  bool clocked_receiver_t::active() const {
    std::lock_guard lock {impl_->mutex};
    return !impl_->shut_down && impl_->receiver.active();
  }

  std::uint64_t clocked_receiver_t::generation() const {
    std::lock_guard lock {impl_->mutex};
    return impl_->receiver.generation();
  }

  std::size_t clocked_receiver_t::queued_packets() const {
    std::lock_guard lock {impl_->mutex};
    return impl_->receiver.queued_packets();
  }

  statistics_t clocked_receiver_t::statistics() const {
    std::lock_guard lock {impl_->mutex};
    return impl_->receiver.statistics();
  }
}  // namespace client_microphone
