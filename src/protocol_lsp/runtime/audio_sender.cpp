/**
 * @file src/protocol_lsp/runtime/audio_sender.cpp
 * @brief Production LSP host-audio RTP/SRTP sender implementation.
 */

#include "audio_sender.h"

#include "../core/wire.h"
#include "../transport/rtcp.h"
#include "udp_socket.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <thread>
#include <utility>

namespace lumen::lsp::runtime {
  namespace {
    using steady_clock = std::chrono::steady_clock;
    using system_clock = std::chrono::system_clock;

    constexpr std::size_t maximum_audio_queue_capacity = 8;
    constexpr std::uint64_t maximum_audio_queue_age_microseconds = 120'000;
    constexpr std::uint64_t minimum_sender_report_interval_microseconds = 100'000;
    constexpr std::uint64_t maximum_sender_report_interval_microseconds = 10'000'000;
    constexpr std::uint64_t ntp_unix_epoch_offset_seconds = 2'208'988'800ULL;
    constexpr std::uint64_t audio_completion_namespace = std::uint64_t {1} << 60U;
    constexpr std::uint64_t audio_completion_namespace_mask = std::uint64_t {0xf} << 60U;
    constexpr std::size_t maximum_pending_datagrams = 64;
    constexpr std::uint64_t pending_slot_bits = 6;
    constexpr std::uint64_t pending_slot_mask = maximum_pending_datagrams - 1U;
    constexpr std::uint64_t pending_generation_mask = (std::uint64_t {1} << (60U - pending_slot_bits)) - 1U;
    constexpr std::uint8_t audio_slab_slot_bits = 3;  ///< Bits naming one of eight fixed Opus slabs.
    constexpr std::uint64_t audio_slab_slot_mask = maximum_audio_queue_capacity - 1U;  ///< Slab-token slot bits.
    constexpr std::uint64_t audio_feedback_freshness_microseconds = 5'000'000;  ///< Sent-ledger age bound.
    constexpr auto audio_feedback_unreported = static_cast<std::uint8_t>(AudioFeedbackState::unreported);
    constexpr auto audio_feedback_unsent = static_cast<std::uint8_t>(AudioFeedbackState::unsent);

    /** @brief Saturatingly subtract one correction from a cumulative atomic counter. */
    void subtract_counter(std::atomic_uint64_t &counter, const std::uint64_t value) noexcept {
      auto current = counter.load(std::memory_order_relaxed);
      while (!counter.compare_exchange_weak(
        current,
        current > value ? current - value : 0,
        std::memory_order_relaxed,
        std::memory_order_relaxed
      )) {
      }
    }

    /** @brief Atomic audio sent-ledger slot indexed by 16-bit RTP sequence. */
    struct AudioSentRecord {
      std::atomic_flag access = ATOMIC_FLAG_INIT;  ///< Serializes wrap replacement and feedback.
      std::atomic<std::uint64_t> serial {};  ///< Nonzero sequence incarnation.
      std::atomic<std::uint64_t> sent_microseconds {};  ///< Final-send or tombstone time.
      std::atomic<std::uint32_t> wire_bytes {};  ///< Complete IP/UDP bytes, zero for tombstone.
      std::atomic<std::uint8_t> state {};  ///< Unreported/lost/received/unsent.
      std::atomic<std::uint8_t> ecn {};  ///< Latest echoed ECN codepoint.
      std::atomic<std::uint32_t> arrival_timestamp {};  ///< Reconstructed middle-NTP arrival timestamp.
      std::atomic<bool> arrival_timestamp_valid {};  ///< Whether exact ATO reconstruction is retained.
    };

    /** @brief NTP timestamp fields derived from one system-clock sample. */
    struct NtpTimestamp {
      std::uint32_t seconds {};  ///< NTP seconds modulo 2^32.
      std::uint32_t fraction {};  ///< Binary NTP fractional seconds.
    };

    /**
     * @brief Convert the current system clock into RFC 3550 NTP fields.
     *
     * @return Current NTP timestamp modulo its 32-bit seconds era.
     */
    NtpTimestamp current_ntp_timestamp() noexcept {
      const auto elapsed = system_clock::now().time_since_epoch();
      const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
      const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed - seconds);
      const auto ntp_seconds = static_cast<std::uint64_t>(seconds.count()) + ntp_unix_epoch_offset_seconds;
      const auto fraction = (static_cast<std::uint64_t>(nanoseconds.count()) << 32U) / 1'000'000'000ULL;
      return {
        .seconds = static_cast<std::uint32_t>(ntp_seconds),
        .fraction = static_cast<std::uint32_t>(fraction),
      };
    }

    /**
     * @brief Return the negotiated audio frame duration in whole microseconds.
     *
     * @param frame_samples Audio samples at 48 kHz.
     * @return Exact duration for every supported LSP/1 Opus frame size.
     */
    constexpr std::uint64_t frame_duration_microseconds(const std::uint16_t frame_samples) noexcept {
      return static_cast<std::uint64_t>(frame_samples) * 1'000'000ULL / media::audio_clock_rate;
    }
  }  // namespace

  bool HostAudioSenderConfig::valid() const noexcept {
    const auto expected_family = peer.family == IpAddressFamily::ipv6 ? media::ip_family::ipv6 : media::ip_family::ipv4;
    const auto frame_duration = frame_duration_microseconds(frame_samples);
    return peer.valid() && forward_path && forward_path->ready() &&
           forward_path->generation() == forward_path_generation && forward_path_generation != 0 &&
           ssrc != 0 && feedback_sender_ssrc != 0 && feedback_sender_ssrc != ssrc && rtcp_cname.valid() &&
           media::valid_dynamic_payload_type(payload_type) &&
           initial_sequence != 0 && initial_timestamp != 0 && media::valid_opus_frame_samples(frame_samples) &&
           path.family == expected_family && static_cast<bool>(media::make_path_payload_limit(path.family, path.udp_payload_size)) &&
           queue_capacity > 0 && queue_capacity <= maximum_audio_queue_capacity &&
           maximum_queue_age_microseconds >= frame_duration &&
           maximum_queue_age_microseconds <= maximum_audio_queue_age_microseconds &&
           sender_report_interval_microseconds >= minimum_sender_report_interval_microseconds &&
           sender_report_interval_microseconds <= maximum_sender_report_interval_microseconds;
  }

  /** @brief Hidden fixed-queue, sender-worker, and RTP timeline implementation. */
  class HostAudioSender::Impl {
  public:
    /**
     * @brief Retain immutable configuration and the association provider.
     *
     * @param config Complete negotiated host-audio configuration.
     * @param srtp Installed provider that outlives this implementation.
     */
    Impl(HostAudioSenderConfig config, LibsrtpServerProvider &srtp) noexcept:
        config_ {std::move(config)},
        srtp_ {srtp},
        sequence_(config_.initial_sequence),
        timestamp_origin_(config_.initial_timestamp) {
      ready_ = config_.valid();
    }

    /** @brief Close, join, and drain direct completions before releasing retained state. */
    ~Impl() {
      close();
      join();
    }

    /**
     * @brief Start the dedicated sender exactly once.
     *
     * @return `true` when the worker was created.
     */
    bool start() noexcept {
      if (!ready_ || started_.exchange(true, std::memory_order_acq_rel)) {
        return false;
      }
      closed_.store(false, std::memory_order_release);
      try {
        worker_ = std::jthread {[this](const std::stop_token stop_token) noexcept {
          run(stop_token);
        }};
        return true;
      } catch (...) {
        closed_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return false;
      }
    }

    /**
     * @brief Offer one encoded packet without waiting for queue capacity.
     *
     * @param packet Encoded Opus packet whose ownership transfers on success.
     * @return Exact nonblocking admission result.
     */
    audio::AudioPacketDestination::enqueue_result_e enqueue(audio::packet_t packet) {
      const auto lease = acquire_packet_storage();
      if (!lease) {
        return closed_.load(std::memory_order_acquire) ?
                 audio::AudioPacketDestination::enqueue_result_e::closed :
                 audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      if (packet.payload.size() > lease->storage.size()) {
        cancel_packet_storage(*lease);
        malformed_packets_.fetch_add(1, std::memory_order_relaxed);
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      std::copy(packet.payload.begin(), packet.payload.end(), lease->storage.begin());
      return commit_packet_storage(
        *lease,
        packet.payload.size(),
        packet.sample_position,
        packet.discontinuity
      );
    }

    /** @brief Reserve one fixed Opus slab without blocking the encoder thread. */
    [[nodiscard]] std::optional<audio::AudioPacketDestination::packet_write_lease_t> acquire_packet_storage() noexcept {
      if (!started_.load(std::memory_order_acquire) || closed_.load(std::memory_order_acquire)) {
        return std::nullopt;
      }
      std::unique_lock lock(mutex_, std::try_to_lock);
      if (!lock.owns_lock()) {
        backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
      }
      purge_expired(steady_clock::now());
      if (closed_.load(std::memory_order_acquire) || reservation_active_ ||
          size_ >= config_.queue_capacity) {
        if (!closed_.load(std::memory_order_relaxed)) {
          backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        }
        return std::nullopt;
      }
      const auto slot = (head_ + size_) % maximum_audio_queue_capacity;
      if (queue_[slot].has_value()) {
        backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
      }
      auto &packet = queue_[slot].emplace();
      auto incarnation = ++slab_incarnations_[slot];
      if (incarnation == 0) {
        incarnation = ++slab_incarnations_[slot];
      }
      packet.incarnation = incarnation;
      reservation_active_ = true;
      reservation_slot_ = slot;
      const auto token = (packet.incarnation << audio_slab_slot_bits) | slot;
      return audio::AudioPacketDestination::packet_write_lease_t {
        .storage = packet.payload,
        .token = token,
      };
    }

    /** @brief Publish one populated fixed Opus slab into the sender ring. */
    [[nodiscard]] audio::AudioPacketDestination::enqueue_result_e commit_packet_storage(
      const audio::AudioPacketDestination::packet_write_lease_t &lease,
      const std::size_t payload_bytes,
      const std::uint64_t sample_position,
      const bool discontinuity
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto slot = static_cast<std::size_t>(lease.token & audio_slab_slot_mask);
      auto *packet = slot < queue_.size() && queue_[slot] ? &*queue_[slot] : nullptr;
      if (!reservation_active_ || slot != reservation_slot_ || packet == nullptr ||
          (lease.token >> audio_slab_slot_bits) != packet->incarnation) {
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      reservation_active_ = false;
      if (closed_.load(std::memory_order_acquire)) {
        queue_[slot].reset();
        changed_.notify_all();
        return audio::AudioPacketDestination::enqueue_result_e::closed;
      }
      const auto maximum_codec_payload = config_.path.plaintext_rtp_capacity() - rtp_fixed_header_size;
      if (payload_bytes == 0 || payload_bytes > media::maximum_opus_packet_size ||
          payload_bytes > maximum_codec_payload || payload_bytes > packet->payload.size() ||
          sample_position > std::numeric_limits<std::uint64_t>::max() - config_.frame_samples) {
        queue_[slot].reset();
        malformed_packets_.fetch_add(1, std::memory_order_relaxed);
        changed_.notify_all();
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      packet->payload_bytes = payload_bytes;
      packet->sample_position = sample_position;
      packet->discontinuity = discontinuity;
      packet->enqueued_at = steady_clock::now();
      ++size_;
      enqueued_packets_.fetch_add(1, std::memory_order_relaxed);
      changed_.notify_one();
      return audio::AudioPacketDestination::enqueue_result_e::enqueued;
    }

    /** @brief Release one uncommitted fixed Opus slab reservation. */
    void cancel_packet_storage(const audio::AudioPacketDestination::packet_write_lease_t &lease) noexcept {
      std::scoped_lock lock(mutex_);
      const auto slot = static_cast<std::size_t>(lease.token & audio_slab_slot_mask);
      if (reservation_active_ && slot == reservation_slot_ && slot < queue_.size() && queue_[slot] &&
          (lease.token >> audio_slab_slot_bits) == queue_[slot]->incarnation) {
        queue_[slot].reset();
        reservation_active_ = false;
        changed_.notify_all();
      }
    }

    /** @brief Stop packet admission, discard queued media, and wake the worker. */
    void close() noexcept {
      (void) closed_.exchange(true, std::memory_order_acq_rel);
      worker_.request_stop();
      changed_.notify_all();
    }

    /** @brief Join the stopped worker and wait until direct path callbacks retire. */
    void join() noexcept {
      if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
      }
      {
        std::unique_lock queue_lock(mutex_);
        changed_.wait(queue_lock, [this]() {
          return !reservation_active_;
        });
        clear_queue();
      }
      std::unique_lock lock(pending_mutex_);
      pending_changed_.wait(lock, [this]() {
        return pending_count_ == 0;
      });
    }

    /**
     * @brief Return immutable configuration readiness.
     *
     * @return `true` when `start()` may be attempted.
     */
    [[nodiscard]] bool ready() const noexcept {
      return ready_;
    }

    /**
     * @brief Read lifecycle and counter state without taking the queue mutex.
     *
     * @return Current sender snapshot.
     */
    [[nodiscard]] HostAudioSenderSnapshot snapshot() const noexcept {
      return {
        .enqueued_packets = enqueued_packets_.load(std::memory_order_relaxed),
        .sent_packets = sent_packets_.load(std::memory_order_relaxed),
        .sent_payload_octets = sent_payload_octets_.load(std::memory_order_relaxed),
        .expired_packets = expired_packets_.load(std::memory_order_relaxed),
        .backpressure_events = backpressure_events_.load(std::memory_order_relaxed),
        .malformed_packets = malformed_packets_.load(std::memory_order_relaxed),
        .send_failures = send_failures_.load(std::memory_order_relaxed),
        .sender_reports = sender_reports_.load(std::memory_order_relaxed),
        .feedback_reports = feedback_reports_.load(std::memory_order_relaxed),
        .delivered_wire_bytes = delivered_wire_bytes_.load(std::memory_order_relaxed),
        .lost_wire_bytes = lost_wire_bytes_.load(std::memory_order_relaxed),
        .ecn_ce_wire_bytes = ecn_ce_wire_bytes_.load(std::memory_order_relaxed),
        .bytes_in_flight = bytes_in_flight_.load(std::memory_order_relaxed),
        .started = started_.load(std::memory_order_acquire),
        .closed = closed_.load(std::memory_order_acquire),
        .failed = failed_.load(std::memory_order_acquire),
      };
    }

    /** @brief Account the exact audio block from an owner-validated RFC 8888 packet. */
    bool receive_congestion_feedback(
      const std::span<const std::uint8_t> packet,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto feedback = transport::validate_congestion_feedback_packet(
        packet,
        config_.feedback_sender_ssrc
      );
      return feedback && receive_congestion_feedback(feedback, now_microseconds);
    }

    bool receive_congestion_feedback(
      const transport::congestion_feedback_packet_view &feedback,
      const std::uint64_t now_microseconds
    ) noexcept {
      return process_congestion_feedback(feedback, now_microseconds, true);
    }

    bool validate_congestion_feedback(
      const transport::congestion_feedback_packet_view &feedback,
      const std::uint64_t now_microseconds
    ) noexcept {
      return process_congestion_feedback(feedback, now_microseconds, false);
    }

    [[nodiscard]] std::optional<AudioCongestionFeedbackPreview> preview_congestion_feedback(
      const transport::congestion_feedback_packet_view &feedback,
      const std::uint64_t now_microseconds
    ) noexcept {
      return validate_congestion_feedback(feedback, now_microseconds) ?
               std::optional<AudioCongestionFeedbackPreview> {{feedback, now_microseconds}} :
               std::nullopt;
    }

    bool commit_congestion_feedback(const AudioCongestionFeedbackPreview &preview) noexcept {
      return receive_congestion_feedback(preview.packet, preview.now_microseconds);
    }

    /** @brief Validate, and optionally atomically commit, one exact audio feedback block. */
    bool process_congestion_feedback(
      const transport::congestion_feedback_packet_view &feedback,
      const std::uint64_t now_microseconds,
      const bool commit
    ) noexcept {
      std::scoped_lock feedback_lock(feedback_mutex_);
      if (!feedback) {
        return false;
      }
      const transport::congestion_feedback_block_view *audio_block = nullptr;
      for (std::size_t index = 0; index < feedback.block_count; ++index) {
        if (feedback.blocks[index].media_ssrc == config_.ssrc) {
          if (audio_block != nullptr) {
            return false;
          }
          audio_block = &feedback.blocks[index];
        }
      }
      if (audio_block == nullptr) {
        return true;
      }
      if ((has_feedback_receive_time_ &&
           (now_microseconds < last_feedback_receive_microseconds_ ||
            now_microseconds - last_feedback_receive_microseconds_ <
              transport::congestion_feedback_floor_microseconds)) ||
          (has_feedback_timestamp_ &&
           static_cast<std::int32_t>(feedback.report_timestamp - last_feedback_timestamp_) <= 0)) {
        return false;
      }

      std::uint64_t first_serial = 0;
      std::size_t locked_records = 0;
      const auto unlock_records = [&]() noexcept {
        for (std::size_t index = 0; index < locked_records; ++index) {
          const auto sequence = static_cast<std::uint16_t>(audio_block->begin_sequence + index);
          sent_ledger_[sequence].access.clear(std::memory_order_release);
        }
        locked_records = 0;
      };

      // Phase one validates the complete block while every named incarnation is locked.
      for (std::size_t index = 0; index < audio_block->report_count; ++index) {
        const auto metric = wire::read_be<std::uint16_t>(audio_block->metrics.subspan(index * 2U, 2));
        const auto received = (metric & 0x8000U) != 0;
        const auto sequence = static_cast<std::uint16_t>(audio_block->begin_sequence + index);
        auto &record = sent_ledger_[sequence];
        while (record.access.test_and_set(std::memory_order_acquire)) {
        }
        ++locked_records;
        const auto serial = record.serial.load(std::memory_order_acquire);
        const auto sent = record.sent_microseconds.load(std::memory_order_relaxed);
        const auto bytes = record.wire_bytes.load(std::memory_order_relaxed);
        const auto state = record.state.load(std::memory_order_relaxed);
        if (index == 0) {
          first_serial = serial;
        }
        const auto prior = state <= audio_feedback_unsent ?
                             static_cast<AudioFeedbackState>(state) :
                             AudioFeedbackState::unsent;
        const auto transition = plan_audio_feedback_transition(
          prior,
          received,
          record.ecn.load(std::memory_order_relaxed) == 3U,
          received && ((metric >> 13U) & 0x03U) == 3U
        );
        auto invalid = state > audio_feedback_unsent || !transition.valid || serial == 0 ||
                       serial != first_serial + index || sent > now_microseconds ||
                       now_microseconds - sent > audio_feedback_freshness_microseconds ||
                       (state == audio_feedback_unsent && bytes != 0);
        if (!invalid && received) {
          const auto ato = static_cast<std::uint16_t>(metric & 0x1fffU);
          if (ato <= 0x1ffdU) {
            const auto arrival = feedback.report_timestamp - static_cast<std::uint32_t>(ato) * 64U;
            if (record.arrival_timestamp_valid.load(std::memory_order_relaxed)) {
              const auto difference = static_cast<std::int32_t>(
                arrival - record.arrival_timestamp.load(std::memory_order_relaxed)
              );
              invalid = difference < -64 || difference > 64;
            }
          }
        }
        if (invalid) {
          unlock_records();
          return false;
        }
      }

      if (!commit) {
        unlock_records();
        return true;
      }

      // Phase two commits only after every metric and ledger incarnation validated.
      for (std::size_t index = 0; index < audio_block->report_count; ++index) {
        const auto metric = wire::read_be<std::uint16_t>(audio_block->metrics.subspan(index * 2U, 2));
        const auto received = (metric & 0x8000U) != 0;
        const auto sequence = static_cast<std::uint16_t>(audio_block->begin_sequence + index);
        auto &record = sent_ledger_[sequence];
        const auto bytes = record.wire_bytes.load(std::memory_order_relaxed);
        const auto prior = static_cast<AudioFeedbackState>(record.state.load(std::memory_order_relaxed));
        const auto transition = plan_audio_feedback_transition(
          prior,
          received,
          record.ecn.load(std::memory_order_relaxed) == 3U,
          received && ((metric >> 13U) & 0x03U) == 3U
        );
        record.state.store(static_cast<std::uint8_t>(transition.next), std::memory_order_relaxed);
        if (received) {
          if (transition.delivered_packets != 0) {
            delivered_wire_bytes_.fetch_add(bytes, std::memory_order_relaxed);
          }
          if (transition.lost_packets < 0) {
            subtract_counter(lost_wire_bytes_, bytes);
          }
          if (transition.upgrade_to_ce) {
            record.ecn.store(3U, std::memory_order_relaxed);
            ecn_ce_wire_bytes_.fetch_add(bytes, std::memory_order_relaxed);
          }
          const auto ato = static_cast<std::uint16_t>(metric & 0x1fffU);
          if (ato <= 0x1ffdU) {
            record.arrival_timestamp.store(
              feedback.report_timestamp - static_cast<std::uint32_t>(ato) * 64U,
              std::memory_order_relaxed
            );
            record.arrival_timestamp_valid.store(true, std::memory_order_relaxed);
          }
        } else if (transition.lost_packets > 0) {
          lost_wire_bytes_.fetch_add(bytes, std::memory_order_relaxed);
        }
        if (transition.retire_in_flight) {
          subtract_counter(bytes_in_flight_, bytes);
        }
      }
      unlock_records();
      last_feedback_timestamp_ = feedback.report_timestamp;
      last_feedback_receive_microseconds_ = now_microseconds;
      has_feedback_timestamp_ = true;
      has_feedback_receive_time_ = true;
      feedback_reports_.fetch_add(1, std::memory_order_relaxed);
      return true;
    }

    bool complete_forward_datagram(
      const std::uint64_t token,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      const auto claimed = apply_forward_completion(
        token,
        completion,
        completed_at_microseconds,
        protected_bytes,
        charged_bytes
      );
      if (claimed) {
        retire_claimed_pending();
      }
      return claimed;
    }

  private:
    struct PendingDatagram;

    /** @brief Replace one audio sequence ledger entry and retire prior unreported bytes. */
    void replace_sent_record(
      const PendingDatagram &pending,
      const std::uint64_t completed_microseconds,
      const std::uint32_t wire_bytes,
      const std::uint8_t state
    ) noexcept {
      auto &record = sent_ledger_[pending.sequence];
      while (record.access.test_and_set(std::memory_order_acquire)) {
      }
      if (record.serial.load(std::memory_order_acquire) != 0 &&
          record.state.load(std::memory_order_relaxed) == audio_feedback_unreported) {
        const auto prior = record.wire_bytes.load(std::memory_order_relaxed);
        auto in_flight = bytes_in_flight_.load(std::memory_order_relaxed);
        while (!bytes_in_flight_.compare_exchange_weak(
          in_flight,
          in_flight > prior ? in_flight - prior : 0,
          std::memory_order_relaxed
        )) {
        }
      }
      record.serial.store(0, std::memory_order_release);
      record.sent_microseconds.store(completed_microseconds, std::memory_order_relaxed);
      record.wire_bytes.store(wire_bytes, std::memory_order_relaxed);
      record.state.store(state, std::memory_order_relaxed);
      record.ecn.store(0, std::memory_order_relaxed);
      record.arrival_timestamp.store(0, std::memory_order_relaxed);
      record.arrival_timestamp_valid.store(false, std::memory_order_relaxed);
      if (state == audio_feedback_unreported) {
        bytes_in_flight_.fetch_add(wire_bytes, std::memory_order_relaxed);
      }
      record.serial.store(pending.packet_serial, std::memory_order_release);
      record.access.clear(std::memory_order_release);
    }

    /** @brief One setup-allocated queue entry and writable Opus transfer slab. */
    struct QueuedPacket {
      std::array<std::uint8_t, audio::AudioPacketDestination::maximum_encoded_packet_bytes> payload {};  ///< Fixed Opus bytes.
      steady_clock::time_point enqueued_at;  ///< Admission time used by the age bound.
      std::uint64_t sample_position {};  ///< Exact 48 kHz first-sample position.
      std::uint64_t incarnation {};  ///< Nonzero slot reuse generation.
      std::size_t payload_bytes {};  ///< Populated leading Opus bytes.
      bool discontinuity {};  ///< Whether the decoder timeline resets before this packet.
    };

    /** @brief Kind of protected datagram awaiting an aggregate-path completion. */
    enum class PendingKind : std::uint8_t {
      rtp,  ///< Opus RTP media packet.
      sender_report,  ///< Periodic SRTCP sender report.
    };

    /** @brief Worker outcome after attempting one queued RTP packet. */
    enum class PacketSendResult : std::uint8_t {
      submitted_or_dropped,  ///< Packet reached one bounded terminal outcome and work may continue.
      stopped,  ///< The aggregate path closed and this sender must stop normally.
      fatal,  ///< SRTP protection prevents continued sending.
    };

    /** @brief Worker outcome after attempting one periodic SRTCP report. */
    enum class ReportSendResult : std::uint8_t {
      submitted,  ///< Report was committed for asynchronous completion.
      deferred,  ///< Current pressure or media timing requires a later attempt.
      fatal,  ///< Report construction or SRTP protection prevents continued sending.
    };

    /** @brief Fixed metadata for one protected datagram awaiting completion. */
    struct PendingDatagram {
      std::uint64_t token {};  ///< Nonzero sender-local completion token.
      std::uint64_t packet_serial {};  ///< RTP sequence incarnation, zero for sender reports.
      std::size_t payload_octets {};  ///< Codec bytes credited only after final send.
      std::uint16_t sequence {};  ///< Protected audio RTP sequence.
      PendingKind kind {PendingKind::rtp};  ///< RTP or periodic SRTCP disposition.
    };

    /**
     * @brief Apply terminal state after claiming its fixed pending entry.
     *
     * The caller must invoke `retire_claimed_pending()` as its final sender
     * access when this method returns `true`.
     *
     * @param token Sender-local committed datagram token.
     * @param completion Final aggregate-path disposition.
     * @param completed_at_microseconds Monotonic terminal time.
     * @param protected_bytes Exact protected UDP payload bytes.
     * @param charged_bytes Complete IP/UDP bytes charged once.
     * @return `true` only when this sender claimed the pending token.
     */
    bool apply_forward_completion(
      const std::uint64_t token,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      (void) protected_bytes;
      const auto pending = claim_pending(token);
      if (!pending) {
        return false;
      }
      if (completion != HostForwardCompletion::sent) {
        if (pending->kind == PendingKind::rtp) {
          replace_sent_record(*pending, completed_at_microseconds, 0, audio_feedback_unsent);
          discontinuity_pending_.store(true, std::memory_order_release);
          if (completion == HostForwardCompletion::expired) {
            expired_packets_.fetch_add(1, std::memory_order_relaxed);
          }
          publish_audio_rtp_terminal(token, completion);
        }
        if (completion == HostForwardCompletion::fatal) {
          fail();
        } else if (completion == HostForwardCompletion::cancelled) {
          close();
        }
        return true;
      }
      if (pending->kind == PendingKind::rtp) {
        replace_sent_record(
          *pending,
          completed_at_microseconds,
          charged_bytes,
          audio_feedback_unreported
        );
        sent_packets_.fetch_add(1, std::memory_order_relaxed);
        sent_payload_octets_.fetch_add(pending->payload_octets, std::memory_order_relaxed);
        rtp_packet_count_.fetch_add(1, std::memory_order_relaxed);
        rtp_octet_count_.fetch_add(static_cast<std::uint32_t>(pending->payload_octets), std::memory_order_relaxed);
        last_media_send_microseconds_.store(completed_at_microseconds, std::memory_order_release);
        publish_audio_rtp_terminal(token, completion);
      } else {
        sender_reports_.fetch_add(1, std::memory_order_relaxed);
      }
      return true;
    }

    /**
     * @brief Dispatch one path completion directly to its exact sender instance.
     *
     * @param context Owning sender implementation retained until pending drain.
     * @param token Sender-local committed datagram token.
     * @param lane Aggregate scheduler lane used by the datagram.
     * @param completion Final aggregate-path disposition.
     * @param completed_at_microseconds Monotonic terminal time.
     * @param protected_bytes Exact protected UDP payload bytes.
     * @param charged_bytes Complete IP/UDP bytes charged once.
     */
    static void forward_completion_callback(
      void *context,
      const std::uint64_t token,
      const HostForwardLane lane,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      const std::size_t protected_bytes,
      const std::uint16_t charged_bytes
    ) noexcept {
      (void) lane;
      auto &self = *static_cast<Impl *>(context);
      if (self.apply_forward_completion(
            token,
            completion,
            completed_at_microseconds,
            protected_bytes,
            charged_bytes
          )) {
        self.retire_claimed_pending();
      }
    }

    /**
     * @brief Drain encoded packets, submit SRTP, and emit periodic SRTCP sender reports.
     *
     * @param stop_token Explicit worker cancellation token.
     */
    void run(const std::stop_token stop_token) noexcept {
      platf::set_thread_name("lsp::audio-send");
      platf::adjust_thread_priority(platf::thread_priority_e::high);

      auto next_report = steady_clock::time_point::max();
      while (!stop_token.stop_requested()) {
        QueuedPacket *queued = nullptr;
        bool report_due = false;
        {
          std::unique_lock lock(mutex_);
          while (!closed_.load(std::memory_order_acquire) && !stop_token.stop_requested()) {
            const auto now = steady_clock::now();
            purge_expired(now);
            if (size_ != 0) {
              head_active_ = true;
              queued = &*queue_[head_];
              break;
            }
            if (media_sent_ && now >= next_report) {
              report_due = true;
              break;
            }
            if (media_sent_) {
              changed_.wait_until(lock, next_report);
            } else {
              changed_.wait(lock);
            }
          }
          if (closed_.load(std::memory_order_acquire) || stop_token.stop_requested()) {
            return;
          }
        }

        if (queued) {
          const auto send_result = send_packet(*queued);
          {
            std::scoped_lock lock(mutex_);
            queue_[head_].reset();
            head_ = (head_ + 1U) % maximum_audio_queue_capacity;
            --size_;
            head_active_ = false;
          }
          changed_.notify_all();
          if (send_result == PacketSendResult::fatal) {
            fail();
            return;
          }
          if (send_result == PacketSendResult::stopped) {
            close();
            return;
          }
        }
        const auto now = steady_clock::now();
        if (media_sent_ && next_report == steady_clock::time_point::max()) {
          next_report = now + std::chrono::microseconds(config_.sender_report_interval_microseconds);
        }
        if (media_sent_ && (report_due || now >= next_report)) {
          const auto report_result = send_sender_report();
          if (report_result == ReportSendResult::fatal) {
            fail();
            return;
          }
          const auto delay = report_result == ReportSendResult::submitted ?
                               config_.sender_report_interval_microseconds :
                               frame_duration_microseconds(config_.frame_samples);
          next_report = now + std::chrono::microseconds(delay);
        }
      }
    }

    /**
     * @brief Build and submit one complete RFC 7587 RTP packet.
     *
     * @param packet Active fixed-slab Opus packet with its original admission time.
     * @return Exact bounded submission, drop, stop, or fatal outcome.
     */
    PacketSendResult send_packet(QueuedPacket &packet) noexcept {
      const auto deadline = packet_deadline_microseconds(packet.enqueued_at);
      const auto now_microseconds = monotonic_microseconds();
      if (now_microseconds >= deadline) {
        expire_media_packet();
        return PacketSendResult::submitted_or_dropped;
      }
      auto lease = config_.forward_path->acquire_until(HostForwardLane::audio, deadline);
      if (!lease) {
        if (config_.forward_path->snapshot().closed) {
          return PacketSendResult::stopped;
        }
        backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        expire_media_packet();
        return PacketSendResult::submitted_or_dropped;
      }
      if (closed_.load(std::memory_order_acquire)) {
        return PacketSendResult::stopped;
      }
      if (monotonic_microseconds() >= deadline) {
        expire_media_packet();
        return PacketSendResult::submitted_or_dropped;
      }

      const auto explicit_discontinuity = discontinuity_pending_.exchange(false, std::memory_order_acq_rel);
      bool marker = !media_sent_ || packet.discontinuity || explicit_discontinuity;
      std::uint32_t timestamp = timestamp_origin_;
      if (!media_sent_) {
        sample_origin_ = packet.sample_position;
      } else if (packet.sample_position < sample_origin_) {
        if (!packet.discontinuity) {
          discontinuity_pending_.store(true, std::memory_order_release);
          malformed_packets_.fetch_add(1, std::memory_order_relaxed);
          return PacketSendResult::submitted_or_dropped;
        }
        timestamp_origin_ = last_rtp_timestamp_ + config_.frame_samples;
        sample_origin_ = packet.sample_position;
        timestamp = timestamp_origin_;
      } else {
        timestamp = timestamp_origin_ + static_cast<std::uint32_t>(packet.sample_position - sample_origin_);
        marker = marker || packet.sample_position != expected_sample_position_;
      }
      const auto opus = std::span<const std::uint8_t> {packet.payload}.first(packet.payload_bytes);
      const media::opus_packetization_config packet_config {
        .stream = {
          .payload_type = config_.payload_type,
          .first_sequence_number = sequence_,
          .timestamp = timestamp,
          .ssrc = config_.ssrc,
        },
        .path = config_.path,
        .marker = marker,
      };
      const auto written = media::write_opus_rtp_packet(opus, packet_config, lease->storage);
      if (!written) {
        discontinuity_pending_.store(true, std::memory_order_release);
        malformed_packets_.fetch_add(1, std::memory_order_relaxed);
        return PacketSendResult::submitted_or_dropped;
      }
      const auto token = register_pending(PendingKind::rtp, opus.size(), sequence_);
      if (token == 0) {
        discontinuity_pending_.store(true, std::memory_order_release);
        backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        return PacketSendResult::submitted_or_dropped;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtp,
            lease->storage,
            written.bytes_written,
            protected_bytes
          )) {
        (void) remove_pending(token);
        discontinuity_pending_.store(true, std::memory_order_release);
        return PacketSendResult::fatal;
      }
      ++sequence_;
      const auto submit_result = config_.forward_path->commit(
        *lease,
        protected_bytes,
        deadline,
        token,
        {.context = this, .completed = forward_completion_callback}
      );
      if (submit_result != HostForwardSubmitResult::accepted) {
        (void) remove_pending(token, true);
        discontinuity_pending_.store(true, std::memory_order_release);
        if (submit_result == HostForwardSubmitResult::closed) {
          return PacketSendResult::stopped;
        }
        if (monotonic_microseconds() >= deadline) {
          expired_packets_.fetch_add(1, std::memory_order_relaxed);
        }
        return PacketSendResult::submitted_or_dropped;
      }
      const auto terminal = wait_for_audio_rtp_terminal(token);
      if (!terminal) {
        return closed_.load(std::memory_order_acquire) ?
                 PacketSendResult::stopped :
                 PacketSendResult::fatal;
      }
      if (*terminal != HostForwardCompletion::sent) {
        return *terminal == HostForwardCompletion::fatal ?
                 PacketSendResult::fatal :
                 PacketSendResult::submitted_or_dropped;
      }
      expected_sample_position_ = packet.sample_position + config_.frame_samples;
      last_rtp_timestamp_ = timestamp;
      media_sent_ = true;
      return PacketSendResult::submitted_or_dropped;
    }

    /** @brief Publish one exact audio RTP terminal result for the completion-ordered worker. */
    void publish_audio_rtp_terminal(
      const std::uint64_t token,
      const HostForwardCompletion completion
    ) noexcept {
      if ((token & audio_completion_namespace_mask) != audio_completion_namespace) {
        return;
      }
      {
        std::scoped_lock lock(pending_mutex_);
        completed_rtp_token_ = token;
        completed_rtp_result_ = completion;
      }
      pending_changed_.notify_all();
    }

    /** @brief Wait for the sole ordered audio RTP completion before constructing the next packet. */
    [[nodiscard]] std::optional<HostForwardCompletion> wait_for_audio_rtp_terminal(
      const std::uint64_t token
    ) noexcept {
      std::unique_lock lock(pending_mutex_);
      pending_changed_.wait(lock, [this, token]() {
        return completed_rtp_token_ == token || closed_.load(std::memory_order_acquire) ||
               failed_.load(std::memory_order_acquire);
      });
      if (completed_rtp_token_ != token) {
        return std::nullopt;
      }
      const auto result = completed_rtp_result_;
      completed_rtp_token_ = 0;
      return result;
    }

    /**
     * @brief Build and submit one report-block-free RFC 3550 sender report.
     *
     * @return Exact submission, pressure deferral, or fatal outcome.
     */
    ReportSendResult send_sender_report() noexcept {
      const auto ntp = current_ntp_timestamp();
      const auto now_microseconds = monotonic_microseconds();
      const auto last_media_send = last_media_send_microseconds_.load(std::memory_order_acquire);
      if (last_media_send == 0 || now_microseconds < last_media_send) {
        return ReportSendResult::deferred;
      }
      const auto elapsed_microseconds = now_microseconds - last_media_send;
      const auto projected_ticks = elapsed_microseconds * media::audio_clock_rate / 1'000'000ULL;
      const transport::sender_report report {
        .sender_ssrc = config_.ssrc,
        .ntp_seconds = ntp.seconds,
        .ntp_fraction = ntp.fraction,
        .rtp_timestamp = last_rtp_timestamp_ + static_cast<std::uint32_t>(projected_ticks),
        .packet_count = rtp_packet_count_.load(std::memory_order_relaxed),
        .octet_count = rtp_octet_count_.load(std::memory_order_relaxed),
      };
      auto lease = config_.forward_path->acquire(HostForwardLane::audio);
      if (!lease) {
        if (config_.forward_path->snapshot().closed) {
          close();
        }
        return ReportSendResult::deferred;
      }
      const auto written = transport::write_sender_report(report, lease->storage);
      if (!written) {
        return ReportSendResult::fatal;
      }
      const auto sdes_bytes = transport::write_sdes_cname(
        config_.ssrc,
        config_.rtcp_cname.view(),
        lease->storage.subspan(written.bytes_written)
      );
      if (sdes_bytes == 0) {
        return ReportSendResult::fatal;
      }
      const auto compound_bytes = written.bytes_written + sdes_bytes;
      const auto token = register_pending(PendingKind::sender_report, 0);
      if (token == 0) {
        return ReportSendResult::deferred;
      }
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtcp,
            lease->storage,
            compound_bytes,
            protected_bytes
          )) {
        (void) remove_pending(token);
        return ReportSendResult::fatal;
      }
      const auto deadline = now_microseconds > std::numeric_limits<std::uint64_t>::max() - 20'000U ?
                              std::numeric_limits<std::uint64_t>::max() :
                              now_microseconds + 20'000U;
      const auto submit_result = config_.forward_path->commit(
        *lease,
        protected_bytes,
        deadline,
        token,
        {.context = this, .completed = forward_completion_callback}
      );
      if (submit_result != HostForwardSubmitResult::accepted) {
        (void) remove_pending(token);
        if (submit_result == HostForwardSubmitResult::closed) {
          close();
        }
        return ReportSendResult::deferred;
      }
      return ReportSendResult::submitted;
    }

    /** @brief Reserve one namespaced completion token before consuming an SRTP index. */
    [[nodiscard]] std::uint64_t register_pending(
      const PendingKind kind,
      const std::size_t payload_octets,
      const std::uint16_t sequence = 0
    ) noexcept {
      std::scoped_lock lock(pending_mutex_);
      for (std::size_t index = 0; index < pending_.size(); ++index) {
        auto &pending = pending_[index];
        if (pending.token != 0) {
          continue;
        }
        auto generation = next_completion_generation_++ & pending_generation_mask;
        if (generation == 0) {
          generation = next_completion_generation_++ & pending_generation_mask;
        }
        const auto token = audio_completion_namespace | (generation << pending_slot_bits) | index;
        auto packet_serial = std::uint64_t {0};
        if (kind == PendingKind::rtp) {
          packet_serial = next_packet_serial_.fetch_add(1, std::memory_order_relaxed);
          if (packet_serial == 0) {
            packet_serial = next_packet_serial_.fetch_add(1, std::memory_order_relaxed);
          }
        }
        pending = {
          .token = token,
          .packet_serial = packet_serial,
          .payload_octets = payload_octets,
          .sequence = sequence,
          .kind = kind,
        };
        ++pending_count_;
        return token;
      }
      return 0;
    }

    /** @brief Claim sender-local metadata in constant time without ending callback ownership. */
    [[nodiscard]] std::optional<PendingDatagram> claim_pending(const std::uint64_t token) noexcept {
      if ((token & audio_completion_namespace_mask) != audio_completion_namespace) {
        return std::nullopt;
      }
      std::scoped_lock lock(pending_mutex_);
      auto &pending = pending_[token & pending_slot_mask];
      if (pending.token != token) {
        return std::nullopt;
      }
      const auto result = pending;
      pending = {};
      return result;
    }

    /** @brief Release one claimed callback as the callback's final sender access. */
    void retire_claimed_pending() noexcept {
      {
        std::scoped_lock lock(pending_mutex_);
        if (pending_count_ != 0) {
          --pending_count_;
        }
      }
      pending_changed_.notify_all();
    }

    /** @brief Remove an uncommitted token and release its pending-drain ownership. */
    [[nodiscard]] bool remove_pending(
      const std::uint64_t token,
      const bool tombstone = false
    ) noexcept {
      const auto pending = claim_pending(token);
      if (!pending) {
        return false;
      }
      if (tombstone && pending->kind == PendingKind::rtp) {
        replace_sent_record(*pending, monotonic_microseconds(), 0, audio_feedback_unsent);
      }
      retire_claimed_pending();
      return true;
    }

    /**
     * @brief Derive the one immutable aggregate-path deadline from queue admission.
     *
     * @param enqueued_at Original bounded-queue admission timestamp.
     * @return Saturated absolute monotonic deadline in whole microseconds.
     */
    [[nodiscard]] std::uint64_t packet_deadline_microseconds(
      const steady_clock::time_point enqueued_at
    ) const noexcept {
      const auto raw = std::chrono::duration_cast<std::chrono::microseconds>(enqueued_at.time_since_epoch()).count();
      const auto admitted = raw > 0 ? static_cast<std::uint64_t>(raw) : 0;
      return admitted > std::numeric_limits<std::uint64_t>::max() - config_.maximum_queue_age_microseconds ?
               std::numeric_limits<std::uint64_t>::max() :
               admitted + config_.maximum_queue_age_microseconds;
    }

    /** @brief Record one bounded media expiry and require a marker on the next committed packet. */
    void expire_media_packet() noexcept {
      expired_packets_.fetch_add(1, std::memory_order_relaxed);
      discontinuity_pending_.store(true, std::memory_order_release);
    }

    /**
     * @brief Remove stale head packets until the queue satisfies its age bound.
     *
     * @param now Current monotonic time while holding `mutex_`.
     */
    void purge_expired(const steady_clock::time_point now) noexcept {
      const auto maximum_age = std::chrono::microseconds(config_.maximum_queue_age_microseconds);
      while (!head_active_ && size_ != 0 && now - queue_[head_]->enqueued_at >= maximum_age) {
        queue_[head_].reset();
        head_ = (head_ + 1) % maximum_audio_queue_capacity;
        --size_;
        expire_media_packet();
      }
    }

    /** @brief Destroy every retained packet while holding `mutex_`. */
    void clear_queue() noexcept {
      while (size_ != 0) {
        queue_[head_].reset();
        head_ = (head_ + 1) % maximum_audio_queue_capacity;
        --size_;
      }
    }

    /** @brief Record a fatal send failure, close admission, and discard queued media. */
    void fail() noexcept {
      if (!failed_.exchange(true, std::memory_order_acq_rel)) {
        send_failures_.fetch_add(1, std::memory_order_relaxed);
      }
      closed_.store(true, std::memory_order_release);
      worker_.request_stop();
      changed_.notify_all();
    }

    HostAudioSenderConfig config_;  ///< Immutable negotiated source configuration.
    LibsrtpServerProvider &srtp_;  ///< Association provider that outlives the joined sender.
    std::array<std::optional<QueuedPacket>, maximum_audio_queue_capacity> queue_ {};  ///< Fixed encoded-packet ring.
    std::array<std::uint64_t, maximum_audio_queue_capacity> slab_incarnations_ {};  ///< Fixed-slab reuse generations.
    std::size_t head_ {};  ///< Oldest occupied ring index.
    std::size_t size_ {};  ///< Current occupied ring entries.
    std::size_t reservation_slot_ {};  ///< Sole encoder-owned writable slab slot.
    bool reservation_active_ {};  ///< Whether the encoder currently writes one fixed slab.
    bool head_active_ {};  ///< Whether the worker reads the current head slab without the mutex.
    std::mutex mutex_;  ///< Protects fixed queue and close transitions.
    std::condition_variable changed_;  ///< Wakes the sender for packets, reports, or close.
    std::jthread worker_;  ///< Dedicated high-priority RTP/SRTP sender.
    std::array<PendingDatagram, maximum_pending_datagrams> pending_ {};  ///< Bounded async path-completion metadata.
    std::mutex pending_mutex_;  ///< Serializes producer registration with path completion.
    std::condition_variable pending_changed_;  ///< Wakes destruction after the final direct callback retires.
    std::size_t pending_count_ {};  ///< Committed or callback-owned pending entries.
    std::uint64_t next_completion_generation_ {1};  ///< Next nonzero fixed-slot token incarnation.
    std::uint64_t completed_rtp_token_ {};  ///< Latest exact ordered RTP terminal result.
    HostForwardCompletion completed_rtp_result_ {HostForwardCompletion::cancelled};  ///< Matching terminal disposition.
    std::uint16_t sequence_ {};  ///< Next RTP sequence number.
    std::uint32_t timestamp_origin_ {};  ///< RTP timestamp corresponding to `sample_origin_`.
    std::uint64_t sample_origin_ {};  ///< First sample position in the current monotonic mapping.
    std::uint64_t expected_sample_position_ {};  ///< Next contiguous first-sample position.
    std::uint32_t last_rtp_timestamp_ {};  ///< Timestamp of the last successfully submitted RTP packet.
    std::atomic_bool discontinuity_pending_ {};  ///< Whether the next committed RTP packet requires a marker.
    std::atomic_uint64_t last_media_send_microseconds_ {};  ///< Actual final-send time of the latest RTP packet.
    std::atomic_uint32_t rtp_packet_count_ {};  ///< Final-sent RFC 3550 packet count modulo 2^32.
    std::atomic_uint32_t rtp_octet_count_ {};  ///< Final-sent RFC 3550 payload-octet count modulo 2^32.
    bool media_sent_ {};  ///< Whether the sender has established its sample origin.
    bool ready_ {};  ///< Whether immutable configuration passed validation.
    std::atomic_bool started_ {};  ///< Whether the worker was started successfully.
    std::atomic_bool closed_ {true};  ///< Whether packet admission is closed.
    std::atomic_bool failed_ {};  ///< Whether SRTP protection or submission terminated the worker.
    std::atomic_uint64_t enqueued_packets_ {};  ///< Accepted packet count.
    std::atomic_uint64_t sent_packets_ {};  ///< Submitted RTP packet count.
    std::atomic_uint64_t sent_payload_octets_ {};  ///< Submitted Opus payload bytes.
    std::atomic_uint64_t expired_packets_ {};  ///< Age-expired queued packet count.
    std::atomic_uint64_t backpressure_events_ {};  ///< Nonblocking enqueue rejection count.
    std::atomic_uint64_t malformed_packets_ {};  ///< Invalid packet or timeline count.
    std::atomic_uint64_t send_failures_ {};  ///< Fatal SRTP/socket submission count.
    std::atomic_uint64_t sender_reports_ {};  ///< Submitted SRTCP sender-report count.
    std::array<AudioSentRecord, 65'536> sent_ledger_ {};  ///< Independent audio sequence feedback ledger.
    std::atomic_uint64_t next_packet_serial_ {1};  ///< Next nonzero audio sequence incarnation.
    std::atomic_uint64_t bytes_in_flight_ {};  ///< Unreported complete IP audio bytes.
    std::atomic_uint64_t delivered_wire_bytes_ {};  ///< Newly reported delivered audio bytes.
    std::atomic_uint64_t lost_wire_bytes_ {};  ///< Current reported loss after overlap corrections.
    std::atomic_uint64_t ecn_ce_wire_bytes_ {};  ///< Newly reported CE-marked audio bytes.
    std::atomic_uint64_t feedback_reports_ {};  ///< Accepted RFC 8888 audio block count.
    std::mutex feedback_mutex_;  ///< Serializes report cadence, overlap validation, and atomic block commit.
    std::uint64_t last_feedback_receive_microseconds_ {};  ///< Local cadence origin for accepted audio blocks.
    std::uint32_t last_feedback_timestamp_ {};  ///< Latest accepted RFC 8888 middle-NTP RTS.
    bool has_feedback_receive_time_ {};  ///< Whether the local cadence has an origin.
    bool has_feedback_timestamp_ {};  ///< Whether RTS monotonicity has an origin.
  };

  HostAudioSender::HostAudioSender(
    HostAudioSenderConfig config,
    LibsrtpServerProvider &srtp
  ) noexcept:
      impl_ {new(std::nothrow) Impl {std::move(config), srtp}} {
  }

  HostAudioSender::~HostAudioSender() = default;

  bool HostAudioSender::start() noexcept {
    return impl_ && impl_->start();
  }

  audio::AudioPacketDestination::enqueue_result_e HostAudioSender::enqueue(audio::packet_t packet) {
    return impl_ ? impl_->enqueue(std::move(packet)) : enqueue_result_e::closed;
  }

  std::optional<audio::AudioPacketDestination::packet_write_lease_t> HostAudioSender::acquire_packet_storage() noexcept {
    return impl_ ? impl_->acquire_packet_storage() : std::nullopt;
  }

  bool HostAudioSender::requires_fixed_packet_storage() const noexcept {
    return true;
  }

  audio::AudioPacketDestination::enqueue_result_e HostAudioSender::commit_packet_storage(
    const packet_write_lease_t &lease,
    const std::size_t payload_bytes,
    const std::uint64_t sample_position,
    const bool discontinuity
  ) noexcept {
    return impl_ ?
             impl_->commit_packet_storage(lease, payload_bytes, sample_position, discontinuity) :
             enqueue_result_e::closed;
  }

  void HostAudioSender::cancel_packet_storage(const packet_write_lease_t &lease) noexcept {
    if (impl_) {
      impl_->cancel_packet_storage(lease);
    }
  }

  void HostAudioSender::close() noexcept {
    if (impl_) {
      impl_->close();
    }
  }

  void HostAudioSender::join() noexcept {
    if (impl_) {
      impl_->join();
    }
  }

  bool HostAudioSender::ready() const noexcept {
    return impl_ && impl_->ready();
  }

  HostAudioSenderSnapshot HostAudioSender::snapshot() const noexcept {
    return impl_ ? impl_->snapshot() : HostAudioSenderSnapshot {.closed = true};
  }

  bool HostAudioSender::receive_congestion_feedback(
    const std::span<const std::uint8_t> packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_congestion_feedback(packet, now_microseconds);
  }

  bool HostAudioSender::validate_congestion_feedback(
    const transport::congestion_feedback_packet_view &packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->validate_congestion_feedback(packet, now_microseconds);
  }

  std::optional<AudioCongestionFeedbackPreview> HostAudioSender::preview_congestion_feedback(
    const transport::congestion_feedback_packet_view &packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ ? impl_->preview_congestion_feedback(packet, now_microseconds) : std::nullopt;
  }

  bool HostAudioSender::commit_congestion_feedback(
    const AudioCongestionFeedbackPreview &preview
  ) noexcept {
    return impl_ && impl_->commit_congestion_feedback(preview);
  }

  bool HostAudioSender::receive_congestion_feedback(
    const transport::congestion_feedback_packet_view &packet,
    const std::uint64_t now_microseconds
  ) noexcept {
    return impl_ && impl_->receive_congestion_feedback(packet, now_microseconds);
  }

  bool HostAudioSender::complete_forward_datagram(
    const std::uint64_t token,
    const HostForwardCompletion completion,
    const std::uint64_t completed_at_microseconds,
    const std::size_t protected_bytes,
    const std::uint16_t charged_bytes
  ) noexcept {
    return impl_ && impl_->complete_forward_datagram(
                      token,
                      completion,
                      completed_at_microseconds,
                      protected_bytes,
                      charged_bytes
                    );
  }
}  // namespace lumen::lsp::runtime
