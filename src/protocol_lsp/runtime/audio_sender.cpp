/**
 * @file src/protocol_lsp/runtime/audio_sender.cpp
 * @brief Production LSP host-audio RTP/SRTP sender implementation.
 */

#include "audio_sender.h"

#include "../transport/rtcp.h"

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
    return peer.valid() && ssrc != 0 && media::valid_dynamic_payload_type(payload_type) &&
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

    /** @brief Close and join the worker before releasing retained packets. */
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
      if (!started_.load(std::memory_order_acquire) || closed_.load(std::memory_order_acquire)) {
        return audio::AudioPacketDestination::enqueue_result_e::closed;
      }
      const auto maximum_codec_payload = config_.path.plaintext_rtp_capacity() - rtp_fixed_header_size;
      if (packet.payload.size() == 0 || packet.payload.size() > media::maximum_opus_packet_size ||
          packet.payload.size() > maximum_codec_payload ||
          packet.sample_position > std::numeric_limits<std::uint64_t>::max() - config_.frame_samples) {
        malformed_packets_.fetch_add(1, std::memory_order_relaxed);
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }

      std::unique_lock lock(mutex_, std::try_to_lock);
      if (!lock.owns_lock()) {
        backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      if (closed_.load(std::memory_order_acquire)) {
        return audio::AudioPacketDestination::enqueue_result_e::closed;
      }
      const auto now = steady_clock::now();
      purge_expired(now);
      if (size_ >= config_.queue_capacity) {
        backpressure_events_.fetch_add(1, std::memory_order_relaxed);
        return audio::AudioPacketDestination::enqueue_result_e::backpressure;
      }
      const auto tail = (head_ + size_) % maximum_audio_queue_capacity;
      queue_[tail].emplace(QueuedPacket {
        .packet = std::move(packet),
        .enqueued_at = now,
      });
      ++size_;
      enqueued_packets_.fetch_add(1, std::memory_order_relaxed);
      lock.unlock();
      changed_.notify_one();
      return audio::AudioPacketDestination::enqueue_result_e::enqueued;
    }

    /** @brief Stop packet admission, discard queued media, and wake the worker. */
    void close() noexcept {
      if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
      }
      {
        std::scoped_lock lock(mutex_);
        clear_queue();
      }
      worker_.request_stop();
      changed_.notify_all();
    }

    /** @brief Join the stopped worker unless called from that worker itself. */
    void join() noexcept {
      if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id()) {
        worker_.join();
      }
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
        .started = started_.load(std::memory_order_acquire),
        .closed = closed_.load(std::memory_order_acquire),
        .failed = failed_.load(std::memory_order_acquire),
      };
    }

  private:
    /** @brief One queue entry retaining an encoded Opus packet and its age origin. */
    struct QueuedPacket {
      audio::packet_t packet;  ///< Move-owned encoded packet and sample position.
      steady_clock::time_point enqueued_at;  ///< Admission time used by the age bound.
    };

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
        std::optional<QueuedPacket> queued;
        bool report_due = false;
        {
          std::unique_lock lock(mutex_);
          while (!closed_.load(std::memory_order_acquire) && !stop_token.stop_requested()) {
            const auto now = steady_clock::now();
            purge_expired(now);
            if (size_ != 0) {
              queued = pop();
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

        if (queued && !send_packet(std::move(queued->packet))) {
          fail();
          return;
        }
        const auto now = steady_clock::now();
        if (queued && next_report == steady_clock::time_point::max()) {
          next_report = now + std::chrono::microseconds(config_.sender_report_interval_microseconds);
        }
        if (media_sent_ && (report_due || now >= next_report)) {
          if (!send_sender_report(now)) {
            fail();
            return;
          }
          next_report = now + std::chrono::microseconds(config_.sender_report_interval_microseconds);
        }
      }
    }

    /**
     * @brief Build and submit one complete RFC 7587 RTP packet.
     *
     * @param packet Move-owned encoded Opus packet.
     * @return `false` only for a fatal SRTP or socket submission failure.
     */
    bool send_packet(audio::packet_t packet) noexcept {
      bool marker = !media_sent_ || packet.discontinuity;
      std::uint32_t timestamp = timestamp_origin_;
      if (!media_sent_) {
        sample_origin_ = packet.sample_position;
      } else if (packet.sample_position < sample_origin_) {
        if (!packet.discontinuity) {
          malformed_packets_.fetch_add(1, std::memory_order_relaxed);
          return true;
        }
        timestamp_origin_ = last_rtp_timestamp_ + config_.frame_samples;
        sample_origin_ = packet.sample_position;
        timestamp = timestamp_origin_;
      } else {
        timestamp = timestamp_origin_ + static_cast<std::uint32_t>(packet.sample_position - sample_origin_);
        marker = marker || packet.sample_position != expected_sample_position_;
      }
      const auto opus = std::span<const std::uint8_t> {packet.payload.begin(), packet.payload.size()};
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
      const auto written = media::write_opus_rtp_packet(opus, packet_config, rtp_storage_);
      if (!written) {
        malformed_packets_.fetch_add(1, std::memory_order_relaxed);
        return true;
      }
      if (!srtp_.protect_and_send(
            config_.peer,
            SecurePacketClass::rtp,
            std::span<const std::uint8_t> {rtp_storage_.data(), written.bytes_written}
          )) {
        return false;
      }

      ++sequence_;
      expected_sample_position_ = packet.sample_position + config_.frame_samples;
      last_rtp_timestamp_ = timestamp;
      last_media_send_ = steady_clock::now();
      media_sent_ = true;
      ++rtp_packet_count_;
      rtp_octet_count_ += static_cast<std::uint32_t>(opus.size());
      sent_packets_.fetch_add(1, std::memory_order_relaxed);
      sent_payload_octets_.fetch_add(opus.size(), std::memory_order_relaxed);
      return true;
    }

    /**
     * @brief Build and submit one report-block-free RFC 3550 sender report.
     *
     * @param now Monotonic report time corresponding to the projected RTP timestamp.
     * @return `true` only after successful SRTCP submission.
     */
    bool send_sender_report(const steady_clock::time_point now) noexcept {
      const auto ntp = current_ntp_timestamp();
      const auto elapsed_microseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now - last_media_send_).count()
      );
      const auto projected_ticks = elapsed_microseconds * media::audio_clock_rate / 1'000'000ULL;
      const transport::sender_report report {
        .sender_ssrc = config_.ssrc,
        .ntp_seconds = ntp.seconds,
        .ntp_fraction = ntp.fraction,
        .rtp_timestamp = last_rtp_timestamp_ + static_cast<std::uint32_t>(projected_ticks),
        .packet_count = rtp_packet_count_,
        .octet_count = rtp_octet_count_,
      };
      const auto written = transport::write_sender_report(report, rtcp_storage_);
      if (!written || !srtp_.protect_and_send(
                        config_.peer,
                        SecurePacketClass::rtcp,
                        std::span<const std::uint8_t> {rtcp_storage_.data(), written.bytes_written}
                      )) {
        return false;
      }
      sender_reports_.fetch_add(1, std::memory_order_relaxed);
      return true;
    }

    /**
     * @brief Remove stale head packets until the queue satisfies its age bound.
     *
     * @param now Current monotonic time while holding `mutex_`.
     */
    void purge_expired(const steady_clock::time_point now) noexcept {
      const auto maximum_age = std::chrono::microseconds(config_.maximum_queue_age_microseconds);
      while (size_ != 0 && now - queue_[head_]->enqueued_at >= maximum_age) {
        queue_[head_].reset();
        head_ = (head_ + 1) % maximum_audio_queue_capacity;
        --size_;
        expired_packets_.fetch_add(1, std::memory_order_relaxed);
      }
    }

    /**
     * @brief Move the oldest packet out of the nonempty queue.
     *
     * @return Oldest queue entry while holding `mutex_`.
     */
    [[nodiscard]] QueuedPacket pop() noexcept {
      auto packet = std::move(*queue_[head_]);
      queue_[head_].reset();
      head_ = (head_ + 1) % maximum_audio_queue_capacity;
      --size_;
      return packet;
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
      send_failures_.fetch_add(1, std::memory_order_relaxed);
      failed_.store(true, std::memory_order_release);
      closed_.store(true, std::memory_order_release);
      std::scoped_lock lock(mutex_);
      clear_queue();
      changed_.notify_all();
    }

    HostAudioSenderConfig config_;  ///< Immutable negotiated source configuration.
    LibsrtpServerProvider &srtp_;  ///< Association provider that outlives the joined sender.
    std::array<std::optional<QueuedPacket>, maximum_audio_queue_capacity> queue_ {};  ///< Fixed encoded-packet ring.
    std::size_t head_ {};  ///< Oldest occupied ring index.
    std::size_t size_ {};  ///< Current occupied ring entries.
    std::mutex mutex_;  ///< Protects fixed queue and close transitions.
    std::condition_variable changed_;  ///< Wakes the sender for packets, reports, or close.
    std::jthread worker_;  ///< Dedicated high-priority RTP/SRTP sender.
    std::array<std::uint8_t, media::ipv4_udp_payload_ceiling - media::srtp_aead_tag_size> rtp_storage_ {};  ///< Caller-owned plaintext RTP storage.
    std::array<std::uint8_t, 28> rtcp_storage_ {};  ///< Caller-owned report-block-free SR storage.
    std::uint16_t sequence_ {};  ///< Next RTP sequence number.
    std::uint32_t timestamp_origin_ {};  ///< RTP timestamp corresponding to `sample_origin_`.
    std::uint64_t sample_origin_ {};  ///< First sample position in the current monotonic mapping.
    std::uint64_t expected_sample_position_ {};  ///< Next contiguous first-sample position.
    std::uint32_t last_rtp_timestamp_ {};  ///< Timestamp of the last successfully submitted RTP packet.
    steady_clock::time_point last_media_send_ {};  ///< Monotonic submission time of the last media packet.
    std::uint32_t rtp_packet_count_ {};  ///< RFC 3550 packet count modulo 2^32.
    std::uint32_t rtp_octet_count_ {};  ///< RFC 3550 payload-octet count modulo 2^32.
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
  };

  HostAudioSender::HostAudioSender(
    HostAudioSenderConfig config,
    LibsrtpServerProvider &srtp
  ) noexcept:
      impl_ {new (std::nothrow) Impl {std::move(config), srtp}} {
  }

  HostAudioSender::~HostAudioSender() = default;

  bool HostAudioSender::start() noexcept {
    return impl_ && impl_->start();
  }

  audio::AudioPacketDestination::enqueue_result_e HostAudioSender::enqueue(audio::packet_t packet) {
    return impl_ ? impl_->enqueue(std::move(packet)) : enqueue_result_e::closed;
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
}  // namespace lumen::lsp::runtime
