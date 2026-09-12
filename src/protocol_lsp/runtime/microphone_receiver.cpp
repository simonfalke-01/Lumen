/**
 * @file src/protocol_lsp/runtime/microphone_receiver.cpp
 * @brief Authenticated LSP reverse-microphone receiver implementation.
 */

#include "microphone_receiver.h"

#include "../core/rtp.h"
#include "../core/wire.h"
#include "../transport/rtcp.h"
#include "host_congestion_feedback.h"
#include "udp_socket.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

namespace lumen::lsp::runtime {
  namespace {
    /** @brief Return the current middle 32 bits of the wall-clock NTP timestamp. */
    std::uint32_t current_middle_ntp() noexcept {
      constexpr std::uint64_t ntp_unix_epoch_seconds = 2'208'988'800ULL;
      const auto elapsed = std::chrono::system_clock::now().time_since_epoch();
      const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed);
      const auto fraction = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed - seconds);
      const auto ntp_seconds = static_cast<std::uint64_t>(seconds.count()) + ntp_unix_epoch_seconds;
      const auto ntp_fraction = static_cast<std::uint64_t>(fraction.count()) * (std::uint64_t {1} << 32U) /
                                1'000'000'000ULL;
      return static_cast<std::uint32_t>((ntp_seconds << 16U) | (ntp_fraction >> 16U));
    }

    /** @brief Map an authenticated socket observation into RFC 8888's two-bit field. */
    transport::ecn_mark feedback_ecn(const IpEcn ecn) noexcept {
      switch (ecn) {
        case IpEcn::ect_0:
          return transport::ecn_mark::ect0;
        case IpEcn::ect_1:
          return transport::ecn_mark::ect1;
        case IpEcn::congestion_experienced:
          return transport::ecn_mark::congestion_experienced;
        case IpEcn::not_ect:
        case IpEcn::unavailable:
          return transport::ecn_mark::not_ect;
      }
      return transport::ecn_mark::not_ect;
    }
  }  // namespace

  std::size_t write_microphone_compound_report(
    const std::span<std::uint8_t> destination,
    const std::uint32_t feedback_ssrc,
    const MicrophoneReceiverReportState &report,
    const std::span<const std::uint8_t> cname
  ) noexcept {
    if (feedback_ssrc == 0 || report.media_ssrc == 0 || report.media_ssrc == feedback_ssrc ||
        cname.empty() || cname.size() > 255U || destination.size() < 32U) {
      return 0;
    }
    auto rr = destination.first<32>();
    std::ranges::fill(rr, 0);
    rr[0] = 0x81U;
    rr[1] = transport::rtcp_receiver_report_type;
    wire::write_be<std::uint16_t>(rr.subspan<2, 2>(), 7);
    wire::write_be<std::uint32_t>(rr.subspan<4, 4>(), feedback_ssrc);
    wire::write_be<std::uint32_t>(rr.subspan<8, 4>(), report.media_ssrc);
    rr[12] = report.fraction_lost;
    const auto cumulative = static_cast<std::uint32_t>(report.cumulative_lost) & 0x00ff'ffffU;
    rr[13] = static_cast<std::uint8_t>(cumulative >> 16U);
    rr[14] = static_cast<std::uint8_t>(cumulative >> 8U);
    rr[15] = static_cast<std::uint8_t>(cumulative);
    wire::write_be<std::uint32_t>(rr.subspan<16, 4>(), report.extended_highest_sequence);
    wire::write_be<std::uint32_t>(rr.subspan<20, 4>(), report.interarrival_jitter);
    wire::write_be<std::uint32_t>(rr.subspan<24, 4>(), report.last_sender_report);
    wire::write_be<std::uint32_t>(rr.subspan<28, 4>(), report.delay_since_sender_report);
    const auto sdes = transport::write_sdes_cname(feedback_ssrc, cname, destination.subspan(rr.size()));
    return sdes == 0 ? 0 : rr.size() + sdes;
  }

  std::size_t write_microphone_compound_report(
    const std::span<std::uint8_t> destination,
    const std::uint32_t feedback_ssrc
  ) noexcept {
    constexpr std::array<std::uint8_t, 16> cname {
      'l',
      'u',
      'm',
      'e',
      'n',
      '-',
      'm',
      'i',
      'c',
      'r',
      'o',
      'p',
      'h',
      'o',
      'n',
      'e'
    };
    return write_microphone_compound_report(
      destination,
      feedback_ssrc,
      {.media_ssrc = feedback_ssrc == std::numeric_limits<std::uint32_t>::max() ? 1U : feedback_ssrc + 1U},
      cname
    );
  }

  std::size_t write_microphone_congestion_report(
    const std::span<std::uint8_t> destination,
    const std::uint32_t feedback_ssrc,
    const std::uint32_t microphone_ssrc,
    const std::uint16_t sequence,
    const std::uint32_t report_timestamp
  ) noexcept {
    if (feedback_ssrc == 0 || microphone_ssrc == 0 || feedback_ssrc == microphone_ssrc ||
        destination.size() < 24U) {
      return 0;
    }
    auto packet = destination.first<24>();
    std::ranges::fill(packet, 0);
    packet[0] = static_cast<std::uint8_t>(0x80U | transport::rtcp_congestion_feedback_format);
    packet[1] = transport::rtcp_transport_feedback_type;
    wire::write_be<std::uint16_t>(packet.subspan<2, 2>(), 5);
    wire::write_be<std::uint32_t>(packet.subspan<4, 4>(), feedback_ssrc);
    wire::write_be<std::uint32_t>(packet.subspan<8, 4>(), microphone_ssrc);
    wire::write_be<std::uint16_t>(packet.subspan<12, 2>(), sequence);
    wire::write_be<std::uint16_t>(packet.subspan<14, 2>(), 1);
    wire::write_be<std::uint16_t>(packet.subspan<16, 2>(), 0x8000U);
    wire::write_be<std::uint32_t>(packet.subspan<20, 4>(), report_timestamp);
    return packet.size();
  }

  std::size_t write_microphone_congestion_report(
    const std::span<std::uint8_t> destination,
    const std::uint32_t feedback_ssrc,
    const transport::reordering_congestion_report_batch &batch,
    const std::uint32_t report_timestamp
  ) noexcept {
    return write_host_congestion_report(destination, feedback_ssrc, batch, report_timestamp);
  }

  bool MicrophoneReceiverConfig::valid() const noexcept {
    return peer.valid() && generation != 0 && ssrc != 0 && payload_type >= 96 && payload_type <= 127 &&
           clock_rate == client_microphone::SAMPLE_RATE && channels == client_microphone::CHANNEL_COUNT &&
           frame_samples == client_microphone::SAMPLES_PER_FRAME && forward_path && forward_path->ready() &&
           forward_path_generation != 0 && forward_path->generation() == forward_path_generation &&
           feedback_ssrc != 0 && feedback_ssrc != ssrc && rtcp_cname.valid();
  }

  /** @brief Hidden generation-qualified writer, sequence, decoder, and sink state. */
  class LspMicrophoneReceiver::Impl {
  public:
    /**
     * @brief Retain an already started receiver and its exact writer ownership.
     *
     * @param config Exact acknowledged mapping.
     * @param srtp Installed association provider.
     * @param owner Claimed LSP writer identity.
     * @param sink Owned platform sink.
     * @param receiver Started clocked receiver borrowing `sink`.
     */
    Impl(
      MicrophoneReceiverConfig config,
      LibsrtpServerProvider &srtp,
      const client_microphone::writer_owner_t owner,
      std::unique_ptr<client_microphone::sink_t> sink,
      std::unique_ptr<client_microphone::clocked_receiver_t> receiver
    ) noexcept:
        config_(std::move(config)),
        srtp_(srtp),
        owner_(owner),
        sink_(std::move(sink)),
        receiver_(std::move(receiver)),
        active_(true) {
      feedback_window_.reset(config_.ssrc, monotonic_microseconds());
    }

    /** @brief Stop and release all exact generation ownership. */
    ~Impl() {
      shutdown();
    }

    /**
     * @brief Expand a 16-bit RTP sequence around the greatest accepted sequence.
     *
     * @param sequence Wire RTP sequence.
     * @return Monotonic sequence suitable for the bounded receiver.
     */
    std::uint64_t expand_sequence(const std::uint16_t sequence) noexcept {
      if (!sequence_initialized_) {
        sequence_initialized_ = true;
        highest_sequence_ = sequence;
        return highest_sequence_;
      }
      const auto cycle = highest_sequence_ & ~std::uint64_t {0xffffU};
      auto candidate = cycle | sequence;
      if (candidate + 0x8000U < highest_sequence_) {
        candidate += 0x1'0000U;
      } else if (candidate > highest_sequence_ + 0x8000U && candidate >= 0x1'0000U) {
        candidate -= 0x1'0000U;
      }
      highest_sequence_ = std::max(highest_sequence_, candidate);
      return candidate;
    }

    enum class FeedbackKind : std::uint8_t {
      compound,  ///< Regular RR plus stable CNAME.
      congestion,  ///< Reduced RFC 8888 feedback prefix.
    };

    struct PendingFeedback {
      std::uint64_t token {};  ///< Exact aggregate completion identity.
      std::uint64_t proposed_at_microseconds {};  ///< Borrow/report time used for this packet.
      std::uint32_t begin_extended_sequence {};  ///< Borrowed prefix origin for overlap repair.
      std::size_t report_count {};  ///< Borrowed RFC 8888 prefix length.
      std::uint64_t receiver_expected {};  ///< RR expected-packet total committed only after final send.
      std::uint64_t receiver_received {};  ///< RR received-packet total committed only after final send.
      FeedbackKind kind {FeedbackKind::compound};  ///< Terminal action selected by completion.
      bool prefix_modified {};  ///< Late reorder/duplicate requires one overlapping correction report.
      bool active {};  ///< Whether aggregate final-send completion remains pending.
    };

    /** @brief Protect and schedule one receiver-owned SRTCP packet with terminal completion. */
    bool submit_feedback(
      const std::span<const std::uint8_t> plaintext,
      const HostForwardLane lane,
      const std::uint64_t now_microseconds,
      const FeedbackKind kind,
      const std::size_t report_count = 0,
      const std::uint32_t begin_extended_sequence = 0,
      const std::uint64_t receiver_expected = 0,
      const std::uint64_t receiver_received = 0
    ) noexcept {
      if (pending_feedback_.active || next_feedback_token_ == 0) {
        return false;
      }
      auto lease = config_.forward_path->acquire(lane);
      if (!lease || plaintext.size() > lease->storage.size()) {
        return false;
      }
      std::copy(plaintext.begin(), plaintext.end(), lease->storage.begin());
      std::size_t protected_bytes = 0;
      if (!srtp_.protect_in_place(
            config_.peer,
            SecurePacketClass::rtcp,
            lease->storage,
            plaintext.size(),
            protected_bytes
          )) {
        return false;
      }
      const auto deadline = now_microseconds > std::numeric_limits<std::uint64_t>::max() - 20'000U ?
                              std::numeric_limits<std::uint64_t>::max() :
                              now_microseconds + 20'000U;
      const auto token = next_feedback_token_++;
      pending_feedback_ = {
        .token = token,
        .proposed_at_microseconds = now_microseconds,
        .begin_extended_sequence = begin_extended_sequence,
        .report_count = report_count,
        .receiver_expected = receiver_expected,
        .receiver_received = receiver_received,
        .kind = kind,
        .active = true,
      };
      if (config_.forward_path->commit(
            *lease,
            protected_bytes,
            deadline,
            token,
            {.context = this, .completed = feedback_completion_callback}
          ) != HostForwardSubmitResult::accepted) {
        pending_feedback_ = {};
        return false;
      }
      return true;
    }

    /** @brief Commit borrowed state only after the aggregate path reports final socket success. */
    void complete_feedback(
      const std::uint64_t token,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds
    ) noexcept {
      std::scoped_lock lock(feedback_mutex_);
      if (!pending_feedback_.active || pending_feedback_.token != token) {
        return;
      }
      const auto pending = pending_feedback_;
      pending_feedback_ = {};
      feedback_condition_.notify_all();
      if (completion != HostForwardCompletion::sent) {
        return;
      }
      if (pending.kind == FeedbackKind::compound) {
        last_compound_report_microseconds_ = completed_at_microseconds;
        receiver_expected_prior_ = pending.receiver_expected;
        receiver_received_prior_ = pending.receiver_received;
        ++receiver_reports_;
      } else {
        ++congestion_reports_;
        if (!pending.prefix_modified &&
            feedback_window_.commit_report(
              pending.begin_extended_sequence,
              pending.report_count,
              completed_at_microseconds
            )) {
          last_congestion_report_microseconds_ = completed_at_microseconds;
        }
        if (pending.prefix_modified) {
          maybe_send_congestion_feedback(completed_at_microseconds);
        }
      }
    }

    /** @brief Adapt aggregate completion to the receiver-owned feedback transaction. */
    static void feedback_completion_callback(
      void *context,
      const std::uint64_t token,
      HostForwardLane,
      const HostForwardCompletion completion,
      const std::uint64_t completed_at_microseconds,
      std::size_t,
      std::uint16_t
    ) noexcept {
      auto *self = static_cast<Impl *>(context);
      if (self != nullptr) {
        self->complete_feedback(token, completion, completed_at_microseconds);
      }
    }

    /** @brief Emit regular RR plus SDES/CNAME to establish reduced-feedback permission. */
    bool maybe_send_compound_report(const std::uint64_t now_microseconds) noexcept {
      if (pending_feedback_.active) {
        return false;
      }
      if (last_compound_report_microseconds_ != 0 &&
          now_microseconds - last_compound_report_microseconds_ < 1'000'000U) {
        return true;
      }
      std::array<std::uint8_t, 128> packet {};
      const auto expected = sequence_initialized_ ? highest_sequence_ - base_sequence_ + 1U : 0U;
      const auto received = unique_received_packets_;
      const auto cumulative_lost_raw = static_cast<std::int64_t>(expected) - static_cast<std::int64_t>(received);
      const auto cumulative_lost = static_cast<std::int32_t>(std::clamp<std::int64_t>(
        cumulative_lost_raw,
        -0x80'0000LL,
        0x7f'ffffLL
      ));
      const auto expected_interval = expected >= receiver_expected_prior_ ? expected - receiver_expected_prior_ : 0U;
      const auto received_interval = received >= receiver_received_prior_ ? received - receiver_received_prior_ : 0U;
      const auto lost_interval = expected_interval > received_interval ? expected_interval - received_interval : 0U;
      const auto fraction_lost = expected_interval == 0 ? 0U :
                                                          std::min<std::uint64_t>(255U, lost_interval * 256U / expected_interval);
      const auto sr_delay_microseconds = last_sender_report_received_microseconds_ == 0 ||
                                             now_microseconds < last_sender_report_received_microseconds_ ?
                                           0U :
                                           now_microseconds - last_sender_report_received_microseconds_;
      const auto dlsr = std::min<std::uint64_t>(
        std::numeric_limits<std::uint32_t>::max(),
        sr_delay_microseconds * 65'536ULL / 1'000'000ULL
      );
      const auto written = write_microphone_compound_report(
        packet,
        config_.feedback_ssrc,
        {
          .media_ssrc = config_.ssrc,
          .extended_highest_sequence = static_cast<std::uint32_t>(highest_sequence_),
          .interarrival_jitter = interarrival_jitter_,
          .last_sender_report = last_sender_report_,
          .delay_since_sender_report = static_cast<std::uint32_t>(dlsr),
          .cumulative_lost = cumulative_lost,
          .fraction_lost = static_cast<std::uint8_t>(fraction_lost),
        },
        config_.rtcp_cname.view()
      );
      if (written == 0 || !submit_feedback(
                            std::span<const std::uint8_t> {packet}.first(written),
                            HostForwardLane::periodic,
                            now_microseconds,
                            FeedbackKind::compound,
                            0,
                            0,
                            expected,
                            received
                          )) {
        return false;
      }
      return false;
    }

    /** @brief Emit one borrowed gap-preserving RFC 8888 prefix when cadence permits. */
    void maybe_send_congestion_feedback(const std::uint64_t now_microseconds) noexcept {
      if (!maybe_send_compound_report(now_microseconds) || pending_feedback_.active) {
        return;
      }
      const auto batch = feedback_window_.pending_report(now_microseconds);
      if (batch.size() == 0) {
        return;
      }
      std::array<std::uint8_t, 1'200> packet {};
      const auto written = write_microphone_congestion_report(
        packet,
        config_.feedback_ssrc,
        batch,
        current_middle_ntp()
      );
      if (written != 0) {
        (void) submit_feedback(
          std::span<const std::uint8_t> {packet}.first(written),
          HostForwardLane::congestion_feedback,
          now_microseconds,
          FeedbackKind::congestion,
          batch.size(),
          batch.begin_extended_sequence
        );
      }
    }

    /** @brief Submit one exact authenticated RTP packet to clocked playout. */
    bool receive_rtp(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> packet,
      const std::size_t protected_bytes,
      std::uint64_t received_at_microseconds,
      const IpEcn ecn
    ) noexcept {
      if (!active_ || peer != config_.peer) {
        ++rejected_rtp_packets_;
        return true;
      }
      const auto rtp = parse_rtp_fixed_header(packet);
      if (!rtp || rtp.header.padding || rtp.header.extension || rtp.header.csrc_count != 0 ||
          rtp.header.ssrc != config_.ssrc || rtp.header.payload_type != config_.payload_type ||
          rtp.bytes_consumed >= packet.size()) {
        ++rejected_rtp_packets_;
        return true;
      }
      const auto payload = packet.subspan(rtp.bytes_consumed);
      if (payload.empty() || payload.size() > client_microphone::MAX_OPUS_PAYLOAD_SIZE) {
        ++rejected_rtp_packets_;
        return true;
      }
      if (protected_bytes == 0 || protected_bytes > std::numeric_limits<std::uint16_t>::max() -
                                                      (peer.family == IpAddressFamily::ipv4 ? 28U : 48U)) {
        ++rejected_rtp_packets_;
        return true;
      }
      if (received_at_microseconds == 0) {
        received_at_microseconds = monotonic_microseconds();
      }
      std::uint64_t expanded_sequence = 0;
      {
        std::scoped_lock lock(feedback_mutex_);
        expanded_sequence = expand_sequence(rtp.header.sequence_number);
        if (pending_feedback_.active && pending_feedback_.kind == FeedbackKind::congestion &&
            expanded_sequence >= pending_feedback_.begin_extended_sequence &&
            expanded_sequence - pending_feedback_.begin_extended_sequence < pending_feedback_.report_count) {
          pending_feedback_.prefix_modified = true;
        }
        const auto report_result = feedback_window_.record({
          .media_ssrc = config_.ssrc,
          .extended_sequence_number = static_cast<std::uint32_t>(expanded_sequence),
          .arrival_microseconds = received_at_microseconds,
          .received_bytes = static_cast<std::uint16_t>(
            protected_bytes + (peer.family == IpAddressFamily::ipv4 ? 28U : 48U)
          ),
          .ecn = feedback_ecn(ecn),
        });
        if (report_result != transport::reordering_congestion_report_result::accepted &&
            report_result != transport::reordering_congestion_report_result::duplicate &&
            report_result != transport::reordering_congestion_report_result::stale) {
          ++rejected_rtp_packets_;
        }
        ++authenticated_rtp_packets_;
        if (report_result == transport::reordering_congestion_report_result::accepted ||
            report_result == transport::reordering_congestion_report_result::duplicate) {
          ++reportable_rtp_packets_;
        }
        if (report_result == transport::reordering_congestion_report_result::accepted) {
          if (unique_received_packets_ == 0) {
            base_sequence_ = expanded_sequence;
          }
          ++unique_received_packets_;
          const auto arrival_ticks = static_cast<std::uint32_t>(
            received_at_microseconds * config_.clock_rate / 1'000'000ULL
          );
          const auto transit = static_cast<std::int32_t>(arrival_ticks - rtp.header.timestamp);
          if (has_transit_) {
            const auto delta = static_cast<std::uint32_t>(std::abs(
              static_cast<std::int64_t>(transit) - prior_transit_
            ));
            const auto next_jitter = static_cast<std::int64_t>(interarrival_jitter_) +
                                     (static_cast<std::int64_t>(delta) - interarrival_jitter_) / 16;
            interarrival_jitter_ = static_cast<std::uint32_t>(std::max<std::int64_t>(0, next_jitter));
          }
          prior_transit_ = transit;
          has_transit_ = true;
        }
        maybe_send_congestion_feedback(received_at_microseconds);
      }
      client_microphone::packet_t microphone_packet {
        .generation = config_.generation,
        .sequence = expanded_sequence,
        .timestamp = rtp.header.timestamp,
        .kind = client_microphone::packet_kind_e::opus,
        .fixed_payload_size = static_cast<std::uint16_t>(payload.size()),
      };
      std::ranges::copy(payload, microphone_packet.fixed_payload.begin());
      if (receiver_->submit(std::move(microphone_packet)) != client_microphone::submit_result_e::accepted) {
        ++rejected_rtp_packets_;
        return true;
      }
      ++accepted_rtp_packets_;
      ++playout_rtp_packets_;
      return true;
    }

    /** @brief Validate RTCP and count sender reports belonging to the microphone SSRC. */
    bool receive_rtcp(const PeerEndpoint &peer, std::span<const std::uint8_t> packet) noexcept {
      if (!active_ || peer != config_.peer) {
        return true;
      }
      const auto authority = transport::validate_compound_rtcp_authority(packet, config_.ssrc);
      if (!authority ||
          (sender_cname_size_ != 0 &&
           (sender_cname_size_ != authority.cname.size() ||
            !std::ranges::equal(std::span<const std::uint8_t> {sender_cname_}.first(sender_cname_size_), authority.cname)))) {
        return true;
      }
      if (sender_cname_size_ == 0) {
        std::copy(authority.cname.begin(), authority.cname.end(), sender_cname_.begin());
        sender_cname_size_ = authority.cname.size();
      }
      if (authority.first_report.packet_type == transport::rtcp_sender_report_type) {
        if (authority.first_report.payload.size() >= 12U) {
          const auto seconds = wire::read_be<std::uint32_t>(authority.first_report.payload.subspan<4, 4>());
          const auto fraction = wire::read_be<std::uint32_t>(authority.first_report.payload.subspan<8, 4>());
          last_sender_report_ = static_cast<std::uint32_t>((seconds << 16U) | (fraction >> 16U));
          last_sender_report_received_microseconds_ = monotonic_microseconds();
        }
        ++sender_reports_;
      }
      return true;
    }

    /** @brief Quiesce platform writes and release authority while retaining callback/worker storage. */
    void stop() noexcept {
      if (active_ && receiver_) {
        receiver_->stop();
      }
      active_ = false;
      // clocked_receiver_t::stop serializes with PCM writes and ends the sink.
      // A successor may now claim its generation even while old feedback
      // completions retain this receiver until shutdown().
      if (owner_.id != 0) {
        client_microphone::release_writer(owner_);
        owner_.id = 0;
      }
    }

    /** @brief Join the receiver worker and release the exact writer once. */
    void shutdown() noexcept {
      stop();
      {
        std::unique_lock lock(feedback_mutex_);
        feedback_condition_.wait(lock, [this]() {
          return !pending_feedback_.active;
        });
      }
      if (receiver_) {
        receiver_->shutdown();
        receiver_.reset();
      }
      sink_.reset();
    }

    /** @brief Return current receive and playout counters. */
    [[nodiscard]] MicrophoneReceiverSnapshot snapshot() const noexcept {
      std::scoped_lock lock(feedback_mutex_);
      return {
        .accepted_rtp_packets = accepted_rtp_packets_,
        .authenticated_rtp_packets = authenticated_rtp_packets_,
        .reportable_rtp_packets = reportable_rtp_packets_,
        .playout_rtp_packets = playout_rtp_packets_,
        .rejected_rtp_packets = rejected_rtp_packets_,
        .sender_reports = sender_reports_,
        .receiver_reports = receiver_reports_,
        .congestion_reports = congestion_reports_,
        .playout = receiver_ ? receiver_->statistics() : client_microphone::statistics_t {},
        .active = active_ && receiver_ && receiver_->active(),
      };
    }

    MicrophoneReceiverConfig config_;  ///< Immutable authenticated mapping.
    LibsrtpServerProvider &srtp_;  ///< Association provider for reverse-path feedback.
    client_microphone::writer_owner_t owner_;  ///< Exact claimed LSP writer.
    std::unique_ptr<client_microphone::sink_t> sink_;  ///< Owned platform injection backend.
    std::unique_ptr<client_microphone::clocked_receiver_t> receiver_;  ///< Bounded decoder/playout owner.
    std::uint64_t highest_sequence_ {};  ///< Greatest expanded RTP sequence observed.
    transport::reordering_congestion_feedback_window<512> feedback_window_;  ///< Authenticated gaps/reorder/ECN state.
    mutable std::mutex feedback_mutex_;  ///< Serializes receive recording with aggregate final-send completion.
    std::condition_variable feedback_condition_;  ///< Wakes teardown after the final feedback callback.
    PendingFeedback pending_feedback_;  ///< Sole borrowed report awaiting final-send completion.
    std::uint64_t next_feedback_token_ {1};  ///< Next nonzero aggregate completion identity.
    std::array<std::uint8_t, 255> sender_cname_ {};  ///< Stable client microphone sender CNAME.
    std::size_t sender_cname_size_ {};  ///< Populated stable sender CNAME bytes.
    std::uint64_t accepted_rtp_packets_ {};  ///< Accepted Opus RTP packets.
    std::uint64_t authenticated_rtp_packets_ {};  ///< Authenticated structurally valid RTP packets.
    std::uint64_t reportable_rtp_packets_ {};  ///< New/overlap packets admitted to congestion reporting.
    std::uint64_t playout_rtp_packets_ {};  ///< Packets accepted by clocked playout.
    std::uint64_t rejected_rtp_packets_ {};  ///< Safely dropped RTP packets.
    std::uint64_t sender_reports_ {};  ///< Valid reverse SR packets.
    std::uint64_t receiver_reports_ {};  ///< Submitted regular compound receiver reports.
    std::uint64_t congestion_reports_ {};  ///< Submitted reduced RFC 8888 reports.
    std::uint64_t last_compound_report_microseconds_ {};  ///< Latest regular report submission.
    std::uint64_t last_congestion_report_microseconds_ {};  ///< Latest reduced feedback submission.
    std::uint64_t base_sequence_ {};  ///< First unique extended sequence used by RR loss accounting.
    std::uint64_t unique_received_packets_ {};  ///< Unique authenticated sequences used by RR loss accounting.
    std::uint64_t receiver_expected_prior_ {};  ///< Expected total at the last final-sent RR.
    std::uint64_t receiver_received_prior_ {};  ///< Received total at the last final-sent RR.
    std::uint64_t last_sender_report_received_microseconds_ {};  ///< Local receive time of latest valid SR.
    std::int64_t prior_transit_ {};  ///< Prior RFC 3550 arrival-minus-RTP transit sample.
    std::uint32_t interarrival_jitter_ {};  ///< Smoothed RFC 3550 interarrival jitter.
    std::uint32_t last_sender_report_ {};  ///< Middle NTP bits of latest microphone SR.
    bool sequence_initialized_ {};  ///< Whether `highest_sequence_` has an origin.
    bool has_transit_ {};  ///< Whether jitter differencing has a prior transit sample.
    bool active_ {};  ///< Whether writer and receiver remain active.
  };

  std::unique_ptr<LspMicrophoneReceiver> LspMicrophoneReceiver::create(
    MicrophoneReceiverConfig config,
    std::unique_ptr<client_microphone::sink_t> sink,
    LibsrtpServerProvider &srtp
  ) noexcept {
    if (!config.valid() || !sink) {
      return nullptr;
    }
    const auto owner = client_microphone::writer_owner_t::lsp(config.generation);
    if (!client_microphone::claim_writer(owner)) {
      return nullptr;
    }
    try {
      auto receiver = std::make_unique<client_microphone::clocked_receiver_t>(
        std::make_unique<client_microphone::opus_decoder_t>(),
        *sink,
        config.inband_fec,
        client_microphone::FRAME_DURATION
      );
      if (!receiver->reset(config.generation)) {
        receiver->shutdown();
        client_microphone::release_writer(owner);
        return nullptr;
      }
      auto impl = std::make_unique<Impl>(std::move(config), srtp, owner, std::move(sink), std::move(receiver));
      return std::unique_ptr<LspMicrophoneReceiver> {new (std::nothrow) LspMicrophoneReceiver(std::move(impl))};
    } catch (...) {
      client_microphone::release_writer(owner);
      return nullptr;
    }
  }

  LspMicrophoneReceiver::LspMicrophoneReceiver(std::unique_ptr<Impl> impl) noexcept:
      impl_(std::move(impl)) {
  }

  LspMicrophoneReceiver::~LspMicrophoneReceiver() = default;

  bool LspMicrophoneReceiver::receive_rtp(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> packet,
    const std::size_t protected_bytes,
    const std::uint64_t received_at_microseconds,
    const IpEcn ecn
  ) noexcept {
    return impl_ && impl_->receive_rtp(peer, packet, protected_bytes, received_at_microseconds, ecn);
  }

  bool LspMicrophoneReceiver::receive_rtcp(const PeerEndpoint &peer, const std::span<const std::uint8_t> packet) noexcept {
    return impl_ && impl_->receive_rtcp(peer, packet);
  }

  void LspMicrophoneReceiver::stop() noexcept {
    if (impl_) {
      impl_->stop();
    }
  }

  void LspMicrophoneReceiver::shutdown() noexcept {
    if (impl_) {
      impl_->shutdown();
    }
  }

  MicrophoneReceiverSnapshot LspMicrophoneReceiver::snapshot() const noexcept {
    return impl_ ? impl_->snapshot() : MicrophoneReceiverSnapshot {};
  }

  const PeerEndpoint &LspMicrophoneReceiver::peer() const noexcept {
    static const PeerEndpoint empty;
    return impl_ ? impl_->config_.peer : empty;
  }

  std::uint32_t LspMicrophoneReceiver::generation() const noexcept {
    return impl_ ? impl_->config_.generation : 0;
  }
}  // namespace lumen::lsp::runtime
