/**
 * @file src/protocol_v3/media_pipeline.cpp
 * @brief Per-session protocol-v3 media packetization and input routing.
 */

#include "media_pipeline.h"

#include "../protocol_common/input_state.h"
#include "start_mode_contract.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace lumen::protocol_v3::media {
  namespace {
    constexpr std::size_t video_payload_header_bytes = 64;
    constexpr std::size_t audio_payload_header_bytes = 48;
    constexpr std::size_t maximum_datagram_payload_bytes =
      quic_server::maximum_semantic_datagram_bytes - quic_server::datagram_header_bytes;
    constexpr std::uint64_t sequence_exhaustion_boundary =
      std::numeric_limits<std::uint64_t>::max() - 1'024;

    void append_be(
      std::vector<std::uint8_t> &output,
      const std::uint64_t value,
      std::size_t byte_count
    ) {
      while (byte_count-- != 0) {
        output.push_back(static_cast<std::uint8_t>(value >> (byte_count * 8U)));
      }
    }

    void write_be(
      const std::span<std::uint8_t> output,
      const std::size_t offset,
      std::uint64_t value,
      std::size_t byte_count
    ) {
      while (byte_count-- != 0) {
        output[offset + byte_count] = static_cast<std::uint8_t>(value);
        value >>= 8U;
      }
    }

    std::uint16_t read_be16(
      const std::span<const std::uint8_t> bytes,
      const std::size_t offset
    ) noexcept {
      return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1]
      );
    }

    std::uint32_t read_be32(
      const std::span<const std::uint8_t> bytes,
      const std::size_t offset
    ) noexcept {
      return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
             (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
             (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
             bytes[offset + 3];
    }

    std::uint64_t read_be64(
      const std::span<const std::uint8_t> bytes,
      const std::size_t offset
    ) noexcept {
      std::uint64_t value = 0;
      for (std::size_t index = 0; index < 8; ++index) {
        value = (value << 8U) | bytes[offset + index];
      }
      return value;
    }

    bool nonzero(const std::span<const std::uint8_t> bytes) noexcept {
      return std::ranges::any_of(bytes, [](const std::uint8_t byte) {
        return byte != 0;
      });
    }

    bool valid_opus_tuple(const OpusTuple &tuple) noexcept {
      if (tuple.sample_rate != 48'000 || tuple.frame_samples == 0 ||
          tuple.channels == 0 || tuple.channels > tuple.mapping.size() ||
          tuple.streams == 0 || tuple.coupled_streams > tuple.streams ||
          tuple.bitrate_bps == 0) {
        return false;
      }
      const auto coded_channels = static_cast<unsigned>(tuple.streams) + tuple.coupled_streams;
      for (std::size_t index = 0; index < tuple.mapping.size(); ++index) {
        const auto mapping = tuple.mapping[index];
        if (index < tuple.channels) {
          if (mapping != 0xff && mapping >= coded_channels) {
            return false;
          }
        } else if (mapping != 0xff) {
          return false;
        }
      }
      return true;
    }

    bool valid_config(const NegotiatedMediaConfig &config) noexcept {
      const auto mode_admission = start_mode::admit(start_mode::Mode {
        config.width,
        config.height,
        config.refresh_numerator,
        config.refresh_denominator,
        config.codec_id,
        config.bit_depth,
        config.chroma_layout,
        config.transfer,
        config.codec_flags,
        config.fidelity,
      });
      return nonzero(config.session_id) &&
             config.semantic_datagram_bytes >= quic_server::datagram_header_bytes +
                                                   audio_payload_header_bytes &&
             config.semantic_datagram_bytes <= quic_server::maximum_semantic_datagram_bytes &&
             config.video_bitrate_kbps >= 1'000 && config.video_bitrate_kbps <= 500'000 &&
             mode_admission == start_mode::AdmissionError::none && config.range <= 1 &&
             (config.matrix_code == 1 || config.matrix_code == 5 ||
              config.matrix_code == 6 || config.matrix_code == 9) &&
             (config.transfer == 1 || (config.primaries == 9 && config.matrix_code == 9)) &&
             (config.transfer != 1 || !config.static_hdr_metadata.has_value()) &&
             (config.transfer != 2 || config.static_hdr_metadata.has_value()) &&
             (config.transfer != 3 || !config.static_hdr_metadata.has_value()) &&
             (config.codec_flags & ~0x03U) == 0 && config.fidelity >= 1 && config.fidelity <= 3 &&
             (config.fidelity != 3 || (config.codec_flags & 0x02U) != 0) &&
             config.video_generation != 0 && config.audio_generation != 0 &&
             config.microphone_generation != 0 && config.input_generation != 0 &&
             valid_opus_tuple(config.audio) && valid_opus_tuple(config.microphone) &&
             !config.fec_enabled;
    }

    std::chrono::milliseconds lifetime(
      const quic_server::Profile profile,
      const quic_server::Lane lane
    ) noexcept {
      if (lane == quic_server::Lane::delta_video) {
        return profile == quic_server::Profile::latency ?
                 std::chrono::milliseconds {12} :
                 std::chrono::milliseconds {35};
      }
      if (lane == quic_server::Lane::input_edge) {
        return profile == quic_server::Profile::latency ?
                 std::chrono::milliseconds {8} :
                 std::chrono::milliseconds {12};
      }
      return profile == quic_server::Profile::latency ?
               std::chrono::milliseconds {20} :
               std::chrono::milliseconds {40};
    }

    PublishResult map_enqueue_result(const quic_server::EnqueueResult result) noexcept {
      switch (result) {
        case quic_server::EnqueueResult::queued:
          return PublishResult::accepted;
        case quic_server::EnqueueResult::datagram_not_negotiated:
        case quic_server::EnqueueResult::datagram_too_large:
          return PublishResult::path_too_small;
        case quic_server::EnqueueResult::unknown_connection:
        case quic_server::EnqueueResult::shutting_down:
          return PublishResult::stopped;
        case quic_server::EnqueueResult::invalid_packet:
          return PublishResult::invalid;
        case quic_server::EnqueueResult::would_block:
          return PublishResult::backpressured;
      }
      return PublishResult::invalid;
    }

    class LazyEncodedVideoFrame final: public quic_server::LazyVideoFrame {
    public:
      LazyEncodedVideoFrame(
        const NegotiatedMediaConfig &config,
        const EncodedVideoFrame &frame,
        const std::uint16_t datagram_maximum,
        const std::uint64_t first_sequence,
        const std::size_t fragment_capacity,
        const std::size_t fragment_count,
        quic_server::MonotonicClock::time_point deadline
      ):
          session_id_ {config.session_id},
          frame_id_ {frame.frame_id},
          capture_time_microseconds_ {frame.capture_time_microseconds},
          encoder_submit_delta_microseconds_ {frame.encoder_submit_delta_microseconds},
          encoder_complete_delta_microseconds_ {frame.encoder_complete_delta_microseconds},
          applied_input_state_sequence_ {frame.applied_input_state_sequence},
          applied_input_edge_id_ {frame.applied_input_edge_id},
          storage_ {frame.storage},
          data_ {frame.bytes.data()},
          data_size_ {frame.bytes.size()},
          recovery_ {frame.request_recovery},
          first_sequence_ {first_sequence},
          fragment_capacity_ {fragment_capacity},
          fragment_count_ {fragment_count},
          datagram_maximum_ {datagram_maximum},
          codec_id_ {config.codec_id},
          matrix_code_ {config.matrix_code},
          bit_depth_ {config.bit_depth},
          video_generation_ {config.video_generation},
          key_frame_ {frame.key_frame},
          discardable_ {frame.discardable},
          static_hdr_metadata_ {frame.static_hdr_metadata},
          deadline_ {deadline} {
      }

      std::uint64_t object_id() const noexcept override { return frame_id_; }
      bool independently_decodable() const noexcept override { return key_frame_; }
      bool replaceable() const noexcept override { return discardable_; }
      quic_server::MonotonicClock::time_point deadline() const noexcept override { return deadline_; }
      std::size_t fragment_count() const noexcept override { return fragment_count_; }
      std::size_t retained_bytes() const noexcept override { return data_size_; }
      std::size_t maximum_datagram_bytes() const noexcept override { return datagram_maximum_; }

      bool materialize(
        const std::size_t fragment_index,
        const std::span<std::uint8_t> header_storage,
        quic_server::VideoFragmentView &fragment
      ) const noexcept override {
        constexpr auto header_bytes = quic_server::datagram_header_bytes + video_payload_header_bytes;
        if (!storage_ || !data_ || fragment_index >= fragment_count_ ||
            header_storage.size() < header_bytes) {
          return false;
        }
        const auto offset = fragment_index * fragment_capacity_;
        if (offset >= data_size_) {
          return false;
        }
        const auto byte_count = std::min(fragment_capacity_, data_size_ - offset);
        const auto payload_size = video_payload_header_bytes + byte_count;
        if (header_bytes + byte_count > datagram_maximum_) {
          return false;
        }
        auto output = header_storage.first(header_bytes);
        std::ranges::fill(output, 0);
        std::uint8_t flags = key_frame_ ? 0x01U : 0;
        if (fragment_index + 1 == fragment_count_) flags |= 0x04U;
        if (discardable_) flags |= 0x10U;
        if (static_hdr_metadata_) flags |= 0x20U;
        output[0] = 'U'; output[1] = 'L'; output[2] = 'M'; output[3] = '3';
        output[4] = 3; output[5] = 2; output[6] = 1; output[7] = flags;
        write_be(output, 8, quic_server::datagram_header_bytes, 2);
        write_be(output, 10, payload_size, 2);
        std::ranges::copy(session_id_, output.begin() + 12);
        write_be(output, 28, first_sequence_ + fragment_index, 8);
        write_be(output, 36, frame_id_, 8);
        const auto base = quic_server::datagram_header_bytes;
        write_be(output, base + 0, capture_time_microseconds_, 8);
        write_be(output, base + 8, encoder_submit_delta_microseconds_.value_or(UINT32_MAX), 4);
        write_be(output, base + 12, encoder_complete_delta_microseconds_, 4);
        write_be(output, base + 16, applied_input_state_sequence_, 8);
        write_be(output, base + 24, applied_input_edge_id_, 8);
        write_be(output, base + 32, data_size_, 4);
        write_be(output, base + 36, offset, 4);
        write_be(output, base + 40, fragment_index, 2);
        write_be(output, base + 42, fragment_count_, 2);
        output[base + 53] = codec_id_;
        output[base + 54] = matrix_code_;
        output[base + 55] = bit_depth_;
        write_be(output, base + 56, video_generation_, 4);
        fragment = {
          .header_size = header_bytes,
          .payload = data_ + offset,
          .payload_size = byte_count,
        };
        return true;
      }

      void request_recovery() const noexcept override {
        try {
          recovery_();
        } catch (...) {
        }
      }

    private:
      std::array<std::uint8_t, 16> session_id_;
      std::uint64_t frame_id_ {};
      std::uint64_t capture_time_microseconds_ {};
      std::optional<std::uint32_t> encoder_submit_delta_microseconds_;
      std::uint32_t encoder_complete_delta_microseconds_ {};
      std::uint64_t applied_input_state_sequence_ {};
      std::uint64_t applied_input_edge_id_ {};
      std::shared_ptr<const void> storage_;
      const std::uint8_t *data_ {};
      std::size_t data_size_ {};
      std::function<void()> recovery_;
      std::uint64_t first_sequence_ {};
      std::size_t fragment_capacity_ {};
      std::size_t fragment_count_ {};
      std::uint16_t datagram_maximum_ {};
      std::uint8_t codec_id_ {};
      std::uint8_t matrix_code_ {};
      std::uint8_t bit_depth_ {};
      std::uint32_t video_generation_ {};
      bool key_frame_ {};
      bool discardable_ {};
      bool static_hdr_metadata_ {};
      quic_server::MonotonicClock::time_point deadline_ {};
    };
  }  // namespace

  SessionPipeline::SessionPipeline(
    NegotiatedMediaConfig config,
    TransportSink &transport,
    InputSink &input,
    MicrophoneSink &microphone,
    VideoFeedbackSink &feedback
  ):
      config_ {std::move(config)},
      transport_ {transport},
      input_ {input},
      microphone_ {microphone},
      feedback_ {feedback},
      datagram_maximum_ {config_.semantic_datagram_bytes} {
    if (!valid_config(config_)) {
      throw std::invalid_argument {"invalid protocol-v3 media selection"};
    }
  }

  bool SessionPipeline::ReplayWindow::permits(const std::uint64_t sequence) const noexcept {
    if (sequence == 0 || sequence > sequence_exhaustion_boundary) return false;
    if (!initialized || sequence > highest) return true;
    const auto age = highest - sequence;
    if (age >= 1'024) return false;
    const auto word = static_cast<std::size_t>(age / 64);
    const auto mask = std::uint64_t {1} << (age % 64);
    return (bitmap[word] & mask) == 0;
  }

  void SessionPipeline::ReplayWindow::commit(const std::uint64_t sequence) noexcept {
    if (!initialized) {
      initialized = true;
      highest = sequence;
      bitmap[0] = 1;
      return;
    }
    if (sequence > highest) {
      const auto distance = sequence - highest;
      if (distance >= 1'024) {
        bitmap.fill(0);
      } else {
        std::array<std::uint64_t, 16> shifted {};
        const auto words = static_cast<std::size_t>(distance / 64);
        const auto bits = static_cast<unsigned>(distance % 64);
        for (std::size_t destination = words; destination < shifted.size(); ++destination) {
          shifted[destination] |= bitmap[destination - words] << bits;
          if (bits != 0 && destination > words) {
            shifted[destination] |= bitmap[destination - words - 1] >> (64U - bits);
          }
        }
        bitmap = shifted;
      }
      highest = sequence;
      bitmap[0] |= 1;
      return;
    }
    const auto age = highest - sequence;
    const auto word = static_cast<std::size_t>(age / 64);
    const auto mask = std::uint64_t {1} << (age % 64);
    bitmap[word] |= mask;
  }

  void SessionPipeline::ReplayWindow::reset() noexcept {
    bitmap.fill(0);
    highest = 0;
    initialized = false;
  }

  bool SessionPipeline::bind_connection(const std::uint64_t connection_id) noexcept {
    std::lock_guard lock {mutex_};
    if (!running_ || connection_id == 0 || connection_id_ != 0) {
      return false;
    }
    if (!transport_.update_policy(connection_id, config_.profile, config_.video_bitrate_kbps)) {
      return false;
    }
    connection_id_ = connection_id;
    return true;
  }

  void SessionPipeline::detach_connection() noexcept {
    std::lock_guard lock {mutex_};
    connection_id_ = 0;
    next_video_sequence_ = 1;
    next_audio_sequence_ = 1;
    next_input_sequence_ = 1;
    highest_input_state_object_ = 0;
    highest_input_edge_id_ = 0;
    input_receive_window_.reset();
    microphone_receive_window_.reset();
    feedback_receive_window_.reset();
  }

  void SessionPipeline::update_datagram_maximum(const std::uint16_t maximum_bytes) noexcept {
    std::lock_guard lock {mutex_};
    datagram_maximum_ = std::min<std::uint16_t>(
      maximum_bytes,
      quic_server::maximum_semantic_datagram_bytes
    );
  }

  PublishResult SessionPipeline::submit_video(const EncodedVideoFrame &frame) {
    struct Reservation {
      std::uint64_t connection_id {};
      std::uint16_t datagram_maximum {};
      std::uint64_t first_sequence {};
      std::size_t fragment_capacity {};
      std::size_t fragment_count {};
    } reservation;
    {
      std::lock_guard lock {mutex_};
      if (!running_) return PublishResult::stopped;
      if (connection_id_ == 0) return PublishResult::detached;
      if (frame.frame_id == 0 || !frame.storage || frame.bytes.empty() || !frame.request_recovery ||
          frame.bytes.size() > 64U * 1'048'576U || frame.frame_id > sequence_exhaustion_boundary ||
          (frame.encoder_submit_delta_microseconds &&
           *frame.encoder_submit_delta_microseconds > frame.encoder_complete_delta_microseconds) ||
          datagram_maximum_ <= quic_server::datagram_header_bytes + video_payload_header_bytes) {
        return datagram_maximum_ <= quic_server::datagram_header_bytes + video_payload_header_bytes ?
                 PublishResult::path_too_small : PublishResult::invalid;
      }
      reservation.connection_id = connection_id_;
      reservation.datagram_maximum = datagram_maximum_;
      reservation.fragment_capacity = static_cast<std::size_t>(datagram_maximum_) -
                                      quic_server::datagram_header_bytes - video_payload_header_bytes;
      reservation.fragment_count =
        (frame.bytes.size() + reservation.fragment_capacity - 1) / reservation.fragment_capacity;
      if (reservation.fragment_count == 0 ||
          reservation.fragment_count > std::numeric_limits<std::uint16_t>::max() ||
          next_video_sequence_ > sequence_exhaustion_boundary - reservation.fragment_count) {
        return PublishResult::invalid;
      }
      reservation.first_sequence = next_video_sequence_;
      next_video_sequence_ += reservation.fragment_count;
    }
    auto object = std::make_shared<const LazyEncodedVideoFrame>(
      config_,
      frame,
      reservation.datagram_maximum,
      reservation.first_sequence,
      reservation.fragment_capacity,
      reservation.fragment_count,
      quic_server::MonotonicClock::now() + lifetime(config_.profile, quic_server::Lane::delta_video)
    );
    const auto result = map_enqueue_result(transport_.enqueue_video_frame(
      reservation.connection_id,
      std::move(object)
    ));
    if (result != PublishResult::accepted) {
      std::lock_guard lock {mutex_};
      ++telemetry_.backpressure_drops;
      return result;
    }
    {
      std::lock_guard lock {mutex_};
      ++telemetry_.video_frames;
      telemetry_.video_fragments += reservation.fragment_count;
      telemetry_.latest_input_state = frame.applied_input_state_sequence;
      telemetry_.latest_input_edge = frame.applied_input_edge_id;
      telemetry_.latest_captured_frame = frame.frame_id;
    }
    return PublishResult::accepted;
  }

  PublishResult SessionPipeline::submit_audio(const EncodedAudioPacket &packet) {
    std::lock_guard lock {mutex_};
    if (!running_) {
      return PublishResult::stopped;
    }
    if (connection_id_ == 0) {
      return PublishResult::detached;
    }
    if (packet.first_sample_position > sequence_exhaustion_boundary ||
        next_audio_sequence_ > sequence_exhaustion_boundary ||
        packet.opus.size() > std::numeric_limits<std::uint16_t>::max() ||
        (!packet.dtx && !packet.end && packet.opus.empty())) {
      return PublishResult::invalid;
    }
    std::vector<std::uint8_t> payload(audio_payload_header_bytes + packet.opus.size());
    write_be(payload, 0, packet.capture_time_microseconds, 8);
    write_be(payload, 8, packet.first_sample_position, 8);
    write_be(payload, 16, config_.audio_generation, 4);
    write_be(payload, 20, config_.audio.frame_samples, 2);
    payload[22] = config_.audio.channels;
    payload[23] = config_.audio.layout;
    payload[24] = 1;
    payload[25] = (packet.dtx ? 0x01U : 0) |
                  (packet.discontinuity ? 0x02U : 0) |
                  (packet.end ? 0x04U : 0);
    payload[26] = config_.audio.streams;
    payload[27] = config_.audio.coupled_streams;
    std::ranges::copy(config_.audio.mapping, payload.begin() + 28);
    write_be(payload, 36, config_.audio.bitrate_bps, 4);
    std::ranges::copy(packet.opus, payload.begin() + audio_payload_header_bytes);
    if (payload.size() + quic_server::datagram_header_bytes > datagram_maximum_) {
      return PublishResult::path_too_small;
    }
    const auto result = publish(
      quic_server::Lane::audio,
      3,
      1,
      0,
      next_audio_sequence_++,
      packet.first_sample_position,
      payload,
      false
    );
    if (result == PublishResult::accepted) {
      ++telemetry_.audio_packets;
    } else {
      ++telemetry_.backpressure_drops;
    }
    return result;
  }

  PublishResult SessionPipeline::submit_input_acknowledgement(
    const InputAcknowledgement &acknowledgement
  ) {
    std::lock_guard lock {mutex_};
    if (!running_) {
      return PublishResult::stopped;
    }
    std::array<std::uint8_t, 48> payload {};
    write_be(payload, 0, acknowledgement.host_receive_time_microseconds, 8);
    write_be(payload, 8, acknowledgement.applied_state_sequence, 8);
    write_be(payload, 16, acknowledgement.applied_edge_id, 8);
    write_be(payload, 24, acknowledgement.received_edge_bitmap, 8);
    write_be(payload, 32, acknowledgement.captured_frame_id, 8);
    return publish(
      quic_server::Lane::input_edge,
      1,
      2,
      0,
      next_input_sequence_++,
      acknowledgement.applied_state_sequence,
      payload,
      true
    );
  }

  PublishResult SessionPipeline::submit_input_resynchronization(
    const InputResynchronization &request
  ) {
    std::lock_guard lock {mutex_};
    if (!running_) {
      return PublishResult::stopped;
    }
    if (request.reason < 1 || request.reason > 3) {
      return PublishResult::invalid;
    }
    std::array<std::uint8_t, 16> payload {};
    write_be(payload, 0, request.expected_edge_id, 8);
    payload[8] = request.reason;
    return publish(
      quic_server::Lane::input_edge,
      1,
      3,
      0,
      next_input_sequence_++,
      request.object_id,
      payload,
      false
    );
  }

  PublishResult SessionPipeline::submit_controller_feedback(
    const ControllerFeedback &feedback
  ) {
    std::lock_guard lock {mutex_};
    if (!running_) {
      return PublishResult::stopped;
    }
    if (feedback.input_generation == 0 || feedback.controller_generation == 0 ||
        feedback.controller_id >= 16 || feedback.command < 1 || feedback.command > 5 ||
        next_input_sequence_ > sequence_exhaustion_boundary) {
      return PublishResult::invalid;
    }

    std::array<std::uint8_t, 40> payload {};
    write_be(payload, 0, feedback.input_generation, 4);
    write_be(payload, 4, feedback.controller_generation, 4);
    payload[8] = feedback.controller_id;
    payload[9] = feedback.command;
    switch (feedback.command) {
      case 1:
      case 2:
        write_be(payload, 10, 4, 2);
        write_be(payload, 12, feedback.low_frequency, 2);
        write_be(payload, 14, feedback.high_frequency, 2);
        break;
      case 3:
        if ((feedback.motion_type != 1 && feedback.motion_type != 2) ||
            feedback.report_rate_hz > 2'000) {
          return PublishResult::invalid;
        }
        write_be(payload, 10, 4, 2);
        payload[12] = feedback.motion_type;
        write_be(payload, 14, feedback.report_rate_hz, 2);
        break;
      case 4:
        write_be(payload, 10, 3, 2);
        payload[12] = feedback.red;
        payload[13] = feedback.green;
        payload[14] = feedback.blue;
        break;
      case 5:
        if ((feedback.adaptive_flags & ~0x0cU) != 0) {
          return PublishResult::invalid;
        }
        write_be(payload, 10, 24, 2);
        payload[12] = feedback.adaptive_flags;
        payload[13] = feedback.adaptive_left_type;
        payload[14] = feedback.adaptive_right_type;
        std::ranges::copy(feedback.adaptive_left, payload.begin() + 16);
        std::ranges::copy(feedback.adaptive_right, payload.begin() + 26);
        break;
      default:
        return PublishResult::invalid;
    }
    return publish(
      quic_server::Lane::input_edge,
      1,
      4,
      0,
      next_input_sequence_++,
      feedback.input_generation,
      payload,
      false
    );
  }

  ReceiveResult SessionPipeline::receive(const quic_server::DatagramRecord &record) {
    std::lock_guard lock {mutex_};
    if (!running_) {
      return ReceiveResult::ignored;
    }
    if (record.session_id != config_.session_id || record.sequence == 0 ||
        record.sequence > sequence_exhaustion_boundary) {
      return ReceiveResult::forbidden;
    }
    ReplayWindow *receive_window = nullptr;
    if (record.channel == 1 && record.kind == 1) receive_window = &input_receive_window_;
    if (record.channel == 4 && record.kind == 1) receive_window = &microphone_receive_window_;
    if (record.channel == 2 && record.kind == 3) receive_window = &feedback_receive_window_;
    if (receive_window == nullptr || !receive_window->permits(record.sequence)) {
      return ReceiveResult::ignored;
    }
    if (record.channel == 1 && record.kind == 1) {
      if (record.payload.size() < 32 || record.payload.size() > maximum_datagram_payload_bytes ||
          record.object_id == 0) {
        return ReceiveResult::malformed;
      }
      const auto state_length = read_be16(record.payload, 16);
      const auto edge_count = read_be16(record.payload, 18);
      const auto state_format = read_be16(record.payload, 20);
      const auto edge_format = read_be16(record.payload, 22);
      const auto expected = 32U + state_length + static_cast<std::size_t>(edge_count) * 32U;
      if (edge_count > 64 || (state_format != 2 && state_format != 3) || edge_format != 2 ||
          read_be64(record.payload, 24) != 0 ||
          expected != record.payload.size()) {
        return ReceiveResult::malformed;
      }
      const auto sample_time = read_be64(record.payload, 0);
      const auto newest_edge = read_be64(record.payload, 8);
      const auto state_block = record.payload.subspan(32, state_length);
      const auto expected_state_format = state_format == 3 ?
                                           protocol_common::input_state::Format::three :
                                           protocol_common::input_state::Format::two;
      if (protocol_common::input_state::validate(state_block, expected_state_format)) {
        return ReceiveResult::malformed;
      }
      const auto state_flags = read_be32(record.payload, 32);
      if ((highest_input_state_object_ == 0 &&
           (record.object_id != 1 || (state_flags & 0x04U) == 0)) ||
          (highest_input_state_object_ != 0 && (state_flags & 0x04U) != 0)) {
        return ReceiveResult::malformed;
      }
      auto prior_edge = std::uint64_t {0};
      std::size_t first_new_edge = edge_count;
      for (std::size_t index = 0; index < edge_count; ++index) {
        const auto offset = 32U + state_length + index * 32U;
        const auto edge = read_be64(record.payload, offset);
        if (edge == 0 || edge > newest_edge || (index != 0 && edge <= prior_edge)) {
          return ReceiveResult::malformed;
        }
        if (edge > highest_input_edge_id_ && first_new_edge == edge_count) {
          first_new_edge = index;
        }
        prior_edge = edge;
      }
      if (edge_count == 0) {
        if (newest_edge != highest_input_edge_id_) return ReceiveResult::malformed;
      } else if (prior_edge != newest_edge) {
        return ReceiveResult::malformed;
      }
      receive_window->commit(record.sequence);
      if (record.object_id <= highest_input_state_object_) {
        return ReceiveResult::ignored;
      }
      const auto retained_window = config_.profile == quic_server::Profile::latency ? 256U : 512U;
      if (highest_input_state_object_ != 0 &&
          record.object_id > highest_input_state_object_ + retained_window) {
        std::array<std::uint8_t, 16> resync {};
        write_be(resync, 0, highest_input_edge_id_ + 1, 8);
        resync[8] = 1;
        static_cast<void>(publish(
          quic_server::Lane::input_edge,
          1,
          3,
          0,
          next_input_sequence_++,
          highest_input_state_object_,
          resync,
          false
        ));
        return ReceiveResult::ignored;
      }
      if (first_new_edge < edge_count) {
        const auto first_new_offset = 32U + state_length + first_new_edge * 32U;
        const auto first_new_id = read_be64(record.payload, first_new_offset);
        if (first_new_id != highest_input_edge_id_ + 1) {
          std::array<std::uint8_t, 16> resync {};
          write_be(resync, 0, highest_input_edge_id_ + 1, 8);
          resync[8] = 1;
          static_cast<void>(publish(
            quic_server::Lane::input_edge,
            1,
            3,
            0,
            next_input_sequence_++,
            highest_input_state_object_,
            resync,
            false
          ));
          return ReceiveResult::ignored;
        }
      }
      const auto new_edge_offset = 32U + state_length + first_new_edge * 32U;
      const InputBatch batch {
        .state_sequence = record.object_id,
        .sample_time_microseconds = sample_time,
        .newest_edge_id = newest_edge,
        .state_block = state_block,
        .edge_records = record.payload.subspan(new_edge_offset),
      };
      if (!input_.submit(batch)) {
        running_ = false;
        input_.reset();
        microphone_.stop();
        return ReceiveResult::forbidden;
      }
      ++telemetry_.input_batches;
      highest_input_state_object_ = record.object_id;
      highest_input_edge_id_ = newest_edge;
      telemetry_.latest_input_state = std::max(telemetry_.latest_input_state, record.object_id);
      telemetry_.latest_input_edge = std::max(telemetry_.latest_input_edge, newest_edge);
      return ReceiveResult::accepted;
    }
    if (record.channel == 4 && record.kind == 1) {
      if (!config_.microphone_enabled || record.payload.size() < audio_payload_header_bytes) {
        return ReceiveResult::forbidden;
      }
      const auto generation = read_be32(record.payload, 16);
      const auto channels = record.payload[22];
      const auto flags = record.payload[25];
      const auto mapping = record.payload.subspan(28, 8);
      if (record.object_id != read_be64(record.payload, 8) ||
          generation != config_.microphone_generation ||
          read_be16(record.payload, 20) != config_.microphone.frame_samples ||
          channels != config_.microphone.channels || record.payload[23] != config_.microphone.layout ||
          record.payload[24] != 1 || (flags & ~0x07U) != 0 ||
          record.payload[26] != config_.microphone.streams ||
          record.payload[27] != config_.microphone.coupled_streams ||
          !std::ranges::equal(mapping, config_.microphone.mapping) ||
          read_be32(record.payload, 36) != config_.microphone.bitrate_bps ||
          read_be64(record.payload, 40) != 0 ||
          (record.payload.size() == audio_payload_header_bytes && (flags & 0x05U) == 0)) {
        return ReceiveResult::malformed;
      }
      const MicrophonePacket packet {
        .capture_time_microseconds = read_be64(record.payload, 0),
        .first_sample_position = record.object_id,
        .generation = generation,
        .flags = flags,
        .opus = record.payload.subspan(audio_payload_header_bytes),
      };
      receive_window->commit(record.sequence);
      if (!microphone_.submit(packet)) {
        return ReceiveResult::forbidden;
      }
      ++telemetry_.microphone_packets;
      return ReceiveResult::accepted;
    }
    if (record.channel == 2 && record.kind == 3) {
      if (record.payload.size() < 32 || record.object_id == 0) {
        return ReceiveResult::malformed;
      }
      const auto action = record.payload[16];
      const auto range_count = record.payload[17];
      const auto deadline_miss_microseconds = read_be32(record.payload, 20);
      if (action < 1 || action > 5 || range_count > 16 ||
          read_be16(record.payload, 18) != 0 ||
          deadline_miss_microseconds > maximum_deadline_miss_microseconds ||
          ((action != 1 && action != 3) && deadline_miss_microseconds != 0) ||
          read_be64(record.payload, 24) != 0 ||
          record.payload.size() != 32U + static_cast<std::size_t>(range_count) * 4U ||
          (action != 2 && range_count != 0)) {
        return ReceiveResult::malformed;
      }
      std::uint32_t prior_end = 0;
      for (std::size_t index = 0; index < range_count; ++index) {
        const auto offset = 32U + index * 4U;
        const auto first = read_be16(record.payload, offset);
        const auto count = read_be16(record.payload, offset + 2);
        if (count == 0 || first < prior_end ||
            static_cast<std::uint32_t>(first) + count > 65'535U) {
          return ReceiveResult::malformed;
        }
        prior_end = static_cast<std::uint32_t>(first) + count;
      }
      receive_window->commit(record.sequence);
      feedback_.submit({
        .affected_frame_id = record.object_id,
        .last_reassembled_frame_id = read_be64(record.payload, 0),
        .last_decoded_frame_id = read_be64(record.payload, 8),
        .action = action,
        .deadline_miss_microseconds = deadline_miss_microseconds,
        .loss_ranges = record.payload.subspan(32),
      });
      ++telemetry_.feedback_packets;
      if (action == 1 || action == 3) {
        if (telemetry_.deadline_samples != std::numeric_limits<std::uint64_t>::max()) {
          ++telemetry_.deadline_samples;
        }
        telemetry_.latest_deadline_miss_microseconds = deadline_miss_microseconds;
        telemetry_.peak_deadline_miss_microseconds = std::max(
          telemetry_.peak_deadline_miss_microseconds,
          deadline_miss_microseconds
        );
        if (deadline_miss_microseconds == 0) {
          telemetry_.consecutive_deadline_misses = 0;
        } else {
          if (telemetry_.deadline_misses != std::numeric_limits<std::uint64_t>::max()) {
            ++telemetry_.deadline_misses;
          }
          if (telemetry_.consecutive_deadline_misses != std::numeric_limits<std::uint64_t>::max()) {
            ++telemetry_.consecutive_deadline_misses;
          }
        }
      }
      return ReceiveResult::accepted;
    }
    return ReceiveResult::forbidden;
  }

  void SessionPipeline::stop() noexcept {
    std::lock_guard lock {mutex_};
    if (!running_) {
      return;
    }
    running_ = false;
    input_.reset();
    microphone_.stop();
  }

  TelemetrySnapshot SessionPipeline::snapshot() const noexcept {
    std::lock_guard lock {mutex_};
    return telemetry_;
  }

  const NegotiatedMediaConfig &SessionPipeline::config() const noexcept {
    return config_;
  }

  PublishResult SessionPipeline::publish(
    const quic_server::Lane lane,
    const std::uint8_t channel,
    const std::uint8_t kind,
    const std::uint8_t flags,
    const std::uint64_t sequence,
    const std::uint64_t object_id,
    const std::span<const std::uint8_t> payload,
    const bool replaceable
  ) {
    if (!running_ || connection_id_ == 0 || sequence == 0 || payload.size() > 0xffffU ||
        payload.size() + quic_server::datagram_header_bytes > datagram_maximum_) {
      return payload.size() + quic_server::datagram_header_bytes > datagram_maximum_ ?
               PublishResult::path_too_small :
               PublishResult::invalid;
    }
    auto bytes = std::make_shared<std::vector<std::uint8_t>>();
    bytes->reserve(quic_server::datagram_header_bytes + payload.size());
    bytes->insert(bytes->end(), {'U', 'L', 'M', '3', 3, channel, kind, flags});
    append_be(*bytes, quic_server::datagram_header_bytes, 2);
    append_be(*bytes, payload.size(), 2);
    bytes->insert(bytes->end(), config_.session_id.begin(), config_.session_id.end());
    append_be(*bytes, sequence, 8);
    append_be(*bytes, object_id, 8);
    bytes->insert(bytes->end(), payload.begin(), payload.end());
    const auto now = quic_server::MonotonicClock::now();
    return map_enqueue_result(transport_.enqueue(
      connection_id_,
      {
        .lane = lane,
        .bytes = std::move(bytes),
        .deadline = now + lifetime(config_.profile, lane),
        .replaceable = replaceable,
      }
    ));
  }
}  // namespace lumen::protocol_v3::media
