/**
 * @file src/audio.cpp
 * @brief Definitions for audio capture and encoding.
 */
// standard includes
#include <span>
#include <thread>

// lib includes
#include <opus/opus_multistream.h>

// local includes
#include "audio.h"
#include "config.h"
#include "globals.h"
#include "logging.h"
#include "platform/common.h"
#include "thread_safe.h"
#include "utility.h"

namespace audio {
  using namespace std::literals;
  /**
   * @brief Owning pointer for an Opus multistream encoder.
   */
  using opus_t = util::safe_ptr<OpusMSEncoder, opus_multistream_encoder_destroy>;
  /**
   * @brief Shared queue carrying captured PCM sample buffers to the encoder thread.
   */
  struct captured_frame_t {
    std::vector<float> samples;
    std::uint64_t sample_position {};
    std::uint32_t gap_frames {};
  };
  using sample_queue_t = std::shared_ptr<safe::queue_t<captured_frame_t>>;

  static int start_audio_control(audio_ctx_t &ctx);
  static void stop_audio_control(audio_ctx_t &);
  static void apply_surround_params(opus_stream_config_t &stream, const stream_params_t &params);

  /**
   * @brief Select the Opus stream configuration for a channel count and quality tier.
   *
   * @param channels Number of audio channels in the stream.
   * @param quality Whether the high-quality Opus layout should be selected.
   * @return Index into `stream_configs` for the requested layout.
   */
  int map_stream(int channels, bool quality);

  constexpr auto SAMPLE_RATE = 48000;  ///< Audio sample rate in hertz required by Opus.

  // NOTE: If you adjust the bitrates listed here, make sure to update the
  // corresponding bitrate adjustment logic in rtsp_stream::cmd_announce()
  /**
   * @brief Opus stream layouts and bitrates advertised to clients.
   */
  opus_stream_config_t stream_configs[MAX_STREAM_CONFIG] {
    {
      SAMPLE_RATE,
      2,
      1,
      1,
      platf::speaker::map_stereo,
      96000,
    },
    {
      SAMPLE_RATE,
      2,
      1,
      1,
      platf::speaker::map_stereo,
      512000,
    },
    {
      SAMPLE_RATE,
      6,
      4,
      2,
      platf::speaker::map_surround51,
      256000,
    },
    {
      SAMPLE_RATE,
      6,
      6,
      0,
      platf::speaker::map_surround51,
      1536000,
    },
    {
      SAMPLE_RATE,
      8,
      5,
      3,
      platf::speaker::map_surround71,
      450000,
    },
    {
      SAMPLE_RATE,
      8,
      8,
      0,
      platf::speaker::map_surround71,
      2048000,
    },
  };

  /**
   * @brief Encode captured PCM samples into Opus packets on the audio worker thread.
   *
   * @param samples Queue of captured PCM sample buffers to encode.
   * @param config Audio stream settings negotiated with the client.
   * @param destination Weak protocol-owned destination for encoded packets.
   * @param encoding True until this worker exits, allowing capture to detect delivery failure.
   */
  void encodeThread(
    sample_queue_t samples,
    config_t config,
    packet_destination_t destination,
    const std::shared_ptr<std::atomic_bool> &encoding
  ) {
    auto encoding_guard = util::fail_guard([&encoding]() {
      encoding->store(false, std::memory_order_release);
    });
    auto stream = stream_configs[map_stream(config.channels, config.flags[config_t::HIGH_QUALITY])];
    if (config.flags[config_t::CUSTOM_SURROUND_PARAMS]) {
      apply_surround_params(stream, config.customStreamParams);
    }
    if (config.bitrate != 0) {
      const auto maximum_bitrate = std::min(2'048'000, stream.streams * 512'000);
      if (config.bitrate < 6'000 || config.bitrate > maximum_bitrate) {
        BOOST_LOG(error) << "Rejected invalid negotiated Opus bitrate: "sv << config.bitrate;
        return;
      }
      stream.bitrate = config.bitrate;
    }

    // Encoding takes place on this thread
    platf::set_thread_name("audio::encode");
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    opus_t opus {opus_multistream_encoder_create(
      stream.sampleRate,
      stream.channelCount,
      stream.streams,
      stream.coupledStreams,
      stream.mapping,
      OPUS_APPLICATION_RESTRICTED_LOWDELAY,
      nullptr
    )};

    opus_multistream_encoder_ctl(opus.get(), OPUS_SET_BITRATE(stream.bitrate));
    opus_multistream_encoder_ctl(opus.get(), OPUS_SET_VBR(0));

    BOOST_LOG(info) << "Opus initialized: "sv << stream.sampleRate / 1000 << " kHz, "sv
                    << stream.channelCount << " channels, "sv
                    << stream.bitrate / 1000 << " kbps (total), LOWDELAY"sv;

    auto frame_size = config.packetDuration * stream.sampleRate / 1000;
    auto encode_and_publish = [&](std::span<const float> pcm, const std::uint64_t sample_position,
                                  const bool discontinuity) {
      buffer_t packet {1400};
      const int bytes = opus_multistream_encode_float(
        opus.get(), pcm.data(), frame_size, std::begin(packet), static_cast<opus_int32>(packet.size())
      );
      if (bytes < 0) {
        BOOST_LOG(error) << "Couldn't encode audio: "sv << opus_strerror(bytes);
        return std::optional<AudioPacketDestination::enqueue_result_e> {};
      }
      packet.fake_resize(bytes);
      const auto locked_destination = destination.lock();
      if (!locked_destination) {
        return std::optional {AudioPacketDestination::enqueue_result_e::closed};
      }
      return std::optional {locked_destination->enqueue(packet_t {
        .payload = std::move(packet),
        .sample_position = sample_position,
        .discontinuity = discontinuity,
      })};
    };
    std::vector<float> silence(static_cast<std::size_t>(frame_size * stream.channelCount), 0.0f);
    while (auto sample = samples->pop()) {
      const auto first_gap_position = sample->sample_position -
                                      static_cast<std::uint64_t>(sample->gap_frames) * frame_size;
      for (std::uint32_t gap = 0; gap < sample->gap_frames; ++gap) {
        const auto result = encode_and_publish(
          silence,
          first_gap_position + static_cast<std::uint64_t>(gap) * frame_size,
          gap == 0
        );
        if (!result || *result == AudioPacketDestination::enqueue_result_e::closed) {
          return;
        }
        if (*result == AudioPacketDestination::enqueue_result_e::backpressure) {
          BOOST_LOG(error) << "Audio destination backpressure while preserving a capture gap"sv;
          return;
        }
      }
      const auto result = encode_and_publish(sample->samples, sample->sample_position, false);
      if (!result || *result == AudioPacketDestination::enqueue_result_e::closed) {
        return;
      }
      if (*result == AudioPacketDestination::enqueue_result_e::backpressure) {
        BOOST_LOG(error) << "Audio destination backpressure"sv;
        return;
      }
    }
  }

  /**
   * @brief Run the capture loop for this backend.
   */
  void capture(safe::mail_t mail, config_t config, packet_destination_t destination) {
    auto shutdown_event = mail->event<bool>(mail::shutdown);
    if (!config::audio.stream) {
      shutdown_event->view();
      return;
    }
    auto stream = stream_configs[map_stream(config.channels, config.flags[config_t::HIGH_QUALITY])];
    if (config.flags[config_t::CUSTOM_SURROUND_PARAMS]) {
      apply_surround_params(stream, config.customStreamParams);
    }

    auto ref = get_audio_ctx_ref();
    if (!ref) {
      return;
    }

    auto init_failure_fg = util::fail_guard([&shutdown_event]() {
      BOOST_LOG(error) << "Unable to initialize audio capture. The stream will not have audio."sv;

      // Wait for shutdown to be signalled if we fail init.
      // This allows streaming to continue without audio.
      shutdown_event->view();
    });

    auto &control = ref->control;
    if (!control) {
      return;
    }

    // Order of priority:
    // 1. Virtual sink
    // 2. Audio sink
    // 3. Host
    std::string *sink = &ref->sink.host;
    if (!config::audio.sink.empty()) {
      sink = &config::audio.sink;
    }

    // Prefer the virtual sink if host playback is disabled or there's no other sink
    if (ref->sink.null && (!config.flags[config_t::HOST_AUDIO] || sink->empty())) {
      auto &null = *ref->sink.null;
      switch (stream.channelCount) {
        case 2:
          sink = &null.stereo;
          break;
        case 6:
          sink = &null.surround51;
          break;
        case 8:
          sink = &null.surround71;
          break;
      }
    }

    // Only the first to start a session may change the default sink
    if (!ref->sink_flag->exchange(true, std::memory_order_acquire)) {
      // If the selected sink is different than the current one, change sinks.
      ref->restore_sink = ref->sink.host != *sink;
      if (ref->restore_sink) {
        if (control->set_sink(*sink)) {
          return;
        }
      }
    }

    auto frame_size = config.packetDuration * stream.sampleRate / 1000;
    bool host_audio = config.flags[config_t::HOST_AUDIO];
    bool continuous_audio = config.flags[config_t::CONTINUOUS_AUDIO];
    auto mic = control->microphone(stream.mapping, stream.channelCount, stream.sampleRate, frame_size, continuous_audio, host_audio);
    if (!mic) {
      return;
    }

    // Audio is initialized, so we don't want to print the failure message
    init_failure_fg.disable();

    // Capture takes place on this thread
    platf::adjust_thread_priority(platf::thread_priority_e::critical);

    const auto maximum_queue_frames = static_cast<std::uint32_t>(
      std::max(1, 120 / std::max(config.packetDuration, 1))
    );
    auto samples = std::make_shared<sample_queue_t::element_type>(maximum_queue_frames);
    auto encoding = std::make_shared<std::atomic_bool>(true);
    std::jthread thread {encodeThread, samples, config, std::move(destination), encoding};
    bool wait_for_shutdown_after_cleanup = true;

    auto fg = util::fail_guard([&]() {
      samples->stop();
      thread.join();

      if (wait_for_shutdown_after_cleanup) {
        shutdown_event->view();
      }
    });

    int samples_per_frame = frame_size * stream.channelCount;

    std::uint64_t next_sample_position {};
    std::uint32_t pending_gap_frames {};
    while (!shutdown_event->peek() && encoding->load(std::memory_order_acquire)) {
      std::vector<float> sample_buffer;
      sample_buffer.resize(samples_per_frame);

      auto status = mic->sample(sample_buffer);
      switch (status) {
        case platf::capture_e::ok:
          break;
        case platf::capture_e::timeout:
          continue;
        case platf::capture_e::reinit:
          BOOST_LOG(info) << "Reinitializing audio capture"sv;
          mic.reset();
          do {
            mic = control->microphone(stream.mapping, stream.channelCount, stream.sampleRate, frame_size, continuous_audio, host_audio);
            if (!mic) {
              BOOST_LOG(warning) << "Couldn't re-initialize audio input"sv;
            }
          } while (!mic && !shutdown_event->view(5s));
          continue;
        default:
          return;
      }

      captured_frame_t captured {
        .samples = std::move(sample_buffer),
        .sample_position = next_sample_position,
        .gap_frames = pending_gap_frames,
      };
      if (samples->raise(std::move(captured))) {
        pending_gap_frames = 0;
      } else if (pending_gap_frames != UINT32_MAX) {
        ++pending_gap_frames;
      }
      next_sample_position += static_cast<std::uint64_t>(frame_size);
    }
    if (!encoding->load(std::memory_order_acquire)) {
      wait_for_shutdown_after_cleanup = false;
    }
  }

  audio_ctx_ref_t get_audio_ctx_ref() {
    static auto control_shared {safe::make_shared<audio_ctx_t>(start_audio_control, stop_audio_control)};
    return control_shared.ref();
  }

  bool is_audio_ctx_sink_available(const audio_ctx_t &ctx) {
    if (!ctx.control) {
      return false;
    }

    const std::string &sink = ctx.sink.host.empty() ? config::audio.sink : ctx.sink.host;
    if (sink.empty()) {
      return false;
    }

    return ctx.control->is_sink_available(sink);
  }

  /**
   * @brief Select the Opus stream configuration for a channel count and quality tier.
   */
  int map_stream(int channels, bool quality) {
    int shift = quality ? 1 : 0;
    switch (channels) {
      case 2:
        return STEREO + shift;
      case 6:
        return SURROUND51 + shift;
      case 8:
        return SURROUND71 + shift;
    }
    return STEREO;
  }

  int start_audio_control(audio_ctx_t &ctx) {
    auto fg = util::fail_guard([]() {
      BOOST_LOG(warning) << "There will be no audio"sv;
    });

    ctx.sink_flag = std::make_unique<std::atomic_bool>(false);

    // The default sink has not been replaced yet.
    ctx.restore_sink = false;

    if (!(ctx.control = platf::audio_control())) {
      return 0;
    }

    auto sink = ctx.control->sink_info();
    if (!sink) {
      // Let the calling code know it failed
      ctx.control.reset();
      return 0;
    }

    ctx.sink = std::move(*sink);

    fg.disable();
    return 0;
  }

  void stop_audio_control(audio_ctx_t &ctx) {
    // restore audio-sink if applicable
    if (!ctx.restore_sink) {
      return;
    }

    // Change back to the host sink, unless there was none
    const std::string &sink = ctx.sink.host.empty() ? config::audio.sink : ctx.sink.host;
    if (!sink.empty()) {
      // Best effort, it's allowed to fail
      ctx.control->set_sink(sink);
    }
  }

  void apply_surround_params(opus_stream_config_t &stream, const stream_params_t &params) {
    stream.channelCount = params.channelCount;
    stream.streams = params.streams;
    stream.coupledStreams = params.coupledStreams;
    stream.mapping = params.mapping;
  }
}  // namespace audio
