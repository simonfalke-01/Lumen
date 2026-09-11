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
    std::vector<float> samples;  ///< Complete interleaved PCM frame.
    std::uint64_t sample_position {};  ///< Exact first-sample position at 48 kHz.
    std::uint32_t gap_frames {};  ///< Missing frames represented by silence before this frame.
    bool discontinuity {};  ///< Whether capture reinitialization invalidated prior continuity.
  };

  using sample_queue_t = std::shared_ptr<safe::queue_t<captured_frame_t>>;
  using pcm_slab_queue_t = std::shared_ptr<safe::queue_t<std::vector<float>>>;

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
    pcm_slab_queue_t free_pcm_slabs,
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
    if (!opus || opus_multistream_encoder_ctl(opus.get(), OPUS_SET_BITRATE(stream.bitrate)) != OPUS_OK ||
        opus_multistream_encoder_ctl(opus.get(), OPUS_SET_VBR(0)) != OPUS_OK ||
        opus_multistream_encoder_ctl(opus.get(), OPUS_SET_INBAND_FEC(config.flags[config_t::INBAND_FEC] ? 1 : 0)) != OPUS_OK ||
        opus_multistream_encoder_ctl(opus.get(), OPUS_SET_PACKET_LOSS_PERC(config.flags[config_t::INBAND_FEC] ? 5 : 0)) != OPUS_OK ||
        opus_multistream_encoder_ctl(opus.get(), OPUS_SET_DTX(config.flags[config_t::DTX] ? 1 : 0)) != OPUS_OK) {
      BOOST_LOG(error) << "Couldn't configure the negotiated Opus encoder"sv;
      return;
    }

    BOOST_LOG(info) << "Opus initialized: "sv << stream.sampleRate / 1000 << " kHz, "sv
                    << stream.channelCount << " channels, "sv
                    << stream.bitrate / 1000 << " kbps (total), LOWDELAY"sv;

    auto frame_size = config.frameSamples != 0 ? config.frameSamples : config.packetDuration * stream.sampleRate / 1000;
    auto encode_and_publish = [&](std::span<const float> pcm, const std::uint64_t sample_position, const bool discontinuity) {
      const auto locked_destination = destination.lock();
      if (!locked_destination) {
        return std::optional {AudioPacketDestination::enqueue_result_e::closed};
      }
      if (const auto lease = locked_destination->acquire_packet_storage()) {
        const int bytes = opus_multistream_encode_float(
          opus.get(),
          pcm.data(),
          frame_size,
          lease->storage.data(),
          static_cast<opus_int32>(lease->storage.size())
        );
        if (bytes < 0) {
          locked_destination->cancel_packet_storage(*lease);
          BOOST_LOG(error) << "Couldn't encode audio: "sv << opus_strerror(bytes);
          return std::optional<AudioPacketDestination::enqueue_result_e> {};
        }
        return std::optional {locked_destination->commit_packet_storage(
          *lease,
          static_cast<std::size_t>(bytes),
          sample_position,
          discontinuity
        )};
      }
      if (locked_destination->requires_fixed_packet_storage()) {
        return std::optional {AudioPacketDestination::enqueue_result_e::backpressure};
      }

      buffer_t packet {AudioPacketDestination::maximum_encoded_packet_bytes};
      const int bytes = opus_multistream_encode_float(
        opus.get(),
        pcm.data(),
        frame_size,
        std::begin(packet),
        static_cast<opus_int32>(packet.size())
      );
      if (bytes < 0) {
        BOOST_LOG(error) << "Couldn't encode audio: "sv << opus_strerror(bytes);
        return std::optional<AudioPacketDestination::enqueue_result_e> {};
      }
      packet.fake_resize(bytes);
      return std::optional {locked_destination->enqueue(packet_t {
        .payload = std::move(packet),
        .sample_position = sample_position,
        .discontinuity = discontinuity,
      })};
    };
    std::vector<float> silence(static_cast<std::size_t>(frame_size * stream.channelCount), 0.0f);
    bool publication_discontinuity_pending = false;
    while (auto sample = samples->pop()) {
      auto recycle_pcm = util::fail_guard([&]() {
        if (free_pcm_slabs && !sample->samples.empty()) {
          (void) free_pcm_slabs->raise(std::move(sample->samples));
        }
      });
      const auto first_gap_position = sample->sample_position -
                                      static_cast<std::uint64_t>(sample->gap_frames) * frame_size;
      for (std::uint32_t gap = 0; gap < sample->gap_frames; ++gap) {
        const auto result = encode_and_publish(
          silence,
          first_gap_position + static_cast<std::uint64_t>(gap) * frame_size,
          gap == 0 || publication_discontinuity_pending
        );
        if (!result || *result == AudioPacketDestination::enqueue_result_e::closed) {
          return;
        }
        if (*result == AudioPacketDestination::enqueue_result_e::backpressure) {
          publication_discontinuity_pending = true;
          break;
        }
        publication_discontinuity_pending = false;
      }
      const auto result = encode_and_publish(
        sample->samples,
        sample->sample_position,
        (sample->discontinuity && sample->gap_frames == 0) || publication_discontinuity_pending
      );
      if (!result || *result == AudioPacketDestination::enqueue_result_e::closed) {
        return;
      }
      if (*result == AudioPacketDestination::enqueue_result_e::backpressure) {
        publication_discontinuity_pending = true;
        continue;
      }
      publication_discontinuity_pending = false;
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

    auto frame_size = config.frameSamples != 0 ? config.frameSamples : config.packetDuration * stream.sampleRate / 1000;
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

    const auto packet_duration_milliseconds = std::max(1, (frame_size * 1'000 + stream.sampleRate - 1) / stream.sampleRate);
    const auto legacy_queue_frames = static_cast<std::uint32_t>(std::max(1, 120 / packet_duration_milliseconds));
    const auto maximum_queue_frames = config.captureQueueFrames == 0 ?
                                        legacy_queue_frames :
                                        std::clamp(config.captureQueueFrames, 1U, legacy_queue_frames);
    auto samples = std::make_shared<sample_queue_t::element_type>(maximum_queue_frames);
    auto free_pcm_slabs = std::make_shared<pcm_slab_queue_t::element_type>(maximum_queue_frames + 1U);
    const auto samples_per_frame = static_cast<std::size_t>(frame_size * stream.channelCount);
    try {
      for (std::uint32_t index = 0; index < maximum_queue_frames + 1U; ++index) {
        std::vector<float> slab(samples_per_frame);
        if (!free_pcm_slabs->raise(std::move(slab))) {
          return;
        }
      }
    } catch (...) {
      return;
    }
    auto encoding = std::make_shared<std::atomic_bool>(true);
    std::jthread thread {encodeThread, samples, free_pcm_slabs, config, std::move(destination), encoding};
    bool wait_for_shutdown_after_cleanup = true;

    auto fg = util::fail_guard([&]() {
      samples->stop();
      thread.join();
      free_pcm_slabs->stop();

      if (wait_for_shutdown_after_cleanup) {
        shutdown_event->view();
      }
    });

    std::uint64_t next_sample_position {};
    std::uint32_t pending_gap_frames {};
    bool pending_discontinuity {};
    while (!shutdown_event->peek() && encoding->load(std::memory_order_acquire)) {
      auto sample_buffer = free_pcm_slabs->pop(std::chrono::milliseconds {0});
      if (!sample_buffer) {
        if (pending_gap_frames != UINT32_MAX) {
          ++pending_gap_frames;
        }
        continue;
      }

      auto status = mic->sample(*sample_buffer);
      switch (status) {
        case platf::capture_e::ok:
          break;
        case platf::capture_e::timeout:
          (void) free_pcm_slabs->raise(std::move(*sample_buffer));
          continue;
        case platf::capture_e::reinit:
          BOOST_LOG(info) << "Reinitializing audio capture"sv;
          pending_discontinuity = true;
          mic.reset();
          do {
            mic = control->microphone(stream.mapping, stream.channelCount, stream.sampleRate, frame_size, continuous_audio, host_audio);
            if (!mic) {
              BOOST_LOG(warning) << "Couldn't re-initialize audio input"sv;
            }
          } while (!mic && !shutdown_event->view(5s));
          (void) free_pcm_slabs->raise(std::move(*sample_buffer));
          continue;
        default:
          return;
      }

      captured_frame_t captured {
        .samples = std::move(*sample_buffer),
        .sample_position = next_sample_position,
        .gap_frames = pending_gap_frames,
        .discontinuity = pending_discontinuity,
      };
      if (samples->raise(std::move(captured))) {
        pending_gap_frames = 0;
        pending_discontinuity = false;
      } else if (pending_gap_frames != UINT32_MAX) {
        (void) free_pcm_slabs->raise(std::move(captured.samples));
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

  std::optional<opus_stream_config_t> select_opus_stream_config(
    const int channels,
    const bool high_quality
  ) noexcept {
    switch (channels) {
      case 2:
      case 6:
      case 8:
        return stream_configs[map_stream(channels, high_quality)];
      default:
        return std::nullopt;
    }
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
