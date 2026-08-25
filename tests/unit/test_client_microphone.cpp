/**
 * @file tests/unit/test_client_microphone.cpp
 * @brief Test the portable client microphone receive and Opus decode core.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <numbers>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

// lib includes
#include <gtest/gtest.h>
#include <opus/opus.h>

// local includes
#include <src/client_microphone.h>

namespace {
  using namespace std::chrono_literals;
  using microphone_clock_t = client_microphone::clock_t;
  using client_microphone::packet_kind_e;
  using client_microphone::packet_t;
  using client_microphone::submit_result_e;

  constexpr auto START = microphone_clock_t::time_point {};  ///< Deterministic origin used by receiver tests.

  /**
   * @brief One invocation recorded by the fake decoder.
   */
  struct decode_call_t {
    std::uint8_t marker;  ///< First encoded payload byte or zero for PLC.
    bool fec;  ///< Whether the invocation requested in-band FEC.
    bool conceal;  ///< Whether the invocation requested packet-loss concealment.
  };

  /**
   * @brief Deterministic decoder that exposes normal, FEC, and PLC decisions.
   */
  class fake_decoder_t final: public client_microphone::decoder_t {
  public:
    int reset() override {
      ++reset_calls;
      return fail_reset ? -1 : 0;
    }

    int decode(
      std::span<const std::uint8_t> payload,
      bool use_fec,
      std::span<std::int16_t> output
    ) override {
      calls.push_back({payload.front(), use_fec, false});
      if (fail_decode) {
        return -1;
      }

      const auto value = static_cast<std::int16_t>(payload.front() + (use_fec ? 1000 : 0));
      std::ranges::fill(output, value);
      return static_cast<int>(client_microphone::SAMPLES_PER_FRAME);
    }

    int conceal(std::span<std::int16_t> output) override {
      calls.push_back({0, false, true});
      if (fail_conceal) {
        return -1;
      }

      std::ranges::fill(output, std::int16_t {-1});
      return static_cast<int>(client_microphone::SAMPLES_PER_FRAME);
    }

    std::vector<decode_call_t> calls;  ///< Ordered decoder invocations.
    int reset_calls {};  ///< Number of codec reset requests.
    bool fail_reset {};  ///< Whether reset should fail.
    bool fail_decode {};  ///< Whether packet and FEC decode should fail.
    bool fail_conceal {};  ///< Whether PLC should fail.
  };

  /**
   * @brief Platform sink double that records lifecycle and complete PCM frames.
   */
  class fake_sink_t final: public client_microphone::sink_t {
  public:
    bool begin(std::uint64_t generation, std::uint32_t sample_rate, std::uint8_t channels) override {
      begin_generations.push_back(generation);
      begin_sample_rates.push_back(sample_rate);
      begin_channel_counts.push_back(channels);
      return begin_result;
    }

    bool write(std::uint64_t generation, std::span<const std::int16_t> samples) override {
      write_generations.push_back(generation);
      frames.emplace_back(samples.begin(), samples.end());
      return write_result;
    }

    void end(std::uint64_t generation) override {
      end_generations.push_back(generation);
    }

    std::vector<std::uint64_t> begin_generations;  ///< Generations passed to begin.
    std::vector<std::uint32_t> begin_sample_rates;  ///< Sample rates passed to begin.
    std::vector<std::uint8_t> begin_channel_counts;  ///< Channel counts passed to begin.
    std::vector<std::uint64_t> write_generations;  ///< Generations passed with PCM frames.
    std::vector<std::vector<std::int16_t>> frames;  ///< Complete PCM frames offered to the sink.
    std::vector<std::uint64_t> end_generations;  ///< Generations passed to end.
    bool begin_result {true};  ///< Result returned by begin.
    bool write_result {true};  ///< Result returned by write.
  };

  /** @brief Thread-safe sink used to observe the real clocked playout worker. */
  class clocked_sink_t final: public client_microphone::sink_t {
  public:
    bool begin(std::uint64_t generation, std::uint32_t, std::uint8_t) override {
      std::lock_guard lock {mutex};
      active_generation = generation;
      return true;
    }

    bool write(std::uint64_t generation, std::span<const std::int16_t> samples) override {
      std::lock_guard lock {mutex};
      if (generation != active_generation) {
        return false;
      }
      frames.emplace_back(samples.begin(), samples.end());
      write_times.push_back(microphone_clock_t::now());
      changed.notify_all();
      return true;
    }

    void end(std::uint64_t generation) override {
      std::lock_guard lock {mutex};
      if (generation == active_generation) {
        active_generation = 0;
        ++end_calls;
      }
      changed.notify_all();
    }

    bool wait_for_frames(const std::size_t count, const std::chrono::milliseconds timeout) {
      std::unique_lock lock {mutex};
      return changed.wait_for(lock, timeout, [&]() {
        return frames.size() >= count;
      });
    }

    std::vector<std::vector<std::int16_t>> frame_snapshot() const {
      std::lock_guard lock {mutex};
      return frames;
    }

    std::vector<microphone_clock_t::time_point> write_time_snapshot() const {
      std::lock_guard lock {mutex};
      return write_times;
    }

    std::uint64_t active_generation_snapshot() const {
      std::lock_guard lock {mutex};
      return active_generation;
    }

    std::size_t end_call_count() const {
      std::lock_guard lock {mutex};
      return end_calls;
    }

  private:
    mutable std::mutex mutex;  ///< Protects observations shared with the playout worker.
    std::condition_variable changed;  ///< Wakes bounded test waits after writes and stop.
    std::uint64_t active_generation {};  ///< Generation accepted by the sink.
    std::vector<std::vector<std::int16_t>> frames;  ///< Complete frames written by the worker.
    std::vector<microphone_clock_t::time_point> write_times;  ///< Monotonic time of each completed write.
    std::size_t end_calls {};  ///< Balanced sink end calls.
  };

  /**
   * @brief Build one ordinary encoded test packet.
   *
   * @param generation Owning stream generation.
   * @param sequence Monotonic packet sequence.
   * @param timestamp Wrapping 48 kHz sample timestamp.
   * @param marker Deterministic fake encoded payload value.
   * @return Packet ready for receiver submission.
   */
  packet_t opus_packet(
    std::uint64_t generation,
    std::uint64_t sequence,
    std::uint32_t timestamp,
    std::uint8_t marker
  ) {
    return {generation, sequence, timestamp, packet_kind_e::opus, {marker}};
  }

  /**
   * @brief Build one authenticated silent test packet.
   *
   * @param generation Owning stream generation.
   * @param sequence Monotonic packet sequence.
   * @param timestamp Wrapping 48 kHz sample timestamp.
   * @return Silent packet ready for receiver submission.
   */
  packet_t silence_packet(std::uint64_t generation, std::uint64_t sequence, std::uint32_t timestamp) {
    return {generation, sequence, timestamp, packet_kind_e::silence, {}};
  }

  /**
   * @brief Fixture exposing fake dependencies before their ownership is transferred.
   */
  class client_microphone_test: public testing::Test {
  protected:
    void SetUp() override {
      auto decoder = std::make_unique<fake_decoder_t>();
      decoder_ = decoder.get();
      receiver_ = std::make_unique<client_microphone::receiver_t>(std::move(decoder), sink_);
    }

    fake_sink_t sink_;  ///< Recording platform sink.
    fake_decoder_t *decoder_ {};  ///< Borrowed decoder owned by receiver.
    std::unique_ptr<client_microphone::receiver_t> receiver_;  ///< Receiver under test.
  };
}  // namespace

TEST(ClientMicrophoneOpusDecoder, DecodesRealTwentyMillisecondMonoPacket) {
  int error = OPUS_OK;
  auto *encoder = opus_encoder_create(
    client_microphone::SAMPLE_RATE,
    client_microphone::CHANNEL_COUNT,
    OPUS_APPLICATION_VOIP,
    &error
  );
  ASSERT_EQ(error, OPUS_OK);
  ASSERT_NE(encoder, nullptr);

  std::array<std::int16_t, client_microphone::SAMPLES_PER_FRAME> source {};
  for (std::size_t index = 0; index < source.size(); ++index) {
    constexpr auto FREQUENCY = 440.0;
    constexpr auto AMPLITUDE = 12000.0;
    const auto phase = 2.0 * std::numbers::pi * FREQUENCY * static_cast<double>(index) /
                       client_microphone::SAMPLE_RATE;
    source[index] = static_cast<std::int16_t>(std::sin(phase) * AMPLITUDE);
  }

  std::array<std::uint8_t, client_microphone::MAX_OPUS_PAYLOAD_SIZE> encoded {};
  const auto encoded_size = opus_encode(
    encoder,
    source.data(),
    static_cast<int>(source.size()),
    encoded.data(),
    static_cast<opus_int32>(encoded.size())
  );
  opus_encoder_destroy(encoder);
  ASSERT_GT(encoded_size, 0);

  client_microphone::opus_decoder_t decoder;
  std::array<std::int16_t, client_microphone::SAMPLES_PER_FRAME> decoded {};
  EXPECT_EQ(
    decoder.decode(std::span {encoded}.first(static_cast<std::size_t>(encoded_size)), false, decoded),
    static_cast<int>(client_microphone::SAMPLES_PER_FRAME)
  );
  EXPECT_TRUE(std::ranges::any_of(decoded, [](std::int16_t sample) {
    return sample != 0;
  }));
  EXPECT_EQ(decoder.reset(), OPUS_OK);
  EXPECT_EQ(
    decoder.decode(std::span {encoded}.first(static_cast<std::size_t>(encoded_size)), true, decoded),
    static_cast<int>(client_microphone::SAMPLES_PER_FRAME)
  );
  EXPECT_EQ(decoder.reset(), OPUS_OK);
  EXPECT_EQ(decoder.conceal(decoded), static_cast<int>(client_microphone::SAMPLES_PER_FRAME));

  client_microphone::opus_decoder_t moved {std::move(decoder)};
  client_microphone::opus_decoder_t assigned;
  assigned = std::move(moved);
  EXPECT_EQ(assigned.reset(), OPUS_OK);
}

TEST(ClientMicrophoneOpusDecoder, RejectsInvalidBufferShapes) {
  client_microphone::opus_decoder_t decoder;
  std::array<std::int16_t, client_microphone::SAMPLES_PER_FRAME> output {};
  std::array<std::int16_t, client_microphone::SAMPLES_PER_FRAME - 1> short_output {};
  std::vector<std::uint8_t> oversized(client_microphone::MAX_OPUS_PAYLOAD_SIZE + 1, 1);

  EXPECT_EQ(decoder.decode({}, false, output), OPUS_BAD_ARG);
  EXPECT_EQ(decoder.decode(oversized, false, output), OPUS_BAD_ARG);
  EXPECT_EQ(decoder.decode(std::array<std::uint8_t, 1> {1}, false, short_output), OPUS_BAD_ARG);
  EXPECT_EQ(decoder.conceal(short_output), OPUS_BAD_ARG);
}

TEST(ClientMicrophoneClockedReceiver, DrivesReorderFecAndPlcFromIndependentTwentyMillisecondClock) {
  clocked_sink_t sink;
  auto decoder = std::make_unique<fake_decoder_t>();
  auto *decoder_observer = decoder.get();
  client_microphone::clocked_receiver_t receiver {std::move(decoder), sink};

  const auto submitted_at = microphone_clock_t::now();
  ASSERT_TRUE(receiver.reset(77));
  EXPECT_EQ(receiver.submit(opus_packet(76, 10, 1000, 10)), submit_result_e::wrong_generation);
  ASSERT_EQ(receiver.submit(opus_packet(77, 10, 1000, 10)), submit_result_e::accepted);
  ASSERT_EQ(receiver.submit(opus_packet(77, 12, 2920, 12)), submit_result_e::accepted);
  ASSERT_EQ(receiver.submit(opus_packet(77, 15, 5800, 15)), submit_result_e::accepted);

  ASSERT_TRUE(sink.wait_for_frames(6, 750ms));
  receiver.shutdown();

  const auto frames = sink.frame_snapshot();
  const auto write_times = sink.write_time_snapshot();
  ASSERT_EQ(frames.size(), 6U);
  ASSERT_EQ(write_times.size(), 6U);
  EXPECT_EQ(frames[0].front(), 10);
  EXPECT_EQ(frames[1].front(), 1012);
  EXPECT_EQ(frames[2].front(), 12);
  EXPECT_EQ(frames[3].front(), -1);
  EXPECT_EQ(frames[4].front(), 1015);
  EXPECT_EQ(frames[5].front(), 15);
  EXPECT_GE(write_times[0] - submitted_at, 45ms);
  for (std::size_t index = 1; index < write_times.size(); ++index) {
    EXPECT_GE(write_times[index] - write_times[index - 1], 10ms);
  }
  ASSERT_EQ(decoder_observer->calls.size(), 6U);
  EXPECT_FALSE(decoder_observer->calls[0].fec);
  EXPECT_TRUE(decoder_observer->calls[1].fec);
  EXPECT_FALSE(decoder_observer->calls[2].fec);
  EXPECT_TRUE(decoder_observer->calls[3].conceal);
  EXPECT_TRUE(decoder_observer->calls[4].fec);
  EXPECT_FALSE(decoder_observer->calls[5].fec);
  EXPECT_EQ(receiver.statistics().fec_frames, 2U);
  EXPECT_EQ(receiver.statistics().plc_frames, 1U);
  EXPECT_FALSE(receiver.active());
  EXPECT_EQ(receiver.submit(opus_packet(77, 13, 3880, 13)), submit_result_e::inactive);
  EXPECT_EQ(sink.active_generation_snapshot(), 0U);
  EXPECT_EQ(sink.end_call_count(), 1U);
}

TEST(ClientMicrophoneClockedReceiver, StopIsReusableAndShutdownJoinsWithinBound) {
  clocked_sink_t sink;
  client_microphone::clocked_receiver_t receiver {std::make_unique<fake_decoder_t>(), sink};
  ASSERT_TRUE(receiver.reset(80));
  ASSERT_EQ(receiver.submit(opus_packet(80, 1, 100, 1)), submit_result_e::accepted);
  receiver.stop();
  EXPECT_FALSE(receiver.active());
  EXPECT_EQ(receiver.queued_packets(), 0U);

  ASSERT_TRUE(receiver.reset(81));
  ASSERT_EQ(receiver.submit(silence_packet(81, 1, 100)), submit_result_e::accepted);
  ASSERT_TRUE(sink.wait_for_frames(1, 500ms));

  const auto shutdown_started = microphone_clock_t::now();
  receiver.shutdown();
  EXPECT_LT(microphone_clock_t::now() - shutdown_started, 2s);
  EXPECT_FALSE(receiver.reset(82));
  EXPECT_EQ(sink.end_call_count(), 2U);
}

TEST(ClientMicrophoneWriter, ArbitratesLegacyAndV3WithTaggedStableOwnership) {
  const auto legacy = client_microphone::writer_owner_t::legacy(0x2001);
  const auto same_numeric_v3 = client_microphone::writer_owner_t::protocol_v3(0x2001);
  const auto second_v3 = client_microphone::writer_owner_t::protocol_v3(0x2002);

  client_microphone::release_writer(legacy);
  client_microphone::release_writer(same_numeric_v3);
  client_microphone::release_writer(second_v3);

  ASSERT_TRUE(client_microphone::claim_writer(legacy));
  EXPECT_TRUE(client_microphone::claim_writer(legacy));
  EXPECT_FALSE(client_microphone::claim_writer(same_numeric_v3));
  EXPECT_FALSE(client_microphone::claim_writer(second_v3));

  client_microphone::release_writer(same_numeric_v3);
  EXPECT_FALSE(client_microphone::claim_writer(second_v3));
  client_microphone::release_writer(legacy);

  ASSERT_TRUE(client_microphone::claim_writer(same_numeric_v3));
  EXPECT_TRUE(client_microphone::claim_writer(same_numeric_v3));
  EXPECT_FALSE(client_microphone::claim_writer(legacy));
  EXPECT_FALSE(client_microphone::claim_writer(second_v3));

  client_microphone::release_writer(legacy);
  EXPECT_FALSE(client_microphone::claim_writer(second_v3));
  client_microphone::release_writer(same_numeric_v3);
  ASSERT_TRUE(client_microphone::claim_writer(second_v3));
  client_microphone::release_writer(second_v3);

  EXPECT_FALSE(client_microphone::claim_writer(client_microphone::writer_owner_t::protocol_v3(0)));
}

TEST(ClientMicrophoneReceiver, RejectsNullDecoder) {
  fake_sink_t sink;
  EXPECT_THROW(client_microphone::receiver_t(nullptr, sink), std::invalid_argument);
}

TEST_F(client_microphone_test, EnforcesLifecycleGenerationAndPayloadBounds) {
  EXPECT_EQ(receiver_->submit(opus_packet(1, 10, 1000, 10), START), submit_result_e::inactive);
  EXPECT_EQ(receiver_->poll(START), 0U);

  ASSERT_TRUE(receiver_->reset(1, START));
  EXPECT_EQ(receiver_->poll(START), 0U);
  EXPECT_TRUE(receiver_->active());
  EXPECT_EQ(receiver_->generation(), 1U);
  ASSERT_EQ(sink_.begin_generations.size(), 1U);
  EXPECT_EQ(sink_.begin_generations.front(), 1U);
  EXPECT_EQ(sink_.begin_sample_rates.front(), client_microphone::SAMPLE_RATE);
  EXPECT_EQ(sink_.begin_channel_counts.front(), client_microphone::CHANNEL_COUNT);

  EXPECT_EQ(receiver_->submit(opus_packet(2, 10, 1000, 10), START), submit_result_e::wrong_generation);
  EXPECT_EQ(
    receiver_->submit({1, 10, 1000, packet_kind_e::opus, {}}, START),
    submit_result_e::invalid_payload
  );
  EXPECT_EQ(
    receiver_->submit(
      {1, 10, 1000, packet_kind_e::opus, std::vector<std::uint8_t>(client_microphone::MAX_OPUS_PAYLOAD_SIZE + 1, 1)},
      START
    ),
    submit_result_e::payload_too_large
  );
  EXPECT_EQ(
    receiver_->submit({1, 10, 1000, packet_kind_e::silence, {1}}, START),
    submit_result_e::invalid_payload
  );

  EXPECT_EQ(receiver_->statistics().wrong_generation_packets, 1U);
  EXPECT_EQ(receiver_->statistics().invalid_payload_packets, 3U);
}

TEST_F(client_microphone_test, ReordersWithinWindowAndRejectsDuplicateLateAndDistantPackets) {
  ASSERT_TRUE(receiver_->reset(7, START));

  EXPECT_EQ(receiver_->submit(opus_packet(7, 101, 1960, 101), START), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 100, 1000, 100), START + 1ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 100, 1000, 100), START + 2ms), submit_result_e::duplicate);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 102, 2920, 102), START + 3ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 103, 3880, 103), START + 4ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 104, 4840, 104), START + 5ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 105, 5800, 105), START + 6ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 106, 6760, 106), START + 7ms), submit_result_e::too_far_ahead);
  EXPECT_EQ(receiver_->queued_packets(), client_microphone::MAX_QUEUED_PACKETS);

  EXPECT_EQ(receiver_->poll(START + 59ms), 0U);
  ASSERT_EQ(receiver_->poll(START + 60ms), 1U);
  ASSERT_EQ(sink_.frames.size(), 1U);
  EXPECT_EQ(sink_.frames[0].front(), 100);
  EXPECT_EQ(receiver_->submit(opus_packet(7, 100, 1000, 100), START + 61ms), submit_result_e::late);

  ASSERT_EQ(receiver_->poll(START + 80ms), 1U);
  ASSERT_EQ(receiver_->poll(START + 100ms), 1U);
  EXPECT_EQ(sink_.frames[1].front(), 101);
  EXPECT_EQ(sink_.frames[2].front(), 102);
  EXPECT_EQ(receiver_->statistics().accepted_packets, 6U);
  EXPECT_EQ(receiver_->statistics().duplicate_packets, 1U);
  EXPECT_EQ(receiver_->statistics().late_packets, 1U);
  EXPECT_EQ(receiver_->statistics().out_of_window_packets, 1U);
}

TEST_F(client_microphone_test, ReordersAcrossTimestampWraparound) {
  constexpr auto LAST_TIMESTAMP = std::numeric_limits<std::uint32_t>::max() - 959U;
  ASSERT_TRUE(receiver_->reset(8, START));

  EXPECT_EQ(receiver_->submit(opus_packet(8, 101, 0, 20), START), submit_result_e::accepted);
  EXPECT_EQ(
    receiver_->submit(opus_packet(8, 100, LAST_TIMESTAMP, 10), START + 1ms),
    submit_result_e::accepted
  );
  EXPECT_EQ(receiver_->submit(opus_packet(8, 102, 960, 30), START + 2ms), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 80ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 100ms), 1U);
  ASSERT_EQ(sink_.frames.size(), 3U);
  EXPECT_EQ(sink_.frames[0].front(), 10);
  EXPECT_EQ(sink_.frames[1].front(), 20);
  EXPECT_EQ(sink_.frames[2].front(), 30);
}

TEST_F(client_microphone_test, RejectsTimestampDiscontinuityWithoutReset) {
  ASSERT_TRUE(receiver_->reset(9, START));
  ASSERT_EQ(receiver_->submit(opus_packet(9, 40, 10000, 40), START), submit_result_e::accepted);

  EXPECT_EQ(
    receiver_->submit(opus_packet(9, 39, 9999, 39), START + 1ms),
    submit_result_e::timestamp_discontinuity
  );
  EXPECT_EQ(
    receiver_->submit(opus_packet(9, 41, 10001, 41), START + 2ms),
    submit_result_e::timestamp_discontinuity
  );
  EXPECT_EQ(receiver_->statistics().timestamp_discontinuity_packets, 2U);
  EXPECT_EQ(receiver_->submit(opus_packet(9, 41, 10960, 41), START + 3ms), submit_result_e::accepted);

  ASSERT_TRUE(receiver_->reset(10, START + 4ms));
  EXPECT_EQ(receiver_->submit(opus_packet(10, 1, 55, 1), START + 5ms), submit_result_e::accepted);
}

TEST_F(client_microphone_test, BoundsExtremeAndVeryLateMonotonicSequences) {
  constexpr auto MAX_SEQUENCE = std::numeric_limits<std::uint64_t>::max();
  ASSERT_TRUE(receiver_->reset(90, START));
  ASSERT_EQ(receiver_->submit(opus_packet(90, 0, 0, 1), START), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(90, MAX_SEQUENCE, 0, 2), START + 1ms), submit_result_e::too_far_ahead);

  ASSERT_TRUE(receiver_->reset(91, START + 2ms));
  ASSERT_EQ(receiver_->submit(opus_packet(91, MAX_SEQUENCE, 0, 1), START + 2ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->submit(opus_packet(91, 0, 0, 2), START + 3ms), submit_result_e::late);
}

TEST_F(client_microphone_test, EvictsPacketsThatFallOutsideWindowAfterEarlyReorder) {
  ASSERT_TRUE(receiver_->reset(92, START));
  ASSERT_EQ(receiver_->submit(opus_packet(92, 105, 5800, 105), START), submit_result_e::accepted);
  ASSERT_EQ(receiver_->submit(opus_packet(92, 110, 10600, 110), START + 1ms), submit_result_e::accepted);
  ASSERT_EQ(receiver_->submit(opus_packet(92, 100, 1000, 100), START + 2ms), submit_result_e::accepted);

  EXPECT_EQ(receiver_->queued_packets(), 2U);
  EXPECT_EQ(receiver_->submit(opus_packet(92, 110, 10600, 110), START + 3ms), submit_result_e::too_far_ahead);
}

TEST_F(client_microphone_test, UsesFollowingPacketFecThenDecodesItNormally) {
  ASSERT_TRUE(receiver_->reset(10, START));
  ASSERT_EQ(receiver_->submit(opus_packet(10, 20, 2000, 20), START), submit_result_e::accepted);
  ASSERT_EQ(receiver_->submit(opus_packet(10, 22, 3920, 22), START + 1ms), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 80ms), 1U);
  EXPECT_EQ(receiver_->queued_packets(), 1U);
  EXPECT_EQ(receiver_->poll(START + 100ms), 1U);

  ASSERT_EQ(sink_.frames.size(), 3U);
  EXPECT_EQ(sink_.frames[0].front(), 20);
  EXPECT_EQ(sink_.frames[1].front(), 1022);
  EXPECT_EQ(sink_.frames[2].front(), 22);
  EXPECT_EQ(receiver_->statistics().decoded_frames, 2U);
  EXPECT_EQ(receiver_->statistics().fec_frames, 1U);
  EXPECT_EQ(receiver_->statistics().plc_frames, 0U);
}

TEST_F(client_microphone_test, UsesPlcWhenFutureDataExistsWithoutImmediateFec) {
  ASSERT_TRUE(receiver_->reset(11, START));
  ASSERT_EQ(receiver_->submit(opus_packet(11, 30, 3000, 30), START), submit_result_e::accepted);
  ASSERT_EQ(receiver_->submit(opus_packet(11, 33, 5880, 33), START + 1ms), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 80ms), 1U);
  ASSERT_EQ(decoder_->calls.size(), 2U);
  EXPECT_FALSE(decoder_->calls[0].fec);
  EXPECT_TRUE(decoder_->calls[1].conceal);
  EXPECT_EQ(receiver_->statistics().plc_frames, 1U);
}

TEST_F(client_microphone_test, UsesPlcBeforeFollowingAuthenticatedSilence) {
  ASSERT_TRUE(receiver_->reset(111, START));
  ASSERT_EQ(receiver_->submit(opus_packet(111, 1, 100, 1), START), submit_result_e::accepted);
  ASSERT_EQ(receiver_->submit(silence_packet(111, 3, 2020), START + 1ms), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 80ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 100ms), 1U);
  ASSERT_EQ(decoder_->calls.size(), 2U);
  EXPECT_FALSE(decoder_->calls[0].conceal);
  EXPECT_TRUE(decoder_->calls[1].conceal);
  EXPECT_EQ(receiver_->statistics().plc_frames, 1U);
  EXPECT_EQ(receiver_->statistics().silence_frames, 1U);
}

TEST_F(client_microphone_test, EmitsSilenceForAuthenticatedSilenceAndQueueUnderrun) {
  ASSERT_TRUE(receiver_->reset(12, START));
  ASSERT_EQ(receiver_->submit(silence_packet(12, 1, 100), START), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 80ms), 1U);
  ASSERT_EQ(sink_.frames.size(), 2U);
  EXPECT_TRUE(std::ranges::all_of(sink_.frames[0], [](std::int16_t sample) {
    return sample == 0;
  }));
  EXPECT_TRUE(std::ranges::all_of(sink_.frames[1], [](std::int16_t sample) {
    return sample == 0;
  }));
  EXPECT_TRUE(decoder_->calls.empty());
  EXPECT_EQ(receiver_->statistics().silence_frames, 2U);
}

TEST_F(client_microphone_test, FallsBackToPlcAfterDecodeFailure) {
  ASSERT_TRUE(receiver_->reset(13, START));
  decoder_->fail_decode = true;
  ASSERT_EQ(receiver_->submit(opus_packet(13, 1, 100, 55), START), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  ASSERT_EQ(decoder_->calls.size(), 2U);
  EXPECT_FALSE(decoder_->calls[0].conceal);
  EXPECT_TRUE(decoder_->calls[1].conceal);
  ASSERT_EQ(sink_.frames.size(), 1U);
  EXPECT_EQ(sink_.frames.front().front(), -1);
  EXPECT_EQ(receiver_->statistics().decode_errors, 1U);
  EXPECT_EQ(receiver_->statistics().plc_frames, 1U);
}

TEST_F(client_microphone_test, RecordsDecoderAndSinkFailuresWithoutDeliveringFrames) {
  ASSERT_TRUE(receiver_->reset(14, START));
  decoder_->fail_decode = true;
  decoder_->fail_conceal = true;
  ASSERT_EQ(receiver_->submit(opus_packet(14, 1, 100, 55), START), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 0U);
  EXPECT_EQ(receiver_->statistics().decode_errors, 2U);
  EXPECT_TRUE(sink_.frames.empty());

  decoder_->fail_decode = false;
  decoder_->fail_conceal = false;
  sink_.write_result = false;
  ASSERT_EQ(receiver_->submit(opus_packet(14, 2, 1060, 56), START + 61ms), submit_result_e::accepted);
  EXPECT_EQ(receiver_->poll(START + 80ms), 0U);
  EXPECT_EQ(receiver_->statistics().sink_errors, 1U);
}

TEST_F(client_microphone_test, RecordsDirectPlcFailureWithoutWritingPartialFrame) {
  ASSERT_TRUE(receiver_->reset(141, START));
  decoder_->fail_conceal = true;
  ASSERT_EQ(receiver_->submit(opus_packet(141, 1, 100, 1), START), submit_result_e::accepted);
  ASSERT_EQ(receiver_->submit(opus_packet(141, 4, 2980, 4), START + 1ms), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 60ms), 1U);
  EXPECT_EQ(receiver_->poll(START + 80ms), 0U);
  EXPECT_EQ(receiver_->statistics().decode_errors, 1U);
  EXPECT_EQ(sink_.frames.size(), 1U);
}

TEST_F(client_microphone_test, BoundsCatchUpAndFlushesAfterInactivity) {
  ASSERT_TRUE(receiver_->reset(15, START));
  ASSERT_EQ(receiver_->submit(opus_packet(15, 1, 100, 1), START), submit_result_e::accepted);

  EXPECT_EQ(receiver_->poll(START + 300ms), client_microphone::MAX_CATCH_UP_FRAMES);
  EXPECT_EQ(sink_.frames.size(), client_microphone::MAX_CATCH_UP_FRAMES);
  EXPECT_EQ(receiver_->statistics().skipped_playout_frames, 10U);
  EXPECT_EQ(receiver_->poll(START + 300ms), 0U);

  EXPECT_EQ(receiver_->poll(START + client_microphone::INACTIVITY_TIMEOUT), 1U);
  EXPECT_EQ(receiver_->queued_packets(), 0U);
  EXPECT_EQ(receiver_->statistics().inactivity_flushes, 1U);
  EXPECT_TRUE(std::ranges::all_of(sink_.frames.back(), [](std::int16_t sample) {
    return sample == 0;
  }));
  EXPECT_EQ(receiver_->poll(START + client_microphone::INACTIVITY_TIMEOUT + 20ms), 1U);
  EXPECT_EQ(receiver_->statistics().inactivity_flushes, 1U);
  EXPECT_EQ(
    receiver_->submit(opus_packet(15, 16, 14500, 16), START + client_microphone::INACTIVITY_TIMEOUT + 21ms),
    submit_result_e::accepted
  );

  ASSERT_TRUE(receiver_->reset(16, START + client_microphone::INACTIVITY_TIMEOUT + 2ms));
  EXPECT_EQ(
    receiver_->submit(opus_packet(16, 100, 500, 100), START + client_microphone::INACTIVITY_TIMEOUT + 3ms),
    submit_result_e::accepted
  );
}

TEST_F(client_microphone_test, ResetClearsQueuedMediaAndBalancesSinkLifecycle) {
  ASSERT_TRUE(receiver_->reset(21, START));
  ASSERT_EQ(receiver_->submit(opus_packet(21, 1, 100, 1), START), submit_result_e::accepted);
  ASSERT_TRUE(receiver_->reset(22, START + 1ms));

  EXPECT_EQ(receiver_->queued_packets(), 0U);
  EXPECT_EQ(decoder_->reset_calls, 2);
  ASSERT_EQ(sink_.end_generations.size(), 1U);
  EXPECT_EQ(sink_.end_generations[0], 21U);
  ASSERT_EQ(sink_.begin_generations.size(), 2U);
  EXPECT_EQ(sink_.begin_generations[1], 22U);

  receiver_->stop();
  EXPECT_FALSE(receiver_->active());
  ASSERT_EQ(sink_.end_generations.size(), 2U);
  EXPECT_EQ(sink_.end_generations[1], 22U);
  receiver_->stop();
  EXPECT_EQ(sink_.end_generations.size(), 2U);
}

TEST_F(client_microphone_test, FailedDecoderOrSinkStartLeavesReceiverInactive) {
  decoder_->fail_reset = true;
  EXPECT_FALSE(receiver_->reset(30, START));
  EXPECT_FALSE(receiver_->active());
  EXPECT_TRUE(sink_.begin_generations.empty());

  decoder_->fail_reset = false;
  sink_.begin_result = false;
  EXPECT_FALSE(receiver_->reset(31, START));
  EXPECT_FALSE(receiver_->active());
  ASSERT_EQ(sink_.begin_generations.size(), 1U);
  EXPECT_EQ(sink_.begin_generations[0], 31U);
}
