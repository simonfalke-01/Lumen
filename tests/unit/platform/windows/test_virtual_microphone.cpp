/**
 * @file tests/unit/platform/windows/test_virtual_microphone.cpp
 * @brief Test the Windows virtual microphone transport with an injectable channel.
 */
#include <gtest/gtest.h>

#ifdef _WIN32
  // local includes
  #include <src/platform/windows/virtual_microphone.h>

  // standard includes
  #include <algorithm>
  #include <cstdint>
  #include <deque>
  #include <memory>
  #include <numeric>
  #include <stdexcept>
  #include <string>
  #include <vector>

namespace {
  using platf::win_audio::virtual_microphone_result_t;

  /** @brief Fake five-operation virtual microphone driver channel. */
  class fake_virtual_microphone_channel_t final: public platf::win_audio::virtual_microphone_channel_t {
  public:
    virtual_microphone_result_t open() override {
      operations.emplace_back("open");
      ++open_calls;
      return open_result;
    }

    virtual_microphone_result_t query_abi(LUMEN_VMIC_QUERY_ABI_RESPONSE &response) override {
      operations.emplace_back("query_abi");
      ++query_abi_calls;
      response = abi;
      return query_abi_result;
    }

    virtual_microphone_result_t open_stream(const LUMEN_VMIC_OPEN_STREAM_REQUEST &request) override {
      operations.emplace_back("open_stream");
      ++open_stream_calls;
      open_requests.push_back(request);
      return open_stream_result;
    }

    virtual_microphone_result_t write_pcm(const LUMEN_VMIC_WRITE_PCM_REQUEST &request) override {
      operations.emplace_back("write_pcm");
      write_requests.push_back(request);
      if (!write_results.empty()) {
        const auto result = write_results.front();
        write_results.pop_front();
        return result;
      }
      return {};
    }

    virtual_microphone_result_t reset(const LUMEN_VMIC_RESET_REQUEST &request) override {
      operations.emplace_back("reset");
      reset_requests.push_back(request);
      return reset_result;
    }

    virtual_microphone_result_t query_stats(LUMEN_VMIC_QUERY_STATS_RESPONSE &response) override {
      operations.emplace_back("query_stats");
      ++query_stats_calls;
      response = stats;
      return query_stats_result;
    }

    void close() noexcept override {
      operations.emplace_back("close");
      ++close_calls;
    }

    LUMEN_VMIC_QUERY_ABI_RESPONSE abi {
      LUMEN_VMIC_ABI_VERSION,
      LUMEN_VMIC_SAMPLE_RATE_HZ,
      LUMEN_VMIC_CHANNEL_COUNT,
      LUMEN_VMIC_BITS_PER_SAMPLE,
      LUMEN_VMIC_MAX_WRITE_FRAMES,
    };  ///< Default compatible ABI.
    LUMEN_VMIC_QUERY_STATS_RESPONSE stats {};  ///< Statistics returned by the fake.
    virtual_microphone_result_t open_result {};  ///< Open result.
    virtual_microphone_result_t query_abi_result {};  ///< ABI query result.
    virtual_microphone_result_t open_stream_result {};  ///< Stream-open result.
    virtual_microphone_result_t reset_result {};  ///< Reset result.
    virtual_microphone_result_t query_stats_result {};  ///< Statistics-query result.
    std::deque<virtual_microphone_result_t> write_results;  ///< Ordered PCM write results.
    std::vector<LUMEN_VMIC_OPEN_STREAM_REQUEST> open_requests;  ///< Captured open requests.
    std::vector<LUMEN_VMIC_WRITE_PCM_REQUEST> write_requests;  ///< Captured PCM requests.
    std::vector<LUMEN_VMIC_RESET_REQUEST> reset_requests;  ///< Captured reset requests.
    std::vector<std::string> operations;  ///< Complete channel operation order.
    int open_calls {};  ///< Open call count.
    int query_abi_calls {};  ///< ABI query call count.
    int open_stream_calls {};  ///< Stream-open call count.
    int query_stats_calls {};  ///< Statistics-query call count.
    int close_calls {};  ///< Close call count.
  };

  /** @brief Fixture providing a fresh fake channel and transport. */
  class virtual_microphone_test: public testing::Test {
  protected:
    void SetUp() override {
      channel = std::make_shared<fake_virtual_microphone_channel_t>();
      microphone = std::make_unique<platf::win_audio::virtual_microphone_t>(channel);
    }

    /**
     * @brief Open the default exact-format generation.
     * @param generation Generation to claim.
     */
    void begin(std::uint64_t generation = 42) {
      ASSERT_TRUE(microphone->begin(generation, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));
      ASSERT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::active);
    }

    std::shared_ptr<fake_virtual_microphone_channel_t> channel;  ///< Injectable fake channel.
    std::unique_ptr<platf::win_audio::virtual_microphone_t> microphone;  ///< Subject.
  };
}  // namespace

TEST_F(virtual_microphone_test, ProbesExactAbiWithoutClaimingStream) {
  EXPECT_TRUE(microphone->probe());
  EXPECT_EQ(channel->operations, std::vector<std::string>({"open", "query_abi", "close"}));
  EXPECT_EQ(channel->open_stream_calls, 0);
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::idle);
}

TEST_F(virtual_microphone_test, ProbeRejectsEveryAbiMismatchAndCloses) {
  const std::vector<LUMEN_VMIC_QUERY_ABI_RESPONSE> incompatible {
    {LUMEN_VMIC_ABI_VERSION + 1U, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT, LUMEN_VMIC_BITS_PER_SAMPLE, LUMEN_VMIC_MAX_WRITE_FRAMES},
    {LUMEN_VMIC_ABI_VERSION, 44100, LUMEN_VMIC_CHANNEL_COUNT, LUMEN_VMIC_BITS_PER_SAMPLE, LUMEN_VMIC_MAX_WRITE_FRAMES},
    {LUMEN_VMIC_ABI_VERSION, LUMEN_VMIC_SAMPLE_RATE_HZ, 2, LUMEN_VMIC_BITS_PER_SAMPLE, LUMEN_VMIC_MAX_WRITE_FRAMES},
    {LUMEN_VMIC_ABI_VERSION, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT, 24, LUMEN_VMIC_MAX_WRITE_FRAMES},
    {LUMEN_VMIC_ABI_VERSION, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT, LUMEN_VMIC_BITS_PER_SAMPLE, LUMEN_VMIC_MAX_WRITE_FRAMES - 1U},
  };

  for (const auto &abi : incompatible) {
    channel = std::make_shared<fake_virtual_microphone_channel_t>();
    channel->abi = abi;
    microphone = std::make_unique<platf::win_audio::virtual_microphone_t>(channel);

    EXPECT_FALSE(microphone->probe());
    EXPECT_EQ(microphone->failure_stage(), "driver ABI");
    EXPECT_EQ(microphone->failure_status(), static_cast<DWORD>(ERROR_REVISION_MISMATCH));
    EXPECT_EQ(channel->close_calls, 1);
    EXPECT_EQ(channel->open_stream_calls, 0);
  }
}

TEST_F(virtual_microphone_test, ProbeReportsOpenAndQueryFailures) {
  channel->open_result = {false, ERROR_FILE_NOT_FOUND};
  EXPECT_FALSE(microphone->probe());
  EXPECT_EQ(microphone->failure_stage(), "interface discovery/open");
  EXPECT_EQ(channel->query_abi_calls, 0);
  EXPECT_EQ(channel->close_calls, 0);

  channel = std::make_shared<fake_virtual_microphone_channel_t>();
  channel->query_abi_result = {false, ERROR_INVALID_DATA};
  microphone = std::make_unique<platf::win_audio::virtual_microphone_t>(channel);
  EXPECT_FALSE(microphone->probe());
  EXPECT_EQ(microphone->failure_stage(), "driver ABI");
  EXPECT_EQ(microphone->failure_status(), static_cast<DWORD>(ERROR_INVALID_DATA));
  EXPECT_EQ(channel->close_calls, 1);
}

TEST_F(virtual_microphone_test, BeginsWithExactGenerationAndFormat) {
  begin(0x1020304050607080ULL);

  ASSERT_EQ(channel->open_requests.size(), 1U);
  const auto &request = channel->open_requests.front();
  EXPECT_EQ(request.requested_generation, 0x1020304050607080ULL);
  EXPECT_EQ(request.sample_rate_hz, LUMEN_VMIC_SAMPLE_RATE_HZ);
  EXPECT_EQ(request.channel_count, LUMEN_VMIC_CHANNEL_COUNT);
  EXPECT_EQ(request.bits_per_sample, LUMEN_VMIC_BITS_PER_SAMPLE);
  EXPECT_EQ(microphone->generation(), 0x1020304050607080ULL);
  EXPECT_EQ(channel->operations, std::vector<std::string>({"open", "query_abi", "open_stream"}));
}

TEST_F(virtual_microphone_test, RejectsInvalidFormatAndZeroGenerationBeforeOpening) {
  EXPECT_FALSE(microphone->begin(1, 44100, LUMEN_VMIC_CHANNEL_COUNT));
  EXPECT_EQ(microphone->failure_stage(), "PCM format");
  EXPECT_FALSE(microphone->begin(1, LUMEN_VMIC_SAMPLE_RATE_HZ, 2));
  EXPECT_EQ(microphone->failure_stage(), "PCM format");
  EXPECT_FALSE(microphone->begin(0, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));
  EXPECT_EQ(microphone->failure_stage(), "stream generation");
  EXPECT_EQ(channel->open_calls, 0);
}

TEST_F(virtual_microphone_test, ClosesWithoutResetWhenStreamOpenFails) {
  channel->open_stream_result = {false, ERROR_SHARING_VIOLATION};

  EXPECT_FALSE(microphone->begin(1, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::idle);
  EXPECT_EQ(microphone->failure_stage(), "open stream");
  EXPECT_TRUE(channel->reset_requests.empty());
  EXPECT_EQ(channel->close_calls, 1);
}

TEST_F(virtual_microphone_test, BeginReportsOpenAndAbiQueryFailures) {
  channel->open_result = {false, ERROR_FILE_NOT_FOUND};
  EXPECT_FALSE(microphone->begin(1, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));
  EXPECT_EQ(microphone->failure_stage(), "interface discovery/open");
  EXPECT_EQ(channel->query_abi_calls, 0);

  channel = std::make_shared<fake_virtual_microphone_channel_t>();
  channel->query_abi_result = {false, ERROR_INVALID_DATA};
  microphone = std::make_unique<platf::win_audio::virtual_microphone_t>(channel);
  EXPECT_FALSE(microphone->begin(1, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));
  EXPECT_EQ(microphone->failure_stage(), "driver ABI");
  EXPECT_EQ(channel->open_stream_calls, 0);
  EXPECT_EQ(channel->close_calls, 1);
}

TEST_F(virtual_microphone_test, BeginResetsPreviousGenerationBeforeReopening) {
  begin(1);

  ASSERT_TRUE(microphone->begin(2, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));

  ASSERT_EQ(channel->reset_requests.size(), 1U);
  EXPECT_EQ(channel->reset_requests.front().generation, 1U);
  EXPECT_EQ(channel->close_calls, 1);
  EXPECT_EQ(channel->open_calls, 2);
  ASSERT_EQ(channel->open_requests.size(), 2U);
  EXPECT_EQ(channel->open_requests.back().requested_generation, 2U);
  EXPECT_EQ(microphone->generation(), 2U);
}

TEST_F(virtual_microphone_test, BeginStopsWhenPreviousGenerationCannotReset) {
  begin(1);
  channel->reset_result = {false, ERROR_TIMEOUT};

  EXPECT_FALSE(microphone->begin(2, LUMEN_VMIC_SAMPLE_RATE_HZ, LUMEN_VMIC_CHANNEL_COUNT));
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::fail_closed);
  EXPECT_EQ(microphone->failure_stage(), "reset stream");
  EXPECT_EQ(channel->open_calls, 1);
  EXPECT_EQ(channel->close_calls, 1);
}

TEST_F(virtual_microphone_test, WritesOneCompleteTwentyMillisecondFrame) {
  begin();
  std::vector<std::int16_t> samples(LUMEN_VMIC_MAX_WRITE_FRAMES);
  std::iota(samples.begin(), samples.end(), std::int16_t {-480});

  ASSERT_TRUE(microphone->write(42, samples));
  ASSERT_EQ(channel->write_requests.size(), 1U);
  const auto &request = channel->write_requests.front();
  EXPECT_EQ(request.generation, 42U);
  EXPECT_EQ(request.frame_count, LUMEN_VMIC_MAX_WRITE_FRAMES);
  EXPECT_TRUE(std::equal(samples.begin(), samples.end(), request.samples));
}

TEST_F(virtual_microphone_test, SplitsOversizedPcmIntoBoundedFixedRequests) {
  begin(7);
  std::vector<std::int16_t> samples(LUMEN_VMIC_MAX_WRITE_FRAMES * 2U + 17U);
  std::iota(samples.begin(), samples.end(), std::int16_t {-1000});

  ASSERT_TRUE(microphone->write(7, samples));
  ASSERT_EQ(channel->write_requests.size(), 3U);
  EXPECT_EQ(channel->write_requests[0].frame_count, LUMEN_VMIC_MAX_WRITE_FRAMES);
  EXPECT_EQ(channel->write_requests[1].frame_count, LUMEN_VMIC_MAX_WRITE_FRAMES);
  EXPECT_EQ(channel->write_requests[2].frame_count, 17U);
  EXPECT_TRUE(std::equal(samples.begin(), samples.begin() + 960, channel->write_requests[0].samples));
  EXPECT_TRUE(std::equal(samples.begin() + 960, samples.begin() + 1920, channel->write_requests[1].samples));
  EXPECT_TRUE(std::equal(samples.begin() + 1920, samples.end(), channel->write_requests[2].samples));
}

TEST_F(virtual_microphone_test, AcceptsEmptyPcmWithoutIssuingAnIoctl) {
  begin();

  EXPECT_TRUE(microphone->write(42, {}));
  EXPECT_TRUE(channel->write_requests.empty());
}

TEST_F(virtual_microphone_test, RejectsWrongGenerationWithoutIssuingAnIoctl) {
  begin(10);

  const std::int16_t sample = 123;
  EXPECT_FALSE(microphone->write(11, std::span {&sample, 1U}));
  EXPECT_EQ(microphone->failure_stage(), "PCM generation");
  EXPECT_TRUE(channel->write_requests.empty());
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::active);
}

TEST_F(virtual_microphone_test, FailsClosedAfterAnyPcmWriteFailure) {
  begin();
  channel->write_results.push_back({false, ERROR_WRITE_FAULT});
  const std::int16_t sample = 123;

  EXPECT_FALSE(microphone->write(42, std::span {&sample, 1U}));
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::fail_closed);
  EXPECT_EQ(microphone->failure_stage(), "write PCM");
  EXPECT_FALSE(microphone->write(42, std::span {&sample, 1U}));
  EXPECT_EQ(channel->write_requests.size(), 1U);
  EXPECT_FALSE(microphone->probe());
}

TEST_F(virtual_microphone_test, EndsMatchingGenerationWithResetBeforeClose) {
  begin(55);
  microphone->end(54);
  EXPECT_TRUE(channel->reset_requests.empty());

  microphone->end(55);

  ASSERT_EQ(channel->reset_requests.size(), 1U);
  EXPECT_EQ(channel->reset_requests.front().generation, 55U);
  ASSERT_GE(channel->operations.size(), 2U);
  EXPECT_EQ(channel->operations[channel->operations.size() - 2U], "reset");
  EXPECT_EQ(channel->operations.back(), "close");
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::idle);
  EXPECT_EQ(microphone->generation(), 0U);
}

TEST_F(virtual_microphone_test, DestructorResetsBeforeClosingActiveStream) {
  begin(88);

  microphone.reset();

  ASSERT_EQ(channel->reset_requests.size(), 1U);
  EXPECT_EQ(channel->reset_requests.front().generation, 88U);
  ASSERT_GE(channel->operations.size(), 2U);
  EXPECT_EQ(channel->operations[channel->operations.size() - 2U], "reset");
  EXPECT_EQ(channel->operations.back(), "close");
}

TEST_F(virtual_microphone_test, ResetFailureLeavesTransportFailClosed) {
  begin(99);
  channel->reset_result = {false, ERROR_TIMEOUT};

  microphone->end(99);

  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::fail_closed);
  EXPECT_EQ(microphone->generation(), 0U);
  EXPECT_EQ(microphone->failure_stage(), "reset stream");
  EXPECT_EQ(microphone->failure_status(), static_cast<DWORD>(ERROR_TIMEOUT));
  EXPECT_EQ(channel->close_calls, 1);
}

TEST_F(virtual_microphone_test, QueriesCompleteDriverStatistics) {
  begin(100);
  channel->stats = {100, 960, 1, 2, 3, 4, 480, 9600};
  LUMEN_VMIC_QUERY_STATS_RESPONSE response {};

  ASSERT_TRUE(microphone->query_stats(response));
  EXPECT_EQ(response.generation, 100U);
  EXPECT_EQ(response.accepted_frames, 960U);
  EXPECT_EQ(response.stale_writes, 1U);
  EXPECT_EQ(response.overflow_drops, 2U);
  EXPECT_EQ(response.underflow_samples, 3U);
  EXPECT_EQ(response.resets, 4U);
  EXPECT_EQ(response.current_fill_frames, 480U);
  EXPECT_EQ(response.capacity_frames, 9600U);
}

TEST_F(virtual_microphone_test, StatisticsRequireAnOwnedStreamAndReportDriverFailure) {
  LUMEN_VMIC_QUERY_STATS_RESPONSE response {};
  EXPECT_FALSE(microphone->query_stats(response));
  EXPECT_EQ(microphone->failure_stage(), "query statistics");
  EXPECT_EQ(channel->query_stats_calls, 0);

  begin(1);
  channel->query_stats_result = {false, ERROR_READ_FAULT};
  EXPECT_FALSE(microphone->query_stats(response));
  EXPECT_EQ(microphone->failure_stage(), "query statistics");
  EXPECT_EQ(microphone->failure_status(), static_cast<DWORD>(ERROR_READ_FAULT));
  EXPECT_EQ(channel->query_stats_calls, 1);
  EXPECT_EQ(microphone->state(), platf::win_audio::virtual_microphone_state_e::active);
}

TEST_F(virtual_microphone_test, ActiveProbeDoesNotDisturbClaimedStream) {
  begin(5);
  const auto operations = channel->operations;

  EXPECT_TRUE(microphone->probe());
  EXPECT_EQ(channel->operations, operations);
  EXPECT_EQ(microphone->generation(), 5U);
}

TEST(VirtualMicrophoneConstructionTest, RejectsNullChannel) {
  EXPECT_THROW(
    platf::win_audio::virtual_microphone_t(std::shared_ptr<platf::win_audio::virtual_microphone_channel_t> {}),
    std::invalid_argument
  );
}

#else
TEST(VirtualMicrophoneTest, IsWindowsOnly) {
  GTEST_SKIP() << "Windows virtual microphone transport is not available on this platform";
}
#endif
