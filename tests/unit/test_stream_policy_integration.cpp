/**
 * @file tests/unit/test_stream_policy_integration.cpp
 * @brief Integration seams for production stream-policy entry points.
 */

// lib includes
#include <gtest/gtest.h>

// standard includes
#include <array>
#include <memory>
#include <optional>
#include <string_view>

// local includes
#include "src/config.h"
#include "src/rtsp.h"
#include "src/stream.h"

namespace {
  /**
   * @brief Restores global configuration mutated through the real configuration parser.
   */
  class StreamPolicyConfigIntegrationTest: public testing::Test {
  protected:
    void TearDown() override {
      config::stream = original_stream_;
      config::modified_config_settings = original_modified_settings_;
    }

    config::stream_t original_stream_ {config::stream};  ///< Stream configuration restored after the test.
    decltype(config::modified_config_settings) original_modified_settings_ {config::modified_config_settings};  ///< Explicit-setting map restored after the test.
  };
}  // namespace

TEST(StreamPolicyIntegrationTest, SessionAllocationRejectsMissingResolvedPolicy) {
  stream::config_t config {};
  rtsp_stream::launch_session_t launch_session {};

  EXPECT_EQ(stream::session::alloc(config, launch_session), nullptr);
}

TEST(StreamPolicyIntegrationTest, SessionAllocationPreservesExactClientProtocolAndPolicy) {
  constexpr auto protocols = std::to_array({
    stream_policy::ClientProtocol::vanilla,
    stream_policy::ClientProtocol::third_party_extension,
    stream_policy::ClientProtocol::umbra_legacy,
    stream_policy::ClientProtocol::umbra_v2,
  });
  for (const auto protocol : protocols) {
    stream::config_t config {};
    config.optimization_policy = std::make_shared<const stream_policy::EffectiveStreamPolicy>(
      stream_policy::resolve_policy(
        std::nullopt,
        stream_policy::StreamOptimizationMode::legacy,
        config::video.nv,
        config::stream.fec_percentage,
        {},
        std::nullopt
      )
    );
    config.client_protocol = protocol;
    rtsp_stream::launch_session_t launch_session {};
    launch_session.gcm_key.assign(16, 0);
    launch_session.iv.assign(16, 0);

    const auto session = stream::session::alloc(config, launch_session);
    ASSERT_NE(session, nullptr);
    const auto video_config = stream::session::video_config_for_test(session);
    EXPECT_EQ(video_config.optimization_policy, config.optimization_policy);
    EXPECT_EQ(video_config.client_protocol, protocol);
  }
}

TEST(StreamPolicyIntegrationTest, FullAnnouncePayloadClassifiesClientBeforeSessionAllocation) {
  struct Case {
    std::string_view payload;
    stream_policy::ClientProtocol expected;
  };

  constexpr auto cases = std::to_array<Case>({
    {"v=0\r\na=x-nv-video[0].maxFPS:120\r\n", stream_policy::ClientProtocol::vanilla},
    {"v=0\r\na=x-lumen-optimization-mode:quality\r\n", stream_policy::ClientProtocol::third_party_extension},
    {"v=0\r\na=x-lumen-optimization-mode:quality\r\na=x-umbra-client-protocol:legacy-v1\r\n", stream_policy::ClientProtocol::umbra_legacy},
  });

  for (const auto &[payload, expected] : cases) {
    const auto parsed = stream_policy::parse_rtsp_announce_client_protocol(payload);
    ASSERT_NE(parsed.status, stream_policy::ParsedClientProtocol::Status::invalid);

    stream::config_t config {};
    config.optimization_policy = std::make_shared<const stream_policy::EffectiveStreamPolicy>(
      stream_policy::resolve_policy(
        std::nullopt,
        stream_policy::StreamOptimizationMode::legacy,
        config::video.nv,
        config::stream.fec_percentage,
        {},
        std::nullopt
      )
    );
    config.client_protocol = parsed.protocol;
    rtsp_stream::launch_session_t launch_session {};
    launch_session.gcm_key.assign(16, 0);
    launch_session.iv.assign(16, 0);

    const auto session = stream::session::alloc(config, launch_session);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(stream::session::video_config_for_test(session).client_protocol, expected);
  }
}

TEST_F(StreamPolicyConfigIntegrationTest, GlobalConfigurationRejectsZeroFecPercentage) {
  config::stream.fec_percentage = 20;
  config::apply_config_for_test("fec_percentage = 0\n");

  EXPECT_EQ(config::stream.fec_percentage, 20);
}
