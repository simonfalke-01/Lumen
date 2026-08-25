/**
 * @file tests/unit/test_protocol_v3_runtime.cpp
 * @brief Filesystem persistence tests for protocol-v3 production authorization state.
 */

#include "src/protocol_common/crypto.h"
#include "src/protocol_common/status.h"
#include "src/protocol_v3/runtime.h"
#include "src/rtsp.h"
#include "src/video.h"

#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <span>
#include <thread>

namespace {
  namespace control = lumen::protocol_v3::control_session;
  namespace media = lumen::protocol_v3::media;
  namespace protocol_crypto = lumen::protocol_common::crypto;
  using ProtocolStatus = lumen::protocol_common::Status;
  namespace quic = lumen::protocol_v3::quic_server;
  namespace runtime = lumen::protocol_v3::runtime;

  struct StopRaceState {
    std::atomic_int stop_calls {};
    std::atomic_int callback_calls {};
    std::atomic_int destructor_calls {};
    std::atomic_bool callback_finished {};
    std::atomic_bool lock_inversion_observed {};
  };

  class StopRaceResources final: public runtime::SessionResources {
  public:
    StopRaceResources(
      std::shared_ptr<StopRaceState> state,
      std::function<void()> terminal_failure
    ):
        state_ {std::move(state)},
        terminal_failure_ {std::move(terminal_failure)} {
    }

    ~StopRaceResources() override {
      ++state_->destructor_calls;
    }

    const media::NegotiatedMediaConfig &effective_media_config() const noexcept override {
      return effective_;
    }

    std::span<const std::uint8_t> video_codec_initialization() const noexcept override {
      return codec_initialization_;
    }

    bool reset_input(std::span<const std::uint8_t>, std::uint32_t) override {
      return true;
    }

    bool apply_text(const control::cbor::Value::Map &) override {
      return true;
    }

    media::ReceiveResult datagram(const quic::DatagramRecord &) override {
      return media::ReceiveResult::accepted;
    }

    bool start_media() override {
      return true;
    }

    void detach_connection() noexcept override {
    }

    bool attach_connection(std::uint64_t) override {
      return true;
    }

    void stop() noexcept override {
      ++state_->stop_calls;
      auto completion = std::make_shared<std::promise<void>>();
      auto completed = completion->get_future();
      std::thread failure {[terminal_failure = terminal_failure_, completion]() noexcept {
        terminal_failure();
        completion->set_value();
      }};
      if (completed.wait_for(std::chrono::seconds {1}) == std::future_status::ready) {
        failure.join();
      } else {
        state_->lock_inversion_observed.store(true);
        failure.detach();
      }
    }

  private:
    std::shared_ptr<StopRaceState> state_;
    std::function<void()> terminal_failure_;
    const std::array<std::uint8_t, 1> codec_initialization_ {0x01};
    media::NegotiatedMediaConfig effective_;
  };

  class StopRaceApplicationBridge final: public runtime::ApplicationBridge {
  public:
    std::expected<runtime::ApplicationSnapshot, std::uint8_t> snapshot() override {
      return std::unexpected(std::uint8_t {8});
    }

    std::expected<runtime::ApplicationAsset, std::uint8_t> asset(
      std::uint64_t,
      const control::Bytes32 &
    ) override {
      return std::unexpected(std::uint8_t {8});
    }

    std::expected<bool, std::uint8_t> start(const runtime::ApplicationLaunch &launch) override {
      last_launch = launch;
      return false;
    }

    bool stop(bool) noexcept override {
      ++stop_calls;
      return false;
    }

    bool running() noexcept override {
      return false;
    }

    std::atomic_int stop_calls {};
    std::optional<runtime::ApplicationLaunch> last_launch;
  };

  class StopRaceResourceFactory final: public runtime::SessionResourceFactory {
  public:
    std::expected<std::unique_ptr<runtime::SessionResources>, std::uint8_t> create(
      const media::NegotiatedMediaConfig &,
      std::uint64_t,
      std::function<void()>
    ) override {
      return std::unexpected(std::uint8_t {8});
    }
  };

  class CapturedSelectionResources final: public runtime::SessionResources {
  public:
    explicit CapturedSelectionResources(media::NegotiatedMediaConfig effective):
        effective_ {std::move(effective)} {
    }

    const media::NegotiatedMediaConfig &effective_media_config() const noexcept override {
      return effective_;
    }

    std::span<const std::uint8_t> video_codec_initialization() const noexcept override {
      return initialization_;
    }
    bool reset_input(std::span<const std::uint8_t>, std::uint32_t) override { return true; }
    bool apply_text(const control::cbor::Value::Map &) override { return true; }
    media::ReceiveResult datagram(const quic::DatagramRecord &) override {
      return media::ReceiveResult::accepted;
    }
    bool start_media() override { return true; }
    void detach_connection() noexcept override {}
    bool attach_connection(std::uint64_t) override { return true; }
    void stop() noexcept override {}

  private:
    media::NegotiatedMediaConfig effective_;
    const std::array<std::uint8_t, 1> initialization_ {0x01};
  };

  class CapturingResourceFactory final: public runtime::SessionResourceFactory {
  public:
    std::expected<std::unique_ptr<runtime::SessionResources>, std::uint8_t> create(
      const media::NegotiatedMediaConfig &config,
      std::uint64_t,
      std::function<void()>
    ) override {
      auto effective = config;
      effective.static_hdr_metadata = resolved_metadata;
      selected = effective;
      return std::make_unique<CapturedSelectionResources>(std::move(effective));
    }

    std::optional<media::NegotiatedMediaConfig> selected;
    std::optional<media::StaticHDRMetadata> resolved_metadata;
  };

  class AcceptingTransport final: public runtime::QuicTransportSink {
  public:
    bool update_policy(std::uint64_t, quic::Profile, std::uint64_t) noexcept override {
      return true;
    }
  };

  const control::cbor::Value *map_field(
    const control::cbor::Value::Map &map,
    const std::uint64_t key
  ) {
    const auto found = std::ranges::find_if(map, [key](const auto &entry) {
      return entry.first == key;
    });
    return found == map.end() ? nullptr : &found->second;
  }

  control::cbor::Value::Map start_fields(
    const std::uint64_t codec_transfer,
    const bool host_audio = false
  ) {
    using control::cbor::Value;
    const auto hdr_transfer = codec_transfer == 16 ? 2U : 3U;
    return {
      {1, Value::Bytes(16, 0x11)},
      {2, 0U},
      {3, 2U},
      {4, 1920U},
      {5, 1080U},
      {6, 60000U},
      {7, 1001U},
      {8, 100000U},
      {9, Value::Array {Value::Map {
            {1, 2U}, {2, 1U}, {3, 10U}, {4, 1U}, {5, 9U},
            {6, codec_transfer}, {7, 9U}, {8, 0U}, {9, 0U}, {10, 1U},
          }}},
      {10, Value::Array {Value::Map {
             {1, 1U}, {2, 48000U}, {3, 2U}, {4, 240U}, {5, 1U},
             {6, 1U}, {7, 1U}, {8, Value::Bytes {0, 1}}, {9, 256000U},
           }}},
      {11, Value {control::cbor::Null {}}},
      {12, static_cast<std::uint64_t>(quic::maximum_semantic_datagram_bytes)},
      {13, Value::Bytes(16, 0x22)},
      {14, Value::Array {Value::Map {
             {1, hdr_transfer}, {2, 9U}, {3, 9U}, {4, 0U}, {5, 10U},
             {6, Value::Map {{1, Value {codec_transfer == 16}}, {2, 10000000U}, {3, 10000U}, {4, 10000U}}},
             {7, Value::Array {}},
           }}},
      {15, Value::Array {Value::Map {{1, 3U}, {2, 2U}, {3, 0U}, {4, 0U}, {5, 0U}}}},
      {16, Value {false}},
      {17, Value::Map {
             {1, 1U}, {2, Value {false}}, {3, Value {false}},
             {4, Value {true}}, {5, Value {true}}, {6, Value {false}},
           }},
      {18, Value {host_audio}},
    };
  }

  std::uint64_t unsigned_value(const control::cbor::Value *value) {
    const auto *integer = value ? std::get_if<std::uint64_t>(&value->storage) : nullptr;
    return integer ? *integer : UINT64_MAX;
  }

  control::cbor::Value::Map stop_fields(
    const control::Identifier &session_id,
    const std::uint8_t intent_byte
  ) {
    return {
      {1, control::cbor::Value::Bytes {session_id.begin(), session_id.end()}},
      {2, 0U},
      {3, 1U},
      {4, control::cbor::Value::Bytes(16, intent_byte)},
    };
  }

  std::uint64_t result_status(const control::ControlResult &result) {
    if (result.response_fields.empty()) {
      return UINT64_MAX;
    }
    const auto *status = std::get_if<std::uint64_t>(&result.response_fields.front().second.storage);
    return status ? *status : UINT64_MAX;
  }

  template<std::size_t Size>
  std::string hex(const std::array<std::uint8_t, Size> &value) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string output(Size * 2, '0');
    for (std::size_t index = 0; index < Size; ++index) {
      output[index * 2] = alphabet[value[index] >> 4U];
      output[index * 2 + 1] = alphabet[value[index] & 0x0fU];
    }
    return output;
  }

  std::uint64_t unix_seconds() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch()
    )
                                        .count());
  }
}  // namespace

TEST(ProtocolV3Runtime, AuthorizationPersistsAtomicallyWithPrivatePermissionsAndExactRetry) {
  control::SecureRandom random;
  std::array<std::uint8_t, 16> suffix {};
  ASSERT_TRUE(random.fill(suffix));
  const auto directory = std::filesystem::temp_directory_path() / ("lumen-v3-runtime-" + hex(suffix));
  const auto state_file = directory / "lumen-state.json";
  ASSERT_TRUE(std::filesystem::create_directory(directory));
  std::filesystem::permissions(
    directory,
    std::filesystem::perms::owner_all,
    std::filesystem::perm_options::replace
  );
  const auto cleanup = std::unique_ptr<void, std::function<void(void *)>> {
    reinterpret_cast<void *>(1),
    [&](void *) {
      std::error_code ignored;
      std::filesystem::remove_all(directory, ignored);
    },
  };

  control::Bytes32 first_seed {};
  control::Identifier client_id {};
  {
    runtime::PersistentAuthorizationStore store {state_file.string(), true};
    ASSERT_TRUE(store.ready());
    const auto seed = store.host_identity_seed(random);
    ASSERT_TRUE(seed.has_value());
    first_seed = *seed;

    runtime::Invitation invitation;
    ASSERT_TRUE(random.fill(invitation.invitation_id));
    ASSERT_TRUE(random.fill(invitation.token));
    ASSERT_TRUE(random.fill(invitation.invitation_sha256));
    invitation.permissions = 0x37;
    invitation.expires_at_unix_seconds = unix_seconds() + 300;
    ASSERT_TRUE(store.add_invitation(invitation));

    control::Bytes32 client_seed {};
    ASSERT_TRUE(random.fill(client_seed));
    const auto public_key = protocol_crypto::ed25519_public_key(client_seed);
    ASSERT_TRUE(public_key.has_value());
    const auto digest = protocol_crypto::sha256(*public_key);
    ASSERT_TRUE(digest.has_value());
    std::copy_n(digest->begin(), client_id.size(), client_id.begin());
    control::PairingClaim claim {
      .invitation_id = invitation.invitation_id,
      .invitation_token = invitation.token,
      .invitation_sha256 = invitation.invitation_sha256,
      .client_id = client_id,
      .client_public_key = *public_key,
      .display_name = "Umbra",
      .requested_permissions = 0x37,
      .approved_permissions = 0x17,
    };
    ASSERT_TRUE(random.fill(claim.pair_attempt_id));
    const auto paired = store.consume_invitation(claim);
    ASSERT_TRUE(paired.has_value());
    EXPECT_EQ(paired->permissions, 0x17U);
    const auto retried = store.consume_invitation(claim);
    ASSERT_TRUE(retried.has_value());
    EXPECT_EQ(retried->generation, paired->generation);

    std::ifstream persisted {state_file, std::ios::binary};
    const std::string serialized {
      std::istreambuf_iterator<char> {persisted},
      std::istreambuf_iterator<char> {}
    };
    EXPECT_EQ(serialized.find(hex(invitation.token)), std::string::npos);
  }

  runtime::PersistentAuthorizationStore reloaded {state_file.string(), true};
  ASSERT_TRUE(reloaded.ready());
  EXPECT_EQ(reloaded.host_identity_seed(random), first_seed);
  ASSERT_TRUE(reloaded.paired_client(client_id).has_value());
  EXPECT_TRUE(reloaded.set_client_permissions(client_id, 0x07));
  EXPECT_EQ(reloaded.paired_client(client_id)->permissions, 0x07U);
  EXPECT_TRUE(reloaded.set_client_enabled(client_id, false));
  EXPECT_FALSE(reloaded.paired_client(client_id).has_value());
  EXPECT_TRUE(reloaded.revoke_client(client_id));
  EXPECT_TRUE(reloaded.clients().empty());
#ifndef _WIN32
  const auto permissions = std::filesystem::status(state_file).permissions();
  EXPECT_EQ(permissions & std::filesystem::perms::group_all, std::filesystem::perms::none);
  EXPECT_EQ(permissions & std::filesystem::perms::others_all, std::filesystem::perms::none);
#endif
}

TEST(ProtocolV3Runtime, AttachIntentCacheReturnsExactCommittedOutcomeBeforeExpiry) {
  control::SecureRandom random;
  control::Identifier intent {};
  ASSERT_TRUE(random.fill(intent));
  runtime::AttachIntentCache cache;
  const auto now = lumen::protocol_v3::quic_server::MonotonicClock::now();
  const std::array<std::uint64_t, 3> media_generations {1, 2, 3};
  control::cbor::Value::Map response {
    {1, 0U},
    {2, control::cbor::Value::Bytes(16, 0x42)},
    {3, 7U},
    {4, 8U},
    {5, control::cbor::Value {true}},
    {6, control::cbor::Value::Map {{1, 1U}, {2, 2U}, {3, 3U}}},
  };
  ASSERT_TRUE(cache.commit(intent, 9, media_generations, response, now));
  const auto exact = cache.lookup(intent, 9, media_generations, now + std::chrono::seconds {1});
  EXPECT_EQ(exact.match, runtime::AttachIntentCache::Match::exact);
  EXPECT_EQ(exact.response_fields, response);
  const auto conflict = cache.lookup(intent, 10, media_generations, now + std::chrono::seconds {1});
  EXPECT_EQ(conflict.match, runtime::AttachIntentCache::Match::conflict);
  const auto expired = cache.lookup(intent, 9, media_generations, now + std::chrono::seconds {61});
  EXPECT_EQ(expired.match, runtime::AttachIntentCache::Match::missing);
}

TEST(ProtocolV3Runtime, BuildsHlgNullAndPqAbi5MasteringIntoStartAndVideoConfig) {
  const auto prior_hevc_mode = video::active_hevc_mode;
  video::active_hevc_mode = 3;
  const auto restore_hevc = std::unique_ptr<void, std::function<void(void *)>> {
    reinterpret_cast<void *>(1),
    [&](void *) {
      video::active_hevc_mode = prior_hevc_mode;
    },
  };
  control::ClientRecord client {
    .client_id = control::Identifier {},
    .permissions = control::start_permission,
    .generation = 1,
  };
  client.client_id.fill(0x31);

  {
    control::SecureRandom random;
    StopRaceApplicationBridge applications;
    CapturingResourceFactory factory;
    AcceptingTransport transport;
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    const auto started = backend.start(
      client,
      start_fields(18),
      1,
      quic::maximum_semantic_datagram_bytes
    );
    ASSERT_TRUE(started.has_value());
    ASSERT_TRUE(applications.last_launch.has_value());
    EXPECT_EQ(applications.last_launch->refresh_numerator, 60'000U);
    EXPECT_EQ(applications.last_launch->refresh_denominator, 1'001U);
    EXPECT_TRUE(applications.last_launch->enable_hdr);
    EXPECT_FALSE(applications.last_launch->host_audio);
    EXPECT_EQ(applications.last_launch->audio.channels, 2U);
    EXPECT_EQ(applications.last_launch->audio.layout, 1U);
    EXPECT_EQ(applications.last_launch->audio.frame_samples, 240U);
    EXPECT_EQ(applications.last_launch->audio.bitrate_bps, 256'000U);
    ASSERT_TRUE(factory.selected);
    EXPECT_EQ(factory.selected->transfer, 3U);
    EXPECT_FALSE(factory.selected->static_hdr_metadata.has_value());
    const auto *response_hdr_value = map_field(started->response_fields, 23);
    const auto *response_hdr = response_hdr_value ?
                                 std::get_if<control::cbor::Value::Map>(&response_hdr_value->storage) :
                                 nullptr;
    ASSERT_NE(response_hdr, nullptr);
    EXPECT_EQ(unsigned_value(map_field(*response_hdr, 1)), 3U);
    ASSERT_NE(map_field(*response_hdr, 6), nullptr);
    EXPECT_TRUE(std::holds_alternative<control::cbor::Null>(map_field(*response_hdr, 6)->storage));
    ASSERT_FALSE(started->host_requests.empty());
    ASSERT_EQ(started->host_requests.front().message_type, 0x0140U);
    const auto *video_hdr_value = map_field(started->host_requests.front().request_fields, 5);
    const auto *video_hdr = video_hdr_value ?
                              std::get_if<control::cbor::Value::Map>(&video_hdr_value->storage) :
                              nullptr;
    ASSERT_NE(video_hdr, nullptr);
    EXPECT_TRUE(std::holds_alternative<control::cbor::Null>(map_field(*video_hdr, 6)->storage));
  }

  const media::StaticHDRMetadata abi5_metadata {
    {35'400, 14'600, 8'500, 39'850, 6'550, 2'300},
    {15'635, 16'450},
    10'000'000,
    50,
    1'000,
    400,
  };
  {
    control::SecureRandom random;
    StopRaceApplicationBridge applications;
    CapturingResourceFactory factory;
    factory.resolved_metadata = abi5_metadata;
    AcceptingTransport transport;
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    auto pq_client = client;
    pq_client.client_id.fill(0x32);
    const auto started = backend.start(
      pq_client,
      start_fields(16),
      2,
      quic::maximum_semantic_datagram_bytes
    );
    ASSERT_TRUE(started.has_value());
    ASSERT_TRUE(factory.selected);
    EXPECT_EQ(factory.selected->transfer, 2U);
    ASSERT_TRUE(factory.selected->static_hdr_metadata.has_value());
    const auto *response_hdr_value = map_field(started->response_fields, 23);
    const auto *response_hdr = response_hdr_value ?
                                 std::get_if<control::cbor::Value::Map>(&response_hdr_value->storage) :
                                 nullptr;
    ASSERT_NE(response_hdr, nullptr);
    EXPECT_EQ(unsigned_value(map_field(*response_hdr, 1)), 2U);
    EXPECT_TRUE(std::holds_alternative<control::cbor::Value::Map>(map_field(*response_hdr, 6)->storage));
    const auto *video_hdr_value = map_field(started->host_requests.front().request_fields, 5);
    ASSERT_NE(video_hdr_value, nullptr);
    EXPECT_EQ(video_hdr_value->storage, response_hdr_value->storage);
  }

  {
    control::SecureRandom random;
    StopRaceApplicationBridge applications;
    CapturingResourceFactory factory;
    AcceptingTransport transport;
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    auto pq_client = client;
    pq_client.client_id.fill(0x33);
    EXPECT_FALSE(backend.start(
      pq_client,
      start_fields(16),
      3,
      quic::maximum_semantic_datagram_bytes
    ).has_value());
  }
}

TEST(ProtocolV3Runtime, LegacyApplicationShapeKeepsExactRefreshHdrAndSelectedSurroundTuple) {
  media::OpusTuple audio {
    .sample_rate = 48'000,
    .frame_samples = 240,
    .channels = 8,
    .layout = 3,
    .streams = 5,
    .coupled_streams = 3,
    .mapping = {0, 1, 2, 3, 4, 5, 6, 7},
    .bitrate_bps = 450'000,
  };
  const runtime::ApplicationLaunch launch {
    .application_id = 7,
    .width = 3456,
    .height = 2160,
    .refresh_numerator = 60'000,
    .refresh_denominator = 1'001,
    .host_audio = true,
    .enable_hdr = true,
    .audio = audio,
    .resume = false,
  };

  const auto shaped = runtime::make_legacy_launch_session(launch);
  ASSERT_TRUE(shaped.has_value());
  EXPECT_EQ((*shaped)->width, 3456);
  EXPECT_EQ((*shaped)->height, 2160);
  EXPECT_EQ((*shaped)->fps, 60);
  EXPECT_EQ((*shaped)->refresh_numerator, 60'000U);
  EXPECT_EQ((*shaped)->refresh_denominator, 1'001U);
  EXPECT_TRUE((*shaped)->host_audio);
  EXPECT_TRUE((*shaped)->enable_hdr);
  EXPECT_TRUE((*shaped)->continuous_audio);
  EXPECT_EQ((*shaped)->surround_info, 0x063f0008);
  EXPECT_EQ((*shaped)->surround_params, "85301234567");
}

TEST(ProtocolV3Runtime, RequiresAndCarriesExplicitHostAudioSelection) {
  const auto prior_hevc_mode = video::active_hevc_mode;
  video::active_hevc_mode = 3;
  const auto restore_hevc = std::unique_ptr<void, std::function<void(void *)>> {
    reinterpret_cast<void *>(1),
    [&](void *) {
      video::active_hevc_mode = prior_hevc_mode;
    },
  };
  control::ClientRecord client {
    .client_id = control::Identifier {},
    .permissions = control::start_permission,
    .generation = 1,
  };

  for (const bool host_audio : {false, true}) {
    client.client_id.fill(host_audio ? 0x52 : 0x51);
    control::SecureRandom random;
    StopRaceApplicationBridge applications;
    CapturingResourceFactory factory;
    AcceptingTransport transport;
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    const auto started = backend.start(
      client,
      start_fields(18, host_audio),
      host_audio ? 52 : 51,
      quic::maximum_semantic_datagram_bytes
    );
    ASSERT_TRUE(started.has_value());
    ASSERT_TRUE(applications.last_launch.has_value());
    EXPECT_EQ(applications.last_launch->host_audio, host_audio);
    ASSERT_TRUE(factory.selected.has_value());
    EXPECT_EQ(factory.selected->host_audio, host_audio);
  }

  const auto expect_malformed = [&](control::cbor::Value::Map fields, const std::uint64_t connection_id) {
    control::SecureRandom random;
    StopRaceApplicationBridge applications;
    CapturingResourceFactory factory;
    AcceptingTransport transport;
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    const auto started = backend.start(
      client,
      fields,
      connection_id,
      quic::maximum_semantic_datagram_bytes
    );
    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::malformed));
    EXPECT_FALSE(applications.last_launch.has_value());
  };

  auto missing = start_fields(18, false);
  std::erase_if(missing, [](const auto &entry) {
    return entry.first == 18;
  });
  expect_malformed(std::move(missing), 53);

  auto malformed = start_fields(18, false);
  const auto host_audio = std::ranges::find_if(malformed, [](const auto &entry) {
    return entry.first == 18;
  });
  ASSERT_NE(host_audio, malformed.end());
  host_audio->second = control::cbor::Value {0U};
  expect_malformed(std::move(malformed), 54);
}

TEST(ProtocolV3Runtime, StopDetachesOwnershipBeforeTerminalCallbackAndRemainsReusable) {
  control::SecureRandom random;
  StopRaceApplicationBridge applications;
  StopRaceResourceFactory factory;
  runtime::QuicTransportSink transport;
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  control::ClientRecord client {
    .client_id = control::Identifier {},
    .permissions = control::stop_permission,
    .generation = 1,
  };
  client.client_id.fill(0x21);
  control::Identifier session_id {};
  session_id.fill(0x31);

  const auto run_stop = [&](const std::uint8_t intent_byte) {
    auto state = std::make_shared<StopRaceState>();
    auto resources = std::make_unique<StopRaceResources>(state, [&, state]() noexcept {
      ++state->callback_calls;
      backend.mark_failed_for_test(session_id);
      state->callback_finished.store(true);
    });
    EXPECT_TRUE(backend.install_session_for_test(client.client_id, session_id, 41, std::move(resources)));

    auto result = backend.control(
      client,
      control::AuthenticatedControl::stop,
      stop_fields(session_id, intent_byte),
      intent_byte,
      41,
      1
    );
    for (unsigned int attempt = 0; attempt < 1'000 && !state->callback_finished.load(); ++attempt) {
      std::this_thread::sleep_for(std::chrono::milliseconds {1});
    }
    EXPECT_TRUE(result.has_value());
    if (!result) {
      return state;
    }
    EXPECT_EQ(result_status(*result), 0U);
    EXPECT_EQ(result->post_response_events.size(), 1U);
    if (!result->post_response_events.empty()) {
      EXPECT_EQ(result->post_response_events.front().message_type, 0x0133U);
    }
    EXPECT_EQ(state->stop_calls.load(), 1);
    EXPECT_EQ(state->callback_calls.load(), 1);
    EXPECT_TRUE(state->callback_finished.load());
    EXPECT_FALSE(state->lock_inversion_observed.load());
    EXPECT_EQ(state->destructor_calls.load(), 1);
    EXPECT_FALSE(backend.owned_session(client).has_value());

    auto repeated = backend.control(
      client,
      control::AuthenticatedControl::stop,
      stop_fields(session_id, static_cast<std::uint8_t>(intent_byte + 1)),
      intent_byte + 2U,
      41,
      1
    );
    EXPECT_TRUE(repeated.has_value());
    if (repeated) {
      EXPECT_NE(result_status(*repeated), 0U);
      EXPECT_TRUE(repeated->post_response_events.empty());
    }
    return state;
  };

  const auto first = run_stop(5);
  const auto second = run_stop(9);
  EXPECT_EQ(first->callback_calls.load(), 1);
  EXPECT_EQ(second->callback_calls.load(), 1);
  EXPECT_EQ(applications.stop_calls.load(), 2);
}
