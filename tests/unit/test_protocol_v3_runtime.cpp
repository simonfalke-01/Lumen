/**
 * @file tests/unit/test_protocol_v3_runtime.cpp
 * @brief Filesystem persistence tests for protocol-v3 production authorization state.
 */

#include "src/protocol_common/crypto.h"
#include "src/protocol_v3/runtime.h"

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

    std::span<const std::uint8_t> video_codec_initialization() const noexcept override {
      return codec_initialization_;
    }

    bool reset_input(std::span<const std::uint8_t>) override {
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

    std::expected<bool, std::uint8_t> start(const runtime::ApplicationLaunch &) override {
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
