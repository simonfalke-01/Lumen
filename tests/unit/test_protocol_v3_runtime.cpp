/**
 * @file tests/unit/test_protocol_v3_runtime.cpp
 * @brief Filesystem persistence tests for protocol-v3 production authorization state.
 */

#include "src/protocol_common/crypto.h"
#include "src/protocol_common/status.h"
#include "src/protocol_v3/host_identity_store.h"
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
#include <map>
#include <mutex>
#include <new>
#include <numeric>
#include <span>
#include <set>
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
      ++state_->callback_calls;
      terminal_failure_();
      state_->callback_finished.store(true);
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
      ++start_calls;
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

    std::atomic_int start_calls {};
    std::atomic_int stop_calls {};
    std::optional<runtime::ApplicationLaunch> last_launch;
  };

  class StopRaceResourceFactory final: public runtime::SessionResourceFactory {
  public:
    std::expected<std::unique_ptr<runtime::SessionResources>, std::uint8_t> create(
      const media::NegotiatedMediaConfig &,
      std::uint64_t,
      std::weak_ptr<runtime::TerminalFailureDispatcher>
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
      std::weak_ptr<runtime::TerminalFailureDispatcher>
    ) override {
      ++create_calls;
      auto effective = config;
      effective.static_hdr_metadata = resolved_metadata;
      selected = effective;
      return std::make_unique<CapturedSelectionResources>(std::move(effective));
    }

    int create_calls {};
    std::optional<media::NegotiatedMediaConfig> selected;
    std::optional<media::StaticHDRMetadata> resolved_metadata;
  };

  class OrderingResources final: public runtime::SessionResources {
  public:
    OrderingResources(media::NegotiatedMediaConfig effective, std::vector<std::string> &events):
        effective_ {std::move(effective)},
        events_ {events} {
    }

    const media::NegotiatedMediaConfig &effective_media_config() const noexcept override { return effective_; }
    std::span<const std::uint8_t> video_codec_initialization() const noexcept override { return initialization_; }
    bool reset_input(std::span<const std::uint8_t>, std::uint32_t) override { return true; }
    bool apply_text(const control::cbor::Value::Map &) override { return true; }
    media::ReceiveResult datagram(const quic::DatagramRecord &) override { return media::ReceiveResult::accepted; }
    bool start_media() override { return true; }
    void detach_connection() noexcept override {}
    bool attach_connection(std::uint64_t) override { return true; }
    void stop() noexcept override {
      if (!stopped_) {
        events_.emplace_back("resource.stop");
        stopped_ = true;
      }
    }

  private:
    media::NegotiatedMediaConfig effective_;
    std::vector<std::string> &events_;
    const std::array<std::uint8_t, 1> initialization_ {0x01};
    bool stopped_ {};
  };

  class OrderingResourceFactory final: public runtime::SessionResourceFactory {
  public:
    explicit OrderingResourceFactory(std::vector<std::string> &events):
        events_ {events} {
    }

    std::expected<std::unique_ptr<runtime::SessionResources>, std::uint8_t> create(
      const media::NegotiatedMediaConfig &config,
      std::uint64_t,
      std::weak_ptr<runtime::TerminalFailureDispatcher>
    ) override {
      ++create_calls;
      events_.emplace_back("resource.create");
      return std::make_unique<OrderingResources>(config, events_);
    }

    int create_calls {};

  private:
    std::vector<std::string> &events_;
  };

  class OrderingApplicationBridge final: public runtime::ApplicationBridge {
  public:
    OrderingApplicationBridge(std::vector<std::string> &events, const bool fail_start):
        events_ {events},
        fail_start_ {fail_start} {
    }

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
      ++start_calls;
      last_launch = launch;
      events_.emplace_back("application.start");
      if (fail_start_) {
        return std::unexpected(static_cast<std::uint8_t>(ProtocolStatus::application_not_found));
      }
      return true;
    }
    bool stop(bool) noexcept override {
      events_.emplace_back("application.stop");
      return true;
    }
    bool running() noexcept override { return false; }

    int start_calls {};
    std::optional<runtime::ApplicationLaunch> last_launch;

  private:
    std::vector<std::string> &events_;
    bool fail_start_ {};
  };

  class AcceptingTransport final: public runtime::QuicTransportSink {
  public:
    bool update_policy(std::uint64_t, quic::Profile, std::uint64_t) noexcept override {
      return true;
    }
  };

  struct LifetimeFailureState {
    void record(std::string value) {
      std::scoped_lock lock {events_mutex};
      events.push_back(std::move(value));
    }

    std::vector<std::string> snapshot() const {
      std::scoped_lock lock {events_mutex};
      return events;
    }

    std::atomic_int resource_stops {};
    std::atomic_int resource_destructions {};
    std::atomic_int failure_attempts {};
    mutable std::mutex events_mutex;
    std::vector<std::string> events;
  };

  class LifetimeFailureResources final: public runtime::SessionResources {
  public:
    LifetimeFailureResources(
      media::NegotiatedMediaConfig effective,
      std::shared_ptr<LifetimeFailureState> state,
      std::weak_ptr<runtime::TerminalFailureDispatcher> terminal_failure,
      const bool report_while_stopping
    ):
        effective_ {std::move(effective)},
        state_ {std::move(state)},
        terminal_failure_ {std::move(terminal_failure)},
        report_while_stopping_ {report_while_stopping} {
    }

    ~LifetimeFailureResources() override {
      ++state_->resource_destructions;
      state_->record("resource.destroy");
    }

    const media::NegotiatedMediaConfig &effective_media_config() const noexcept override {
      return effective_;
    }

    std::span<const std::uint8_t> video_codec_initialization() const noexcept override {
      return initialization_;
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

    void detach_connection() noexcept override {}

    bool attach_connection(std::uint64_t) override {
      return true;
    }

    void stop() noexcept override {
      bool expected = false;
      if (!stopped_.compare_exchange_strong(expected, true)) {
        return;
      }
      ++state_->resource_stops;
      state_->record("resource.stop");
      if (report_while_stopping_) {
        ++state_->failure_attempts;
        if (const auto terminal_failure = terminal_failure_.lock()) {
          terminal_failure->report();
        }
      }
    }

  private:
    media::NegotiatedMediaConfig effective_;
    std::shared_ptr<LifetimeFailureState> state_;
    std::weak_ptr<runtime::TerminalFailureDispatcher> terminal_failure_;
    const std::array<std::uint8_t, 1> initialization_ {0x01};
    bool report_while_stopping_ {};
    std::atomic_bool stopped_ {};
  };

  enum class LifetimeFactoryMode {
    success,
    report_and_succeed,
    report_and_error,
    null_resource,
    throw_allocation,
  };

  class LifetimeFailureFactory final: public runtime::SessionResourceFactory {
  public:
    LifetimeFailureFactory(
      std::shared_ptr<LifetimeFailureState> state,
      const LifetimeFactoryMode mode = LifetimeFactoryMode::success,
      const bool report_while_stopping = false
    ):
        state_ {std::move(state)},
        mode_ {mode},
        report_while_stopping_ {report_while_stopping} {
    }

    std::expected<std::unique_ptr<runtime::SessionResources>, std::uint8_t> create(
      const media::NegotiatedMediaConfig &config,
      std::uint64_t,
      std::weak_ptr<runtime::TerminalFailureDispatcher> terminal_failure
    ) override {
      terminal_failure_ = terminal_failure;
      state_->record("resource.create");
      if (mode_ == LifetimeFactoryMode::throw_allocation) {
        throw std::bad_alloc {};
      }
      if (mode_ == LifetimeFactoryMode::report_and_succeed ||
          mode_ == LifetimeFactoryMode::report_and_error) {
        trigger_failure();
      }
      if (mode_ == LifetimeFactoryMode::report_and_error) {
        return std::unexpected(static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
      }
      if (mode_ == LifetimeFactoryMode::null_resource) {
        return std::unique_ptr<runtime::SessionResources> {};
      }
      return std::make_unique<LifetimeFailureResources>(
        config,
        state_,
        terminal_failure,
        report_while_stopping_
      );
    }

    bool trigger_failure() noexcept {
      ++state_->failure_attempts;
      if (const auto terminal_failure = terminal_failure_.lock()) {
        terminal_failure->report();
        return true;
      }
      return false;
    }

  private:
    std::shared_ptr<LifetimeFailureState> state_;
    LifetimeFactoryMode mode_;
    bool report_while_stopping_ {};
    std::weak_ptr<runtime::TerminalFailureDispatcher> terminal_failure_;
  };

  class LifetimeApplicationBridge final: public runtime::ApplicationBridge {
  public:
    explicit LifetimeApplicationBridge(std::shared_ptr<LifetimeFailureState> state):
        state_ {std::move(state)} {
    }

    std::expected<runtime::ApplicationSnapshot, std::uint8_t> snapshot() override {
      return std::unexpected(static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
    }

    std::expected<runtime::ApplicationAsset, std::uint8_t> asset(
      std::uint64_t,
      const control::Bytes32 &
    ) override {
      return std::unexpected(static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
    }

    std::expected<bool, std::uint8_t> start(const runtime::ApplicationLaunch &) override {
      ++start_calls;
      state_->record("application.start");
      return true;
    }

    bool stop(bool) noexcept override {
      ++stop_calls;
      state_->record("application.stop");
      return true;
    }

    bool running() noexcept override {
      return false;
    }

    std::atomic_int start_calls {};
    std::atomic_int stop_calls {};

  private:
    std::shared_ptr<LifetimeFailureState> state_;
  };

  class LifetimeTransport final: public runtime::QuicTransportSink {
  public:
    explicit LifetimeTransport(std::shared_ptr<LifetimeFailureState> state):
        state_ {std::move(state)} {
    }

    bool update_policy(std::uint64_t, quic::Profile, std::uint64_t) noexcept override {
      ++update_calls;
      state_->record("transport.update");
      return true;
    }

    bool reset_policy(std::uint64_t) noexcept override {
      ++reset_calls;
      state_->record("transport.reset");
      return true;
    }

    bool revoke(std::uint64_t) noexcept override {
      ++revoke_calls;
      state_->record("transport.revoke");
      return true;
    }

    quic::EnqueueResult enqueue(std::uint64_t, quic::Packet) override {
      ++enqueue_calls;
      return quic::EnqueueResult::queued;
    }

    std::atomic_int update_calls {};
    std::atomic_int reset_calls {};
    std::atomic_int revoke_calls {};
    std::atomic_int enqueue_calls {};

  private:
    std::shared_ptr<LifetimeFailureState> state_;
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

  control::cbor::Value *mutable_map_field(control::cbor::Value::Map &map, const std::uint64_t key) {
    const auto found = std::ranges::find_if(map, [key](const auto &entry) {
      return entry.first == key;
    });
    return found == map.end() ? nullptr : &found->second;
  }

  control::cbor::Value::Map sdr_h264_start_fields(const std::uint64_t width, const std::uint64_t height) {
    auto fields = start_fields(18);
    *mutable_map_field(fields, 4) = width;
    *mutable_map_field(fields, 5) = height;
    auto *codec_array = std::get_if<control::cbor::Value::Array>(&mutable_map_field(fields, 9)->storage);
    auto *codec = std::get_if<control::cbor::Value::Map>(&codec_array->front().storage);
    *mutable_map_field(*codec, 1) = 1U;
    *mutable_map_field(*codec, 3) = 8U;
    *mutable_map_field(*codec, 4) = 1U;
    *mutable_map_field(*codec, 5) = 1U;
    *mutable_map_field(*codec, 6) = 1U;
    *mutable_map_field(*codec, 7) = 1U;
    *mutable_map_field(*codec, 8) = 0U;
    *mutable_map_field(*codec, 9) = 0U;
    *mutable_map_field(*codec, 10) = 1U;
    auto *quality = std::get_if<control::cbor::Value::Map>(&mutable_map_field(fields, 17)->storage);
    *mutable_map_field(*quality, 1) = 1U;
    for (std::uint64_t key = 2; key <= 5; ++key) {
      *mutable_map_field(*quality, key) = control::cbor::Value {false};
    }
    return fields;
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

  control::ClientRecord start_client(const std::uint8_t identity_byte = 0x81) {
    control::ClientRecord client {
      .client_id = control::Identifier {},
      .permissions = control::start_permission | control::stop_permission,
      .generation = 1,
    };
    client.client_id.fill(identity_byte);
    return client;
  }

  template<typename Predicate>
  bool wait_for(const std::chrono::milliseconds timeout, Predicate &&predicate) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!predicate()) {
      if (std::chrono::steady_clock::now() >= deadline) {
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds {1});
    }
    return true;
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

  struct FakeIdentityFiles {
    runtime::HostPrincipal principal {runtime::HostPrincipal::elevated_administrator};
    std::map<std::string, std::vector<std::uint8_t>> files;
    std::set<std::string> secure;
    bool reject_writes {};
  };

  class FakeIdentityPlatform final: public runtime::HostIdentityPlatform {
  public:
    explicit FakeIdentityPlatform(std::shared_ptr<FakeIdentityFiles> files):
        files_ {std::move(files)} {
    }

    runtime::HostPrincipal principal() const noexcept override {
      return files_->principal;
    }

    std::expected<std::vector<std::uint8_t>, runtime::HostIdentityError> protect(
      const std::span<const std::uint8_t> plaintext
    ) override {
      std::vector<std::uint8_t> output(plaintext.begin(), plaintext.end());
      for (auto &byte : output) {
        byte ^= 0xa5U;
      }
      return output;
    }

    std::expected<std::vector<std::uint8_t>, runtime::HostIdentityError> unprotect(
      const std::span<const std::uint8_t> protected_bytes
    ) override {
      std::vector<std::uint8_t> output(protected_bytes.begin(), protected_bytes.end());
      for (auto &byte : output) {
        byte ^= 0xa5U;
      }
      return output;
    }

    bool write_private(
      const std::filesystem::path &path,
      const std::span<const std::uint8_t> bytes
    ) override {
      if (files_->reject_writes) {
        return false;
      }
      files_->files[path.string()] = {bytes.begin(), bytes.end()};
      files_->secure.insert(path.string());
      return true;
    }

    bool read_private(
      const std::filesystem::path &path,
      std::vector<std::uint8_t> &bytes
    ) const override {
      const auto found = files_->files.find(path.string());
      if (found == files_->files.end() || !verify_private(path)) {
        return false;
      }
      bytes = found->second;
      return true;
    }

    bool exists(const std::filesystem::path &path) const override {
      return files_->files.contains(path.string());
    }

    bool verify_private(const std::filesystem::path &path) const override {
      return files_->secure.contains(path.string());
    }

    bool replace_private(
      const std::filesystem::path &source,
      const std::filesystem::path &destination
    ) override {
      const auto found = files_->files.find(source.string());
      if (found == files_->files.end() || !verify_private(source)) {
        return false;
      }
      files_->files[destination.string()] = found->second;
      files_->files.erase(found);
      files_->secure.erase(source.string());
      files_->secure.insert(destination.string());
      return true;
    }

    bool remove_private(const std::filesystem::path &path) override {
      files_->files.erase(path.string());
      files_->secure.erase(path.string());
      return true;
    }

  private:
    std::shared_ptr<FakeIdentityFiles> files_;
  };

  runtime::HostIdentityPaths fake_identity_paths() {
    return {
      .identity = "/identity/credentials/protocol_v3_identity.bin",
      .temporary = "/identity/credentials/protocol_v3_identity.bin.pending",
      .journal = "/identity/credentials/protocol_v3_identity.journal",
    };
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
    EXPECT_EQ(serialized.find(hex(first_seed)), std::string::npos);
    const auto identity_paths = runtime::host_identity_paths_for_state_file(state_file);
    EXPECT_TRUE(std::filesystem::is_regular_file(identity_paths.identity));
    EXPECT_TRUE(std::filesystem::is_regular_file(identity_paths.journal));
    EXPECT_FALSE(std::filesystem::exists(identity_paths.temporary));
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

TEST(ProtocolV3Identity, MigratesLegacySeedToVersionedProtectedBlobAndRetiresPlaintext) {
  auto files = std::make_shared<FakeIdentityFiles>();
  const auto paths = fake_identity_paths();
  runtime::HostIdentityStore store {
    paths,
    std::make_unique<FakeIdentityPlatform>(files),
    true,
  };
  control::SecureRandom random;
  control::Bytes32 legacy {};
  std::iota(legacy.begin(), legacy.end(), 1U);

  const auto loaded = store.load_or_create(legacy, random);
  ASSERT_TRUE(loaded.has_value());
  EXPECT_EQ(loaded->seed, legacy);
  EXPECT_TRUE(loaded->retire_legacy_seed);
  EXPECT_TRUE(files->files.contains(paths.identity.string()));
  EXPECT_TRUE(files->files.contains(paths.journal.string()));
  EXPECT_FALSE(files->files.contains(paths.temporary.string()));
  const auto &blob = files->files.at(paths.identity.string());
  EXPECT_EQ(std::search(blob.begin(), blob.end(), legacy.begin(), legacy.end()), blob.end());
}

TEST(ProtocolV3Identity, RecoversEveryInterruptedMigrationStageWithoutRotatingIdentity) {
  const std::array stages {
    runtime::HostIdentityStage::journal_started,
    runtime::HostIdentityStage::temporary_written,
    runtime::HostIdentityStage::temporary_verified,
    runtime::HostIdentityStage::identity_replaced,
    runtime::HostIdentityStage::journal_committed,
  };
  control::Bytes32 legacy {};
  std::iota(legacy.begin(), legacy.end(), 7U);
  control::SecureRandom random;

  for (const auto stage : stages) {
    auto files = std::make_shared<FakeIdentityFiles>();
    const auto paths = fake_identity_paths();
    runtime::HostIdentityStore interrupted {
      paths,
      std::make_unique<FakeIdentityPlatform>(files),
      true,
      [stage](const auto observed) { return observed == stage; },
    };
    const auto first = interrupted.load_or_create(legacy, random);
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(first.error(), runtime::HostIdentityError::injected_interruption);

    runtime::HostIdentityStore recovered {
      paths,
      std::make_unique<FakeIdentityPlatform>(files),
      true,
    };
    const auto second = recovered.load_or_create(legacy, random);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->seed, legacy);
    EXPECT_TRUE(second->retire_legacy_seed);
    EXPECT_TRUE(files->files.contains(paths.identity.string()));
    EXPECT_TRUE(files->files.contains(paths.journal.string()));
    EXPECT_FALSE(files->files.contains(paths.temporary.string()));
  }
}

TEST(ProtocolV3Identity, CorruptProtectedBlobFailsClosedWithoutReplacement) {
  auto files = std::make_shared<FakeIdentityFiles>();
  const auto paths = fake_identity_paths();
  control::SecureRandom random;
  control::Bytes32 legacy {};
  std::iota(legacy.begin(), legacy.end(), 3U);
  {
    runtime::HostIdentityStore store {
      paths,
      std::make_unique<FakeIdentityPlatform>(files),
      true,
    };
    ASSERT_TRUE(store.load_or_create(legacy, random).has_value());
  }
  auto &blob = files->files.at(paths.identity.string());
  ASSERT_GT(blob.size(), 20U);
  blob[20] ^= 0x5aU;
  const auto corrupted = blob;

  runtime::HostIdentityStore reloaded {
    paths,
    std::make_unique<FakeIdentityPlatform>(files),
    true,
  };
  const auto result = reloaded.load_or_create(legacy, random);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), runtime::HostIdentityError::identity_mismatch);
  EXPECT_EQ(files->files.at(paths.identity.string()), corrupted);
}

TEST(ProtocolV3Identity, UnsupportedPrincipalCreatesNoSecondIdentity) {
  auto files = std::make_shared<FakeIdentityFiles>();
  files->principal = runtime::HostPrincipal::unsupported;
  const auto paths = fake_identity_paths();
  runtime::HostIdentityStore store {
    paths,
    std::make_unique<FakeIdentityPlatform>(files),
    true,
  };
  control::SecureRandom random;
  const auto result = store.load_or_create(std::nullopt, random);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), runtime::HostIdentityError::unsupported_principal);
  EXPECT_TRUE(files->files.empty());
}

TEST(ProtocolV3Identity, InsecureExistingBlobIsRejectedWithoutAclWeakening) {
  auto files = std::make_shared<FakeIdentityFiles>();
  const auto paths = fake_identity_paths();
  files->files[paths.identity.string()] = {'L', 'U', 'M', 'E', 'N', 'I', 'D', '3'};
  runtime::HostIdentityStore store {
    paths,
    std::make_unique<FakeIdentityPlatform>(files),
    true,
  };
  control::SecureRandom random;
  const auto result = store.load_or_create(std::nullopt, random);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), runtime::HostIdentityError::security_failure);
  EXPECT_FALSE(files->secure.contains(paths.identity.string()));
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

TEST(ProtocolV3Runtime, RejectsCanonicalModeViolationsBeforeResourcesOrApplicationMutation) {
  control::ClientRecord client {
    .client_id = control::Identifier {},
    .permissions = control::start_permission,
    .generation = 1,
  };
  client.client_id.fill(0x61);

  std::vector<control::cbor::Value::Map> invalid;
  invalid.push_back(sdr_h264_start_fields(4098, 2160));
  invalid.push_back(sdr_h264_start_fields(3840, 4098));

  auto unreduced = sdr_h264_start_fields(1920, 1080);
  *mutable_map_field(unreduced, 6) = 60'000U;
  *mutable_map_field(unreduced, 7) = 1'000U;
  invalid.push_back(std::move(unreduced));

  auto below_minimum = sdr_h264_start_fields(1920, 1080);
  *mutable_map_field(below_minimum, 6) = 9'999U;
  *mutable_map_field(below_minimum, 7) = 1'000U;
  invalid.push_back(std::move(below_minimum));

  auto sdr10 = sdr_h264_start_fields(1920, 1080);
  auto *codec_array = std::get_if<control::cbor::Value::Array>(&mutable_map_field(sdr10, 9)->storage);
  auto *codec = std::get_if<control::cbor::Value::Map>(&codec_array->front().storage);
  *mutable_map_field(*codec, 1) = 2U;
  *mutable_map_field(*codec, 3) = 10U;
  invalid.push_back(std::move(sdr10));

  const auto prior_hevc_mode = video::active_hevc_mode;
  video::active_hevc_mode = 3;
  const auto restore_hevc = std::unique_ptr<void, std::function<void(void *)>> {
    reinterpret_cast<void *>(1),
    [&](void *) {
      video::active_hevc_mode = prior_hevc_mode;
    },
  };

  for (std::size_t index = 0; index < invalid.size(); ++index) {
    client.client_id.back() = static_cast<std::uint8_t>(0x61 + index);
    control::SecureRandom random;
    std::vector<std::string> events;
    OrderingApplicationBridge applications {events, false};
    OrderingResourceFactory factory {events};
    AcceptingTransport transport;
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};

    const auto started = backend.start(
      client,
      invalid[index],
      61 + index,
      quic::maximum_semantic_datagram_bytes
    );
    ASSERT_FALSE(started.has_value()) << index;
    EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::unsupported_media)) << index;
    EXPECT_EQ(factory.create_calls, 0) << index;
    EXPECT_EQ(applications.start_calls, 0) << index;
    EXPECT_TRUE(events.empty()) << index;
  }
}

TEST(ProtocolV3Runtime, ActivatesExactResourcesBeforeApplicationAndRollsBackLaunchFailure) {
  control::SecureRandom random;
  std::vector<std::string> events;
  OrderingApplicationBridge applications {events, true};
  OrderingResourceFactory factory {events};
  AcceptingTransport transport;
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  control::ClientRecord client {
    .client_id = control::Identifier {},
    .permissions = control::start_permission,
    .generation = 1,
  };
  client.client_id.fill(0x71);

  const auto started = backend.start(
    client,
    sdr_h264_start_fields(4096, 4096),
    71,
    quic::maximum_semantic_datagram_bytes
  );

  ASSERT_FALSE(started.has_value());
  EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::application_not_found));
  ASSERT_TRUE(applications.last_launch.has_value());
  EXPECT_EQ(applications.last_launch->width, 4096U);
  EXPECT_EQ(applications.last_launch->height, 4096U);
  EXPECT_EQ(applications.last_launch->refresh_numerator, 60'000U);
  EXPECT_EQ(applications.last_launch->refresh_denominator, 1'001U);
  EXPECT_EQ(
    events,
    (std::vector<std::string> {"resource.create", "application.start", "resource.stop"})
  );
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
    auto resources = std::make_unique<StopRaceResources>(state, [&]() noexcept {
      backend.mark_failed_for_test(session_id);
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

    auto exact_retry = backend.control(
      client,
      control::AuthenticatedControl::stop,
      stop_fields(session_id, intent_byte),
      intent_byte + 1U,
      99,
      2
    );
    EXPECT_TRUE(exact_retry.has_value());
    if (exact_retry) {
      EXPECT_EQ(result_status(*exact_retry), 0U);
      EXPECT_TRUE(exact_retry->post_response_events.empty());
    }
    EXPECT_EQ(state->stop_calls.load(), 1);

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

TEST(ProtocolV3Runtime, StartAndStopOutcomesReplayAcrossAuthoritiesWithoutRepeatingSideEffects) {
  control::SecureRandom random;
  StopRaceApplicationBridge applications;
  CapturingResourceFactory factory;
  AcceptingTransport transport;
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  const auto client = start_client(0x91);
  const auto request = sdr_h264_start_fields(1920, 1080);

  const auto first = backend.start(
    client,
    request,
    91,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_TRUE(first.has_value());
  EXPECT_FALSE(first->replay_requires_attach);
  EXPECT_EQ(factory.create_calls, 1);
  EXPECT_EQ(applications.start_calls.load(), 1);

  const auto replayed = backend.start(
    client,
    request,
    92,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_TRUE(replayed.has_value());
  EXPECT_TRUE(replayed->replay_requires_attach);
  EXPECT_TRUE(replayed->host_requests.empty());
  EXPECT_EQ(replayed->session_id, first->session_id);
  EXPECT_EQ(replayed->response_fields, first->response_fields);
  EXPECT_EQ(factory.create_calls, 1);
  EXPECT_EQ(applications.start_calls.load(), 1);

  auto conflicting_request = request;
  *mutable_map_field(conflicting_request, 8) = 90'000U;
  const auto conflict = backend.start(
    client,
    conflicting_request,
    93,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_FALSE(conflict.has_value());
  EXPECT_EQ(conflict.error(), static_cast<std::uint8_t>(ProtocolStatus::busy));
  EXPECT_EQ(factory.create_calls, 1);

  const auto stopped = backend.control(
    client,
    control::AuthenticatedControl::stop,
    stop_fields(first->session_id, 0x44),
    3,
    91,
    1
  );
  ASSERT_TRUE(stopped.has_value());
  EXPECT_EQ(result_status(*stopped), 0U);

  const auto expired = backend.start(
    client,
    request,
    94,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_FALSE(expired.has_value());
  EXPECT_EQ(expired.error(), static_cast<std::uint8_t>(ProtocolStatus::expired));
  EXPECT_EQ(factory.create_calls, 1);
}

TEST(ProtocolV3Runtime, OutcomeBudgetRefusalHappensBeforeStartSideEffects) {
  control::SecureRandom random;
  StopRaceApplicationBridge applications;
  CapturingResourceFactory factory;
  AcceptingTransport transport;
  auto budget = std::make_shared<lumen::protocol_v3::resource_budget::ResourceBudgetCoordinator>();
  auto held = budget->reserve(
    lumen::protocol_v3::resource_budget::ResourceClass::operation_outcomes,
    lumen::protocol_v3::resource_budget::class_ceilings[
      static_cast<std::size_t>(lumen::protocol_v3::resource_budget::ResourceClass::operation_outcomes)
    ]
  );
  ASSERT_TRUE(held.has_value());
  runtime::ProductionSessionBackend backend {random, applications, factory, transport, budget};

  const auto started = backend.start(
    start_client(0x92),
    sdr_h264_start_fields(1920, 1080),
    95,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_FALSE(started.has_value());
  EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
  EXPECT_EQ(factory.create_calls, 0);
  EXPECT_EQ(applications.start_calls.load(), 0);
}

TEST(ProtocolV3Runtime, LifeU03LatchesFailureDuringFactoryCreateBeforeCommit) {
  const auto state = std::make_shared<LifetimeFailureState>();
  control::SecureRandom random;
  LifetimeApplicationBridge applications {state};
  LifetimeFailureFactory factory {state, LifetimeFactoryMode::report_and_succeed};
  LifetimeTransport transport {state};
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  const auto client = start_client();

  const auto started_at = std::chrono::steady_clock::now();
  const auto started = backend.start(
    client,
    sdr_h264_start_fields(1920, 1080),
    81,
    quic::maximum_semantic_datagram_bytes
  );
  const auto elapsed = std::chrono::steady_clock::now() - started_at;

  ASSERT_FALSE(started.has_value());
  EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
  EXPECT_LT(elapsed, std::chrono::seconds {2});
  EXPECT_EQ(applications.start_calls.load(), 0);
  EXPECT_EQ(applications.stop_calls.load(), 0);
  EXPECT_EQ(state->resource_stops.load(), 1);
  EXPECT_EQ(state->resource_destructions.load(), 1);
  EXPECT_EQ(transport.update_calls.load(), 1);
  EXPECT_EQ(transport.reset_calls.load(), 1);
  EXPECT_FALSE(backend.owned_session(client).has_value());
  EXPECT_FALSE(factory.trigger_failure());
}

TEST(ProtocolV3Runtime, LifeI01FactoryFailureModesRollbackPolicyWithoutPublication) {
  const std::array modes {
    LifetimeFactoryMode::report_and_error,
    LifetimeFactoryMode::null_resource,
    LifetimeFactoryMode::throw_allocation,
  };
  for (std::size_t index = 0; index < modes.size(); ++index) {
    SCOPED_TRACE(index);
    const auto state = std::make_shared<LifetimeFailureState>();
    control::SecureRandom random;
    LifetimeApplicationBridge applications {state};
    LifetimeFailureFactory factory {state, modes[index]};
    LifetimeTransport transport {state};
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    const auto client = start_client(static_cast<std::uint8_t>(0x82 + index));

    const auto started = backend.start(
      client,
      sdr_h264_start_fields(1920, 1080),
      82 + index,
      quic::maximum_semantic_datagram_bytes
    );

    ASSERT_FALSE(started.has_value());
    EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
    EXPECT_EQ(applications.start_calls.load(), 0);
    EXPECT_EQ(applications.stop_calls.load(), 0);
    EXPECT_EQ(state->resource_stops.load(), 0);
    EXPECT_EQ(transport.update_calls.load(), 1);
    EXPECT_EQ(transport.reset_calls.load(), 1);
    EXPECT_FALSE(backend.owned_session(client).has_value());
    EXPECT_FALSE(factory.trigger_failure());
  }
}

TEST(ProtocolV3Runtime, LifeU01PostCommitFailureTerminatesExactlyOnce) {
  const auto state = std::make_shared<LifetimeFailureState>();
  control::SecureRandom random;
  LifetimeApplicationBridge applications {state};
  LifetimeFailureFactory factory {state};
  LifetimeTransport transport {state};
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  const auto client = start_client(0x91);

  const auto started = backend.start(
    client,
    sdr_h264_start_fields(1920, 1080),
    91,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_TRUE(started.has_value());
  ASSERT_TRUE(backend.owned_session(client).has_value());

  const auto failed_at = std::chrono::steady_clock::now();
  EXPECT_TRUE(factory.trigger_failure());
  EXPECT_TRUE(factory.trigger_failure());
  ASSERT_TRUE(wait_for(std::chrono::seconds {2}, [&]() {
    return !backend.owned_session(client).has_value() && state->resource_destructions.load() == 1;
  }));
  EXPECT_LT(std::chrono::steady_clock::now() - failed_at, std::chrono::seconds {2});
  EXPECT_EQ(state->resource_stops.load(), 1);
  EXPECT_EQ(state->resource_destructions.load(), 1);
  EXPECT_EQ(applications.stop_calls.load(), 0);
  EXPECT_EQ(transport.enqueue_calls.load(), 2);
  EXPECT_FALSE(factory.trigger_failure());
}

TEST(ProtocolV3Runtime, LifeU02StopRevokesFailureBeforeResourceJoin) {
  const auto state = std::make_shared<LifetimeFailureState>();
  control::SecureRandom random;
  LifetimeApplicationBridge applications {state};
  LifetimeFailureFactory factory {state, LifetimeFactoryMode::success, true};
  LifetimeTransport transport {state};
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  const auto client = start_client(0x92);
  const auto started = backend.start(
    client,
    sdr_h264_start_fields(1920, 1080),
    92,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_TRUE(started.has_value());

  const auto stopped_at = std::chrono::steady_clock::now();
  const auto stopped = backend.control(
    client,
    control::AuthenticatedControl::stop,
    stop_fields(started->session_id, 0x92),
    92,
    92,
    1
  );
  const auto elapsed = std::chrono::steady_clock::now() - stopped_at;

  ASSERT_TRUE(stopped.has_value());
  EXPECT_EQ(result_status(*stopped), 0U);
  EXPECT_LT(elapsed, std::chrono::seconds {2});
  EXPECT_EQ(state->failure_attempts.load(), 1);
  EXPECT_EQ(state->resource_stops.load(), 1);
  EXPECT_EQ(state->resource_destructions.load(), 1);
  EXPECT_EQ(applications.stop_calls.load(), 1);
  EXPECT_EQ(transport.reset_calls.load(), 1);
  EXPECT_EQ(transport.enqueue_calls.load(), 0);
  EXPECT_FALSE(backend.owned_session(client).has_value());
}

TEST(ProtocolV3Runtime, LifeU03BackendDestructionRevokesAndCompletesWithinStopBound) {
  const auto state = std::make_shared<LifetimeFailureState>();
  control::SecureRandom random;
  LifetimeApplicationBridge applications {state};
  LifetimeFailureFactory factory {state, LifetimeFactoryMode::success, true};
  LifetimeTransport transport {state};
  const auto client = start_client(0x93);

  const auto destroyed_at = std::chrono::steady_clock::now();
  {
    runtime::ProductionSessionBackend backend {random, applications, factory, transport};
    const auto started = backend.start(
      client,
      sdr_h264_start_fields(1920, 1080),
      93,
      quic::maximum_semantic_datagram_bytes
    );
    ASSERT_TRUE(started.has_value());
  }
  const auto elapsed = std::chrono::steady_clock::now() - destroyed_at;

  EXPECT_LT(elapsed, std::chrono::seconds {5});
  EXPECT_EQ(state->failure_attempts.load(), 1);
  EXPECT_EQ(state->resource_stops.load(), 1);
  EXPECT_EQ(state->resource_destructions.load(), 1);
  EXPECT_EQ(applications.stop_calls.load(), 1);
  EXPECT_EQ(transport.revoke_calls.load(), 1);
  EXPECT_EQ(transport.enqueue_calls.load(), 0);
  EXPECT_FALSE(factory.trigger_failure());
}

TEST(ProtocolV3Runtime, LifeU01ConcurrentFailureAndBackendDestructionRemainGenerationSafe) {
  const auto state = std::make_shared<LifetimeFailureState>();
  control::SecureRandom random;
  LifetimeApplicationBridge applications {state};
  LifetimeFailureFactory factory {state, LifetimeFactoryMode::success, true};
  LifetimeTransport transport {state};
  const auto client = start_client(0x95);
  auto backend = std::make_unique<runtime::ProductionSessionBackend>(
    random,
    applications,
    factory,
    transport
  );
  const auto started = backend->start(
    client,
    sdr_h264_start_fields(1920, 1080),
    95,
    quic::maximum_semantic_datagram_bytes
  );
  ASSERT_TRUE(started.has_value());

  std::atomic_bool release_reporter {};
  std::atomic_bool reporter_ready {};
  std::jthread reporter {[&]() noexcept {
    reporter_ready.store(true, std::memory_order_release);
    while (!release_reporter.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    static_cast<void>(factory.trigger_failure());
    static_cast<void>(factory.trigger_failure());
  }};
  ASSERT_TRUE(wait_for(std::chrono::seconds {1}, [&]() {
    return reporter_ready.load(std::memory_order_acquire);
  }));

  const auto destroyed_at = std::chrono::steady_clock::now();
  release_reporter.store(true, std::memory_order_release);
  backend.reset();
  reporter.join();
  const auto elapsed = std::chrono::steady_clock::now() - destroyed_at;

  EXPECT_LT(elapsed, std::chrono::seconds {5});
  EXPECT_EQ(state->resource_stops.load(), 1);
  EXPECT_EQ(state->resource_destructions.load(), 1);
  EXPECT_LE(applications.stop_calls.load(), 1);
  EXPECT_FALSE(factory.trigger_failure());
}

TEST(ProtocolV3Runtime, LifeI02PostApplicationPreCommitFailureRollsBackExactlyOnce) {
  const auto state = std::make_shared<LifetimeFailureState>();
  control::SecureRandom random;
  LifetimeApplicationBridge applications {state};
  LifetimeFailureFactory factory {state};
  LifetimeTransport transport {state};
  runtime::ProductionSessionBackend backend {random, applications, factory, transport};
  const auto client = start_client(0x94);
  backend.fail_next_start_before_commit_for_test();

  const auto started = backend.start(
    client,
    sdr_h264_start_fields(1920, 1080),
    94,
    quic::maximum_semantic_datagram_bytes
  );

  ASSERT_FALSE(started.has_value());
  EXPECT_EQ(started.error(), static_cast<std::uint8_t>(ProtocolStatus::resource_failure));
  EXPECT_EQ(state->resource_stops.load(), 1);
  EXPECT_EQ(state->resource_destructions.load(), 1);
  EXPECT_EQ(applications.start_calls.load(), 1);
  EXPECT_EQ(applications.stop_calls.load(), 1);
  EXPECT_EQ(transport.update_calls.load(), 1);
  EXPECT_EQ(transport.reset_calls.load(), 1);
  EXPECT_FALSE(backend.owned_session(client).has_value());
  EXPECT_EQ(
    state->snapshot(),
    (std::vector<std::string> {
      "transport.update",
      "resource.create",
      "application.start",
      "resource.stop",
      "application.stop",
      "transport.reset",
      "resource.destroy",
    })
  );
  EXPECT_FALSE(factory.trigger_failure());
}
