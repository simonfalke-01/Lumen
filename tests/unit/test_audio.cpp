/**
 * @file tests/unit/test_audio.cpp
 * @brief Test src/audio.*.
 */
#include "../tests_common.h"

#include <array>
#include <condition_variable>
#include <future>
#include <mutex>
#include <src/audio.h>
#include <vector>

using namespace audio;

namespace {
  class recording_destination_t final: public AudioPacketDestination {
  public:
    enqueue_result_e enqueue(packet_t packet) override {
      std::lock_guard lock {mutex_};
      if (closed_) {
        return enqueue_result_e::closed;
      }
      packets_.emplace_back(std::move(packet));
      packet_available_.notify_all();
      return enqueue_result_e::enqueued;
    }

    void close() noexcept override {
      std::lock_guard lock {mutex_};
      closed_ = true;
      packet_available_.notify_all();
    }

    bool wait_for_packet(const std::chrono::milliseconds timeout) {
      std::unique_lock lock {mutex_};
      return packet_available_.wait_for(lock, timeout, [this] {
        return !packets_.empty() || closed_;
      }) && !packets_.empty();
    }

    std::vector<packet_t> packets() const {
      std::lock_guard lock {mutex_};
      return packets_;
    }

  private:
    mutable std::mutex mutex_;
    std::condition_variable packet_available_;
    std::vector<packet_t> packets_;
    bool closed_ {};
  };

  class fixed_slab_destination_t final: public AudioPacketDestination {
  public:
    bool requires_fixed_packet_storage() const noexcept override {
      return true;
    }

    std::optional<packet_write_lease_t> acquire_packet_storage() noexcept override {
      std::scoped_lock lock(mutex_);
      if (closed_ || reserved_) {
        return std::nullopt;
      }
      reserved_ = true;
      ++acquired_;
      return packet_write_lease_t {.storage = storage_, .token = 1};
    }

    enqueue_result_e commit_packet_storage(
      const packet_write_lease_t &lease,
      const std::size_t payload_bytes,
      const std::uint64_t,
      const bool
    ) noexcept override {
      std::scoped_lock lock(mutex_);
      if (!reserved_ || lease.token != 1 || payload_bytes == 0 || payload_bytes > storage_.size()) {
        return enqueue_result_e::backpressure;
      }
      reserved_ = false;
      ++committed_;
      available_.notify_all();
      return enqueue_result_e::enqueued;
    }

    void cancel_packet_storage(const packet_write_lease_t &) noexcept override {
      std::scoped_lock lock(mutex_);
      reserved_ = false;
      available_.notify_all();
    }

    enqueue_result_e enqueue(packet_t) override {
      ++fallback_enqueues_;
      return enqueue_result_e::backpressure;
    }

    void close() noexcept override {
      std::scoped_lock lock(mutex_);
      closed_ = true;
      available_.notify_all();
    }

    bool wait_for_commit(const std::chrono::milliseconds timeout) {
      std::unique_lock lock(mutex_);
      return available_.wait_for(lock, timeout, [this] {
        return committed_ != 0 || closed_;
      }) && committed_ != 0;
    }

    std::size_t acquired() const noexcept {
      return acquired_.load(std::memory_order_acquire);
    }

    std::size_t committed() const noexcept {
      return committed_.load(std::memory_order_acquire);
    }

    std::size_t fallback_enqueues() const noexcept {
      return fallback_enqueues_.load(std::memory_order_acquire);
    }

  private:
    std::array<std::uint8_t, maximum_encoded_packet_bytes> storage_ {};
    mutable std::mutex mutex_;
    std::condition_variable available_;
    std::atomic_size_t acquired_ {};
    std::atomic_size_t committed_ {};
    std::atomic_size_t fallback_enqueues_ {};
    bool reserved_ {};
    bool closed_ {};
  };

  class transient_fixed_slab_destination_t final: public AudioPacketDestination {
  public:
    bool requires_fixed_packet_storage() const noexcept override {
      return true;
    }

    std::optional<packet_write_lease_t> acquire_packet_storage() noexcept override {
      const auto attempt = attempts_.fetch_add(1, std::memory_order_acq_rel);
      if (attempt < 2) {
        return std::nullopt;
      }
      return packet_write_lease_t {.storage = storage_, .token = 1};
    }

    enqueue_result_e commit_packet_storage(
      const packet_write_lease_t &,
      const std::size_t payload_bytes,
      const std::uint64_t,
      const bool discontinuity
    ) noexcept override {
      if (payload_bytes == 0 || payload_bytes > storage_.size()) {
        return enqueue_result_e::backpressure;
      }
      discontinuity_.store(discontinuity, std::memory_order_release);
      committed_.store(true, std::memory_order_release);
      available_.notify_all();
      return enqueue_result_e::enqueued;
    }

    void cancel_packet_storage(const packet_write_lease_t &) noexcept override {
    }

    enqueue_result_e enqueue(packet_t) override {
      fallback_enqueues_.fetch_add(1, std::memory_order_relaxed);
      return enqueue_result_e::backpressure;
    }

    void close() noexcept override {
      available_.notify_all();
    }

    bool wait_for_commit(const std::chrono::milliseconds timeout) {
      std::unique_lock lock(mutex_);
      return available_.wait_for(lock, timeout, [this] {
        return committed_.load(std::memory_order_acquire);
      });
    }

    std::size_t attempts() const noexcept {
      return attempts_.load(std::memory_order_acquire);
    }

    bool discontinuity() const noexcept {
      return discontinuity_.load(std::memory_order_acquire);
    }

    std::size_t fallback_enqueues() const noexcept {
      return fallback_enqueues_.load(std::memory_order_acquire);
    }

  private:
    std::array<std::uint8_t, maximum_encoded_packet_bytes> storage_ {};
    std::mutex mutex_;
    std::condition_variable available_;
    std::atomic_size_t attempts_ {};
    std::atomic_size_t fallback_enqueues_ {};
    std::atomic_bool committed_ {};
    std::atomic_bool discontinuity_ {};
  };

  struct blocking_destination_state_t {
    std::promise<void> entered;
    std::promise<void> release;
    std::promise<void> destroyed;
  };

  class blocking_destination_t final: public AudioPacketDestination {
  public:
    explicit blocking_destination_t(std::shared_ptr<blocking_destination_state_t> state):
        state_ {std::move(state)},
        release_ {state_->release.get_future().share()} {
    }

    ~blocking_destination_t() override {
      state_->destroyed.set_value();
    }

    enqueue_result_e enqueue(packet_t) override {
      std::call_once(entered_once_, [this] {
        state_->entered.set_value();
      });
      release_.wait();
      return enqueue_result_e::enqueued;
    }

    void close() noexcept override {
    }

  private:
    std::shared_ptr<blocking_destination_state_t> state_;
    std::shared_future<void> release_;
    std::once_flag entered_once_;
  };

  class rejecting_destination_t final: public AudioPacketDestination {
  public:
    explicit rejecting_destination_t(const enqueue_result_e result):
        result_ {result} {
    }

    enqueue_result_e enqueue(packet_t) override {
      ++calls_;
      std::call_once(called_once_, [this] {
        called_.set_value();
      });
      return result_;
    }

    void close() noexcept override {
      ++close_calls_;
    }

    std::future<void> called_future() {
      return called_.get_future();
    }

    std::size_t calls() const noexcept {
      return calls_.load(std::memory_order_acquire);
    }

    std::size_t close_calls() const noexcept {
      return close_calls_.load(std::memory_order_acquire);
    }

  private:
    enqueue_result_e result_;
    std::promise<void> called_;
    std::once_flag called_once_;
    std::atomic_size_t calls_ {};
    std::atomic_size_t close_calls_ {};
  };

  config_t destination_test_config(const int channels = 2, const int channel_mask = 0x3) {
    auto config = config_t {5, channels, channel_mask, {0}, {}};
    config.flags.set(config_t::HOST_AUDIO);
    config.flags.set(config_t::CONTINUOUS_AUDIO);
    return config;
  }

  void stop_capture(const safe::mail_t &mail) {
    mail->event<bool>(mail::shutdown)->raise(true);
  }
}  // namespace

struct AudioTest: PlatformTestSuite, testing::WithParamInterface<std::tuple<std::basic_string_view<char>, config_t>> {
  void SetUp() override {
    BaseTest::SetUp();
    m_config = std::get<1>(GetParam());
    m_mail = std::make_shared<safe::mail_raw_t>();
  }

  config_t m_config;
  safe::mail_t m_mail;
};

constexpr std::bitset<config_t::MAX_FLAGS> config_flags(const int flag = -1) {
  auto result = std::bitset<config_t::MAX_FLAGS>();
  if (flag >= 0) {
    result.set(flag);
  }
  return result;
}

INSTANTIATE_TEST_SUITE_P(
  Configurations,
  AudioTest,
  testing::Values(
    std::make_tuple("HIGH_STEREO", config_t {5, 2, 0x3, {0}, config_flags(config_t::HIGH_QUALITY)}),
    std::make_tuple("SURROUND51", config_t {5, 6, 0x3F, {0}, config_flags()}),
    std::make_tuple("SURROUND71", config_t {5, 8, 0x63F, {0}, config_flags()}),
    std::make_tuple("NEGOTIATED_71", config_t {5, 8, 0x63F, {0}, config_flags(), 1'536'000}),
    std::make_tuple("SURROUND51_CUSTOM", config_t {5, 6, 0x3F, {6, 4, 2, {0, 1, 4, 5, 2, 3}}, config_flags(config_t::CUSTOM_SURROUND_PARAMS)})
  ),
  [](const auto &info) {
    return std::string(std::get<0>(info.param));
  }
);

TEST_P(AudioTest, TestEncode) {
  const auto destination = std::make_shared<recording_destination_t>();
  std::atomic_bool packet_received {};
  std::jthread timer([&] {
    packet_received.store(destination->wait_for_packet(2s), std::memory_order_release);
    stop_capture(m_mail);
  });
  audio::capture(m_mail, m_config, destination);

  timer.join();
  EXPECT_TRUE(packet_received.load(std::memory_order_acquire));
  const auto packets = destination->packets();
  ASSERT_FALSE(packets.empty());
  for (const auto &packet : packets) {
    EXPECT_NE(packet.payload.size(), 0U);
    EXPECT_EQ(packet.sample_position % 240, 0U);
  }
}

struct AudioPacketDestinationTest: PlatformTestSuite {};

TEST_F(AudioPacketDestinationTest, HostStyleFixedSlabAvoidsFallbackPacketAllocation) {
  auto mail = std::make_shared<safe::mail_raw_t>();
  const auto destination = std::make_shared<fixed_slab_destination_t>();
  std::atomic_bool committed {};
  std::jthread timer([&] {
    committed.store(destination->wait_for_commit(5s), std::memory_order_release);
    stop_capture(mail);
  });
  audio::capture(mail, destination_test_config(), destination);
  timer.join();

  EXPECT_TRUE(committed.load(std::memory_order_acquire));
  EXPECT_GT(destination->acquired(), 0U);
  EXPECT_GT(destination->committed(), 0U);
  EXPECT_EQ(destination->fallback_enqueues(), 0U);
}

TEST_F(AudioPacketDestinationTest, FixedSlabPressureMarksTheNextPublishedPacketDiscontinuous) {
  auto mail = std::make_shared<safe::mail_raw_t>();
  const auto destination = std::make_shared<transient_fixed_slab_destination_t>();
  std::jthread capture([mail, destination] {
    audio::capture(mail, destination_test_config(), destination);
  });
  ASSERT_TRUE(destination->wait_for_commit(5s));
  stop_capture(mail);
  capture.join();
  EXPECT_GE(destination->attempts(), 3U);
  EXPECT_TRUE(destination->discontinuity());
  EXPECT_EQ(destination->fallback_enqueues(), 0U);
}

// AUD-U01: the encoder owns only a weak typed destination reference while an enqueue is active.
TEST_F(AudioPacketDestinationTest, DestinationCanBeDestroyedWhileEncodeIsInFlight) {
  auto mail = std::make_shared<safe::mail_raw_t>();
  auto state = std::make_shared<blocking_destination_state_t>();
  auto entered = state->entered.get_future();
  auto destroyed = state->destroyed.get_future();
  auto destination = std::make_shared<blocking_destination_t>(state);
  const packet_destination_t weak_destination = destination;
  std::jthread capture([mail, weak_destination] {
    audio::capture(mail, destination_test_config(), weak_destination);
  });

  if (entered.wait_for(2s) != std::future_status::ready) {
    stop_capture(mail);
    state->release.set_value();
    capture.join();
    FAIL() << "Audio encoder never offered a packet to its typed destination";
    return;
  }
  destination.reset();
  EXPECT_EQ(destroyed.wait_for(20ms), std::future_status::timeout);
  state->release.set_value();
  EXPECT_EQ(destroyed.wait_for(2s), std::future_status::ready);

  stop_capture(mail);
  capture.join();
}

// AUD-U02: transient destination pressure drops bounded packets but does not terminate capture.
TEST_F(AudioPacketDestinationTest, BackpressureContinuesPublicationWhileClosedStopsIt) {
  auto pressured_mail = std::make_shared<safe::mail_raw_t>();
  auto pressured = std::make_shared<rejecting_destination_t>(AudioPacketDestination::enqueue_result_e::backpressure);
  auto first_pressure = pressured->called_future();
  std::jthread pressured_capture([pressured_mail, pressured] {
    audio::capture(pressured_mail, destination_test_config(), pressured);
  });
  ASSERT_EQ(first_pressure.wait_for(2s), std::future_status::ready);
  std::this_thread::sleep_for(30ms);
  stop_capture(pressured_mail);
  pressured_capture.join();
  EXPECT_GT(pressured->calls(), 1U);

  auto closed_mail = std::make_shared<safe::mail_raw_t>();
  auto closed = std::make_shared<rejecting_destination_t>(AudioPacketDestination::enqueue_result_e::closed);
  auto first_closed = closed->called_future();
  std::jthread closed_capture([closed_mail, closed] {
    audio::capture(closed_mail, destination_test_config(), closed);
  });
  ASSERT_EQ(first_closed.wait_for(2s), std::future_status::ready);
  std::this_thread::sleep_for(30ms);
  stop_capture(closed_mail);
  closed_capture.join();
  EXPECT_EQ(closed->calls(), 1U);
}
