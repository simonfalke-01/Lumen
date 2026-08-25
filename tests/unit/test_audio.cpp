/**
 * @file tests/unit/test_audio.cpp
 * @brief Test src/audio.*.
 */
#include "../tests_common.h"

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

  config_t stereo_config() {
    return config_t {5, 2, 0x3, {0}, {}};
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

// AUD-U01: the encoder owns only a weak typed destination reference while an enqueue is active.
TEST_F(AudioPacketDestinationTest, DestinationCanBeDestroyedWhileEncodeIsInFlight) {
  auto mail = std::make_shared<safe::mail_raw_t>();
  auto state = std::make_shared<blocking_destination_state_t>();
  auto entered = state->entered.get_future();
  auto destroyed = state->destroyed.get_future();
  auto destination = std::make_shared<blocking_destination_t>(state);
  const packet_destination_t weak_destination = destination;
  std::jthread capture([mail, weak_destination] {
    audio::capture(mail, stereo_config(), weak_destination);
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

// AUD-U02: exact full/closed results terminate publication instead of spinning or dropping silently.
TEST_F(AudioPacketDestinationTest, BackpressureAndClosedResultsStopFurtherPublication) {
  for (const auto result : {
         AudioPacketDestination::enqueue_result_e::backpressure,
         AudioPacketDestination::enqueue_result_e::closed,
       }) {
    auto mail = std::make_shared<safe::mail_raw_t>();
    auto destination = std::make_shared<rejecting_destination_t>(result);
    auto called = destination->called_future();
    std::jthread capture([mail, destination] {
      audio::capture(mail, stereo_config(), destination);
    });

    if (called.wait_for(2s) != std::future_status::ready) {
      stop_capture(mail);
      capture.join();
      FAIL() << "Audio encoder never observed the scripted destination result";
      return;
    }
    std::this_thread::sleep_for(30ms);
    stop_capture(mail);
    capture.join();
    EXPECT_EQ(destination->calls(), 1U);
  }
}

// AUD-I01/AUD-I02: three simultaneous protocol owners receive their own PCM-to-Opus stream.
TEST_F(AudioPacketDestinationTest, TwoProtocolV3AndOneLegacyDestinationRemainIsolated) {
  std::array<safe::mail_t, 3> mails {
    std::make_shared<safe::mail_raw_t>(),
    std::make_shared<safe::mail_raw_t>(),
    std::make_shared<safe::mail_raw_t>(),
  };
  std::array<std::shared_ptr<recording_destination_t>, 3> destinations {
    std::make_shared<recording_destination_t>(),
    std::make_shared<recording_destination_t>(),
    std::make_shared<recording_destination_t>(),
  };
  std::array<std::jthread, 3> captures;
  for (std::size_t index = 0; index < captures.size(); ++index) {
    captures[index] = std::jthread {[mail = mails[index], destination = destinations[index]] {
      audio::capture(mail, stereo_config(), destination);
    }};
  }

  std::array<bool, 3> received {};
  for (std::size_t index = 0; index < destinations.size(); ++index) {
    received[index] = destinations[index]->wait_for_packet(3s);
  }
  for (const auto &mail : mails) {
    stop_capture(mail);
  }
  for (auto &capture : captures) {
    capture.join();
  }

  for (std::size_t index = 0; index < destinations.size(); ++index) {
    EXPECT_TRUE(received[index]);
    const auto &destination = destinations[index];
    const auto packets = destination->packets();
    ASSERT_FALSE(packets.empty());
    EXPECT_TRUE(std::ranges::all_of(packets, [](const auto &packet) {
      return packet.payload.size() != 0;
    }));
  }
}
