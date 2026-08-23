/**
 * @file tests/unit/platform/windows/test_virtual_hid_session.cpp
 * @brief Unit tests for the dynamic VHF user-mode session.
 */

// local includes
#include "src/platform/windows/virtual_hid_session.h"

// standard includes
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

// lib includes
#include <gtest/gtest.h>

namespace {
  using namespace std::chrono_literals;
  using namespace platf::win_gamepad;

  /**
   * @brief Thread-safe fake dynamic-gamepad channel.
   */
  class fake_channel_t final: public gamepad_channel_t {
  public:
    fake_channel_t() {
      caps.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
      caps.size = sizeof(caps);
      caps.base_abi_version = LUMEN_VHID_ABI_VERSION;
      caps.capability_flags =
        LUMEN_VHID_GAMEPAD_CAPABILITY_OUTPUT_REPORTS |
        LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS |
        LUMEN_VHID_GAMEPAD_CAPABILITY_OWNER_CLEANUP |
        LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS;
      caps.supported_profiles = LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE);
      caps.max_devices = LUMEN_VHID_MAX_GAMEPADS;
      caps.max_input_report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
      caps.max_output_report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
    }

    channel_result_t open() override {
      std::lock_guard lock(mutex);
      ++opens;
      opened = open_result.status == channel_status_e::success;
      return open_result;
    }

    channel_result_t capabilities(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE &response) override {
      std::lock_guard lock(mutex);
      response = caps;
      return capability_result;
    }

    channel_result_t create(
      const LUMEN_VHID_GAMEPAD_CREATE_REQUEST &request,
      LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &response
    ) override {
      std::lock_guard lock(mutex);
      ++creates;
      last_create = request;
      response.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
      response.size = sizeof(response);
      response.handle.device_id = next_device_id++;
      response.handle.generation = next_generation++;
      std::fill(
        std::begin(response.handle.session_token),
        std::end(response.handle.session_token),
        static_cast<std::uint8_t>(response.handle.generation)
      );
      if (zero_generation) {
        response.handle.generation = 0;
      }
      if (zero_token) {
        std::fill(std::begin(response.handle.session_token), std::end(response.handle.session_token), 0);
      }
      response.profile = request.profile;
      response.vendor_id = 0x054C;
      response.product_id = 0x0CE6;
      response.version_number = 0x8111;
      response.input_report_id = 1;
      response.input_report_size = 4;
      response.output_report_size = 8;
      last_handle = response.handle;
      return create_result;
    }

    channel_result_t submit(const LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST &request) override {
      std::lock_guard lock(mutex);
      ++submits;
      last_submit = request;
      return submit_result;
    }

    channel_result_t destroy(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) override {
      std::lock_guard lock(mutex);
      ++destroys;
      last_destroy = request;
      return destroy_result;
    }

    channel_result_t read_output(
      const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request,
      LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE &response
    ) override {
      std::lock_guard lock(mutex);
      ++reads;
      if (outputs.empty()) {
        return empty_read_result;
      }
      response = outputs.front();
      outputs.pop_front();
      last_read = request;
      return {};
    }

    channel_result_t reset(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) override {
      std::lock_guard lock(mutex);
      ++resets;
      last_reset = request;
      return reset_result;
    }

    void close() noexcept override {
      std::lock_guard lock(mutex);
      if (opened) {
        ++closes;
      }
      opened = false;
    }

    /**
     * @brief Queue one output response for the session thread.
     *
     * @param response Complete response.
     */
    void push_output(const LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE &response) {
      std::lock_guard lock(mutex);
      outputs.push_back(response);
    }

    std::mutex mutex;  ///< Protects all fake state.
    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE caps {};  ///< Returned capabilities.
    channel_result_t open_result;  ///< Configurable open result.
    channel_result_t capability_result;  ///< Configurable capability result.
    channel_result_t create_result;  ///< Configurable creation result.
    channel_result_t submit_result;  ///< Configurable submit result.
    channel_result_t destroy_result;  ///< Configurable destroy result.
    channel_result_t reset_result;  ///< Configurable reset result.
    channel_result_t empty_read_result {channel_status_e::no_data, 259};  ///< Result when no output is queued.
    std::deque<LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE> outputs;  ///< Queued outputs.
    bool opened {};  ///< Whether open succeeded.
    int opens {};  ///< Open count.
    int creates {};  ///< Create count.
    int submits {};  ///< Submit count.
    int destroys {};  ///< Destroy count.
    int resets {};  ///< Reset count.
    int reads {};  ///< Read count.
    int closes {};  ///< Close count.
    std::uint64_t next_device_id {20};  ///< Next fake driver ID.
    std::uint64_t next_generation {40};  ///< Next fake generation.
    bool zero_generation {};  ///< Whether creation returns an invalid zero generation.
    bool zero_token {};  ///< Whether creation returns an invalid zero token.
    LUMEN_VHID_GAMEPAD_HANDLE last_handle {};  ///< Most recently created handle.
    LUMEN_VHID_GAMEPAD_CREATE_REQUEST last_create {};  ///< Last create request.
    LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST last_submit {};  ///< Last submitted report.
    LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST last_destroy {};  ///< Last destroy request.
    LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST last_reset {};  ///< Last reset request.
    LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST last_read {};  ///< Last read request.
  };

  /**
   * @brief Construct a valid output response for one device.
   *
   * @param device Session device.
   * @param value First payload byte.
   * @return Complete output response.
   */
  LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE output_for(const session_device_t &device, std::uint8_t value) {
    LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE response {
      .version = LUMEN_VHID_GAMEPAD_ABI_VERSION,
      .size = sizeof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE),
      .handle = device.handle,
      .report_size = 2,
    };
    response.report[0] = value;
    response.report[1] = static_cast<std::uint8_t>(value + 1);
    return response;
  }

  /**
   * @brief Wait until a predicate is true without unbounded blocking.
   *
   * @param predicate Predicate to poll.
   * @return `true` when the predicate became true.
   */
  template<class Predicate>
  bool eventually(Predicate predicate) {
    const auto deadline = std::chrono::steady_clock::now() + 500ms;
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      std::this_thread::yield();
    }
    return predicate();
  }

}  // namespace

TEST(VirtualHidSessionTest, ValidatesCapabilitiesBeforeStartingOutputThread) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize()) << session.failure();
  EXPECT_TRUE(session.available());
  EXPECT_EQ(session.capabilities().version, LUMEN_VHID_GAMEPAD_ABI_VERSION);
  EXPECT_EQ(channel->opens, 1);
}

TEST(VirtualHidSessionTest, NullChannelFailsInitializationAndTearsDownSafely) {
  virtual_hid_session_t session {nullptr};

  EXPECT_FALSE(session.initialize());
  EXPECT_FALSE(session.available());
  EXPECT_NE(session.failure().find("null"), std::string::npos);
}

TEST(VirtualHidSessionTest, RejectsIncompatibleCapabilityContract) {
  auto channel = std::make_shared<fake_channel_t>();
  channel->caps.capability_flags &= ~LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS;
  virtual_hid_session_t session {channel};
  EXPECT_FALSE(session.initialize());
  EXPECT_FALSE(session.available());
  EXPECT_NE(session.failure().find("incompatible"), std::string::npos);
  EXPECT_EQ(channel->closes, 1);
}

TEST(VirtualHidSessionTest, RequiresFeatureReportSupportForModernProfiles) {
  auto channel = std::make_shared<fake_channel_t>();
  channel->caps.capability_flags &= ~LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS;
  virtual_hid_session_t session {channel};

  EXPECT_FALSE(session.initialize());
  EXPECT_FALSE(session.available());
  EXPECT_NE(session.failure().find("incompatible"), std::string::npos);
  EXPECT_EQ(channel->closes, 1);
}

TEST(VirtualHidSessionTest, RejectsZeroReportSizeCapabilities) {
  for (const bool zero_input : {true, false}) {
    auto channel = std::make_shared<fake_channel_t>();
    if (zero_input) {
      channel->caps.max_input_report_size = 0;
    } else {
      channel->caps.max_output_report_size = 0;
    }
    virtual_hid_session_t session {channel};

    EXPECT_FALSE(session.initialize());
    EXPECT_FALSE(session.available());
    EXPECT_NE(session.failure().find("incompatible"), std::string::npos);
  }
}

TEST(VirtualHidSessionTest, RejectsZeroGenerationAndSessionToken) {
  for (const bool zero_generation : {true, false}) {
    auto channel = std::make_shared<fake_channel_t>();
    channel->zero_generation = zero_generation;
    channel->zero_token = !zero_generation;
    virtual_hid_session_t session {channel};
    ASSERT_TRUE(session.initialize());

    const auto created = session.create(10, LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE, {});

    EXPECT_FALSE(created.success);
    EXPECT_TRUE(created.became_visible);
    EXPECT_NE(created.error.find("invalid"), std::string::npos);
    EXPECT_EQ(channel->destroys, 1);
  }
}

TEST(VirtualHidSessionTest, CreatesSubmitsAndDestroysExactAuthenticatedGeneration) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());
  const auto created = session.create(99, LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE, {});
  ASSERT_TRUE(created.success) << created.error;
  EXPECT_EQ(channel->last_create.client_device_id, 99U);
  EXPECT_EQ(channel->last_create.reserved, 0U);

  const std::array<std::uint8_t, 4> report {1, 2, 3, 4};
  EXPECT_TRUE(session.submit(created.device, report));
  EXPECT_EQ(channel->last_submit.report_size, report.size());
  EXPECT_TRUE(std::equal(report.begin(), report.end(), channel->last_submit.report));

  EXPECT_TRUE(session.reset(created.device));
  EXPECT_EQ(channel->last_reset.handle.device_id, created.device.handle.device_id);
  EXPECT_TRUE(session.destroy(created.device));
  EXPECT_EQ(channel->last_destroy.handle.generation, created.device.handle.generation);
  EXPECT_FALSE(session.submit(created.device, report));
}

TEST(VirtualHidSessionTest, RoutesOnlyExactHandleAndRejectsStaleEvents) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());

  std::mutex received_mutex;
  std::vector<std::uint8_t> received;
  const auto created = session.create(
    7,
    LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE,
    [&](const session_device_t &, std::span<const std::uint8_t> report) {
      std::lock_guard lock(received_mutex);
      received.push_back(report.front());
    }
  );
  ASSERT_TRUE(created.success);

  auto stale = output_for(created.device, 10);
  ++stale.handle.generation;
  channel->push_output(stale);
  channel->push_output(output_for(created.device, 20));
  ASSERT_TRUE(eventually([&] {
    std::lock_guard lock(received_mutex);
    return received.size() == 1;
  }));
  std::lock_guard lock(received_mutex);
  ASSERT_EQ(received.size(), 1U);
  EXPECT_EQ(received.front(), 20U);
}

TEST(VirtualHidSessionTest, RejectsZeroLengthOutputAndRoutesTheNextValidReport) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());
  std::atomic_int callbacks {};
  const auto created = session.create(
    11,
    LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE,
    [&](const session_device_t &, std::span<const std::uint8_t>) {
      ++callbacks;
    }
  );
  ASSERT_TRUE(created.success);
  auto empty = output_for(created.device, 1);
  empty.report_size = 0;
  channel->push_output(empty);
  channel->push_output(output_for(created.device, 2));

  ASSERT_TRUE(eventually([&] {
    return callbacks.load() == 1;
  }));
  EXPECT_EQ(callbacks.load(), 1);
  EXPECT_TRUE(session.destroy(created.device));
}

TEST(VirtualHidSessionTest, CallbackExceptionIsObservableAndDestroyStillDrains) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());
  const auto created = session.create(
    12,
    LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE,
    [](const session_device_t &, std::span<const std::uint8_t>) {
      throw std::runtime_error("planned callback failure");
    }
  );
  ASSERT_TRUE(created.success);
  channel->push_output(output_for(created.device, 3));

  ASSERT_TRUE(eventually([&] {
    return session.failure().find("planned callback failure") != std::string::npos;
  }));
  EXPECT_TRUE(session.destroy(created.device));
}

TEST(VirtualHidSessionTest, ConcurrentCreateCannotInvalidateDestroyDrainState) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());
  std::mutex callback_mutex;
  std::condition_variable callback_state;
  bool callback_entered = false;
  bool release_callback = false;
  const auto first = session.create(
    13,
    LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE,
    [&](const session_device_t &, std::span<const std::uint8_t>) {
      std::unique_lock lock(callback_mutex);
      callback_entered = true;
      callback_state.notify_all();
      callback_state.wait(lock, [&] {
        return release_callback;
      });
    }
  );
  ASSERT_TRUE(first.success);
  channel->push_output(output_for(first.device, 4));
  bool entered;
  {
    std::unique_lock lock(callback_mutex);
    entered = callback_state.wait_for(lock, 500ms, [&] {
      return callback_entered;
    });
    if (!entered) {
      release_callback = true;
    }
  }
  callback_state.notify_all();
  ASSERT_TRUE(entered);

  auto destroy = std::async(std::launch::async, [&] {
    return session.destroy(first.device);
  });
  const auto second = session.create(14, LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE, {});
  EXPECT_TRUE(second.success) << second.error;
  {
    std::lock_guard lock(callback_mutex);
    release_callback = true;
  }
  callback_state.notify_all();

  EXPECT_EQ(destroy.wait_for(500ms), std::future_status::ready);
  EXPECT_TRUE(destroy.get());
  if (second.success) {
    EXPECT_TRUE(session.destroy(second.device));
  }
}

TEST(VirtualHidSessionTest, TerminalOutputLossDisablesSessionAndRetryFailsFast) {
  auto channel = std::make_shared<fake_channel_t>();
  channel->empty_read_result = {channel_status_e::closed, 6};
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());
  const auto created = session.create(15, LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE, {});
  ASSERT_TRUE(created.success);

  ASSERT_TRUE(eventually([&] {
    return !session.available();
  }));
  EXPECT_NE(session.failure().find("output channel"), std::string::npos);
  EXPECT_FALSE(session.initialize());
  EXPECT_NE(session.failure().find("cannot be reinitialized"), std::string::npos);
  EXPECT_TRUE(session.destroy(created.device));
}

TEST(VirtualHidSessionTest, DestroyClearsCallbackBeforeLateOutputAndDrains) {
  auto channel = std::make_shared<fake_channel_t>();
  virtual_hid_session_t session {channel};
  ASSERT_TRUE(session.initialize());
  std::atomic_int callbacks {};
  const auto created = session.create(
    8,
    LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE,
    [&](const session_device_t &, std::span<const std::uint8_t>) {
      ++callbacks;
    }
  );
  ASSERT_TRUE(created.success);
  EXPECT_TRUE(session.destroy(created.device));
  int reads_before_late_output;
  {
    std::lock_guard lock(channel->mutex);
    reads_before_late_output = channel->reads;
  }
  channel->push_output(output_for(created.device, 30));
  std::this_thread::yield();
  EXPECT_EQ(callbacks.load(), 0);
  {
    std::lock_guard lock(channel->mutex);
    EXPECT_EQ(channel->reads, reads_before_late_output);
  }
}

TEST(VirtualHidSessionTest, DestructorResetsAndDestroysEveryRemainingDevice) {
  auto channel = std::make_shared<fake_channel_t>();
  {
    virtual_hid_session_t session {channel};
    ASSERT_TRUE(session.initialize());
    ASSERT_TRUE(session.create(9, LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE, {}).success);
  }
  EXPECT_EQ(channel->resets, 1);
  EXPECT_EQ(channel->destroys, 1);
  EXPECT_EQ(channel->closes, 1);
}
