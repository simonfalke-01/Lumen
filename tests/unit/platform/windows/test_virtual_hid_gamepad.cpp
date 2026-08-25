/**
 * @file tests/unit/platform/windows/test_virtual_hid_gamepad.cpp
 * @brief Unit tests for Lumen's dynamic VHF gamepad adapter.
 */

// local includes
#include "src/config.h"
#include "src/platform/windows/virtual_hid_gamepad.h"

// standard includes
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// lib includes
#include <gtest/gtest.h>

namespace {
  using namespace std::chrono_literals;
  using namespace platf;
  using namespace platf::win_gamepad;

  /**
   * @brief Convert a protocol profile to the Lumen profile discriminator.
   *
   * @param profile LUMEN_VHID_GAMEPAD_PROFILE_* value.
   * @return Lumen profile kind.
   */
  profile_kind_e lumen_profile(std::uint32_t profile) {
    switch (profile) {
      case LUMEN_VHID_GAMEPAD_PROFILE_GENERIC:
        return profile_kind_e::generic;
      case LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE:
        return profile_kind_e::xbox_one;
      case LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES:
        return profile_kind_e::xbox_series;
      case LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE:
        return profile_kind_e::dualsense;
      case LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO:
        return profile_kind_e::switch_pro;
      case LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4:
        return profile_kind_e::dualshock4;
      default:
        return profile_kind_e::xbox_360;
    }
  }

  /**
   * @brief Return dynamic ABI feature flags for a portable definition.
   *
   * @param definition Portable profile definition.
   * @return LUMEN_VHID_GAMEPAD_FEATURE_* bitmap.
   */
  std::uint32_t features(const lvh_core::profile_definition_t &definition) {
    std::uint32_t result = 0;
    result |= definition.capabilities.rumble ? LUMEN_VHID_GAMEPAD_FEATURE_RUMBLE : 0;
    result |= definition.capabilities.motion ? LUMEN_VHID_GAMEPAD_FEATURE_MOTION : 0;
    result |= definition.capabilities.touchpad ? LUMEN_VHID_GAMEPAD_FEATURE_TOUCHPAD : 0;
    result |= definition.capabilities.rgb_led ? LUMEN_VHID_GAMEPAD_FEATURE_RGB_LED : 0;
    result |= definition.capabilities.battery ? LUMEN_VHID_GAMEPAD_FEATURE_BATTERY : 0;
    result |= definition.capabilities.adaptive_triggers ? LUMEN_VHID_GAMEPAD_FEATURE_ADAPTIVE_TRIGGERS : 0;
    return result;
  }

  /**
   * @brief Fake driver channel implementing Windows-effective profile metadata.
   */
  class gamepad_channel_fake_t final: public gamepad_channel_t {
  public:
    gamepad_channel_fake_t() {
      caps.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
      caps.size = sizeof(caps);
      caps.base_abi_version = LUMEN_VHID_ABI_VERSION;
      caps.capability_flags =
        LUMEN_VHID_GAMEPAD_CAPABILITY_OUTPUT_REPORTS |
        LUMEN_VHID_GAMEPAD_CAPABILITY_FEATURE_REPORTS |
        LUMEN_VHID_GAMEPAD_CAPABILITY_OWNER_CLEANUP |
        LUMEN_VHID_GAMEPAD_CAPABILITY_SESSION_TOKENS;
      caps.supported_profiles =
        LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_GENERIC) |
        LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_ONE) |
        LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_XBOX_SERIES) |
        LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSENSE) |
        LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_SWITCH_PRO) |
        LUMEN_VHID_GAMEPAD_PROFILE_BIT(LUMEN_VHID_GAMEPAD_PROFILE_DUALSHOCK4);
      caps.max_devices = LUMEN_VHID_MAX_GAMEPADS;
      caps.max_input_report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
      caps.max_output_report_size = LUMEN_VHID_GAMEPAD_MAX_REPORT_SIZE;
    }

    channel_result_t open() override {
      return {};
    }

    channel_result_t capabilities(LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE &response) override {
      response = caps;
      return {};
    }

    channel_result_t create(
      const LUMEN_VHID_GAMEPAD_CREATE_REQUEST &request,
      LUMEN_VHID_GAMEPAD_CREATE_RESPONSE &response
    ) override {
      std::lock_guard lock(mutex);
      const auto profile = lumen_profile(request.profile);
      if (profile == profile_kind_e::xbox_360) {
        return {channel_status_e::failure, 50};
      }
      const auto definition = lvh_core::profile(profile);
      response.version = LUMEN_VHID_GAMEPAD_ABI_VERSION;
      response.size = sizeof(response);
      response.handle.device_id = ++next_device_id;
      response.handle.generation = ++next_generation;
      std::fill(
        std::begin(response.handle.session_token),
        std::end(response.handle.session_token),
        static_cast<std::uint8_t>(response.handle.generation)
      );
      response.profile = request.profile;
      response.feature_flags = features(definition);
      response.vendor_id = definition.vendor_id;
      response.product_id = definition.product_id;
      response.version_number = profile == profile_kind_e::xbox_series ? 0x0509U : definition.version;
      response.input_report_id = definition.report_id;
      response.input_report_size = static_cast<std::uint32_t>(definition.input_size);
      response.output_report_size = static_cast<std::uint32_t>(
        profile == profile_kind_e::generic ? 22U : definition.output_size
      );
      handles[response.handle.device_id] = response.handle;
      last_created = response;
      return {};
    }

    channel_result_t submit(const LUMEN_VHID_GAMEPAD_SUBMIT_REPORT_REQUEST &request) override {
      std::lock_guard lock(mutex);
      submitted.emplace_back(request.report, request.report + request.report_size);
      return submit_result;
    }

    channel_result_t destroy(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request) override {
      std::lock_guard lock(mutex);
      handles.erase(request.handle.device_id);
      ++destroys;
      return {};
    }

    channel_result_t read_output(
      const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &request,
      LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE &response
    ) override {
      std::lock_guard lock(mutex);
      auto &device_outputs = outputs[request.handle.device_id];
      if (device_outputs.empty()) {
        return {channel_status_e::no_data, 259};
      }
      response = device_outputs.front();
      device_outputs.pop_front();
      return {};
    }

    channel_result_t reset(const LUMEN_VHID_GAMEPAD_AUTHENTICATED_REQUEST &) override {
      return {};
    }

    void close() noexcept override {
    }

    /**
     * @brief Queue an output report for the last-created device.
     *
     * @param report Complete raw HID output report.
     * @param stale_generation Whether to deliberately stamp a stale generation.
     */
    void push_output(const std::vector<std::uint8_t> &report, bool stale_generation = false) {
      std::lock_guard lock(mutex);
      LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE response {
        .version = LUMEN_VHID_GAMEPAD_ABI_VERSION,
        .size = sizeof(LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE),
        .handle = last_created.handle,
        .report_size = static_cast<std::uint32_t>(report.size()),
      };
      if (stale_generation) {
        ++response.handle.generation;
      }
      std::copy(report.begin(), report.end(), response.report);
      outputs[last_created.handle.device_id].push_back(response);
    }

    /**
     * @brief Return a copy of the most recent submitted report.
     *
     * @return Complete submitted report.
     */
    std::vector<std::uint8_t> last_report() {
      std::lock_guard lock(mutex);
      return submitted.empty() ? std::vector<std::uint8_t> {} : submitted.back();
    }

    std::mutex mutex;  ///< Protects fake channel state.
    LUMEN_VHID_GAMEPAD_CAPABILITIES_RESPONSE caps {};  ///< Returned capabilities.
    channel_result_t submit_result;  ///< Configurable report result.
    std::uint64_t next_device_id {};  ///< Next device ID.
    std::uint64_t next_generation {};  ///< Next driver generation.
    std::unordered_map<std::uint64_t, LUMEN_VHID_GAMEPAD_HANDLE> handles;  ///< Live handles.
    std::unordered_map<std::uint64_t, std::deque<LUMEN_VHID_GAMEPAD_OUTPUT_RESPONSE>> outputs;  ///< Output queues.
    std::vector<std::vector<std::uint8_t>> submitted;  ///< Accepted input reports.
    LUMEN_VHID_GAMEPAD_CREATE_RESPONSE last_created {};  ///< Last create response.
    int destroys {};  ///< Destroy count.
  };

  /**
   * @brief Session plus fake channel prepared for gamepad creation.
   */
  struct harness_t {
    harness_t():
        channel {std::make_shared<gamepad_channel_fake_t>()},
        session {std::make_shared<virtual_hid_session_t>(channel)} {
      EXPECT_TRUE(session->initialize()) << session->failure();
    }

    std::shared_ptr<gamepad_channel_fake_t> channel;  ///< Fake driver channel.
    std::shared_ptr<virtual_hid_session_t> session;  ///< Validated user-mode session.
  };

  /**
   * @brief Create a mailbox-backed feedback queue for tests.
   *
   * @return Mailbox and typed queue retained together.
   */
  std::pair<safe::mail_t, feedback_queue_t> feedback_queue() {
    auto mail = std::make_shared<safe::mail_raw_t>();
    return {mail, mail->queue<gamepad_feedback_msg_t>("vhid-gamepad-test")};
  }

  /**
   * @brief Wait for a feedback queue item with a short test deadline.
   *
   * @param queue Feedback queue.
   * @return Optional queue item.
   */
  auto pop_feedback(const feedback_queue_t &queue) {
    return queue->pop(500ms);
  }

  /**
   * @brief Create one backend and return the concrete VHF adapter.
   *
   * @param harness Session harness.
   * @param profile Selected profile.
   * @param queue Feedback queue.
   * @param generation Router generation.
   * @return Creation result.
   */
  create_result_t create_gamepad(
    harness_t &harness,
    profile_kind_e profile,
    feedback_queue_t queue = {},
    std::uint64_t generation = 1,
    std::uint32_t input_generation = 0,
    std::uint32_t controller_generation = 0
  ) {
    return virtual_hid_gamepad_t::create(
      harness.session,
      profile,
      {0, 3, input_generation, controller_generation},
      {},
      std::move(queue),
      generation
    );
  }

}  // namespace

TEST(VirtualHidGamepadTest, CreatesAllModernProfilesAndRejectsXbox360) {
  const std::vector<profile_kind_e> profiles {
    profile_kind_e::generic,
    profile_kind_e::xbox_one,
    profile_kind_e::xbox_series,
    profile_kind_e::dualshock4,
    profile_kind_e::dualsense,
    profile_kind_e::switch_pro,
  };
  for (const auto profile : profiles) {
    harness_t harness;
    auto created = create_gamepad(harness, profile);
    ASSERT_TRUE(created) << created.error;
    EXPECT_EQ(created.backend->kind(), backend_kind_e::virtual_hid);
    EXPECT_EQ(created.backend->profile(), profile);
    created.backend->close();
  }

  harness_t harness;
  const auto rejected = create_gamepad(harness, profile_kind_e::xbox_360);
  EXPECT_FALSE(rejected);
  EXPECT_FALSE(rejected.became_visible);
}

TEST(VirtualHidGamepadTest, ValidatesXboxSeriesWindowsEffectiveVersion) {
  harness_t harness;
  auto created = create_gamepad(harness, profile_kind_e::xbox_series);
  ASSERT_TRUE(created) << created.error;
  EXPECT_EQ(harness.channel->last_created.version_number, 0x0509U);
  created.backend->close();
}

TEST(VirtualHidGamepadTest, BackAsTouchpadClickAppliesOnlyToDualShock4) {
  harness_t dualshock4_harness;
  harness_t dualsense_harness;
  auto dualshock4 = create_gamepad(dualshock4_harness, profile_kind_e::dualshock4);
  auto dualsense = create_gamepad(dualsense_harness, profile_kind_e::dualsense);
  ASSERT_TRUE(dualshock4) << dualshock4.error;
  ASSERT_TRUE(dualsense) << dualsense.error;
  auto *dualshock4_gamepad = dynamic_cast<virtual_hid_gamepad_t *>(dualshock4.backend.get());
  auto *dualsense_gamepad = dynamic_cast<virtual_hid_gamepad_t *>(dualsense.backend.get());
  ASSERT_NE(dualshock4_gamepad, nullptr);
  ASSERT_NE(dualsense_gamepad, nullptr);

  const auto previous = config::input.ds4_back_as_touchpad_click;
  config::input.ds4_back_as_touchpad_click = true;
  EXPECT_TRUE(dualshock4_gamepad->update({.buttonFlags = BACK}));
  EXPECT_TRUE(dualsense_gamepad->update({.buttonFlags = BACK}));
  const auto dualshock4_state = dualshock4_gamepad->state_snapshot();
  const auto dualsense_state = dualsense_gamepad->state_snapshot();
  config::input.ds4_back_as_touchpad_click = previous;

  EXPECT_NE(dualshock4_state.buttons & lvh_core::button_bit(lvh_core::button_e::touchpad), 0U);
  EXPECT_EQ(dualsense_state.buttons & lvh_core::button_bit(lvh_core::button_e::touchpad), 0U);
  dualshock4.backend->close();
  dualsense.backend->close();
}

TEST(VirtualHidGamepadTest, OrdinaryUpdatePreservesMotionTouchAndBattery) {
  harness_t harness;
  auto [mail, queue] = feedback_queue();
  auto created = create_gamepad(harness, profile_kind_e::dualsense, queue);
  ASSERT_TRUE(created) << created.error;
  auto *gamepad = dynamic_cast<virtual_hid_gamepad_t *>(created.backend.get());
  ASSERT_NE(gamepad, nullptr);

  // Consume the two motion-report enable messages raised at creation.
  ASSERT_TRUE(pop_feedback(queue));
  ASSERT_TRUE(pop_feedback(queue));
  EXPECT_TRUE(gamepad->motion({.id = {0, 3}, .motionType = LI_MOTION_TYPE_ACCEL, .x = 1, .y = 2, .z = 3}));
  EXPECT_TRUE(gamepad->motion({.id = {0, 3}, .motionType = LI_MOTION_TYPE_GYRO, .x = 4, .y = 5, .z = 6}));
  EXPECT_TRUE(gamepad->touch({.id = {0, 3}, .eventType = LI_TOUCH_EVENT_DOWN, .pointerId = 77, .x = 0.25F, .y = 0.75F}));
  EXPECT_TRUE(gamepad->battery({.id = {0, 3}, .state = LI_BATTERY_STATE_CHARGING, .percentage = 42}));

  EXPECT_TRUE(gamepad->update({.buttonFlags = A | MISC_BUTTON, .lt = 50, .rt = 200, .lsX = -123, .lsY = 456, .rsX = 789, .rsY = -321}));
  const auto state = gamepad->state_snapshot();
  ASSERT_TRUE(state.acceleration);
  EXPECT_FLOAT_EQ(state.acceleration->x, 1.0F);
  ASSERT_TRUE(state.gyroscope);
  EXPECT_FLOAT_EQ(state.gyroscope->z, 6.0F);
  ASSERT_TRUE(state.battery);
  EXPECT_EQ(state.battery->percentage, 42U);
  EXPECT_TRUE(state.touchpad_contacts[0].active);
  EXPECT_FLOAT_EQ(state.touchpad_contacts[0].x, 0.25F);
  EXPECT_NE(state.buttons & lvh_core::button_bit(lvh_core::button_e::a), 0U);
  EXPECT_NE(state.buttons & lvh_core::button_bit(lvh_core::button_e::misc1), 0U);
  created.backend->close();
}

TEST(VirtualHidGamepadTest, GenericWindowsReportInvertsTriggerPolarity) {
  harness_t harness;
  auto created = create_gamepad(harness, profile_kind_e::generic);
  ASSERT_TRUE(created) << created.error;
  ASSERT_TRUE(created.backend->update({.lt = 0, .rt = 255}));
  const auto report = harness.channel->last_report();
  ASSERT_EQ(report.size(), 9U);
  EXPECT_EQ(report[7], 255U);
  EXPECT_EQ(report[8], 0U);
  created.backend->close();
}

TEST(VirtualHidGamepadTest, DeduplicatesParsedRumbleAndRgbFeedback) {
  harness_t harness;
  auto [mail, queue] = feedback_queue();
  auto created = create_gamepad(harness, profile_kind_e::dualshock4, queue, 9, 7, 3);
  ASSERT_TRUE(created) << created.error;
  const auto acceleration = pop_feedback(queue);
  const auto gyroscope = pop_feedback(queue);
  ASSERT_TRUE(acceleration);
  ASSERT_TRUE(gyroscope);
  EXPECT_EQ(acceleration->identity, (gamepad_feedback_id_t {3, 7, 3}));
  EXPECT_EQ(gyroscope->identity, (gamepad_feedback_id_t {3, 7, 3}));

  // DS4 USB output: report 0x05, valid rumble + lightbar flags, motors, RGB.
  std::vector<std::uint8_t> report(32);
  report[0] = 0x05;
  report[1] = 0x03;
  report[4] = 0x22;
  report[5] = 0x44;
  report[6] = 1;
  report[7] = 2;
  report[8] = 3;
  harness.channel->push_output(report);
  harness.channel->push_output(report);

  const auto first = pop_feedback(queue);
  const auto second = pop_feedback(queue);
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);
  EXPECT_EQ(first->type, gamepad_feedback_e::rumble);
  EXPECT_EQ(second->type, gamepad_feedback_e::set_rgb_led);
  EXPECT_EQ(first->identity, (gamepad_feedback_id_t {3, 7, 3}));
  EXPECT_EQ(second->identity, (gamepad_feedback_id_t {3, 7, 3}));
  EXPECT_FALSE(queue->pop(30ms));
  created.backend->close();
}

TEST(VirtualHidGamepadTest, RejectsStaleGenerationOutputBeforeFeedback) {
  harness_t harness;
  auto [mail, queue] = feedback_queue();
  auto created = create_gamepad(harness, profile_kind_e::dualshock4, queue, 11);
  ASSERT_TRUE(created);
  ASSERT_TRUE(pop_feedback(queue));
  ASSERT_TRUE(pop_feedback(queue));
  std::vector<std::uint8_t> report(32);
  report[0] = 0x05;
  report[1] = 0x01;
  report[4] = 0x10;
  report[5] = 0x20;
  harness.channel->push_output(report, true);
  EXPECT_FALSE(queue->pop(50ms));
  created.backend->close();
}

TEST(VirtualHidGamepadTest, GenericPidOutputProducesBoundedRumbleAndDeduplicates) {
  harness_t harness;
  auto [mail, queue] = feedback_queue();
  auto created = create_gamepad(harness, profile_kind_e::generic, queue);
  ASSERT_TRUE(created);

  // Configure effect block 1 as an infinite constant force at full gain.
  std::vector<std::uint8_t> set_effect(22);
  set_effect[0] = 0x11;
  set_effect[1] = 1;
  set_effect[2] = 1;
  set_effect[3] = 0xFF;
  set_effect[4] = 0xFF;
  set_effect[11] = 0xFF;
  std::vector<std::uint8_t> magnitude(22);
  magnitude[0] = 0x15;
  magnitude[1] = 1;
  magnitude[2] = 0x10;
  magnitude[3] = 0x27;
  std::vector<std::uint8_t> start(22);
  start[0] = 0x1A;
  start[1] = 1;
  start[2] = 1;
  start[3] = 1;
  harness.channel->push_output(set_effect);
  harness.channel->push_output(magnitude);
  harness.channel->push_output(start);
  harness.channel->push_output(start);

  bool saw_nonzero = false;
  for (int attempt = 0; attempt < 4; ++attempt) {
    const auto message = queue->pop(200ms);
    if (!message) {
      break;
    }
    ASSERT_EQ(message->type, gamepad_feedback_e::rumble);
    if (message->data.rumble.lowfreq != 0) {
      EXPECT_EQ(message->data.rumble.lowfreq, message->data.rumble.highfreq);
      saw_nonzero = true;
      break;
    }
  }
  EXPECT_TRUE(saw_nonzero);
  created.backend->close();
}
