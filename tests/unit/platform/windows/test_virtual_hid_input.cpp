/**
 * @file tests/unit/platform/windows/test_virtual_hid_input.cpp
 * @brief Test the lean Windows Virtual HID transport with injectable fakes.
 */
#include <gtest/gtest.h>

#ifdef _WIN32
  // local includes
  #include <src/config.h>
  #include <src/platform/windows/virtual_hid_input.h>

  // standard includes
  #include <algorithm>
  #include <cstdint>
  #include <deque>
  #include <memory>
  #include <utility>
  #include <vector>

  // moonlight-common-c includes
  #include <moonlight-common-c/src/Input.h>
  #include <moonlight-common-c/src/Limelight.h>

namespace {
  using platf::win_input::channel_result_t;

  /** @brief Fake SendInput surface recording every auxiliary submission. */
  class fake_win32_api_t final: public platf::win_input::win32_api_t {
  public:
    UINT send_input(UINT count, INPUT *inputs, int) override {
      submitted.insert(submitted.end(), inputs, inputs + count);
      return count;
    }

    HDESK sync_thread_desktop() override {
      return nullptr;
    }

    DWORD last_error() override {
      return ERROR_ACCESS_DENIED;
    }

    std::vector<INPUT> submitted;  ///< Captured input records.
  };

  /** @brief Fake four-operation driver channel. */
  class fake_virtual_hid_channel_t final: public platf::win_input::virtual_hid_channel_t {
  public:
    channel_result_t open() override {
      ++open_calls;
      return open_result;
    }

    channel_result_t get_info(LUMEN_VHID_GET_INFO_RESPONSE &response) override {
      ++get_info_calls;
      response = info;
      return get_info_result;
    }

    channel_result_t claim() override {
      ++claim_calls;
      return claim_result;
    }

    channel_result_t submit(const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request) override {
      submissions.push_back(request);
      if (!submit_results.empty()) {
        const auto result = submit_results.front();
        submit_results.pop_front();
        return result;
      }
      return {};
    }

    channel_result_t reset_and_release() override {
      ++reset_calls;
      return reset_result;
    }

    void close() noexcept override {
      ++close_calls;
    }

    LUMEN_VHID_GET_INFO_RESPONSE info {LUMEN_VHID_ABI_VERSION, 1};  ///< Default compatible info.
    channel_result_t open_result {};  ///< Open result.
    channel_result_t get_info_result {};  ///< Info result.
    channel_result_t claim_result {};  ///< Claim result.
    channel_result_t reset_result {};  ///< Reset result.
    std::deque<channel_result_t> submit_results;  ///< Ordered submission results.
    std::vector<LUMEN_VHID_SUBMIT_REPORT_REQUEST> submissions;  ///< Captured requests.
    int open_calls {0};  ///< Open calls.
    int get_info_calls {0};  ///< Info calls.
    int claim_calls {0};  ///< Claim calls.
    int reset_calls {0};  ///< Reset calls.
    int close_calls {0};  ///< Close calls.
  };

  /** @brief Fixture preserving process-wide input mapping configuration. */
  class virtual_hid_input_test: public testing::Test {
  protected:
    void SetUp() override {
      saved_always_send_scancodes_ = config::input.always_send_scancodes;
      channel = std::make_shared<fake_virtual_hid_channel_t>();
      fallback_api = std::make_shared<fake_win32_api_t>();
      auto fallback = std::make_unique<platf::win_input::send_input_transport_t>(fallback_api);
      transport = std::make_unique<platf::win_input::virtual_hid_transport_t>(channel, std::move(fallback));
    }

    void TearDown() override {
      transport.reset();
      config::input.always_send_scancodes = saved_always_send_scancodes_;
    }

    /**
     * @brief Initialize the preferred transport.
     */
    void initialize() {
      ASSERT_TRUE(transport->initialize());
      ASSERT_EQ(transport->backend(), platf::win_input::backend_t::virtual_hid);
    }

    std::shared_ptr<fake_virtual_hid_channel_t> channel;  ///< Fake driver channel.
    std::shared_ptr<fake_win32_api_t> fallback_api;  ///< Fake SendInput surface.
    std::unique_ptr<platf::win_input::virtual_hid_transport_t> transport;  ///< Subject.

  private:
    bool saved_always_send_scancodes_ {false};  ///< Restored mapping setting.
  };
}  // namespace

TEST_F(virtual_hid_input_test, InitializesThroughExactLeanOperations) {
  initialize();

  EXPECT_EQ(channel->open_calls, 1);
  EXPECT_EQ(channel->get_info_calls, 1);
  EXPECT_EQ(channel->claim_calls, 1);
  EXPECT_TRUE(channel->submissions.empty());
}

TEST_F(virtual_hid_input_test, FallsBackWhenOpenFails) {
  channel->open_result = {false, ERROR_ACCESS_DENIED};

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "interface discovery/open");
  EXPECT_EQ(channel->get_info_calls, 0);
}

TEST_F(virtual_hid_input_test, FallsBackForWrongAbiOrUnreadyDriver) {
  channel->info.abi_version = LUMEN_VHID_ABI_VERSION + 1;
  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->failure_stage(), "driver info");

  transport.reset();
  channel = std::make_shared<fake_virtual_hid_channel_t>();
  channel->info.ready = 0;
  auto fallback = std::make_unique<platf::win_input::send_input_transport_t>(fallback_api);
  transport = std::make_unique<platf::win_input::virtual_hid_transport_t>(channel, std::move(fallback));
  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
}

TEST_F(virtual_hid_input_test, FallsBackWhenClaimFails) {
  channel->claim_result = {false, ERROR_SHARING_VIOLATION};

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "exclusive claim");
}

TEST_F(virtual_hid_input_test, BuildsCompleteNkroKeyboardSnapshots) {
  initialize();

  ASSERT_TRUE(transport->keyboard('A', false, 0));
  ASSERT_TRUE(transport->keyboard(VK_RCONTROL, false, 0));
  ASSERT_TRUE(transport->keyboard('A', true, 0));

  ASSERT_EQ(channel->submissions.size(), 3);
  const auto &press = channel->submissions[1];
  EXPECT_EQ(press.report_kind, LUMEN_VHID_REPORT_KIND_KEYBOARD);
  EXPECT_EQ(press.report.keyboard.report_id, LUMEN_VHID_REPORT_ID_KEYBOARD);
  EXPECT_NE(press.report.keyboard.key_bitmap[0], 0);
  EXPECT_EQ(press.report.keyboard.modifiers, 1U << 4);
  const auto &release = channel->submissions[2].report.keyboard;
  EXPECT_TRUE(std::ranges::all_of(release.key_bitmap, [](std::uint8_t byte) {
    return byte == 0;
  }));
  EXPECT_EQ(release.modifiers, 1U << 4);
}

TEST_F(virtual_hid_input_test, MapsCommonMediaKeyThroughConsumerControl) {
  initialize();

  ASSERT_TRUE(transport->keyboard(VK_VOLUME_UP, false, 0));
  ASSERT_TRUE(transport->keyboard(VK_VOLUME_UP, true, 0));

  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report_kind, LUMEN_VHID_REPORT_KIND_CONSUMER);
  EXPECT_EQ(channel->submissions[0].report.consumer.report_id, LUMEN_VHID_REPORT_ID_CONSUMER);
  EXPECT_EQ(channel->submissions[0].report.consumer.usages[0], 0x00E9);
  EXPECT_EQ(channel->submissions[1].report.consumer.usages[0], 0);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, UsesPerKeySendInputForUnsupportedKeyWhileHealthy) {
  initialize();

  const auto result = transport->keyboard(VK_PACKET, false, 0);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::virtual_hid);
  EXPECT_TRUE(channel->submissions.empty());
  ASSERT_EQ(fallback_api->submitted.size(), 1);
  EXPECT_EQ(fallback_api->submitted[0].ki.wVk, VK_PACKET);
}

TEST_F(virtual_hid_input_test, RoutesMatchingUnsupportedReleaseThroughSendInput) {
  initialize();

  ASSERT_TRUE(transport->keyboard(VK_PACKET, false, 0));

  const auto result = transport->keyboard(VK_PACKET, true, 0);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::virtual_hid);
  EXPECT_TRUE(channel->submissions.empty());
  ASSERT_EQ(fallback_api->submitted.size(), 2);
  EXPECT_EQ(fallback_api->submitted[1].ki.dwFlags, KEYEVENTF_KEYUP);
}

TEST_F(virtual_hid_input_test, RoutesAbsoluteMouseAndUnicodeThroughSendInputWhileHealthy) {
  initialize();

  ASSERT_TRUE(transport->absolute_mouse(50.0f, 25.0f, 100, 100));
  constexpr char utf8[] = "\xC3\xA9";
  ASSERT_TRUE(transport->unicode(utf8, 2));

  EXPECT_TRUE(channel->submissions.empty());
  ASSERT_EQ(fallback_api->submitted.size(), 3);
  EXPECT_EQ(fallback_api->submitted[0].type, INPUT_MOUSE);
  EXPECT_EQ(fallback_api->submitted[0].mi.dwFlags, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
  EXPECT_EQ(fallback_api->submitted[1].ki.dwFlags, KEYEVENTF_UNICODE);
  EXPECT_EQ(fallback_api->submitted[2].ki.dwFlags, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
}

TEST_F(virtual_hid_input_test, BuildsSegmentedRelativeMouseAndWheelReports) {
  initialize();

  ASSERT_TRUE(transport->move_mouse(40000, -40000));
  ASSERT_TRUE(transport->horizontal_scroll(40000));

  ASSERT_EQ(channel->submissions.size(), 4);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.x, 32767);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.y, -32768);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.x, 7233);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.y, -7232);
  EXPECT_EQ(channel->submissions[2].report.relative_mouse.horizontal_wheel, 32767);
  EXPECT_EQ(channel->submissions[3].report.relative_mouse.horizontal_wheel, 7233);
}

TEST_F(virtual_hid_input_test, FallsBackWhenFirstVirtualReportIsRejected) {
  initialize();
  channel->submit_results.push_back({false, ERROR_WRITE_FAULT});

  const auto result = transport->move_mouse(5, -7);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  ASSERT_EQ(fallback_api->submitted.size(), 1);
  EXPECT_EQ(fallback_api->submitted[0].mi.dx, 5);
  EXPECT_EQ(fallback_api->submitted[0].mi.dy, -7);
}

TEST_F(virtual_hid_input_test, FailsClosedAfterAnyAcceptedVirtualReport) {
  initialize();
  ASSERT_TRUE(transport->keyboard('A', false, 0));
  channel->submit_results.push_back({false, ERROR_WRITE_FAULT});

  const auto failed = transport->move_mouse(1, 2);

  EXPECT_FALSE(failed);
  EXPECT_EQ(failed.completion, platf::win_input::completion_t::ambiguous);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::fail_closed);
  EXPECT_TRUE(fallback_api->submitted.empty());
  EXPECT_FALSE(transport->absolute_mouse(1, 1, 100, 100));
  EXPECT_FALSE(transport->unicode("a", 1));
  EXPECT_FALSE(transport->keyboard(VK_PACKET, false, 0));
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, ResetRecoversFailClosedTransportWithoutReplay) {
  initialize();
  ASSERT_TRUE(transport->keyboard('A', false, 0));
  ASSERT_TRUE(transport->mouse_button(1, false));
  channel->submit_results.push_back({false, ERROR_WRITE_FAULT});
  ASSERT_FALSE(transport->move_mouse(1, 2));

  const auto result = transport->reset_session();

  ASSERT_TRUE(result);
  EXPECT_EQ(channel->reset_calls, 1);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_TRUE(fallback_api->submitted.empty());
  ASSERT_TRUE(transport->move_mouse(3, 4));
  ASSERT_EQ(fallback_api->submitted.size(), 1);
  EXPECT_EQ(fallback_api->submitted[0].mi.dx, 3);
}

TEST_F(virtual_hid_input_test, ResetFailureKeepsTransportFailClosed) {
  initialize();
  ASSERT_TRUE(transport->keyboard('A', false, 0));
  channel->submit_results.push_back({false, ERROR_WRITE_FAULT});
  ASSERT_FALSE(transport->move_mouse(1, 2));
  channel->reset_result = {false, ERROR_TIMEOUT};

  const auto result = transport->reset_session();

  EXPECT_FALSE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::fail_closed);
  EXPECT_EQ(transport->failure_stage(), "reset and release");
}

TEST(VirtualHidKeyMappingTest, MapsAndRejectsExpectedKeys) {
  EXPECT_EQ(platf::win_input::map_key_to_hid_usage('A', 0, false), 0x04);
  EXPECT_EQ(platf::win_input::map_key_to_hid_usage(VK_RCONTROL, 0, false), 0xE4);
  EXPECT_FALSE(platf::win_input::map_key_to_hid_usage(VK_PACKET, 0, false));
  EXPECT_FALSE(platf::win_input::map_key_to_hid_usage('A', SS_KBE_FLAG_NON_NORMALIZED, false));
}

#else
TEST(VirtualHidInputTest, IsWindowsOnly) {
  GTEST_SKIP() << "Windows Virtual HID transport is not available on this platform";
}
#endif
