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
  #include <array>
  #include <cstdint>
  #include <deque>
  #include <memory>
  #include <optional>
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

  /** @brief Expected HID bitmap bit for one Moonlight mouse button. */
  struct virtual_hid_mouse_button_case_t {
    int button;  ///< Moonlight mouse button constant.
    std::uint8_t hid_bit;  ///< Expected HID mouse button bit.
  };

  /** @brief Parameterized fixture covering Virtual HID mouse button mappings. */
  class virtual_hid_mouse_button_test:
      public virtual_hid_input_test,
      public testing::WithParamInterface<virtual_hid_mouse_button_case_t> {};

  /** Complete expected Windows virtual-key to keyboard-page usage map. */
  using expected_keyboard_map_t = std::array<std::optional<std::uint8_t>, 256>;

  /** Complete expected Windows virtual-key to Consumer-page usage map. */
  using expected_consumer_map_t = std::array<std::optional<std::uint16_t>, 256>;

  /**
   * @brief Build the independently specified canonical keyboard-page map.
   * @return Expected usage for every eight-bit Windows virtual key.
   */
  expected_keyboard_map_t expected_keyboard_map() {
    expected_keyboard_map_t expected {};
    for (std::uint16_t key = 'A'; key <= 'Z'; ++key) {
      expected[key] = static_cast<std::uint8_t>(0x04 + key - 'A');
    }
    for (std::uint16_t key = '1'; key <= '9'; ++key) {
      expected[key] = static_cast<std::uint8_t>(0x1E + key - '1');
    }
    expected['0'] = 0x27;
    for (std::uint16_t key = VK_F1; key <= VK_F12; ++key) {
      expected[key] = static_cast<std::uint8_t>(0x3A + key - VK_F1);
    }
    for (std::uint16_t key = VK_F13; key <= VK_F24; ++key) {
      expected[key] = static_cast<std::uint8_t>(0x68 + key - VK_F13);
    }
    for (std::uint16_t key = VK_NUMPAD1; key <= VK_NUMPAD9; ++key) {
      expected[key] = static_cast<std::uint8_t>(0x59 + key - VK_NUMPAD1);
    }

    const auto fixed = std::to_array<std::pair<std::uint16_t, std::uint8_t>>({
      {VK_SHIFT, 0xE1},
      {VK_LSHIFT, 0xE1},
      {VK_RSHIFT, 0xE5},
      {VK_CONTROL, 0xE0},
      {VK_LCONTROL, 0xE0},
      {VK_RCONTROL, 0xE4},
      {VK_MENU, 0xE2},
      {VK_LMENU, 0xE2},
      {VK_RMENU, 0xE6},
      {VK_LWIN, 0xE3},
      {VK_RWIN, 0xE7},
      {VK_RETURN, 0x28},
      {VK_ESCAPE, 0x29},
      {VK_BACK, 0x2A},
      {VK_TAB, 0x2B},
      {VK_SPACE, 0x2C},
      {VK_OEM_MINUS, 0x2D},
      {VK_OEM_PLUS, 0x2E},
      {VK_OEM_4, 0x2F},
      {VK_OEM_6, 0x30},
      {VK_OEM_5, 0x31},
      {VK_OEM_1, 0x33},
      {VK_OEM_7, 0x34},
      {VK_OEM_3, 0x35},
      {VK_OEM_COMMA, 0x36},
      {VK_OEM_PERIOD, 0x37},
      {VK_OEM_2, 0x38},
      {VK_CAPITAL, 0x39},
      {VK_SNAPSHOT, 0x46},
      {VK_SCROLL, 0x47},
      {VK_PAUSE, 0x48},
      {VK_INSERT, 0x49},
      {VK_HOME, 0x4A},
      {VK_PRIOR, 0x4B},
      {VK_DELETE, 0x4C},
      {VK_END, 0x4D},
      {VK_NEXT, 0x4E},
      {VK_RIGHT, 0x4F},
      {VK_LEFT, 0x50},
      {VK_DOWN, 0x51},
      {VK_UP, 0x52},
      {VK_NUMLOCK, 0x53},
      {VK_DIVIDE, 0x54},
      {VK_MULTIPLY, 0x55},
      {VK_SUBTRACT, 0x56},
      {VK_ADD, 0x57},
      {VK_NUMPAD0, 0x62},
      {VK_DECIMAL, 0x63},
      {VK_OEM_102, 0x64},
      {VK_APPS, 0x65},
      {VK_SEPARATOR, 0x9F},
    });
    for (const auto &[key, usage] : fixed) {
      expected[key] = usage;
    }
    return expected;
  }

  /**
   * @brief Build the independently specified canonical Consumer-page map.
   * @return Expected usage for every eight-bit Windows virtual key.
   */
  expected_consumer_map_t expected_consumer_map() {
    expected_consumer_map_t expected {};
    const auto fixed = std::to_array<std::pair<std::uint16_t, std::uint16_t>>({
      {VK_BROWSER_BACK, 0x0224},
      {VK_BROWSER_FORWARD, 0x0225},
      {VK_BROWSER_REFRESH, 0x0227},
      {VK_BROWSER_STOP, 0x0226},
      {VK_BROWSER_SEARCH, 0x0221},
      {VK_BROWSER_FAVORITES, 0x022A},
      {VK_BROWSER_HOME, 0x0223},
      {VK_VOLUME_MUTE, 0x00E2},
      {VK_VOLUME_DOWN, 0x00EA},
      {VK_VOLUME_UP, 0x00E9},
      {VK_MEDIA_NEXT_TRACK, 0x00B5},
      {VK_MEDIA_PREV_TRACK, 0x00B6},
      {VK_MEDIA_STOP, 0x00B7},
      {VK_MEDIA_PLAY_PAUSE, 0x00CD},
      {VK_LAUNCH_MAIL, 0x018A},
      {VK_LAUNCH_MEDIA_SELECT, 0x0183},
      {VK_LAUNCH_APP1, 0x0194},
      {VK_LAUNCH_APP2, 0x0192},
    });
    for (const auto &[key, usage] : fixed) {
      expected[key] = usage;
    }
    return expected;
  }

  /**
   * @brief Store one expected Set 1 scan-code mapping.
   * @param expected Normal and `0xE0`-prefixed scan-code maps.
   * @param scan_code Set 1 scan code, optionally prefixed by `0xE0`.
   * @param usage Expected keyboard-page usage.
   */
  void set_expected_scan_usage(
    std::array<expected_keyboard_map_t, 2> &expected,
    UINT scan_code,
    std::uint8_t usage
  ) {
    const auto prefix_index = (scan_code & 0xFF00U) == 0xE000U ? 1U : 0U;
    expected[prefix_index][scan_code & 0xFFU] = usage;
  }

  /**
   * @brief Build the canonical Set 1 scan-code to keyboard-page usage map.
   * @return Expected maps for unprefixed and `0xE0`-prefixed scan codes.
   */
  std::array<expected_keyboard_map_t, 2> expected_scan_code_map() {
    std::array<expected_keyboard_map_t, 2> expected {};
    const auto fixed = std::to_array<std::pair<UINT, std::uint8_t>>({
      {0x01, 0x29},
      {0x02, 0x1E},
      {0x03, 0x1F},
      {0x04, 0x20},
      {0x05, 0x21},
      {0x06, 0x22},
      {0x07, 0x23},
      {0x08, 0x24},
      {0x09, 0x25},
      {0x0A, 0x26},
      {0x0B, 0x27},
      {0x0C, 0x2D},
      {0x0D, 0x2E},
      {0x0E, 0x2A},
      {0x0F, 0x2B},
      {0x10, 0x14},
      {0x11, 0x1A},
      {0x12, 0x08},
      {0x13, 0x15},
      {0x14, 0x17},
      {0x15, 0x1C},
      {0x16, 0x18},
      {0x17, 0x0C},
      {0x18, 0x12},
      {0x19, 0x13},
      {0x1A, 0x2F},
      {0x1B, 0x30},
      {0x1C, 0x28},
      {0x1D, 0xE0},
      {0x1E, 0x04},
      {0x1F, 0x16},
      {0x20, 0x07},
      {0x21, 0x09},
      {0x22, 0x0A},
      {0x23, 0x0B},
      {0x24, 0x0D},
      {0x25, 0x0E},
      {0x26, 0x0F},
      {0x27, 0x33},
      {0x28, 0x34},
      {0x29, 0x35},
      {0x2A, 0xE1},
      {0x2B, 0x31},
      {0x2C, 0x1D},
      {0x2D, 0x1B},
      {0x2E, 0x06},
      {0x2F, 0x19},
      {0x30, 0x05},
      {0x31, 0x11},
      {0x32, 0x10},
      {0x33, 0x36},
      {0x34, 0x37},
      {0x35, 0x38},
      {0x36, 0xE5},
      {0x37, 0x55},
      {0x38, 0xE2},
      {0x39, 0x2C},
      {0x3A, 0x39},
      {0x3B, 0x3A},
      {0x3C, 0x3B},
      {0x3D, 0x3C},
      {0x3E, 0x3D},
      {0x3F, 0x3E},
      {0x40, 0x3F},
      {0x41, 0x40},
      {0x42, 0x41},
      {0x43, 0x42},
      {0x44, 0x43},
      {0x45, 0x53},
      {0x46, 0x47},
      {0x47, 0x5F},
      {0x48, 0x60},
      {0x49, 0x61},
      {0x4A, 0x56},
      {0x4B, 0x5C},
      {0x4C, 0x5D},
      {0x4D, 0x5E},
      {0x4E, 0x57},
      {0x4F, 0x59},
      {0x50, 0x5A},
      {0x51, 0x5B},
      {0x52, 0x62},
      {0x53, 0x63},
      {0x54, 0x46},
      {0x56, 0x64},
      {0x57, 0x44},
      {0x58, 0x45},
      {0x64, 0x68},
      {0x65, 0x69},
      {0x66, 0x6A},
      {0x67, 0x6B},
      {0x68, 0x6C},
      {0x69, 0x6D},
      {0x6A, 0x6E},
      {0x6B, 0x6F},
      {0x6C, 0x70},
      {0x6D, 0x71},
      {0x6E, 0x72},
      {0x76, 0x73},
      {0xE01C, 0x58},
      {0xE01D, 0xE4},
      {0xE035, 0x54},
      {0xE037, 0x46},
      {0xE038, 0xE6},
      {0xE047, 0x4A},
      {0xE048, 0x52},
      {0xE049, 0x4B},
      {0xE04B, 0x50},
      {0xE04D, 0x4F},
      {0xE04F, 0x4D},
      {0xE050, 0x51},
      {0xE051, 0x4E},
      {0xE052, 0x49},
      {0xE053, 0x4C},
      {0xE05B, 0xE3},
      {0xE05C, 0xE7},
      {0xE05D, 0x65},
    });
    for (const auto &[scan_code, usage] : fixed) {
      set_expected_scan_usage(expected, scan_code, usage);
    }
    return expected;
  }
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

TEST_F(virtual_hid_input_test, ReleasesStoredUsageAfterScancodeSettingChanges) {
  initialize();
  config::input.always_send_scancodes = true;
  ASSERT_TRUE(transport->keyboard('A', false, SS_KBE_FLAG_NON_NORMALIZED));

  config::input.always_send_scancodes = false;
  ASSERT_TRUE(transport->keyboard('A', true, SS_KBE_FLAG_NON_NORMALIZED));

  ASSERT_EQ(channel->submissions.size(), 2);
  const auto &release = channel->submissions.back().report.keyboard;
  EXPECT_EQ(release.modifiers, 0);
  EXPECT_TRUE(std::ranges::all_of(release.key_bitmap, [](std::uint8_t byte) {
    return byte == 0;
  }));
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, TracksNormalizedAndNonNormalizedKeysIndependently) {
  initialize();
  config::input.always_send_scancodes = true;

  ASSERT_TRUE(transport->keyboard('A', false, 0));
  ASSERT_TRUE(transport->keyboard('A', false, SS_KBE_FLAG_NON_NORMALIZED));
  ASSERT_TRUE(transport->keyboard('A', true, 0));
  ASSERT_TRUE(transport->keyboard('A', true, SS_KBE_FLAG_NON_NORMALIZED));

  ASSERT_EQ(channel->submissions.size(), 4);
  EXPECT_TRUE(std::ranges::any_of(channel->submissions[2].report.keyboard.key_bitmap, [](std::uint8_t byte) {
    return byte != 0;
  }));
  EXPECT_TRUE(std::ranges::all_of(channel->submissions[3].report.keyboard.key_bitmap, [](std::uint8_t byte) {
    return byte == 0;
  }));
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

TEST_F(virtual_hid_input_test, RoutesSystemSleepThroughSendInputInsteadOfKeyboardPage) {
  initialize();

  const auto result = transport->keyboard(VK_SLEEP, false, 0);

  ASSERT_TRUE(result);
  EXPECT_TRUE(channel->submissions.empty());
  ASSERT_EQ(fallback_api->submitted.size(), 1);
  EXPECT_EQ(fallback_api->submitted[0].ki.wVk, 0);
  EXPECT_EQ(fallback_api->submitted[0].ki.wScan, 0x5F);
  EXPECT_EQ(fallback_api->submitted[0].ki.dwFlags, KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY);
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

TEST_F(virtual_hid_input_test, TracksFallbackKeysIndependentlyByPacketFlags) {
  initialize();

  ASSERT_TRUE(transport->keyboard(VK_PACKET, false, 0));
  ASSERT_TRUE(transport->keyboard(VK_PACKET, false, SS_KBE_FLAG_NON_NORMALIZED));
  ASSERT_TRUE(transport->keyboard(VK_PACKET, true, 0));
  ASSERT_TRUE(transport->keyboard(VK_PACKET, true, SS_KBE_FLAG_NON_NORMALIZED));

  ASSERT_EQ(fallback_api->submitted.size(), 4);
  EXPECT_EQ(fallback_api->submitted[2].ki.dwFlags, KEYEVENTF_KEYUP);
  EXPECT_EQ(fallback_api->submitted[3].ki.dwFlags, KEYEVENTF_KEYUP);
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

TEST_F(virtual_hid_input_test, BuildsSegmentedRelativeMouseReports) {
  initialize();

  ASSERT_TRUE(transport->move_mouse(40000, -40000));

  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.x, 32767);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.y, -32768);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.x, 7233);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.y, -7232);
}

TEST_F(virtual_hid_input_test, ConvertsWindowsWheelUnitsToVirtualHidDetents) {
  initialize();

  ASSERT_TRUE(transport->vertical_scroll(WHEEL_DELTA));
  ASSERT_TRUE(transport->horizontal_scroll(-2 * WHEEL_DELTA));

  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.vertical_wheel, 1);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.horizontal_wheel, -2);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::virtual_hid);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, AccumulatesFractionalVirtualHidWheelDetents) {
  initialize();

  ASSERT_TRUE(transport->vertical_scroll(40));
  ASSERT_TRUE(transport->vertical_scroll(79));
  ASSERT_TRUE(transport->horizontal_scroll(-30));
  EXPECT_TRUE(channel->submissions.empty());

  ASSERT_TRUE(transport->vertical_scroll(1));
  ASSERT_TRUE(transport->horizontal_scroll(-90));
  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.vertical_wheel, 1);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.horizontal_wheel, -1);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, SegmentsLargeVirtualHidWheelDetents) {
  initialize();

  ASSERT_TRUE(transport->horizontal_scroll(40000 * WHEEL_DELTA));

  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.horizontal_wheel, 32767);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.horizontal_wheel, 7233);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, SegmentsLargeNegativeVirtualHidWheelDetents) {
  initialize();

  ASSERT_TRUE(transport->vertical_scroll(-40000 * WHEEL_DELTA));

  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.vertical_wheel, -32768);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.vertical_wheel, -7232);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, ResetSessionClearsFractionalVirtualHidWheelDetents) {
  initialize();

  ASSERT_TRUE(transport->vertical_scroll(WHEEL_DELTA / 2));
  ASSERT_TRUE(transport->horizontal_scroll(WHEEL_DELTA / 2));
  ASSERT_TRUE(transport->reset_session());
  ASSERT_TRUE(transport->vertical_scroll(WHEEL_DELTA / 2));
  ASSERT_TRUE(transport->horizontal_scroll(WHEEL_DELTA / 2));
  EXPECT_TRUE(channel->submissions.empty());

  ASSERT_TRUE(transport->vertical_scroll(WHEEL_DELTA / 2));
  ASSERT_TRUE(transport->horizontal_scroll(WHEEL_DELTA / 2));
  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.vertical_wheel, 1);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.horizontal_wheel, 1);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, ReplaysAccumulatedWheelUnitsOnlyAfterVirtualHidFallback) {
  initialize();
  channel->submit_results.push_back({false, ERROR_ACCESS_DENIED});

  ASSERT_TRUE(transport->vertical_scroll(40));
  const auto result = transport->vertical_scroll(80);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  ASSERT_EQ(channel->submissions.size(), 1);
  ASSERT_EQ(fallback_api->submitted.size(), 1);
  EXPECT_EQ(fallback_api->submitted[0].mi.dwFlags, MOUSEEVENTF_WHEEL);
  EXPECT_EQ(fallback_api->submitted[0].mi.mouseData, static_cast<DWORD>(WHEEL_DELTA));
}

TEST_F(virtual_hid_input_test, DoesNotReplayWheelAfterAcceptedVirtualHidInputFails) {
  initialize();

  ASSERT_TRUE(transport->vertical_scroll(WHEEL_DELTA));
  channel->submit_results.push_back({false, ERROR_WRITE_FAULT});
  const auto result = transport->vertical_scroll(WHEEL_DELTA);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.completion, platf::win_input::completion_t::ambiguous);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::fail_closed);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_P(virtual_hid_mouse_button_test, MapsPressAndReleaseToHidBitmap) {
  initialize();
  const auto &test_case = GetParam();

  ASSERT_TRUE(transport->mouse_button(test_case.button, false));
  EXPECT_EQ(transport->acknowledged_mouse_buttons(), test_case.hid_bit);
  ASSERT_TRUE(transport->mouse_button(test_case.button, true));

  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].report_kind, LUMEN_VHID_REPORT_KIND_RELATIVE_MOUSE);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.report_id, LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE);
  EXPECT_EQ(channel->submissions[0].report.relative_mouse.buttons, test_case.hid_bit);
  EXPECT_EQ(channel->submissions[1].report.relative_mouse.buttons, 0);
  EXPECT_EQ(transport->acknowledged_mouse_buttons(), 0);
}

INSTANTIATE_TEST_SUITE_P(
  AllButtons,
  virtual_hid_mouse_button_test,
  testing::Values(
    virtual_hid_mouse_button_case_t {BUTTON_LEFT, 0x01},
    virtual_hid_mouse_button_case_t {BUTTON_MIDDLE, 0x04},
    virtual_hid_mouse_button_case_t {BUTTON_RIGHT, 0x02},
    virtual_hid_mouse_button_case_t {BUTTON_X1, 0x08},
    virtual_hid_mouse_button_case_t {BUTTON_X2, 0x10}
  )
);

TEST_F(virtual_hid_input_test, PreservesHeldButtonsAcrossTransitionsAndMovement) {
  initialize();

  ASSERT_TRUE(transport->mouse_button(BUTTON_LEFT, false));
  ASSERT_TRUE(transport->mouse_button(BUTTON_MIDDLE, false));
  ASSERT_TRUE(transport->mouse_button(BUTTON_RIGHT, false));
  ASSERT_TRUE(transport->mouse_button(BUTTON_X1, false));
  ASSERT_TRUE(transport->mouse_button(BUTTON_X2, false));
  ASSERT_TRUE(transport->mouse_button(BUTTON_RIGHT, true));
  ASSERT_TRUE(transport->move_mouse(1, -1));

  ASSERT_EQ(channel->submissions.size(), 7);
  EXPECT_EQ(channel->submissions[4].report.relative_mouse.buttons, 0x1F);
  EXPECT_EQ(channel->submissions[5].report.relative_mouse.buttons, 0x1D);
  EXPECT_EQ(channel->submissions[6].report.relative_mouse.buttons, 0x1D);
  EXPECT_EQ(transport->acknowledged_mouse_buttons(), 0x1D);
}

TEST_F(virtual_hid_input_test, RejectsUnknownMouseButtons) {
  initialize();

  const auto below_range = transport->mouse_button(0, false);
  const auto above_range = transport->mouse_button(BUTTON_X2 + 1, false);

  EXPECT_FALSE(below_range);
  EXPECT_EQ(below_range.completion, platf::win_input::completion_t::rejected);
  EXPECT_EQ(below_range.status, ERROR_INVALID_PARAMETER);
  EXPECT_FALSE(above_range);
  EXPECT_EQ(above_range.completion, platf::win_input::completion_t::rejected);
  EXPECT_EQ(above_range.status, ERROR_INVALID_PARAMETER);
  EXPECT_TRUE(channel->submissions.empty());
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
  EXPECT_FALSE(transport->vertical_scroll(WHEEL_DELTA));
  EXPECT_FALSE(transport->horizontal_scroll(WHEEL_DELTA));
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

TEST_F(virtual_hid_input_test, PacksGraveAndEscapeIntoDistinctBitmapBits) {
  initialize();

  ASSERT_TRUE(transport->keyboard(VK_OEM_3, false, 0));
  ASSERT_EQ(channel->submissions.size(), 1);
  const auto &grave = channel->submissions.back().report.keyboard;
  EXPECT_EQ(grave.key_bitmap[0x35 / 8], 1U << (0x35 % 8));
  EXPECT_EQ(grave.key_bitmap[0x29 / 8], 0);

  ASSERT_TRUE(transport->keyboard(VK_OEM_3, true, 0));
  ASSERT_TRUE(transport->keyboard(VK_ESCAPE, false, 0));
  ASSERT_EQ(channel->submissions.size(), 3);
  const auto &escape = channel->submissions.back().report.keyboard;
  EXPECT_EQ(escape.key_bitmap[0x29 / 8], 1U << (0x29 % 8));
  EXPECT_EQ(escape.key_bitmap[0x35 / 8], 0);
}

TEST(VirtualHidKeyMappingTest, MapsEveryVirtualKeyToCanonicalKeyboardUsage) {
  const auto expected = expected_keyboard_map();

  for (std::uint16_t key = 0; key < expected.size(); ++key) {
    SCOPED_TRACE(testing::Message() << "virtual key 0x" << std::hex << key);
    EXPECT_EQ(platf::win_input::map_key_to_hid_usage(key, 0, false), expected[key]);
  }

  EXPECT_EQ(expected[VK_OEM_3], 0x35);
  EXPECT_EQ(expected[VK_ESCAPE], 0x29);
  EXPECT_FALSE(expected[VK_SLEEP]);
}

TEST(VirtualHidKeyMappingTest, MapsEveryVirtualKeyToCanonicalConsumerUsage) {
  const auto expected = expected_consumer_map();

  for (std::uint16_t key = 0; key < expected.size(); ++key) {
    SCOPED_TRACE(testing::Message() << "virtual key 0x" << std::hex << key);
    EXPECT_EQ(platf::win_input::map_key_to_consumer_usage(key), expected[key]);
  }
}

TEST(VirtualHidKeyMappingTest, MapsEverySet1ScanCodeToCanonicalKeyboardUsage) {
  const auto expected = expected_scan_code_map();

  for (UINT code = 0; code <= 0xFFU; ++code) {
    SCOPED_TRACE(testing::Message() << "Set 1 scan code 0x" << std::hex << code);
    EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(code), expected[0][code]);
    EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0xE000U | code), expected[1][code]);
    EXPECT_FALSE(platf::win_input::map_scan_code_to_hid_usage(0xE100U | code));
  }

  EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0x29), 0x35);
  EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0x01), 0x29);
  EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0x35), 0x38);
  EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0xE035), 0x54);
  EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0x52), 0x62);
  EXPECT_EQ(platf::win_input::map_scan_code_to_hid_usage(0xE052), 0x49);
  EXPECT_FALSE(platf::win_input::map_scan_code_to_hid_usage(0x01E029));
}

TEST(VirtualHidKeyMappingTest, RejectsNonNormalizedKeysUnlessScancodeMappingIsEnabled) {
  EXPECT_FALSE(platf::win_input::map_key_to_hid_usage('A', SS_KBE_FLAG_NON_NORMALIZED, false));
}

#else
TEST(VirtualHidInputTest, IsWindowsOnly) {
  GTEST_SKIP() << "Windows Virtual HID transport is not available on this platform";
}
#endif
