/**
 * @file tests/unit/platform/windows/test_input_transport.cpp
 * @brief Test the Windows SendInput keyboard and mouse transport seam.
 */
#include <gtest/gtest.h>

#ifdef _WIN32
  // local includes
  #include <src/config.h>
  #include <src/platform/windows/input_transport.h>

  // standard includes
  #include <cstdint>
  #include <memory>
  #include <string_view>
  #include <utility>
  #include <vector>

  // moonlight-common-c includes
  #include <moonlight-common-c/src/Input.h>
  #include <moonlight-common-c/src/Limelight.h>

namespace {
  /**
   * @brief Fake Win32 input surface that records submitted input structures.
   */
  class fake_win32_api_t final: public platf::win_input::win32_api_t {
  public:
    UINT send_input(UINT count, INPUT *inputs, int size) override {
      counts.push_back(count);
      sizes.push_back(size);
      submitted.insert(submitted.end(), inputs, inputs + count);

      if (next_send_result < send_results.size()) {
        return send_results[next_send_result++];
      }
      return count;
    }

    HDESK sync_thread_desktop() override {
      ++sync_calls;
      if (next_desktop < desktops.size()) {
        return desktops[next_desktop++];
      }
      return desktop;
    }

    DWORD last_error() override {
      ++last_error_calls;
      return error;
    }

    std::vector<INPUT> submitted;
    std::vector<UINT> counts;
    std::vector<int> sizes;
    std::vector<UINT> send_results;
    std::vector<HDESK> desktops;
    std::size_t next_send_result {0};
    std::size_t next_desktop {0};
    HDESK desktop {reinterpret_cast<HDESK>(static_cast<std::uintptr_t>(1))};
    DWORD error {ERROR_ACCESS_DENIED};
    int sync_calls {0};
    int last_error_calls {0};
  };

  /**
   * @brief Test fixture preserving the process-wide keyboard mapping option.
   */
  class send_input_transport_test: public testing::Test {
  protected:
    void SetUp() override {
      saved_always_send_scancodes_ = config::input.always_send_scancodes;
      api = std::make_shared<fake_win32_api_t>();
      transport = std::make_unique<platf::win_input::send_input_transport_t>(api);
    }

    void TearDown() override {
      config::input.always_send_scancodes = saved_always_send_scancodes_;
      transport.reset();
      api.reset();
    }

    std::shared_ptr<fake_win32_api_t> api;
    std::unique_ptr<platf::win_input::send_input_transport_t> transport;

  private:
    bool saved_always_send_scancodes_ {false};
  };

  /**
   * @brief Expected mapping for one Moonlight mouse button transition.
   */
  struct mouse_button_case_t {
    int button;  ///< Moonlight mouse button number.
    bool release;  ///< Whether the transition releases the button.
    DWORD flags;  ///< Expected Win32 mouse flags.
    DWORD data;  ///< Expected Win32 mouse data.
  };

  /**
   * @brief Parameterized fixture for mouse button mappings.
   */
  class send_input_mouse_button_test:
      public send_input_transport_test,
      public testing::WithParamInterface<mouse_button_case_t> {};
}  // namespace

TEST_F(send_input_transport_test, ReportsSendInputBackend) {
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
}

TEST_F(send_input_transport_test, BuildsRelativeMouseInput) {
  const auto result = transport->move_mouse(-123, 456);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_MOUSE);
  EXPECT_EQ(input.mi.dx, -123);
  EXPECT_EQ(input.mi.dy, 456);
  EXPECT_EQ(input.mi.mouseData, 0);
  EXPECT_EQ(input.mi.dwFlags, MOUSEEVENTF_MOVE);
  EXPECT_EQ(input.mi.time, 0);
  EXPECT_EQ(input.mi.dwExtraInfo, 0);
  EXPECT_EQ(api->counts.front(), 1);
  EXPECT_EQ(api->sizes.front(), sizeof(INPUT));
}

TEST_F(send_input_transport_test, BuildsZeroRelativeMouseInput) {
  const auto result = transport->move_mouse(0, 0);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  EXPECT_EQ(api->submitted.front().mi.dx, 0);
  EXPECT_EQ(api->submitted.front().mi.dy, 0);
  EXPECT_EQ(api->submitted.front().mi.dwFlags, MOUSEEVENTF_MOVE);
}

TEST_F(send_input_transport_test, BuildsAbsoluteVirtualDesktopMouseInput) {
  const auto result = transport->absolute_mouse(50.0f, 25.0f, 100, 100);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_MOUSE);
  EXPECT_EQ(input.mi.dx, 32768);
  EXPECT_EQ(input.mi.dy, 16384);
  EXPECT_EQ(input.mi.mouseData, 0);
  EXPECT_EQ(input.mi.dwFlags, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
}

TEST_F(send_input_transport_test, BuildsAbsoluteMouseEndpointInput) {
  const auto result = transport->absolute_mouse(1920.0f, 1080.0f, 1920, 1080);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  EXPECT_EQ(api->submitted.front().mi.dx, 65535);
  EXPECT_EQ(api->submitted.front().mi.dy, 65535);
}

TEST_F(send_input_transport_test, RejectsAbsoluteMouseInputWithInvalidSourceSize) {
  const auto result = transport->absolute_mouse(1.0f, 1.0f, 0, 1080);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.completion, platf::win_input::completion_t::rejected);
  EXPECT_EQ(result.status, ERROR_INVALID_PARAMETER);
  EXPECT_TRUE(api->submitted.empty());
}

TEST_P(send_input_mouse_button_test, BuildsMouseButtonInput) {
  const auto &test_case = GetParam();

  const auto result = transport->mouse_button(test_case.button, test_case.release);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_MOUSE);
  EXPECT_EQ(input.mi.dx, 0);
  EXPECT_EQ(input.mi.dy, 0);
  EXPECT_EQ(input.mi.dwFlags, test_case.flags);
  EXPECT_EQ(input.mi.mouseData, test_case.data);
}

INSTANTIATE_TEST_SUITE_P(
  AllButtons,
  send_input_mouse_button_test,
  testing::Values(
    mouse_button_case_t {1, false, MOUSEEVENTF_LEFTDOWN, 0},
    mouse_button_case_t {1, true, MOUSEEVENTF_LEFTUP, 0},
    mouse_button_case_t {2, false, MOUSEEVENTF_MIDDLEDOWN, 0},
    mouse_button_case_t {2, true, MOUSEEVENTF_MIDDLEUP, 0},
    mouse_button_case_t {3, false, MOUSEEVENTF_RIGHTDOWN, 0},
    mouse_button_case_t {3, true, MOUSEEVENTF_RIGHTUP, 0},
    mouse_button_case_t {4, false, MOUSEEVENTF_XDOWN, XBUTTON1},
    mouse_button_case_t {4, true, MOUSEEVENTF_XUP, XBUTTON1},
    mouse_button_case_t {5, false, MOUSEEVENTF_XDOWN, XBUTTON2},
    mouse_button_case_t {5, true, MOUSEEVENTF_XUP, XBUTTON2}
  )
);

TEST_F(send_input_transport_test, RejectsUnknownMouseButton) {
  const auto result = transport->mouse_button(6, false);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.status, ERROR_INVALID_PARAMETER);
  EXPECT_TRUE(api->submitted.empty());
}

TEST_F(send_input_transport_test, BuildsVerticalWheelInput) {
  const auto result = transport->vertical_scroll(-240);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_MOUSE);
  EXPECT_EQ(input.mi.dwFlags, MOUSEEVENTF_WHEEL);
  EXPECT_EQ(input.mi.mouseData, static_cast<DWORD>(-240));
}

TEST_F(send_input_transport_test, BuildsHorizontalWheelInput) {
  const auto result = transport->horizontal_scroll(37);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_MOUSE);
  EXPECT_EQ(input.mi.dwFlags, MOUSEEVENTF_HWHEEL);
  EXPECT_EQ(input.mi.mouseData, 37);
}

TEST_F(send_input_transport_test, BuildsNormalizedKeyboardScancodeInput) {
  config::input.always_send_scancodes = false;

  const auto result = transport->keyboard('A', false, 0);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_KEYBOARD);
  EXPECT_EQ(input.ki.wVk, 0);
  EXPECT_EQ(input.ki.wScan, 0x1E);
  EXPECT_EQ(input.ki.dwFlags, KEYEVENTF_SCANCODE);
}

TEST_F(send_input_transport_test, BuildsNonNormalizedVirtualKeyInput) {
  config::input.always_send_scancodes = false;

  const auto result = transport->keyboard('A', false, SS_KBE_FLAG_NON_NORMALIZED);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.type, INPUT_KEYBOARD);
  EXPECT_EQ(input.ki.wVk, 'A');
  EXPECT_EQ(input.ki.wScan, 0);
  EXPECT_EQ(input.ki.dwFlags, 0);
}

TEST_F(send_input_transport_test, BuildsAlwaysScancodeKeyboardInput) {
  config::input.always_send_scancodes = true;

  const auto result = transport->keyboard('A', false, SS_KBE_FLAG_NON_NORMALIZED);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.ki.wVk, 0);
  EXPECT_EQ(input.ki.wScan, MapVirtualKey('A', MAPVK_VK_TO_VSC));
  EXPECT_EQ(input.ki.dwFlags, KEYEVENTF_SCANCODE);
}

TEST_F(send_input_transport_test, BuildsExtendedKeyboardReleaseInput) {
  const auto result = transport->keyboard(VK_RCONTROL, true, 0);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.ki.wVk, 0);
  EXPECT_EQ(input.ki.wScan, 0x1D);
  EXPECT_EQ(input.ki.dwFlags, KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP);
}

TEST_F(send_input_transport_test, KeepsPauseAsVirtualKeyWhenAlwaysScancodesEnabled) {
  config::input.always_send_scancodes = true;

  const auto result = transport->keyboard(VK_PAUSE, false, SS_KBE_FLAG_NON_NORMALIZED);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 1);
  const auto &input = api->submitted.front();
  EXPECT_EQ(input.ki.wVk, VK_PAUSE);
  EXPECT_EQ(input.ki.wScan, 0);
  EXPECT_EQ(input.ki.dwFlags, 0);
}

TEST_F(send_input_transport_test, BuildsUnicodeDownThenUpInputs) {
  constexpr std::string_view utf8 {"\xC3\xA9"};

  const auto result = transport->unicode(utf8.data(), static_cast<int>(utf8.size()));

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 2);
  EXPECT_EQ(api->submitted[0].type, INPUT_KEYBOARD);
  EXPECT_EQ(api->submitted[0].ki.wVk, 0);
  EXPECT_EQ(api->submitted[0].ki.wScan, L'\u00E9');
  EXPECT_EQ(api->submitted[0].ki.dwFlags, KEYEVENTF_UNICODE);
  EXPECT_EQ(api->submitted[1].type, INPUT_KEYBOARD);
  EXPECT_EQ(api->submitted[1].ki.wVk, 0);
  EXPECT_EQ(api->submitted[1].ki.wScan, L'\u00E9');
  EXPECT_EQ(api->submitted[1].ki.dwFlags, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
}

TEST_F(send_input_transport_test, RejectsInvalidUnicodeInput) {
  const auto result = transport->unicode(nullptr, 0);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.status, ERROR_INVALID_PARAMETER);
  EXPECT_TRUE(api->submitted.empty());
}

TEST_F(send_input_transport_test, RetriesAfterInputDesktopChanges) {
  api->send_results = {0, 1};
  api->desktop = reinterpret_cast<HDESK>(static_cast<std::uintptr_t>(2));

  const auto result = transport->move_mouse(5, -7);

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 2);
  EXPECT_EQ(api->sync_calls, 1);
  EXPECT_EQ(api->last_error_calls, 1);
  EXPECT_EQ(api->submitted[0].mi.dx, api->submitted[1].mi.dx);
  EXPECT_EQ(api->submitted[0].mi.dy, api->submitted[1].mi.dy);
  EXPECT_EQ(api->submitted[0].mi.dwFlags, api->submitted[1].mi.dwFlags);
}

TEST_F(send_input_transport_test, DoesNotRetryAgainOnUnchangedInputDesktop) {
  api->send_results = {0, 1, 0};
  api->desktop = reinterpret_cast<HDESK>(static_cast<std::uintptr_t>(3));
  ASSERT_TRUE(transport->move_mouse(1, 2));

  const auto result = transport->move_mouse(3, 4);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.completion, platf::win_input::completion_t::rejected);
  EXPECT_EQ(result.status, ERROR_ACCESS_DENIED);
  EXPECT_EQ(api->submitted.size(), 3);
  EXPECT_EQ(api->sync_calls, 2);
}

TEST_F(send_input_transport_test, NeutralizeReleasesHeldKey) {
  ASSERT_TRUE(transport->keyboard('A', false, 0));

  const auto result = transport->neutralize();

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 2);
  EXPECT_EQ(api->submitted[1].type, INPUT_KEYBOARD);
  EXPECT_EQ(api->submitted[1].ki.wScan, 0x1E);
  EXPECT_EQ(api->submitted[1].ki.dwFlags, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP);
}

TEST_F(send_input_transport_test, NeutralizeReleasesHeldMouseButton) {
  ASSERT_TRUE(transport->mouse_button(5, false));

  const auto result = transport->neutralize();

  ASSERT_TRUE(result);
  ASSERT_EQ(api->submitted.size(), 2);
  EXPECT_EQ(api->submitted[1].type, INPUT_MOUSE);
  EXPECT_EQ(api->submitted[1].mi.dwFlags, MOUSEEVENTF_XUP);
  EXPECT_EQ(api->submitted[1].mi.mouseData, XBUTTON2);
}

TEST_F(send_input_transport_test, NeutralizeIsIdempotent) {
  ASSERT_TRUE(transport->mouse_button(1, false));
  ASSERT_TRUE(transport->neutralize());
  const auto submissions_after_first_neutralize = api->submitted.size();

  const auto result = transport->neutralize();

  EXPECT_TRUE(result);
  EXPECT_EQ(api->submitted.size(), submissions_after_first_neutralize);
}

#else
TEST(InputTransportTest, IsWindowsOnly) {
  GTEST_SKIP() << "Windows SendInput transport is not available on this platform";
}
#endif
