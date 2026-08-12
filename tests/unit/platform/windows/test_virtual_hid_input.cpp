/**
 * @file tests/unit/platform/windows/test_virtual_hid_input.cpp
 * @brief Test the Windows Virtual HID transport with host-independent fakes.
 */
#include <gtest/gtest.h>

#ifdef _WIN32
  // local includes
  #include <src/platform/windows/virtual_hid_input.h>

  // standard includes
  #include <algorithm>
  #include <array>
  #include <bit>
  #include <cstdint>
  #include <cstring>
  #include <limits>
  #include <memory>
  #include <optional>
  #include <string>
  #include <utility>
  #include <vector>

  // moonlight-common-c includes
  #include <moonlight-common-c/src/Input.h>
  #include <moonlight-common-c/src/Limelight.h>

namespace {
  using platf::win_input::channel_completion_t;
  using platf::win_input::channel_result_t;

  constexpr std::uint64_t initial_session_token = UINT64_C(0x1122334455667788);
  constexpr std::uint64_t reset_session_token = UINT64_C(0x8877665544332211);

  /**
   * @brief Build a valid fixed-size protocol response header.
   *
   * @param operation Protocol operation identifier.
   * @param size Complete response structure size.
   * @return Populated response header.
   */
  LUMEN_VHID_MESSAGE_HEADER response_header(std::uint16_t operation, std::size_t size) {
    return {
      LUMEN_VHID_PROTOCOL_MAGIC,
      LUMEN_VHID_PROTOCOL_MAJOR,
      LUMEN_VHID_PROTOCOL_MINOR,
      sizeof(LUMEN_VHID_MESSAGE_HEADER),
      operation,
      static_cast<std::uint32_t>(size),
      0
    };
  }

  /**
   * @brief Win32 fake used to observe all fallback input records.
   */
  class recording_win32_api_t final: public platf::win_input::win32_api_t {
  public:
    /**
     * @brief Construct a recorder sharing an optional cross-backend trace.
     * @param trace Cross-backend operation trace.
     */
    explicit recording_win32_api_t(std::shared_ptr<std::vector<std::string>> trace):
        trace_(std::move(trace)) {
    }

    UINT send_input(UINT count, INPUT *inputs, int size) override {
      trace_->emplace_back("fallback submit");
      submitted.insert(submitted.end(), inputs, inputs + count);
      sizes.push_back(size);
      return count;
    }

    HDESK sync_thread_desktop() override {
      return reinterpret_cast<HDESK>(static_cast<std::uintptr_t>(1));
    }

    DWORD last_error() override {
      return ERROR_SUCCESS;
    }

    std::vector<INPUT> submitted;
    std::vector<int> sizes;

  private:
    std::shared_ptr<std::vector<std::string>> trace_;
  };

  /**
   * @brief Virtual HID channel fake that emits valid responses by default.
   */
  class fake_virtual_hid_channel_t final: public platf::win_input::virtual_hid_channel_t {
  public:
    /**
     * @brief Construct a fake sharing a cross-backend operation trace.
     * @param trace Cross-backend operation trace.
     */
    explicit fake_virtual_hid_channel_t(std::shared_ptr<std::vector<std::string>> trace):
        trace_(std::move(trace)) {
    }

    channel_result_t open() override {
      trace_->emplace_back("open");
      ++open_calls;
      return open_result;
    }

    channel_result_t get_capabilities(
      const LUMEN_VHID_GET_CAPABILITIES_REQUEST &request,
      LUMEN_VHID_GET_CAPABILITIES_RESPONSE &response
    ) override {
      trace_->emplace_back("capabilities");
      capabilities_requests.push_back(request);
      if (!capabilities_result) {
        return capabilities_result;
      }

      response.header = response_header(
        LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
        sizeof(response)
      );
      response.header.protocol_major = capability_major;
      response.header.protocol_minor = capability_minor;
      response.capabilities = capabilities;
      response.required_capabilities = required_capabilities;
      response.max_control_size = max_control_size;
      response.max_report_payload = max_report_payload;
      response.keyboard_report_size = keyboard_report_size;
      response.relative_mouse_report_size = relative_mouse_report_size;
      response.absolute_mouse_report_size = absolute_mouse_report_size;
      response.min_minor_get_capabilities = LUMEN_VHID_MIN_MINOR_GET_PROTOCOL_CAPABILITIES;
      response.min_minor_claim = LUMEN_VHID_MIN_MINOR_CLAIM_INPUT_SESSION;
      response.min_minor_submit = LUMEN_VHID_MIN_MINOR_SUBMIT_INPUT_REPORT;
      response.min_minor_reset = LUMEN_VHID_MIN_MINOR_RESET_INPUT_SESSION;
      response.min_minor_release = LUMEN_VHID_MIN_MINOR_RELEASE_INPUT_SESSION;
      return {};
    }

    channel_result_t claim(
      const LUMEN_VHID_CLAIM_SESSION_REQUEST &request,
      LUMEN_VHID_CLAIM_SESSION_RESPONSE &response
    ) override {
      trace_->emplace_back("claim");
      claim_requests.push_back(request);
      if (!claim_result) {
        return claim_result;
      }

      response.header = response_header(LUMEN_VHID_OPERATION_CLAIM_INPUT_SESSION, sizeof(response));
      response.session_token = claim_token;
      response.granted_capabilities = granted_capabilities;
      return {};
    }

    channel_result_t submit(
      const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request,
      LUMEN_VHID_SUBMIT_REPORT_RESPONSE &response
    ) override {
      trace_->emplace_back("virtual submit");
      submissions.push_back(request);

      channel_result_t result {};
      if (!submit_results.empty()) {
        result = submit_results.front();
        submit_results.erase(submit_results.begin());
      }
      if (!result) {
        return result;
      }

      response.header = response_header(LUMEN_VHID_OPERATION_SUBMIT_INPUT_REPORT, sizeof(response));
      response.session_token = stale_submit_token ? request.session_token + 1U : request.session_token;
      response.accepted_sequence = wrong_accepted_sequence ? request.sequence + 1U : request.sequence;
      return {};
    }

    channel_result_t reset(
      const LUMEN_VHID_SESSION_REQUEST &request,
      LUMEN_VHID_SESSION_RESPONSE &response
    ) override {
      trace_->emplace_back("reset");
      reset_requests.push_back(request);
      if (!reset_result) {
        return reset_result;
      }

      response.header = response_header(LUMEN_VHID_OPERATION_RESET_INPUT_SESSION, sizeof(response));
      response.session_token = reset_token;
      response.last_sequence = reset_last_sequence;
      return {};
    }

    channel_result_t release(
      const LUMEN_VHID_SESSION_REQUEST &request,
      LUMEN_VHID_SESSION_RESPONSE &response
    ) override {
      trace_->emplace_back("release");
      release_requests.push_back(request);
      if (!release_result) {
        return release_result;
      }

      response.header = response_header(LUMEN_VHID_OPERATION_RELEASE_INPUT_SESSION, sizeof(response));
      response.session_token = request.session_token;
      response.last_sequence = 0;
      return {};
    }

    channel_result_t cleanup() override {
      trace_->emplace_back("cleanup");
      ++cleanup_calls;
      return cleanup_result;
    }

    channel_result_t open_result {};
    channel_result_t capabilities_result {};
    channel_result_t claim_result {};
    channel_result_t reset_result {};
    channel_result_t release_result {};
    channel_result_t cleanup_result {};
    std::vector<channel_result_t> submit_results;
    std::uint16_t capability_major {LUMEN_VHID_PROTOCOL_MAJOR};
    std::uint16_t capability_minor {LUMEN_VHID_PROTOCOL_MINOR};
    std::uint64_t capabilities {LUMEN_VHID_CAP_REQUIRED};
    std::uint64_t required_capabilities {LUMEN_VHID_CAP_REQUIRED};
    std::uint64_t granted_capabilities {LUMEN_VHID_CAP_REQUIRED};
    std::uint64_t claim_token {initial_session_token};
    std::uint64_t reset_token {reset_session_token};
    std::uint64_t reset_last_sequence {0};
    std::uint32_t max_control_size {LUMEN_VHID_MAX_CONTROL_SIZE};
    std::uint32_t max_report_payload {LUMEN_VHID_MAX_REPORT_PAYLOAD};
    std::uint16_t keyboard_report_size {sizeof(LUMEN_VHID_KEYBOARD_REPORT)};
    std::uint16_t relative_mouse_report_size {sizeof(LUMEN_VHID_RELATIVE_MOUSE_REPORT)};
    std::uint16_t absolute_mouse_report_size {sizeof(LUMEN_VHID_ABSOLUTE_MOUSE_REPORT)};
    bool stale_submit_token {false};
    bool wrong_accepted_sequence {false};
    int open_calls {0};
    int cleanup_calls {0};
    std::vector<LUMEN_VHID_GET_CAPABILITIES_REQUEST> capabilities_requests;
    std::vector<LUMEN_VHID_CLAIM_SESSION_REQUEST> claim_requests;
    std::vector<LUMEN_VHID_SUBMIT_REPORT_REQUEST> submissions;
    std::vector<LUMEN_VHID_SESSION_REQUEST> reset_requests;
    std::vector<LUMEN_VHID_SESSION_REQUEST> release_requests;

  private:
    std::shared_ptr<std::vector<std::string>> trace_;
  };

  /**
   * @brief Decode one fixed-size report payload from a recorded submission.
   *
   * @tparam Report Report structure type.
   * @param request Recorded submission request.
   * @return Decoded report structure.
   */
  template<class Report>
  Report submitted_report(const LUMEN_VHID_SUBMIT_REPORT_REQUEST &request) {
    Report report {};
    EXPECT_EQ(request.payload_size, sizeof(report));
    std::memcpy(&report, request.payload, std::min<std::size_t>(request.payload_size, sizeof(report)));
    return report;
  }

  /**
   * @brief Test fixture that builds a Virtual HID transport entirely from fakes.
   */
  class virtual_hid_input_test: public testing::Test {
  protected:
    void SetUp() override {
      trace = std::make_shared<std::vector<std::string>>();
      channel = std::make_shared<fake_virtual_hid_channel_t>(trace);
      fallback_api = std::make_shared<recording_win32_api_t>(trace);
      auto fallback = std::make_unique<platf::win_input::send_input_transport_t>(fallback_api);
      transport = std::make_unique<platf::win_input::virtual_hid_transport_t>(channel, std::move(fallback));
    }

    /**
     * @brief Initialize the fake transport and clear the operation trace.
     * @return `true` when Virtual HID became active.
     */
    bool activate() {
      const auto active = transport->initialize();
      trace->clear();
      return active;
    }

    std::shared_ptr<std::vector<std::string>> trace;
    std::shared_ptr<fake_virtual_hid_channel_t> channel;
    std::shared_ptr<recording_win32_api_t> fallback_api;
    std::unique_ptr<platf::win_input::virtual_hid_transport_t> transport;
  };

  /**
   * @brief Expected direct key-to-HID mapping.
   */
  struct key_mapping_case_t {
    std::uint16_t virtual_key;  ///< Windows virtual-key value.
    std::uint8_t usage;  ///< Expected keyboard-page usage.
  };

  /**
   * @brief Parameterized fixture for deterministic key mappings.
   */
  class virtual_hid_key_mapping_test: public testing::TestWithParam<key_mapping_case_t> {};
}  // namespace

TEST_F(virtual_hid_input_test, StartsInProbingState) {
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::probing);
}

TEST_F(virtual_hid_input_test, InitializesThroughHandshakeClaimAndNeutralReports) {
  ASSERT_TRUE(transport->initialize());

  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::virtual_hid);
  EXPECT_EQ(channel->open_calls, 1);
  ASSERT_EQ(channel->capabilities_requests.size(), 1);
  EXPECT_TRUE(lumen_vhid_validate_message_header(
    &channel->capabilities_requests.front().header,
    sizeof(LUMEN_VHID_GET_CAPABILITIES_REQUEST),
    LUMEN_VHID_OPERATION_GET_PROTOCOL_CAPABILITIES,
    sizeof(LUMEN_VHID_GET_CAPABILITIES_REQUEST)
  ));
  ASSERT_EQ(channel->claim_requests.size(), 1);
  EXPECT_EQ(channel->claim_requests.front().required_capabilities, LUMEN_VHID_CAP_REQUIRED);
  ASSERT_EQ(channel->submissions.size(), 2);
  EXPECT_EQ(channel->submissions[0].sequence, 1);
  EXPECT_EQ(channel->submissions[1].sequence, 2);

  const auto keyboard = submitted_report<LUMEN_VHID_KEYBOARD_REPORT>(channel->submissions[0]);
  EXPECT_EQ(keyboard.report_id, LUMEN_VHID_REPORT_ID_KEYBOARD);
  EXPECT_EQ(keyboard.modifiers, 0);
  EXPECT_TRUE(std::ranges::all_of(keyboard.key_bitmap, [](std::uint8_t value) {
    return value == 0;
  }));

  const auto mouse = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions[1]);
  EXPECT_EQ(mouse.report_id, LUMEN_VHID_REPORT_ID_MOUSE_RELATIVE);
  EXPECT_EQ(mouse.buttons, 0);
  EXPECT_EQ(mouse.x, 0);
  EXPECT_EQ(mouse.y, 0);
  EXPECT_EQ(mouse.vertical_wheel, 0);
  EXPECT_EQ(mouse.horizontal_wheel, 0);
}

TEST_F(virtual_hid_input_test, FallsBackWhenInterfaceOpenFails) {
  channel->open_result = {channel_completion_t::definite_reject, ERROR_ACCESS_DENIED};

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "interface discovery/open");
  EXPECT_EQ(transport->failure_status(), ERROR_ACCESS_DENIED);
  EXPECT_TRUE(channel->capabilities_requests.empty());
}

TEST_F(virtual_hid_input_test, FallsBackWhenCapabilitiesAreIncomplete) {
  channel->capabilities &= ~LUMEN_VHID_CAP_MOUSE_ABSOLUTE;

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "capability handshake");
  EXPECT_EQ(transport->failure_status(), ERROR_REVISION_MISMATCH);
  EXPECT_EQ(channel->cleanup_calls, 1);
}

TEST_F(virtual_hid_input_test, FallsBackWhenProtocolMajorIsIncompatible) {
  ++channel->capability_major;

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "capability handshake");
  EXPECT_EQ(transport->failure_status(), ERROR_REVISION_MISMATCH);
}

TEST_F(virtual_hid_input_test, FallsBackWhenExclusiveClaimFails) {
  channel->claim_result = {channel_completion_t::definite_reject, ERROR_SHARING_VIOLATION};

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "exclusive session claim");
  EXPECT_EQ(transport->failure_status(), ERROR_SHARING_VIOLATION);
  EXPECT_EQ(channel->cleanup_calls, 1);
}

TEST_F(virtual_hid_input_test, FallsBackWhenNeutralReportFails) {
  channel->submit_results.push_back({channel_completion_t::definite_reject, ERROR_WRITE_FAULT});

  EXPECT_FALSE(transport->initialize());
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "neutral report");
  EXPECT_EQ(transport->failure_status(), ERROR_WRITE_FAULT);
  EXPECT_EQ(channel->reset_requests.size(), 1);
  EXPECT_EQ(channel->release_requests.size(), 1);
}

TEST_F(virtual_hid_input_test, InitializationIsIdempotentAfterActivation) {
  ASSERT_TRUE(transport->initialize());
  const auto submit_count = channel->submissions.size();

  EXPECT_TRUE(transport->initialize());
  EXPECT_EQ(channel->open_calls, 1);
  EXPECT_EQ(channel->submissions.size(), submit_count);
}

TEST_P(virtual_hid_key_mapping_test, MapsVirtualKeyToKeyboardUsage) {
  const auto &test_case = GetParam();

  const auto usage = platf::win_input::map_key_to_hid_usage(test_case.virtual_key, 0, false);

  ASSERT_TRUE(usage.has_value());
  EXPECT_EQ(*usage, test_case.usage);
}

INSTANTIATE_TEST_SUITE_P(
  SupportedKeys,
  virtual_hid_key_mapping_test,
  testing::Values(
    key_mapping_case_t {'A', 0x04},
    key_mapping_case_t {'Z', 0x1D},
    key_mapping_case_t {'1', 0x1E},
    key_mapping_case_t {'9', 0x26},
    key_mapping_case_t {'0', 0x27},
    key_mapping_case_t {VK_F1, 0x3A},
    key_mapping_case_t {VK_F12, 0x45},
    key_mapping_case_t {VK_F13, 0x68},
    key_mapping_case_t {VK_F24, 0x73},
    key_mapping_case_t {VK_LSHIFT, 0xE1},
    key_mapping_case_t {VK_RSHIFT, 0xE5},
    key_mapping_case_t {VK_LCONTROL, 0xE0},
    key_mapping_case_t {VK_RCONTROL, 0xE4},
    key_mapping_case_t {VK_LMENU, 0xE2},
    key_mapping_case_t {VK_RMENU, 0xE6},
    key_mapping_case_t {VK_LWIN, 0xE3},
    key_mapping_case_t {VK_RWIN, 0xE7},
    key_mapping_case_t {VK_RETURN, 0x28},
    key_mapping_case_t {VK_ESCAPE, 0x29},
    key_mapping_case_t {VK_BACK, 0x2A},
    key_mapping_case_t {VK_TAB, 0x2B},
    key_mapping_case_t {VK_SPACE, 0x2C},
    key_mapping_case_t {VK_INSERT, 0x49},
    key_mapping_case_t {VK_HOME, 0x4A},
    key_mapping_case_t {VK_PRIOR, 0x4B},
    key_mapping_case_t {VK_DELETE, 0x4C},
    key_mapping_case_t {VK_END, 0x4D},
    key_mapping_case_t {VK_NEXT, 0x4E},
    key_mapping_case_t {VK_RIGHT, 0x4F},
    key_mapping_case_t {VK_LEFT, 0x50},
    key_mapping_case_t {VK_DOWN, 0x51},
    key_mapping_case_t {VK_UP, 0x52},
    key_mapping_case_t {VK_DIVIDE, 0x54},
    key_mapping_case_t {VK_NUMPAD1, 0x59},
    key_mapping_case_t {VK_NUMPAD9, 0x61},
    key_mapping_case_t {VK_NUMPAD0, 0x62},
    key_mapping_case_t {VK_DECIMAL, 0x63},
    key_mapping_case_t {VK_APPS, 0x65}
  )
);

TEST(VirtualHidKeyMappingTest, RejectsUnsupportedVirtualKey) {
  EXPECT_FALSE(platf::win_input::map_key_to_hid_usage(VK_PACKET, 0, false).has_value());
}

TEST(VirtualHidKeyMappingTest, RejectsNonNormalizedKeyWhenScancodesDisabled) {
  const auto usage = platf::win_input::map_key_to_hid_usage(
    'A',
    SS_KBE_FLAG_NON_NORMALIZED,
    false
  );

  EXPECT_FALSE(usage.has_value());
}

TEST(VirtualHidKeyMappingTest, MapsNonNormalizedKeyThroughActiveLayoutWhenScancodesEnabled) {
  const auto usage = platf::win_input::map_key_to_hid_usage(
    'A',
    SS_KBE_FLAG_NON_NORMALIZED,
    true
  );

  ASSERT_TRUE(usage.has_value());
  EXPECT_EQ(*usage, 0x04);
}

TEST_F(virtual_hid_input_test, BuildsNkroKeyboardReport) {
  ASSERT_TRUE(activate());

  ASSERT_TRUE(transport->keyboard('A', false, 0));

  const auto report = submitted_report<LUMEN_VHID_KEYBOARD_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.report_id, LUMEN_VHID_REPORT_ID_KEYBOARD);
  EXPECT_EQ(report.modifiers, 0);
  EXPECT_EQ(report.key_bitmap[0], 0x10);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, UpdatesAcknowledgedKeyboardOnlyAfterAcceptedReport) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->keyboard('A', false, 0));
  channel->submit_results.push_back({channel_completion_t::ambiguous, ERROR_TIMEOUT});

  ASSERT_TRUE(transport->keyboard('B', false, 0));

  const auto acknowledged = transport->acknowledged_keyboard_report();
  EXPECT_EQ(acknowledged.key_bitmap[0] & 0x10, 0x10);
  EXPECT_EQ(acknowledged.key_bitmap[0] & 0x20, 0);
}

TEST_F(virtual_hid_input_test, KeepsLeftAndRightModifiersIndependent) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->keyboard(VK_LCONTROL, false, 0));

  ASSERT_TRUE(transport->keyboard(VK_RCONTROL, false, 0));

  const auto report = submitted_report<LUMEN_VHID_KEYBOARD_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.modifiers, 0x11);
}

TEST_F(virtual_hid_input_test, RemovesReleasedKeyFromCompleteKeyboardState) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->keyboard('A', false, 0));

  ASSERT_TRUE(transport->keyboard('A', true, 0));

  const auto report = submitted_report<LUMEN_VHID_KEYBOARD_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.key_bitmap[0] & 0x10, 0);
}

TEST_F(virtual_hid_input_test, DuplicateKeyDownKeepsOneNkroBit) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->keyboard('A', false, 0));

  ASSERT_TRUE(transport->keyboard('A', false, 0));

  const auto report = submitted_report<LUMEN_VHID_KEYBOARD_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.key_bitmap[0], 0x10);
}

TEST_F(virtual_hid_input_test, RepresentsTenSimultaneousKeysWithoutRollover) {
  ASSERT_TRUE(activate());
  for (std::uint16_t key = 'A'; key <= 'J'; ++key) {
    ASSERT_TRUE(transport->keyboard(key, false, 0));
  }

  const auto report = submitted_report<LUMEN_VHID_KEYBOARD_REPORT>(channel->submissions.back());
  int held_count = 0;
  for (const auto byte : report.key_bitmap) {
    held_count += std::popcount(byte);
  }
  EXPECT_EQ(held_count, 10);
}

TEST_F(virtual_hid_input_test, UsesContiguousSequenceAndClaimToken) {
  ASSERT_TRUE(activate());

  ASSERT_TRUE(transport->keyboard('A', false, 0));
  ASSERT_TRUE(transport->move_mouse(1, 2));

  ASSERT_EQ(channel->submissions.size(), 4);
  for (std::size_t index = 0; index < channel->submissions.size(); ++index) {
    EXPECT_EQ(channel->submissions[index].sequence, index + 1U);
    EXPECT_EQ(channel->submissions[index].session_token, initial_session_token);
  }
}

TEST_F(virtual_hid_input_test, BuildsRelativeMouseBoundaryReport) {
  ASSERT_TRUE(activate());

  ASSERT_TRUE(transport->move_mouse(INT16_MIN, INT16_MAX));

  const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.x, INT16_MIN);
  EXPECT_EQ(report.y, INT16_MAX);
  EXPECT_EQ(report.vertical_wheel, 0);
  EXPECT_EQ(report.horizontal_wheel, 0);
}

TEST_F(virtual_hid_input_test, SendsOneReportForZeroRelativeMovement) {
  ASSERT_TRUE(activate());
  const auto before = channel->submissions.size();

  ASSERT_TRUE(transport->move_mouse(0, 0));

  ASSERT_EQ(channel->submissions.size(), before + 1U);
  const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.x, 0);
  EXPECT_EQ(report.y, 0);
}

TEST_F(virtual_hid_input_test, SegmentsRelativeMovementWithoutTruncation) {
  ASSERT_TRUE(activate());
  const auto before = channel->submissions.size();

  ASSERT_TRUE(transport->move_mouse(40000, -40000));

  ASSERT_EQ(channel->submissions.size(), before + 2U);
  std::int32_t total_x = 0;
  std::int32_t total_y = 0;
  for (std::size_t index = before; index < channel->submissions.size(); ++index) {
    const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions[index]);
    total_x += report.x;
    total_y += report.y;
  }
  EXPECT_EQ(total_x, 40000);
  EXPECT_EQ(total_y, -40000);
}

TEST_F(virtual_hid_input_test, BuildsAbsoluteMouseEndpoints) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->absolute_mouse(0.0f, 0.0f, 1920, 1080));

  ASSERT_TRUE(transport->absolute_mouse(1920.0f, 1080.0f, 1920, 1080));

  const auto first = submitted_report<LUMEN_VHID_ABSOLUTE_MOUSE_REPORT>(
    channel->submissions[channel->submissions.size() - 2]
  );
  const auto second = submitted_report<LUMEN_VHID_ABSOLUTE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(first.x, 0);
  EXPECT_EQ(first.y, 0);
  EXPECT_EQ(second.x, 65535);
  EXPECT_EQ(second.y, 65535);
}

TEST_F(virtual_hid_input_test, RejectsAbsoluteMouseWithInvalidSourceSize) {
  ASSERT_TRUE(activate());
  const auto before = channel->submissions.size();

  const auto result = transport->absolute_mouse(1.0f, 1.0f, -1, 1080);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.status, ERROR_INVALID_PARAMETER);
  EXPECT_EQ(channel->submissions.size(), before);
}

TEST_F(virtual_hid_input_test, KeepsFiveButtonsInCompleteMouseState) {
  ASSERT_TRUE(activate());
  for (int button = 1; button <= 5; ++button) {
    ASSERT_TRUE(transport->mouse_button(button, false));
  }

  const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.buttons, 0x1F);
}

TEST_F(virtual_hid_input_test, UpdatesAcknowledgedButtonsOnlyAfterAcceptedReport) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->mouse_button(1, false));
  channel->submit_results.push_back({channel_completion_t::ambiguous, ERROR_TIMEOUT});

  ASSERT_TRUE(transport->mouse_button(2, false));

  EXPECT_EQ(transport->acknowledged_mouse_buttons(), 0x01);
}

TEST_F(virtual_hid_input_test, KeepsButtonStateAcrossRelativeAndAbsoluteReports) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->mouse_button(4, false));
  ASSERT_TRUE(transport->move_mouse(2, 3));

  ASSERT_TRUE(transport->absolute_mouse(5.0f, 6.0f, 10, 10));

  const auto relative = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(
    channel->submissions[channel->submissions.size() - 2]
  );
  const auto absolute = submitted_report<LUMEN_VHID_ABSOLUTE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(relative.buttons, 0x08);
  EXPECT_EQ(absolute.buttons, 0x08);
}

TEST_F(virtual_hid_input_test, MouseButtonReleaseIsIdempotent) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->mouse_button(2, true));

  ASSERT_TRUE(transport->mouse_button(2, true));

  const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.buttons, 0);
}

TEST_F(virtual_hid_input_test, BuildsPositiveAndNegativeVerticalWheelReports) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->vertical_scroll(120));

  ASSERT_TRUE(transport->vertical_scroll(-75));

  const auto positive = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(
    channel->submissions[channel->submissions.size() - 2]
  );
  const auto negative = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(positive.vertical_wheel, 120);
  EXPECT_EQ(negative.vertical_wheel, -75);
}

TEST_F(virtual_hid_input_test, SegmentsHorizontalWheelWithoutTruncation) {
  ASSERT_TRUE(activate());
  const auto before = channel->submissions.size();

  ASSERT_TRUE(transport->horizontal_scroll(40000));

  ASSERT_EQ(channel->submissions.size(), before + 2U);
  std::int32_t total = 0;
  for (std::size_t index = before; index < channel->submissions.size(); ++index) {
    const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions[index]);
    total += report.horizontal_wheel;
  }
  EXPECT_EQ(total, 40000);
}

TEST_F(virtual_hid_input_test, ClearsMouseEdgeFieldsOnNextStateReport) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->vertical_scroll(120));

  ASSERT_TRUE(transport->mouse_button(1, false));

  const auto report = submitted_report<LUMEN_VHID_RELATIVE_MOUSE_REPORT>(channel->submissions.back());
  EXPECT_EQ(report.buttons, 1);
  EXPECT_EQ(report.x, 0);
  EXPECT_EQ(report.y, 0);
  EXPECT_EQ(report.vertical_wheel, 0);
  EXPECT_EQ(report.horizontal_wheel, 0);
}

TEST_F(virtual_hid_input_test, RoutesUnicodeOnlyThroughSendInputFallback) {
  ASSERT_TRUE(activate());
  const auto virtual_submissions = channel->submissions.size();

  ASSERT_TRUE(transport->unicode("a", 1));

  EXPECT_EQ(channel->submissions.size(), virtual_submissions);
  ASSERT_EQ(fallback_api->submitted.size(), 2);
  EXPECT_EQ(fallback_api->submitted[0].ki.dwFlags, KEYEVENTF_UNICODE);
  EXPECT_EQ(fallback_api->submitted[1].ki.dwFlags, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP);
}

TEST_F(virtual_hid_input_test, FencesBeforeReplayingDefinitelyRejectedDelta) {
  ASSERT_TRUE(activate());
  channel->submit_results.push_back({channel_completion_t::definite_reject, ERROR_WRITE_FAULT});

  const auto result = transport->move_mouse(9, -4);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(
    *trace,
    (std::vector<std::string> {"virtual submit", "reset", "release", "cleanup", "fallback submit"})
  );
  ASSERT_EQ(fallback_api->submitted.size(), 1);
  EXPECT_EQ(fallback_api->submitted.front().mi.dx, 9);
  EXPECT_EQ(fallback_api->submitted.front().mi.dy, -4);
}

TEST_F(virtual_hid_input_test, DropsAmbiguouslyCompletedDeltaAfterFence) {
  ASSERT_TRUE(activate());
  channel->submit_results.push_back({channel_completion_t::ambiguous, ERROR_TIMEOUT});

  const auto result = transport->vertical_scroll(120);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(*trace, (std::vector<std::string> {"virtual submit", "reset", "release", "cleanup"}));
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, UsesConfirmedRemovalAsFenceWithoutReset) {
  ASSERT_TRUE(activate());
  channel->submit_results.push_back({channel_completion_t::removed, ERROR_DEVICE_NOT_CONNECTED});

  const auto result = transport->move_mouse(3, 4);

  ASSERT_TRUE(result);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(*trace, (std::vector<std::string> {"virtual submit", "cleanup"}));
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, FailsClosedWhenNoQuiescenceFenceSucceeds) {
  ASSERT_TRUE(activate());
  channel->submit_results.push_back({channel_completion_t::ambiguous, ERROR_TIMEOUT});
  channel->reset_result = {channel_completion_t::ambiguous, ERROR_TIMEOUT};
  channel->cleanup_result = {channel_completion_t::ambiguous, ERROR_TIMEOUT};

  const auto result = transport->move_mouse(3, 4);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.completion, platf::win_input::completion_t::ambiguous);
  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::fail_closed);
  EXPECT_EQ(*trace, (std::vector<std::string> {"virtual submit", "reset", "cleanup"}));
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, RejectsLaterInputAfterFailClosedTransition) {
  ASSERT_TRUE(activate());
  channel->submit_results.push_back({channel_completion_t::ambiguous, ERROR_TIMEOUT});
  channel->reset_result = {channel_completion_t::ambiguous, ERROR_TIMEOUT};
  channel->cleanup_result = {channel_completion_t::ambiguous, ERROR_TIMEOUT};
  ASSERT_FALSE(transport->move_mouse(3, 4));
  trace->clear();

  const auto result = transport->keyboard('A', false, 0);

  EXPECT_FALSE(result);
  EXPECT_EQ(result.completion, platf::win_input::completion_t::ambiguous);
  EXPECT_TRUE(trace->empty());
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, ReplaysFinalHeldKeyboardAndButtonStateOnceAfterFence) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->keyboard('A', false, 0));
  ASSERT_TRUE(transport->mouse_button(3, false));
  trace->clear();
  channel->submit_results.push_back({channel_completion_t::definite_reject, ERROR_WRITE_FAULT});

  ASSERT_TRUE(transport->move_mouse(7, 8));

  ASSERT_EQ(fallback_api->submitted.size(), 3);
  EXPECT_EQ(fallback_api->submitted[0].type, INPUT_KEYBOARD);
  EXPECT_EQ(fallback_api->submitted[0].ki.wScan, 0x1E);
  EXPECT_EQ(fallback_api->submitted[1].type, INPUT_MOUSE);
  EXPECT_EQ(fallback_api->submitted[1].mi.dwFlags, MOUSEEVENTF_RIGHTDOWN);
  EXPECT_EQ(fallback_api->submitted[2].type, INPUT_MOUSE);
  EXPECT_EQ(fallback_api->submitted[2].mi.dwFlags, MOUSEEVENTF_MOVE);
}

TEST_F(virtual_hid_input_test, ReplaysDesiredStateWhenKeyboardReportIsAmbiguous) {
  ASSERT_TRUE(activate());
  ASSERT_TRUE(transport->keyboard('A', false, 0));
  channel->submit_results.push_back({channel_completion_t::ambiguous, ERROR_TIMEOUT});

  ASSERT_TRUE(transport->keyboard('B', false, 0));

  ASSERT_EQ(fallback_api->submitted.size(), 2);
  std::array<WORD, 2> scans {
    fallback_api->submitted[0].ki.wScan,
    fallback_api->submitted[1].ki.wScan
  };
  std::ranges::sort(scans);
  EXPECT_EQ(scans, (std::array<WORD, 2> {0x1E, 0x30}));
}

TEST_F(virtual_hid_input_test, TreatsStaleSubmissionResponseAsAmbiguousWithoutDeltaReplay) {
  ASSERT_TRUE(activate());
  channel->stale_submit_token = true;

  ASSERT_TRUE(transport->move_mouse(10, 20));

  EXPECT_EQ(transport->backend(), platf::win_input::backend_t::send_input);
  EXPECT_EQ(transport->failure_stage(), "relative mouse report");
  EXPECT_EQ(transport->failure_status(), ERROR_INVALID_DATA);
  EXPECT_TRUE(fallback_api->submitted.empty());
}

TEST_F(virtual_hid_input_test, ResetsSessionToNewGenerationAndSequenceOne) {
  ASSERT_TRUE(activate());

  ASSERT_TRUE(transport->neutralize());
  ASSERT_TRUE(transport->keyboard('A', false, 0));

  ASSERT_EQ(channel->reset_requests.size(), 1);
  EXPECT_EQ(channel->reset_requests.front().session_token, initial_session_token);
  EXPECT_EQ(channel->submissions.back().session_token, reset_session_token);
  EXPECT_EQ(channel->submissions.back().sequence, 1);
}

TEST_F(virtual_hid_input_test, DestructorFencesAndReleasesActiveSession) {
  ASSERT_TRUE(activate());
  trace->clear();

  transport.reset();

  EXPECT_EQ(*trace, (std::vector<std::string> {"reset", "release", "cleanup"}));
}

#else
TEST(VirtualHidInputTest, IsWindowsOnly) {
  GTEST_SKIP() << "Windows Virtual HID transport is not available on this platform";
}
#endif
