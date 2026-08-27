/**
 * @file tests/unit/platform/windows/test_audio_endpoint_notification.cpp
 * @brief Regression tests for Windows default audio endpoint notification filtering.
 */

#include <gtest/gtest.h>

#ifdef _WIN32
  #include <functional>
  #include <string>

namespace platf::audio {
  /**
   * @brief Exercise virtual-sink endpoint notification filtering for unit tests.
   *
   * @param assigned_device_id Assigned virtual render endpoint ID.
   * @param notified_device_id Endpoint ID supplied by the Windows notification.
   * @param reassert_sink Callback recording virtual-sink reassertion.
   * @return `true` when the notification is actionable and capture must reinitialize.
   */
  bool process_virtual_sink_default_device_change_for_test(
    const std::wstring &assigned_device_id,
    const wchar_t *notified_device_id,
    const std::function<void()> &reassert_sink
  );
}  // namespace platf::audio

TEST(WindowsAudioEndpointNotification, AssignedVirtualSinkSelfNotificationIsNoOp) {
  int reassertions = 0;
  const std::wstring assigned_device_id = L"{assigned-virtual-sink}";

  EXPECT_FALSE(platf::audio::process_virtual_sink_default_device_change_for_test(assigned_device_id, assigned_device_id.c_str(), [&reassertions] {
    ++reassertions;
  }));
  EXPECT_EQ(reassertions, 0);
}

TEST(WindowsAudioEndpointNotification, ExternalDefaultReassertsAssignedVirtualSink) {
  int reassertions = 0;

  EXPECT_TRUE(platf::audio::process_virtual_sink_default_device_change_for_test(L"{assigned-virtual-sink}", L"{external-default-sink}", [&reassertions] {
    ++reassertions;
  }));
  EXPECT_EQ(reassertions, 1);
}

TEST(WindowsAudioEndpointNotification, MissingDefaultReassertsAssignedVirtualSink) {
  int reassertions = 0;

  EXPECT_TRUE(platf::audio::process_virtual_sink_default_device_change_for_test(L"{assigned-virtual-sink}", nullptr, [&reassertions] {
    ++reassertions;
  }));
  EXPECT_EQ(reassertions, 1);
}
#endif
