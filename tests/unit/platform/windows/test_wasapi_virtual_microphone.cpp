/**
 * @file tests/unit/platform/windows/test_wasapi_virtual_microphone.cpp
 * @brief Behavioral tests for the production WASAPI virtual-microphone core.
 */

#include <gtest/gtest.h>

#ifdef _WIN32
  #include "src/platform/windows/wasapi_virtual_microphone.h"

  #include <array>
  #include <cstddef>
  #include <cstdint>
  #include <cstring>
  #include <limits>
  #include <string>
  #include <vector>

namespace platf::win_audio {
  namespace {
    constexpr GUID CONTAINER_A {0x10203040, 0x5060, 0x7080, {0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}};
    constexpr GUID CONTAINER_B {0x10203040, 0x5060, 0x7080, {0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x02}};
  }  // namespace

  TEST(WasapiVirtualMicrophone, SelectsOnlyACompleteWhitelistedPair) {
    const std::vector<wasapi_endpoint_identity_t> renders {
      {L"render", L"CABLE Input (VB-Audio Virtual Cable)", L"VB-Audio Virtual Cable", CONTAINER_A},
    };
    const std::vector<wasapi_endpoint_identity_t> captures {
      {L"capture", L"CABLE Output (VB-Audio Virtual Cable)", L"VB-Audio Virtual Cable", CONTAINER_A},
    };
    const auto *render = select_wasapi_virtual_microphone_endpoint(
      renders,
      captures,
      wasapi_virtual_microphone_kind_e::vb_cable
    );
    ASSERT_NE(render, nullptr);
    EXPECT_EQ(render->device_id, L"render");

    const std::vector<wasapi_endpoint_identity_t> empty;
    const std::vector<wasapi_endpoint_identity_t> untrusted {
      {L"untrusted", L"CABLE Input (VB-Audio Virtual Cable)", L"Untrusted adapter", CONTAINER_A},
    };
    EXPECT_EQ(
      select_wasapi_virtual_microphone_endpoint(renders, empty, wasapi_virtual_microphone_kind_e::vb_cable),
      nullptr
    );
    EXPECT_EQ(
      select_wasapi_virtual_microphone_endpoint(untrusted, captures, wasapi_virtual_microphone_kind_e::vb_cable),
      nullptr
    );
  }

  TEST(WasapiVirtualMicrophone, SelectsLocalizedSteamEndpointsByStableAdapterIdentity) {
    const std::vector<wasapi_endpoint_identity_t> renders {
      {L"vb-render", L"CABLE Input (VB-Audio Virtual Cable)", L"VB-Audio Virtual Cable", CONTAINER_A},
      {L"steam-render", L"\u626c\u58f0\u5668 (Steam Streaming Microphone)", L"Steam Streaming Microphone", CONTAINER_B},
    };
    const std::vector<wasapi_endpoint_identity_t> captures {
      {L"vb-capture", L"CABLE Output (VB-Audio Virtual Cable)", L"VB-Audio Virtual Cable", CONTAINER_A},
      {L"steam-capture", L"\u9ea6\u514b\u98ce (Steam Streaming Microphone)", L"Steam Streaming Microphone", CONTAINER_B},
    };
    const auto *render = select_wasapi_virtual_microphone_endpoint(
      renders,
      captures,
      wasapi_virtual_microphone_kind_e::steam
    );
    ASSERT_NE(render, nullptr);
    EXPECT_EQ(render->device_id, L"steam-render");
  }

  TEST(WasapiVirtualMicrophone, DoesNotFallThroughOrCrossAdapterContainers) {
    const std::vector<wasapi_endpoint_identity_t> renders {
      {L"steam-render", L"\u626c\u58f0\u5668 (Steam Streaming Microphone)", L"Steam Streaming Microphone", CONTAINER_A},
      {L"vb-render", L"CABLE Input (VB-Audio Virtual Cable)", L"VB-Audio Virtual Cable", CONTAINER_B},
    };
    const std::vector<wasapi_endpoint_identity_t> mismatched_captures {
      {L"steam-capture", L"\u9ea6\u514b\u98ce (Steam Streaming Microphone)", L"Steam Streaming Microphone", CONTAINER_B},
      {L"vb-capture", L"CABLE Output (VB-Audio Virtual Cable)", L"VB-Audio Virtual Cable", CONTAINER_B},
    };

    EXPECT_EQ(
      select_wasapi_virtual_microphone_endpoint(
        renders,
        mismatched_captures,
        wasapi_virtual_microphone_kind_e::steam
      ),
      nullptr
    );
    const auto *vb_render = select_wasapi_virtual_microphone_endpoint(
      renders,
      mismatched_captures,
      wasapi_virtual_microphone_kind_e::vb_cable
    );
    ASSERT_NE(vb_render, nullptr);
    EXPECT_EQ(vb_render->device_id, L"vb-render");
  }

  TEST(WasapiVirtualMicrophone, FrameRingIsBoundedAlignedAndWrapsWithoutLoss) {
    wasapi_frame_ring_t ring;
    ASSERT_TRUE(ring.reset(4, 2));
    const std::array<std::byte, 6> first {
      std::byte {1},
      std::byte {2},
      std::byte {3},
      std::byte {4},
      std::byte {5},
      std::byte {6},
    };
    ASSERT_TRUE(ring.push(first));
    EXPECT_EQ(ring.size_frames(), 3U);

    std::array<std::byte, 4> output {};
    EXPECT_EQ(ring.pop(output), 2U);
    EXPECT_EQ(output[0], std::byte {1});
    EXPECT_EQ(output[3], std::byte {4});

    const std::array<std::byte, 6> second {
      std::byte {7},
      std::byte {8},
      std::byte {9},
      std::byte {10},
      std::byte {11},
      std::byte {12},
    };
    ASSERT_TRUE(ring.push(second));
    EXPECT_EQ(ring.size_frames(), 4U);
    EXPECT_FALSE(ring.push(std::array<std::byte, 2> {std::byte {13}, std::byte {14}}));
    EXPECT_FALSE(ring.push(std::array<std::byte, 1> {std::byte {15}}));

    std::array<std::byte, 8> remaining {};
    EXPECT_EQ(ring.pop(remaining), 4U);
    const std::array<std::byte, 8> expected {
      std::byte {5},
      std::byte {6},
      std::byte {7},
      std::byte {8},
      std::byte {9},
      std::byte {10},
      std::byte {11},
      std::byte {12},
    };
    EXPECT_EQ(remaining, expected);
  }

  TEST(WasapiVirtualMicrophone, ConvertsMonoS16ToInterleavedEndpointFrames) {
    wasapi_mono_converter_t converter;
    ASSERT_TRUE(converter.reset({48000, 2, 8, wasapi_sample_format_e::float_f32}));
    const std::array<std::int16_t, 3> input {
      std::numeric_limits<std::int16_t>::min(),
      0,
      std::numeric_limits<std::int16_t>::max(),
    };
    const auto output = converter.convert(input);
    ASSERT_EQ(output.size(), 3U * 2U * sizeof(float));
    std::array<float, 6> values {};
    std::memcpy(values.data(), output.data(), output.size());
    EXPECT_FLOAT_EQ(values[0], -1.0f);
    EXPECT_FLOAT_EQ(values[1], -1.0f);
    EXPECT_FLOAT_EQ(values[2], 0.0f);
    EXPECT_FLOAT_EQ(values[3], 0.0f);
    EXPECT_FLOAT_EQ(values[4], static_cast<float>(std::numeric_limits<std::int16_t>::max()) / 32768.0f);
    EXPECT_FLOAT_EQ(values[5], values[4]);

    EXPECT_FALSE(converter.reset({48000, 2, 7, wasapi_sample_format_e::float_f32}));
  }

  TEST(WasapiVirtualMicrophone, GenerationStateFailsClosedUntilExactEndAndRestart) {
    wasapi_generation_state_t state;
    EXPECT_FALSE(state.begin(0));
    ASSERT_TRUE(state.begin(7));
    EXPECT_TRUE(state.accepts(7));
    EXPECT_FALSE(state.accepts(8));
    state.fail();
    EXPECT_TRUE(state.failed());
    EXPECT_FALSE(state.accepts(7));
    EXPECT_FALSE(state.end(8));
    EXPECT_TRUE(state.end(7));
    EXPECT_EQ(state.generation(), 0U);
    ASSERT_TRUE(state.begin(9));
    EXPECT_TRUE(state.accepts(9));
    EXPECT_FALSE(state.failed());
  }
}  // namespace platf::win_audio
#endif
