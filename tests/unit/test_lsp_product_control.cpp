/**
 * @file tests/unit/test_lsp_product_control.cpp
 * @brief Exact deterministic-CBOR coverage for LSP product control operations.
 */

#include "src/protocol_common/cbor.h"
#include "src/protocol_lsp/runtime/control/wire.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <variant>

namespace {
  namespace cbor = lumen::protocol_common::cbor;
  namespace lsp = lumen::lsp::runtime;

  template<std::size_t Size>
  std::array<std::uint8_t, Size> filled(const std::uint8_t value) {
    std::array<std::uint8_t, Size> result {};
    result.fill(value);
    return result;
  }

  cbor::Value::Bytes bytes(const auto &value) {
    return {value.begin(), value.end()};
  }

  std::size_t map_size(const std::vector<std::uint8_t> &encoded) {
    const auto decoded = cbor::decode(encoded);
    return decoded ? std::get<cbor::Value::Map>(decoded.value->storage).size() : 0;
  }

  /** @brief Encode one exact valid START request with the selected application intent. */
  std::vector<std::uint8_t> start_request(const bool resume) {
    const cbor::Value::Map audio_offer {
      {1, 2U},
      {2, 240U},
      {3, 128'000U},
      {4, cbor::Value {false}},
      {5, cbor::Value {true}},
    };
    const cbor::Value::Map video_offer {
      {1, 3U},
      {2, 1U},
      {3, 1U},
      {4, 1'920U},
      {5, 1'080U},
      {6, 240U},
      {7, 1U},
      {8, 100'000'000U},
      {9, 120'000'000U},
      {10, 1U},
      {11, 1U},
      {12, 1U},
      {13, 1U},
      {14, cbor::Value {false}},
      {15, 1U},
      {16, cbor::Value {true}},
      {17, cbor::Value {true}},
      {18, 16U * 1'024U * 1'024U},
    };
    return cbor::encode(cbor::Value {cbor::Value::Map {
                          {1, lumen::lsp::wire_version},
                          {2, cbor::Value::Map {{1, "1"}, {2, cbor::Value {resume}}}},
                          {3, 1'000U},
                          {4, 250U},
                          {5, 250U},
                          {6, 100U},
                          {7, 32'000'000U},
                          {8, cbor::Value::Array {cbor::Value {audio_offer}}},
                          {9, 1'472U},
                          {10, cbor::Value {cbor::Null {}}},
                          {11, 0U},
                          {12, cbor::Value::Array {cbor::Value {video_offer}}},
                          {13, 64U},
                          {14, 3U},
                          {15, 1U},
                          {16, 20'000U},
                        }})
      .bytes;
  }
}  // namespace

TEST(LspProductControlWire, FreezesRegistryAndCertificateRotationMaps) {
  EXPECT_EQ(static_cast<std::uint16_t>(lsp::ControlMessageType::certificate_rotate), 0x0022);
  EXPECT_EQ(static_cast<std::uint16_t>(lsp::ControlMessageType::quit_application), 0x0102);
  EXPECT_EQ(static_cast<std::uint16_t>(lsp::ControlMessageType::text_input), 0x0216);
  EXPECT_EQ(static_cast<std::uint16_t>(lsp::ControlMessageType::input_rate_request), 0x0218);
  EXPECT_EQ(static_cast<std::uint16_t>(lsp::ControlMessageType::stream_ended), 0x0220);
  EXPECT_EQ(static_cast<std::uint16_t>(lsp::ControlMessageType::object_chunk), 0x0400);

  const auto rotation = lsp::encode_certificate_rotate({
    .host_id = filled<16>(1),
    .connection_generation = 2,
    .rotation_generation = 3,
    .new_spki_sha256 = filled<32>(4),
    .host_signature = filled<64>(5),
  });
  ASSERT_TRUE(rotation);
  EXPECT_EQ(map_size(*rotation), 6U);
  const auto transcript = lsp::encode_certificate_rotation_transcript(
    filled<16>(1),
    filled<32>(2),
    filled<32>(3),
    filled<32>(4),
    2,
    3
  );
  ASSERT_TRUE(transcript);
  EXPECT_EQ(map_size(*transcript), 8U);

  const auto acknowledgement = cbor::encode(cbor::Value {cbor::Value::Map {
                                              {1, lumen::lsp::wire_version},
                                              {2, static_cast<std::uint8_t>(lsp::ControlStatus::success)},
                                              {3, bytes(filled<16>(1))},
                                              {4, 2U},
                                              {5, 3U},
                                            }})
                                 .bytes;
  ASSERT_TRUE(lsp::decode_certificate_rotate_ack(acknowledgement));
}

TEST(LspProductControlWire, DecodesLaunchAndResumeApplicationIntentWithoutChangingOuterShape) {
  const auto launch_bytes = start_request(false);
  const auto launch_map = cbor::decode(launch_bytes);
  ASSERT_TRUE(launch_map);
  EXPECT_EQ(std::get<cbor::Value::Map>(launch_map.value->storage).size(), 16U);
  const auto launch = lsp::decode_start(launch_bytes);
  ASSERT_TRUE(launch);
  EXPECT_EQ(launch->application_id, "1");
  EXPECT_FALSE(launch->resume);

  const auto resume = lsp::decode_start(start_request(true));
  ASSERT_TRUE(resume);
  EXPECT_TRUE(resume->resume);

  auto legacy = cbor::decode(launch_bytes);
  ASSERT_TRUE(legacy);
  std::get<cbor::Value::Map>(legacy.value->storage)[1].second = cbor::Value {std::string {"1"}};
  EXPECT_FALSE(lsp::decode_start(cbor::encode(*legacy.value).bytes));
}

TEST(LspProductControlWire, PublishesAuthoritativeApplicationRunningAndResumeState) {
  const std::array applications {
    lsp::ControlApplication {
      .id = "1",
      .name = "Idle",
    },
    lsp::ControlApplication {
      .id = "2",
      .name = "Running",
      .running = true,
      .resume_available = true,
      .process_generation = 9,
    },
  };
  const auto encoded = lsp::encode_applications(applications);
  ASSERT_TRUE(encoded);
  const auto decoded = cbor::decode(*encoded);
  ASSERT_TRUE(decoded);
  const auto &top = std::get<cbor::Value::Map>(decoded.value->storage);
  const auto &entries = std::get<cbor::Value::Array>(top[2].second.storage);
  ASSERT_EQ(entries.size(), 2U);
  const auto &idle = std::get<cbor::Value::Map>(entries[0].storage);
  const auto &running = std::get<cbor::Value::Map>(entries[1].storage);
  EXPECT_EQ(idle.size(), 6U);
  EXPECT_FALSE(std::get<bool>(idle[3].second.storage));
  EXPECT_EQ(std::get<std::uint64_t>(idle[5].second.storage), 0U);
  EXPECT_EQ(running.size(), 6U);
  EXPECT_TRUE(std::get<bool>(running[3].second.storage));
  EXPECT_TRUE(std::get<bool>(running[4].second.storage));
  EXPECT_EQ(std::get<std::uint64_t>(running[5].second.storage), 9U);

  auto invalid = applications[0];
  invalid.resume_available = true;
  EXPECT_FALSE(lsp::encode_applications(std::span<const lsp::ControlApplication> {&invalid, 1}));
}

TEST(LspProductControlWire, FreezesQuitTextAndTerminalMaps) {
  const auto session = filled<16>(7);
  const auto quit = cbor::encode(cbor::Value {cbor::Value::Map {
                                   {1, lumen::lsp::wire_version},
                                   {2, bytes(session)},
                                   {3, std::string {"steam"}},
                                 }})
                      .bytes;
  const auto decoded_quit = lsp::decode_quit_application(quit);
  ASSERT_TRUE(decoded_quit);
  EXPECT_EQ(decoded_quit->application_id, "steam");
  const auto quit_response = lsp::encode_quit_application_response({
    .session_id = session,
  });
  ASSERT_TRUE(quit_response);
  EXPECT_EQ(map_size(*quit_response), 3U);

  const std::array<std::uint8_t, 5> utf8 {'h', 'e', 'l', 'l', 'o'};
  const auto text = cbor::encode(cbor::Value {cbor::Value::Map {
                                   {1, lumen::lsp::wire_version},
                                   {2, bytes(session)},
                                   {3, 9U},
                                   {4, 11U},
                                   {5, utf8.size()},
                                   {6, bytes(utf8)},
                                   {7, cbor::Value {cbor::Null {}}},
                                   {8, cbor::Value {cbor::Null {}}},
                                 }})
                      .bytes;
  const auto decoded_text = lsp::decode_text_input(text);
  ASSERT_TRUE(decoded_text);
  EXPECT_EQ(decoded_text->inline_utf8.size(), utf8.size());
  const auto text_response = lsp::encode_text_input_response({
    .session_id = session,
    .input_generation = 9,
    .preceding_edge_id = 11,
  });
  ASSERT_TRUE(text_response);
  EXPECT_EQ(map_size(*text_response), 5U);

  const auto ended = lsp::encode_stream_ended({
    .session_id = session,
    .stream_generation = 12,
    .reason = 1,
  });
  ASSERT_TRUE(ended);
  EXPECT_EQ(map_size(*ended), 4U);
}

TEST(LspProductControlWire, FreezesInputRateRequestAndFourteenKeyResponse) {
  const auto session = filled<16>(8);
  const auto request = cbor::encode(cbor::Value {cbor::Value::Map {
                                      {1, lumen::lsp::wire_version},
                                      {2, bytes(session)},
                                      {3, 4U},
                                      {4, static_cast<std::uint8_t>(lsp::InputRateDeviceType::controller)},
                                      {5, 2U},
                                      {6, 3U},
                                      {7, 1'000U},
                                      {8, 125U},
                                      {9, 1'000U},
                                      {10, 125U},
                                      {11, 500U},
                                      {12, 96U},
                                      {13, 32U},
                                    }})
                         .bytes;
  const auto decoded = lsp::decode_input_rate_request(request);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->device_id, 2U);
  const auto removal = cbor::encode(cbor::Value {cbor::Value::Map {
                                      {1, lumen::lsp::wire_version},
                                      {2, bytes(session)},
                                      {3, 4U},
                                      {4, static_cast<std::uint8_t>(lsp::InputRateDeviceType::controller)},
                                      {5, 2U},
                                      {6, 3U},
                                      {7, 0U},
                                      {8, 0U},
                                      {9, 0U},
                                      {10, 0U},
                                      {11, 0U},
                                      {12, 0U},
                                      {13, 0U},
                                    }})
                         .bytes;
  const auto decoded_removal = lsp::decode_input_rate_request(removal);
  ASSERT_TRUE(decoded_removal);
  EXPECT_EQ(decoded_removal->maximum_state_rate, 0U);
  EXPECT_EQ(decoded_removal->maximum_sensor_rate, 0U);
  auto partial_removal = cbor::decode(removal);
  ASSERT_TRUE(partial_removal);
  auto &partial_removal_map = std::get<cbor::Value::Map>(partial_removal.value->storage);
  partial_removal_map[11].second = cbor::Value {96U};
  EXPECT_FALSE(lsp::decode_input_rate_request(cbor::encode(*partial_removal.value).bytes));
  const auto response = lsp::encode_input_rate_response({
    .session_id = session,
    .input_generation = 4,
    .device_type = lsp::InputRateDeviceType::controller,
    .device_id = 2,
    .instance_generation = 3,
    .state_rate = 1'000,
    .sensor_rate = 500,
    .pointer_rate = 8'000,
    .controller_rate = 1'000,
    .aggregate_sensor_rate = 500,
    .reconciliation_rate = 250,
    .reserved_input_wire_bits_per_second = 2'000'000,
  });
  ASSERT_TRUE(response);
  EXPECT_EQ(map_size(*response), 14U);
  const auto removal_response = lsp::encode_input_rate_response({
    .session_id = session,
    .input_generation = 4,
    .device_type = lsp::InputRateDeviceType::controller,
    .device_id = 2,
    .instance_generation = 3,
    .state_rate = 0,
    .sensor_rate = 0,
    .pointer_rate = 8'000,
    .controller_rate = 1'000,
    .aggregate_sensor_rate = 500,
    .reconciliation_rate = 250,
    .reserved_input_wire_bits_per_second = 1'900'000,
  });
  ASSERT_TRUE(removal_response);
  EXPECT_EQ(map_size(*removal_response), 14U);
}

TEST(LspProductControlWire, FreezesRequestAndResponseFlagObjectChunkPayloads) {
  const auto object_id = filled<16>(9);
  const auto digest = filled<32>(10);
  const std::array<std::uint8_t, 4> chunk_bytes {1, 2, 3, 4};
  const lsp::ObjectChunkPayload chunk {
    .object_id = object_id,
    .offset = 0,
    .total_length = 4,
    .bytes = {chunk_bytes.begin(), chunk_bytes.end()},
    .sha256 = digest,
  };
  const auto encoded = lsp::encode_object_chunk(chunk);
  ASSERT_TRUE(encoded);
  EXPECT_EQ(map_size(*encoded), 6U);
  const auto decoded = lsp::decode_object_chunk(*encoded);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->bytes.size(), 4U);

  const auto acknowledgement = lsp::encode_object_chunk_ack({
    .object_id = object_id,
    .next_offset = 4,
    .total_length = 4,
  });
  ASSERT_TRUE(acknowledgement);
  EXPECT_EQ(map_size(*acknowledgement), 5U);
  ASSERT_TRUE(lsp::decode_object_chunk_ack(*acknowledgement));
}
