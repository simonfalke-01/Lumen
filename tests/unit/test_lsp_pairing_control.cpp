/**
 * @file tests/unit/test_lsp_pairing_control.cpp
 * @brief Exact deterministic-CBOR checks for LSP PIN pairing control maps.
 */

#include "src/protocol_common/cbor.h"
#include "src/protocol_lsp/runtime/control/wire.h"
#include "src/protocol_lsp/runtime/control_server.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <variant>
#include <vector>

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

  std::vector<std::uint8_t> begin_payload(
    const std::array<std::uint8_t, lsp::pairing_spake_point_size> &point,
    const std::string &name = "Umbra Mac"
  ) {
    return cbor::encode(cbor::Value {cbor::Value::Map {
                          {1, lumen::lsp::wire_version},
                          {2, lsp::pairing_schema_version},
                          {3, bytes(filled<16>(1))},
                          {4, bytes(filled<32>(2))},
                          {5, name},
                          {6, bytes(filled<16>(3))},
                          {7, bytes(filled<16>(4))},
                          {8, bytes(point)},
                          {9, lumen::lsp::PermissionSet::default_pairing_mask},
                        }})
      .bytes;
  }
}  // namespace

TEST(LspPinPairingWire, DecodesExactNineKeyBeginAndRejectsShapePointAndNameChanges) {
  auto point_a = filled<lsp::pairing_spake_point_size>(5);
  point_a[0] = 0x04;
  const auto decoded = lsp::decode_pair_begin(begin_payload(point_a));
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->client_id, filled<16>(1));
  EXPECT_EQ(decoded->client_identity_key, filled<32>(2));
  EXPECT_EQ(decoded->client_name, "Umbra Mac");
  EXPECT_EQ(decoded->client_pairing_nonce, filled<16>(3));
  EXPECT_EQ(decoded->scrypt_salt, filled<16>(4));
  EXPECT_EQ(decoded->point_a, point_a);
  EXPECT_EQ(decoded->requested_permissions.mask(), lumen::lsp::PermissionSet::default_pairing_mask);

  auto invalid_point = point_a;
  invalid_point[0] = 0x03;
  EXPECT_FALSE(lsp::decode_pair_begin(begin_payload(invalid_point)));
  EXPECT_FALSE(lsp::decode_pair_begin(begin_payload(point_a, "")));
  EXPECT_FALSE(lsp::decode_pair_begin(begin_payload(point_a, std::string(65, 'x'))));
}

TEST(LspPinPairingWire, FreezesPendingPollChallengeFinishAndResultMaps) {
  const auto permissions = lumen::lsp::PermissionSet::default_pairing();
  const auto session_id = filled<16>(7);
  const auto pending = lsp::encode_pair_pending({
    .pairing_session_id = session_id,
    .expires_at_utc_seconds = 1'900'000'120,
    .effective_permissions = permissions,
  });
  ASSERT_TRUE(pending);
  const auto pending_value = cbor::decode(*pending);
  ASSERT_TRUE(pending_value);
  EXPECT_EQ(std::get<cbor::Value::Map>(pending_value.value->storage).size(), 6U);

  const auto poll = cbor::encode(cbor::Value {cbor::Value::Map {
                                   {1, lumen::lsp::wire_version},
                                   {2, lsp::pairing_schema_version},
                                   {3, bytes(session_id)},
                                 }})
                      .bytes;
  const auto decoded_poll = lsp::decode_pair_poll(poll);
  ASSERT_TRUE(decoded_poll);
  EXPECT_EQ(decoded_poll->pairing_session_id, session_id);

  auto point_b = filled<lsp::pairing_spake_point_size>(8);
  point_b[0] = 0x04;
  const auto challenge = lsp::encode_pair_challenge({
    .pairing_session_id = session_id,
    .approval_generation = 2,
    .point_b = point_b,
    .effective_permissions = permissions,
    .expires_at_utc_seconds = 1'900'000'120,
  });
  ASSERT_TRUE(challenge);
  const auto challenge_value = cbor::decode(*challenge);
  ASSERT_TRUE(challenge_value);
  EXPECT_EQ(std::get<cbor::Value::Map>(challenge_value.value->storage).size(), 7U);

  const auto finish = cbor::encode(cbor::Value {cbor::Value::Map {
                                     {1, lumen::lsp::wire_version},
                                     {2, lsp::pairing_schema_version},
                                     {3, bytes(session_id)},
                                     {4, 2U},
                                     {5, bytes(filled<32>(9))},
                                     {6, bytes(filled<64>(10))},
                                   }})
                        .bytes;
  const auto decoded_finish = lsp::decode_pair_finish(finish);
  ASSERT_TRUE(decoded_finish);
  EXPECT_EQ(decoded_finish->approval_generation, 2U);

  const auto result = lsp::encode_pair_result({
    .pairing_session_id = session_id,
    .approval_generation = 2,
    .permissions = permissions,
    .revocation_generation = 1,
    .confirmation_b = filled<32>(11),
    .host_signature = filled<64>(12),
  });
  ASSERT_TRUE(result);
  const auto result_value = cbor::decode(*result);
  ASSERT_TRUE(result_value);
  EXPECT_EQ(std::get<cbor::Value::Map>(result_value.value->storage).size(), 9U);
}

TEST(LspPinPairingTranscript, FreezesExactEighteenFieldDedicatedExporterAad) {
  const auto requested = lumen::lsp::PermissionSet::default_pairing();
  const auto effective = *lumen::lsp::PermissionSet::from_mask(
    requested.mask() & ~static_cast<std::uint32_t>(lumen::lsp::Permission::controller_output)
  );
  const auto aad = lsp::pairing_confirmation_aad({
    .host_id = filled<16>(1),
    .host_identity_key = filled<32>(2),
    .dtls_spki_sha256 = filled<32>(3),
    .client_id = filled<16>(4),
    .client_identity_key = filled<32>(5),
    .pairing_session_id = filled<16>(6),
    .client_pairing_nonce = filled<16>(7),
    .connection_generation = 8,
    .approval_generation = 9,
    .client_hello_nonce = filled<32>(10),
    .server_hello_nonce = filled<32>(11),
    .scrypt_salt = filled<16>(12),
    .requested_permissions = requested,
    .effective_permissions = effective,
    .expires_at_utc_seconds = 1'900'000'120,
    .pairing_exporter = filled<lsp::pairing_dtls_exporter_size>(13),
  });
  ASSERT_TRUE(aad);
  const auto decoded = cbor::decode(*aad);
  ASSERT_TRUE(decoded);
  const auto &map = std::get<cbor::Value::Map>(decoded.value->storage);
  ASSERT_EQ(map.size(), 18U);
  EXPECT_EQ(std::get<std::string>(map[0].second.storage), "lumen-stream/1 pin-pair aad");
  EXPECT_EQ(std::get<std::uint64_t>(map[1].second.storage), lsp::pairing_schema_version);
  EXPECT_EQ(std::get<std::uint64_t>(map[14].second.storage), requested.mask());
  EXPECT_EQ(std::get<std::uint64_t>(map[15].second.storage), effective.mask());
  EXPECT_EQ(std::get<cbor::Value::Bytes>(map[17].second.storage).size(), lsp::pairing_dtls_exporter_size);

  const auto client = lsp::pairing_client_signature_transcript(*aad, filled<32>(14));
  const auto host = lsp::pairing_host_signature_transcript(*aad, filled<32>(14), filled<32>(15), 1);
  ASSERT_TRUE(client);
  ASSERT_TRUE(host);
  EXPECT_EQ(std::get<cbor::Value::Map>(cbor::decode(*client).value->storage).size(), 3U);
  EXPECT_EQ(std::get<cbor::Value::Map>(cbor::decode(*host).value->storage).size(), 5U);
}

TEST(LspPinPairingPoll, EnforcesFloorBackoffEarlyAbuseAndCooldown) {
  lsp::PairingPollLimiter limiter;
  EXPECT_EQ(limiter.admit(1'000'000), lsp::PairingPollResult::accepted);
  EXPECT_EQ(limiter.interval_microseconds, 40'000U);
  EXPECT_EQ(limiter.admit(1'000'001), lsp::PairingPollResult::too_early);
  EXPECT_EQ(limiter.admit(1'000'002), lsp::PairingPollResult::too_early);
  EXPECT_EQ(limiter.admit(1'000'003), lsp::PairingPollResult::too_early);
  EXPECT_EQ(limiter.admit(1'000'004), lsp::PairingPollResult::cooldown);
  EXPECT_EQ(limiter.admit(1'500'000), lsp::PairingPollResult::cooldown);
  EXPECT_EQ(limiter.admit(2'000'004), lsp::PairingPollResult::accepted);
  EXPECT_EQ(limiter.interval_microseconds, 80'000U);
}
