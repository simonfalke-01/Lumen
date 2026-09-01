/**
 * @file tests/integration/test_lsp_wolfssl_spake2.cpp
 * @brief RFC 9382 vectors and live bilateral tests for the wolfSSL LSP SPAKE2 provider.
 */

#include "src/protocol_lsp/security/wolfssl_spake2.h"

#include <gtest/gtest.h>

#if LUMEN_LSP_WOLFSSL_AVAILABLE

  #include <array>
  #include <cstdint>
  #include <span>
  #include <string_view>

namespace {
  namespace lsp = lumen::lsp;

  /**
   * @brief Decode one fixed-size lowercase hexadecimal test vector.
   *
   * @tparam Size Output byte count.
   * @param input Exact hexadecimal input.
   * @return Decoded bytes.
   */
  template<std::size_t Size>
  std::array<std::uint8_t, Size> decode_hex(const std::string_view input) {
    EXPECT_EQ(input.size(), Size * 2);
    std::array<std::uint8_t, Size> output {};
    const auto nibble = [](const char value) -> std::uint8_t {
      if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
      }
      if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
      }
      ADD_FAILURE() << "invalid hexadecimal test vector";
      return 0;
    };
    for (std::size_t index = 0; index < output.size(); ++index) {
      output[index] = static_cast<std::uint8_t>(
        (nibble(input[index * 2]) << 4U) | nibble(input[index * 2 + 1])
      );
    }
    return output;
  }

  /**
   * @brief View ASCII test identity bytes.
   *
   * @param value ASCII value.
   * @return Non-owning byte span.
   */
  std::span<const std::uint8_t> bytes(const std::string_view value) {
    return {reinterpret_cast<const std::uint8_t *>(value.data()), value.size()};
  }
}  // namespace

TEST(LspWolfsslSpake2, MatchesMandatoryRfc9382P256Vector) {
  const auto w = decode_hex<32>("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f");
  const auto x = decode_hex<32>("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729");
  const auto y = decode_hex<32>("dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be");
  const auto expected_point_a = decode_hex<65>(
    "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470"
    "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c"
  );
  const auto expected_point_b = decode_hex<65>(
    "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676"
    "d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7"
  );
  const auto expected_key = decode_hex<16>("0e0672dc86f8e45565d338b0540abe69");
  const auto expected_confirmation_a = decode_hex<32>(
    "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0"
  );
  const auto expected_confirmation_b = decode_hex<32>(
    "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b"
  );

  lsp::Spake2Status status = lsp::Spake2Status::crypto_failure;
  auto client = lsp::WolfsslSpake2ClientSession::create_for_test({
                                                                   .w = w,
                                                                   .ephemeral_scalar = x,
                                                                   .identity_a = bytes("server"),
                                                                   .identity_b = bytes("client"),
                                                                 },
                                                                 status);
  ASSERT_EQ(status, lsp::Spake2Status::success);
  ASSERT_NE(client, nullptr);
  auto host = lsp::WolfsslSpake2HostSession::create_for_test({
                                                               .w = w,
                                                               .ephemeral_scalar = y,
                                                               .identity_a = bytes("server"),
                                                               .identity_b = bytes("client"),
                                                             },
                                                             status);
  ASSERT_EQ(status, lsp::Spake2Status::success);
  ASSERT_NE(host, nullptr);

  lsp::Spake2Point point_a {};
  lsp::Spake2Point point_b {};
  lsp::Spake2Confirmation confirmation_a {};
  lsp::Spake2Confirmation confirmation_b {};
  lsp::Spake2SharedKey client_key {};
  lsp::Spake2SharedKey host_key {};
  ASSERT_EQ(client->start(point_a), lsp::Spake2Status::success);
  EXPECT_EQ(point_a, expected_point_a);
  ASSERT_EQ(host->receive_client_point(point_a, {}, point_b), lsp::Spake2Status::success);
  EXPECT_EQ(point_b, expected_point_b);
  ASSERT_EQ(client->receive_host_point(point_b, {}, confirmation_a), lsp::Spake2Status::success);
  EXPECT_EQ(confirmation_a, expected_confirmation_a);
  ASSERT_EQ(
    host->verify_client_confirmation(confirmation_a, confirmation_b, host_key),
    lsp::Spake2Status::success
  );
  EXPECT_EQ(confirmation_b, expected_confirmation_b);
  EXPECT_EQ(host_key, expected_key);
  ASSERT_EQ(client->verify_host_confirmation(confirmation_b, client_key), lsp::Spake2Status::success);
  EXPECT_EQ(client_key, expected_key);
}

TEST(LspWolfsslSpake2, DerivesFrozenPinToScalarVector) {
  std::array<std::uint8_t, 16> salt {};
  for (std::size_t index = 0; index < salt.size(); ++index) {
    salt[index] = static_cast<std::uint8_t>(index);
  }
  const auto expected = decode_hex<32>(
    "2c96fb20f5af7503bd94936a79d3e5e0a068ee179925f84628b9ca753cb0199d"
  );
  lsp::Spake2Scalar scalar;
  scalar.fill(0xff);
  EXPECT_EQ(
    lsp::derive_spake2_password_scalar_for_test("123456", salt, scalar),
    lsp::Spake2Status::success
  );
  EXPECT_EQ(scalar, expected);
}

TEST(LspWolfsslSpake2, CompletesLiveScryptExchangeWithChallengeBoundAad) {
  std::array<std::uint8_t, 16> salt {};
  for (std::size_t index = 0; index < salt.size(); ++index) {
    salt[index] = static_cast<std::uint8_t>(index + 1);
  }
  const auto identity_a = decode_hex<16>("00112233445566778899aabbccddeeff");
  const auto identity_b = decode_hex<16>("ffeeddccbbaa99887766554433221100");
  const auto aad = decode_hex<64>(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
  );
  lsp::Spake2Status status = lsp::Spake2Status::crypto_failure;
  auto client = lsp::WolfsslSpake2ClientSession::create({
                                                          .pin = "123456",
                                                          .salt = salt,
                                                          .identity_a = identity_a,
                                                          .identity_b = identity_b,
                                                        },
                                                        status);
  ASSERT_EQ(status, lsp::Spake2Status::success);
  ASSERT_NE(client, nullptr);
  auto host = lsp::WolfsslSpake2HostSession::create({
                                                      .pin = "123456",
                                                      .salt = salt,
                                                      .identity_a = identity_a,
                                                      .identity_b = identity_b,
                                                    },
                                                    status);
  ASSERT_EQ(status, lsp::Spake2Status::success);
  ASSERT_NE(host, nullptr);

  lsp::Spake2Point point_a {};
  lsp::Spake2Point point_b {};
  lsp::Spake2Confirmation confirmation_a {};
  lsp::Spake2Confirmation confirmation_b {};
  lsp::Spake2SharedKey client_key {};
  lsp::Spake2SharedKey host_key {};
  ASSERT_EQ(client->start(point_a), lsp::Spake2Status::success);
  ASSERT_EQ(host->receive_client_point(point_a, aad, point_b), lsp::Spake2Status::success);
  ASSERT_EQ(client->receive_host_point(point_b, aad, confirmation_a), lsp::Spake2Status::success);
  ASSERT_EQ(
    host->verify_client_confirmation(confirmation_a, confirmation_b, host_key),
    lsp::Spake2Status::success
  );
  ASSERT_EQ(client->verify_host_confirmation(confirmation_b, client_key), lsp::Spake2Status::success);
  EXPECT_EQ(client_key, host_key);
}

TEST(LspWolfsslSpake2, RejectsMalformedPinScalarPointAndConfirmation) {
  std::array<std::uint8_t, 16> salt {};
  salt.fill(1);
  lsp::Spake2Status status = lsp::Spake2Status::success;
  EXPECT_EQ(lsp::WolfsslSpake2ClientSession::create({
                                                      .pin = "12345x",
                                                      .salt = salt,
                                                    },
                                                    status),
            nullptr);
  EXPECT_EQ(status, lsp::Spake2Status::invalid_pin);

  lsp::Spake2Scalar invalid_scalar {};
  EXPECT_EQ(lsp::WolfsslSpake2ClientSession::create_for_test({
                                                               .w = invalid_scalar,
                                                               .ephemeral_scalar = invalid_scalar,
                                                             },
                                                             status),
            nullptr);
  EXPECT_EQ(status, lsp::Spake2Status::invalid_scalar);

  const auto w = decode_hex<32>("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f");
  const auto x = decode_hex<32>("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729");
  const auto y = decode_hex<32>("dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be");
  const auto order = decode_hex<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
  EXPECT_EQ(lsp::WolfsslSpake2ClientSession::create_for_test({
                                                               .w = w,
                                                               .ephemeral_scalar = order,
                                                             },
                                                             status),
            nullptr);
  EXPECT_EQ(status, lsp::Spake2Status::invalid_scalar);

  auto client = lsp::WolfsslSpake2ClientSession::create_for_test({
                                                                   .w = w,
                                                                   .ephemeral_scalar = x,
                                                                 },
                                                                 status);
  ASSERT_NE(client, nullptr);
  lsp::Spake2Point point_a {};
  ASSERT_EQ(client->start(point_a), lsp::Spake2Status::success);
  lsp::Spake2Point malformed_point {};
  malformed_point[0] = 0x04;
  lsp::Spake2Confirmation confirmation {};
  EXPECT_EQ(
    client->receive_host_point(malformed_point, {}, confirmation),
    lsp::Spake2Status::invalid_point
  );

  client = lsp::WolfsslSpake2ClientSession::create_for_test({
                                                              .w = w,
                                                              .ephemeral_scalar = x,
                                                            },
                                                            status);
  auto host = lsp::WolfsslSpake2HostSession::create_for_test({
                                                               .w = w,
                                                               .ephemeral_scalar = y,
                                                             },
                                                             status);
  ASSERT_NE(client, nullptr);
  ASSERT_NE(host, nullptr);
  lsp::Spake2Point point_b {};
  ASSERT_EQ(client->start(point_a), lsp::Spake2Status::success);
  ASSERT_EQ(host->receive_client_point(point_a, {}, point_b), lsp::Spake2Status::success);
  ASSERT_EQ(client->receive_host_point(point_b, {}, confirmation), lsp::Spake2Status::success);
  confirmation[0] ^= 1;
  lsp::Spake2Confirmation host_confirmation;
  lsp::Spake2SharedKey host_key;
  host_confirmation.fill(0xff);
  host_key.fill(0xff);
  EXPECT_EQ(
    host->verify_client_confirmation(confirmation, host_confirmation, host_key),
    lsp::Spake2Status::confirmation_failed
  );
  EXPECT_EQ(host_confirmation, lsp::Spake2Confirmation {});
  EXPECT_EQ(host_key, lsp::Spake2SharedKey {});
}

#endif
