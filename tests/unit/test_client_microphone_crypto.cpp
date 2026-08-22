/**
 * @file tests/unit/test_client_microphone_crypto.cpp
 * @brief Verify microphone-specific HKDF-SHA-256 and AES-256-GCM behavior.
 */

// standard includes
#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

// lib includes
#include <gtest/gtest.h>

// local includes
#include <src/crypto.h>

namespace {
  /**
   * @brief Decode an even-length lowercase hexadecimal test vector.
   *
   * @param text Hexadecimal bytes.
   * @return Decoded byte vector.
   */
  std::vector<std::uint8_t> decode_hex(std::string_view text) {
    auto digit = [](char value) -> std::uint8_t {
      return value <= '9' ? static_cast<std::uint8_t>(value - '0') : static_cast<std::uint8_t>(value - 'a' + 10);
    };

    std::vector<std::uint8_t> bytes;
    bytes.reserve(text.size() / 2);
    for (std::size_t index = 0; index < text.size(); index += 2) {
      bytes.push_back(static_cast<std::uint8_t>((digit(text[index]) << 4U) | digit(text[index + 1])));
    }
    return bytes;
  }
}  // namespace

TEST(ClientMicrophoneCryptoTest, MatchesRfc5869Sha256CaseOne) {
  const std::vector<std::uint8_t> input_key_material(22, 0x0b);
  const auto salt = decode_hex("000102030405060708090a0b0c");
  const auto info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
  const auto expected = decode_hex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
  );

  const auto derived = crypto::hkdf_sha256(
    input_key_material,
    salt,
    {reinterpret_cast<const char *>(info.data()), info.size()},
    expected.size()
  );

  ASSERT_TRUE(derived.has_value());
  EXPECT_EQ(*derived, expected);
}

TEST(ClientMicrophoneCryptoTest, MatchesNistEmptyPlaintextTag) {
  crypto::aes_256_gcm_t::key_t key {};
  crypto::aes_256_gcm_t::nonce_t nonce {};
  crypto::aes_256_gcm_t cipher {key};
  crypto::aes_256_gcm_t::tag_t tag {};
  crypto::aes_t ciphertext;

  ASSERT_TRUE(cipher.encrypt({}, {}, nonce, ciphertext, tag));
  EXPECT_TRUE(ciphertext.empty());

  const auto expected = decode_hex("530f8afbc74536b9a963b4f1c4cb738b");
  EXPECT_TRUE(std::ranges::equal(tag, expected));
}

TEST(ClientMicrophoneCryptoTest, AuthenticatesAdditionalDataBeforePublishingPlaintext) {
  crypto::aes_256_gcm_t::key_t key {};
  for (std::size_t index = 0; index < key.size(); ++index) {
    key[index] = static_cast<std::uint8_t>(index);
  }

  crypto::aes_256_gcm_t::nonce_t nonce {};
  nonce.back() = 7;
  const std::array<std::uint8_t, 8> additional_data {0x4c, 0x4d, 0x43, 0x31, 0, 1, 2, 3};
  const std::array<std::uint8_t, 5> plaintext {1, 3, 5, 7, 9};
  crypto::aes_256_gcm_t cipher {key};
  crypto::aes_256_gcm_t::tag_t tag {};
  crypto::aes_t ciphertext;

  ASSERT_TRUE(cipher.encrypt(plaintext, additional_data, nonce, ciphertext, tag));

  crypto::aes_t recovered;
  ASSERT_TRUE(cipher.decrypt(ciphertext, additional_data, nonce, tag, recovered));
  EXPECT_TRUE(std::ranges::equal(recovered, plaintext));

  auto changed_additional_data = additional_data;
  changed_additional_data[5] ^= 1;
  const crypto::aes_t sentinel {0xaa};
  recovered = sentinel;
  EXPECT_FALSE(cipher.decrypt(ciphertext, changed_additional_data, nonce, tag, recovered));
  EXPECT_EQ(recovered, sentinel);
}
