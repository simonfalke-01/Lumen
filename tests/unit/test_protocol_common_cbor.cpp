/**
 * @file tests/unit/test_protocol_common_cbor.cpp
 * @brief Deterministic-CBOR hostile conformance tests.
 */

#include "src/protocol_common/cbor.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

namespace {
  namespace cbor = lumen::protocol_common::cbor;

  std::vector<std::uint8_t> hex(const std::string_view encoded) {
    std::vector<std::uint8_t> output;
    output.reserve(encoded.size() / 2);
    const auto nibble = [](const char value) -> std::uint8_t {
      if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
      }
      if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
      }
      return static_cast<std::uint8_t>(value - 'A' + 10);
    };
    for (std::size_t index = 0; index < encoded.size(); index += 2) {
      output.push_back(static_cast<std::uint8_t>((nibble(encoded[index]) << 4) | nibble(encoded[index + 1])));
    }
    return output;
  }

  cbor::Value nested_empty_arrays(const std::size_t count) {
    cbor::Value value {cbor::Value::Array {}};
    for (std::size_t index = 1; index < count; ++index) {
      cbor::Value::Array next;
      next.push_back(std::move(value));
      value = cbor::Value {std::move(next)};
    }
    return value;
  }
}  // namespace

TEST(ProtocolCommonCbor, EncodesEveryDeterministicArgumentBoundary) {
  struct Boundary {
    std::uint64_t value;
    std::string_view expected;
  };

  constexpr std::array boundaries {
    Boundary {23, "17"},
    Boundary {24, "1818"},
    Boundary {255, "18ff"},
    Boundary {256, "190100"},
    Boundary {65'535, "19ffff"},
    Boundary {65'536, "1a00010000"},
    Boundary {4'294'967'296ULL, "1b0000000100000000"},
  };
  for (const auto &[value, expected] : boundaries) {
    const auto encoded = cbor::encode(cbor::Value {value});
    ASSERT_TRUE(encoded) << cbor::error_name(encoded.error);
    EXPECT_EQ(encoded.bytes, hex(expected));
    const auto decoded = cbor::decode(encoded.bytes);
    ASSERT_TRUE(decoded) << cbor::error_name(decoded.error);
    EXPECT_EQ(decoded.value->storage, cbor::Value {value}.storage);
  }
}

TEST(ProtocolCommonCbor, DeterministicallySortsUnsignedMapKeys) {
  cbor::Value::Map map {{256, 3U}, {1, 1U}, {24, 2U}};
  const auto encoded = cbor::encode(cbor::Value {map});
  ASSERT_TRUE(encoded);
  EXPECT_EQ(encoded.bytes, hex("a3010118180219010003"));
}

TEST(ProtocolCommonCbor, SupportsApprovedScalarsAndRejectsUnsupportedTypes) {
  const auto negative = cbor::Value::from_negative(-24);
  ASSERT_TRUE(negative);
  EXPECT_EQ(cbor::encode(*negative).bytes, hex("37"));
  EXPECT_EQ(cbor::encode(cbor::Value {true}).bytes, hex("f5"));
  EXPECT_EQ(cbor::encode(cbor::Value {false}).bytes, hex("f4"));
  EXPECT_EQ(cbor::encode(cbor::Value {cbor::Null {}}).bytes, hex("f6"));

  for (const auto &malformed : {"c000", "f90000", "fa00000000", "fb0000000000000000", "f7"}) {
    const auto decoded = cbor::decode(hex(malformed));
    EXPECT_FALSE(decoded) << malformed;
  }
}

TEST(ProtocolCommonCbor, RejectsReservedIndefiniteAndNonMinimalArguments) {
  for (const auto &malformed : {"bc", "bd", "be"}) {
    const auto decoded = cbor::decode(hex(malformed));
    EXPECT_FALSE(decoded);
    EXPECT_EQ(decoded.error, cbor::Error::reserved_additional_information);
  }
  for (const auto &malformed : {"1f", "5f", "7f", "9f", "bf"}) {
    const auto decoded = cbor::decode(hex(malformed));
    EXPECT_FALSE(decoded);
    EXPECT_EQ(decoded.error, cbor::Error::indefinite_length);
  }
  for (const auto &malformed : {"1817", "1900ff", "1a0000ffff", "1b00000000ffffffff"}) {
    const auto decoded = cbor::decode(hex(malformed));
    EXPECT_FALSE(decoded);
    EXPECT_EQ(decoded.error, cbor::Error::non_minimal_argument);
  }
}

TEST(ProtocolCommonCbor, RejectsDuplicateNonDeterministicAndNonUnsignedMapKeys) {
  struct Case {
    std::string_view encoded;
    cbor::Error error;
  };

  constexpr std::array cases {
    Case {"a202000101", cbor::Error::non_deterministic_map_order},
    Case {"a201000101", cbor::Error::duplicate_map_key},
    Case {"a20100", cbor::Error::truncated},
    Case {"a1616100", cbor::Error::map_key_not_unsigned},
  };
  for (const auto &[encoded, error] : cases) {
    const auto decoded = cbor::decode(hex(encoded));
    EXPECT_FALSE(decoded) << encoded;
    EXPECT_EQ(decoded.error, error) << encoded;
  }
}

TEST(ProtocolCommonCbor, RejectsInvalidUtf8AndTrailingBytes) {
  for (const auto &invalid : {"61ff", "62c080", "63eda080", "64f4908080", "61c2"}) {
    const auto decoded = cbor::decode(hex(invalid));
    EXPECT_FALSE(decoded) << invalid;
  }
  const auto trailing = cbor::decode(hex("0102"));
  EXPECT_FALSE(trailing);
  EXPECT_EQ(trailing.error, cbor::Error::trailing_bytes);
}

TEST(ProtocolCommonCbor, EnforcesContainerAndCollectionLimits) {
  EXPECT_TRUE(cbor::encode(nested_empty_arrays(8)));
  EXPECT_EQ(cbor::encode(nested_empty_arrays(9)).error, cbor::Error::nesting_limit);
  auto eight_encoded = std::vector<std::uint8_t>(8, 0x81);
  eight_encoded.push_back(0xf6);
  EXPECT_TRUE(cbor::decode(eight_encoded));
  auto nine_encoded = std::vector<std::uint8_t>(9, 0x81);
  nine_encoded.push_back(0xf6);
  EXPECT_EQ(cbor::decode(nine_encoded).error, cbor::Error::nesting_limit);

  cbor::Value::Array oversized_array(4097, cbor::Value {0U});
  EXPECT_EQ(cbor::encode(cbor::Value {std::move(oversized_array)}).error, cbor::Error::array_size_limit);
  cbor::Value::Map oversized_map;
  for (std::uint64_t key = 0; key < 129; ++key) {
    oversized_map.emplace_back(key, cbor::Value {0U});
  }
  EXPECT_EQ(cbor::encode(cbor::Value {std::move(oversized_map)}).error, cbor::Error::map_size_limit);
  EXPECT_EQ(cbor::encode(cbor::Value {std::string(65'536, 'a')}).error, cbor::Error::text_size_limit);
}

TEST(ProtocolCommonCbor, DeterministicFuzzLikeCorpusRemainsBounded) {
  std::uint64_t state = 0x9e3779b97f4a7c15ULL;
  for (std::size_t sample = 0; sample < 10'000; ++sample) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    const auto length = static_cast<std::size_t>(state % 96);
    std::vector<std::uint8_t> bytes(length);
    for (auto &byte : bytes) {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      byte = static_cast<std::uint8_t>(state);
    }
    const auto decoded = cbor::decode(bytes);
    if (decoded) {
      const auto encoded = cbor::encode(*decoded.value);
      ASSERT_TRUE(encoded);
      EXPECT_EQ(encoded.bytes, bytes);
    }
  }
}
