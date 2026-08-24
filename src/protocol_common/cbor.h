/**
 * @file src/protocol_common/cbor.h
 * @brief Restricted deterministic-CBOR values and codec shared by Lumen protocols.
 */

#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace lumen::protocol_common::cbor {
  /**
   * @brief Protocol-v2 deterministic-CBOR resource limits.
   */
  struct Limits {
    std::size_t max_encoded_bytes {1'048'576};  ///< Maximum complete encoded CBOR item size.
    std::size_t max_byte_string_bytes {1'048'576};  ///< Maximum byte-string size.
    std::size_t max_text_bytes {65'535};  ///< Maximum UTF-8 text-string size.
    std::size_t max_array_elements {4'096};  ///< Maximum array cardinality.
    std::size_t max_map_entries {128};  ///< Maximum map cardinality.
    std::size_t max_container_depth {8};  ///< Maximum nested container count.
  };

  /**
   * @brief Negative CBOR integer represented by its major-type argument.
   *
   * The mathematical value is `-1 - argument`. This representation preserves
   * the complete CBOR negative-integer range without signed overflow.
   */
  struct Negative {
    std::uint64_t argument {};  ///< Encoded major-type-1 argument.

    bool operator==(const Negative &) const = default;
  };

  /**
   * @brief CBOR null marker.
   */
  struct Null {
    bool operator==(const Null &) const = default;
  };

  /**
   * @brief Restricted protocol-v2 CBOR value.
   */
  struct Value {
    using Bytes = std::vector<std::uint8_t>;  ///< CBOR byte string.
    using Array = std::vector<Value>;  ///< CBOR array.
    using Map = std::vector<std::pair<std::uint64_t, Value>>;  ///< Unsigned-key CBOR map.
    using Storage = std::variant<std::uint64_t, Negative, Bytes, std::string, Array, Map, bool, Null>;

    Storage storage {Null {}};  ///< Active CBOR value.

    Value() = default;  ///< Construct null.

    template<std::unsigned_integral Integer>
      requires(!std::same_as<std::remove_cv_t<Integer>, bool>)
    Value(const Integer value):
        storage {static_cast<std::uint64_t>(value)} {
    }  ///< Construct unsigned integer.

    Value(Negative value);  ///< Construct negative integer.
    Value(Bytes value);  ///< Construct byte string.
    Value(std::string value);  ///< Construct text string.
    Value(std::string_view value);  ///< Copy text string.

    template<std::size_t Size>
    Value(const char (&value)[Size]):
        storage {std::string {value, Size - 1}} {
    }  ///< Copy string literal.

    Value(Array value);  ///< Construct array.
    Value(Map value);  ///< Construct unsigned-key map.
    explicit Value(bool value);  ///< Construct boolean.
    Value(Null value);  ///< Construct null.

    /**
     * @brief Construct a negative value from a signed integer.
     *
     * @param value Strictly negative integer.
     * @return Negative CBOR value, or nullopt when value is nonnegative.
     */
    static std::optional<Value> from_negative(std::int64_t value);

    bool operator==(const Value &) const = default;
  };

  /**
   * @brief CBOR codec error.
   */
  enum class Error {
    none,
    empty_input,
    encoded_size_limit,
    truncated,
    reserved_additional_information,
    indefinite_length,
    non_minimal_argument,
    unsupported_type,
    invalid_utf8,
    text_size_limit,
    byte_string_size_limit,
    array_size_limit,
    map_size_limit,
    nesting_limit,
    map_key_not_unsigned,
    duplicate_map_key,
    non_deterministic_map_order,
    trailing_bytes,
    allocation_failure,
  };

  /**
   * @brief Result of deterministic CBOR encoding.
   */
  struct EncodeResult {
    std::vector<std::uint8_t> bytes;  ///< Deterministic bytes when successful.
    Error error {Error::none};  ///< Failure reason.

    explicit operator bool() const noexcept;
  };

  /**
   * @brief Result of strict deterministic CBOR decoding.
   */
  struct DecodeResult {
    std::optional<Value> value;  ///< Decoded value when successful.
    Error error {Error::none};  ///< Failure reason.
    std::size_t consumed {};  ///< Bytes consumed before success or failure.

    explicit operator bool() const noexcept;
  };

  /**
   * @brief Encode one restricted value using RFC 8949 deterministic ordering.
   *
   * @param value Value to encode.
   * @param limits Resource limits.
   * @return Deterministic bytes or a specific error.
   */
  EncodeResult encode(const Value &value, const Limits &limits = {});

  /**
   * @brief Decode exactly one restricted deterministic-CBOR item.
   *
   * @param bytes Complete encoded item.
   * @param limits Resource limits.
   * @return Decoded value or a specific error. Trailing bytes are rejected.
   */
  DecodeResult decode(std::span<const std::uint8_t> bytes, const Limits &limits = {});

  /**
   * @brief Validate a string as well-formed UTF-8.
   *
   * @param text Candidate UTF-8 bytes.
   * @return True only for shortest-form Unicode scalar encodings.
   */
  bool is_valid_utf8(std::string_view text) noexcept;

  /**
   * @brief Return a stable diagnostic name for a codec error.
   *
   * @param error Error value.
   * @return Static diagnostic string.
   */
  std::string_view error_name(Error error) noexcept;
}  // namespace lumen::protocol_common::cbor
