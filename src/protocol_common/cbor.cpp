/**
 * @file src/protocol_common/cbor.cpp
 * @brief Restricted deterministic-CBOR implementation shared by Lumen protocols.
 */

#include "cbor.h"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <type_traits>

namespace lumen::protocol_common::cbor {
  namespace {
    constexpr std::uint8_t major_shift = 5;
    constexpr std::uint8_t argument_mask = 0x1f;

    struct Head {
      std::uint8_t major {};
      std::uint64_t argument {};
    };

    void append_be(std::vector<std::uint8_t> &output, const std::uint64_t value, const std::size_t width) {
      for (std::size_t index = width; index > 0; --index) {
        output.push_back(static_cast<std::uint8_t>(value >> ((index - 1) * 8)));
      }
    }

    bool append_head(std::vector<std::uint8_t> &output, const std::uint8_t major, const std::uint64_t argument, const Limits &limits) {
      if (output.size() >= limits.max_encoded_bytes) {
        return false;
      }

      const auto base = static_cast<std::uint8_t>(major << major_shift);
      if (argument < 24) {
        output.push_back(static_cast<std::uint8_t>(base | argument));
      } else if (argument <= std::numeric_limits<std::uint8_t>::max()) {
        output.push_back(static_cast<std::uint8_t>(base | 24));
        append_be(output, argument, 1);
      } else if (argument <= std::numeric_limits<std::uint16_t>::max()) {
        output.push_back(static_cast<std::uint8_t>(base | 25));
        append_be(output, argument, 2);
      } else if (argument <= std::numeric_limits<std::uint32_t>::max()) {
        output.push_back(static_cast<std::uint8_t>(base | 26));
        append_be(output, argument, 4);
      } else {
        output.push_back(static_cast<std::uint8_t>(base | 27));
        append_be(output, argument, 8);
      }
      return output.size() <= limits.max_encoded_bytes;
    }

    Error encode_value(const Value &value, std::vector<std::uint8_t> &output, const Limits &limits, const std::size_t container_depth) {
      return std::visit(
        [&](const auto &item) -> Error {
          using Item = std::decay_t<decltype(item)>;
          if constexpr (std::is_same_v<Item, std::uint64_t>) {
            return append_head(output, 0, item, limits) ? Error::none : Error::encoded_size_limit;
          } else if constexpr (std::is_same_v<Item, Negative>) {
            return append_head(output, 1, item.argument, limits) ? Error::none : Error::encoded_size_limit;
          } else if constexpr (std::is_same_v<Item, Value::Bytes>) {
            if (item.size() > limits.max_byte_string_bytes) {
              return Error::byte_string_size_limit;
            }
            if (!append_head(output, 2, item.size(), limits) || item.size() > limits.max_encoded_bytes - output.size()) {
              return Error::encoded_size_limit;
            }
            output.insert(output.end(), item.begin(), item.end());
            return Error::none;
          } else if constexpr (std::is_same_v<Item, std::string>) {
            if (!is_valid_utf8(item)) {
              return Error::invalid_utf8;
            }
            if (item.size() > limits.max_text_bytes) {
              return Error::text_size_limit;
            }
            if (!append_head(output, 3, item.size(), limits) || item.size() > limits.max_encoded_bytes - output.size()) {
              return Error::encoded_size_limit;
            }
            output.insert(output.end(), item.begin(), item.end());
            return Error::none;
          } else if constexpr (std::is_same_v<Item, Value::Array>) {
            if (item.size() > limits.max_array_elements) {
              return Error::array_size_limit;
            }
            if (container_depth >= limits.max_container_depth) {
              return Error::nesting_limit;
            }
            if (!append_head(output, 4, item.size(), limits)) {
              return Error::encoded_size_limit;
            }
            for (const auto &child : item) {
              if (const auto error = encode_value(child, output, limits, container_depth + 1); error != Error::none) {
                return error;
              }
            }
            return Error::none;
          } else if constexpr (std::is_same_v<Item, Value::Map>) {
            if (item.size() > limits.max_map_entries) {
              return Error::map_size_limit;
            }
            if (container_depth >= limits.max_container_depth) {
              return Error::nesting_limit;
            }

            std::vector<const std::pair<std::uint64_t, Value> *> sorted;
            sorted.reserve(item.size());
            for (const auto &entry : item) {
              sorted.push_back(&entry);
            }
            std::sort(sorted.begin(), sorted.end(), [](const auto *left, const auto *right) {
              return left->first < right->first;
            });
            for (std::size_t index = 1; index < sorted.size(); ++index) {
              if (sorted[index - 1]->first == sorted[index]->first) {
                return Error::duplicate_map_key;
              }
            }

            if (!append_head(output, 5, sorted.size(), limits)) {
              return Error::encoded_size_limit;
            }
            for (const auto *entry : sorted) {
              if (!append_head(output, 0, entry->first, limits)) {
                return Error::encoded_size_limit;
              }
              if (const auto error = encode_value(entry->second, output, limits, container_depth + 1); error != Error::none) {
                return error;
              }
            }
            return Error::none;
          } else if constexpr (std::is_same_v<Item, bool>) {
            if (output.size() >= limits.max_encoded_bytes) {
              return Error::encoded_size_limit;
            }
            output.push_back(item ? 0xf5 : 0xf4);
            return Error::none;
          } else {
            if (output.size() >= limits.max_encoded_bytes) {
              return Error::encoded_size_limit;
            }
            output.push_back(0xf6);
            return Error::none;
          }
        },
        value.storage
      );
    }

    class Decoder {
    public:
      Decoder(const std::span<const std::uint8_t> input, const Limits &limits):
          input_ {input},
          limits_ {limits} {
      }

      std::optional<Value> parse_value(const std::size_t container_depth) {
        const auto head = parse_head();
        if (!head) {
          return std::nullopt;
        }

        switch (head->major) {
          case 0:
            return Value {head->argument};
          case 1:
            return Value {Negative {head->argument}};
          case 2:
            return parse_bytes(head->argument);
          case 3:
            return parse_text(head->argument);
          case 4:
            return parse_array(head->argument, container_depth);
          case 5:
            return parse_map(head->argument, container_depth);
          case 7:
            if (head->argument == 20) {
              return Value {false};
            }
            if (head->argument == 21) {
              return Value {true};
            }
            if (head->argument == 22) {
              return Value {Null {}};
            }
            set_error(Error::unsupported_type);
            return std::nullopt;
          default:
            set_error(Error::unsupported_type);
            return std::nullopt;
        }
      }

      Error error() const noexcept {
        return error_;
      }

      std::size_t position() const noexcept {
        return position_;
      }

    private:
      std::optional<Head> parse_head() {
        if (position_ >= input_.size()) {
          set_error(Error::truncated);
          return std::nullopt;
        }

        const auto initial = input_[position_++];
        const auto major = static_cast<std::uint8_t>(initial >> major_shift);
        const auto additional = static_cast<std::uint8_t>(initial & argument_mask);
        if (additional < 24) {
          return Head {major, additional};
        }
        if (additional == 31) {
          set_error(Error::indefinite_length);
          return std::nullopt;
        }
        if (additional > 27) {
          set_error(Error::reserved_additional_information);
          return std::nullopt;
        }

        const std::array<std::size_t, 4> widths {1, 2, 4, 8};
        const auto width = widths[additional - 24];
        if (width > input_.size() - position_) {
          set_error(Error::truncated);
          return std::nullopt;
        }
        std::uint64_t argument = 0;
        for (std::size_t index = 0; index < width; ++index) {
          argument = (argument << 8) | input_[position_++];
        }
        constexpr std::array<std::uint64_t, 4> minimums {24, 256, 65'536, 4'294'967'296ULL};
        if (argument < minimums[additional - 24]) {
          set_error(Error::non_minimal_argument);
          return std::nullopt;
        }
        return Head {major, argument};
      }

      std::optional<Value> parse_bytes(const std::uint64_t size) {
        if (size > limits_.max_byte_string_bytes) {
          set_error(Error::byte_string_size_limit);
          return std::nullopt;
        }
        if (size > input_.size() - position_) {
          set_error(Error::truncated);
          return std::nullopt;
        }
        Value::Bytes bytes(input_.begin() + static_cast<std::ptrdiff_t>(position_), input_.begin() + static_cast<std::ptrdiff_t>(position_ + size));
        position_ += static_cast<std::size_t>(size);
        return Value {std::move(bytes)};
      }

      std::optional<Value> parse_text(const std::uint64_t size) {
        if (size > limits_.max_text_bytes) {
          set_error(Error::text_size_limit);
          return std::nullopt;
        }
        if (size > input_.size() - position_) {
          set_error(Error::truncated);
          return std::nullopt;
        }
        std::string text(input_.begin() + static_cast<std::ptrdiff_t>(position_), input_.begin() + static_cast<std::ptrdiff_t>(position_ + size));
        position_ += static_cast<std::size_t>(size);
        if (!is_valid_utf8(text)) {
          set_error(Error::invalid_utf8);
          return std::nullopt;
        }
        return Value {std::move(text)};
      }

      std::optional<Value> parse_array(const std::uint64_t size, const std::size_t container_depth) {
        if (size > limits_.max_array_elements) {
          set_error(Error::array_size_limit);
          return std::nullopt;
        }
        if (container_depth >= limits_.max_container_depth) {
          set_error(Error::nesting_limit);
          return std::nullopt;
        }
        Value::Array array;
        array.reserve(static_cast<std::size_t>(size));
        for (std::uint64_t index = 0; index < size; ++index) {
          auto child = parse_value(container_depth + 1);
          if (!child) {
            return std::nullopt;
          }
          array.push_back(std::move(*child));
        }
        return Value {std::move(array)};
      }

      std::optional<Value> parse_map(const std::uint64_t size, const std::size_t container_depth) {
        if (size > limits_.max_map_entries) {
          set_error(Error::map_size_limit);
          return std::nullopt;
        }
        if (container_depth >= limits_.max_container_depth) {
          set_error(Error::nesting_limit);
          return std::nullopt;
        }

        Value::Map map;
        map.reserve(static_cast<std::size_t>(size));
        std::optional<std::uint64_t> previous_key;
        for (std::uint64_t index = 0; index < size; ++index) {
          const auto key_head = parse_head();
          if (!key_head) {
            return std::nullopt;
          }
          if (key_head->major != 0) {
            set_error(Error::map_key_not_unsigned);
            return std::nullopt;
          }
          if (previous_key && key_head->argument == *previous_key) {
            set_error(Error::duplicate_map_key);
            return std::nullopt;
          }
          if (previous_key && key_head->argument < *previous_key) {
            set_error(Error::non_deterministic_map_order);
            return std::nullopt;
          }

          auto mapped = parse_value(container_depth + 1);
          if (!mapped) {
            return std::nullopt;
          }
          previous_key = key_head->argument;
          map.emplace_back(key_head->argument, std::move(*mapped));
        }
        return Value {std::move(map)};
      }

      void set_error(const Error error) noexcept {
        if (error_ == Error::none) {
          error_ = error;
        }
      }

      std::span<const std::uint8_t> input_;
      const Limits &limits_;
      std::size_t position_ {};
      Error error_ {Error::none};
    };
  }  // namespace

  Value::Value(const Negative value):
      storage {value} {
  }

  Value::Value(Bytes value):
      storage {std::move(value)} {
  }

  Value::Value(std::string value):
      storage {std::move(value)} {
  }

  Value::Value(const std::string_view value):
      storage {std::string {value}} {
  }

  Value::Value(Array value):
      storage {std::move(value)} {
  }

  Value::Value(Map value):
      storage {std::move(value)} {
  }

  Value::Value(const bool value):
      storage {value} {
  }

  Value::Value(const Null value):
      storage {value} {
  }

  std::optional<Value> Value::from_negative(const std::int64_t value) {
    if (value >= 0) {
      return std::nullopt;
    }
    return Value {Negative {static_cast<std::uint64_t>(-(value + 1))}};
  }

  EncodeResult::operator bool() const noexcept {
    return error == Error::none;
  }

  DecodeResult::operator bool() const noexcept {
    return error == Error::none && value.has_value();
  }

  EncodeResult encode(const Value &value, const Limits &limits) {
    try {
      EncodeResult result;
      result.bytes.reserve(256);
      result.error = encode_value(value, result.bytes, limits, 0);
      if (result.error != Error::none) {
        result.bytes.clear();
      }
      return result;
    } catch (const std::bad_alloc &) {
      return {{}, Error::allocation_failure};
    }
  }

  DecodeResult decode(const std::span<const std::uint8_t> bytes, const Limits &limits) {
    if (bytes.empty()) {
      return {std::nullopt, Error::empty_input, 0};
    }
    if (bytes.size() > limits.max_encoded_bytes) {
      return {std::nullopt, Error::encoded_size_limit, 0};
    }

    try {
      Decoder decoder {bytes, limits};
      auto value = decoder.parse_value(0);
      if (!value) {
        return {std::nullopt, decoder.error(), decoder.position()};
      }
      if (decoder.position() != bytes.size()) {
        return {std::nullopt, Error::trailing_bytes, decoder.position()};
      }
      return {std::move(value), Error::none, decoder.position()};
    } catch (const std::bad_alloc &) {
      return {std::nullopt, Error::allocation_failure, 0};
    }
  }

  bool is_valid_utf8(const std::string_view text) noexcept {
    const auto *data = reinterpret_cast<const unsigned char *>(text.data());
    std::size_t index = 0;
    while (index < text.size()) {
      const auto first = data[index++];
      if (first <= 0x7f) {
        continue;
      }

      std::uint32_t codepoint = 0;
      std::size_t continuation_count = 0;
      std::uint32_t minimum = 0;
      if (first >= 0xc2 && first <= 0xdf) {
        codepoint = first & 0x1f;
        continuation_count = 1;
        minimum = 0x80;
      } else if (first >= 0xe0 && first <= 0xef) {
        codepoint = first & 0x0f;
        continuation_count = 2;
        minimum = 0x800;
      } else if (first >= 0xf0 && first <= 0xf4) {
        codepoint = first & 0x07;
        continuation_count = 3;
        minimum = 0x10000;
      } else {
        return false;
      }

      if (continuation_count > text.size() - index) {
        return false;
      }
      for (std::size_t continuation = 0; continuation < continuation_count; ++continuation) {
        const auto byte = data[index++];
        if ((byte & 0xc0) != 0x80) {
          return false;
        }
        codepoint = (codepoint << 6) | (byte & 0x3f);
      }
      if (codepoint < minimum || codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
        return false;
      }
    }
    return true;
  }

  std::string_view error_name(const Error error) noexcept {
    switch (error) {
      case Error::none:
        return "none";
      case Error::empty_input:
        return "empty input";
      case Error::encoded_size_limit:
        return "encoded size limit";
      case Error::truncated:
        return "truncated";
      case Error::reserved_additional_information:
        return "reserved additional information";
      case Error::indefinite_length:
        return "indefinite length";
      case Error::non_minimal_argument:
        return "non-minimal argument";
      case Error::unsupported_type:
        return "unsupported type";
      case Error::invalid_utf8:
        return "invalid UTF-8";
      case Error::text_size_limit:
        return "text size limit";
      case Error::byte_string_size_limit:
        return "byte-string size limit";
      case Error::array_size_limit:
        return "array size limit";
      case Error::map_size_limit:
        return "map size limit";
      case Error::nesting_limit:
        return "nesting limit";
      case Error::map_key_not_unsigned:
        return "map key is not unsigned";
      case Error::duplicate_map_key:
        return "duplicate map key";
      case Error::non_deterministic_map_order:
        return "non-deterministic map order";
      case Error::trailing_bytes:
        return "trailing bytes";
      case Error::allocation_failure:
        return "allocation failure";
    }
    return "unknown";
  }
}  // namespace lumen::protocol_common::cbor
