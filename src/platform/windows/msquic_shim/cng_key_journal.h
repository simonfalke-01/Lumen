/**
 * @file src/platform/windows/msquic_shim/cng_key_journal.h
 * @brief Portable owned-key journal and reaper state machine for the MSVC shim.
 */

#ifndef LUMEN_MSQUIC_CNG_KEY_JOURNAL_H
#define LUMEN_MSQUIC_CNG_KEY_JOURNAL_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace lumen::msquic::cng {
  inline constexpr std::size_t maximum_journal_entries = 32;
  inline constexpr std::size_t maximum_identity_characters = 512;
  inline constexpr std::size_t maximum_serialized_bytes = 104'857;

  struct KeyIdentity {
    std::u16string provider;
    std::u16string container;
    std::u16string unique_name;
    bool machine_key {};

    friend bool operator==(const KeyIdentity &, const KeyIdentity &) = default;
  };

  inline bool same_locator(const KeyIdentity &left, const KeyIdentity &right) noexcept {
    return left.provider == right.provider &&
           left.container == right.container &&
           left.machine_key == right.machine_key;
  }

  inline bool valid_field(const std::u16string &value) noexcept {
    return !value.empty() && value.size() <= maximum_identity_characters &&
           std::ranges::find(value, u'\0') == value.end();
  }

  inline bool valid_identity(const KeyIdentity &identity) noexcept {
    return valid_field(identity.provider) &&
           valid_field(identity.container) &&
           valid_field(identity.unique_name);
  }

  enum class Status {
    success,
    already_owned,
    invalid_identity,
    invalid_journal,
    journal_full,
    storage_error,
    not_owned,
    cleanup_incomplete,
  };

  struct Result {
    Status status {Status::success};
    std::size_t deleted {};
    std::size_t freed {};
    std::size_t retained {};
    std::size_t skipped_unrelated {};
  };

  class JournalStore {
  public:
    virtual ~JournalStore() = default;
    virtual bool read(std::vector<KeyIdentity> &entries) noexcept = 0;
    virtual bool write(const std::vector<KeyIdentity> &entries) noexcept = 0;
  };

  class KeyBackend {
  public:
    using Handle = std::uintptr_t;

    enum class OpenStatus {
      opened,
      missing,
      error,
    };

    struct OpenResult {
      OpenStatus status {OpenStatus::error};
      Handle handle {};
      std::u16string unique_name;
    };

    virtual ~KeyBackend() = default;
    virtual OpenResult open(const KeyIdentity &identity) noexcept = 0;

    /**
     * @brief Delete a key; success consumes the handle per NCryptDeleteKey.
     */
    virtual bool delete_key(Handle handle) noexcept = 0;

    /** @brief Free a handle only when deletion did not consume it. */
    virtual void free_key(Handle handle) noexcept = 0;
  };

  namespace detail {
    inline bool valid_entries(const std::vector<KeyIdentity> &entries) noexcept {
      if (entries.size() > maximum_journal_entries) {
        return false;
      }
      for (std::size_t index = 0; index < entries.size(); ++index) {
        if (!valid_identity(entries[index])) {
          return false;
        }
        for (std::size_t previous = 0; previous < index; ++previous) {
          if (entries[index] == entries[previous] ||
              same_locator(entries[index], entries[previous])) {
            return false;
          }
        }
      }
      return true;
    }

    inline void append_u16(std::vector<std::uint8_t> &output, const std::uint16_t value) {
      output.push_back(static_cast<std::uint8_t>(value & 0xffu));
      output.push_back(static_cast<std::uint8_t>(value >> 8u));
    }

    inline void append_u32(std::vector<std::uint8_t> &output, const std::uint32_t value) {
      for (unsigned shift = 0; shift < 32; shift += 8) {
        output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
      }
    }

    inline bool read_u16(
      const std::vector<std::uint8_t> &input,
      std::size_t &offset,
      std::uint16_t &value
    ) noexcept {
      if (input.size() - offset < 2) {
        return false;
      }
      value = static_cast<std::uint16_t>(input[offset]) |
              static_cast<std::uint16_t>(input[offset + 1] << 8u);
      offset += 2;
      return true;
    }

    inline bool read_u32(
      const std::vector<std::uint8_t> &input,
      std::size_t &offset,
      std::uint32_t &value
    ) noexcept {
      if (input.size() - offset < 4) {
        return false;
      }
      value = 0;
      for (unsigned shift = 0; shift < 32; shift += 8) {
        value |= static_cast<std::uint32_t>(input[offset++]) << shift;
      }
      return true;
    }

    inline void append_field(std::vector<std::uint8_t> &output, const std::u16string &field) {
      append_u16(output, static_cast<std::uint16_t>(field.size()));
      for (const auto character : field) {
        append_u16(output, static_cast<std::uint16_t>(character));
      }
    }

    inline bool read_field(
      const std::vector<std::uint8_t> &input,
      std::size_t &offset,
      std::u16string &field
    ) {
      std::uint16_t length {};
      if (!read_u16(input, offset, length) || length == 0 ||
          length > maximum_identity_characters || input.size() - offset < length * 2u) {
        return false;
      }
      field.clear();
      field.reserve(length);
      for (std::uint16_t index = 0; index < length; ++index) {
        std::uint16_t character {};
        if (!read_u16(input, offset, character) || character == 0) {
          return false;
        }
        field.push_back(static_cast<char16_t>(character));
      }
      return true;
    }
  }  // namespace detail

  inline bool serialize(
    const std::vector<KeyIdentity> &entries,
    std::vector<std::uint8_t> &output
  ) {
    static constexpr std::uint8_t magic[] {'L', 'C', 'N', 'G', 'J', 'N', 'L', '1'};
    if (!detail::valid_entries(entries)) {
      return false;
    }
    output.assign(std::begin(magic), std::end(magic));
    detail::append_u32(output, static_cast<std::uint32_t>(entries.size()));
    for (const auto &entry : entries) {
      output.push_back(entry.machine_key ? 1u : 0u);
      detail::append_field(output, entry.provider);
      detail::append_field(output, entry.container);
      detail::append_field(output, entry.unique_name);
    }
    return output.size() <= maximum_serialized_bytes;
  }

  inline bool deserialize(
    const std::vector<std::uint8_t> &input,
    std::vector<KeyIdentity> &entries
  ) {
    static constexpr std::uint8_t magic[] {'L', 'C', 'N', 'G', 'J', 'N', 'L', '1'};
    if (input.size() < std::size(magic) + 4 || input.size() > maximum_serialized_bytes ||
        !std::equal(std::begin(magic), std::end(magic), input.begin())) {
      return false;
    }
    std::size_t offset = std::size(magic);
    std::uint32_t count {};
    if (!detail::read_u32(input, offset, count) || count > maximum_journal_entries) {
      return false;
    }
    std::vector<KeyIdentity> decoded;
    decoded.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
      if (offset == input.size() || input[offset] > 1) {
        return false;
      }
      KeyIdentity entry;
      entry.machine_key = input[offset++] != 0;
      if (!detail::read_field(input, offset, entry.provider) ||
          !detail::read_field(input, offset, entry.container) ||
          !detail::read_field(input, offset, entry.unique_name)) {
        return false;
      }
      decoded.push_back(std::move(entry));
    }
    if (offset != input.size() || !detail::valid_entries(decoded)) {
      return false;
    }
    entries = std::move(decoded);
    return true;
  }

  class OwnedKeyJournal {
  public:
    explicit OwnedKeyJournal(std::shared_ptr<JournalStore> store):
        store_ {std::move(store)} {
    }

    Status record_before_escape(const KeyIdentity &identity) noexcept {
      std::lock_guard lock {mutex_};
      if (!valid_identity(identity)) {
        return Status::invalid_identity;
      }
      std::vector<KeyIdentity> entries;
      const auto loaded = load(entries);
      if (loaded != Status::success) {
        return loaded;
      }
      const auto exact = std::ranges::find(entries, identity);
      if (exact != entries.end()) {
        return Status::already_owned;
      }
      if (std::ranges::any_of(entries, [&](const auto &entry) {
            return same_locator(entry, identity);
          })) {
        return Status::invalid_journal;
      }
      if (entries.size() == maximum_journal_entries) {
        return Status::journal_full;
      }
      try {
        entries.push_back(identity);
      } catch (...) {
        return Status::storage_error;
      }
      return store_->write(entries) ? Status::success : Status::storage_error;
    }

    Result release_owned(
      const KeyIdentity &identity,
      const KeyBackend::Handle handle,
      KeyBackend &backend
    ) noexcept {
      std::lock_guard lock {mutex_};
      Result result;
      std::vector<KeyIdentity> entries;
      result.status = load(entries);
      if (result.status != Status::success) {
        backend.free_key(handle);
        result.freed = 1;
        return result;
      }
      const auto owned = std::ranges::find(entries, identity);
      if (owned == entries.end()) {
        backend.free_key(handle);
        result.status = Status::not_owned;
        result.freed = 1;
        result.retained = entries.size();
        return result;
      }
      if (!backend.delete_key(handle)) {
        backend.free_key(handle);
        result.status = Status::cleanup_incomplete;
        result.freed = 1;
        result.retained = entries.size();
        return result;
      }
      ++result.deleted;
      entries.erase(owned);
      result.retained = entries.size();
      if (!store_->write(entries)) {
        result.status = Status::storage_error;
      }
      return result;
    }

    Result reap(KeyBackend &backend) noexcept {
      std::lock_guard lock {mutex_};
      Result result;
      std::vector<KeyIdentity> entries;
      result.status = load(entries);
      if (result.status != Status::success) {
        return result;
      }
      std::vector<KeyIdentity> retained;
      try {
        retained.reserve(entries.size());
      } catch (...) {
        result.status = Status::storage_error;
        return result;
      }
      bool incomplete = false;
      for (const auto &entry : entries) {
        const auto opened = backend.open(entry);
        if (opened.status == KeyBackend::OpenStatus::missing) {
          continue;
        }
        if (opened.status != KeyBackend::OpenStatus::opened || !opened.handle) {
          incomplete = true;
          try {
            retained.push_back(entry);
          } catch (...) {
            result.status = Status::storage_error;
            return result;
          }
          continue;
        }
        if (opened.unique_name != entry.unique_name) {
          backend.free_key(opened.handle);
          ++result.freed;
          ++result.skipped_unrelated;
          continue;
        }
        if (backend.delete_key(opened.handle)) {
          ++result.deleted;
          continue;
        }
        backend.free_key(opened.handle);
        ++result.freed;
        incomplete = true;
        try {
          retained.push_back(entry);
        } catch (...) {
          result.status = Status::storage_error;
          return result;
        }
      }
      result.retained = retained.size();
      if (retained != entries && !store_->write(retained)) {
        result.status = Status::storage_error;
      } else if (incomplete) {
        result.status = Status::cleanup_incomplete;
      }
      return result;
    }

  private:
    Status load(std::vector<KeyIdentity> &entries) noexcept {
      if (!store_ || !store_->read(entries)) {
        return Status::storage_error;
      }
      return detail::valid_entries(entries) ? Status::success : Status::invalid_journal;
    }

    std::shared_ptr<JournalStore> store_;
    std::mutex mutex_;
  };
}  // namespace lumen::msquic::cng

#endif
