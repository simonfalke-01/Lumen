/**
 * @file src/protocol_v3/runtime.cpp
 * @brief Production persistence and service adapters for Lumen protocol v3.
 */

#include "runtime.h"
#include "host_identity_store.h"
#include "start_mode_contract.h"

#include "../file_handler.h"
#include "../httpcommon.h"
#include "../process.h"
#include "../protocol_common/crypto.h"
#include "../protocol_common/input_state.h"
#include "../protocol_common/status.h"
#include "../rtsp.h"
#include "../utility.h"
#include "../video.h"

#include <algorithm>
#include <array>
#include <boost/asio/ip/address.hpp>
#include <boost/property_tree/ptree.hpp>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <openssl/crypto.h>
#include <ranges>
#include <set>
#include <stdexcept>
#include <utility>

namespace lumen::protocol_v3::runtime {
  namespace {
    using Status = lumen::protocol_common::Status;
    using Tree = boost::property_tree::ptree;
    using Map = control::cbor::Value::Map;
    using Array = control::cbor::Value::Array;
    using Bytes = control::cbor::Value::Bytes;

    constexpr std::size_t maximum_paired_clients = 256;
    constexpr std::size_t maximum_invitations = 16;
    constexpr std::size_t maximum_consumed_tombstones = 16;
    constexpr std::uint64_t maximum_invitation_lifetime_seconds = 300;
    constexpr std::uint64_t consumed_tombstone_lifetime_seconds = 600;

    std::mutex active_service_mutex;
    ProtocolV3Service *active_service {};

    template<std::size_t Size>
    bool nonzero(const std::array<std::uint8_t, Size> &value) noexcept {
      return std::ranges::any_of(value, [](const auto byte) {
        return byte != 0;
      });
    }

    template<std::size_t Size>
    bool secure_equal(
      const std::array<std::uint8_t, Size> &left,
      const std::array<std::uint8_t, Size> &right
    ) noexcept {
      return CRYPTO_memcmp(left.data(), right.data(), Size) == 0;
    }

    template<std::size_t Size>
    std::string encode_hex(const std::array<std::uint8_t, Size> &value) {
      static constexpr char alphabet[] = "0123456789abcdef";
      std::string output;
      output.resize(Size * 2);
      for (std::size_t index = 0; index < Size; ++index) {
        output[index * 2] = alphabet[value[index] >> 4U];
        output[index * 2 + 1] = alphabet[value[index] & 0x0fU];
      }
      return output;
    }

    std::optional<std::uint8_t> decode_nibble(const char value) noexcept {
      if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
      }
      if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
      }
      if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
      }
      return std::nullopt;
    }

    template<std::size_t Size>
    std::optional<std::array<std::uint8_t, Size>> decode_hex(const std::string_view encoded) noexcept {
      if (encoded.size() != Size * 2) {
        return std::nullopt;
      }
      std::array<std::uint8_t, Size> output {};
      for (std::size_t index = 0; index < Size; ++index) {
        const auto high = decode_nibble(encoded[index * 2]);
        const auto low = decode_nibble(encoded[index * 2 + 1]);
        if (!high || !low) {
          return std::nullopt;
        }
        output[index] = static_cast<std::uint8_t>((*high << 4U) | *low);
      }
      return output;
    }

    std::uint64_t system_unix_seconds() noexcept {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::system_clock::now().time_since_epoch()
      )
                                          .count());
    }

    const control::cbor::Value *field(const Map &map, const std::uint64_t key) noexcept {
      const auto iterator = std::lower_bound(map.begin(), map.end(), key, [](const auto &entry, const auto wanted) {
        return entry.first < wanted;
      });
      return iterator != map.end() && iterator->first == key ? &iterator->second : nullptr;
    }

    const std::uint64_t *unsigned_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<std::uint64_t>(&value->storage) : nullptr;
    }

    const Bytes *bytes_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<Bytes>(&value->storage) : nullptr;
    }

    const Array *array_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<Array>(&value->storage) : nullptr;
    }

    template<std::size_t Size>
    std::optional<std::array<std::uint8_t, Size>> fixed_field(
      const Map &map,
      const std::uint64_t key
    ) noexcept {
      const auto *value = bytes_field(map, key);
      if (!value || value->size() != Size) {
        return std::nullopt;
      }
      std::array<std::uint8_t, Size> output {};
      std::ranges::copy(*value, output.begin());
      return output;
    }

    template<std::size_t Size>
    Bytes bytes(const std::array<std::uint8_t, Size> &value) {
      return {value.begin(), value.end()};
    }

    bool exact_keys(const Map &map, const std::uint64_t first, const std::uint64_t last) noexcept {
      if (map.size() != last - first + 1) {
        return false;
      }
      for (std::size_t index = 0; index < map.size(); ++index) {
        if (map[index].first != first + index) {
          return false;
        }
      }
      return true;
    }

    std::optional<std::uint32_t> application_id(const std::string_view value) noexcept {
      std::uint32_t output {};
      const auto parsed = std::from_chars(value.data(), value.data() + value.size(), output);
      return parsed.ec == std::errc {} && parsed.ptr == value.data() + value.size() && output != 0 ?
               std::optional {output} :
               std::nullopt;
    }

    std::uint64_t snapshot_revision(const std::span<const ApplicationEntry> entries) noexcept {
      constexpr std::uint64_t offset = 14'695'981'039'346'656'037ULL;
      constexpr std::uint64_t prime = 1'099'511'628'211ULL;
      auto hash = offset;
      const auto mix = [&](const std::uint8_t byte) {
        hash = (hash ^ byte) * prime;
      };
      for (const auto &entry : entries) {
        auto id = entry.application_id;
        for (std::size_t index = 0; index < sizeof(id); ++index) {
          mix(static_cast<std::uint8_t>(id));
          id >>= 8U;
        }
        for (const auto character : entry.display_name) {
          mix(static_cast<std::uint8_t>(character));
        }
        mix(static_cast<std::uint8_t>(entry.state));
      }
      return hash == 0 ? 1 : hash;
    }

    std::expected<media::OpusTuple, std::uint8_t> parse_opus_tuple(const Map &tuple) {
      if (!exact_keys(tuple, 1, 9)) {
        return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
      }
      const auto *sample_rate = unsigned_field(tuple, 2);
      const auto *channels = unsigned_field(tuple, 3);
      const auto *frame_samples = unsigned_field(tuple, 4);
      const auto *layout = unsigned_field(tuple, 5);
      const auto *streams = unsigned_field(tuple, 6);
      const auto *coupled = unsigned_field(tuple, 7);
      const auto *mapping = bytes_field(tuple, 8);
      const auto *bitrate = unsigned_field(tuple, 9);
      const auto *codec = unsigned_field(tuple, 1);
      if (!codec || *codec != 1 || !sample_rate || !channels || !frame_samples || !layout ||
          !streams || !coupled || !mapping || !bitrate || *sample_rate > UINT32_MAX ||
          *channels == 0 || *channels > 8 || mapping->size() != *channels ||
          *frame_samples > UINT16_MAX || *layout > UINT8_MAX || *streams > UINT8_MAX ||
          *coupled > UINT8_MAX || *bitrate < 6'000 ||
          *bitrate > std::min<std::uint64_t>(2'048'000, *streams * 512'000)) {
        return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
      }
      media::OpusTuple output;
      output.sample_rate = static_cast<std::uint32_t>(*sample_rate);
      output.channels = static_cast<std::uint8_t>(*channels);
      output.frame_samples = static_cast<std::uint16_t>(*frame_samples);
      output.layout = static_cast<std::uint8_t>(*layout);
      output.streams = static_cast<std::uint8_t>(*streams);
      output.coupled_streams = static_cast<std::uint8_t>(*coupled);
      output.mapping.fill(0xff);
      std::ranges::copy(*mapping, output.mapping.begin());
      output.bitrate_bps = static_cast<std::uint32_t>(*bitrate);
      return output;
    }

    void append_big_endian(
      std::vector<std::uint8_t> &output,
      const std::uint64_t value,
      std::size_t bytes
    ) {
      while (bytes-- != 0) {
        output.push_back(static_cast<std::uint8_t>(value >> (bytes * 8U)));
      }
    }

    std::string base64url(const std::span<const std::uint8_t> input) {
      static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      std::string output;
      output.reserve((input.size() * 4 + 2) / 3);
      for (std::size_t offset = 0; offset < input.size(); offset += 3) {
        const auto remaining = input.size() - offset;
        const auto block = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (remaining > 1 ? static_cast<std::uint32_t>(input[offset + 1]) << 8U : 0U) |
                           (remaining > 2 ? input[offset + 2] : 0U);
        output.push_back(alphabet[(block >> 18U) & 0x3fU]);
        output.push_back(alphabet[(block >> 12U) & 0x3fU]);
        if (remaining > 1) {
          output.push_back(alphabet[(block >> 6U) & 0x3fU]);
        }
        if (remaining > 2) {
          output.push_back(alphabet[block & 0x3fU]);
        }
      }
      return output;
    }

    std::optional<std::string> normalize_invitation_hostname(
      std::string hostname,
      const bool hostname_is_ip
    ) {
      if (hostname.empty() || hostname.size() > 253) {
        return std::nullopt;
      }
      if (hostname_is_ip) {
        boost::system::error_code error;
        const auto address = boost::asio::ip::make_address(hostname, error);
        return error ? std::nullopt : std::optional {address.to_string()};
      }
      std::ranges::transform(hostname, hostname.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
      });
      if (hostname.back() == '.') {
        return std::nullopt;
      }
      std::size_t label_start = 0;
      while (label_start < hostname.size()) {
        const auto label_end = hostname.find('.', label_start);
        const auto end = label_end == std::string::npos ? hostname.size() : label_end;
        const auto length = end - label_start;
        if (length == 0 || length > 63 || hostname[label_start] == '-' || hostname[end - 1] == '-') {
          return std::nullopt;
        }
        for (auto index = label_start; index < end; ++index) {
          const auto character = hostname[index];
          if (!((character >= 'a' && character <= 'z') ||
                (character >= '0' && character <= '9') || character == '-')) {
            return std::nullopt;
          }
        }
        if (label_end == std::string::npos) {
          break;
        }
        label_start = label_end + 1;
      }
      return hostname;
    }

    std::shared_ptr<const std::vector<std::uint8_t>> control_event(
      const std::uint16_t message_type,
      Map fields
    ) {
      const auto payload = control::cbor::encode(control::cbor::Value {std::move(fields)});
      if (!payload) {
        return {};
      }
      auto output = std::make_shared<std::vector<std::uint8_t>>();
      output->reserve(24 + payload.bytes.size());
      output->insert(output->end(), {'U', 'L', 'C', '3', 3, 0});
      append_big_endian(*output, message_type, 2);
      append_big_endian(*output, 0, 8);
      append_big_endian(*output, payload.bytes.size(), 4);
      append_big_endian(*output, 0, 4);
      output->insert(output->end(), payload.bytes.begin(), payload.bytes.end());
      return output;
    }
  }  // namespace

  AttachIntentCache::Lookup AttachIntentCache::lookup(
    const control::Identifier &intent_id,
    const std::uint64_t last_input_generation,
    const std::array<std::uint64_t, 3> &last_media_generations,
    const quic_server::MonotonicClock::time_point now
  ) {
    std::erase_if(entries_, [&](const auto &entry) {
      return entry.second.expires_at <= now;
    });
    const auto found = entries_.find(intent_id);
    if (found == entries_.end()) {
      return {};
    }
    if (found->second.last_input_generation != last_input_generation ||
        found->second.last_media_generations != last_media_generations) {
      return {.match = Match::conflict};
    }
    return {.match = Match::exact, .response_fields = found->second.response_fields};
  }

  bool AttachIntentCache::commit(
    const control::Identifier &intent_id,
    const std::uint64_t last_input_generation,
    const std::array<std::uint64_t, 3> &last_media_generations,
    Map response_fields,
    const quic_server::MonotonicClock::time_point now
  ) {
    std::erase_if(entries_, [&](const auto &entry) {
      return entry.second.expires_at <= now;
    });
    if (entries_.contains(intent_id) || entries_.size() >= 16) {
      return false;
    }
    entries_.emplace(intent_id, Entry {
                                  .last_input_generation = last_input_generation,
                                  .last_media_generations = last_media_generations,
                                  .response_fields = std::move(response_fields),
                                  .expires_at = now + std::chrono::seconds {60},
                                });
    return true;
  }

  std::size_t AttachIntentCache::size() const noexcept {
    return entries_.size();
  }

  struct PersistentAuthorizationStore::Impl {
    struct StoredClient {
      control::ClientRecord record;
      std::string display_name;
      bool enabled {true};
    };

    struct StoredInvitation {
      control::Identifier invitation_id {};
      control::Bytes32 token_sha256 {};
      control::Bytes32 invitation_sha256 {};
      std::uint64_t permissions {};
      std::uint64_t expires_at_unix_seconds {};
    };

    struct ConsumedInvitation {
      StoredInvitation invitation;
      control::Identifier pair_attempt_id {};
      control::Identifier client_id {};
      control::Bytes32 client_public_key {};
      std::string display_name;
      std::uint64_t requested_permissions {};
      std::uint64_t approved_permissions {};
      control::ClientRecord outcome;
      std::uint64_t expires_at_unix_seconds {};
    };

    explicit Impl(std::string path, const bool persist, WallClock clock):
        state_file {std::move(path)},
        persistent {persist},
        wall_clock {clock ? std::move(clock) : WallClock {system_unix_seconds}},
        identity_store {
          host_identity_paths_for_state_file(state_file),
          make_native_host_identity_platform(),
          persistent
        } {
      load();
    }

    bool load() noexcept {
      std::scoped_lock lock {mutex};
      if (!persistent) {
        loaded = true;
        return true;
      }
      if (state_file.empty()) {
        return false;
      }
      std::error_code error;
      if (!std::filesystem::exists(state_file, error)) {
        loaded = !error;
        return loaded;
      }

      http::state_file_tree_t root;
      if (!http::read_state_file(state_file, root)) {
        return false;
      }
      try {
        std::map<control::Identifier, StoredClient> next_clients;
        std::map<control::Identifier, StoredInvitation> next_invitations;
        std::map<control::Identifier, ConsumedInvitation> next_consumed;
        const auto subtree = root.get_child_optional("protocol_v3");
        if (!subtree) {
          loaded = true;
          return true;
        }

        if (const auto seed_text = subtree->get_optional<std::string>("host_identity_seed")) {
          const auto decoded = decode_hex<32>(*seed_text);
          if (!decoded || !nonzero(*decoded)) {
            return false;
          }
          legacy_host_seed = *decoded;
        }

        if (const auto nodes = subtree->get_child_optional("clients")) {
          for (const auto &[_, node] : *nodes) {
            const auto client_id = decode_hex<16>(node.get<std::string>("client_id"));
            const auto public_key = decode_hex<32>(node.get<std::string>("public_key"));
            StoredClient client;
            if (!client_id || !public_key || !nonzero(*client_id) || !nonzero(*public_key)) {
              return false;
            }
            client.record.client_id = *client_id;
            client.record.public_key = *public_key;
            client.record.permissions = node.get<std::uint64_t>("permissions");
            client.record.generation = node.get<std::uint64_t>("generation");
            client.display_name = node.get<std::string>("display_name");
            client.enabled = node.get<bool>("enabled", true);
            if (client.record.permissions == 0 ||
                (client.record.permissions & ~control::defined_permission_mask) != 0 ||
                client.record.generation == 0 || client.display_name.empty() ||
                !next_clients.emplace(client.record.client_id, std::move(client)).second) {
              return false;
            }
          }
        }
        if (next_clients.size() > maximum_paired_clients) {
          return false;
        }

        if (const auto nodes = subtree->get_child_optional("invitations")) {
          const auto now = wall_clock();
          for (const auto &[_, node] : *nodes) {
            StoredInvitation invitation;
            const auto invitation_id = decode_hex<16>(node.get<std::string>("invitation_id"));
            const auto token_hash = decode_hex<32>(node.get<std::string>("token_sha256"));
            const auto digest = decode_hex<32>(node.get<std::string>("invitation_sha256"));
            if (!invitation_id || !token_hash || !digest) {
              return false;
            }
            invitation.invitation_id = *invitation_id;
            invitation.token_sha256 = *token_hash;
            invitation.invitation_sha256 = *digest;
            invitation.permissions = node.get<std::uint64_t>("permissions");
            invitation.expires_at_unix_seconds = node.get<std::uint64_t>("expires_at_unix_seconds");
            if (!valid_stored_invitation(invitation, now)) {
              continue;
            }
            if (!next_invitations.emplace(invitation.invitation_id, invitation).second) {
              return false;
            }
          }
        }
        if (next_invitations.size() > maximum_invitations) {
          return false;
        }

        if (const auto nodes = subtree->get_child_optional("consumed_invitations")) {
          const auto now = wall_clock();
          for (const auto &[_, node] : *nodes) {
            ConsumedInvitation consumed;
            const auto invitation_id = decode_hex<16>(node.get<std::string>("invitation_id"));
            const auto token_hash = decode_hex<32>(node.get<std::string>("token_sha256"));
            const auto invitation_digest = decode_hex<32>(node.get<std::string>("invitation_sha256"));
            const auto attempt = decode_hex<16>(node.get<std::string>("pair_attempt_id"));
            const auto client_id = decode_hex<16>(node.get<std::string>("client_id"));
            const auto public_key = decode_hex<32>(node.get<std::string>("client_public_key"));
            if (!invitation_id || !token_hash || !invitation_digest || !attempt || !client_id || !public_key) {
              return false;
            }
            consumed.invitation.invitation_id = *invitation_id;
            consumed.invitation.token_sha256 = *token_hash;
            consumed.invitation.invitation_sha256 = *invitation_digest;
            consumed.invitation.permissions = node.get<std::uint64_t>("invitation_permissions");
            consumed.pair_attempt_id = *attempt;
            consumed.client_id = *client_id;
            consumed.client_public_key = *public_key;
            consumed.display_name = node.get<std::string>("display_name");
            consumed.requested_permissions = node.get<std::uint64_t>("requested_permissions");
            consumed.approved_permissions = node.get<std::uint64_t>("approved_permissions");
            consumed.outcome.client_id = consumed.client_id;
            consumed.outcome.public_key = consumed.client_public_key;
            consumed.outcome.permissions = node.get<std::uint64_t>("outcome_permissions");
            consumed.outcome.generation = node.get<std::uint64_t>("outcome_generation");
            consumed.expires_at_unix_seconds = node.get<std::uint64_t>("expires_at_unix_seconds");
            if (consumed.expires_at_unix_seconds <= now || !valid_consumed(consumed) ||
                !next_consumed.emplace(consumed.invitation.invitation_id, std::move(consumed)).second) {
              continue;
            }
          }
        }
        if (next_consumed.size() > maximum_consumed_tombstones) {
          return false;
        }
        clients = std::move(next_clients);
        invitations = std::move(next_invitations);
        consumed = std::move(next_consumed);
        loaded = true;
        return true;
      } catch (...) {
        return false;
      }
    }

    bool persist_state(
      const std::map<control::Identifier, StoredClient> &next_clients,
      const std::map<control::Identifier, StoredInvitation> &next_invitations,
      const std::map<control::Identifier, ConsumedInvitation> &next_consumed,
      const std::optional<control::Bytes32> &next_seed
    ) const {
      if (!persistent) {
        return true;
      }
      const auto committed = http::update_state_file(state_file, [&](Tree &root) {
        Tree protocol;
        if (next_seed) {
          protocol.put("host_identity_seed", encode_hex(*next_seed));
        }

        Tree client_nodes;
        for (const auto &[_, client] : next_clients) {
          Tree node;
          node.put("client_id", encode_hex(client.record.client_id));
          node.put("public_key", encode_hex(client.record.public_key));
          node.put("permissions", client.record.permissions);
          node.put("generation", client.record.generation);
          node.put("display_name", client.display_name);
          node.put("enabled", client.enabled);
          client_nodes.push_back({"", std::move(node)});
        }
        protocol.add_child("clients", client_nodes);

        Tree invitation_nodes;
        for (const auto &[_, invitation] : next_invitations) {
          Tree node;
          node.put("invitation_id", encode_hex(invitation.invitation_id));
          node.put("token_sha256", encode_hex(invitation.token_sha256));
          node.put("invitation_sha256", encode_hex(invitation.invitation_sha256));
          node.put("permissions", invitation.permissions);
          node.put("expires_at_unix_seconds", invitation.expires_at_unix_seconds);
          invitation_nodes.push_back({"", std::move(node)});
        }
        protocol.add_child("invitations", invitation_nodes);

        Tree consumed_nodes;
        for (const auto &[_, consumed_invitation] : next_consumed) {
          Tree node;
          node.put("invitation_id", encode_hex(consumed_invitation.invitation.invitation_id));
          node.put("token_sha256", encode_hex(consumed_invitation.invitation.token_sha256));
          node.put("invitation_sha256", encode_hex(consumed_invitation.invitation.invitation_sha256));
          node.put("invitation_permissions", consumed_invitation.invitation.permissions);
          node.put("pair_attempt_id", encode_hex(consumed_invitation.pair_attempt_id));
          node.put("client_id", encode_hex(consumed_invitation.client_id));
          node.put("client_public_key", encode_hex(consumed_invitation.client_public_key));
          node.put("display_name", consumed_invitation.display_name);
          node.put("requested_permissions", consumed_invitation.requested_permissions);
          node.put("approved_permissions", consumed_invitation.approved_permissions);
          node.put("outcome_permissions", consumed_invitation.outcome.permissions);
          node.put("outcome_generation", consumed_invitation.outcome.generation);
          node.put("expires_at_unix_seconds", consumed_invitation.expires_at_unix_seconds);
          consumed_nodes.push_back({"", std::move(node)});
        }
        protocol.add_child("consumed_invitations", consumed_nodes);
        root.put_child("protocol_v3", protocol);
      });
      if (!committed) {
        return false;
      }
#ifndef _WIN32
      std::error_code permission_error;
      std::filesystem::permissions(
        state_file,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        permission_error
      );
      if (permission_error) {
        return false;
      }
#endif
      return true;
    }

    bool valid_invitation(
      const Invitation &invitation,
      const std::uint64_t now,
      const bool newly_issued
    ) const noexcept {
      if (!nonzero(invitation.invitation_id) || !nonzero(invitation.token) ||
          !nonzero(invitation.invitation_sha256) || invitation.permissions == 0 ||
          (invitation.permissions & ~control::defined_permission_mask) != 0 ||
          invitation.expires_at_unix_seconds <= now) {
        return false;
      }
      return !newly_issued || invitation.expires_at_unix_seconds - now <= maximum_invitation_lifetime_seconds;
    }

    bool valid_stored_invitation(
      const StoredInvitation &invitation,
      const std::uint64_t now
    ) const noexcept {
      return nonzero(invitation.invitation_id) && nonzero(invitation.token_sha256) &&
             nonzero(invitation.invitation_sha256) && invitation.permissions != 0 &&
             (invitation.permissions & ~control::defined_permission_mask) == 0 &&
             invitation.expires_at_unix_seconds > now;
    }

    bool valid_consumed(const ConsumedInvitation &entry) const noexcept {
      return nonzero(entry.invitation.invitation_id) && nonzero(entry.invitation.token_sha256) &&
             nonzero(entry.invitation.invitation_sha256) && nonzero(entry.pair_attempt_id) &&
             nonzero(entry.client_id) && nonzero(entry.client_public_key) &&
             !entry.display_name.empty() && entry.requested_permissions != 0 &&
             entry.approved_permissions != 0 &&
             (entry.approved_permissions & ~entry.requested_permissions) == 0 &&
             (entry.approved_permissions & ~entry.invitation.permissions) == 0 &&
             entry.outcome.client_id == entry.client_id &&
             entry.outcome.public_key == entry.client_public_key &&
             entry.outcome.permissions != 0 && entry.outcome.generation != 0;
    }

    std::string state_file;
    bool persistent {};
    WallClock wall_clock;
    HostIdentityStore identity_store;
    mutable std::mutex mutex;
    bool loaded {};
    std::optional<control::Bytes32> legacy_host_seed;
    std::optional<control::Bytes32> host_seed;
    std::map<control::Identifier, StoredClient> clients;
    std::map<control::Identifier, StoredInvitation> invitations;
    std::map<control::Identifier, ConsumedInvitation> consumed;
  };

  PersistentAuthorizationStore::PersistentAuthorizationStore(
    std::string state_file,
    const bool persistent,
    WallClock wall_clock
  ):
      impl_ {std::make_unique<Impl>(std::move(state_file), persistent, std::move(wall_clock))} {
  }

  PersistentAuthorizationStore::~PersistentAuthorizationStore() = default;

  bool PersistentAuthorizationStore::ready() const noexcept {
    return impl_->loaded;
  }

  std::expected<control::Bytes32, std::uint8_t> PersistentAuthorizationStore::host_identity_seed(
    control::Random &random
  ) {
    std::scoped_lock lock {impl_->mutex};
    if (!impl_->loaded) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    if (impl_->host_seed) {
      return *impl_->host_seed;
    }
    auto loaded = impl_->identity_store.load_or_create(impl_->legacy_host_seed, random);
    if (!loaded || !nonzero(loaded->seed)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    if (loaded->retire_legacy_seed &&
        !impl_->persist_state(impl_->clients, impl_->invitations, impl_->consumed, std::nullopt)) {
      OPENSSL_cleanse(loaded->seed.data(), loaded->seed.size());
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    impl_->legacy_host_seed.reset();
    impl_->host_seed = loaded->seed;
    return loaded->seed;
  }

  bool PersistentAuthorizationStore::add_invitation(const Invitation &invitation) {
    std::scoped_lock lock {impl_->mutex};
    if (!impl_->loaded || !impl_->valid_invitation(invitation, impl_->wall_clock(), true)) {
      return false;
    }
    auto candidate = impl_->invitations;
    auto consumed_candidate = impl_->consumed;
    std::erase_if(candidate, [&](const auto &entry) {
      return entry.second.expires_at_unix_seconds <= impl_->wall_clock();
    });
    if (!candidate.contains(invitation.invitation_id) && candidate.size() >= maximum_invitations) {
      return false;
    }
    const auto token_hash = lumen::protocol_common::crypto::sha256(invitation.token);
    if (!token_hash) {
      return false;
    }
    candidate[invitation.invitation_id] = Impl::StoredInvitation {
      .invitation_id = invitation.invitation_id,
      .token_sha256 = *token_hash,
      .invitation_sha256 = invitation.invitation_sha256,
      .permissions = invitation.permissions,
      .expires_at_unix_seconds = invitation.expires_at_unix_seconds,
    };
    consumed_candidate.erase(invitation.invitation_id);
    if (!impl_->persist_state(impl_->clients, candidate, consumed_candidate, impl_->legacy_host_seed)) {
      return false;
    }
    impl_->invitations = std::move(candidate);
    impl_->consumed = std::move(consumed_candidate);
    return true;
  }

  bool PersistentAuthorizationStore::revoke_invitation(const control::Identifier &invitation_id) {
    std::scoped_lock lock {impl_->mutex};
    if (!impl_->loaded || !impl_->invitations.contains(invitation_id)) {
      return false;
    }
    auto candidate = impl_->invitations;
    candidate.erase(invitation_id);
    if (!impl_->persist_state(impl_->clients, candidate, impl_->consumed, impl_->legacy_host_seed)) {
      return false;
    }
    impl_->invitations = std::move(candidate);
    return true;
  }

  std::optional<control::ClientRecord> PersistentAuthorizationStore::paired_client(
    const control::Identifier &client_id
  ) {
    std::scoped_lock lock {impl_->mutex};
    if (!impl_->loaded) {
      return std::nullopt;
    }
    const auto existing = impl_->clients.find(client_id);
    return existing == impl_->clients.end() || !existing->second.enabled ?
             std::nullopt :
             std::optional {existing->second.record};
  }

  std::vector<AuthorizedClientInfo> PersistentAuthorizationStore::clients() const {
    std::scoped_lock lock {impl_->mutex};
    std::vector<AuthorizedClientInfo> output;
    if (!impl_->loaded) {
      return output;
    }
    output.reserve(impl_->clients.size());
    for (const auto &[_, client] : impl_->clients) {
      output.push_back({
        client.record.client_id,
        client.display_name,
        client.record.permissions,
        client.record.generation,
        client.enabled,
      });
    }
    return output;
  }

  bool PersistentAuthorizationStore::set_client_enabled(
    const control::Identifier &client_id,
    const bool enabled
  ) {
    std::scoped_lock lock {impl_->mutex};
    const auto existing = impl_->clients.find(client_id);
    if (!impl_->loaded || existing == impl_->clients.end()) {
      return false;
    }
    if (existing->second.enabled == enabled) {
      return true;
    }
    if (existing->second.record.generation == UINT64_MAX) {
      return false;
    }
    auto candidate = impl_->clients;
    auto &updated = candidate.find(client_id)->second;
    updated.enabled = enabled;
    ++updated.record.generation;
    if (!impl_->persist_state(candidate, impl_->invitations, impl_->consumed, impl_->legacy_host_seed)) {
      return false;
    }
    impl_->clients = std::move(candidate);
    return true;
  }

  bool PersistentAuthorizationStore::set_client_permissions(
    const control::Identifier &client_id,
    const std::uint64_t permissions
  ) {
    std::scoped_lock lock {impl_->mutex};
    const auto existing = impl_->clients.find(client_id);
    if (!impl_->loaded || existing == impl_->clients.end() || permissions == 0 ||
        (permissions & ~control::defined_permission_mask) != 0) {
      return false;
    }
    if (existing->second.record.permissions == permissions) {
      return true;
    }
    if (existing->second.record.generation == UINT64_MAX) {
      return false;
    }
    auto candidate = impl_->clients;
    auto &updated = candidate.find(client_id)->second;
    updated.record.permissions = permissions;
    ++updated.record.generation;
    if (!impl_->persist_state(candidate, impl_->invitations, impl_->consumed, impl_->legacy_host_seed)) {
      return false;
    }
    impl_->clients = std::move(candidate);
    return true;
  }

  bool PersistentAuthorizationStore::revoke_client(const control::Identifier &client_id) {
    std::scoped_lock lock {impl_->mutex};
    if (!impl_->loaded || !impl_->clients.contains(client_id)) {
      return false;
    }
    auto candidate = impl_->clients;
    candidate.erase(client_id);
    if (!impl_->persist_state(candidate, impl_->invitations, impl_->consumed, impl_->legacy_host_seed)) {
      return false;
    }
    impl_->clients = std::move(candidate);
    return true;
  }

  std::expected<control::ClientRecord, std::uint8_t> PersistentAuthorizationStore::consume_invitation(
    const control::PairingClaim &claim
  ) {
    std::scoped_lock lock {impl_->mutex};
    if (!impl_->loaded) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    const auto token_hash = lumen::protocol_common::crypto::sha256(claim.invitation_token);
    if (!token_hash) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    const auto existing = impl_->invitations.find(claim.invitation_id);
    if (existing == impl_->invitations.end()) {
      const auto tombstone = impl_->consumed.find(claim.invitation_id);
      if (tombstone != impl_->consumed.end() && tombstone->second.expires_at_unix_seconds > impl_->wall_clock()) {
        const auto &entry = tombstone->second;
        const bool exact_retry = secure_equal(entry.invitation.token_sha256, *token_hash) &&
                                 secure_equal(entry.invitation.invitation_sha256, claim.invitation_sha256) &&
                                 entry.pair_attempt_id == claim.pair_attempt_id &&
                                 entry.client_id == claim.client_id &&
                                 entry.client_public_key == claim.client_public_key &&
                                 entry.display_name == claim.display_name &&
                                 entry.requested_permissions == claim.requested_permissions &&
                                 entry.approved_permissions == claim.approved_permissions;
        if (exact_retry) {
          return entry.outcome;
        }
      }
      return std::unexpected(static_cast<std::uint8_t>(Status::consumed));
    }
    const auto &invitation = existing->second;
    if (invitation.expires_at_unix_seconds <= impl_->wall_clock()) {
      return std::unexpected(static_cast<std::uint8_t>(Status::expired));
    }
    if (!secure_equal(invitation.token_sha256, *token_hash) ||
        !secure_equal(invitation.invitation_sha256, claim.invitation_sha256) ||
        claim.display_name.empty() || !nonzero(claim.client_id) || !nonzero(claim.client_public_key) ||
        claim.requested_permissions == 0 ||
        (claim.requested_permissions & ~control::defined_permission_mask) != 0 ||
        claim.approved_permissions == 0 ||
        (claim.approved_permissions & ~claim.requested_permissions) != 0 ||
        (claim.approved_permissions & ~invitation.permissions) != 0) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unauthenticated));
    }

    auto next_clients = impl_->clients;
    auto next_invitations = impl_->invitations;
    auto next_consumed = impl_->consumed;
    next_invitations.erase(claim.invitation_id);
    auto generation = std::uint64_t {1};
    if (const auto prior = next_clients.find(claim.client_id); prior != next_clients.end()) {
      if (prior->second.record.generation == UINT64_MAX) {
        return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
      }
      generation = prior->second.record.generation + 1;
    } else if (next_clients.size() >= maximum_paired_clients) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    Impl::StoredClient stored {
      .record = {
        .client_id = claim.client_id,
        .public_key = claim.client_public_key,
        .permissions = claim.approved_permissions,
        .generation = generation,
      },
      .display_name = claim.display_name,
    };
    next_clients[claim.client_id] = stored;
    std::erase_if(next_consumed, [&](const auto &entry) {
      return entry.second.expires_at_unix_seconds <= impl_->wall_clock();
    });
    if (!next_consumed.contains(claim.invitation_id) && next_consumed.size() >= maximum_consumed_tombstones) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    next_consumed[claim.invitation_id] = Impl::ConsumedInvitation {
      .invitation = invitation,
      .pair_attempt_id = claim.pair_attempt_id,
      .client_id = claim.client_id,
      .client_public_key = claim.client_public_key,
      .display_name = claim.display_name,
      .requested_permissions = claim.requested_permissions,
      .approved_permissions = claim.approved_permissions,
      .outcome = stored.record,
      .expires_at_unix_seconds = impl_->wall_clock() + consumed_tombstone_lifetime_seconds,
    };
    if (!impl_->persist_state(next_clients, next_invitations, next_consumed, impl_->legacy_host_seed)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    impl_->clients = std::move(next_clients);
    impl_->invitations = std::move(next_invitations);
    impl_->consumed = std::move(next_consumed);
    return stored.record;
  }

  std::expected<ApplicationSnapshot, std::uint8_t> LumenApplicationBridge::snapshot() {
    ApplicationSnapshot output;
    const auto running = proc::proc.running();
    try {
      output.entries.reserve(proc::proc.get_apps().size());
      for (const auto &application : proc::proc.get_apps()) {
        const auto id = application_id(application.id);
        if (!id) {
          return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
        }
        ApplicationEntry entry {
          .application_id = *id,
          .display_name = application.name,
          .state = running == static_cast<int>(*id) ? 2U : 0U,
          .flags = 0,
          .asset_sha256 = std::nullopt,
          .last_changed_revision = 0,
          .launch_capabilities = application.cmd.empty() ? 0x5U : 0xbU,
        };
        const auto image_path = proc::proc.get_app_image(static_cast<int>(*id));
        std::error_code image_error;
        const auto image_size = std::filesystem::file_size(image_path, image_error);
        if (!image_error && image_size <= 5U * 1024U * 1024U) {
          std::ifstream image {image_path, std::ios::binary};
          const std::vector<std::uint8_t> contents {
            std::istreambuf_iterator<char> {image},
            std::istreambuf_iterator<char> {}
          };
          if (image || image.eof()) {
            entry.asset_sha256 = lumen::protocol_common::crypto::sha256(contents);
          }
        }
        output.entries.push_back(std::move(entry));
      }
      std::ranges::sort(output.entries, {}, &ApplicationEntry::application_id);
      output.revision = snapshot_revision(output.entries);
      for (auto &entry : output.entries) {
        entry.last_changed_revision = output.revision;
      }
      return output;
    } catch (...) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
  }

  std::expected<ApplicationAsset, std::uint8_t> LumenApplicationBridge::asset(
    const std::uint64_t wanted_application_id,
    const control::Bytes32 &expected_sha256
  ) {
    if (wanted_application_id == 0 || wanted_application_id > INT_MAX) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    const auto &configured = proc::proc.get_apps();
    if (std::ranges::find(configured, std::to_string(wanted_application_id), &proc::ctx_t::id) == configured.end()) {
      return std::unexpected(static_cast<std::uint8_t>(Status::application_not_found));
    }
    try {
      const auto path = proc::proc.get_app_image(static_cast<int>(wanted_application_id));
      std::error_code error;
      const auto size = std::filesystem::file_size(path, error);
      if (error || size > 5U * 1024U * 1024U) {
        return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
      }
      std::ifstream input {path, std::ios::binary};
      std::vector<std::uint8_t> contents {
        std::istreambuf_iterator<char> {input},
        std::istreambuf_iterator<char> {}
      };
      const auto digest = lumen::protocol_common::crypto::sha256(contents);
      if (!input.eof() || contents.size() != size || !digest || !secure_equal(*digest, expected_sha256)) {
        return std::unexpected(static_cast<std::uint8_t>(Status::busy));
      }
      auto extension = std::filesystem::path {path}.extension().string();
      std::ranges::transform(extension, extension.begin(), [](const unsigned char value) {
        return static_cast<char>(std::tolower(value));
      });
      return ApplicationAsset {
        wanted_application_id,
        *digest,
        extension == ".jpg" || extension == ".jpeg" ? "image/jpeg" : "image/png",
        std::move(contents),
      };
    } catch (...) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
  }

  std::expected<bool, std::uint8_t> LumenApplicationBridge::start(const ApplicationLaunch &launch) {
    const auto running = proc::proc.running();
    if (running != 0) {
      if (launch.resume && running == static_cast<int>(launch.application_id)) {
        return false;
      }
      return std::unexpected(static_cast<std::uint8_t>(Status::busy));
    }
    if (launch.application_id == 0) {
      return false;
    }
    auto legacy_shape = make_legacy_launch_session(launch);
    if (!legacy_shape) {
      return std::unexpected(legacy_shape.error());
    }
    if (const auto status = proc::proc.execute(static_cast<int>(launch.application_id), *legacy_shape); status != 0) {
      return std::unexpected(static_cast<std::uint8_t>(status == 404 ? Status::application_not_found : Status::resource_failure));
    }
    return true;
  }

  std::expected<std::shared_ptr<rtsp_stream::launch_session_t>, std::uint8_t>
    make_legacy_launch_session(const ApplicationLaunch &launch) {
    if (launch.application_id > INT_MAX || launch.width > INT_MAX || launch.height > INT_MAX ||
        launch.refresh_numerator == 0 || launch.refresh_denominator == 0 ||
        launch.audio.sample_rate != 48'000 ||
        (launch.audio.channels != 2 && launch.audio.channels != 6 && launch.audio.channels != 8) ||
        launch.audio.layout != (launch.audio.channels == 2 ? 1 : launch.audio.channels == 6 ? 2 :
                                                                                              3) ||
        static_cast<unsigned>(launch.audio.streams) + launch.audio.coupled_streams != launch.audio.channels) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    const auto rounded_fps =
      (static_cast<std::uint64_t>(launch.refresh_numerator) + launch.refresh_denominator / 2U) /
      launch.refresh_denominator;
    if (rounded_fps == 0 || rounded_fps > INT_MAX) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    const auto channel_mask = launch.audio.channels == 2 ? 0x3U :
                              launch.audio.channels == 6 ? 0x3fU :
                                                           0x63fU;
    std::string surround_params;
    surround_params.reserve(static_cast<std::size_t>(launch.audio.channels) + 3U);
    surround_params.push_back(static_cast<char>('0' + launch.audio.channels));
    surround_params.push_back(static_cast<char>('0' + launch.audio.streams));
    surround_params.push_back(static_cast<char>('0' + launch.audio.coupled_streams));
    for (std::size_t index = 0; index < launch.audio.channels; ++index) {
      if (launch.audio.mapping[index] >= launch.audio.channels) {
        return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
      }
      surround_params.push_back(static_cast<char>('0' + launch.audio.mapping[index]));
    }

    auto legacy_shape = std::make_shared<rtsp_stream::launch_session_t>();
    legacy_shape->host_audio = launch.host_audio;
    legacy_shape->unique_id = "protocol-v3";
    legacy_shape->width = static_cast<int>(launch.width);
    legacy_shape->height = static_cast<int>(launch.height);
    legacy_shape->fps = static_cast<int>(rounded_fps);
    legacy_shape->refresh_numerator = launch.refresh_numerator;
    legacy_shape->refresh_denominator = launch.refresh_denominator;
    legacy_shape->appid = static_cast<int>(launch.application_id);
    legacy_shape->surround_info = static_cast<int>((channel_mask << 16U) | launch.audio.channels);
    legacy_shape->surround_params = std::move(surround_params);
    legacy_shape->continuous_audio = true;
    legacy_shape->enable_hdr = launch.enable_hdr;
    return legacy_shape;
  }

  bool LumenApplicationBridge::stop(const bool quit_application) noexcept {
    if (quit_application && proc::proc.running() != 0) {
      proc::proc.terminate();
      return proc::proc.running() == 0;
    }
    return false;
  }

  bool LumenApplicationBridge::running() noexcept {
    return proc::proc.running() != 0;
  }

  void QuicTransportSink::attach(
    quic_server::QuicServer &server,
    const quic_server::Profile default_profile,
    const std::uint64_t default_video_bitrate_kbps
  ) noexcept {
    server_ = &server;
    default_profile_ = default_profile;
    default_video_bitrate_kbps_ = default_video_bitrate_kbps;
  }

  bool QuicTransportSink::revoke(const std::uint64_t connection_id) noexcept {
    return server_ && server_->revoke_connection(connection_id);
  }

  bool QuicTransportSink::reset_policy(const std::uint64_t connection_id) noexcept {
    return server_ && server_->set_connection_policy(
                        connection_id,
                        default_profile_,
                        default_video_bitrate_kbps_
                      );
  }

  bool QuicTransportSink::update_policy(
    const std::uint64_t connection_id,
    const quic_server::Profile profile,
    const std::uint64_t video_bitrate_kbps
  ) noexcept {
    return server_ && server_->set_connection_policy(connection_id, profile, video_bitrate_kbps);
  }

  quic_server::EnqueueResult QuicTransportSink::enqueue(
    const std::uint64_t connection_id,
    quic_server::Packet packet
  ) {
    return server_ ? server_->enqueue(connection_id, std::move(packet)) :
                     quic_server::EnqueueResult::shutting_down;
  }

  quic_server::EnqueueResult QuicTransportSink::enqueue_video_frame(
    const std::uint64_t connection_id,
    std::shared_ptr<const quic_server::LazyVideoFrame> frame
  ) {
    return server_ ? server_->enqueue_video_frame(connection_id, std::move(frame)) :
                     quic_server::EnqueueResult::shutting_down;
  }

  TerminalFailureDispatcher::TerminalFailureDispatcher(
    const std::uint64_t generation,
    std::weak_ptr<std::condition_variable_any> watchdog
  ) noexcept:
      generation_ {generation},
      watchdog_ {std::move(watchdog)} {
  }

  void TerminalFailureDispatcher::report() noexcept {
    if (revoked_.load(std::memory_order_acquire)) {
      return;
    }
    bool expected = false;
    if (!reported_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
      return;
    }
    if (revoked_.load(std::memory_order_acquire)) {
      return;
    }
    if (const auto watchdog = watchdog_.lock()) {
      watchdog->notify_all();
    }
  }

  void TerminalFailureDispatcher::revoke() noexcept {
    revoked_.store(true, std::memory_order_release);
  }

  bool TerminalFailureDispatcher::reported() const noexcept {
    return reported_.load(std::memory_order_acquire);
  }

  std::uint64_t TerminalFailureDispatcher::generation() const noexcept {
    return generation_;
  }

  struct ProductionSessionBackend::Impl {
    struct ActiveSession {
      control::Identifier owner_client_id {};
      control::Identifier start_intent_id {};
      control::Bytes32 attach_token {};
      std::uint64_t connection_id {};
      std::uint64_t authority_generation {};
      quic_server::Profile profile {quic_server::Profile::quality};
      std::uint64_t video_bitrate_kbps {100'000};
      std::uint32_t input_generation {1};
      std::uint32_t text_revision {};
      std::uint64_t last_text_operation {};
      bool launched_application {};
      bool video_configured {};
      bool audio_configured {};
      bool microphone_configured {};
      bool microphone_required {};
      bool media_started {};
      bool input_baseline_required {};
      std::optional<std::uint32_t> decoder_capacity;
      quic_server::MonotonicClock::time_point configuration_deadline {};
      std::optional<quic_server::MonotonicClock::time_point> attach_deadline;
      AttachIntentCache attach_outcomes;
      std::uint64_t terminal_failure_generation {};
      std::shared_ptr<TerminalFailureDispatcher> terminal_failure;
      std::unique_ptr<SessionResources> resources;
    };

    Impl(
      control::Random &random_source,
      ApplicationBridge &application_bridge,
      SessionResourceFactory &resource_factory,
      QuicTransportSink &transport_sink
    ):
        random {random_source},
        applications {application_bridge},
        factory {resource_factory},
        transport {transport_sink},
        watchdog {[this](const std::stop_token stop_token) {
          run_watchdog(stop_token);
        }} {
    }

    ~Impl() {
      struct StoppedSession {
        std::unique_ptr<SessionResources> resources;
        std::uint64_t connection_id {};
        bool launched_application {};
      };

      std::array<StoppedSession, 8> stopped_sessions;
      std::size_t stopped_session_count {};
      {
        std::scoped_lock lock {mutex};
        shutting_down = true;
        for (auto &[_, session] : sessions) {
          if (session.terminal_failure) {
            session.terminal_failure->revoke();
          }
          if (session.resources && stopped_session_count < stopped_sessions.size()) {
            stopped_sessions[stopped_session_count++] = {
              std::move(session.resources),
              session.connection_id,
              session.launched_application,
            };
          }
        }
        sessions.clear();
        terminal_closures.clear();
        watchdog_wakeup->notify_all();
      }
      for (std::size_t index = 0; index < stopped_session_count; ++index) {
        auto &session = stopped_sessions[index];
        session.resources->stop();
        if (session.launched_application) {
          applications.stop(true);
        }
        if (session.connection_id != 0) {
          static_cast<void>(transport.revoke(session.connection_id));
        }
      }
      watchdog.request_stop();
      watchdog_wakeup->notify_all();
      if (watchdog.joinable()) {
        watchdog.join();
      }
    }

    void run_watchdog(const std::stop_token stop_token) noexcept {
      while (!stop_token.stop_requested()) {
        struct ExpiredSession {
          std::unique_ptr<SessionResources> resources;
          control::Identifier session_id {};
          std::uint64_t connection_id {};
          bool launched_application {};
          bool terminal_failure {};
        };

        std::vector<ExpiredSession> expired;
        {
          std::unique_lock lock {mutex};
          const auto deadline = [&]() {
            auto earliest = quic_server::MonotonicClock::time_point::max();
            for (const auto &[_, session] : sessions) {
              if (!session.media_started) {
                earliest = std::min(earliest, session.configuration_deadline);
              } else if (session.attach_deadline) {
                earliest = std::min(earliest, *session.attach_deadline);
              }
            }
            for (const auto &[_, close_at] : terminal_closures) {
              earliest = std::min(earliest, close_at);
            }
            return earliest;
          }();
          if (deadline == quic_server::MonotonicClock::time_point::max()) {
            watchdog_wakeup->wait(lock, stop_token, [&]() {
              return stop_token.stop_requested() || shutting_down || std::ranges::any_of(sessions, [](const auto &entry) {
                       return !entry.second.media_started || entry.second.attach_deadline.has_value();
                     }) ||
                     std::ranges::any_of(sessions, [](const auto &entry) {
                       return entry.second.terminal_failure &&
                              entry.second.terminal_failure->generation() == entry.second.terminal_failure_generation &&
                              entry.second.terminal_failure->reported();
                     }) ||
                     !terminal_closures.empty();
            });
          } else {
            watchdog_wakeup->wait_until(lock, stop_token, deadline, [this]() {
              return shutting_down || std::ranges::any_of(sessions, [](const auto &entry) {
                       return entry.second.terminal_failure &&
                              entry.second.terminal_failure->generation() == entry.second.terminal_failure_generation &&
                              entry.second.terminal_failure->reported();
                     });
            });
          }
          if (stop_token.stop_requested() || shutting_down) {
            return;
          }
          const auto now = quic_server::MonotonicClock::now();
          std::vector<std::uint64_t> due_closures;
          for (auto closure = terminal_closures.begin(); closure != terminal_closures.end();) {
            if (closure->second <= now) {
              due_closures.push_back(closure->first);
              closure = terminal_closures.erase(closure);
            } else {
              ++closure;
            }
          }
          for (auto session = sessions.begin(); session != sessions.end();) {
            const auto terminal_failure = session->second.terminal_failure &&
                                          session->second.terminal_failure->generation() ==
                                            session->second.terminal_failure_generation &&
                                          session->second.terminal_failure->reported();
            if (terminal_failure ||
                (!session->second.media_started && now >= session->second.configuration_deadline) ||
                (session->second.attach_deadline && now >= *session->second.attach_deadline)) {
              if (session->second.terminal_failure) {
                session->second.terminal_failure->revoke();
              }
              expired.push_back({
                std::move(session->second.resources),
                session->first,
                session->second.connection_id,
                session->second.launched_application,
                terminal_failure,
              });
              expired_intents.emplace(
                std::pair {session->second.owner_client_id, session->second.start_intent_id},
                now + std::chrono::seconds {60}
              );
              session = sessions.erase(session);
            } else {
              ++session;
            }
          }
          std::erase_if(expired_intents, [&](const auto &entry) {
            return entry.second <= now;
          });
          lock.unlock();
          for (const auto connection_id : due_closures) {
            static_cast<void>(transport.revoke(connection_id));
          }
        }
        for (auto &session : expired) {
          if (session.terminal_failure && session.connection_id != 0) {
            const auto stopping = control_event(0x0132, {
                                                          {1, bytes(session.session_id)},
                                                          {2, 7U},
                                                        });
            if (stopping) {
              static_cast<void>(transport.enqueue(session.connection_id, {
                                                                           .lane = quic_server::Lane::control,
                                                                           .bytes = stopping,
                                                                         }));
            }
          }
          session.resources->stop();
          if (!session.terminal_failure && session.launched_application) {
            applications.stop(true);
          }
          if (session.terminal_failure && session.connection_id != 0) {
            const auto ended = control_event(0x0133, {
                                                       {1, bytes(session.session_id)},
                                                       {2, 7U},
                                                       {3, static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(quic_server::MonotonicClock::now().time_since_epoch()).count())},
                                                       {4, control::cbor::Value {applications.running()}},
                                                       {5, 0U},
                                                       {6, 0U},
                                                       {7, 0U},
                                                       {8, 0U},
                                                     });
            if (ended) {
              static_cast<void>(transport.enqueue(session.connection_id, {
                                                                           .lane = quic_server::Lane::control,
                                                                           .bytes = ended,
                                                                         }));
            }
            std::scoped_lock lock {mutex};
            terminal_closures[session.connection_id] =
              quic_server::MonotonicClock::now() + std::chrono::milliseconds {250};
            watchdog_wakeup->notify_all();
          } else if (session.connection_id != 0) {
            static_cast<void>(transport.revoke(session.connection_id));
          }
        }
      }
    }

    std::shared_ptr<TerminalFailureDispatcher> make_terminal_failure_dispatcher() {
      if (next_terminal_failure_generation == UINT64_MAX) {
        return {};
      }
      const auto generation = next_terminal_failure_generation++;
      return std::make_shared<TerminalFailureDispatcher>(generation, watchdog_wakeup);
    }

    template<std::size_t Size>
    bool random_nonzero(std::array<std::uint8_t, Size> &output) noexcept {
      for (unsigned int attempt = 0; attempt < 8; ++attempt) {
        if (!random.fill(output)) {
          return false;
        }
        if (nonzero(output)) {
          return true;
        }
      }
      return false;
    }

    std::map<control::Identifier, ActiveSession>::iterator owned_session(
      const control::Identifier &session_id,
      const control::Identifier &client_id
    ) {
      const auto session = sessions.find(session_id);
      return session != sessions.end() && session->second.owner_client_id == client_id ? session : sessions.end();
    }

    control::Random &random;
    ApplicationBridge &applications;
    SessionResourceFactory &factory;
    QuicTransportSink &transport;
    std::mutex mutex;
    std::shared_ptr<std::condition_variable_any> watchdog_wakeup {
      std::make_shared<std::condition_variable_any>()
    };
    std::map<control::Identifier, ActiveSession> sessions;
    std::map<std::pair<control::Identifier, control::Identifier>, quic_server::MonotonicClock::time_point> expired_intents;
    std::map<std::uint64_t, quic_server::MonotonicClock::time_point> terminal_closures;
    std::uint64_t next_authority_generation {1};
    std::uint64_t next_terminal_failure_generation {1};
#ifdef SUNSHINE_TESTS
    bool fail_start_before_commit_for_test {};
#endif
    bool shutting_down {};
    std::jthread watchdog;
  };

  ProductionSessionBackend::ProductionSessionBackend(
    control::Random &random,
    ApplicationBridge &applications,
    SessionResourceFactory &resources,
    QuicTransportSink &transport
  ):
      impl_ {std::make_unique<Impl>(random, applications, resources, transport)} {
  }

  ProductionSessionBackend::~ProductionSessionBackend() = default;

#ifdef SUNSHINE_TESTS
  bool ProductionSessionBackend::install_session_for_test(
    const control::Identifier &client_id,
    const control::Identifier &session_id,
    const std::uint64_t connection_id,
    std::unique_ptr<SessionResources> resources
  ) {
    if (!nonzero(client_id) || !nonzero(session_id) || connection_id == 0 || !resources) {
      return false;
    }
    std::scoped_lock lock {impl_->mutex};
    std::shared_ptr<TerminalFailureDispatcher> terminal_failure;
    try {
      terminal_failure = impl_->make_terminal_failure_dispatcher();
    } catch (...) {
      return false;
    }
    if (!terminal_failure) {
      return false;
    }
    return impl_->sessions.emplace(session_id, Impl::ActiveSession {
                                                 .owner_client_id = client_id,
                                                 .start_intent_id = session_id,
                                                 .connection_id = connection_id,
                                                 .authority_generation = 1,
                                                 .media_started = true,
                                                 .terminal_failure_generation = terminal_failure->generation(),
                                                 .terminal_failure = std::move(terminal_failure),
                                                 .resources = std::move(resources),
                                               })
      .second;
  }

  void ProductionSessionBackend::mark_failed_for_test(const control::Identifier &session_id) noexcept {
    std::shared_ptr<TerminalFailureDispatcher> terminal_failure;
    {
      std::scoped_lock lock {impl_->mutex};
      const auto session = impl_->sessions.find(session_id);
      if (session != impl_->sessions.end()) {
        terminal_failure = session->second.terminal_failure;
      }
    }
    if (terminal_failure) {
      terminal_failure->report();
    }
  }

  void ProductionSessionBackend::fail_next_start_before_commit_for_test() noexcept {
    std::scoped_lock lock {impl_->mutex};
    impl_->fail_start_before_commit_for_test = true;
  }
#endif

  std::expected<control::StartResult, std::uint8_t> ProductionSessionBackend::start(
    const control::ClientRecord &client,
    const Map &request_fields,
    const std::uint64_t connection_id,
    const std::uint16_t maximum_datagram_bytes
  ) {
    std::scoped_lock lock {impl_->mutex};
    if ((client.permissions & control::start_permission) == 0) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unauthorized));
    }
    if (connection_id == 0 || maximum_datagram_bytes < quic_server::maximum_semantic_datagram_bytes ||
        impl_->sessions.size() >= 8 ||
        std::ranges::any_of(impl_->sessions, [&](const auto &entry) {
          return entry.second.owner_client_id == client.client_id;
        })) {
      return std::unexpected(static_cast<std::uint8_t>(Status::busy));
    }
    if (!exact_keys(request_fields, 1, 18)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    const auto intent = fixed_field<16>(request_fields, 1);
    const auto trace = fixed_field<16>(request_fields, 13);
    const auto *app = unsigned_field(request_fields, 2);
    const auto *profile = unsigned_field(request_fields, 3);
    const auto *width = unsigned_field(request_fields, 4);
    const auto *height = unsigned_field(request_fields, 5);
    const auto *refresh_numerator = unsigned_field(request_fields, 6);
    const auto *refresh_denominator = unsigned_field(request_fields, 7);
    const auto *bitrate = unsigned_field(request_fields, 8);
    const auto *codec_offers = array_field(request_fields, 9);
    const auto *audio_offers = array_field(request_fields, 10);
    const auto *microphone_value = field(request_fields, 11);
    const auto *presentation_offers = array_field(request_fields, 15);
    const auto *resume = field(request_fields, 16);
    const auto *resume_value = resume ? std::get_if<bool>(&resume->storage) : nullptr;
    const auto *host_audio = field(request_fields, 18);
    const auto *host_audio_value = host_audio ? std::get_if<bool>(&host_audio->storage) : nullptr;
    if (!intent || !trace || !app || !profile || !width || !height || !refresh_numerator ||
        !refresh_denominator || !bitrate || !codec_offers || codec_offers->empty() ||
        !audio_offers || audio_offers->empty() || !microphone_value || !presentation_offers ||
        presentation_offers->empty() || !resume_value || !host_audio_value ||
        *app > UINT32_MAX || *width > UINT32_MAX ||
        *height > UINT32_MAX || *refresh_numerator > UINT32_MAX || *refresh_denominator > UINT32_MAX ||
        *bitrate > UINT32_MAX || (*profile != 1 && *profile != 2)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    if (const auto expired = impl_->expired_intents.find({client.client_id, *intent});
        expired != impl_->expired_intents.end() && expired->second > quic_server::MonotonicClock::now()) {
      return std::unexpected(static_cast<std::uint8_t>(Status::busy));
    }
    const control::cbor::Value *selected_codec_value {};
    const Map *codec {};
    for (const auto &offer : *codec_offers) {
      const auto *candidate = std::get_if<Map>(&offer.storage);
      if (!candidate || !exact_keys(*candidate, 1, 10)) {
        continue;
      }
      const auto *candidate_codec = unsigned_field(*candidate, 1);
      const auto *candidate_depth = unsigned_field(*candidate, 3);
      const auto *candidate_layout = unsigned_field(*candidate, 4);
      const auto *candidate_primaries = unsigned_field(*candidate, 5);
      const auto *candidate_transfer = unsigned_field(*candidate, 6);
      const auto *candidate_matrix = unsigned_field(*candidate, 7);
      const auto *candidate_range = unsigned_field(*candidate, 8);
      const auto *candidate_flags = unsigned_field(*candidate, 9);
      const auto *candidate_fidelity = unsigned_field(*candidate, 10);
      if (!candidate_codec || !candidate_depth || !candidate_layout || !candidate_primaries ||
          !candidate_transfer || !candidate_matrix || !candidate_range || !candidate_flags ||
          !candidate_fidelity || *candidate_codec < 1 || *candidate_codec > 3 ||
          (*candidate_depth != 8 && *candidate_depth != 10) ||
          (*candidate_layout != 1 && *candidate_layout != 2) ||
          (*candidate_transfer != 1 && *candidate_transfer != 16 && *candidate_transfer != 18) ||
          (*candidate_matrix != 1 && *candidate_matrix != 5 && *candidate_matrix != 6 && *candidate_matrix != 9) ||
          *candidate_range > 1 ||
          (*candidate_transfer != 1 && (*candidate_depth != 10 || *candidate_primaries != 9 || *candidate_matrix != 9)) ||
          *candidate_fidelity < 1 || *candidate_fidelity > 3) {
        continue;
      }
      const auto index = static_cast<std::size_t>(*candidate_codec - 1);
      const auto codec_available = *candidate_codec == 1 ||
                                   (*candidate_codec == 2 && video::active_hevc_mode >= 2) ||
                                   (*candidate_codec == 3 && video::active_av1_mode >= 2);
      const auto ten_bit_available = *candidate_depth == 8 ||
                                     (*candidate_codec == 2 &&
                                      (video::active_hevc_mode == 3 || video::active_hevc_mode == 5)) ||
                                     (*candidate_codec == 3 &&
                                      (video::active_av1_mode == 3 || video::active_av1_mode == 5));
      const auto chroma_available = *candidate_layout == 1 ||
                                    (video::last_encoder_probe_supported_yuv444_for_codec[index] &&
                                     ((*candidate_codec == 1 && *candidate_depth == 8) ||
                                      (*candidate_codec == 2 && video::active_hevc_mode >= 4) ||
                                      (*candidate_codec == 3 && video::active_av1_mode >= 4)));
      const auto lossless_available = *candidate_fidelity != 3 ||
                                      (((*candidate_flags & 0x02U) != 0) &&
                                       video::current_nvenc_lossless_capability(static_cast<int>(index)));
      if (codec_available && ten_bit_available && chroma_available && lossless_available) {
        selected_codec_value = &offer;
        codec = candidate;
        break;
      }
    }
    const control::cbor::Value *selected_audio_value {};
    std::optional<media::OpusTuple> audio;
    for (const auto &offer : *audio_offers) {
      const auto *candidate = std::get_if<Map>(&offer.storage);
      if (!candidate) {
        continue;
      }
      const auto parsed = parse_opus_tuple(*candidate);
      if (parsed && (parsed->channels == 2 || parsed->channels == 6 || parsed->channels == 8)) {
        selected_audio_value = &offer;
        audio = *parsed;
        break;
      }
    }
    const control::cbor::Value *selected_presentation_value {};
    for (const auto &offer : *presentation_offers) {
      const auto *candidate = std::get_if<Map>(&offer.storage);
      const auto *mode = candidate ? unsigned_field(*candidate, 1) : nullptr;
      const auto *queued = candidate ? unsigned_field(*candidate, 2) : nullptr;
      const auto compatible = mode && ((*profile == 1 && (*mode == 1 || *mode == 2)) ||
                                       (*profile == 2 && *mode == 3));
      if (candidate && exact_keys(*candidate, 1, 5) && compatible && queued && *queued >= 1 && *queued <= 2) {
        selected_presentation_value = &offer;
        break;
      }
    }
    if (!codec || !selected_codec_value || !audio || !selected_audio_value || !selected_presentation_value) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }
    const auto *codec_id = unsigned_field(*codec, 1);
    const auto *bit_depth = unsigned_field(*codec, 3);
    const auto *layout = unsigned_field(*codec, 4);
    const auto *primaries = unsigned_field(*codec, 5);
    const auto *transfer = unsigned_field(*codec, 6);
    const auto *matrix = unsigned_field(*codec, 7);
    const auto *range = unsigned_field(*codec, 8);
    const auto *codec_flags = unsigned_field(*codec, 9);
    const auto *fidelity = unsigned_field(*codec, 10);
    if (!codec_id || !bit_depth || !layout || !primaries || !transfer || !matrix || !range ||
        !codec_flags || !fidelity || *codec_id > UINT8_MAX ||
        *bit_depth > UINT8_MAX || *layout > UINT8_MAX || *primaries > UINT8_MAX ||
        *transfer > UINT8_MAX || *matrix > UINT8_MAX || *range > UINT8_MAX ||
        *codec_flags > UINT8_MAX || *fidelity > UINT8_MAX) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }

    media::NegotiatedMediaConfig selected;
    bool unique_session_id = false;
    for (unsigned int attempt = 0; attempt < 8 && !unique_session_id; ++attempt) {
      unique_session_id = impl_->random_nonzero(selected.session_id) &&
                          !impl_->sessions.contains(selected.session_id);
    }
    if (!unique_session_id) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    control::Bytes32 attach_token {};
    if (!impl_->random_nonzero(attach_token)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    selected.profile = *profile == 1 ? quic_server::Profile::latency : quic_server::Profile::quality;
    selected.semantic_datagram_bytes = quic_server::maximum_semantic_datagram_bytes;
    selected.video_bitrate_kbps = static_cast<std::uint32_t>(*bitrate);
    selected.width = static_cast<std::uint32_t>(*width);
    selected.height = static_cast<std::uint32_t>(*height);
    selected.refresh_numerator = static_cast<std::uint32_t>(*refresh_numerator);
    selected.refresh_denominator = static_cast<std::uint32_t>(*refresh_denominator);
    selected.codec_id = static_cast<std::uint8_t>(*codec_id);
    selected.matrix_code = static_cast<std::uint8_t>(*matrix);
    selected.bit_depth = static_cast<std::uint8_t>(*bit_depth);
    selected.chroma_layout = static_cast<std::uint8_t>(*layout);
    selected.primaries = static_cast<std::uint8_t>(*primaries);
    selected.transfer = static_cast<std::uint8_t>(*transfer == 16 ? 2 : *transfer == 18 ? 3 : 1);
    selected.range = static_cast<std::uint8_t>(*range);
    selected.codec_flags = static_cast<std::uint8_t>(*codec_flags);
    selected.fidelity = static_cast<std::uint8_t>(*fidelity);
    selected.audio = *audio;
    selected.host_audio = *host_audio_value;
    if (const auto *microphone_map = std::get_if<Map>(&microphone_value->storage)) {
      if ((client.permissions & control::microphone_permission) == 0) {
        return std::unexpected(static_cast<std::uint8_t>(Status::unauthorized));
      }
      const auto microphone = parse_opus_tuple(*microphone_map);
      if (!microphone) {
        return std::unexpected(microphone.error());
      }
      selected.microphone = *microphone;
      selected.microphone_enabled = true;
    } else if (!std::holds_alternative<control::cbor::Null>(microphone_value->storage)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    const auto *selected_presentation = std::get_if<Map>(&selected_presentation_value->storage);
    const auto *presentation_mode = selected_presentation ? unsigned_field(*selected_presentation, 1) : nullptr;
    const auto *presentation_queue = selected_presentation ? unsigned_field(*selected_presentation, 2) : nullptr;
    if (!presentation_mode || !presentation_queue ||
        start_mode::admit(start_mode::Request {
          {
            selected.width,
            selected.height,
            selected.refresh_numerator,
            selected.refresh_denominator,
            selected.codec_id,
            selected.bit_depth,
            selected.chroma_layout,
            selected.transfer,
            selected.codec_flags,
            selected.fidelity,
          },
          *bitrate,
          *profile,
          *presentation_mode,
          *presentation_queue,
          selected.microphone_enabled,
          true,
          selected.host_audio,
          true,
        }) != start_mode::AdmissionError::none) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }
    const auto *hdr_offers = array_field(request_fields, 14);
    control::cbor::Value selected_hdr {control::cbor::Null {}};
    std::uint32_t client_maximum_mastering {};
    std::uint16_t client_maximum_cll {};
    std::uint16_t client_maximum_fall {};
    if (*transfer != 1 && hdr_offers) {
      for (const auto &offer : *hdr_offers) {
        const auto *candidate = std::get_if<Map>(&offer.storage);
        const auto *hdr_transfer = candidate ? unsigned_field(*candidate, 1) : nullptr;
        const auto *hdr_primaries = candidate ? unsigned_field(*candidate, 2) : nullptr;
        const auto *hdr_matrix = candidate ? unsigned_field(*candidate, 3) : nullptr;
        const auto *hdr_range = candidate ? unsigned_field(*candidate, 4) : nullptr;
        const auto *hdr_depth = candidate ? unsigned_field(*candidate, 5) : nullptr;
        const auto *static_capability_value = candidate ? field(*candidate, 6) : nullptr;
        const auto *static_capability = static_capability_value ?
                                          std::get_if<Map>(&static_capability_value->storage) :
                                          nullptr;
        const auto *static_supported_value = static_capability ? field(*static_capability, 1) : nullptr;
        const auto *static_supported = static_supported_value ?
                                         std::get_if<bool>(&static_supported_value->storage) :
                                         nullptr;
        const auto *maximum_mastering = static_capability ? unsigned_field(*static_capability, 2) : nullptr;
        const auto *maximum_cll = static_capability ? unsigned_field(*static_capability, 3) : nullptr;
        const auto *maximum_fall = static_capability ? unsigned_field(*static_capability, 4) : nullptr;
        const auto *dynamic_metadata = candidate ? array_field(*candidate, 7) : nullptr;
        const auto common_match = candidate && exact_keys(*candidate, 1, 7) && hdr_transfer && hdr_primaries &&
            hdr_matrix && hdr_range && hdr_depth && static_capability && exact_keys(*static_capability, 1, 4) &&
            static_supported && maximum_mastering && *maximum_mastering <= UINT32_MAX &&
            maximum_cll && *maximum_cll <= UINT16_MAX && maximum_fall && *maximum_fall <= UINT16_MAX &&
            dynamic_metadata &&
            ((*hdr_transfer == 2 && *transfer == 16) || (*hdr_transfer == 3 && *transfer == 18)) &&
            *hdr_primaries == *primaries && *hdr_matrix == *matrix && *hdr_range == *range &&
            *hdr_depth == *bit_depth && *bit_depth == 10 && (*hdr_transfer == 2 || *hdr_transfer == 3);
        const auto pq_static_match = *transfer != 16 || (common_match && *static_supported);
        if (common_match && pq_static_match) {
          client_maximum_mastering = static_cast<std::uint32_t>(*maximum_mastering);
          client_maximum_cll = static_cast<std::uint16_t>(*maximum_cll);
          client_maximum_fall = static_cast<std::uint16_t>(*maximum_fall);
          selected_hdr = Map {
            {1, *hdr_transfer},
            {2, *hdr_primaries},
            {3, *hdr_matrix},
            {4, *hdr_range},
            {5, *hdr_depth},
            {6, control::cbor::Null {}},
            {7, Array {}},
          };
          break;
        }
      }
    }
    const auto hdr_selected = !std::holds_alternative<control::cbor::Null>(selected_hdr.storage);
    if ((*transfer == 1 && hdr_selected) || (*transfer != 1 && !hdr_selected)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }
    const auto *quality_value = field(request_fields, 17);
    const auto *quality = quality_value ? std::get_if<Map>(&quality_value->storage) : nullptr;
    const auto quality_bool = [&](const std::uint64_t key) -> std::optional<bool> {
      const auto *value = quality ? field(*quality, key) : nullptr;
      const auto *boolean = value ? std::get_if<bool>(&value->storage) : nullptr;
      return boolean ? std::optional {*boolean} : std::nullopt;
    };
    const auto *minimum_fidelity = quality ? unsigned_field(*quality, 1) : nullptr;
    const auto require_rgb = quality_bool(2);
    const auto require_444 = quality_bool(3);
    const auto require_10_bit = quality_bool(4);
    const auto require_hdr = quality_bool(5);
    const auto allow_adjustment = quality_bool(6);
    if (!quality || !exact_keys(*quality, 1, 6) || !minimum_fidelity || !require_rgb ||
        !require_444 || !require_10_bit || !require_hdr || !allow_adjustment ||
        *minimum_fidelity > *fidelity || *require_rgb || (*require_444 && *layout != 2) ||
        (*require_10_bit && *bit_depth != 10) || (*require_hdr && !hdr_selected)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }

    Array adjustments;
    if (selected_codec_value != &codec_offers->front()) {
      adjustments.emplace_back(Map {
        {1, 4U},
        {2, codec_offers->front()},
        {3, *selected_codec_value},
        {4, 1U},
      });
    }
    if (selected_audio_value != &audio_offers->front()) {
      adjustments.emplace_back(Map {
        {1, 8U},
        {2, audio_offers->front()},
        {3, *selected_audio_value},
        {4, 1U},
      });
    }
    if (selected_presentation_value != &presentation_offers->front()) {
      adjustments.emplace_back(Map {
        {1, 7U},
        {2, presentation_offers->front()},
        {3, *selected_presentation_value},
        {4, 1U},
      });
    }
    if (!adjustments.empty() && !*allow_adjustment) {
      return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
    }
    if (impl_->next_authority_generation == UINT64_MAX) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    const auto authority_generation = impl_->next_authority_generation;
    Map response {
      {2, bytes(*intent)},
      {3, bytes(selected.session_id)},
      {4, *profile},
      {5, *selected_codec_value},
      {6, *width},
      {7, *height},
      {8, *refresh_numerator},
      {9, *refresh_denominator},
      {10, *bitrate},
      {11, static_cast<std::uint64_t>(quic_server::maximum_semantic_datagram_bytes)},
      {12, *selected_audio_value},
      {13, *microphone_value},
      {14, 1U},
      {15, 1U},
      {16, 1U},
      {17, 1U},
      {18, *selected_presentation_value},
      {19, std::move(adjustments)},
      {20, bytes(*trace)},
      {21, bytes(attach_token)},
      {22, authority_generation},
      {23, std::move(selected_hdr)},
    };

    bool policy_updated = false;
    bool launched_application = false;
    bool session_committed = false;
    std::unique_ptr<SessionResources> staged_resources;
    std::shared_ptr<TerminalFailureDispatcher> terminal_failure;
    try {
      terminal_failure = impl_->make_terminal_failure_dispatcher();
    } catch (...) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    if (!terminal_failure) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    auto rollback = util::fail_guard([&]() noexcept {
      terminal_failure->revoke();
      if (session_committed) {
        const auto committed = impl_->sessions.find(selected.session_id);
        if (committed != impl_->sessions.end()) {
          if (committed->second.resources) {
            staged_resources = std::move(committed->second.resources);
          }
          launched_application = launched_application || committed->second.launched_application;
          impl_->sessions.erase(committed);
        }
      }
      if (staged_resources) {
        staged_resources->stop();
      }
      if (launched_application) {
        impl_->applications.stop(true);
      }
      if (policy_updated) {
        static_cast<void>(impl_->transport.reset_policy(connection_id));
      }
    });

    if (!impl_->transport.update_policy(
          connection_id,
          selected.profile,
          selected.video_bitrate_kbps
        )) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    policy_updated = true;

    std::expected<std::unique_ptr<SessionResources>, std::uint8_t> resources =
      std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    try {
      resources = impl_->factory.create(selected, connection_id, terminal_failure);
    } catch (...) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    if (!resources || !*resources) {
      return std::unexpected(resources ? static_cast<std::uint8_t>(Status::resource_failure) : resources.error());
    }
    staged_resources = std::move(*resources);
    if (terminal_failure->reported()) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    const auto &effective = staged_resources->effective_media_config();
    const auto immutable_selection_matches =
      effective.session_id == selected.session_id && effective.profile == selected.profile &&
      effective.semantic_datagram_bytes == selected.semantic_datagram_bytes &&
      effective.video_bitrate_kbps == selected.video_bitrate_kbps &&
      effective.width == selected.width && effective.height == selected.height &&
      effective.refresh_numerator == selected.refresh_numerator &&
      effective.refresh_denominator == selected.refresh_denominator &&
      effective.codec_id == selected.codec_id && effective.matrix_code == selected.matrix_code &&
      effective.bit_depth == selected.bit_depth && effective.chroma_layout == selected.chroma_layout &&
      effective.primaries == selected.primaries && effective.transfer == selected.transfer &&
      effective.range == selected.range && effective.codec_flags == selected.codec_flags &&
      effective.fidelity == selected.fidelity && effective.host_audio == selected.host_audio;
    if (!immutable_selection_matches ||
        (selected.transfer == 1 && effective.static_hdr_metadata) ||
        (selected.transfer == 2 && !effective.static_hdr_metadata) ||
        (selected.transfer == 3 && effective.static_hdr_metadata)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    selected.static_hdr_metadata = effective.static_hdr_metadata;
    if (selected.transfer == 2) {
      const auto &metadata = *selected.static_hdr_metadata;
      const auto valid_chromaticity = std::ranges::all_of(metadata.display_primaries, [](const auto coordinate) {
        return coordinate != 0 && coordinate <= 50'000;
      }) && std::ranges::all_of(metadata.white_point, [](const auto coordinate) {
        return coordinate != 0 && coordinate <= 50'000;
      });
      if (!valid_chromaticity || metadata.maximum_mastering_luminance == 0 ||
          metadata.minimum_mastering_luminance > metadata.maximum_mastering_luminance ||
          metadata.maximum_mastering_luminance > client_maximum_mastering ||
          metadata.maximum_content_light_level > client_maximum_cll ||
          metadata.maximum_frame_average_light_level > client_maximum_fall) {
        return std::unexpected(static_cast<std::uint8_t>(Status::unsupported_media));
      }
      auto *response_hdr = std::get_if<Map>(&response.back().second.storage);
      if (!response_hdr) {
        return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
      }
      const auto mastering_field = std::ranges::find_if(*response_hdr, [](const auto &entry) {
        return entry.first == 6;
      });
      if (mastering_field == response_hdr->end()) {
        return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
      }
      Array primary_values;
      primary_values.reserve(metadata.display_primaries.size());
      for (const auto coordinate : metadata.display_primaries) {
        primary_values.emplace_back(coordinate);
      }
      mastering_field->second = Map {
        {1, std::move(primary_values)},
        {2, Array {metadata.white_point[0], metadata.white_point[1]}},
        {3, metadata.maximum_mastering_luminance},
        {4, metadata.minimum_mastering_luminance},
        {5, metadata.maximum_content_light_level},
        {6, metadata.maximum_frame_average_light_level},
      };
    }
    const auto codec_initialization_view = staged_resources->video_codec_initialization();
    if (codec_initialization_view.empty() || codec_initialization_view.size() > 1'048'576U) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    Bytes codec_initialization {
      codec_initialization_view.begin(),
      codec_initialization_view.end()
    };
    ApplicationLaunch launch {
      .application_id = static_cast<std::uint32_t>(*app),
      .width = selected.width,
      .height = selected.height,
      .refresh_numerator = selected.refresh_numerator,
      .refresh_denominator = selected.refresh_denominator,
      .host_audio = selected.host_audio,
      .enable_hdr = selected.transfer != 1,
      .audio = selected.audio,
      .resume = *resume_value,
    };
    std::expected<bool, std::uint8_t> application =
      std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    try {
      application = impl_->applications.start(launch);
    } catch (...) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
    if (!application) {
      return std::unexpected(application.error());
    }
    launched_application = *application;
    if (terminal_failure->reported()) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
#ifdef SUNSHINE_TESTS
    if (impl_->fail_start_before_commit_for_test) {
      impl_->fail_start_before_commit_for_test = false;
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
#endif
    try {
      std::vector<control::HostControlRequest> host_requests;
      host_requests.reserve(selected.microphone_enabled ? 3 : 2);
      host_requests.push_back({
        0x0140,
        {
          {1, bytes(selected.session_id)},
          {2, 1U},
          {3, *selected_codec_value},
          {4, std::move(codec_initialization)},
          {5, response.back().second},
          {6, *width},
          {7, *height},
          {8, *refresh_numerator},
          {9, *refresh_denominator},
        },
      });
      host_requests.push_back({
        0x0142,
        {{1, bytes(selected.session_id)}, {2, 1U}, {3, *selected_audio_value}, {4, 0U}},
      });
      if (selected.microphone_enabled) {
        host_requests.push_back({
          0x0144,
          {{1, bytes(selected.session_id)}, {2, 1U}, {3, *microphone_value}, {4, 0U}},
        });
      }
      const auto [committed, inserted] = impl_->sessions.try_emplace(selected.session_id);
      if (!inserted) {
        return std::unexpected(static_cast<std::uint8_t>(Status::busy));
      }
      session_committed = true;
      auto &active = committed->second;
      active.owner_client_id = client.client_id;
      active.start_intent_id = *intent;
      active.attach_token = attach_token;
      active.connection_id = connection_id;
      active.authority_generation = authority_generation;
      active.profile = selected.profile;
      active.video_bitrate_kbps = selected.video_bitrate_kbps;
      active.launched_application = launched_application;
      active.microphone_required = selected.microphone_enabled;
      active.configuration_deadline = quic_server::MonotonicClock::now() + std::chrono::seconds {3};
      active.terminal_failure_generation = terminal_failure->generation();
      active.terminal_failure = terminal_failure;
      active.resources = std::move(staged_resources);
      ++impl_->next_authority_generation;
      impl_->watchdog_wakeup->notify_all();
      rollback.disable();
      return control::StartResult {selected.session_id, std::move(response), std::move(host_requests)};
    } catch (...) {
      return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
    }
  }

  std::expected<control::ControlResult, std::uint8_t> ProductionSessionBackend::control(
    const control::ClientRecord &client,
    const control::AuthenticatedControl request,
    const Map &request_fields,
    const std::uint64_t request_id,
    const std::uint64_t connection_id,
    const std::uint64_t connection_authority_generation
  ) {
    std::unique_lock lock {impl_->mutex};
    const auto make_result = [&](Map fields) {
      return control::ControlResult {request, std::move(fields)};
    };
    switch (request) {
      case control::AuthenticatedControl::ping:
        {
          const auto *client_send = unsigned_field(request_fields, 1);
          const auto *probe = unsigned_field(request_fields, 2);
          if (!exact_keys(request_fields, 1, 2) || !client_send || !probe) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          const auto receive = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                            std::chrono::steady_clock::now().time_since_epoch()
          )
                                                            .count());
          const auto send = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                         std::chrono::steady_clock::now().time_since_epoch()
          )
                                                         .count());
          return make_result({{1, *client_send}, {2, *probe}, {3, receive}, {4, send}});
        }
      case control::AuthenticatedControl::application_list:
        {
          const auto *cursor = unsigned_field(request_fields, 1);
          const auto *limit = unsigned_field(request_fields, 2);
          const auto *known = unsigned_field(request_fields, 3);
          if ((!exact_keys(request_fields, 1, 2) && !exact_keys(request_fields, 1, 3)) ||
              !cursor || !limit || *limit == 0 || *limit > 128 || (*cursor != 0 && !known)) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          auto snapshot = impl_->applications.snapshot();
          if (!snapshot) {
            return std::unexpected(snapshot.error());
          }
          if ((*cursor != 0 && (!known || *known != snapshot->revision)) || *cursor > snapshot->entries.size()) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::busy)},
              {2, snapshot->revision},
              {3, Array {}},
              {4, control::cbor::Null {}},
              {5, control::cbor::Value {false}},
            });
          }
          if (*cursor == 0 && known && *known == snapshot->revision) {
            return make_result({{1, 0U}, {2, snapshot->revision}, {3, Array {}}, {4, control::cbor::Null {}}, {5, control::cbor::Value {true}}});
          }
          Array entries;
          const auto end = std::min<std::size_t>(snapshot->entries.size(), static_cast<std::size_t>(*cursor + *limit));
          entries.reserve(end - static_cast<std::size_t>(*cursor));
          for (auto index = static_cast<std::size_t>(*cursor); index < end; ++index) {
            const auto &entry = snapshot->entries[index];
            control::cbor::Value asset = entry.asset_sha256 ? control::cbor::Value {bytes(*entry.asset_sha256)} :
                                                              control::cbor::Value {control::cbor::Null {}};
            entries.emplace_back(Map {
              {1, entry.application_id},
              {2, entry.display_name},
              {3, entry.state},
              {4, entry.flags},
              {5, std::move(asset)},
              {6, entry.last_changed_revision},
              {7, entry.launch_capabilities},
            });
          }
          control::cbor::Value next = end < snapshot->entries.size() ? control::cbor::Value {static_cast<std::uint64_t>(end)} :
                                                                       control::cbor::Value {control::cbor::Null {}};
          return make_result({{1, 0U}, {2, snapshot->revision}, {3, std::move(entries)}, {4, std::move(next)}, {5, control::cbor::Value {false}}});
        }
      case control::AuthenticatedControl::application_asset:
        {
          const auto *app = unsigned_field(request_fields, 1);
          const auto digest = fixed_field<32>(request_fields, 2);
          const auto *offset = unsigned_field(request_fields, 3);
          const auto *maximum = unsigned_field(request_fields, 4);
          if (!exact_keys(request_fields, 1, 4) || !app || !digest || !offset || !maximum) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          if (*offset != 0 || *maximum == 0 || *maximum > 16U * 1024U * 1024U) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          auto asset = impl_->applications.asset(*app, *digest);
          if (!asset) {
            return make_result({
              {1, static_cast<std::uint64_t>(asset.error())},
              {2, *app},
              {3, bytes(*digest)},
              {4, "image/png"},
              {5, 1U},
              {6, 0U},
              {7, 0U},
            });
          }
          std::array<std::uint8_t, 8> object_bytes {};
          if (!impl_->random_nonzero(object_bytes)) {
            return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
          }
          std::uint64_t object_id = 0;
          for (const auto byte : object_bytes) {
            object_id = (object_id << 8U) | byte;
          }
          auto bulk = std::make_shared<std::vector<std::uint8_t>>();
          bulk->reserve(64 + asset->bytes.size());
          bulk->insert(bulk->end(), {'U', 'L', 'B', '3', 3, 1, 0, 0});
          append_big_endian(*bulk, request_id, 8);
          append_big_endian(*bulk, object_id, 8);
          append_big_endian(*bulk, asset->bytes.size(), 8);
          bulk->insert(bulk->end(), asset->sha256.begin(), asset->sha256.end());
          bulk->insert(bulk->end(), asset->bytes.begin(), asset->bytes.end());
          return control::ControlResult {
            request,
            {
              {1, 0U},
              {2, asset->application_id},
              {3, bytes(asset->sha256)},
              {4, asset->mime},
              {5, 1U},
              {6, asset->bytes.size()},
              {7, object_id},
            },
            quic_server::BulkTransfer {request_id, object_id, std::move(bulk)},
          };
        }
      case control::AuthenticatedControl::stop:
        {
          const auto session_id = fixed_field<16>(request_fields, 1);
          const auto *action = unsigned_field(request_fields, 2);
          const auto *reason = unsigned_field(request_fields, 3);
          const auto stop_intent = fixed_field<16>(request_fields, 4);
          if (!exact_keys(request_fields, 1, 4) || !session_id || !action || !reason || !stop_intent ||
              *action > 1 || *reason < 1 || *reason > 3) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          if (*action == 1 && (client.permissions & (1U << 5)) == 0) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::unauthorized)},
              {2, bytes(*session_id)},
              {3, bytes(*stop_intent)},
              {4, control::cbor::Value {false}},
            });
          }
          const auto session = impl_->owned_session(*session_id, client.client_id);
          if (session == impl_->sessions.end()) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::unauthorized)},
              {2, bytes(*session_id)},
              {3, bytes(*stop_intent)},
              {4, control::cbor::Value {false}},
            });
          }
          // Remove callback-visible authority before crossing the blocking
          // native teardown barrier. Capture threads may report terminal
          // failure while stop() joins them; revocation makes those reports inert.
          if (session->second.terminal_failure) {
            session->second.terminal_failure->revoke();
          }
          auto stopped_session = std::move(session->second);
          impl_->sessions.erase(session);
          impl_->watchdog_wakeup->notify_all();
          lock.unlock();

          stopped_session.resources->stop();
          const auto application_quit = impl_->applications.stop(*action == 1);
          if (stopped_session.connection_id != 0) {
            static_cast<void>(impl_->transport.reset_policy(stopped_session.connection_id));
          }
          auto result = make_result({{1, 0U}, {2, bytes(*session_id)}, {3, bytes(*stop_intent)}, {4, control::cbor::Value {application_quit}}});
          result.post_response_events.push_back({
            0x0133,
            {
              {1, bytes(*session_id)},
              {2, *reason},
              {3, static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(quic_server::MonotonicClock::now().time_since_epoch()).count())},
              {4, control::cbor::Value {impl_->applications.running()}},
              {5, 0U},
              {6, 0U},
              {7, 0U},
              {8, 0U},
            },
          });
          return result;
        }
      case control::AuthenticatedControl::input_reset:
        {
          const auto session_id = fixed_field<16>(request_fields, 1);
          const auto *state = bytes_field(request_fields, 2);
          if (!exact_keys(request_fields, 1, 2) || !session_id || !state ||
              lumen::protocol_common::input_state::validate(*state)) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          const auto session = impl_->owned_session(*session_id, client.client_id);
          if (session == impl_->sessions.end()) {
            return make_result({{1, static_cast<std::uint64_t>(Status::unauthorized)}, {2, 0U}});
          }
          if (session->second.input_generation == UINT32_MAX ||
              !session->second.resources->reset_input(
                *state,
                session->second.input_generation + 1
              )) {
            return make_result({{1, static_cast<std::uint64_t>(Status::resource_failure)}, {2, session->second.input_generation}});
          }
          session->second.input_baseline_required = false;
          return make_result({{1, 0U}, {2, ++session->second.input_generation}});
        }
      case control::AuthenticatedControl::text_composition:
        {
          const auto session_id = fixed_field<16>(request_fields, 1);
          const auto *composition = unsigned_field(request_fields, 2);
          const auto *operation = unsigned_field(request_fields, 3);
          const auto *expected_revision = unsigned_field(request_fields, 4);
          const auto *phase = unsigned_field(request_fields, 5);
          if (!exact_keys(request_fields, 1, 10) || !session_id || !composition || !operation ||
              !expected_revision || !phase || *phase < 1 || *phase > 4) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          const auto session = impl_->owned_session(*session_id, client.client_id);
          if (session == impl_->sessions.end()) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::unauthorized)},
              {2, bytes(*session_id)},
              {3, *composition},
              {4, *operation},
              {5, 0U},
            });
          }
          if (*operation <= session->second.last_text_operation || *expected_revision != session->second.text_revision ||
              session->second.input_baseline_required || session->second.text_revision == UINT32_MAX ||
              !session->second.resources->apply_text(request_fields)) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::busy)},
              {2, bytes(*session_id)},
              {3, *composition},
              {4, *operation},
              {5, session->second.text_revision},
            });
          }
          session->second.last_text_operation = *operation;
          ++session->second.text_revision;
          return make_result({
            {1, 0U},
            {2, bytes(*session_id)},
            {3, *composition},
            {4, *operation},
            {5, session->second.text_revision},
          });
        }
      case control::AuthenticatedControl::session_attach:
        {
          const auto session_id = fixed_field<16>(request_fields, 1);
          const auto attach_token = fixed_field<32>(request_fields, 2);
          const auto attach_intent = fixed_field<16>(request_fields, 3);
          const auto *last_input_generation = unsigned_field(request_fields, 4);
          const auto *last_generations = field(request_fields, 5);
          const auto *generation_map = last_generations ? std::get_if<Map>(&last_generations->storage) : nullptr;
          const auto *last_video = generation_map ? unsigned_field(*generation_map, 1) : nullptr;
          const auto *last_audio = generation_map ? unsigned_field(*generation_map, 2) : nullptr;
          const auto *last_microphone = generation_map ? unsigned_field(*generation_map, 3) : nullptr;
          if (!exact_keys(request_fields, 1, 5) || !session_id || !attach_token || !attach_intent ||
              !nonzero(*attach_intent) || !last_input_generation || !generation_map ||
              !exact_keys(*generation_map, 1, 3) || !last_video || !last_audio || !last_microphone ||
              connection_id == 0 || connection_authority_generation == 0) {
            return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
          }
          const auto session = impl_->owned_session(*session_id, client.client_id);
          const auto generations = Map {{1, 1U}, {2, 1U}, {3, 1U}};
          if (session == impl_->sessions.end()) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::unauthorized)},
              {2, bytes(*session_id)},
              {3, connection_authority_generation},
              {4, 0U},
              {5, control::cbor::Value {true}},
              {6, generations},
            });
          }
          const auto now = quic_server::MonotonicClock::now();
          const auto media_generations =
            std::array<std::uint64_t, 3> {*last_video, *last_audio, *last_microphone};
          const auto cached = session->second.attach_outcomes.lookup(
            *attach_intent,
            *last_input_generation,
            media_generations,
            now
          );
          if (cached.match == AttachIntentCache::Match::exact &&
              secure_equal(session->second.attach_token, *attach_token)) {
            return control::ControlResult {request, cached.response_fields};
          }
          if (cached.match != AttachIntentCache::Match::missing) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::unauthorized)},
              {2, bytes(*session_id)},
              {3, connection_authority_generation},
              {4, session->second.authority_generation},
              {5, control::cbor::Value {true}},
              {6, generations},
            });
          }
          if (!session->second.attach_deadline || now > *session->second.attach_deadline ||
              !secure_equal(session->second.attach_token, *attach_token) || session->second.connection_id != 0 ||
              session->second.authority_generation == UINT64_MAX) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::unauthorized)},
              {2, bytes(*session_id)},
              {3, connection_authority_generation},
              {4, 0U},
              {5, control::cbor::Value {true}},
              {6, generations},
            });
          }
          if (session->second.attach_outcomes.size() >= 16) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::resource_failure)},
              {2, bytes(*session_id)},
              {3, connection_authority_generation},
              {4, session->second.authority_generation},
              {5, control::cbor::Value {true}},
              {6, generations},
            });
          }
          if (!impl_->transport.update_policy(
                connection_id,
                session->second.profile,
                session->second.video_bitrate_kbps
              )) {
            return make_result({
              {1, static_cast<std::uint64_t>(Status::resource_failure)},
              {2, bytes(*session_id)},
              {3, connection_authority_generation},
              {4, session->second.authority_generation},
              {5, control::cbor::Value {true}},
              {6, generations},
            });
          }
          if (!session->second.resources->attach_connection(connection_id)) {
            static_cast<void>(impl_->transport.reset_policy(connection_id));
            return make_result({
              {1, static_cast<std::uint64_t>(Status::resource_failure)},
              {2, bytes(*session_id)},
              {3, connection_authority_generation},
              {4, session->second.authority_generation},
              {5, control::cbor::Value {true}},
              {6, generations},
            });
          }
          session->second.connection_id = connection_id;
          session->second.attach_deadline.reset();
          ++session->second.authority_generation;
          session->second.input_baseline_required = true;
          impl_->watchdog_wakeup->notify_all();
          Map response_fields {
            {1, 0U},
            {2, bytes(*session_id)},
            {3, connection_authority_generation},
            {4, session->second.authority_generation},
            {5, control::cbor::Value {true}},
            {6, generations},
          };
          if (!session->second.attach_outcomes.commit(
                *attach_intent,
                *last_input_generation,
                media_generations,
                response_fields,
                now
              )) {
            session->second.resources->detach_connection();
            session->second.connection_id = 0;
            session->second.attach_deadline = now + std::chrono::seconds {2};
            static_cast<void>(impl_->transport.reset_policy(connection_id));
            return std::unexpected(static_cast<std::uint8_t>(Status::resource_failure));
          }
          return make_result(std::move(response_fields));
        }
    }
    return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
  }

  std::optional<control::Identifier> ProductionSessionBackend::owned_session(
    const control::ClientRecord &client
  ) {
    std::scoped_lock lock {impl_->mutex};
    const auto now = quic_server::MonotonicClock::now();
    const auto owned = std::ranges::find_if(impl_->sessions, [&](const auto &entry) {
      return entry.second.owner_client_id == client.client_id &&
             (!entry.second.attach_deadline || *entry.second.attach_deadline > now);
    });
    return owned == impl_->sessions.end() ? std::nullopt : std::optional {owned->first};
  }

  void ProductionSessionBackend::datagram(
    const control::ClientRecord &client,
    const quic_server::DatagramRecord &record
  ) {
    std::scoped_lock lock {impl_->mutex};
    const auto session = impl_->owned_session(record.session_id, client.client_id);
    if (session == impl_->sessions.end() || !session->second.media_started ||
        (record.channel == 1 && session->second.input_baseline_required)) {
      throw std::runtime_error {"v3 production DATAGRAM rejected"};
    }
    const auto result = session->second.resources->datagram(record);
    if (result == media::ReceiveResult::malformed || result == media::ReceiveResult::forbidden) {
      throw std::runtime_error {"v3 production DATAGRAM rejected"};
    }
  }

  bool ProductionSessionBackend::acknowledge_configuration(
    const control::ClientRecord &client,
    const control::ConfigurationAcknowledgement acknowledgement,
    const control::Identifier &session_id,
    const std::uint32_t generation,
    const std::optional<std::uint32_t> decoder_capacity
  ) {
    std::scoped_lock lock {impl_->mutex};
    const auto session = impl_->owned_session(session_id, client.client_id);
    if (session == impl_->sessions.end() || generation != 1 || session->second.media_started ||
        quic_server::MonotonicClock::now() > session->second.configuration_deadline) {
      return false;
    }
    switch (acknowledgement) {
      case control::ConfigurationAcknowledgement::video:
        if (!decoder_capacity || (*decoder_capacity != 1 && *decoder_capacity != 2) ||
            session->second.video_configured) {
          return false;
        }
        session->second.video_configured = true;
        session->second.decoder_capacity = decoder_capacity;
        return true;
      case control::ConfigurationAcknowledgement::audio:
        if (decoder_capacity || session->second.audio_configured) {
          return false;
        }
        session->second.audio_configured = true;
        return true;
      case control::ConfigurationAcknowledgement::microphone:
        if (decoder_capacity || !session->second.microphone_required || session->second.microphone_configured) {
          return false;
        }
        session->second.microphone_configured = true;
        return true;
    }
    return false;
  }

  bool ProductionSessionBackend::start_media(
    const control::ClientRecord &client,
    const control::Identifier &session_id
  ) {
    std::scoped_lock lock {impl_->mutex};
    const auto session = impl_->owned_session(session_id, client.client_id);
    if (session == impl_->sessions.end() || session->second.media_started ||
        !session->second.video_configured || !session->second.audio_configured ||
        (session->second.microphone_required && !session->second.microphone_configured) ||
        quic_server::MonotonicClock::now() > session->second.configuration_deadline ||
        !session->second.resources->start_media()) {
      return false;
    }
    session->second.media_started = true;
    impl_->watchdog_wakeup->notify_all();
    return true;
  }

  void ProductionSessionBackend::revoke_connection(const std::uint64_t connection_id) noexcept {
    {
      std::scoped_lock lock {impl_->mutex};
      for (auto &[_, session] : impl_->sessions) {
        if (session.connection_id == connection_id) {
          session.resources->detach_connection();
          session.connection_id = 0;
          session.attach_deadline = quic_server::MonotonicClock::now() + std::chrono::seconds {2};
        }
      }
      impl_->watchdog_wakeup->notify_all();
    }
    static_cast<void>(impl_->transport.revoke(connection_id));
  }

  void ProductionSessionBackend::disconnect(
    const std::optional<control::Identifier> &session_id,
    const std::uint64_t connection_id
  ) noexcept {
    if (!session_id || connection_id == 0) {
      return;
    }
    std::scoped_lock lock {impl_->mutex};
    const auto session = impl_->sessions.find(*session_id);
    if (session != impl_->sessions.end() && session->second.connection_id == connection_id) {
      session->second.resources->detach_connection();
      session->second.connection_id = 0;
      session->second.attach_deadline = quic_server::MonotonicClock::now() + std::chrono::seconds {2};
      impl_->watchdog_wakeup->notify_all();
    }
  }

  void ProductionSessionBackend::revoke_client(const control::Identifier &client_id) noexcept {
    struct RevokedSession {
      std::unique_ptr<SessionResources> resources;
      std::uint64_t connection_id {};
      bool launched_application {};
    };

    std::vector<RevokedSession> revoked;
    {
      std::scoped_lock lock {impl_->mutex};
      for (auto session = impl_->sessions.begin(); session != impl_->sessions.end();) {
        if (session->second.owner_client_id == client_id) {
          if (session->second.terminal_failure) {
            session->second.terminal_failure->revoke();
          }
          revoked.push_back({
            std::move(session->second.resources),
            session->second.connection_id,
            session->second.launched_application,
          });
          session = impl_->sessions.erase(session);
        } else {
          ++session;
        }
      }
      impl_->watchdog_wakeup->notify_all();
    }
    for (auto &session : revoked) {
      session.resources->stop();
      if (session.launched_application) {
        impl_->applications.stop(true);
      }
      if (session.connection_id != 0) {
        static_cast<void>(impl_->transport.revoke(session.connection_id));
      }
    }
  }

  struct ProtocolV3Service::Impl {
    struct ActiveInvitation {
      control::Identifier invitation_id {};
      std::string uri;
      std::uint64_t expires_at_unix_seconds {};
    };

    explicit Impl(ResourceFactoryBuilder resource_builder):
        builder {std::move(resource_builder)} {
      if (builder) {
        resources = builder(transport);
      }
    }

    void clear() noexcept {
      if (server) {
        server->stop();
      }
      {
        std::scoped_lock invitation_lock {invitation_mutex};
        if (active_invitation && authorization) {
          static_cast<void>(authorization->revoke_invitation(active_invitation->invitation_id));
        }
        active_invitation.reset();
      }
      server.reset();
      session_factory.reset();
      backend.reset();
      authorities.reset();
      pairing_admission.reset();
      nonces.reset();
      identity.reset();
      authorization.reset();
      api.reset();
      certificate.reset();
      udp_port = 0;
    }

    ResourceFactoryBuilder builder;
    std::unique_ptr<SessionResourceFactory> resources;
    std::shared_ptr<const quic_server::CertificateCredential> certificate;
    std::unique_ptr<quic_server::MsQuicApi> api;
    control::SecureRandom random;
    std::unique_ptr<PersistentAuthorizationStore> authorization;
    std::unique_ptr<control::SeedHostIdentity> identity;
    std::unique_ptr<control::BoundedNonceRegistry> nonces;
    std::unique_ptr<control::BoundedPairingAdmission> pairing_admission;
    std::unique_ptr<control::ConnectionAuthorities> authorities;
    LumenApplicationBridge applications;
    QuicTransportSink transport;
    std::unique_ptr<ProductionSessionBackend> backend;
    std::unique_ptr<control::SessionFactory> session_factory;
    std::unique_ptr<quic_server::QuicServer> server;
    quic_server::StartupStage startup_stage {quic_server::StartupStage::validation};
    mutable std::mutex invitation_mutex;
    std::optional<ActiveInvitation> active_invitation;
    std::uint16_t udp_port {};
    std::uint64_t pairing_permissions {0x17};
  };

  ProtocolV3Service::ProtocolV3Service(ResourceFactoryBuilder builder):
      impl_ {std::make_unique<Impl>(std::move(builder))} {
  }

  ProtocolV3Service::~ProtocolV3Service() {
    stop();
  }

  quic_server::ApiStatus ProtocolV3Service::start(const ServiceConfig &config) {
    impl_->clear();
    impl_->startup_stage = quic_server::StartupStage::validation;
    if (config.state_file.empty() || config.certificate_file.empty() || config.private_key_file.empty() ||
        config.udp_port == 0 || !impl_->resources || config.pairing_permissions == 0 ||
        (config.pairing_permissions & ~control::defined_permission_mask) != 0 ||
        (config.pairing_permissions & 0x17U) != 0x17U) {
      return quic_server::ApiStatus::invalid_state;
    }
    if (!verify_private_key_file(config.private_key_file)) {
      return quic_server::ApiStatus::invalid_state;
    }
    const auto certificate_pem = file_handler::read_file(config.certificate_file.c_str());
    const auto private_key_pem = file_handler::read_file(config.private_key_file.c_str());
    impl_->certificate = quic_server::make_certificate_credential_from_pem(certificate_pem, private_key_pem);
    if (!impl_->certificate) {
      impl_->clear();
      return quic_server::ApiStatus::invalid_state;
    }
    const auto cng_journal = host_identity_paths_for_state_file(config.state_file).identity.parent_path() /
                             "protocol_v3_cng_keys.journal";
    impl_->api = quic_server::make_native_msquic_api(cng_journal.string());
    if (!impl_->api) {
      impl_->clear();
      return quic_server::ApiStatus::not_supported;
    }
    impl_->authorization = std::make_unique<PersistentAuthorizationStore>(
      config.state_file,
      config.persistent_authorization
    );
    if (!impl_->authorization->ready()) {
      impl_->clear();
      return quic_server::ApiStatus::invalid_state;
    }
    auto seed = impl_->authorization->host_identity_seed(impl_->random);
    if (!seed) {
      impl_->clear();
      return quic_server::ApiStatus::invalid_state;
    }
    try {
      impl_->identity = std::make_unique<control::SeedHostIdentity>(*seed);
      OPENSSL_cleanse(seed->data(), seed->size());
      impl_->nonces = std::make_unique<control::BoundedNonceRegistry>();
      impl_->pairing_admission = std::make_unique<control::BoundedPairingAdmission>();
      impl_->authorities = std::make_unique<control::ConnectionAuthorities>();
      impl_->backend = std::make_unique<ProductionSessionBackend>(
        impl_->random,
        impl_->applications,
        *impl_->resources,
        impl_->transport
      );
      impl_->session_factory = std::make_unique<control::SessionFactory>(
        control::Config {
          .capabilities = control::Config {}.capabilities,
          .default_pairing_permissions = config.pairing_permissions,
        },
        impl_->random,
        *impl_->identity,
        *impl_->authorization,
        *impl_->nonces,
        *impl_->pairing_admission,
        *impl_->authorities,
        *impl_->backend
      );
      quic_server::Config server_config;
      server_config.udp_port = config.udp_port;
      server_config.profile = config.profile;
      server_config.certificate = impl_->certificate;
      impl_->server = std::make_unique<quic_server::QuicServer>(
        *impl_->api,
        std::move(server_config),
        *impl_->session_factory
      );
      impl_->transport.attach(*impl_->server, config.profile, 100'000);
      impl_->udp_port = config.udp_port;
      impl_->pairing_permissions = config.pairing_permissions;
    } catch (...) {
      OPENSSL_cleanse(seed->data(), seed->size());
      impl_->clear();
      return quic_server::ApiStatus::out_of_memory;
    }
    const auto status = impl_->server->start();
    impl_->startup_stage = impl_->server->startup_stage();
    if (!quic_server::accepted(status)) {
      impl_->clear();
    } else {
      std::scoped_lock active_lock {active_service_mutex};
      active_service = this;
    }
    return status;
  }

  void ProtocolV3Service::stop() noexcept {
    {
      std::scoped_lock active_lock {active_service_mutex};
      if (active_service == this) {
        active_service = nullptr;
      }
    }
    impl_->clear();
  }

  bool ProtocolV3Service::running() const noexcept {
    return impl_->server && impl_->server->running();
  }

  quic_server::StartupStage ProtocolV3Service::startup_stage() const noexcept {
    return impl_->startup_stage;
  }

  std::expected<std::string, std::uint8_t> ProtocolV3Service::issue_invitation(
    std::string hostname,
    const bool hostname_is_ip,
    const std::uint64_t permissions
  ) {
    const auto normalized = normalize_invitation_hostname(std::move(hostname), hostname_is_ip);
    if (!normalized || !running() || !impl_->authorization || !impl_->identity ||
        permissions == 0 || (permissions & ~control::defined_permission_mask) != 0 ||
        (permissions & ~impl_->pairing_permissions) != 0 ||
        impl_->udp_port == 0) {
      return std::unexpected(static_cast<std::uint8_t>(Status::malformed));
    }
    const auto spki = impl_->server->leaf_spki_sha256();
    if (!spki || !nonzero(*spki)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    Invitation invitation;
    if (!impl_->random.fill(invitation.invitation_id) || !nonzero(invitation.invitation_id) ||
        !impl_->random.fill(invitation.token) || !nonzero(invitation.token)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    [[maybe_unused]] const auto cleanse_token = util::fail_guard([&invitation] {
      OPENSSL_cleanse(invitation.token.data(), invitation.token.size());
    });
    const auto issued = system_unix_seconds();
    invitation.permissions = permissions;
    invitation.expires_at_unix_seconds = issued + maximum_invitation_lifetime_seconds;
    std::vector<std::uint8_t> encoded;
    encoded.reserve(172 + normalized->size());
    encoded.insert(encoded.end(), {'U', 'L', 'I', '3'});
    encoded.push_back(1);
    encoded.push_back(hostname_is_ip ? 1 : 0);
    append_big_endian(encoded, 172, 2);
    append_big_endian(encoded, 172 + normalized->size(), 2);
    append_big_endian(encoded, impl_->udp_port, 2);
    append_big_endian(encoded, 3, 2);
    append_big_endian(encoded, 3, 2);
    encoded.insert(encoded.end(), invitation.invitation_id.begin(), invitation.invitation_id.end());
    encoded.insert(encoded.end(), invitation.token.begin(), invitation.token.end());
    const auto host_id = impl_->identity->host_id();
    const auto host_public_key = impl_->identity->public_key();
    encoded.insert(encoded.end(), host_id.begin(), host_id.end());
    encoded.insert(encoded.end(), spki->begin(), spki->end());
    encoded.insert(encoded.end(), host_public_key.begin(), host_public_key.end());
    append_big_endian(encoded, issued, 8);
    append_big_endian(encoded, invitation.expires_at_unix_seconds, 8);
    append_big_endian(encoded, control::Config {}.capabilities, 8);
    append_big_endian(encoded, normalized->size(), 2);
    append_big_endian(encoded, 0, 2);
    encoded.insert(encoded.end(), normalized->begin(), normalized->end());
    if (encoded.size() != 172 + normalized->size()) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    const auto digest = lumen::protocol_common::crypto::sha256(encoded);
    if (!digest) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    invitation.invitation_sha256 = *digest;
    const auto uri = std::string {"umbra://pair/v3#"} + base64url(encoded);
    std::scoped_lock lock {impl_->invitation_mutex};
    if (impl_->active_invitation) {
      if (!impl_->authorization->revoke_invitation(impl_->active_invitation->invitation_id)) {
        OPENSSL_cleanse(invitation.token.data(), invitation.token.size());
        return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
      }
      impl_->active_invitation.reset();
    }
    if (!impl_->authorization->add_invitation(invitation)) {
      return std::unexpected(static_cast<std::uint8_t>(Status::internal_failure));
    }
    impl_->active_invitation = Impl::ActiveInvitation {
      invitation.invitation_id,
      uri,
      invitation.expires_at_unix_seconds,
    };
    OPENSSL_cleanse(invitation.token.data(), invitation.token.size());
    return uri;
  }

  std::optional<std::string> ProtocolV3Service::current_invitation() const {
    std::scoped_lock lock {impl_->invitation_mutex};
    if (!impl_->active_invitation ||
        impl_->active_invitation->expires_at_unix_seconds <= system_unix_seconds()) {
      impl_->active_invitation.reset();
      return std::nullopt;
    }
    return impl_->active_invitation->uri;
  }

  bool ProtocolV3Service::revoke_invitation(const control::Identifier &invitation_id) {
    std::scoped_lock lock {impl_->invitation_mutex};
    if (!impl_->active_invitation || impl_->active_invitation->invitation_id != invitation_id ||
        !impl_->authorization || !impl_->authorization->revoke_invitation(invitation_id)) {
      return false;
    }
    impl_->active_invitation.reset();
    return true;
  }

  bool ProtocolV3Service::revoke_current_invitation() {
    std::scoped_lock lock {impl_->invitation_mutex};
    if (!impl_->active_invitation || !impl_->authorization ||
        !impl_->authorization->revoke_invitation(impl_->active_invitation->invitation_id)) {
      return false;
    }
    impl_->active_invitation.reset();
    return true;
  }

  std::vector<AuthorizedClientInfo> ProtocolV3Service::clients() const {
    return impl_->authorization ? impl_->authorization->clients() : std::vector<AuthorizedClientInfo> {};
  }

  bool ProtocolV3Service::set_client_enabled(
    const control::Identifier &client_id,
    const bool enabled
  ) {
    if (!impl_->authorization || !impl_->authorization->set_client_enabled(client_id, enabled)) {
      return false;
    }
    const auto connections = impl_->authorities ? impl_->authorities->revoke_client(client_id) :
                                                  std::vector<std::uint64_t> {};
    if (impl_->backend) {
      impl_->backend->revoke_client(client_id);
      for (const auto connection_id : connections) {
        impl_->backend->revoke_connection(connection_id);
      }
    }
    return true;
  }

  bool ProtocolV3Service::set_client_permissions(
    const control::Identifier &client_id,
    const std::uint64_t permissions
  ) {
    if (permissions == 0 || (permissions & ~impl_->pairing_permissions) != 0 ||
        !impl_->authorization || !impl_->authorization->set_client_permissions(client_id, permissions)) {
      return false;
    }
    const auto connections = impl_->authorities ? impl_->authorities->revoke_client(client_id) :
                                                  std::vector<std::uint64_t> {};
    if (impl_->backend) {
      impl_->backend->revoke_client(client_id);
      for (const auto connection_id : connections) {
        impl_->backend->revoke_connection(connection_id);
      }
    }
    return true;
  }

  bool ProtocolV3Service::revoke_client(const control::Identifier &client_id) {
    if (!impl_->authorization || !impl_->authorization->revoke_client(client_id)) {
      return false;
    }
    const auto connections = impl_->authorities ? impl_->authorities->revoke_client(client_id) :
                                                  std::vector<std::uint64_t> {};
    if (impl_->backend) {
      impl_->backend->revoke_client(client_id);
      for (const auto connection_id : connections) {
        impl_->backend->revoke_connection(connection_id);
      }
    }
    return true;
  }

  std::uint64_t ProtocolV3Service::pairing_permissions() const noexcept {
    return impl_->pairing_permissions;
  }

  std::expected<std::string, std::uint8_t> issue_active_invitation(
    std::string hostname,
    const bool hostname_is_ip,
    const std::uint64_t permissions
  ) {
    std::scoped_lock lock {active_service_mutex};
    return active_service ? active_service->issue_invitation(
                              std::move(hostname),
                              hostname_is_ip,
                              permissions
                            ) :
                            std::unexpected(static_cast<std::uint8_t>(Status::busy));
  }

  std::optional<std::string> current_active_invitation() {
    std::scoped_lock lock {active_service_mutex};
    return active_service ? active_service->current_invitation() : std::nullopt;
  }

  bool revoke_active_invitation(const control::Identifier &invitation_id) {
    std::scoped_lock lock {active_service_mutex};
    return active_service && active_service->revoke_invitation(invitation_id);
  }

  bool revoke_current_active_invitation() {
    std::scoped_lock lock {active_service_mutex};
    return active_service && active_service->revoke_current_invitation();
  }

  std::vector<AuthorizedClientInfo> active_clients() {
    std::scoped_lock lock {active_service_mutex};
    return active_service ? active_service->clients() : std::vector<AuthorizedClientInfo> {};
  }

  bool set_active_client_enabled(const control::Identifier &client_id, const bool enabled) {
    std::scoped_lock lock {active_service_mutex};
    return active_service && active_service->set_client_enabled(client_id, enabled);
  }

  bool set_active_client_permissions(
    const control::Identifier &client_id,
    const std::uint64_t permissions
  ) {
    std::scoped_lock lock {active_service_mutex};
    return active_service && active_service->set_client_permissions(client_id, permissions);
  }

  bool revoke_active_client(const control::Identifier &client_id) {
    std::scoped_lock lock {active_service_mutex};
    return active_service && active_service->revoke_client(client_id);
  }

  std::uint64_t active_pairing_permissions() {
    std::scoped_lock lock {active_service_mutex};
    return active_service ? active_service->pairing_permissions() : 0;
  }
}  // namespace lumen::protocol_v3::runtime
