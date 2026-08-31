/**
 * @file src/protocol_lsp/invitation.cpp
 * @brief Exact LSP/1 pairing invitation URI model and codec.
 */

#include "invitation.h"

#include "../protocol_common/cbor.h"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace lumen::lsp {
  namespace {
    namespace cbor = lumen::protocol_common::cbor;

    constexpr std::string_view base64url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    constexpr std::size_t maximum_invitation_uri_bytes = 2'048;
    constexpr std::size_t maximum_host_bytes = 255;

    bool valid_host(const std::string_view host) noexcept {
      if (host.empty() || host.size() > maximum_host_bytes || !cbor::is_valid_utf8(host)) {
        return false;
      }
      return std::ranges::none_of(host, [](const unsigned char byte) {
        return byte <= 0x20U || byte == 0x7fU;
      });
    }

    std::string base64url_encode(const std::span<const std::uint8_t> input) {
      std::string output;
      output.reserve((input.size() * 4 + 2) / 3);
      std::size_t offset = 0;
      while (input.size() - offset >= 3) {
        const auto value = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (static_cast<std::uint32_t>(input[offset + 1]) << 8U) |
                           static_cast<std::uint32_t>(input[offset + 2]);
        output.push_back(base64url_alphabet[(value >> 18U) & 0x3fU]);
        output.push_back(base64url_alphabet[(value >> 12U) & 0x3fU]);
        output.push_back(base64url_alphabet[(value >> 6U) & 0x3fU]);
        output.push_back(base64url_alphabet[value & 0x3fU]);
        offset += 3;
      }
      if (input.size() - offset == 1) {
        const auto value = static_cast<std::uint32_t>(input[offset]) << 16U;
        output.push_back(base64url_alphabet[(value >> 18U) & 0x3fU]);
        output.push_back(base64url_alphabet[(value >> 12U) & 0x3fU]);
      } else if (input.size() - offset == 2) {
        const auto value = (static_cast<std::uint32_t>(input[offset]) << 16U) |
                           (static_cast<std::uint32_t>(input[offset + 1]) << 8U);
        output.push_back(base64url_alphabet[(value >> 18U) & 0x3fU]);
        output.push_back(base64url_alphabet[(value >> 12U) & 0x3fU]);
        output.push_back(base64url_alphabet[(value >> 6U) & 0x3fU]);
      }
      return output;
    }

    std::optional<std::uint8_t> base64url_value(const char encoded) noexcept {
      if (encoded >= 'A' && encoded <= 'Z') {
        return static_cast<std::uint8_t>(encoded - 'A');
      }
      if (encoded >= 'a' && encoded <= 'z') {
        return static_cast<std::uint8_t>(encoded - 'a' + 26);
      }
      if (encoded >= '0' && encoded <= '9') {
        return static_cast<std::uint8_t>(encoded - '0' + 52);
      }
      if (encoded == '-') {
        return 62;
      }
      if (encoded == '_') {
        return 63;
      }
      return std::nullopt;
    }

    std::optional<std::vector<std::uint8_t>> base64url_decode(const std::string_view input) {
      if (input.empty() || input.size() % 4 == 1) {
        return std::nullopt;
      }
      std::vector<std::uint8_t> output;
      output.reserve(input.size() * 3 / 4);
      std::uint32_t accumulator = 0;
      unsigned bits = 0;
      for (const auto encoded : input) {
        const auto value = base64url_value(encoded);
        if (!value) {
          return std::nullopt;
        }
        accumulator = (accumulator << 6U) | *value;
        bits += 6;
        if (bits >= 8) {
          bits -= 8;
          output.push_back(static_cast<std::uint8_t>(accumulator >> bits));
          if (bits == 0) {
            accumulator = 0;
          } else {
            accumulator &= (1U << bits) - 1U;
          }
        }
      }
      if (accumulator != 0) {
        return std::nullopt;
      }
      return output;
    }

    template<std::size_t Size>
    cbor::Value::Bytes bytes(const std::array<std::uint8_t, Size> &value) {
      return {value.begin(), value.end()};
    }

    template<std::size_t Size>
    bool load_bytes(const cbor::Value &value, std::array<std::uint8_t, Size> &output) {
      const auto *encoded = std::get_if<cbor::Value::Bytes>(&value.storage);
      if (encoded == nullptr || encoded->size() != Size) {
        return false;
      }
      std::copy(encoded->begin(), encoded->end(), output.begin());
      return true;
    }

    const std::uint64_t *unsigned_value(const cbor::Value &value) noexcept {
      return std::get_if<std::uint64_t>(&value.storage);
    }

    const std::string *text_value(const cbor::Value &value) noexcept {
      return std::get_if<std::string>(&value.storage);
    }
  }  // namespace

  bool PairingInvitation::valid() const noexcept {
    return version == wire_version && !is_zero(host_id) && !is_zero(host_identity_key) && !is_zero(dtls_spki_sha256) &&
           port != 0 && valid_host(host) && !is_zero(invitation_id) && !is_zero(invitation_secret) &&
           expires_at_utc_seconds != 0 && (offered_permissions.mask() & ~PermissionSet::known_mask) == 0;
  }

  bool PairingInvitation::expired(const std::uint64_t now_utc_seconds) const noexcept {
    return now_utc_seconds >= expires_at_utc_seconds;
  }

  std::expected<std::string, InvitationError> encode_invitation_uri(const PairingInvitation &invitation) {
    if (!invitation.valid()) {
      return std::unexpected(InvitationError::invalid_model);
    }
    cbor::Value::Map map {
      {1, invitation.version},
      {2, bytes(invitation.host_id)},
      {3, bytes(invitation.host_identity_key)},
      {4, bytes(invitation.dtls_spki_sha256)},
      {5, invitation.port},
      {6, invitation.host},
      {7, bytes(invitation.invitation_id)},
      {8, bytes(invitation.invitation_secret)},
      {9, invitation.expires_at_utc_seconds},
      {10, invitation.offered_permissions.mask()},
    };
    cbor::Limits limits;
    limits.max_encoded_bytes = maximum_invitation_uri_bytes;
    limits.max_byte_string_bytes = 32;
    limits.max_text_bytes = maximum_host_bytes;
    limits.max_map_entries = 10;
    limits.max_container_depth = 1;
    const auto encoded = cbor::encode(cbor::Value {std::move(map)}, limits);
    if (!encoded) {
      return std::unexpected(InvitationError::invalid_cbor);
    }
    return std::string {invitation_uri_prefix} + base64url_encode(encoded.bytes);
  }

  std::expected<PairingInvitation, InvitationError> decode_invitation_uri(const std::string_view uri) {
    if (uri.size() > maximum_invitation_uri_bytes || !uri.starts_with(invitation_uri_prefix)) {
      return std::unexpected(InvitationError::invalid_uri);
    }
    const auto fragment = uri.substr(invitation_uri_prefix.size());
    const auto encoded = base64url_decode(fragment);
    if (!encoded || base64url_encode(*encoded) != fragment) {
      return std::unexpected(InvitationError::invalid_base64url);
    }

    cbor::Limits limits;
    limits.max_encoded_bytes = maximum_invitation_uri_bytes;
    limits.max_byte_string_bytes = 32;
    limits.max_text_bytes = maximum_host_bytes;
    limits.max_map_entries = 10;
    limits.max_container_depth = 1;
    const auto decoded = cbor::decode(*encoded, limits);
    if (!decoded) {
      return std::unexpected(InvitationError::invalid_cbor);
    }
    const auto *map = std::get_if<cbor::Value::Map>(&decoded.value->storage);
    if (map == nullptr || map->size() != 10) {
      return std::unexpected(InvitationError::invalid_shape);
    }
    for (std::size_t index = 0; index < map->size(); ++index) {
      if ((*map)[index].first != index + 1) {
        return std::unexpected(InvitationError::invalid_shape);
      }
    }

    PairingInvitation invitation;
    const auto *version = unsigned_value((*map)[0].second);
    if (version == nullptr || *version > std::numeric_limits<std::uint8_t>::max()) {
      return std::unexpected(InvitationError::invalid_field);
    }
    if (*version != wire_version) {
      return std::unexpected(InvitationError::version_mismatch);
    }
    invitation.version = static_cast<std::uint8_t>(*version);
    if (!load_bytes((*map)[1].second, invitation.host_id) ||
        !load_bytes((*map)[2].second, invitation.host_identity_key) ||
        !load_bytes((*map)[3].second, invitation.dtls_spki_sha256) ||
        !load_bytes((*map)[6].second, invitation.invitation_id) ||
        !load_bytes((*map)[7].second, invitation.invitation_secret)) {
      return std::unexpected(InvitationError::invalid_field);
    }

    const auto *port = unsigned_value((*map)[4].second);
    const auto *host = text_value((*map)[5].second);
    const auto *expiration = unsigned_value((*map)[8].second);
    const auto *permissions = unsigned_value((*map)[9].second);
    if (port == nullptr || *port == 0 || *port > std::numeric_limits<std::uint16_t>::max() ||
        host == nullptr || !valid_host(*host) || expiration == nullptr || *expiration == 0 ||
        permissions == nullptr || *permissions > std::numeric_limits<std::uint32_t>::max()) {
      return std::unexpected(InvitationError::invalid_field);
    }
    const auto permission_set = PermissionSet::from_mask(static_cast<std::uint32_t>(*permissions));
    if (!permission_set) {
      return std::unexpected(InvitationError::unknown_permissions);
    }
    invitation.port = static_cast<std::uint16_t>(*port);
    invitation.host = *host;
    invitation.expires_at_utc_seconds = *expiration;
    invitation.offered_permissions = *permission_set;
    if (!invitation.valid()) {
      return std::unexpected(InvitationError::invalid_field);
    }
    return invitation;
  }
}  // namespace lumen::lsp
