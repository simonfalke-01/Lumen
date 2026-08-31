/**
 * @file src/protocol_lsp/runtime/control_server.cpp
 * @brief Authenticated deterministic-CBOR LSPC host control vertical slice.
 */

#include "control_server.h"

#include "../core/control.h"
#include "../../protocol_common/cbor.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <mutex>
#include <new>
#include <utility>

namespace lumen::lsp::runtime {
  namespace {
    namespace cbor = lumen::protocol_common::cbor;

    constexpr std::size_t maximum_control_connections = 64;
    constexpr std::size_t maximum_pending_invitations = 64;
    constexpr std::size_t maximum_applications = 64;
    constexpr std::size_t maximum_application_id_bytes = 128;
    constexpr std::size_t maximum_application_name_bytes = 256;
    constexpr std::size_t maximum_application_image_bytes = 512;
    constexpr std::uint64_t response_deadline_microseconds = 1'000'000;

    template<std::size_t Size>
    cbor::Value::Bytes bytes(const std::array<std::uint8_t, Size> &value) {
      return {value.begin(), value.end()};
    }

    template<std::size_t Size>
    bool fixed_bytes(const cbor::Value &value, std::array<std::uint8_t, Size> &output) noexcept {
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

    const cbor::Value::Map *exact_map(
      const std::span<const std::uint8_t> payload,
      const std::size_t expected_entries
    ) noexcept {
      cbor::Limits limits;
      limits.max_encoded_bytes = maximum_control_frame_bytes - lspc_header_size;
      limits.max_byte_string_bytes = 64;
      limits.max_text_bytes = maximum_application_image_bytes;
      limits.max_array_elements = maximum_applications;
      limits.max_map_entries = 16;
      limits.max_container_depth = 3;
      thread_local cbor::DecodeResult decoded;
      decoded = cbor::decode(payload, limits);
      if (!decoded) {
        return nullptr;
      }
      const auto *map = std::get_if<cbor::Value::Map>(&decoded.value->storage);
      if (map == nullptr || map->size() != expected_entries) {
        return nullptr;
      }
      for (std::size_t index = 0; index < map->size(); ++index) {
        if ((*map)[index].first != index + 1) {
          return nullptr;
        }
      }
      return map;
    }

    std::optional<std::vector<std::uint8_t>> encode_control_value(cbor::Value value) {
      cbor::Limits limits;
      limits.max_encoded_bytes = maximum_control_frame_bytes - lspc_header_size;
      limits.max_byte_string_bytes = 64;
      limits.max_text_bytes = maximum_application_image_bytes;
      limits.max_array_elements = maximum_applications;
      limits.max_map_entries = 16;
      limits.max_container_depth = 3;
      auto encoded = cbor::encode(value, limits);
      if (!encoded) {
        return std::nullopt;
      }
      return std::move(encoded.bytes);
    }

    std::optional<std::vector<std::uint8_t>> status_payload(const ControlStatus status) {
      return encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(status)},
      }});
    }

    bool valid_text(const std::string &value, const std::size_t maximum) noexcept {
      return !value.empty() && value.size() <= maximum && cbor::is_valid_utf8(value);
    }

    std::uint64_t saturating_add(const std::uint64_t value, const std::uint64_t increment) noexcept {
      return value > std::numeric_limits<std::uint64_t>::max() - increment ?
               std::numeric_limits<std::uint64_t>::max() : value + increment;
    }
  }  // namespace

  bool TrustedClient::valid() const noexcept {
    return !is_zero(client_id) && !is_zero(identity_key) && revocation_generation != 0 &&
           (permissions.mask() & ~PermissionSet::known_mask) == 0;
  }

  bool PendingInvitation::valid() const noexcept {
    return !is_zero(invitation_id) && !is_zero(verifier_salt) && !is_zero(secret_verifier) && expires_at_utc_seconds != 0 && !consumed &&
           (permissions.mask() & ~PermissionSet::known_mask) == 0;
  }

  std::optional<std::vector<std::uint8_t>> pairing_signature_transcript(
    const Identifier128 &host_id,
    const Identifier128 &client_id,
    const Identifier128 &invitation_id,
    const Secret256 &client_nonce,
    const Secret256 &server_nonce,
    const PermissionSet permissions
  ) {
    if (is_zero(host_id) || is_zero(client_id) || is_zero(invitation_id) || is_zero(client_nonce) || is_zero(server_nonce)) {
      return std::nullopt;
    }
    return encode_control_value(cbor::Value {cbor::Value::Map {
      {1, "lumen-stream/1 pair"},
      {2, bytes(host_id)},
      {3, bytes(client_id)},
      {4, bytes(invitation_id)},
      {5, bytes(client_nonce)},
      {6, bytes(server_nonce)},
      {7, permissions.mask()},
    }});
  }

  std::optional<std::vector<std::uint8_t>> authentication_signature_transcript(
    const Identifier128 &host_id,
    const Identifier128 &client_id,
    const Secret256 &client_nonce,
    const Secret256 &server_nonce,
    const std::uint32_t connection_generation
  ) {
    if (is_zero(host_id) || is_zero(client_id) || is_zero(client_nonce) || is_zero(server_nonce) || connection_generation == 0) {
      return std::nullopt;
    }
    return encode_control_value(cbor::Value {cbor::Value::Map {
      {1, "lumen-stream/1 auth"},
      {2, bytes(host_id)},
      {3, bytes(client_id)},
      {4, bytes(client_nonce)},
      {5, bytes(server_nonce)},
      {6, connection_generation},
    }});
  }

  class HostControlServer::Impl {
  public:
    struct Connection {
      PeerEndpoint peer;  ///< Exact DTLS association.
      std::uint32_t generation {};  ///< Assigned connection authority generation.
      Secret256 client_nonce {};  ///< Nonce accepted from CLIENT_HELLO.
      Secret256 server_nonce {};  ///< Fresh server nonce.
      std::optional<TrustedClient> authenticated_client;  ///< Authenticated LSP trust record.
      selective_ack_window inbound;  ///< Received message-ID/ACK state.
      outbound_control_window<maximum_control_frame_bytes> outbound;  ///< Byte-identical retry storage.
      response_cache<maximum_control_frame_bytes, maximum_control_frame_bytes> responses;  ///< Idempotent terminal responses.
      control_rto rto {true};  ///< Local-path initial RTO.
      std::uint64_t next_message_id {1};  ///< Next outbound logical message ID.
      bool hello_complete {};  ///< Whether CLIENT_HELLO completed.
    };

    Impl(
      const HostIdentity &identity,
      const Digest256 spki_sha256,
      ControlTrustStore &trust_store,
      ControlApplicationProvider &applications,
      ControlStartHandler &start_handler,
      ControlCrypto &crypto,
      ControlTransport &transport,
      const std::size_t maximum_connections
    ) noexcept:
        identity_ {identity},
        spki_sha256_ {spki_sha256},
        trust_store_ {trust_store},
        applications_ {applications},
        start_handler_ {start_handler},
        crypto_ {crypto},
        transport_ {transport},
        maximum_connections_ {maximum_connections} {
      try {
        if (identity_.valid() && !is_zero(spki_sha256_) && maximum_connections_ > 0 &&
            maximum_connections_ <= maximum_control_connections) {
          connections_.reserve(maximum_connections_);
          invitations_.reserve(maximum_pending_invitations);
          ready_ = true;
        }
      } catch (...) {
        ready_ = false;
      }
    }

    bool add_invitation(const PairingInvitation &invitation) noexcept {
      std::scoped_lock lock(mutex_);
      if (!ready_ || !invitation.valid() || invitations_.size() >= maximum_pending_invitations) {
        return false;
      }
      const auto duplicate = std::ranges::find(invitations_, invitation.invitation_id, &PendingInvitation::invitation_id);
      if (duplicate != invitations_.end()) {
        return false;
      }
      PendingInvitation admission {
        .invitation_id = invitation.invitation_id,
        .expires_at_utc_seconds = invitation.expires_at_utc_seconds,
        .permissions = invitation.offered_permissions,
      };
      if (!crypto_.random(admission.verifier_salt) || is_zero(admission.verifier_salt)) {
        return false;
      }
      std::array<std::uint8_t, 80> verifier_input {};
      std::copy(admission.verifier_salt.begin(), admission.verifier_salt.end(), verifier_input.begin());
      std::copy(admission.invitation_id.begin(), admission.invitation_id.end(), verifier_input.begin() + 32);
      std::copy(invitation.invitation_secret.begin(), invitation.invitation_secret.end(), verifier_input.begin() + 48);
      if (!crypto_.sha256(verifier_input, admission.secret_verifier)) {
        std::ranges::fill(verifier_input, 0);
        return false;
      }
      std::ranges::fill(verifier_input, 0);
      try {
        invitations_.push_back(std::move(admission));
        return true;
      } catch (...) {
        return false;
      }
    }

    void revoke_invitations() noexcept {
      std::scoped_lock lock(mutex_);
      for (auto &invitation : invitations_) {
        std::ranges::fill(invitation.verifier_salt, 0);
        std::ranges::fill(invitation.secret_verifier, 0);
        invitation.consumed = true;
      }
    }

    std::uint32_t association_ready(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(mutex_);
      if (!ready_ || !peer.valid() || connections_.size() >= maximum_connections_) {
        return 0;
      }
      if (find(peer) != connections_.size() || next_generation_ == 0) {
        return 0;
      }
      Connection connection {
        .peer = peer,
        .generation = next_generation_,
      };
      if (!crypto_.random(connection.server_nonce) || is_zero(connection.server_nonce)) {
        return 0;
      }
      ++next_generation_;
      if (next_generation_ == 0) {
        next_generation_ = 0;
      }
      try {
        connections_.push_back(std::move(connection));
        return connections_.back().generation;
      } catch (...) {
        return 0;
      }
    }

    void association_closed(const PeerEndpoint &peer) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index != connections_.size()) {
        connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(index));
      }
    }

    void disconnect_client(const Identifier128 &client_id) noexcept {
      std::scoped_lock lock(mutex_);
      std::array<PeerEndpoint, maximum_control_connections> peers {};
      std::size_t count = 0;
      for (const auto &connection : connections_) {
        if (connection.authenticated_client && connection.authenticated_client->client_id == client_id) {
          peers[count++] = connection.peer;
        }
      }
      for (std::size_t index = 0; index < count; ++index) {
        transport_.close(peers[index]);
        if (const auto remaining = find(peers[index]); remaining != connections_.size()) {
          connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
        }
      }
    }

    bool receive(
      const PeerEndpoint &peer,
      const std::span<const std::uint8_t> frame,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      std::scoped_lock lock(mutex_);
      const auto index = find(peer);
      if (index == connections_.size()) {
        return false;
      }
      auto &connection = connections_[index];
      const auto parsed = parse_lspc(frame);
      if (!parsed) {
        transport_.close(peer);
        return false;
      }
      connection.outbound.acknowledge(parsed.header.acknowledgement_base, parsed.header.acknowledgement_bitmap);

      if (has_flag(parsed.header.flags, lspc_flag::acknowledgement_only)) {
        const auto observed = connection.inbound.observe(parsed.header.message_id);
        if (observed == receive_id_result::too_far_ahead || observed == receive_id_result::too_old ||
            observed == receive_id_result::zero) {
          transport_.close(peer);
          return false;
        }
        return true;
      }
      if (has_flag(parsed.header.flags, lspc_flag::response) || parsed.header.request_id == 0) {
        transport_.close(peer);
        return false;
      }

      const auto cached = connection.responses.lookup(parsed.header.request_id, frame);
      if (cached.result == response_cache_result::hit) {
        return transport_.send(peer, cached.response);
      }
      if (cached.result == response_cache_result::conflicting_request) {
        transport_.close(peer);
        return false;
      }

      const auto observed = connection.inbound.observe(parsed.header.message_id);
      if (observed == receive_id_result::duplicate) {
        transport_.close(peer);
        return false;
      }
      if (observed != receive_id_result::accepted) {
        transport_.close(peer);
        return false;
      }

      const auto message_type = static_cast<ControlMessageType>(parsed.header.message_type);
      if (message_type == ControlMessageType::client_hello) {
        if (parsed.header.connection_generation != 0 || connection.hello_complete) {
          return send_error(connection, frame, parsed.header, ControlMessageType::server_hello, ControlStatus::stale_generation, now_microseconds);
        }
        return client_hello(connection, frame, parsed.header, parsed.payload, now_microseconds);
      }
      if (!connection.hello_complete || parsed.header.connection_generation != connection.generation) {
        return send_error(connection, frame, parsed.header, response_type(message_type), ControlStatus::stale_generation, now_microseconds);
      }
      switch (message_type) {
        case ControlMessageType::pair_request:
          return pair(connection, frame, parsed.header, parsed.payload, now_microseconds, now_utc_seconds);
        case ControlMessageType::auth_request:
          return authenticate(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::list_applications:
          return list_applications(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::start:
          return start_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::attach:
          return attach_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::stop:
          return stop_input(connection, frame, parsed.header, parsed.payload, now_microseconds);
        case ControlMessageType::client_hello:
        case ControlMessageType::server_hello:
        case ControlMessageType::pair_response:
        case ControlMessageType::auth_response:
        case ControlMessageType::applications:
        case ControlMessageType::start_response:
        case ControlMessageType::attach_response:
        case ControlMessageType::stop_response:
          return send_error(connection, frame, parsed.header, response_type(message_type), ControlStatus::unsupported, now_microseconds);
      }
      return send_error(connection, frame, parsed.header, message_type, ControlStatus::unsupported, now_microseconds);
    }

    void tick(const std::uint64_t now_microseconds) noexcept {
      std::scoped_lock lock(mutex_);
      for (std::size_t index = 0; index < connections_.size();) {
        auto &connection = connections_[index];
        if (connection.outbound.has_failed(now_microseconds)) {
          const auto peer = connection.peer;
          transport_.close(peer);
          if (const auto remaining = find(peer); remaining != connections_.size()) {
            connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
          }
          continue;
        }
        if (auto *due = connection.outbound.due(now_microseconds); due != nullptr) {
          if (!transport_.send(connection.peer, due->frame.bytes())) {
            const auto peer = connection.peer;
            transport_.close(peer);
            if (const auto remaining = find(peer); remaining != connections_.size()) {
              connections_.erase(connections_.begin() + static_cast<std::ptrdiff_t>(remaining));
            }
            continue;
          }
          connection.outbound.mark_retransmitted(*due, now_microseconds, connection.rto);
        }
        ++index;
      }
    }

    [[nodiscard]] std::size_t connection_count() const noexcept {
      std::scoped_lock lock(mutex_);
      return connections_.size();
    }

    [[nodiscard]] std::size_t invitation_count() const noexcept {
      std::scoped_lock lock(mutex_);
      return static_cast<std::size_t>(std::ranges::count_if(invitations_, [](const PendingInvitation &invitation) {
        return invitation.valid();
      }));
    }

  private:
    [[nodiscard]] std::size_t find(const PeerEndpoint &peer) const noexcept {
      const auto iterator = std::ranges::find(connections_, peer, &Connection::peer);
      return static_cast<std::size_t>(std::distance(connections_.begin(), iterator));
    }

    static ControlMessageType response_type(const ControlMessageType request) noexcept {
      switch (request) {
        case ControlMessageType::client_hello:
          return ControlMessageType::server_hello;
        case ControlMessageType::pair_request:
          return ControlMessageType::pair_response;
        case ControlMessageType::auth_request:
          return ControlMessageType::auth_response;
        case ControlMessageType::list_applications:
          return ControlMessageType::applications;
        case ControlMessageType::start:
          return ControlMessageType::start_response;
        case ControlMessageType::attach:
          return ControlMessageType::attach_response;
        case ControlMessageType::stop:
          return ControlMessageType::stop_response;
        case ControlMessageType::server_hello:
        case ControlMessageType::pair_response:
        case ControlMessageType::auth_response:
        case ControlMessageType::applications:
        case ControlMessageType::start_response:
        case ControlMessageType::attach_response:
        case ControlMessageType::stop_response:
          return request;
      }
      return request;
    }

    bool send_error(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &request_header,
      const ControlMessageType response,
      const ControlStatus status,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto payload = status_payload(status);
      return payload && send_response(connection, request, request_header, response, *payload, true, now_microseconds);
    }

    bool send_response(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &request_header,
      const ControlMessageType response_type,
      const std::span<const std::uint8_t> payload,
      const bool error,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (connection.next_message_id == 0 || payload.size() > maximum_control_frame_bytes - lspc_header_size) {
        transport_.close(connection.peer);
        return false;
      }
      std::array<std::uint8_t, maximum_control_frame_bytes> storage {};
      auto flags = static_cast<std::uint8_t>(
        static_cast<std::uint8_t>(lspc_flag::acknowledgement_required) |
        static_cast<std::uint8_t>(lspc_flag::response)
      );
      if (error) {
        flags |= static_cast<std::uint8_t>(lspc_flag::error_response);
      }
      const lspc_header header {
        .flags = flags,
        .message_type = static_cast<std::uint16_t>(response_type),
        .connection_generation = connection.generation,
        .payload_length = static_cast<std::uint32_t>(payload.size()),
        .message_id = connection.next_message_id,
        .request_id = request_header.request_id,
        .acknowledgement_base = connection.inbound.base(),
        .acknowledgement_bitmap = connection.inbound.bitmap(),
      };
      const auto serialized = serialize_lspc(header, payload, storage);
      if (!serialized) {
        transport_.close(connection.peer);
        return false;
      }
      const auto response = std::span<const std::uint8_t> {storage.data(), serialized.bytes_written};
      const auto cache_result = connection.responses.insert(request_header.request_id, request, response);
      if (cache_result != response_cache_result::stored && cache_result != response_cache_result::hit) {
        transport_.close(connection.peer);
        return false;
      }
      if (connection.outbound.store(
            connection.next_message_id,
            response,
            now_microseconds,
            saturating_add(now_microseconds, response_deadline_microseconds),
            connection.rto
          ) != outbound_store_result::stored) {
        transport_.close(connection.peer);
        return false;
      }
      ++connection.next_message_id;
      return transport_.send(connection.peer, response);
    }

    bool client_hello(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto *map = exact_map(payload, 2);
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, connection.client_nonce) ||
          is_zero(connection.client_nonce)) {
        return send_error(connection, request, header, ControlMessageType::server_hello, ControlStatus::malformed, now_microseconds);
      }
      connection.hello_complete = true;
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, connection.generation},
        {4, bytes(identity_.host_id)},
        {5, bytes(identity_.application_public_key)},
        {6, bytes(spki_sha256_)},
        {7, bytes(connection.server_nonce)},
      }});
      return response && send_response(connection, request, header, ControlMessageType::server_hello, *response, false, now_microseconds);
    }

    bool pair(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds,
      const std::uint64_t now_utc_seconds
    ) noexcept {
      const auto *map = exact_map(payload, 6);
      Identifier128 client_id {};
      PublicKey256 client_key {};
      Identifier128 invitation_id {};
      Secret256 invitation_secret {};
      std::array<std::uint8_t, ed25519_signature_size> signature {};
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version ||
          !fixed_bytes((*map)[1].second, client_id) || !fixed_bytes((*map)[2].second, client_key) ||
          !fixed_bytes((*map)[3].second, invitation_id) || !fixed_bytes((*map)[4].second, invitation_secret) ||
          !fixed_bytes((*map)[5].second, signature) || is_zero(client_id) || is_zero(client_key)) {
        return send_error(connection, request, header, ControlMessageType::pair_response, ControlStatus::malformed, now_microseconds);
      }
      const auto iterator = std::ranges::find(invitations_, invitation_id, &PendingInvitation::invitation_id);
      std::array<std::uint8_t, 80> verifier_input {};
      Digest256 presented_verifier {};
      if (iterator != invitations_.end()) {
        std::copy(iterator->verifier_salt.begin(), iterator->verifier_salt.end(), verifier_input.begin());
        std::copy(iterator->invitation_id.begin(), iterator->invitation_id.end(), verifier_input.begin() + 32);
        std::copy(invitation_secret.begin(), invitation_secret.end(), verifier_input.begin() + 48);
      }
      const auto verifier_valid = iterator != invitations_.end() && crypto_.sha256(verifier_input, presented_verifier);
      std::ranges::fill(verifier_input, 0);
      if (iterator == invitations_.end() || !iterator->valid() || now_utc_seconds >= iterator->expires_at_utc_seconds ||
          !verifier_valid || !crypto_.equal_secret(presented_verifier, iterator->secret_verifier)) {
        return send_error(connection, request, header, ControlMessageType::pair_response, ControlStatus::authentication_failed, now_microseconds);
      }
      const auto transcript = pairing_signature_transcript(
        identity_.host_id,
        client_id,
        invitation_id,
        connection.client_nonce,
        connection.server_nonce,
        iterator->permissions
      );
      if (!transcript || !crypto_.verify(client_key, *transcript, signature)) {
        return send_error(connection, request, header, ControlMessageType::pair_response, ControlStatus::authentication_failed, now_microseconds);
      }

      TrustedClient client {
        .client_id = client_id,
        .identity_key = client_key,
        .permissions = iterator->permissions,
        .revocation_generation = 1,
        .enabled = true,
      };
      std::array<std::uint8_t, ed25519_signature_size> server_signature {};
      if (!trust_store_.upsert(client) || !crypto_.sign(*transcript, server_signature)) {
        return send_error(connection, request, header, ControlMessageType::pair_response, ControlStatus::internal_failure, now_microseconds);
      }
      iterator->consumed = true;
      std::ranges::fill(iterator->verifier_salt, 0);
      std::ranges::fill(iterator->secret_verifier, 0);
      connection.authenticated_client = client;
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, client.permissions.mask()},
        {4, client.revocation_generation},
        {5, bytes(server_signature)},
      }});
      std::ranges::fill(server_signature, 0);
      return response && send_response(connection, request, header, ControlMessageType::pair_response, *response, false, now_microseconds);
    }

    bool authenticate(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto *map = exact_map(payload, 3);
      Identifier128 client_id {};
      std::array<std::uint8_t, ed25519_signature_size> signature {};
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, client_id) ||
          !fixed_bytes((*map)[2].second, signature) || is_zero(client_id)) {
        return send_error(connection, request, header, ControlMessageType::auth_response, ControlStatus::malformed, now_microseconds);
      }
      const auto client = trust_store_.find(client_id);
      const auto transcript = authentication_signature_transcript(
        identity_.host_id,
        client_id,
        connection.client_nonce,
        connection.server_nonce,
        connection.generation
      );
      if (!client || !client->valid() || !client->enabled || !transcript || !crypto_.verify(client->identity_key, *transcript, signature)) {
        return send_error(connection, request, header, ControlMessageType::auth_response, ControlStatus::authentication_failed, now_microseconds);
      }
      std::array<std::uint8_t, ed25519_signature_size> server_signature {};
      if (!crypto_.sign(*transcript, server_signature)) {
        return send_error(connection, request, header, ControlMessageType::auth_response, ControlStatus::internal_failure, now_microseconds);
      }
      connection.authenticated_client = *client;
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, client->permissions.mask()},
        {4, client->revocation_generation},
        {5, connection.generation},
        {6, bytes(server_signature)},
      }});
      std::ranges::fill(server_signature, 0);
      return response && send_response(connection, request, header, ControlMessageType::auth_response, *response, false, now_microseconds);
    }

    bool list_applications(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      const auto *map = exact_map(payload, 1);
      const auto *version = map == nullptr ? nullptr : unsigned_value((*map)[0].second);
      if (version == nullptr || *version != wire_version) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::malformed, now_microseconds);
      }
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::browse_applications)) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::permission_denied, now_microseconds);
      }
      const auto snapshot = applications_.snapshot();
      if (!snapshot || snapshot->size() > maximum_applications) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::busy, now_microseconds);
      }
      cbor::Value::Array application_values;
      try {
        application_values.reserve(snapshot->size());
        for (const auto &application : *snapshot) {
          if (!valid_text(application.id, maximum_application_id_bytes) ||
              !valid_text(application.name, maximum_application_name_bytes) ||
              (!application.image_path.empty() && !valid_text(application.image_path, maximum_application_image_bytes))) {
            return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::internal_failure, now_microseconds);
          }
          application_values.emplace_back(cbor::Value::Map {
            {1, application.id},
            {2, application.name},
            {3, application.image_path},
          });
        }
      } catch (...) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::internal_failure, now_microseconds);
      }
      const auto response = encode_control_value(cbor::Value {cbor::Value::Map {
        {1, wire_version},
        {2, static_cast<std::uint8_t>(ControlStatus::success)},
        {3, std::move(application_values)},
      }});
      if (!response) {
        return send_error(connection, request, header, ControlMessageType::applications, ControlStatus::busy, now_microseconds);
      }
      return send_response(connection, request, header, ControlMessageType::applications, *response, false, now_microseconds);
    }

    bool start_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::start_attach) ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::start_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_start(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::start_response, ControlStatus::malformed, now_microseconds);
      }
      const auto selected = start_handler_.start_input(
        connection.peer,
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      if (!selected) {
        return send_error(connection, request, header, ControlMessageType::start_response, selected.error(), now_microseconds);
      }
      const auto response = encode_start_response(*selected);
      return response && send_response(connection, request, header, ControlMessageType::start_response, *response, false, now_microseconds);
    }

    bool stop_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::stop_own_stream)) {
        return send_error(connection, request, header, ControlMessageType::stop_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_stop(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::stop_response, ControlStatus::malformed, now_microseconds);
      }
      const auto status = start_handler_.stop_input(
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      const auto response = encode_stop_response(status);
      return response && send_response(
                           connection,
                           request,
                           header,
                           ControlMessageType::stop_response,
                           *response,
                           status != ControlStatus::success,
                           now_microseconds
                         );
    }

    bool attach_input(
      Connection &connection,
      const std::span<const std::uint8_t> request,
      const lspc_header &header,
      const std::span<const std::uint8_t> payload,
      const std::uint64_t now_microseconds
    ) noexcept {
      if (!connection.authenticated_client ||
          !connection.authenticated_client->permissions.contains(Permission::start_attach) ||
          !connection.authenticated_client->permissions.contains(Permission::input)) {
        return send_error(connection, request, header, ControlMessageType::attach_response, ControlStatus::permission_denied, now_microseconds);
      }
      const auto decoded = decode_attach(payload);
      if (!decoded) {
        return send_error(connection, request, header, ControlMessageType::attach_response, ControlStatus::malformed, now_microseconds);
      }
      const auto attached = start_handler_.attach_input(
        connection.peer,
        *connection.authenticated_client,
        connection.generation,
        *decoded
      );
      if (!attached) {
        return send_error(connection, request, header, ControlMessageType::attach_response, attached.error(), now_microseconds);
      }
      const auto response = encode_attach_response(*attached);
      return response && send_response(connection, request, header, ControlMessageType::attach_response, *response, false, now_microseconds);
    }

    const HostIdentity &identity_;  ///< Stable LSP-only identity.
    Digest256 spki_sha256_ {};  ///< Exact DTLS leaf SPKI pin.
    ControlTrustStore &trust_store_;  ///< Persistent LSP trust owner.
    ControlApplicationProvider &applications_;  ///< Product application snapshot.
    ControlStartHandler &start_handler_;  ///< Input-only START authority owner.
    ControlCrypto &crypto_;  ///< Randomness and Ed25519 operations.
    ControlTransport &transport_;  ///< Exact DTLS record output.
    std::vector<Connection> connections_;  ///< Bounded authenticated-DTLS association state.
    std::vector<PendingInvitation> invitations_;  ///< Bounded single-use invitation state.
    std::size_t maximum_connections_ {};  ///< Configured association bound.
    std::uint32_t next_generation_ {1};  ///< Next nonzero connection generation.
    bool ready_ {};  ///< Constructor validation and allocation status.
    mutable std::recursive_mutex mutex_;  ///< Synchronizes socket callbacks and low-rate administration.
  };

  HostControlServer::HostControlServer(
    const HostIdentity &identity,
    const Digest256 spki_sha256,
    ControlTrustStore &trust_store,
    ControlApplicationProvider &applications,
    ControlStartHandler &start_handler,
    ControlCrypto &crypto,
    ControlTransport &transport,
    const std::size_t maximum_connections
  ) noexcept:
      impl_ {new (std::nothrow) Impl {
        identity,
        spki_sha256,
        trust_store,
        applications,
        start_handler,
        crypto,
        transport,
        maximum_connections,
      }} {
  }

  HostControlServer::~HostControlServer() = default;

  bool HostControlServer::add_invitation(const PairingInvitation &invitation) noexcept {
    return impl_ && impl_->add_invitation(invitation);
  }

  void HostControlServer::revoke_invitations() noexcept {
    if (impl_) {
      impl_->revoke_invitations();
    }
  }

  std::uint32_t HostControlServer::association_ready(const PeerEndpoint &peer) noexcept {
    return impl_ ? impl_->association_ready(peer) : 0;
  }

  void HostControlServer::association_closed(const PeerEndpoint &peer) noexcept {
    if (impl_) {
      impl_->association_closed(peer);
    }
  }

  void HostControlServer::disconnect_client(const Identifier128 &client_id) noexcept {
    if (impl_) {
      impl_->disconnect_client(client_id);
    }
  }

  bool HostControlServer::receive(
    const PeerEndpoint &peer,
    const std::span<const std::uint8_t> frame,
    const std::uint64_t now_microseconds,
    const std::uint64_t now_utc_seconds
  ) noexcept {
    return impl_ && impl_->receive(peer, frame, now_microseconds, now_utc_seconds);
  }

  void HostControlServer::tick(const std::uint64_t now_microseconds) noexcept {
    if (impl_) {
      impl_->tick(now_microseconds);
    }
  }

  std::size_t HostControlServer::connection_count() const noexcept {
    return impl_ ? impl_->connection_count() : 0;
  }

  std::size_t HostControlServer::invitation_count() const noexcept {
    return impl_ ? impl_->invitation_count() : 0;
  }
}  // namespace lumen::lsp::runtime
