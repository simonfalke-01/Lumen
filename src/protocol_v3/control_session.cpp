/**
 * @file src/protocol_v3/control_session.cpp
 * @brief Authenticated protocol-v3 HELLO, pairing, authorization, and START state machine.
 */

#include "control_session.h"

#include "../protocol_common/crypto.h"

#include <algorithm>
#include <climits>
#include <map>
#include <openssl/rand.h>
#include <stdexcept>
#include <utility>

namespace lumen::protocol_v3::control_session {
  namespace crypto = lumen::protocol_common::crypto;

  namespace {
    using Map = cbor::Value::Map;
    using Bytes = cbor::Value::Bytes;

    constexpr std::string_view pair_client_domain {"lumen/3 pair client\0", 20};
    constexpr std::string_view pair_host_domain {"lumen/3 pair host\0", 18};
    constexpr std::string_view auth_client_domain {"lumen/3 auth client\0", 20};
    constexpr std::string_view auth_host_domain {"lumen/3 auth host\0", 18};

    template<std::size_t Size>
    bool nonzero(const std::array<std::uint8_t, Size> &value) noexcept {
      return std::ranges::any_of(value, [](const auto byte) { return byte != 0; });
    }

    const cbor::Value *field(const Map &map, const std::uint64_t key) noexcept {
      const auto found = std::lower_bound(map.begin(), map.end(), key, [](const auto &entry, const auto wanted) {
        return entry.first < wanted;
      });
      return found != map.end() && found->first == key ? &found->second : nullptr;
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

    std::optional<std::uint64_t> unsigned_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<std::uint64_t>(&value->storage) ?
                       std::optional {*std::get_if<std::uint64_t>(&value->storage)} :
                       std::nullopt :
                     std::nullopt;
    }

    std::optional<bool> bool_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      if (!value) {
        return std::nullopt;
      }
      const auto *boolean = std::get_if<bool>(&value->storage);
      return boolean ? std::optional {*boolean} : std::nullopt;
    }

    const Map *map_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<Map>(&value->storage) : nullptr;
    }

    const cbor::Value::Array *array_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<cbor::Value::Array>(&value->storage) : nullptr;
    }

    const std::string *text_field(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value ? std::get_if<std::string>(&value->storage) : nullptr;
    }

    bool is_null(const Map &map, const std::uint64_t key) noexcept {
      const auto *value = field(map, key);
      return value && std::holds_alternative<cbor::Null>(value->storage);
    }

    template<std::size_t Size>
    std::optional<std::array<std::uint8_t, Size>> fixed_field(
      const Map &map,
      const std::uint64_t key
    ) noexcept {
      const auto *value = field(map, key);
      const auto *bytes = value ? std::get_if<Bytes>(&value->storage) : nullptr;
      if (!bytes || bytes->size() != Size) {
        return std::nullopt;
      }
      std::array<std::uint8_t, Size> output;
      std::copy(bytes->begin(), bytes->end(), output.begin());
      return output;
    }

    template<std::size_t Size>
    Bytes bytes(const std::array<std::uint8_t, Size> &value) {
      return {value.begin(), value.end()};
    }

    cbor::Value unsigned_value(const std::uint64_t value) {
      return cbor::Value {value};
    }

    Map decode_map(const quic_server::ControlFrame &frame) {
      const auto decoded = cbor::decode(frame.bytes.subspan(quic_server::control_header_bytes));
      if (!decoded) {
        throw std::runtime_error {"v3 control CBOR"};
      }
      const auto *map = std::get_if<Map>(&decoded.value->storage);
      if (!map) {
        throw std::runtime_error {"v3 control map"};
      }
      return *map;
    }

    std::vector<std::uint8_t> encode_frame(
      const std::uint16_t type,
      const std::uint64_t request_id,
      const std::uint8_t flags,
      const Map &fields
    ) {
      const auto payload = cbor::encode(cbor::Value {fields});
      if (!payload || payload.bytes.empty() || payload.bytes.size() > quic_server::maximum_control_payload_bytes) {
        throw std::runtime_error {"v3 control encode"};
      }
      std::vector<std::uint8_t> output {'U', 'L', 'C', '3', 3, flags};
      const auto append = [&output](const std::uint64_t value, std::size_t count) {
        while (count-- > 0) {
          output.push_back(static_cast<std::uint8_t>(value >> (count * 8U)));
        }
      };
      append(type, 2);
      append(request_id, 8);
      append(payload.bytes.size(), 4);
      append(0, 4);
      output.insert(output.end(), payload.bytes.begin(), payload.bytes.end());
      return output;
    }

    std::vector<std::uint8_t> transcript(
      const std::string_view domain,
      const Bytes32 &spki,
      const std::initializer_list<std::span<const std::uint8_t>> frames
    ) {
      std::size_t size = domain.size() + spki.size();
      for (const auto frame : frames) {
        size += 4 + frame.size();
      }
      std::vector<std::uint8_t> output;
      output.reserve(size);
      output.insert(output.end(), domain.begin(), domain.end());
      output.insert(output.end(), spki.begin(), spki.end());
      for (const auto frame : frames) {
        const auto length = static_cast<std::uint32_t>(frame.size());
        output.push_back(static_cast<std::uint8_t>(length >> 24U));
        output.push_back(static_cast<std::uint8_t>(length >> 16U));
        output.push_back(static_cast<std::uint8_t>(length >> 8U));
        output.push_back(static_cast<std::uint8_t>(length));
        output.insert(output.end(), frame.begin(), frame.end());
      }
      return output;
    }

    Identifier derived_id(const Bytes32 &public_key) {
      const auto digest = crypto::sha256(public_key);
      if (!digest) {
        throw std::runtime_error {"v3 identity digest"};
      }
      Identifier output;
      std::copy_n(digest->begin(), output.size(), output.begin());
      return output;
    }

    Map without_last_signature(Map fields, const std::uint64_t key) {
      if (fields.empty() || fields.back().first != key) {
        throw std::runtime_error {"v3 signature field"};
      }
      fields.pop_back();
      return fields;
    }

    bool valid_profile_array(const cbor::Value::Array &profiles) noexcept {
      if (profiles.empty() || profiles.size() > 2) {
        return false;
      }
      std::uint64_t previous = 0;
      for (const auto &profile : profiles) {
        const auto *value = std::get_if<std::uint64_t>(&profile.storage);
        if (!value || *value < 1 || *value > 2 || *value <= previous) {
          return false;
        }
        previous = *value;
      }
      return true;
    }

    bool valid_start_request(const Map &fields, const std::uint16_t datagram_maximum) noexcept {
      if (!exact_keys(fields, 1, 17) || datagram_maximum < quic_server::maximum_semantic_datagram_bytes) {
        return false;
      }
      const auto intent = fixed_field<16>(fields, 1);
      const auto application = unsigned_field(fields, 2);
      const auto profile = unsigned_field(fields, 3);
      const auto width = unsigned_field(fields, 4);
      const auto height = unsigned_field(fields, 5);
      const auto refresh_numerator = unsigned_field(fields, 6);
      const auto refresh_denominator = unsigned_field(fields, 7);
      const auto bitrate = unsigned_field(fields, 8);
      const auto semantic_cap = unsigned_field(fields, 12);
      const auto trace = fixed_field<16>(fields, 13);
      const auto resume = bool_field(fields, 16);
      const auto *codecs = array_field(fields, 9);
      const auto *audio = array_field(fields, 10);
      const auto *hdr = array_field(fields, 14);
      const auto *presentation = array_field(fields, 15);
      return intent && nonzero(*intent) && application && *application <= UINT32_MAX && profile &&
             (*profile == 1 || *profile == 2) && width && *width >= 320 && *width <= 7'680 && *width % 2 == 0 &&
             height && *height >= 200 && *height <= 4'320 && *height % 2 == 0 && refresh_numerator &&
             *refresh_numerator > 0 && *refresh_numerator <= 480'000 && refresh_denominator &&
             *refresh_denominator > 0 && *refresh_denominator <= 1'000 &&
             *refresh_numerator / *refresh_denominator >= 1 && *refresh_numerator / *refresh_denominator <= 480 &&
             bitrate && *bitrate >= 1'000 && *bitrate <= 500'000 && semantic_cap &&
             *semantic_cap == quic_server::maximum_semantic_datagram_bytes && trace && nonzero(*trace) && resume &&
             codecs && !codecs->empty() && codecs->size() <= 16 && audio && !audio->empty() && audio->size() <= 6 &&
             (is_null(fields, 11) || map_field(fields, 11)) && hdr && hdr->size() <= 16 &&
             presentation && !presentation->empty() && presentation->size() <= 3 && map_field(fields, 17);
    }

  }  // namespace

  struct ControlSession::Impl {
    enum class State {
      hello,
      authorization,
      ready,
      streaming,
      closed,
    };

    struct CachedResponse {
      std::vector<std::uint8_t> request;
      std::shared_ptr<const std::vector<std::uint8_t>> response;
    };

    struct OutstandingHostRequest {
      std::uint16_t request_type {};
      std::uint16_t acknowledgement_type {};
      Identifier session_id {};
      std::uint32_t generation {};
      std::shared_ptr<const std::vector<std::uint8_t>> encoded;
      quic_server::MonotonicClock::time_point deadline {};
    };

    Impl(
      quic_server::ConnectionContext live_connection,
      Config policy,
      Random &random_source,
      HostIdentity &host_identity,
      AuthorizationStore &authorization_store,
      NonceRegistry &nonce_registry,
      PairingAdmission &pairing_limiter,
      ConnectionAuthorityRegistry &authority_registry,
      SessionBackend &session_backend
    ):
        connection {std::move(live_connection)},
        config {std::move(policy)},
        random {random_source},
        identity {host_identity},
        authorization {authorization_store},
        nonces {nonce_registry},
        pairing_admission {pairing_limiter},
        authorities {authority_registry},
        backend {session_backend},
        datagram_maximum {connection.maximum_datagram_bytes} {
      spki = connection.leaf_spki_sha256;
      if (!nonzero(spki) || identity.host_id() != derived_id(identity.public_key())) {
        throw std::invalid_argument {"invalid v3 host identity"};
      }
    }

    std::shared_ptr<const std::vector<std::uint8_t>> response(
      const quic_server::ControlFrame &frame,
      const std::uint16_t type,
      Map fields
    ) {
      auto encoded = std::make_shared<const std::vector<std::uint8_t>>(
        encode_frame(type, frame.request_id, 1, fields)
      );
      if (cache.size() >= 128) {
        throw std::runtime_error {"v3 response cache"};
      }
      cache.emplace(
        frame.request_id,
        CachedResponse {
          .request = {frame.bytes.begin(), frame.bytes.end()},
          .response = encoded,
        }
      );
      return encoded;
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> process(
      const quic_server::ControlFrame &frame
    ) {
      if (state == State::closed || frame.request_id == 0) {
        throw std::runtime_error {"invalid v3 request"};
      }
      if ((frame.flags & 1U) != 0) {
        return configuration_acknowledgement(frame);
      }
      if (frame.flags != 0 || frame.request_id % 2 == 0) {
        throw std::runtime_error {"invalid v3 client request authority"};
      }
      if (const auto duplicate = cache.find(frame.request_id); duplicate != cache.end()) {
        if (!std::ranges::equal(duplicate->second.request, frame.bytes)) {
          throw std::runtime_error {"v3 request id conflict"};
        }
        return {duplicate->second.response};
      }
      const auto expected = last_request_id == 0 ? 1 : last_request_id + 2;
      if (frame.request_id != expected || frame.request_id < last_request_id) {
        throw std::runtime_error {"v3 request sequence"};
      }
      last_request_id = frame.request_id;
      const auto fields = decode_map(frame);
      switch (state) {
        case State::hello:
          return {hello(frame, fields)};
        case State::authorization:
          if (pairing) {
            return {pair(frame, fields)};
          }
          return {authenticate(frame, fields)};
        case State::ready:
          if (frame.message_type == 0x0100) {
            return start(frame, fields);
          }
          return authenticated_control(frame, fields);
        case State::streaming:
          if (frame.message_type == 0x0100 && client_record && !backend.owned_session(*client_record)) {
            session_id.reset();
            outstanding_host_requests.clear();
            completed_host_acknowledgements.clear();
            media_started = false;
            state = State::ready;
            return start(frame, fields);
          }
          return authenticated_control(frame, fields);
        case State::closed:
          throw std::runtime_error {"unsupported v3 request state"};
      }
      throw std::runtime_error {"unreachable v3 state"};
    }

    std::shared_ptr<const std::vector<std::uint8_t>> hello(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0001 || !exact_keys(fields, 1, 8) ||
          unsigned_field(fields, 1) != 3 || unsigned_field(fields, 2) != 3) {
        throw std::runtime_error {"invalid v3 CLIENT_HELLO"};
      }
      const auto nonce = fixed_field<32>(fields, 3);
      const auto capabilities = unsigned_field(fields, 4);
      const auto *profiles = array_field(fields, 5);
      const auto client = fixed_field<16>(fields, 6);
      const auto invitation = fixed_field<16>(fields, 7);
      const auto attempt = fixed_field<16>(fields, 8);
      if (!nonce || !nonzero(*nonce) || !capabilities || (*capabilities & ~config.capabilities) != 0 ||
          !profiles || !valid_profile_array(*profiles) || !attempt || !nonzero(*attempt) ||
          (client.has_value() == invitation.has_value()) ||
          (!client && !is_null(fields, 6)) || (!invitation && !is_null(fields, 7)) ||
          !pairing_admission.admit_hello(
            connection.remote_source,
            *attempt,
            quic_server::MonotonicClock::now()
          ) ||
          !nonces.claim(connection.remote_source, *attempt, *nonce, quic_server::MonotonicClock::now())) {
        throw std::runtime_error {"invalid or replayed v3 CLIENT_HELLO"};
      }
      if (!random.fill(server_nonce) || !nonzero(server_nonce)) {
        throw std::runtime_error {"v3 server nonce"};
      }
      pairing = invitation.has_value();
      claimed_client_id = client;
      invitation_id = invitation;
      attempt_id = *attempt;
      client_hello.assign(frame.bytes.begin(), frame.bytes.end());
      Map response_fields {
        {1, unsigned_value(3)},
        {2, bytes(server_nonce)},
        {3, bytes(identity.host_id())},
        {4, bytes(identity.public_key())},
        {5, bytes(spki)},
        {6, unsigned_value(config.capabilities)},
        {7, unsigned_value(quic_server::maximum_semantic_datagram_bytes)},
        {8, bytes(attempt_id)},
      };
      auto encoded = response(frame, 0x0002, response_fields);
      server_hello = *encoded;
      state = State::authorization;
      return encoded;
    }

    std::shared_ptr<const std::vector<std::uint8_t>> pair(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0010 || !exact_keys(fields, 1, 9)) {
        throw std::runtime_error {"invalid v3 PAIR_REQUEST"};
      }
      const auto id = fixed_field<16>(fields, 1);
      const auto token = fixed_field<32>(fields, 2);
      const auto invitation_hash = fixed_field<32>(fields, 3);
      const auto attempt = fixed_field<16>(fields, 4);
      const auto client_id = fixed_field<16>(fields, 5);
      const auto client_public = fixed_field<32>(fields, 6);
      const auto *name = text_field(fields, 7);
      const auto permissions = unsigned_field(fields, 8);
      const auto signature = fixed_field<64>(fields, 9);
      if (!id || id != invitation_id || !token || !nonzero(*token) || !attempt || *attempt != attempt_id ||
          !pairing_admission.admit(connection.remote_source, *id, quic_server::MonotonicClock::now())) {
        throw std::runtime_error {"v3 pairing admission rejected"};
      }
      if (!invitation_hash || !nonzero(*invitation_hash) || !client_id ||
          !client_public || derived_id(*client_public) != *client_id || !name || name->empty() ||
          name->size() > 64 || !cbor::is_valid_utf8(*name) || !permissions ||
          (*permissions & ~defined_permission_mask) != 0 || !signature) {
        throw std::runtime_error {"invalid v3 pairing fields"};
      }
      const auto unsigned_request = encode_frame(
        frame.message_type,
        frame.request_id,
        0,
        without_last_signature(fields, 9)
      );
      const auto client_transcript = transcript(
        pair_client_domain,
        spki,
        {client_hello, server_hello, unsigned_request}
      );
      if (!crypto::ed25519_verify(*client_public, client_transcript, *signature)) {
        throw std::runtime_error {"invalid v3 client pairing signature"};
      }
      PairingClaim claim {
        .invitation_id = *id,
        .invitation_token = *token,
        .invitation_sha256 = *invitation_hash,
        .pair_attempt_id = *attempt,
        .client_id = *client_id,
        .client_public_key = *client_public,
        .display_name = *name,
        .requested_permissions = *permissions,
        .approved_permissions = *permissions & config.default_pairing_permissions,
      };
      auto stored = authorization.consume_invitation(claim);
      if (!stored || stored->client_id != *client_id || stored->public_key != *client_public ||
          stored->permissions == 0 || (stored->permissions & ~claim.approved_permissions) != 0 ||
          stored->generation == 0) {
        throw std::runtime_error {"v3 invitation rejected"};
      }
      client_record = *stored;
      const auto authority = authorities.claim(stored->client_id, connection.connection_id, true);
      if (!authority) {
        throw std::runtime_error {"v3 connection authority rejected"};
      }
      authority_generation = authority->generation;
      if (authority->replaced_connection_id) {
        backend.revoke_connection(*authority->replaced_connection_id);
      }
      Map response_fields {
        {1, unsigned_value(0)},
        {2, bytes(identity.host_id())},
        {3, bytes(identity.public_key())},
        {4, bytes(stored->client_id)},
        {5, unsigned_value(stored->permissions)},
        {6, unsigned_value(3)},
        {7, bytes(attempt_id)},
        {8, unsigned_value(stored->generation)},
      };
      const auto unsigned_response = encode_frame(0x0011, frame.request_id, 1, response_fields);
      const auto host_transcript = transcript(
        pair_host_domain,
        spki,
        {client_hello, server_hello, frame.bytes, unsigned_response}
      );
      const auto host_signature = identity.sign(host_transcript);
      if (!host_signature) {
        throw std::runtime_error {"v3 host pairing signature"};
      }
      response_fields.emplace_back(9, bytes(*host_signature));
      state = State::ready;
      return response(frame, 0x0011, std::move(response_fields));
    }

    std::shared_ptr<const std::vector<std::uint8_t>> authenticate(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0003 || !exact_keys(fields, 1, 4)) {
        throw std::runtime_error {"invalid v3 CLIENT_AUTH"};
      }
      const auto client_id = fixed_field<16>(fields, 1);
      const auto attempt = fixed_field<16>(fields, 2);
      const auto replace = bool_field(fields, 3);
      const auto signature = fixed_field<64>(fields, 4);
      if (!client_id || client_id != claimed_client_id || !attempt || *attempt != attempt_id ||
          !replace || !signature) {
        throw std::runtime_error {"invalid v3 auth fields"};
      }
      const auto record = authorization.paired_client(*client_id);
      if (!record || record->client_id != *client_id || derived_id(record->public_key) != *client_id ||
          record->permissions == 0 || (record->permissions & ~defined_permission_mask) != 0 ||
          record->generation == 0) {
        throw std::runtime_error {"unknown v3 client"};
      }
      const auto unsigned_request = encode_frame(
        frame.message_type,
        frame.request_id,
        0,
        without_last_signature(fields, 4)
      );
      const auto client_transcript = transcript(
        auth_client_domain,
        spki,
        {client_hello, server_hello, unsigned_request}
      );
      if (!crypto::ed25519_verify(record->public_key, client_transcript, *signature)) {
        throw std::runtime_error {"invalid v3 client auth signature"};
      }
      client_record = *record;
      const auto authority = authorities.claim(record->client_id, connection.connection_id, *replace);
      if (!authority) {
        throw std::runtime_error {"v3 connection replacement rejected"};
      }
      authority_generation = authority->generation;
      if (authority->replaced_connection_id) {
        backend.revoke_connection(*authority->replaced_connection_id);
      }
      const auto owned_session = backend.owned_session(*record);
      Map response_fields {
        {1, unsigned_value(0)},
        {2, bytes(record->client_id)},
        {3, unsigned_value(record->permissions)},
        {4, unsigned_value(*authority_generation)},
        {5, owned_session ? cbor::Value {bytes(*owned_session)} : cbor::Value {cbor::Null {}}},
        {6, bytes(attempt_id)},
      };
      const auto unsigned_response = encode_frame(0x0004, frame.request_id, 1, response_fields);
      const auto host_transcript = transcript(
        auth_host_domain,
        spki,
        {client_hello, server_hello, frame.bytes, unsigned_response}
      );
      const auto host_signature = identity.sign(host_transcript);
      if (!host_signature) {
        throw std::runtime_error {"v3 host auth signature"};
      }
      response_fields.emplace_back(7, bytes(*host_signature));
      state = State::ready;
      return response(frame, 0x0004, std::move(response_fields));
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> start(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (frame.message_type != 0x0100 || !client_record ||
          (client_record->permissions & start_permission) == 0 ||
          !valid_start_request(fields, datagram_maximum)) {
        throw std::runtime_error {"invalid or unauthorized v3 START"};
      }
      const auto request_intent = fixed_field<16>(fields, 1);
      if (!request_intent) {
        throw std::runtime_error {"missing v3 START intent"};
      }
      auto authority_lease = current_authority_lease();
      if (!authority_lease) {
        throw std::runtime_error {"stale v3 START authority"};
      }
      auto result = backend.start(
        *client_record,
        fields,
        connection.connection_id,
        datagram_maximum
      );
      if (!result) {
        const auto status = result.error();
        if (status == 0 || status > 12) {
          throw std::runtime_error {"invalid v3 START failure status"};
        }
        Map failed {
          {1, unsigned_value(status)}, {2, bytes(*request_intent)},
        };
        for (std::uint64_t key = 3; key <= 23; ++key) {
          failed.emplace_back(key, key == 19 ? cbor::Value {cbor::Value::Array {}} : cbor::Value {cbor::Null {}});
        }
        return {response(frame, 0x0101, std::move(failed))};
      }
      if (!nonzero(result->session_id) || !exact_keys(result->response_fields, 2, 23) ||
          result->host_requests.size() < 2 || result->host_requests.size() > 3 ||
          outstanding_host_requests.size() + result->host_requests.size() > 32) {
        throw std::runtime_error {"v3 START failed"};
      }
      const auto response_session = fixed_field<16>(result->response_fields, 3);
      const auto response_intent = fixed_field<16>(result->response_fields, 2);
      if (!response_session || *response_session != result->session_id ||
          !response_intent || response_intent != request_intent ||
          unsigned_field(result->response_fields, 11) != quic_server::maximum_semantic_datagram_bytes) {
        throw std::runtime_error {"invalid v3 START selection"};
      }
      Map response_fields {{1, unsigned_value(0)}};
      response_fields.insert(
        response_fields.end(),
        result->response_fields.begin(),
        result->response_fields.end()
      );
      session_id = result->session_id;
      state = State::streaming;
      std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> output;
      output.reserve(1 + result->host_requests.size());
      output.push_back(response(frame, 0x0101, std::move(response_fields)));
      const auto deadline = quic_server::MonotonicClock::now() + std::chrono::seconds {3};
      for (auto &request : result->host_requests) {
        if ((request.message_type != 0x0140 && request.message_type != 0x0142 && request.message_type != 0x0144) ||
            (request.message_type == 0x0144 && (client_record->permissions & microphone_permission) == 0) ||
            (request.message_type == 0x0140 && !exact_keys(request.request_fields, 1, 9)) ||
            (request.message_type != 0x0140 && !exact_keys(request.request_fields, 1, 4)) ||
            next_host_request_id > UINT64_MAX - 2) {
          throw std::runtime_error {"invalid v3 host configuration request"};
        }
        const auto request_session = fixed_field<16>(request.request_fields, 1);
        const auto generation = unsigned_field(request.request_fields, 2);
        if (!request_session || *request_session != result->session_id || !generation ||
            *generation == 0 || *generation > UINT32_MAX) {
          throw std::runtime_error {"invalid v3 host configuration fields"};
        }
        const auto request_id = next_host_request_id;
        next_host_request_id += 2;
        auto encoded = std::make_shared<const std::vector<std::uint8_t>>(
          encode_frame(request.message_type, request_id, 0, request.request_fields)
        );
        const auto acknowledgement_type = static_cast<std::uint16_t>(request.message_type + 1);
        outstanding_host_requests.emplace(request_id, OutstandingHostRequest {
          .request_type = request.message_type,
          .acknowledgement_type = acknowledgement_type,
          .session_id = result->session_id,
          .generation = static_cast<std::uint32_t>(*generation),
          .encoded = encoded,
          .deadline = deadline,
        });
        output.push_back(std::move(encoded));
      }
      return output;
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> configuration_acknowledgement(
      const quic_server::ControlFrame &frame
    ) {
      if (state != State::streaming || !client_record || !session_id ||
          frame.request_id % 2 != 0 || (frame.flags != 1 && frame.flags != 3)) {
        throw std::runtime_error {"invalid v3 configuration acknowledgement authority"};
      }
      if (const auto completed = completed_host_acknowledgements.find(frame.request_id);
          completed != completed_host_acknowledgements.end()) {
        if (!std::ranges::equal(completed->second, frame.bytes)) {
          throw std::runtime_error {"v3 configuration acknowledgement conflict"};
        }
        return {};
      }
      const auto outstanding = outstanding_host_requests.find(frame.request_id);
      if (outstanding == outstanding_host_requests.end() ||
          outstanding->second.acknowledgement_type != frame.message_type ||
          quic_server::MonotonicClock::now() > outstanding->second.deadline) {
        throw std::runtime_error {"unknown or expired v3 configuration acknowledgement"};
      }
      const auto fields = decode_map(frame);
      const auto status = unsigned_field(fields, 1);
      const auto acknowledged_session = fixed_field<16>(fields, 2);
      const auto generation = unsigned_field(fields, 3);
      const bool video = frame.message_type == 0x0141;
      const auto decoder_capacity = video ? unsigned_field(fields, 4) : std::nullopt;
      if ((!video && !exact_keys(fields, 1, 3)) || (video && !exact_keys(fields, 1, 4)) ||
          !status || *status != 0 || frame.flags != 1 || !acknowledged_session ||
          *acknowledged_session != outstanding->second.session_id || !generation ||
          *generation != outstanding->second.generation ||
          (video && (!decoder_capacity || (*decoder_capacity != 1 && *decoder_capacity != 2)))) {
        throw std::runtime_error {"rejected or malformed v3 configuration acknowledgement"};
      }
      const auto acknowledgement = frame.message_type == 0x0141 ? ConfigurationAcknowledgement::video :
                                   frame.message_type == 0x0143 ? ConfigurationAcknowledgement::audio :
                                                                  ConfigurationAcknowledgement::microphone;
      auto authority_lease = current_authority_lease();
      if (!authority_lease) {
        throw std::runtime_error {"stale v3 configuration acknowledgement authority"};
      }
      if (!backend.acknowledge_configuration(
            *client_record,
            acknowledgement,
            outstanding->second.session_id,
            outstanding->second.generation,
            video ? std::optional {static_cast<std::uint32_t>(*decoder_capacity)} : std::nullopt
          )) {
        throw std::runtime_error {"v3 configuration backend rejected acknowledgement"};
      }
      if (completed_host_acknowledgements.size() >= 32) {
        throw std::runtime_error {"v3 configuration acknowledgement cache"};
      }
      completed_host_acknowledgements.emplace(
        frame.request_id,
        std::vector<std::uint8_t> {frame.bytes.begin(), frame.bytes.end()}
      );
      outstanding_host_requests.erase(outstanding);
      if (outstanding_host_requests.empty() && !media_started) {
        if (!backend.start_media(*client_record, *session_id)) {
          throw std::runtime_error {"v3 media start barrier failed"};
        }
        media_started = true;
      }
      return {};
    }

    std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> authenticated_control(
      const quic_server::ControlFrame &frame,
      const Map &fields
    ) {
      if (!client_record) {
        throw std::runtime_error {"stale v3 control authority"};
      }
      const auto operation = [&]() -> std::optional<AuthenticatedControl> {
        switch (frame.message_type) {
          case 0x0005: return AuthenticatedControl::ping;
          case 0x0102: return AuthenticatedControl::session_attach;
          case 0x0120: return AuthenticatedControl::input_reset;
          case 0x0122: return AuthenticatedControl::text_composition;
          case 0x0130: return AuthenticatedControl::stop;
          case 0x0200: return AuthenticatedControl::application_list;
          case 0x0202: return AuthenticatedControl::application_asset;
          default: return std::nullopt;
        }
      }();
      if (!operation) {
        throw std::runtime_error {"unsupported v3 control operation"};
      }
      const auto required_permission = [&]() -> std::uint64_t {
        switch (*operation) {
          case AuthenticatedControl::application_list:
          case AuthenticatedControl::application_asset:
            return browse_permission;
          case AuthenticatedControl::input_reset:
          case AuthenticatedControl::text_composition:
            return input_permission;
          case AuthenticatedControl::stop:
            return stop_permission;
          case AuthenticatedControl::ping:
          case AuthenticatedControl::session_attach:
            return 0;
        }
        return UINT64_MAX;
      }();
      if (required_permission != 0 && (client_record->permissions & required_permission) == 0) {
        throw std::runtime_error {"forbidden v3 control operation"};
      }
      auto authority_lease = current_authority_lease();
      if (!authority_lease) {
        throw std::runtime_error {"stale v3 control authority"};
      }
      auto result = backend.control(
        *client_record,
        *operation,
        fields,
        frame.request_id,
        connection.connection_id,
        *authority_generation
      );
      if (!result || result->request != *operation || result->response_fields.empty()) {
        throw std::runtime_error {"v3 control backend failure"};
      }
      const auto response_type = static_cast<std::uint16_t>(frame.message_type + 1);
      const auto successful_stop = *operation == AuthenticatedControl::stop &&
                                   unsigned_field(result->response_fields, 1) == 0;
      const auto stopped_session = successful_stop ? session_id : std::nullopt;
      if (*operation == AuthenticatedControl::session_attach && unsigned_field(result->response_fields, 1) == 0) {
        const auto attached = fixed_field<16>(result->response_fields, 2);
        if (!attached || !nonzero(*attached)) {
          throw std::runtime_error {"invalid v3 attach response"};
        }
        session_id = *attached;
        state = State::streaming;
      } else if (*operation == AuthenticatedControl::stop && unsigned_field(result->response_fields, 1) == 0) {
        session_id.reset();
        state = State::ready;
        outstanding_host_requests.clear();
        completed_host_acknowledgements.clear();
        media_started = false;
      }
      std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> output;
      output.reserve(1 + result->post_response_events.size());
      output.push_back(response(frame, response_type, std::move(result->response_fields)));
      if (result->bulk_transfer) {
        if (result->bulk_transfer->request_id != frame.request_id ||
            result->bulk_transfer->object_id == 0 || !result->bulk_transfer->bytes) {
          throw std::runtime_error {"invalid v3 bulk transfer binding"};
        }
        pending_bulk_transfers.push_back(std::move(*result->bulk_transfer));
      }
      if (!result->post_response_events.empty()) {
        if (!successful_stop || !stopped_session || result->post_response_events.size() != 1) {
          throw std::runtime_error {"invalid v3 post-response event authority"};
        }
        auto &event = result->post_response_events.front();
        const auto ended_session = fixed_field<16>(event.fields, 1);
        if (event.message_type != 0x0133 || !exact_keys(event.fields, 1, 8) ||
            !ended_session || *ended_session != *stopped_session) {
          throw std::runtime_error {"invalid v3 SESSION_ENDED event"};
        }
        output.push_back(std::make_shared<const std::vector<std::uint8_t>>(
          encode_frame(event.message_type, 0, 0, event.fields)
        ));
      }
      return output;
    }

    void close() noexcept {
      if (state == State::closed) {
        return;
      }
      state = State::closed;
      if (client_record && authority_generation) {
        authorities.release(client_record->client_id, connection.connection_id, *authority_generation);
      }
      try {
        backend.disconnect(session_id, connection.connection_id);
      } catch (...) {
      }
      session_id.reset();
      client_record.reset();
      cache.clear();
      outstanding_host_requests.clear();
      completed_host_acknowledgements.clear();
      pending_bulk_transfers.clear();
      media_started = false;
    }

    bool current_authority() noexcept {
      return client_record && authority_generation && authorities.current(
        client_record->client_id,
        connection.connection_id,
        *authority_generation
      );
    }

    std::unique_ptr<ConnectionAuthorityLease> current_authority_lease() noexcept {
      if (!client_record || !authority_generation) {
        return nullptr;
      }
      return authorities.lease(
        client_record->client_id,
        connection.connection_id,
        *authority_generation
      );
    }

    quic_server::ConnectionContext connection;
    Config config;
    Random &random;
    HostIdentity &identity;
    AuthorizationStore &authorization;
    NonceRegistry &nonces;
    PairingAdmission &pairing_admission;
    ConnectionAuthorityRegistry &authorities;
    SessionBackend &backend;
    State state {State::hello};
    Bytes32 spki {};
    Bytes32 server_nonce {};
    bool pairing {};
    std::optional<Identifier> claimed_client_id;
    std::optional<Identifier> invitation_id;
    Identifier attempt_id {};
    std::optional<ClientRecord> client_record;
    std::optional<std::uint64_t> authority_generation;
    std::optional<Identifier> session_id;
    std::uint16_t datagram_maximum {};
    std::uint64_t last_request_id {};
    std::uint64_t next_host_request_id {2};
    bool media_started {};
    std::vector<std::uint8_t> client_hello;
    std::vector<std::uint8_t> server_hello;
    std::map<std::uint64_t, CachedResponse> cache;
    std::map<std::uint64_t, OutstandingHostRequest> outstanding_host_requests;
    std::map<std::uint64_t, std::vector<std::uint8_t>> completed_host_acknowledgements;
    std::vector<quic_server::BulkTransfer> pending_bulk_transfers;
  };

  ControlSession::ControlSession(
    quic_server::ConnectionContext connection,
    Config config,
    Random &random,
    HostIdentity &identity,
    AuthorizationStore &authorization,
    NonceRegistry &nonces,
    PairingAdmission &pairing_admission,
    ConnectionAuthorityRegistry &authorities,
    SessionBackend &backend
  ):
      impl_ {std::make_unique<Impl>(
        std::move(connection),
        std::move(config),
        random,
        identity,
        authorization,
        nonces,
        pairing_admission,
        authorities,
        backend
      )} {
  }

  ControlSession::~ControlSession() {
    if (impl_) {
      impl_->close();
    }
  }

  std::vector<std::shared_ptr<const std::vector<std::uint8_t>>> ControlSession::control(
    const quic_server::ControlFrame &frame
  ) {
    return impl_->process(frame);
  }

  void ControlSession::datagram(const quic_server::DatagramRecord &record) {
    if (!impl_->client_record || !impl_->session_id || record.session_id != *impl_->session_id) {
      throw std::runtime_error {"unauthorized v3 DATAGRAM"};
    }
    const bool permitted =
      (record.channel == 1 && (impl_->client_record->permissions & input_permission) != 0) ||
      (record.channel == 2 && record.kind == 3) ||
      (record.channel == 4 && (impl_->client_record->permissions & microphone_permission) != 0);
    if (!permitted) {
      throw std::runtime_error {"forbidden v3 DATAGRAM channel"};
    }
    auto authority_lease = impl_->current_authority_lease();
    if (!authority_lease) {
      throw std::runtime_error {"unauthorized v3 DATAGRAM"};
    }
    impl_->backend.datagram(*impl_->client_record, record);
  }

  std::optional<Identifier> ControlSession::active_session_id() const noexcept {
    return impl_->current_authority() ? impl_->session_id : std::nullopt;
  }

  bool ControlSession::authenticated() const noexcept {
    return impl_->current_authority();
  }

  std::vector<quic_server::BulkTransfer> ControlSession::take_bulk_transfers() {
    std::vector<quic_server::BulkTransfer> output;
    output.swap(impl_->pending_bulk_transfers);
    return output;
  }

  std::uint64_t ControlSession::idle_timeout_ms() const noexcept {
    if (!impl_->current_authority()) {
      return 5'000;
    }
    if (impl_->outstanding_host_requests.empty()) {
      return 0;
    }
    const auto deadline = std::ranges::min_element(
      impl_->outstanding_host_requests,
      {},
      [](const auto &entry) { return entry.second.deadline; }
    )->second.deadline;
    const auto now = quic_server::MonotonicClock::now();
    if (deadline <= now) {
      return 1;
    }
    return static_cast<std::uint64_t>(std::max<std::int64_t>(
      1,
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()
    ));
  }

  void ControlSession::datagram_maximum_changed(const std::uint16_t maximum_bytes) {
    impl_->datagram_maximum = maximum_bytes;
  }

  void ControlSession::disconnect() noexcept {
    impl_->close();
  }

  SessionFactory::SessionFactory(
    Config config,
    Random &random,
    HostIdentity &identity,
    AuthorizationStore &authorization,
    NonceRegistry &nonces,
    PairingAdmission &pairing_admission,
    ConnectionAuthorityRegistry &authorities,
    SessionBackend &backend
  ):
      config_ {std::move(config)},
      random_ {random},
      identity_ {identity},
      authorization_ {authorization},
      nonces_ {nonces},
      pairing_admission_ {pairing_admission},
      authorities_ {authorities},
      backend_ {backend} {
  }

  std::unique_ptr<quic_server::ControlSessionV3> SessionFactory::create(
    const quic_server::ConnectionContext &connection
  ) {
    return std::make_unique<ControlSession>(
      connection,
      config_,
      random_,
      identity_,
      authorization_,
      nonces_,
      pairing_admission_,
      authorities_,
      backend_
    );
  }

  bool SecureRandom::fill(const std::span<std::uint8_t> output) noexcept {
    return !output.empty() && output.size() <= INT_MAX &&
           RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
  }

  SeedHostIdentity::SeedHostIdentity(Bytes32 private_seed):
      private_seed_ {std::span<const std::uint8_t, 32> {private_seed}} {
    const auto public_key = crypto::ed25519_public_key(private_seed_.bytes());
    if (!public_key) {
      throw std::invalid_argument {"invalid v3 host seed"};
    }
    public_key_ = *public_key;
    host_id_ = derived_id(public_key_);
  }

  SeedHostIdentity::~SeedHostIdentity() = default;

  Identifier SeedHostIdentity::host_id() const noexcept {
    return host_id_;
  }

  Bytes32 SeedHostIdentity::public_key() const noexcept {
    return public_key_;
  }

  std::optional<Signature> SeedHostIdentity::sign(
    const std::span<const std::uint8_t> message
  ) noexcept {
    return crypto::ed25519_sign(private_seed_.bytes(), message);
  }

  struct BoundedNonceRegistry::Entry {
    quic_server::RemoteSourcePrefix source;
    Identifier attempt_id {};
    Bytes32 nonce {};
    quic_server::MonotonicClock::time_point expiry {};
  };

  BoundedNonceRegistry::BoundedNonceRegistry() = default;
  BoundedNonceRegistry::~BoundedNonceRegistry() = default;

  bool BoundedNonceRegistry::claim(
    const quic_server::RemoteSourcePrefix &source,
    const Identifier &attempt_id,
    const Bytes32 &nonce,
    const quic_server::MonotonicClock::time_point now
  ) noexcept {
    std::lock_guard lock {mutex_};
    std::erase_if(entries_, [now](const Entry &entry) { return entry.expiry <= now; });
    if (std::ranges::any_of(entries_, [&](const Entry &entry) {
          return entry.attempt_id == attempt_id && entry.nonce == nonce;
        })) {
      return false;
    }
    const auto source_count = std::ranges::count(entries_, source, &Entry::source);
    if (source_count >= 64) {
      return false;
    }
    if (entries_.size() >= 4'096) {
      std::map<quic_server::RemoteSourcePrefix, std::size_t> counts;
      for (const auto &entry : entries_) {
        ++counts[entry.source];
      }
      const auto largest = std::ranges::max_element(counts, {}, [](const auto &entry) {
        return entry.second;
      });
      if (largest == counts.end() || largest->second <= source_count) {
        return false;
      }
      const auto oldest = std::ranges::min_element(entries_, {}, [&](const Entry &entry) {
        return entry.source == largest->first ? entry.expiry : quic_server::MonotonicClock::time_point::max();
      });
      if (oldest == entries_.end() || oldest->source != largest->first) {
        return false;
      }
      entries_.erase(oldest);
    }
    entries_.push_back({source, attempt_id, nonce, now + std::chrono::minutes {10}});
    return true;
  }

  struct BoundedPairingAdmission::Entry {
    quic_server::RemoteSourcePrefix source;
    std::vector<quic_server::MonotonicClock::time_point> attempts;
  };

  BoundedPairingAdmission::BoundedPairingAdmission() = default;
  BoundedPairingAdmission::~BoundedPairingAdmission() = default;

  bool BoundedPairingAdmission::admit_hello(
    const quic_server::RemoteSourcePrefix &source,
    const Identifier &attempt_id,
    const quic_server::MonotonicClock::time_point now
  ) noexcept {
    return admit(source, attempt_id, now);
  }

  bool BoundedPairingAdmission::admit(
    const quic_server::RemoteSourcePrefix &source,
    const Identifier &invitation_id,
    const quic_server::MonotonicClock::time_point now
  ) noexcept {
    static_cast<void>(invitation_id);
    std::lock_guard lock {mutex_};
    const auto cutoff = now - std::chrono::seconds {1};
    for (auto &entry : entries_) {
      std::erase_if(entry.attempts, [cutoff](const auto attempt) { return attempt <= cutoff; });
    }
    std::erase_if(entries_, [](const Entry &entry) { return entry.attempts.empty(); });
    auto found = std::ranges::find(entries_, source, &Entry::source);
    if (found == entries_.end()) {
      if (entries_.size() >= 64) {
        return false;
      }
      entries_.push_back({source, {}});
      found = std::prev(entries_.end());
    }
    if (found->attempts.size() >= 32) {
      return false;
    }
    found->attempts.push_back(now);
    return true;
  }

  struct ConnectionAuthorities::Entry {
    Identifier client_id {};
    std::uint64_t connection_id {};
    std::uint64_t generation {};
    std::size_t leases {};
  };

  struct ConnectionAuthorities::Lease final: ConnectionAuthorityLease {
    Lease(
      ConnectionAuthorities &owner,
      const Identifier &client_id,
      const std::uint64_t connection_id,
      const std::uint64_t generation
    ) noexcept:
        owner_ {owner},
        client_id_ {client_id},
        connection_id_ {connection_id},
        generation_ {generation} {
    }

    ~Lease() override {
      owner_.release_lease(client_id_, connection_id_, generation_);
    }

  private:
    ConnectionAuthorities &owner_;
    Identifier client_id_ {};
    std::uint64_t connection_id_ {};
    std::uint64_t generation_ {};
  };

  ConnectionAuthorities::ConnectionAuthorities() = default;
  ConnectionAuthorities::~ConnectionAuthorities() = default;

  std::optional<AuthorityClaim> ConnectionAuthorities::claim(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const bool replace_existing
  ) noexcept {
    std::lock_guard lock {mutex_};
    auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    if (found != entries_.end() && found->connection_id != connection_id && !replace_existing) {
      return std::nullopt;
    }
    if (found != entries_.end() && found->leases != 0) {
      return std::nullopt;
    }
    if (next_generation_ == 0 || next_generation_ == UINT64_MAX) {
      return std::nullopt;
    }
    const auto generation = next_generation_++;
    const auto replaced = found != entries_.end() && found->connection_id != connection_id ?
                            std::optional {found->connection_id} :
                            std::nullopt;
    if (found == entries_.end()) {
      entries_.push_back({client_id, connection_id, generation, 0});
    } else {
      found->connection_id = connection_id;
      found->generation = generation;
    }
    return AuthorityClaim {generation, replaced};
  }

  bool ConnectionAuthorities::current(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::lock_guard lock {mutex_};
    const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    return found != entries_.end() && found->connection_id == connection_id &&
           found->generation == generation;
  }

  std::unique_ptr<ConnectionAuthorityLease> ConnectionAuthorities::lease(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::lock_guard lock {mutex_};
    const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    if (found == entries_.end() || found->connection_id != connection_id ||
        found->generation != generation) {
      return nullptr;
    }
    ++found->leases;
    try {
      return std::make_unique<Lease>(*this, client_id, connection_id, generation);
    } catch (...) {
      --found->leases;
      return nullptr;
    }
  }

  void ConnectionAuthorities::release_lease(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::lock_guard lock {mutex_};
    const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
    if (found != entries_.end() && found->connection_id == connection_id &&
        found->generation == generation && found->leases != 0) {
      --found->leases;
      condition_.notify_all();
    }
  }

  void ConnectionAuthorities::release(
    const Identifier &client_id,
    const std::uint64_t connection_id,
    const std::uint64_t generation
  ) noexcept {
    std::unique_lock lock {mutex_};
    condition_.wait(lock, [&] {
      const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
      return found == entries_.end() || found->connection_id != connection_id ||
             found->generation != generation || found->leases == 0;
    });
    std::erase_if(entries_, [&](const Entry &entry) {
      return entry.client_id == client_id && entry.connection_id == connection_id &&
             entry.generation == generation;
    });
  }

  std::vector<std::uint64_t> ConnectionAuthorities::revoke_client(
    const Identifier &client_id
  ) noexcept {
    std::unique_lock lock {mutex_};
    condition_.wait(lock, [&] {
      const auto found = std::ranges::find(entries_, client_id, &Entry::client_id);
      return found == entries_.end() || found->leases == 0;
    });
    std::vector<std::uint64_t> connections;
    for (const auto &entry : entries_) {
      if (entry.client_id == client_id) {
        connections.push_back(entry.connection_id);
      }
    }
    std::erase_if(entries_, [&](const Entry &entry) { return entry.client_id == client_id; });
    return connections;
  }
}  // namespace lumen::protocol_v3::control_session
