/**
 * @file src/protocol_lsp/runtime/control/wire.cpp
 * @brief Frozen deterministic-CBOR schemas for the initial LSP/1 control slice.
 */

#include "wire.h"

#include "../../../protocol_common/cbor.h"

#include <algorithm>
#include <optional>
#include <variant>

namespace lumen::lsp::runtime {
  namespace {
    namespace cbor = lumen::protocol_common::cbor;
    constexpr std::size_t maximum_payload_bytes = 1'152;
    constexpr std::size_t maximum_applications = 64;
    constexpr std::size_t maximum_audio_offers = 12;

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

    /** @brief Return a borrowed boolean only when the CBOR value has exact boolean type. */
    const bool *boolean_value(const cbor::Value &value) noexcept {
      return std::get_if<bool>(&value.storage);
    }

    cbor::Limits limits() noexcept {
      cbor::Limits value;
      value.max_encoded_bytes = maximum_payload_bytes;
      value.max_byte_string_bytes = ed25519_signature_size;
      value.max_text_bytes = 512;
      value.max_array_elements = maximum_applications;
      value.max_map_entries = 30;
      value.max_container_depth = 4;
      return value;
    }

    std::expected<cbor::Value::Map, ControlWireError> decode_map(
      const std::span<const std::uint8_t> payload,
      const std::size_t entries
    ) {
      const auto decoded = cbor::decode(payload, limits());
      if (!decoded) {
        return std::unexpected(ControlWireError::malformed_cbor);
      }
      const auto *map = std::get_if<cbor::Value::Map>(&decoded.value->storage);
      if (map == nullptr || map->size() != entries) {
        return std::unexpected(ControlWireError::invalid_shape);
      }
      for (std::size_t index = 0; index < entries; ++index) {
        if ((*map)[index].first != index + 1) {
          return std::unexpected(ControlWireError::invalid_shape);
        }
      }
      return *map;
    }

    std::expected<std::vector<std::uint8_t>, ControlWireError> encode(cbor::Value::Map map) {
      auto encoded = cbor::encode(cbor::Value {std::move(map)}, limits());
      if (!encoded) {
        return std::unexpected(ControlWireError::size_limit);
      }
      return std::move(encoded.bytes);
    }

    bool valid_status(const ControlStatus status) noexcept {
      switch (status) {
        case ControlStatus::success:
        case ControlStatus::malformed:
        case ControlStatus::unsupported:
        case ControlStatus::authentication_failed:
        case ControlStatus::permission_denied:
        case ControlStatus::busy:
        case ControlStatus::unsupported_media_tuple:
        case ControlStatus::stale_generation:
        case ControlStatus::timeout:
        case ControlStatus::path_capacity_insufficient:
        case ControlStatus::internal_failure:
          return true;
      }
      return false;
    }

    /** @brief Validate one LSP/1 Opus duration expressed in 48 kHz samples. */
    bool valid_audio_frame_samples(const std::uint64_t samples) noexcept {
      return samples == 120 || samples == 240 || samples == 480 || samples == 960;
    }

    /** @brief Validate one built-in host Opus channel count. */
    bool valid_audio_channels(const std::uint64_t channels) noexcept {
      return channels == 2 || channels == 6 || channels == 8;
    }

    /** @brief Validate the exact selected audio tuple shared by three control messages. */
    bool valid_audio_selection(const AudioSelectionPayload &audio) noexcept {
      if (audio.audio_generation == 0 || audio.audio_ssrc == 0 || audio.audio_payload_type < 96 ||
          audio.audio_payload_type > 127 || audio.clock_rate != 48'000 || !valid_audio_channels(audio.channels) ||
          audio.streams == 0 || audio.streams > audio.channels || audio.coupled_streams > audio.streams ||
          static_cast<std::uint16_t>(audio.streams) + audio.coupled_streams != audio.channels ||
          !valid_audio_frame_samples(audio.frame_samples) || audio.bitrate < 6'000 ||
          audio.bitrate > std::min<std::uint32_t>(2'048'000, static_cast<std::uint32_t>(audio.streams) * 512'000U) ||
          audio.initial_udp_payload_size < 1'200 || audio.initial_udp_payload_size > 1'472 ||
          audio.initial_preroll_packets != 1) {
        return false;
      }
      return std::ranges::all_of(
        std::span<const std::uint8_t> {audio.mapping}.first(audio.channels),
        [&](const std::uint8_t value) {
          return value < audio.channels;
        }
      );
    }

    /** @brief Copy the selected leading channel mapping into one CBOR byte string. */
    cbor::Value::Bytes audio_mapping(const AudioSelectionPayload &audio) {
      return {audio.mapping.begin(), audio.mapping.begin() + audio.channels};
    }
  }  // namespace

  std::expected<ClientHelloPayload, ControlWireError> decode_client_hello(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 2);
    ClientHelloPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, result.client_nonce) ||
        is_zero(result.client_nonce)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_server_hello(const ServerHelloPayload &payload) {
    if (!valid_status(payload.status) || payload.connection_generation == 0 || is_zero(payload.host_id) ||
        is_zero(payload.host_identity_key) || is_zero(payload.dtls_spki_sha256) || is_zero(payload.server_nonce)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, payload.connection_generation},
      {4, bytes(payload.host_id)},
      {5, bytes(payload.host_identity_key)},
      {6, bytes(payload.dtls_spki_sha256)},
      {7, bytes(payload.server_nonce)},
    });
  }

  std::expected<PairRequestPayload, ControlWireError> decode_pair_request(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 6);
    PairRequestPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, result.client_id) ||
        !fixed_bytes((*map)[2].second, result.client_identity_key) || !fixed_bytes((*map)[3].second, result.invitation_id) ||
        !fixed_bytes((*map)[4].second, result.invitation_secret) || !fixed_bytes((*map)[5].second, result.signature) ||
        is_zero(result.client_id) || is_zero(result.client_identity_key)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_response(const PairResponsePayload &payload) {
    if (!valid_status(payload.status) || payload.revocation_generation == 0 || is_zero(payload.signature)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, payload.permissions.mask()},
      {4, payload.revocation_generation},
      {5, bytes(payload.signature)},
    });
  }

  std::expected<AuthRequestPayload, ControlWireError> decode_auth_request(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 3);
    AuthRequestPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, result.client_id) ||
        !fixed_bytes((*map)[2].second, result.signature) || is_zero(result.client_id)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_auth_response(const AuthResponsePayload &payload) {
    if (!valid_status(payload.status) || payload.revocation_generation == 0 || payload.connection_generation == 0 ||
        is_zero(payload.signature)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, payload.permissions.mask()},
      {4, payload.revocation_generation},
      {5, payload.connection_generation},
      {6, bytes(payload.signature)},
    });
  }

  std::expected<void, ControlWireError> decode_list_applications(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 1);
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return {};
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_applications(
    const std::span<const ControlApplication> applications
  ) {
    if (applications.size() > maximum_applications) {
      return std::unexpected(ControlWireError::size_limit);
    }
    cbor::Value::Array values;
    values.reserve(applications.size());
    for (const auto &application : applications) {
      if (application.id.empty() || application.id.size() > 128 || application.name.empty() || application.name.size() > 256 ||
          application.image_path.size() > 512 || !cbor::is_valid_utf8(application.id) ||
          !cbor::is_valid_utf8(application.name) || !cbor::is_valid_utf8(application.image_path)) {
        return std::unexpected(ControlWireError::invalid_field);
      }
      values.emplace_back(cbor::Value::Map {{1, application.id}, {2, application.name}, {3, application.image_path}});
    }
    return encode({{1, wire_version}, {2, static_cast<std::uint8_t>(ControlStatus::success)}, {3, std::move(values)}});
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_control_error(const ControlStatus status) {
    if (!valid_status(status) || status == ControlStatus::success) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({{1, wire_version}, {2, static_cast<std::uint8_t>(status)}});
  }

  std::expected<StartRequestPayload, ControlWireError> decode_start(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 9);
    StartRequestPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *application = map ? std::get_if<std::string>(&(*map)[1].second.storage) : nullptr;
    const auto *pointer = map ? unsigned_value((*map)[2].second) : nullptr;
    const auto *controller = map ? unsigned_value((*map)[3].second) : nullptr;
    const auto *sensor = map ? unsigned_value((*map)[4].second) : nullptr;
    const auto *reconciliation = map ? unsigned_value((*map)[5].second) : nullptr;
    const auto *budget = map ? unsigned_value((*map)[6].second) : nullptr;
    const auto *offers = map ? std::get_if<cbor::Value::Array>(&(*map)[7].second.storage) : nullptr;
    const auto *maximum_udp_payload = map ? unsigned_value((*map)[8].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || application == nullptr || application->empty() ||
        application->size() > 128 || pointer == nullptr || *pointer < 125 || *pointer > 16'000 || controller == nullptr ||
        *controller < 125 || *controller > 2'000 || sensor == nullptr || *sensor < 125 || *sensor > 4'000 ||
        reconciliation == nullptr || *reconciliation < 50 || *reconciliation > 1'000 || budget == nullptr ||
        *budget == 0 || *budget > 32'000'000 || offers == nullptr || offers->empty() ||
        offers->size() > maximum_audio_offers || maximum_udp_payload == nullptr || *maximum_udp_payload < 1'200 ||
        *maximum_udp_payload > 1'472) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    result.audio_offers.reserve(offers->size());
    for (const auto &encoded_offer : *offers) {
      const auto *offer = std::get_if<cbor::Value::Map>(&encoded_offer.storage);
      if (offer == nullptr || offer->size() != 5) {
        return std::unexpected(ControlWireError::invalid_shape);
      }
      for (std::size_t index = 0; index < offer->size(); ++index) {
        if ((*offer)[index].first != index + 1) {
          return std::unexpected(ControlWireError::invalid_shape);
        }
      }
      const auto *channels = unsigned_value((*offer)[0].second);
      const auto *frame_samples = unsigned_value((*offer)[1].second);
      const auto *maximum_bitrate = unsigned_value((*offer)[2].second);
      const auto *inband_fec = boolean_value((*offer)[3].second);
      const auto *dtx = boolean_value((*offer)[4].second);
      if (channels == nullptr || !valid_audio_channels(*channels) || frame_samples == nullptr ||
          !valid_audio_frame_samples(*frame_samples) || maximum_bitrate == nullptr || *maximum_bitrate < 6'000 ||
          *maximum_bitrate > 2'048'000 || inband_fec == nullptr || dtx == nullptr) {
        return std::unexpected(ControlWireError::invalid_field);
      }
      result.audio_offers.push_back({
        .channels = static_cast<std::uint8_t>(*channels),
        .frame_samples = static_cast<std::uint16_t>(*frame_samples),
        .maximum_bitrate = static_cast<std::uint32_t>(*maximum_bitrate),
        .inband_fec = *inband_fec,
        .dtx = *dtx,
      });
    }
    auto audio_offers = std::move(result.audio_offers);
    result = {
      .application_id = *application,
      .pointer_rate = static_cast<std::uint32_t>(*pointer),
      .controller_rate = static_cast<std::uint32_t>(*controller),
      .sensor_rate = static_cast<std::uint32_t>(*sensor),
      .reconciliation_rate = static_cast<std::uint32_t>(*reconciliation),
      .maximum_input_wire_bits_per_second = *budget,
      .audio_offers = std::move(audio_offers),
      .offered_maximum_udp_payload = static_cast<std::uint16_t>(*maximum_udp_payload),
    };
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_start_response(const StartResponsePayload &payload) {
    if (payload.status != ControlStatus::success || is_zero(payload.session_id) || is_zero(payload.attach_token) ||
        payload.stream_generation == 0 || payload.input_generation == 0 || payload.input_ssrc == 0 ||
        payload.acknowledgement_ssrc == 0 || payload.input_ssrc == payload.acknowledgement_ssrc ||
        payload.input_payload_type < 96 || payload.input_payload_type > 127 || payload.pointer_rate < 125 ||
        payload.pointer_rate > 16'000 || payload.controller_rate < 125 || payload.controller_rate > 2'000 ||
        payload.sensor_rate < 125 || payload.sensor_rate > 4'000 || payload.reconciliation_rate < 50 ||
        payload.reconciliation_rate > 1'000 || payload.reserved_input_wire_bits_per_second == 0 ||
        payload.reserved_input_wire_bits_per_second > 32'000'000 || !payload.baseline_required ||
        !valid_audio_selection(payload.audio) || payload.audio.audio_ssrc == payload.input_ssrc ||
        payload.audio.audio_ssrc == payload.acknowledgement_ssrc || payload.audio.audio_payload_type == payload.input_payload_type) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, bytes(payload.session_id)},
      {4, bytes(payload.attach_token)},
      {5, payload.stream_generation},
      {6, payload.input_generation},
      {7, payload.input_ssrc},
      {8, payload.acknowledgement_ssrc},
      {9, payload.input_payload_type},
      {10, payload.pointer_rate},
      {11, payload.controller_rate},
      {12, payload.sensor_rate},
      {13, payload.reconciliation_rate},
      {14, payload.reserved_input_wire_bits_per_second},
      {15, cbor::Value {payload.baseline_required}},
      {16, payload.audio.audio_generation},
      {17, payload.audio.audio_ssrc},
      {18, payload.audio.audio_payload_type},
      {19, payload.audio.clock_rate},
      {20, payload.audio.channels},
      {21, payload.audio.streams},
      {22, payload.audio.coupled_streams},
      {23, audio_mapping(payload.audio)},
      {24, payload.audio.frame_samples},
      {25, payload.audio.bitrate},
      {26, cbor::Value {payload.audio.inband_fec}},
      {27, cbor::Value {payload.audio.dtx}},
      {28, payload.audio.initial_udp_payload_size},
      {29, payload.audio.initial_preroll_packets},
    });
  }

  std::expected<StopRequestPayload, ControlWireError> decode_stop(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 2);
    StopRequestPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, result.session_id) ||
        is_zero(result.session_id)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_stop_response(const ControlStatus status) {
    if (!valid_status(status)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({{1, wire_version}, {2, static_cast<std::uint8_t>(status)}});
  }

  std::expected<AttachRequestPayload, ControlWireError> decode_attach(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 4);
    AttachRequestPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, result.session_id) ||
        !fixed_bytes((*map)[2].second, result.attach_token) || !fixed_bytes((*map)[3].second, result.intent_id) ||
        is_zero(result.session_id) || is_zero(result.attach_token) || is_zero(result.intent_id)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_attach_response(const AttachResponsePayload &payload) {
    if (payload.status != ControlStatus::success || is_zero(payload.session_id) || is_zero(payload.attach_token) ||
        payload.connection_generation == 0 || payload.stream_generation == 0 || payload.input_generation == 0 ||
        payload.input_ssrc == 0 || payload.acknowledgement_ssrc == 0 || payload.input_ssrc == payload.acknowledgement_ssrc ||
        payload.input_payload_type < 96 || payload.input_payload_type > 127 || payload.pointer_rate < 125 ||
        payload.pointer_rate > 16'000 || payload.controller_rate < 125 || payload.controller_rate > 2'000 ||
        payload.sensor_rate < 125 || payload.sensor_rate > 4'000 || payload.reconciliation_rate < 50 ||
        payload.reconciliation_rate > 1'000 || payload.reserved_input_wire_bits_per_second == 0 ||
        payload.reserved_input_wire_bits_per_second > 32'000'000 || !payload.baseline_required ||
        !valid_audio_selection(payload.audio) || payload.audio.audio_ssrc == payload.input_ssrc ||
        payload.audio.audio_ssrc == payload.acknowledgement_ssrc || payload.audio.audio_payload_type == payload.input_payload_type) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, bytes(payload.session_id)},
      {4, bytes(payload.attach_token)},
      {5, payload.connection_generation},
      {6, payload.stream_generation},
      {7, payload.input_generation},
      {8, payload.input_ssrc},
      {9, payload.acknowledgement_ssrc},
      {10, payload.input_payload_type},
      {11, payload.pointer_rate},
      {12, payload.controller_rate},
      {13, payload.sensor_rate},
      {14, payload.reconciliation_rate},
      {15, payload.reserved_input_wire_bits_per_second},
      {16, cbor::Value {payload.baseline_required}},
      {17, payload.audio.audio_generation},
      {18, payload.audio.audio_ssrc},
      {19, payload.audio.audio_payload_type},
      {20, payload.audio.clock_rate},
      {21, payload.audio.channels},
      {22, payload.audio.streams},
      {23, payload.audio.coupled_streams},
      {24, audio_mapping(payload.audio)},
      {25, payload.audio.frame_samples},
      {26, payload.audio.bitrate},
      {27, cbor::Value {payload.audio.inband_fec}},
      {28, cbor::Value {payload.audio.dtx}},
      {29, payload.audio.initial_udp_payload_size},
      {30, payload.audio.initial_preroll_packets},
    });
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_audio_config(const AudioConfigPayload &payload) {
    if (is_zero(payload.session_id) || payload.stream_generation == 0 || !valid_audio_selection(payload.audio)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, bytes(payload.session_id)},
      {3, payload.stream_generation},
      {4, payload.audio.audio_generation},
      {5, payload.audio.audio_ssrc},
      {6, payload.audio.audio_payload_type},
      {7, payload.audio.clock_rate},
      {8, payload.audio.channels},
      {9, payload.audio.streams},
      {10, payload.audio.coupled_streams},
      {11, audio_mapping(payload.audio)},
      {12, payload.audio.frame_samples},
      {13, payload.audio.bitrate},
      {14, cbor::Value {payload.audio.inband_fec}},
      {15, cbor::Value {payload.audio.dtx}},
      {16, payload.audio.initial_udp_payload_size},
      {17, payload.audio.initial_preroll_packets},
    });
  }

  std::expected<AudioConfigAckPayload, ControlWireError> decode_audio_config_ack(
    const std::span<const std::uint8_t> payload
  ) {
    const auto map = decode_map(payload, 4);
    AudioConfigAckPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *status = map ? unsigned_value((*map)[1].second) : nullptr;
    const auto *audio_generation = map ? unsigned_value((*map)[3].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || status == nullptr ||
        *status > static_cast<std::uint8_t>(ControlStatus::internal_failure) ||
        !fixed_bytes((*map)[2].second, result.session_id) || is_zero(result.session_id) ||
        audio_generation == nullptr || *audio_generation == 0 ||
        !valid_status(static_cast<ControlStatus>(*status))) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    result.status = static_cast<ControlStatus>(*status);
    result.audio_generation = static_cast<std::uint32_t>(*audio_generation);
    return result;
  }
}  // namespace lumen::lsp::runtime
