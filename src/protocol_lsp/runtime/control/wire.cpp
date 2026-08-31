/**
 * @file src/protocol_lsp/runtime/control/wire.cpp
 * @brief Frozen deterministic-CBOR schemas for the initial LSP/1 control slice.
 */

#include "wire.h"

#include "../../../protocol_common/cbor.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <variant>

namespace lumen::lsp::runtime {
  namespace {
    namespace cbor = lumen::protocol_common::cbor;
    constexpr std::size_t maximum_payload_bytes = 1'152;
    constexpr std::size_t maximum_applications = 64;
    constexpr std::size_t maximum_audio_offers = 12;
    constexpr std::size_t maximum_video_offers = 8;
    constexpr std::size_t maximum_video_parameter_set_bytes = 512;

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
      value.max_byte_string_bytes = maximum_video_parameter_set_bytes;
      value.max_text_bytes = 512;
      value.max_array_elements = maximum_applications;
      value.max_map_entries = 32;
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

    /** @brief Validate one exact selected reverse-microphone tuple. */
    bool valid_microphone_selection(const MicrophoneSelectionPayload &microphone) noexcept {
      return microphone.microphone_generation != 0 && microphone.microphone_ssrc != 0 &&
             microphone.microphone_payload_type >= 96 && microphone.microphone_payload_type <= 127 &&
             microphone.clock_rate == 48'000 && microphone.channels == 1 && microphone.frame_samples == 960 &&
             microphone.bitrate >= 6'000 && microphone.bitrate <= 128'000 &&
             microphone.initial_udp_payload_size == 1'200;
    }

    /** @brief Encode an optional selected microphone tuple as null or an exact ten-key map. */
    cbor::Value microphone_selection(const std::optional<MicrophoneSelectionPayload> &microphone) {
      if (!microphone) {
        return cbor::Value {cbor::Null {}};
      }
      return cbor::Value {cbor::Value::Map {
        {1, microphone->microphone_generation},
        {2, microphone->microphone_ssrc},
        {3, microphone->microphone_payload_type},
        {4, microphone->clock_rate},
        {5, microphone->channels},
        {6, microphone->frame_samples},
        {7, microphone->bitrate},
        {8, cbor::Value {microphone->inband_fec}},
        {9, cbor::Value {microphone->dtx}},
        {10, microphone->initial_udp_payload_size},
      }};
    }

    /** @brief Return whether a codec and profile form one frozen SDR tuple. */
    bool valid_video_codec_profile(const VideoCodec codec, const VideoProfile profile) noexcept {
      return (codec == VideoCodec::h264 && profile == VideoProfile::h264_high) ||
             (codec == VideoCodec::hevc && profile == VideoProfile::hevc_main);
    }

    /** @brief Validate one exact ordered SDR video offer. */
    bool valid_video_offer(const VideoOfferPayload &offer) noexcept {
      return valid_video_codec_profile(offer.codec, offer.profile) &&
             offer.width > 0 && offer.width <= 16'384 && offer.height > 0 && offer.height <= 16'384 &&
             offer.refresh_numerator > 0 && offer.refresh_denominator > 0 &&
             offer.preferred_bits_per_second > 0 &&
             offer.preferred_bits_per_second <= offer.maximum_bits_per_second &&
             offer.maximum_bits_per_second <= 1'000'000'000ULL &&
             offer.pixel_format == video_pixel_format_nv12 &&
             offer.delivery == video_delivery_complete_access_unit && !offer.flexfec && !offer.rtx;
    }

    /** @brief Validate the exact first-slice selected SDR video tuple. */
    bool valid_video_selection(const VideoSelectionPayload &video) noexcept {
      return video.video_generation != 0 && video.primary_ssrc != 0 &&
             video.primary_payload_type >= 96 && video.primary_payload_type <= 127 &&
             video.clock_rate == 90'000 && valid_video_codec_profile(video.codec, video.profile) &&
             video.width > 0 && video.width <= 16'384 && video.height > 0 && video.height <= 16'384 &&
             video.refresh_numerator > 0 && video.refresh_denominator > 0 &&
             video.selected_bits_per_second > 0 && video.selected_bits_per_second <= 1'000'000'000ULL &&
             video.pixel_format == video_pixel_format_nv12 &&
             video.color_primaries == video_color_rec709 &&
             video.transfer_function == video_color_rec709 &&
             video.matrix_coefficients == video_color_rec709 && !video.full_range &&
             video.initial_udp_payload_size == 1'200 &&
             video.decoder_surfaces >= 2 && video.decoder_surfaces <= 4 &&
             video.render_mailbox == 1 && video.delivery == video_delivery_complete_access_unit &&
             video.frame_marking_extension == video_frame_marking_extension_id &&
             video.absolute_capture_time_extension == video_absolute_capture_time_extension_id &&
             video.frame_id_extension == video_frame_id_extension_id &&
             video.input_watermark_extension == video_input_watermark_extension_id &&
             video.encoder_timing_extension == video_encoder_timing_extension_id &&
             !video.flexfec && !video.rtx && video.maximum_frame_age_microseconds > 0;
    }

    /** @brief Encode the frozen twenty-seven-key SDR video selection. */
    cbor::Value video_selection(const VideoSelectionPayload &video) {
      return cbor::Value {cbor::Value::Map {
        {1, video.video_generation},
        {2, video.primary_ssrc},
        {3, video.primary_payload_type},
        {4, video.clock_rate},
        {5, static_cast<std::uint8_t>(video.codec)},
        {6, static_cast<std::uint8_t>(video.profile)},
        {7, video.width},
        {8, video.height},
        {9, video.refresh_numerator},
        {10, video.refresh_denominator},
        {11, video.selected_bits_per_second},
        {12, video.pixel_format},
        {13, video.color_primaries},
        {14, video.transfer_function},
        {15, video.matrix_coefficients},
        {16, cbor::Value {video.full_range}},
        {17, video.initial_udp_payload_size},
        {18, video.decoder_surfaces},
        {19, video.render_mailbox},
        {20, video.delivery},
        {21, video.frame_marking_extension},
        {22, video.absolute_capture_time_extension},
        {23, video.frame_id_extension},
        {24, video.input_watermark_extension},
        {25, video.encoder_timing_extension},
        {26, cbor::Value {video.flexfec}},
        {27, cbor::Value {video.rtx}},
        {28, video.maximum_frame_age_microseconds},
      }};
    }

    /** @brief Validate prefix-free parameter sets for the selected codec. */
    bool valid_parameter_sets(
      const VideoCodec codec,
      const std::vector<std::vector<std::uint8_t>> &sets
    ) noexcept {
      const auto expected = codec == VideoCodec::h264 ? std::size_t {2} : std::size_t {3};
      if (sets.size() != expected) {
        return false;
      }
      for (const auto &set : sets) {
        if (set.empty() || set.size() > maximum_video_parameter_set_bytes ||
            (set.size() >= 3 && set[0] == 0 && set[1] == 0 && (set[2] == 1 || (set.size() >= 4 && set[2] == 0 && set[3] == 1)))) {
          return false;
        }
      }
      if (codec == VideoCodec::h264) {
        return (sets[0][0] & 0x1fU) == 7U && (sets[1][0] & 0x1fU) == 8U;
      }
      return sets[0].size() >= 2 && sets[1].size() >= 2 && sets[2].size() >= 2 &&
             ((sets[0][0] >> 1U) & 0x3fU) == 32U &&
             ((sets[1][0] >> 1U) & 0x3fU) == 33U &&
             ((sets[2][0] >> 1U) & 0x3fU) == 34U;
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
    const auto map = decode_map(payload, 16);
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
    const auto *microphone_null = map ? std::get_if<cbor::Null>(&(*map)[9].second.storage) : nullptr;
    const auto *microphone_map = map ? std::get_if<cbor::Value::Map>(&(*map)[9].second.storage) : nullptr;
    const auto *network_profile = map ? unsigned_value((*map)[10].second) : nullptr;
    const auto *video_offers = map ? std::get_if<cbor::Value::Array>(&(*map)[11].second.storage) : nullptr;
    const auto *receive_batch = map ? unsigned_value((*map)[12].second) : nullptr;
    const auto *decoder_surfaces = map ? unsigned_value((*map)[13].second) : nullptr;
    const auto *render_mailbox = map ? unsigned_value((*map)[14].second) : nullptr;
    const auto *capture_to_present = map ? unsigned_value((*map)[15].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || application == nullptr || application->empty() ||
        application->size() > 128 || pointer == nullptr || *pointer < 125 || *pointer > 16'000 || controller == nullptr ||
        *controller < 125 || *controller > 2'000 || sensor == nullptr || *sensor < 125 || *sensor > 4'000 ||
        reconciliation == nullptr || *reconciliation < 50 || *reconciliation > 1'000 || budget == nullptr ||
        *budget == 0 || *budget > 32'000'000 || offers == nullptr || offers->empty() ||
        offers->size() > maximum_audio_offers || maximum_udp_payload == nullptr || *maximum_udp_payload < 1'200 ||
        *maximum_udp_payload > 1'472 || (microphone_null == nullptr && microphone_map == nullptr) ||
        network_profile == nullptr || *network_profile > static_cast<std::uint8_t>(VideoNetworkProfile::competition) ||
        video_offers == nullptr || video_offers->empty() || video_offers->size() > maximum_video_offers ||
        receive_batch == nullptr || *receive_batch == 0 || *receive_batch > 64 ||
        decoder_surfaces == nullptr || *decoder_surfaces < 2 || *decoder_surfaces > 4 ||
        render_mailbox == nullptr || *render_mailbox != 1 ||
        capture_to_present == nullptr || *capture_to_present == 0 ||
        *capture_to_present > std::numeric_limits<std::uint32_t>::max()) {
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
    std::optional<MicrophoneOfferPayload> microphone_offer;
    if (microphone_map != nullptr) {
      if (microphone_map->size() != 6) {
        return std::unexpected(ControlWireError::invalid_shape);
      }
      for (std::size_t index = 0; index < microphone_map->size(); ++index) {
        if ((*microphone_map)[index].first != index + 1) {
          return std::unexpected(ControlWireError::invalid_shape);
        }
      }
      const auto *channels = unsigned_value((*microphone_map)[0].second);
      const auto *frame_samples = unsigned_value((*microphone_map)[1].second);
      const auto *maximum_bitrate = unsigned_value((*microphone_map)[2].second);
      const auto *inband_fec = boolean_value((*microphone_map)[3].second);
      const auto *dtx = boolean_value((*microphone_map)[4].second);
      const auto *required = boolean_value((*microphone_map)[5].second);
      if (channels == nullptr || *channels != 1 || frame_samples == nullptr || *frame_samples != 960 ||
          maximum_bitrate == nullptr || *maximum_bitrate < 6'000 || *maximum_bitrate > 128'000 ||
          inband_fec == nullptr || dtx == nullptr || required == nullptr) {
        return std::unexpected(ControlWireError::invalid_field);
      }
      microphone_offer = MicrophoneOfferPayload {
        .channels = 1,
        .frame_samples = 960,
        .maximum_bitrate = static_cast<std::uint32_t>(*maximum_bitrate),
        .inband_fec = *inband_fec,
        .dtx = *dtx,
        .required = *required,
      };
    }
    std::vector<VideoOfferPayload> decoded_video_offers;
    decoded_video_offers.reserve(video_offers->size());
    for (const auto &encoded_video_offer : *video_offers) {
      const auto *offer = std::get_if<cbor::Value::Map>(&encoded_video_offer.storage);
      if (offer == nullptr || offer->size() != 12) {
        return std::unexpected(ControlWireError::invalid_shape);
      }
      for (std::size_t index = 0; index < offer->size(); ++index) {
        if ((*offer)[index].first != index + 1) {
          return std::unexpected(ControlWireError::invalid_shape);
        }
      }
      const auto *codec = unsigned_value((*offer)[0].second);
      const auto *profile = unsigned_value((*offer)[1].second);
      const auto *width = unsigned_value((*offer)[2].second);
      const auto *height = unsigned_value((*offer)[3].second);
      const auto *refresh_numerator = unsigned_value((*offer)[4].second);
      const auto *refresh_denominator = unsigned_value((*offer)[5].second);
      const auto *preferred_bitrate = unsigned_value((*offer)[6].second);
      const auto *maximum_bitrate = unsigned_value((*offer)[7].second);
      const auto *pixel_format = unsigned_value((*offer)[8].second);
      const auto *delivery = unsigned_value((*offer)[9].second);
      const auto *flexfec = boolean_value((*offer)[10].second);
      const auto *rtx = boolean_value((*offer)[11].second);
      if (codec == nullptr || profile == nullptr || width == nullptr || height == nullptr ||
          refresh_numerator == nullptr || refresh_denominator == nullptr || preferred_bitrate == nullptr ||
          maximum_bitrate == nullptr || pixel_format == nullptr || delivery == nullptr ||
          flexfec == nullptr || rtx == nullptr ||
          *codec > std::numeric_limits<std::uint8_t>::max() ||
          *profile > std::numeric_limits<std::uint8_t>::max() ||
          *width > std::numeric_limits<std::uint32_t>::max() ||
          *height > std::numeric_limits<std::uint32_t>::max() ||
          *refresh_numerator > std::numeric_limits<std::uint32_t>::max() ||
          *refresh_denominator > std::numeric_limits<std::uint32_t>::max() ||
          *pixel_format > std::numeric_limits<std::uint8_t>::max() ||
          *delivery > std::numeric_limits<std::uint8_t>::max()) {
        return std::unexpected(ControlWireError::invalid_field);
      }
      VideoOfferPayload decoded {
        .codec = static_cast<VideoCodec>(*codec),
        .profile = static_cast<VideoProfile>(*profile),
        .width = static_cast<std::uint32_t>(*width),
        .height = static_cast<std::uint32_t>(*height),
        .refresh_numerator = static_cast<std::uint32_t>(*refresh_numerator),
        .refresh_denominator = static_cast<std::uint32_t>(*refresh_denominator),
        .preferred_bits_per_second = *preferred_bitrate,
        .maximum_bits_per_second = *maximum_bitrate,
        .pixel_format = static_cast<std::uint8_t>(*pixel_format),
        .delivery = static_cast<std::uint8_t>(*delivery),
        .flexfec = *flexfec,
        .rtx = *rtx,
      };
      if (!valid_video_offer(decoded)) {
        return std::unexpected(ControlWireError::invalid_field);
      }
      decoded_video_offers.push_back(decoded);
    }
    result = {
      .application_id = *application,
      .pointer_rate = static_cast<std::uint32_t>(*pointer),
      .controller_rate = static_cast<std::uint32_t>(*controller),
      .sensor_rate = static_cast<std::uint32_t>(*sensor),
      .reconciliation_rate = static_cast<std::uint32_t>(*reconciliation),
      .maximum_input_wire_bits_per_second = *budget,
      .audio_offers = std::move(audio_offers),
      .offered_maximum_udp_payload = static_cast<std::uint16_t>(*maximum_udp_payload),
      .microphone_offer = microphone_offer,
      .network_profile = static_cast<VideoNetworkProfile>(*network_profile),
      .video_offers = std::move(decoded_video_offers),
      .client_receive_batch_capacity = static_cast<std::uint8_t>(*receive_batch),
      .decoder_surfaces = static_cast<std::uint8_t>(*decoder_surfaces),
      .render_mailbox = static_cast<std::uint8_t>(*render_mailbox),
      .maximum_capture_to_present_microseconds = static_cast<std::uint32_t>(*capture_to_present),
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
        payload.audio.audio_ssrc == payload.acknowledgement_ssrc || payload.audio.audio_payload_type == payload.input_payload_type ||
        (payload.microphone && (!valid_microphone_selection(*payload.microphone) ||
                                payload.microphone->microphone_ssrc == payload.input_ssrc ||
                                payload.microphone->microphone_ssrc == payload.acknowledgement_ssrc ||
                                payload.microphone->microphone_ssrc == payload.audio.audio_ssrc ||
                                payload.microphone->microphone_payload_type == payload.input_payload_type ||
                                payload.microphone->microphone_payload_type == payload.audio.audio_payload_type)) ||
        !valid_video_selection(payload.video) || payload.video.primary_ssrc == payload.input_ssrc ||
        payload.video.primary_ssrc == payload.acknowledgement_ssrc ||
        payload.video.primary_ssrc == payload.audio.audio_ssrc ||
        payload.video.primary_payload_type == payload.input_payload_type ||
        payload.video.primary_payload_type == payload.audio.audio_payload_type ||
        (payload.microphone && (payload.video.primary_ssrc == payload.microphone->microphone_ssrc ||
                                payload.video.primary_payload_type == payload.microphone->microphone_payload_type))) {
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
      {30, microphone_selection(payload.microphone)},
      {31, video_selection(payload.video)},
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
        payload.audio.audio_ssrc == payload.acknowledgement_ssrc || payload.audio.audio_payload_type == payload.input_payload_type ||
        (payload.microphone && (!valid_microphone_selection(*payload.microphone) ||
                                payload.microphone->microphone_ssrc == payload.input_ssrc ||
                                payload.microphone->microphone_ssrc == payload.acknowledgement_ssrc ||
                                payload.microphone->microphone_ssrc == payload.audio.audio_ssrc ||
                                payload.microphone->microphone_payload_type == payload.input_payload_type ||
                                payload.microphone->microphone_payload_type == payload.audio.audio_payload_type)) ||
        !valid_video_selection(payload.video) || payload.video.primary_ssrc == payload.input_ssrc ||
        payload.video.primary_ssrc == payload.acknowledgement_ssrc ||
        payload.video.primary_ssrc == payload.audio.audio_ssrc ||
        payload.video.primary_payload_type == payload.input_payload_type ||
        payload.video.primary_payload_type == payload.audio.audio_payload_type ||
        (payload.microphone && (payload.video.primary_ssrc == payload.microphone->microphone_ssrc ||
                                payload.video.primary_payload_type == payload.microphone->microphone_payload_type))) {
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
      {31, microphone_selection(payload.microphone)},
      {32, video_selection(payload.video)},
    });
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_video_config(
    const VideoConfigPayload &payload
  ) {
    if (is_zero(payload.session_id) || payload.stream_generation == 0 ||
        !valid_video_selection(payload.video) ||
        !valid_parameter_sets(payload.video.codec, payload.parameter_sets) ||
        payload.frame_id_origin == 0 || payload.recovery_epoch == 0 ||
        payload.maximum_complete_access_unit_bytes == 0 ||
        payload.maximum_complete_access_unit_bytes > 16U * 1024U * 1024U) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    cbor::Value::Array parameter_sets;
    parameter_sets.reserve(payload.parameter_sets.size());
    for (const auto &set : payload.parameter_sets) {
      parameter_sets.emplace_back(cbor::Value::Bytes {set.begin(), set.end()});
    }
    return encode({
      {1, wire_version},
      {2, bytes(payload.session_id)},
      {3, payload.stream_generation},
      {4, video_selection(payload.video)},
      {5, std::move(parameter_sets)},
      {6, payload.frame_id_origin},
      {7, payload.recovery_epoch},
      {8, payload.maximum_complete_access_unit_bytes},
    });
  }

  std::expected<VideoConfigAckPayload, ControlWireError> decode_video_config_ack(
    const std::span<const std::uint8_t> payload
  ) {
    const auto map = decode_map(payload, 5);
    VideoConfigAckPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *status = map ? unsigned_value((*map)[1].second) : nullptr;
    const auto *video_generation = map ? unsigned_value((*map)[3].second) : nullptr;
    const auto *decoder_credit = map ? unsigned_value((*map)[4].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || status == nullptr ||
        *status > static_cast<std::uint8_t>(ControlStatus::internal_failure) ||
        !fixed_bytes((*map)[2].second, result.session_id) || is_zero(result.session_id) ||
        video_generation == nullptr || *video_generation == 0 ||
        *video_generation > std::numeric_limits<std::uint32_t>::max() ||
        decoder_credit == nullptr || *decoder_credit < 2 || *decoder_credit > 4 ||
        !valid_status(static_cast<ControlStatus>(*status))) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    result.status = static_cast<ControlStatus>(*status);
    result.video_generation = static_cast<std::uint32_t>(*video_generation);
    result.decoder_credit = static_cast<std::uint8_t>(*decoder_credit);
    return result;
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

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_microphone_config(
    const MicrophoneConfigPayload &payload
  ) {
    if (is_zero(payload.session_id) || payload.stream_generation == 0 || !valid_microphone_selection(payload.microphone)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, bytes(payload.session_id)},
      {3, payload.stream_generation},
      {4, payload.microphone.microphone_generation},
      {5, payload.microphone.microphone_ssrc},
      {6, payload.microphone.microphone_payload_type},
      {7, payload.microphone.clock_rate},
      {8, payload.microphone.channels},
      {9, payload.microphone.frame_samples},
      {10, payload.microphone.bitrate},
      {11, cbor::Value {payload.microphone.inband_fec}},
      {12, cbor::Value {payload.microphone.dtx}},
      {13, payload.microphone.initial_udp_payload_size},
    });
  }

  std::expected<MicrophoneConfigAckPayload, ControlWireError> decode_microphone_config_ack(
    const std::span<const std::uint8_t> payload
  ) {
    const auto map = decode_map(payload, 4);
    MicrophoneConfigAckPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *status = map ? unsigned_value((*map)[1].second) : nullptr;
    const auto *microphone_generation = map ? unsigned_value((*map)[3].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || status == nullptr ||
        *status > static_cast<std::uint8_t>(ControlStatus::internal_failure) ||
        !fixed_bytes((*map)[2].second, result.session_id) || is_zero(result.session_id) ||
        microphone_generation == nullptr || *microphone_generation == 0 ||
        !valid_status(static_cast<ControlStatus>(*status))) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    result.status = static_cast<ControlStatus>(*status);
    result.microphone_generation = static_cast<std::uint32_t>(*microphone_generation);
    return result;
  }
}  // namespace lumen::lsp::runtime
