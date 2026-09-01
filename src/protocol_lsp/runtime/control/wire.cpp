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
    constexpr std::size_t maximum_video_codec_configuration_unit_bytes = 512;

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
      value.max_byte_string_bytes = maximum_video_codec_configuration_unit_bytes;
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

    /**
     * @brief Return whether one codec, profile, and pixel class form a frozen video tuple.
     *
     * @param codec Negotiated video codec.
     * @param profile Codec profile selected within that codec family.
     * @param pixel Exact chroma-sampling and bit-depth class.
     * @return True only for a schema-revision-three codec/profile/pixel tuple.
     */
    bool valid_video_codec_profile_pixel(
      const VideoCodec codec,
      const VideoProfile profile,
      const VideoPixelClass pixel
    ) noexcept {
      switch (codec) {
        case VideoCodec::h264:
          return (profile == VideoProfile::h264_high && pixel == VideoPixelClass::yuv420_8) ||
                 (profile == VideoProfile::h264_high_444_predictive && pixel == VideoPixelClass::yuv444_8);
        case VideoCodec::hevc:
          return (profile == VideoProfile::hevc_main && pixel == VideoPixelClass::yuv420_8) ||
                 (profile == VideoProfile::hevc_main10 && pixel == VideoPixelClass::yuv420_10) ||
                 (profile == VideoProfile::hevc_range_extensions &&
                  (pixel == VideoPixelClass::yuv444_8 || pixel == VideoPixelClass::yuv444_10));
        case VideoCodec::av1:
          return (profile == VideoProfile::av1_main &&
                  (pixel == VideoPixelClass::yuv420_8 || pixel == VideoPixelClass::yuv420_10)) ||
                 (profile == VideoProfile::av1_high &&
                  (pixel == VideoPixelClass::yuv444_8 || pixel == VideoPixelClass::yuv444_10));
      }
      return false;
    }

    /**
     * @brief Return whether H.273 color values match the codec pixel-depth contract.
     *
     * @param codec Negotiated video codec.
     * @param pixel Exact chroma-sampling and bit-depth class.
     * @param primaries H.273 color-primaries value.
     * @param transfer H.273 transfer-characteristic value.
     * @param matrix H.273 matrix-coefficients value.
     * @param full_range Whether decoded luma and chroma use full range.
     * @return True only for exact BT.709 SDR, BT.2020/PQ, or BT.2020/HLG semantics.
     */
    bool valid_video_color_tuple(
      const VideoCodec codec,
      const VideoPixelClass pixel,
      const std::uint8_t primaries,
      const std::uint8_t transfer,
      const std::uint8_t matrix,
      const bool full_range
    ) noexcept {
      if (primaries == video_color_bt709 && transfer == video_color_bt709 &&
          matrix == video_color_bt709) {
        return true;
      }
      const auto ten_bit = pixel == VideoPixelClass::yuv420_10 || pixel == VideoPixelClass::yuv444_10;
      return codec != VideoCodec::h264 && ten_bit && !full_range &&
             primaries == video_color_primaries_bt2020 && matrix == video_matrix_bt2020_ncl &&
             (transfer == video_transfer_pq || transfer == video_transfer_hlg);
    }

    /**
     * @brief Validate one exact ordered video offer.
     *
     * @param offer Decoded eighteen-key video offer.
     * @return True only when every codec, color, rate, delivery, and resource bound is valid.
     */
    bool valid_video_offer(const VideoOfferPayload &offer) noexcept {
      return valid_video_codec_profile_pixel(offer.codec, offer.profile, offer.pixel_format) &&
             valid_video_color_tuple(
               offer.codec,
               offer.pixel_format,
               offer.color_primaries,
               offer.transfer_function,
               offer.matrix_coefficients,
               offer.full_range
             ) &&
             offer.width > 0 && offer.width <= 16'384 && offer.height > 0 && offer.height <= 16'384 &&
             offer.refresh_numerator > 0 && offer.refresh_denominator > 0 &&
             offer.preferred_bits_per_second >= video_minimum_bits_per_second &&
             offer.preferred_bits_per_second <= offer.maximum_bits_per_second &&
             offer.maximum_bits_per_second >= video_minimum_bits_per_second &&
             offer.maximum_bits_per_second <= 1'000'000'000ULL &&
             offer.delivery == video_delivery_complete_access_unit &&
             offer.maximum_complete_access_unit_bytes > 0 &&
             offer.maximum_complete_access_unit_bytes <= 16U * 1024U * 1024U;
    }

    /**
     * @brief Validate one nullable FlexFEC association against its selected primary source.
     *
     * @param video Complete selected video tuple containing the nullable repair association.
     * @return True for null or one exact bounded, collision-free FlexFEC selection.
     */
    bool valid_flexfec_selection(const VideoSelectionPayload &video) noexcept {
      if (!video.flexfec) {
        return true;
      }
      return video.flexfec->repair_ssrc != 0 && video.flexfec->repair_ssrc != video.primary_ssrc &&
             video.flexfec->repair_payload_type >= 96 && video.flexfec->repair_payload_type <= 127 &&
             video.flexfec->repair_payload_type != video.primary_payload_type &&
             video.flexfec->window_microseconds > 0 &&
             video.flexfec->window_microseconds <= video_maximum_frame_age_microseconds &&
             video.flexfec->window_microseconds <= video.maximum_frame_age_microseconds &&
             video.flexfec->maximum_group_packets == 15;
    }

    /**
     * @brief Validate one nullable RTX association against its selected primary source.
     *
     * @param video Complete selected video tuple containing the nullable RTX association.
     * @return True for null or one exact collision-free RFC 4588 selection.
     */
    bool valid_rtx_selection(const VideoSelectionPayload &video) noexcept {
      if (!video.rtx) {
        return true;
      }
      return video.rtx->rtx_ssrc != 0 && video.rtx->rtx_ssrc != video.primary_ssrc &&
             video.rtx->rtx_payload_type >= 96 && video.rtx->rtx_payload_type <= 127 &&
             video.rtx->rtx_payload_type != video.primary_payload_type &&
             video.rtx->associated_payload_type == video.primary_payload_type &&
             (!video.flexfec ||
              (video.rtx->rtx_ssrc != video.flexfec->repair_ssrc &&
               video.rtx->rtx_payload_type != video.flexfec->repair_payload_type));
    }

    /**
     * @brief Validate the exact selected video tuple.
     *
     * @param video Thirty-key video selection model to validate before encoding.
     * @return True only when all media, extension, repair, and resource invariants hold.
     */
    bool valid_video_selection(const VideoSelectionPayload &video) noexcept {
      return video.video_generation != 0 && video.primary_ssrc != 0 &&
             video.primary_payload_type >= 96 && video.primary_payload_type <= 127 &&
             video.clock_rate == 90'000 &&
             valid_video_codec_profile_pixel(video.codec, video.profile, video.pixel_format) &&
             valid_video_color_tuple(
               video.codec,
               video.pixel_format,
               video.color_primaries,
               video.transfer_function,
               video.matrix_coefficients,
               video.full_range
             ) &&
             video.width > 0 && video.width <= 16'384 && video.height > 0 && video.height <= 16'384 &&
             video.refresh_numerator > 0 && video.refresh_denominator > 0 &&
             video.selected_bits_per_second >= video_minimum_bits_per_second &&
             video.selected_bits_per_second <= 1'000'000'000ULL &&
             video.initial_udp_payload_size == 1'200 &&
             video.decoder_surfaces >= 2 && video.decoder_surfaces <= 4 &&
             video.render_mailbox == 1 && video.delivery == video_delivery_complete_access_unit &&
             video.frame_marking_extension == video_frame_marking_extension_id &&
             video.absolute_capture_time_extension == video_absolute_capture_time_extension_id &&
             video.frame_id_extension == video_frame_id_extension_id &&
             video.input_watermark_extension == video_input_watermark_extension_id &&
             video.encoder_timing_extension == video_encoder_timing_extension_id &&
             video.maximum_frame_age_microseconds > 0 &&
             video.maximum_frame_age_microseconds <= video_maximum_frame_age_microseconds &&
             video.maximum_complete_access_unit_bytes > 0 &&
             video.maximum_complete_access_unit_bytes <= 16U * 1024U * 1024U &&
             valid_flexfec_selection(video) && valid_rtx_selection(video);
    }

    /**
     * @brief Reject video primary/repair/RTX assignments that collide with another negotiated lane.
     *
     * @param video Validated video selection being compared.
     * @param input_ssrc Negotiated client input SSRC.
     * @param acknowledgement_ssrc Negotiated host input-acknowledgement SSRC.
     * @param audio_ssrc Negotiated host-audio SSRC.
     * @param microphone_ssrc Negotiated microphone SSRC, or zero when absent.
     * @param input_payload_type Negotiated input RTP payload type.
     * @param audio_payload_type Negotiated host-audio RTP payload type.
     * @param microphone_payload_type Negotiated microphone payload type, or zero when absent.
     * @return True when any video source or payload type conflicts with another lane.
     */
    bool video_selection_conflicts(
      const VideoSelectionPayload &video,
      const std::uint32_t input_ssrc,
      const std::uint32_t acknowledgement_ssrc,
      const std::uint32_t audio_ssrc,
      const std::uint32_t microphone_ssrc,
      const std::uint8_t input_payload_type,
      const std::uint8_t audio_payload_type,
      const std::uint8_t microphone_payload_type
    ) noexcept {
      const std::array reserved_ssrcs {input_ssrc, acknowledgement_ssrc, audio_ssrc, microphone_ssrc};
      const std::array reserved_payload_types {input_payload_type, audio_payload_type, microphone_payload_type};
      const auto ssrc_conflicts = [&](const std::uint32_t ssrc) {
        return std::ranges::find(reserved_ssrcs, ssrc) != reserved_ssrcs.end();
      };
      const auto payload_type_conflicts = [&](const std::uint8_t payload_type) {
        return std::ranges::find(reserved_payload_types, payload_type) != reserved_payload_types.end();
      };
      return ssrc_conflicts(video.primary_ssrc) || payload_type_conflicts(video.primary_payload_type) ||
             (video.flexfec &&
              (ssrc_conflicts(video.flexfec->repair_ssrc) ||
               payload_type_conflicts(video.flexfec->repair_payload_type))) ||
             (video.rtx &&
              (ssrc_conflicts(video.rtx->rtx_ssrc) ||
               payload_type_conflicts(video.rtx->rtx_payload_type)));
    }

    /**
     * @brief Encode a nullable exact FlexFEC association.
     *
     * @param flexfec Optional validated FlexFEC selection.
     * @return CBOR null or the exact four-key FlexFEC map.
     */
    cbor::Value flexfec_selection(const std::optional<FlexFecSelectionPayload> &flexfec) {
      if (!flexfec) {
        return cbor::Value {cbor::Null {}};
      }
      return cbor::Value {cbor::Value::Map {
        {1, flexfec->repair_ssrc},
        {2, flexfec->repair_payload_type},
        {3, flexfec->window_microseconds},
        {4, flexfec->maximum_group_packets},
      }};
    }

    /**
     * @brief Encode a nullable exact RTX association.
     *
     * @param rtx Optional validated RTX selection.
     * @return CBOR null or the exact three-key RTX map.
     */
    cbor::Value rtx_selection(const std::optional<RtxSelectionPayload> &rtx) {
      if (!rtx) {
        return cbor::Value {cbor::Null {}};
      }
      return cbor::Value {cbor::Value::Map {
        {1, rtx->rtx_ssrc},
        {2, rtx->rtx_payload_type},
        {3, rtx->associated_payload_type},
      }};
    }

    /**
     * @brief Encode the frozen thirty-key video selection.
     *
     * @param video Validated video selection.
     * @return Exact deterministic-CBOR selection map.
     */
    cbor::Value video_selection(const VideoSelectionPayload &video) {
      return cbor::Value {cbor::Value::Map {
        {1, video_schema_version},
        {2, video.video_generation},
        {3, video.primary_ssrc},
        {4, video.primary_payload_type},
        {5, video.clock_rate},
        {6, static_cast<std::uint8_t>(video.codec)},
        {7, static_cast<std::uint8_t>(video.profile)},
        {8, video.width},
        {9, video.height},
        {10, video.refresh_numerator},
        {11, video.refresh_denominator},
        {12, video.selected_bits_per_second},
        {13, static_cast<std::uint8_t>(video.pixel_format)},
        {14, video.color_primaries},
        {15, video.transfer_function},
        {16, video.matrix_coefficients},
        {17, cbor::Value {video.full_range}},
        {18, video.initial_udp_payload_size},
        {19, video.decoder_surfaces},
        {20, video.render_mailbox},
        {21, video.delivery},
        {22, video.frame_marking_extension},
        {23, video.absolute_capture_time_extension},
        {24, video.frame_id_extension},
        {25, video.input_watermark_extension},
        {26, video.encoder_timing_extension},
        {27, flexfec_selection(video.flexfec)},
        {28, rtx_selection(video.rtx)},
        {29, video.maximum_frame_age_microseconds},
        {30, video.maximum_complete_access_unit_bytes},
      }};
    }

    /**
     * @brief Validate one canonical low-overhead AV1 sequence-header OBU.
     *
     * @param unit Complete prefix-free OBU including its canonical size field.
     * @return True only for one exact nonempty sequence-header OBU.
     */
    bool valid_av1_sequence_header(const std::span<const std::uint8_t> unit) noexcept {
      if (unit.size() < 3 || (unit[0] & 0x81U) != 0 || ((unit[0] >> 3U) & 0x0fU) != 1U ||
          (unit[0] & 0x02U) == 0) {
        return false;
      }
      std::size_t offset = 1;
      if ((unit[0] & 0x04U) != 0) {
        if (offset >= unit.size() || (unit[offset] & 0x07U) != 0) {
          return false;
        }
        ++offset;
      }
      std::size_t payload_size = 0;
      std::size_t shift = 0;
      std::size_t leb_bytes = 0;
      for (; leb_bytes < 8 && offset < unit.size(); ++leb_bytes, ++offset) {
        const auto byte = unit[offset];
        const auto value = static_cast<std::size_t>(byte & 0x7fU);
        if (shift >= std::numeric_limits<std::size_t>::digits ||
            value > (std::numeric_limits<std::size_t>::max() >> shift)) {
          return false;
        }
        payload_size |= value << shift;
        if ((byte & 0x80U) == 0) {
          ++offset;
          ++leb_bytes;
          return payload_size != 0 && offset + payload_size == unit.size() &&
                 (leb_bytes == 1 || value != 0);
        }
        shift += 7;
      }
      return false;
    }

    /**
     * @brief Validate exact prefix-free codec configuration units.
     *
     * @param configuration Codec discriminator and ordered configuration units.
     * @return True only for SPS/PPS, VPS/SPS/PPS, or one canonical AV1 sequence header.
     */
    bool valid_codec_configuration(const VideoCodecConfigurationPayload &configuration) noexcept {
      const auto expected = configuration.kind == VideoCodec::h264 ? std::size_t {2} :
                            configuration.kind == VideoCodec::hevc ? std::size_t {3} :
                            configuration.kind == VideoCodec::av1  ? std::size_t {1} :
                                                                     std::size_t {0};
      if (expected == 0 || configuration.units.size() != expected) {
        return false;
      }
      for (const auto &unit : configuration.units) {
        if (unit.empty() || unit.size() > maximum_video_codec_configuration_unit_bytes ||
            (unit.size() >= 3 && unit[0] == 0 && unit[1] == 0 &&
             (unit[2] == 1 || (unit.size() >= 4 && unit[2] == 0 && unit[3] == 1)))) {
          return false;
        }
      }
      if (configuration.kind == VideoCodec::h264) {
        return (configuration.units[0][0] & 0x1fU) == 7U &&
               (configuration.units[1][0] & 0x1fU) == 8U;
      }
      if (configuration.kind == VideoCodec::hevc) {
        return configuration.units[0].size() >= 2 && configuration.units[1].size() >= 2 &&
               configuration.units[2].size() >= 2 &&
               ((configuration.units[0][0] >> 1U) & 0x3fU) == 32U &&
               ((configuration.units[1][0] >> 1U) & 0x3fU) == 33U &&
               ((configuration.units[2][0] >> 1U) & 0x3fU) == 34U;
      }
      return valid_av1_sequence_header(configuration.units.front());
    }

    /**
     * @brief Validate exact HDR10 mastering and content-light metadata.
     *
     * @param metadata Thirteen-field unsigned HDR10 metadata block.
     * @return True only when chromaticity and luminance relationships are internally valid.
     */
    bool valid_hdr_metadata(const HdrMetadataPayload &metadata) noexcept {
      const auto valid_point = [](const std::uint16_t x, const std::uint16_t y) {
        return x != 0 && y != 0 && x <= 50'000U && y <= 50'000U;
      };
      if (!valid_point(metadata.red_primary_x, metadata.red_primary_y) ||
          !valid_point(metadata.green_primary_x, metadata.green_primary_y) ||
          !valid_point(metadata.blue_primary_x, metadata.blue_primary_y) ||
          !valid_point(metadata.white_point_x, metadata.white_point_y) ||
          metadata.maximum_display_luminance == 0 ||
          static_cast<std::uint32_t>(metadata.minimum_display_luminance) >
            static_cast<std::uint32_t>(metadata.maximum_display_luminance) * 10'000U ||
          (metadata.maximum_content_light_level == 0) !=
            (metadata.maximum_frame_average_light_level == 0) ||
          metadata.maximum_frame_average_light_level > metadata.maximum_content_light_level ||
          (metadata.maximum_full_frame_luminance != 0 &&
           metadata.maximum_full_frame_luminance > metadata.maximum_display_luminance)) {
        return false;
      }
      return !(metadata.red_primary_x == metadata.green_primary_x &&
               metadata.red_primary_y == metadata.green_primary_y) &&
             !(metadata.red_primary_x == metadata.blue_primary_x &&
               metadata.red_primary_y == metadata.blue_primary_y) &&
             !(metadata.green_primary_x == metadata.blue_primary_x &&
               metadata.green_primary_y == metadata.blue_primary_y);
    }

    /**
     * @brief Encode an exact codec-configuration map.
     *
     * @param configuration Validated codec discriminator and units.
     * @return Exact two-key deterministic-CBOR codec-configuration map.
     */
    cbor::Value codec_configuration(const VideoCodecConfigurationPayload &configuration) {
      cbor::Value::Array units;
      units.reserve(configuration.units.size());
      for (const auto &unit : configuration.units) {
        units.emplace_back(cbor::Value::Bytes {unit.begin(), unit.end()});
      }
      return cbor::Value {cbor::Value::Map {
        {1, static_cast<std::uint8_t>(configuration.kind)},
        {2, std::move(units)},
      }};
    }

    /**
     * @brief Encode null or one exact thirteen-key HDR metadata map.
     *
     * @param metadata Optional validated HDR10 static metadata.
     * @return CBOR null or the exact thirteen-key deterministic-CBOR metadata map.
     */
    cbor::Value hdr_metadata(const std::optional<HdrMetadataPayload> &metadata) {
      if (!metadata) {
        return cbor::Value {cbor::Null {}};
      }
      return cbor::Value {cbor::Value::Map {
        {1, metadata->red_primary_x},
        {2, metadata->red_primary_y},
        {3, metadata->green_primary_x},
        {4, metadata->green_primary_y},
        {5, metadata->blue_primary_x},
        {6, metadata->blue_primary_y},
        {7, metadata->white_point_x},
        {8, metadata->white_point_y},
        {9, metadata->maximum_display_luminance},
        {10, metadata->minimum_display_luminance},
        {11, metadata->maximum_content_light_level},
        {12, metadata->maximum_frame_average_light_level},
        {13, metadata->maximum_full_frame_luminance},
      }};
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

  std::expected<PairBeginPayload, ControlWireError> decode_pair_begin(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 9);
    PairBeginPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *schema = map ? unsigned_value((*map)[1].second) : nullptr;
    const auto *client_name = map ? std::get_if<std::string>(&(*map)[4].second.storage) : nullptr;
    const auto *permissions = map ? unsigned_value((*map)[8].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || schema == nullptr ||
        *schema != pairing_schema_version || !fixed_bytes((*map)[2].second, result.client_id) ||
        !fixed_bytes((*map)[3].second, result.client_identity_key) || client_name == nullptr ||
        client_name->empty() || client_name->size() > 64 || !cbor::is_valid_utf8(*client_name) ||
        !fixed_bytes((*map)[5].second, result.client_pairing_nonce) ||
        !fixed_bytes((*map)[6].second, result.scrypt_salt) ||
        !fixed_bytes((*map)[7].second, result.point_a) || permissions == nullptr ||
        *permissions > std::numeric_limits<std::uint32_t>::max() || is_zero(result.client_id) ||
        is_zero(result.client_identity_key) || is_zero(result.client_pairing_nonce) ||
        is_zero(result.scrypt_salt) || is_zero(result.point_a) || result.point_a[0] != 0x04) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    const auto requested_permissions = PermissionSet::from_mask(static_cast<std::uint32_t>(*permissions));
    if (!requested_permissions) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    result.client_name = *client_name;
    result.requested_permissions = *requested_permissions;
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_pending(const PairPendingPayload &payload) {
    if (payload.status != ControlStatus::success || is_zero(payload.pairing_session_id) ||
        payload.expires_at_utc_seconds == 0 || payload.effective_permissions.mask() == 0) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, pairing_schema_version},
      {4, bytes(payload.pairing_session_id)},
      {5, payload.expires_at_utc_seconds},
      {6, payload.effective_permissions.mask()},
    });
  }

  std::expected<PairPollPayload, ControlWireError> decode_pair_poll(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 3);
    PairPollPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *schema = map ? unsigned_value((*map)[1].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || schema == nullptr ||
        *schema != pairing_schema_version || !fixed_bytes((*map)[2].second, result.pairing_session_id) ||
        is_zero(result.pairing_session_id)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_challenge(const PairChallengePayload &payload) {
    if (is_zero(payload.pairing_session_id) || payload.approval_generation == 0 || is_zero(payload.point_b) ||
        payload.point_b[0] != 0x04 || payload.effective_permissions.mask() == 0 ||
        payload.expires_at_utc_seconds == 0) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, pairing_schema_version},
      {3, bytes(payload.pairing_session_id)},
      {4, payload.approval_generation},
      {5, bytes(payload.point_b)},
      {6, payload.effective_permissions.mask()},
      {7, payload.expires_at_utc_seconds},
    });
  }

  std::expected<PairFinishPayload, ControlWireError> decode_pair_finish(const std::span<const std::uint8_t> payload) {
    const auto map = decode_map(payload, 6);
    PairFinishPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *schema = map ? unsigned_value((*map)[1].second) : nullptr;
    const auto *approval_generation = map ? unsigned_value((*map)[3].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || schema == nullptr ||
        *schema != pairing_schema_version || !fixed_bytes((*map)[2].second, result.pairing_session_id) ||
        approval_generation == nullptr || *approval_generation == 0 ||
        *approval_generation > std::numeric_limits<std::uint32_t>::max() ||
        !fixed_bytes((*map)[4].second, result.confirmation_a) ||
        !fixed_bytes((*map)[5].second, result.client_signature) || is_zero(result.pairing_session_id) ||
        is_zero(result.confirmation_a) || is_zero(result.client_signature)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    result.approval_generation = static_cast<std::uint32_t>(*approval_generation);
    return result;
  }

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_pair_result(const PairResultPayload &payload) {
    if (payload.status != ControlStatus::success || is_zero(payload.pairing_session_id) ||
        payload.approval_generation == 0 || payload.permissions.mask() == 0 ||
        payload.revocation_generation == 0 || is_zero(payload.confirmation_b) || is_zero(payload.host_signature)) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, static_cast<std::uint8_t>(payload.status)},
      {3, pairing_schema_version},
      {4, bytes(payload.pairing_session_id)},
      {5, payload.approval_generation},
      {6, payload.permissions.mask()},
      {7, payload.revocation_generation},
      {8, bytes(payload.confirmation_b)},
      {9, bytes(payload.host_signature)},
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

  std::expected<ControlStatus, ControlWireError> decode_control_error(
    const std::span<const std::uint8_t> payload
  ) {
    const auto map = decode_map(payload, 2);
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *status = map ? unsigned_value((*map)[1].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || status == nullptr ||
        *status > static_cast<std::uint8_t>(ControlStatus::internal_failure) ||
        !valid_status(static_cast<ControlStatus>(*status)) ||
        static_cast<ControlStatus>(*status) == ControlStatus::success) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return static_cast<ControlStatus>(*status);
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
        *capture_to_present > video_maximum_frame_age_microseconds ||
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
      if (offer == nullptr || offer->size() != 18) {
        return std::unexpected(ControlWireError::invalid_shape);
      }
      for (std::size_t index = 0; index < offer->size(); ++index) {
        if ((*offer)[index].first != index + 1) {
          return std::unexpected(ControlWireError::invalid_shape);
        }
      }
      const auto *schema = unsigned_value((*offer)[0].second);
      const auto *codec = unsigned_value((*offer)[1].second);
      const auto *profile = unsigned_value((*offer)[2].second);
      const auto *width = unsigned_value((*offer)[3].second);
      const auto *height = unsigned_value((*offer)[4].second);
      const auto *refresh_numerator = unsigned_value((*offer)[5].second);
      const auto *refresh_denominator = unsigned_value((*offer)[6].second);
      const auto *preferred_bitrate = unsigned_value((*offer)[7].second);
      const auto *maximum_bitrate = unsigned_value((*offer)[8].second);
      const auto *pixel_class = unsigned_value((*offer)[9].second);
      const auto *color_primaries = unsigned_value((*offer)[10].second);
      const auto *transfer_function = unsigned_value((*offer)[11].second);
      const auto *matrix_coefficients = unsigned_value((*offer)[12].second);
      const auto *full_range = boolean_value((*offer)[13].second);
      const auto *delivery = unsigned_value((*offer)[14].second);
      const auto *flexfec = boolean_value((*offer)[15].second);
      const auto *rtx = boolean_value((*offer)[16].second);
      const auto *maximum_access_unit = unsigned_value((*offer)[17].second);
      if (schema == nullptr || *schema != video_schema_version || codec == nullptr ||
          profile == nullptr || width == nullptr || height == nullptr ||
          refresh_numerator == nullptr || refresh_denominator == nullptr || preferred_bitrate == nullptr ||
          maximum_bitrate == nullptr || pixel_class == nullptr || color_primaries == nullptr ||
          transfer_function == nullptr || matrix_coefficients == nullptr || full_range == nullptr ||
          delivery == nullptr || flexfec == nullptr || rtx == nullptr || maximum_access_unit == nullptr ||
          *codec > std::numeric_limits<std::uint8_t>::max() ||
          *profile > std::numeric_limits<std::uint8_t>::max() ||
          *width > std::numeric_limits<std::uint32_t>::max() ||
          *height > std::numeric_limits<std::uint32_t>::max() ||
          *refresh_numerator > std::numeric_limits<std::uint32_t>::max() ||
          *refresh_denominator > std::numeric_limits<std::uint32_t>::max() ||
          *pixel_class > std::numeric_limits<std::uint8_t>::max() ||
          *color_primaries > std::numeric_limits<std::uint8_t>::max() ||
          *transfer_function > std::numeric_limits<std::uint8_t>::max() ||
          *matrix_coefficients > std::numeric_limits<std::uint8_t>::max() ||
          *delivery > std::numeric_limits<std::uint8_t>::max() ||
          *maximum_access_unit > std::numeric_limits<std::uint32_t>::max()) {
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
        .pixel_format = static_cast<VideoPixelClass>(*pixel_class),
        .color_primaries = static_cast<std::uint8_t>(*color_primaries),
        .transfer_function = static_cast<std::uint8_t>(*transfer_function),
        .matrix_coefficients = static_cast<std::uint8_t>(*matrix_coefficients),
        .full_range = *full_range,
        .delivery = static_cast<std::uint8_t>(*delivery),
        .flexfec = *flexfec,
        .rtx = *rtx,
        .maximum_complete_access_unit_bytes = static_cast<std::uint32_t>(*maximum_access_unit),
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
        !valid_video_selection(payload.video) ||
        video_selection_conflicts(
          payload.video,
          payload.input_ssrc,
          payload.acknowledgement_ssrc,
          payload.audio.audio_ssrc,
          payload.microphone ? payload.microphone->microphone_ssrc : 0,
          payload.input_payload_type,
          payload.audio.audio_payload_type,
          payload.microphone ? payload.microphone->microphone_payload_type : 0
        )) {
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
    const auto map = decode_map(payload, 5);
    AttachRequestPayload result;
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || !fixed_bytes((*map)[1].second, result.session_id) ||
        !fixed_bytes((*map)[2].second, result.attach_token) || !fixed_bytes((*map)[3].second, result.intent_id) ||
        !fixed_bytes((*map)[4].second, result.successor_attach_token) || is_zero(result.session_id) ||
        is_zero(result.attach_token) || is_zero(result.intent_id) || is_zero(result.successor_attach_token) ||
        result.attach_token == result.successor_attach_token) {
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
        !valid_video_selection(payload.video) ||
        video_selection_conflicts(
          payload.video,
          payload.input_ssrc,
          payload.acknowledgement_ssrc,
          payload.audio.audio_ssrc,
          payload.microphone ? payload.microphone->microphone_ssrc : 0,
          payload.input_payload_type,
          payload.audio.audio_payload_type,
          payload.microphone ? payload.microphone->microphone_payload_type : 0
        )) {
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
        payload.codec_configuration.kind != payload.video.codec ||
        !valid_codec_configuration(payload.codec_configuration) ||
        payload.frame_id_origin == 0 || payload.recovery_epoch == 0 ||
        (payload.video.transfer_function == video_transfer_pq) != payload.hdr_metadata.has_value() ||
        (payload.hdr_metadata && !valid_hdr_metadata(*payload.hdr_metadata))) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, video_schema_version},
      {2, bytes(payload.session_id)},
      {3, payload.stream_generation},
      {4, video_selection(payload.video)},
      {5, codec_configuration(payload.codec_configuration)},
      {6, payload.frame_id_origin},
      {7, payload.recovery_epoch},
      {8, hdr_metadata(payload.hdr_metadata)},
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
    if (!map || version == nullptr || *version != video_schema_version || status == nullptr ||
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

  std::expected<std::vector<std::uint8_t>, ControlWireError> encode_path_probe(
    const PathProbePayload &payload
  ) {
    if (payload.probe_id == 0 || payload.udp_payload_size < 1'200 || payload.udp_payload_size > 1'472) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return encode({
      {1, wire_version},
      {2, payload.probe_id},
      {3, payload.udp_payload_size},
    });
  }

  std::expected<PathProbePayload, ControlWireError> decode_path_probe(
    const std::span<const std::uint8_t> payload
  ) {
    const auto map = decode_map(payload, 3);
    const auto *version = map ? unsigned_value((*map)[0].second) : nullptr;
    const auto *probe_id = map ? unsigned_value((*map)[1].second) : nullptr;
    const auto *udp_payload_size = map ? unsigned_value((*map)[2].second) : nullptr;
    if (!map || version == nullptr || *version != wire_version || probe_id == nullptr || *probe_id == 0 ||
        udp_payload_size == nullptr || *udp_payload_size < 1'200 || *udp_payload_size > 1'472) {
      return std::unexpected(ControlWireError::invalid_field);
    }
    return PathProbePayload {
      .probe_id = *probe_id,
      .udp_payload_size = static_cast<std::uint16_t>(*udp_payload_size),
    };
  }
}  // namespace lumen::lsp::runtime
