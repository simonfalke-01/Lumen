/**
 * @file src/nvenc/nvenc_config.h
 * @brief Declarations for NVENC encoder configuration.
 */
#pragma once

namespace nvenc {

  /**
   * @brief Enumerates the NVENC tuning objectives used by stream policies.
   */
  enum class nvenc_tuning {
    ultra_low_latency,  ///< Minimize encoder buffering and reordering.
    high_quality,  ///< Prefer compression quality within the selected bounded preset.
    lossless,  ///< Use the SDK lossless preset contract after runtime capability proof.
  };

  /**
   * @brief Selects whether encoded samples must be mathematically lossless.
   */
  enum class nvenc_fidelity {
    rate_controlled,  ///< Bounded rate control; compression artifacts remain possible.
    codec_lossless_required,  ///< Fail unless the negotiated encoder input is preserved exactly.
  };

  /**
   * @brief SDK-neutral golden values required by the NVENC codec-lossless path.
   */
  struct nvenc_lossless_contract {
    unsigned qp_inter_p;  ///< Constant P-frame QP.
    unsigned qp_inter_b;  ///< Constant B-frame QP, retained at zero even though B frames are disabled.
    unsigned qp_intra;  ///< Constant intra-frame QP.
    bool multipass;  ///< Whether an extra rate-control pass is permitted.
    bool adaptive_quantization;  ///< Whether AQ is permitted.
    bool lookahead;  ///< Whether lookahead is permitted.
  };

  /**
   * @brief Return the auditable fixed QP0/single-pass/no-lookahead contract.
   * @return Compile-time lossless configuration values.
   */
  [[nodiscard]] constexpr nvenc_lossless_contract required_lossless_contract() noexcept {
    return {0, 0, 0, false, false, false};
  }

  /**
   * @brief Clear preset residue and apply the complete lossless RC contract.
   *
   * The template is instantiated with the real `NV_ENC_RC_PARAMS` in production and
   * a layout-compatible hostile prefilled test object in unit tests.
   *
   * @tparam RateControl NVENC rate-control-like structure.
   * @tparam Version SDK structure-version type.
   * @tparam Mode SDK rate-control-mode type.
   * @tparam MultiPass SDK multipass type.
   * @param rate_control Structure to clear and configure.
   * @param version SDK-specific `NV_ENC_RC_PARAMS_VER`.
   * @param const_qp SDK-specific `NV_ENC_PARAMS_RC_CONSTQP`.
   * @param disabled_pass SDK-specific `NV_ENC_MULTI_PASS_DISABLED`.
   */
  template<typename RateControl, typename Version, typename Mode, typename MultiPass>
  constexpr void apply_lossless_rate_control(
    RateControl &rate_control,
    Version version,
    Mode const_qp,
    MultiPass disabled_pass
  ) noexcept {
    constexpr auto lossless = required_lossless_contract();
    rate_control = {};
    rate_control.version = version;
    rate_control.rateControlMode = const_qp;
    rate_control.constQP.qpInterP = lossless.qp_inter_p;
    rate_control.constQP.qpInterB = lossless.qp_inter_b;
    rate_control.constQP.qpIntra = lossless.qp_intra;
    rate_control.zeroReorderDelay = 1;
    rate_control.enableLookahead = lossless.lookahead;
    rate_control.multiPass = disabled_pass;
  }

  /**
   * @brief Enumerates supported nVENC two pass options.
   */
  enum class nvenc_two_pass {
    disabled,  ///< Single pass, the fastest and no extra vram
    quarter_resolution,  ///< Larger motion vectors being caught, faster and uses less extra vram
    full_resolution,  ///< Better overall statistics, slower and uses more extra vram
  };

  /**
   * @brief Enumerates supported nVENC split frame encoding options.
   */
  enum class nvenc_split_frame_encoding {
    disabled,  ///< Disable
    driver_decides,  ///< Let driver decide
    force_enabled,  ///< Force-enable
  };

  /**
   * @brief NVENC encoder configuration.
   */
  struct nvenc_config {
    // Quality preset from 1 to 7, higher is slower
    int quality_preset = 1;  ///< Quality preset.

    nvenc_tuning tuning = nvenc_tuning::ultra_low_latency;  ///< Encoder tuning objective.

    nvenc_fidelity fidelity = nvenc_fidelity::rate_controlled;  ///< Required encoded-sample fidelity.

    // Use optional preliminary pass for better motion vectors, bitrate distribution and stricter VBV(HRD), uses CUDA cores
    nvenc_two_pass two_pass = nvenc_two_pass::quarter_resolution;  ///< Two pass.

    // Percentage increase of VBV/HRD from the default single frame, allows low-latency variable bitrate
    int vbv_percentage_increase = 0;  ///< Vbv percentage increase.

    // Improves fades compression, uses CUDA cores
    bool weighted_prediction = false;  ///< Enable weighted prediction for NVENC.

    // Allocate more bitrate to flat regions since they're visually more perceptible, uses CUDA cores
    bool adaptive_quantization = false;  ///< Enable adaptive quantization for NVENC.

    // Don't use QP below certain value, limits peak image quality to save bitrate
    bool enable_min_qp = false;  ///< Enable minimum QP limits for NVENC.

    // Min QP value for H.264 when enable_min_qp is selected
    unsigned min_qp_h264 = 19;  ///< Min qp h264.

    // Min QP value for HEVC when enable_min_qp is selected
    unsigned min_qp_hevc = 23;  ///< Min qp HEVC.

    // Min QP value for AV1 when enable_min_qp is selected
    unsigned min_qp_av1 = 23;  ///< Min qp AV1.

    // Use CAVLC entropy coding in H.264 instead of CABAC, not relevant and here for historical reasons
    bool h264_cavlc = false;  ///< Use CAVLC entropy coding for H.264.

    // Add filler data to encoded frames to stay at target bitrate, mainly for testing
    bool insert_filler_data = false;  ///< Insert filler data to maintain bitrate constraints.

    // Enable split-frame encoding if the gpu has multiple NVENC hardware clusters
    nvenc_split_frame_encoding split_frame_encoding = nvenc_split_frame_encoding::driver_decides;  ///< Split frame encoding.
  };

}  // namespace nvenc
