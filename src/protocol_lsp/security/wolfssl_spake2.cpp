/**
 * @file WolfsslSpake2.cpp
 * @brief Internal wolfSSL 5.9.2 RFC 9382 SPAKE2-P256 provider.
 */

#if __has_include("wolfssl_spake2.h")
  #include "wolfssl_spake2.h"
#else
  #include "WolfsslSpake2.h"
#endif

#if __has_include("secure_zero.h")
  #include "secure_zero.h"
#else
  #include "SecureZero.h"
#endif

#include <utility>

#ifndef LSP_SPAKE2_WOLFSSL_AVAILABLE
  #if defined(CLSP_CORE_HAS_WOLFSSL)
    #define LSP_SPAKE2_WOLFSSL_AVAILABLE CLSP_CORE_HAS_WOLFSSL
  #elif defined(LUMEN_LSP_WOLFSSL_AVAILABLE)
    #define LSP_SPAKE2_WOLFSSL_AVAILABLE LUMEN_LSP_WOLFSSL_AVAILABLE
  #else
    #define LSP_SPAKE2_WOLFSSL_AVAILABLE 0
  #endif
#endif

#if LSP_SPAKE2_WOLFSSL_AVAILABLE

  #if __has_include(<wolfssl/lsp_spake2_settings.h>)
    #include <wolfssl/lsp_spake2_settings.h>
  #else
    #include <wolfssl/options.h>
  #endif

  #if !defined(HAVE_SCRYPT) || defined(NO_PWDBASED)
    #error "LSP SPAKE2 requires wolfSSL HAVE_SCRYPT and PWDBASED"
  #endif
  #if !defined(HAVE_ECC) || !defined(HAVE_HKDF)
    #error "LSP SPAKE2 requires wolfSSL P-256 ECC and HKDF"
  #endif
  #if !defined(WOLFSSL_PUBLIC_MP) || !defined(WOLFSSL_PUBLIC_ECC_ADD_DBL)
    #error "LSP SPAKE2 requires the reviewed public wolfCrypt MP and ECC add APIs"
  #endif
  #if !defined(ECC_TIMING_RESISTANT) || !defined(WOLFSSL_ECC_GEN_REJECT_SAMPLING)
    #error "LSP SPAKE2 requires hardened ECC and rejection-sampled scalars"
  #endif
  #if !defined(WOLFSSL_SP_MATH_ALL)
    #error "LSP SPAKE2 requires wolfSSL SP math for the reviewed P-256 point-add path"
  #endif

  #include <algorithm>
  #include <array>
  #include <cstring>
  #include <limits>
  #include <new>
  #include <wolfssl/wolfcrypt/ecc.h>
  #include <wolfssl/wolfcrypt/error-crypt.h>
  #include <wolfssl/wolfcrypt/hmac.h>
  #include <wolfssl/wolfcrypt/pwdbased.h>
  #include <wolfssl/wolfcrypt/random.h>
  #include <wolfssl/wolfcrypt/sha256.h>

namespace lumen::lsp {
  namespace {
    constexpr std::size_t transcript_capacity = 800;
    constexpr std::size_t confirmation_label_size = 16;
    constexpr std::size_t confirmation_key_material_size = 32;
    constexpr std::size_t maximum_random_scalar_attempts = 128;
    constexpr std::array<std::uint8_t, spake2_scalar_size> p256_order {
      0xff,
      0xff,
      0xff,
      0xff,
      0x00,
      0x00,
      0x00,
      0x00,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xff,
      0xbc,
      0xe6,
      0xfa,
      0xad,
      0xa7,
      0x17,
      0x9e,
      0x84,
      0xf3,
      0xb9,
      0xca,
      0xc2,
      0xfc,
      0x63,
      0x25,
      0x51,
    };
    constexpr std::array<std::uint8_t, spake2_point_size> p256_point_m {
      0x04,
      0x88,
      0x6e,
      0x2f,
      0x97,
      0xac,
      0xe4,
      0x6e,
      0x55,
      0xba,
      0x9d,
      0xd7,
      0x24,
      0x25,
      0x79,
      0xf2,
      0x99,
      0x3b,
      0x64,
      0xe1,
      0x6e,
      0xf3,
      0xdc,
      0xab,
      0x95,
      0xaf,
      0xd4,
      0x97,
      0x33,
      0x3d,
      0x8f,
      0xa1,
      0x2f,
      0x5f,
      0xf3,
      0x55,
      0x16,
      0x3e,
      0x43,
      0xce,
      0x22,
      0x4e,
      0x0b,
      0x0e,
      0x65,
      0xff,
      0x02,
      0xac,
      0x8e,
      0x5c,
      0x7b,
      0xe0,
      0x94,
      0x19,
      0xc7,
      0x85,
      0xe0,
      0xca,
      0x54,
      0x7d,
      0x55,
      0xa1,
      0x2e,
      0x2d,
      0x20,
    };
    constexpr std::array<std::uint8_t, spake2_point_size> p256_point_n {
      0x04,
      0xd8,
      0xbb,
      0xd6,
      0xc6,
      0x39,
      0xc6,
      0x29,
      0x37,
      0xb0,
      0x4d,
      0x99,
      0x7f,
      0x38,
      0xc3,
      0x77,
      0x07,
      0x19,
      0xc6,
      0x29,
      0xd7,
      0x01,
      0x4d,
      0x49,
      0xa2,
      0x4b,
      0x4f,
      0x98,
      0xba,
      0xa1,
      0x29,
      0x2b,
      0x49,
      0x07,
      0xd6,
      0x0a,
      0xa6,
      0xbf,
      0xad,
      0xe4,
      0x50,
      0x08,
      0xa6,
      0x36,
      0x33,
      0x7f,
      0x51,
      0x68,
      0xc6,
      0x4d,
      0x9b,
      0xd3,
      0x60,
      0x34,
      0x80,
      0x8c,
      0xd5,
      0x64,
      0x49,
      0x0b,
      0x1e,
      0x65,
      0x6e,
      0xdb,
      0xe7,
    };
    constexpr std::array<std::uint8_t, confirmation_label_size> confirmation_label {
      'C',
      'o',
      'n',
      'f',
      'i',
      'r',
      'm',
      'a',
      't',
      'i',
      'o',
      'n',
      'K',
      'e',
      'y',
      's',
    };

    /** @brief Internal one-shot protocol state. */
    enum class SessionState : std::uint8_t {
      ready,  ///< Password scalar is ready; no wire point was emitted.
      point_sent,  ///< Client pA was emitted and pB is expected.
      confirmation_pending,  ///< Local confirmation was derived and peer confirmation is expected.
      terminal,  ///< Session completed or failed and secret state was cleared.
    };

    /**
     * @brief Compare fixed confirmation values without content-dependent exits.
     *
     * @param left First confirmation.
     * @param right Second confirmation.
     * @return True only when all bytes match.
     */
    [[nodiscard]] bool constant_equal(
      const Spake2Confirmation &left,
      const Spake2Confirmation &right
    ) noexcept {
      volatile std::uint8_t difference = 0;
      for (std::size_t index = 0; index < left.size(); ++index) {
        difference = static_cast<std::uint8_t>(difference | (left[index] ^ right[index]));
      }
      return difference == 0;
    }

    /**
     * @brief Validate a six-digit ASCII PIN without locale-dependent parsing.
     *
     * @param pin Candidate PIN.
     * @return True only for exactly six bytes in `0...9`.
     */
    [[nodiscard]] bool valid_pin(const std::string_view pin) noexcept {
      if (pin.size() != spake2_pin_size) {
        return false;
      }
      std::uint8_t invalid = 0;
      for (const auto character : pin) {
        const auto value = static_cast<std::uint8_t>(character);
        invalid = static_cast<std::uint8_t>(invalid | static_cast<std::uint8_t>(value < '0' || value > '9'));
      }
      return invalid == 0;
    }

    /**
     * @brief Subtract the P-256 order from one 256-bit big-endian value.
     *
     * @param input Candidate scalar.
     * @param difference Fixed-width subtraction result.
     * @return One when input is less than the order, otherwise zero.
     */
    [[nodiscard]] std::uint8_t subtract_order(
      const Spake2Scalar &input,
      Spake2Scalar &difference
    ) noexcept {
      std::uint16_t borrow = 0;
      for (std::size_t reverse_index = 0; reverse_index < input.size(); ++reverse_index) {
        const auto index = input.size() - 1 - reverse_index;
        const auto minuend = static_cast<std::uint16_t>(input[index]);
        const auto subtrahend = static_cast<std::uint16_t>(p256_order[index]) + borrow;
        difference[index] = static_cast<std::uint8_t>(minuend - subtrahend);
        borrow = static_cast<std::uint16_t>(minuend < subtrahend);
      }
      return static_cast<std::uint8_t>(borrow);
    }

    /**
     * @brief Test the exact P-256 private-scalar range `[1,n-1]`.
     *
     * @param scalar Fixed-width candidate.
     * @return True only when nonzero and strictly less than the order.
     */
    [[nodiscard]] bool valid_scalar(const Spake2Scalar &scalar) noexcept {
      Spake2Scalar discarded;
      const auto less_than_order = subtract_order(scalar, discarded);
      secure_zero(discarded);
      std::uint8_t aggregate = 0;
      for (const auto byte : scalar) {
        aggregate = static_cast<std::uint8_t>(aggregate | byte);
      }
      return less_than_order == 1 && aggregate != 0;
    }

    /**
     * @brief Reduce one 256-bit scrypt output modulo the P-256 order.
     *
     * Only one conditional subtraction is necessary because both values are
     * 256 bits. Selection is performed bytewise without a password-dependent
     * branch.
     *
     * @param input Raw 32-byte scrypt output.
     * @param scalar Reduced fixed-width scalar.
     * @return True when the reduced scalar is nonzero.
     */
    [[nodiscard]] bool reduce_password_scalar(
      const Spake2Scalar &input,
      Spake2Scalar &scalar
    ) noexcept {
      Spake2Scalar difference;
      const auto input_less_than_order = subtract_order(input, difference);
      const auto use_difference_mask = static_cast<std::uint8_t>(0U - (input_less_than_order ^ 1U));
      const auto use_input_mask = static_cast<std::uint8_t>(~use_difference_mask);
      std::uint8_t aggregate = 0;
      for (std::size_t index = 0; index < scalar.size(); ++index) {
        scalar[index] = static_cast<std::uint8_t>(
          (difference[index] & use_difference_mask) | (input[index] & use_input_mask)
        );
        aggregate = static_cast<std::uint8_t>(aggregate | scalar[index]);
      }
      secure_zero(difference);
      return aggregate != 0;
    }

    /** @brief RAII owner for one wolfCrypt multi-precision integer. */
    class MpOwner {
    public:
      /** @brief Initialize an empty integer. */
      MpOwner() noexcept:
          ready_ {mp_init(&value_) == MP_OKAY} {
      }

      MpOwner(const MpOwner &) = delete;
      MpOwner &operator=(const MpOwner &) = delete;

      /** @brief Clear integer storage. */
      ~MpOwner() {
        if (ready_) {
          mp_forcezero(&value_);
        }
      }

      /** @brief Return initialization status. */
      [[nodiscard]] bool ready() const noexcept {
        return ready_;
      }

      /** @brief Return mutable wolfCrypt integer. */
      [[nodiscard]] mp_int *get() noexcept {
        return &value_;
      }

      /** @brief Return immutable wolfCrypt integer. */
      [[nodiscard]] const mp_int *get() const noexcept {
        return &value_;
      }

    private:
      mp_int value_ {};  ///< wolfCrypt integer storage.
      bool ready_ {};  ///< Successful initialization flag.
    };

    /** @brief RAII owner for one wolfCrypt ECC point. */
    class PointOwner {
    public:
      /** @brief Allocate an empty point. */
      PointOwner() noexcept:
          point_ {wc_ecc_new_point()} {
      }

      PointOwner(const PointOwner &) = delete;
      PointOwner &operator=(const PointOwner &) = delete;

      /** @brief Clear coordinates and release the point. */
      ~PointOwner() {
        if (point_ != nullptr) {
          wc_ecc_forcezero_point(point_);
          wc_ecc_del_point(point_);
        }
      }

      /** @brief Return mutable point storage. */
      [[nodiscard]] ecc_point *get() noexcept {
        return point_;
      }

      /** @brief Return immutable point storage. */
      [[nodiscard]] const ecc_point *get() const noexcept {
        return point_;
      }

      /** @brief Return allocation status. */
      [[nodiscard]] bool ready() const noexcept {
        return point_ != nullptr;
      }

    private:
      ecc_point *point_ {};  ///< Allocated wolfCrypt point.
    };

    /** @brief RAII owner for one wolfCrypt random generator. */
    class RngOwner {
    public:
      /** @brief Initialize the operating-system-backed generator. */
      RngOwner() noexcept:
          ready_ {wc_InitRng(&rng_) == 0} {
      }

      RngOwner(const RngOwner &) = delete;
      RngOwner &operator=(const RngOwner &) = delete;

      /** @brief Clear and release generator state. */
      ~RngOwner() {
        if (ready_) {
          wc_FreeRng(&rng_);
        }
      }

      /** @brief Return initialization status. */
      [[nodiscard]] bool ready() const noexcept {
        return ready_;
      }

      /** @brief Return mutable wolfCrypt generator. */
      [[nodiscard]] WC_RNG *get() noexcept {
        return &rng_;
      }

    private:
      WC_RNG rng_ {};  ///< wolfCrypt generator state.
      bool ready_ {};  ///< Successful initialization flag.
    };

    /**
     * @brief Import and fully validate one exact uncompressed P-256 point.
     *
     * @param encoded Exact SEC1 point.
     * @param curve_index wolfCrypt P-256 index.
     * @param output Destination point.
     * @return True only for a non-infinity point in the prime-order group.
     */
    [[nodiscard]] bool import_point(
      const Spake2Point &encoded,
      const int curve_index,
      ecc_point *output
    ) noexcept {
      if (encoded[0] != 0x04U || output == nullptr) {
        return false;
      }
      ecc_key key {};
      if (wc_ecc_init(&key) != 0) {
        return false;
      }
      const auto result = wc_ecc_import_x963_ex2(
        encoded.data(),
        static_cast<word32>(encoded.size()),
        &key,
        ECC_SECP256R1,
        1
      );
      const auto valid = result == 0 && wc_ecc_check_key(&key) == 0 &&
                         wc_ecc_point_is_at_infinity(&key.pubkey) == 0 &&
                         wc_ecc_point_is_on_curve(&key.pubkey, curve_index) == MP_OKAY &&
                         wc_ecc_copy_point(&key.pubkey, output) == MP_OKAY;
      wc_ecc_free(&key);
      return valid;
    }

    /**
     * @brief Export one affine P-256 point in exact uncompressed SEC1 form.
     *
     * @param point Valid affine point.
     * @param output Exact wire output.
     * @return True when both coordinates serialize to 32 bytes.
     */
    [[nodiscard]] bool export_point(ecc_point *point, Spake2Point &output) noexcept {
      if (point == nullptr || wc_ecc_point_is_at_infinity(point) != 0) {
        return false;
      }
      output.fill(0);
      output[0] = 0x04;
      return mp_to_unsigned_bin_len(point->x, output.data() + 1, spake2_scalar_size) == MP_OKAY &&
             mp_to_unsigned_bin_len(point->y, output.data() + 1 + spake2_scalar_size, spake2_scalar_size) == MP_OKAY;
    }

    /** @brief Reviewed P-256 curve parameters and fixed SPAKE2 points. */
    class CurveContext {
    public:
      /** @brief Parse parameters and validate RFC 9382 M/N. */
      CurveContext() noexcept {
        curve_index_ = wc_ecc_get_curve_idx(ECC_SECP256R1);
        const auto *parameters = curve_index_ >= 0 ? wc_ecc_get_curve_params(curve_index_) : nullptr;
        ready_ = parameters != nullptr && prime_.ready() && curve_a_.ready() && order_.ready() &&
                 generator_.ready() && point_m_.ready() && point_n_.ready() && rng_.ready() &&
                 mp_read_radix(prime_.get(), parameters->prime, 16) == MP_OKAY &&
                 mp_read_radix(curve_a_.get(), parameters->Af, 16) == MP_OKAY &&
                 mp_read_radix(order_.get(), parameters->order, 16) == MP_OKAY &&
                 mp_montgomery_setup(prime_.get(), &montgomery_) == MP_OKAY &&
                 wc_ecc_get_generator(generator_.get(), curve_index_) == MP_OKAY &&
                 import_point(p256_point_m, curve_index_, point_m_.get()) &&
                 import_point(p256_point_n, curve_index_, point_n_.get());
      }

      CurveContext(const CurveContext &) = delete;
      CurveContext &operator=(const CurveContext &) = delete;

      /** @brief Return complete initialization status. */
      [[nodiscard]] bool ready() const noexcept {
        return ready_;
      }

      /** @brief Return P-256 curve index. */
      [[nodiscard]] int index() const noexcept {
        return curve_index_;
      }

      /** @brief Return field prime. */
      [[nodiscard]] mp_int *prime() noexcept {
        return prime_.get();
      }

      /** @brief Return curve parameter a. */
      [[nodiscard]] mp_int *curve_a() noexcept {
        return curve_a_.get();
      }

      /** @brief Return subgroup order. */
      [[nodiscard]] mp_int *order() noexcept {
        return order_.get();
      }

      /** @brief Return generator P. */
      [[nodiscard]] ecc_point *generator() noexcept {
        return generator_.get();
      }

      /** @brief Return fixed point M. */
      [[nodiscard]] ecc_point *point_m() noexcept {
        return point_m_.get();
      }

      /** @brief Return fixed point N. */
      [[nodiscard]] ecc_point *point_n() noexcept {
        return point_n_.get();
      }

      /** @brief Return hardened scalar-multiplication RNG. */
      [[nodiscard]] WC_RNG *rng() noexcept {
        return rng_.get();
      }

      /** @brief Return the field Montgomery reduction constant. */
      [[nodiscard]] mp_digit montgomery() const noexcept {
        return montgomery_;
      }

    private:
      MpOwner prime_;  ///< P-256 field prime.
      MpOwner curve_a_;  ///< P-256 curve parameter a.
      MpOwner order_;  ///< P-256 subgroup order.
      PointOwner generator_;  ///< P-256 generator P.
      PointOwner point_m_;  ///< RFC 9382 P-256 fixed point M.
      PointOwner point_n_;  ///< RFC 9382 P-256 fixed point N.
      RngOwner rng_;  ///< Hardened multiplication and scalar RNG.
      int curve_index_ {-1};  ///< wolfCrypt curve index.
      mp_digit montgomery_ {};  ///< Field Montgomery reduction constant.
      bool ready_ {};  ///< Complete parameter-validation status.
    };

    /**
     * @brief Convert one fixed scalar into wolfCrypt integer form.
     *
     * @param scalar Valid fixed-width scalar.
     * @param output Initialized integer output.
     * @return True when conversion succeeds.
     */
    [[nodiscard]] bool import_scalar(const Spake2Scalar &scalar, MpOwner &output) noexcept {
      return output.ready() && valid_scalar(scalar) &&
             mp_read_unsigned_bin(output.get(), scalar.data(), static_cast<int>(scalar.size())) == MP_OKAY;
    }

    /**
     * @brief Generate an exact uniformly rejection-sampled P-256 scalar.
     *
     * @param rng Initialized generator.
     * @param scalar Fixed-width output.
     * @return True when a valid scalar is found within the hard attempt bound.
     */
    [[nodiscard]] bool generate_scalar(WC_RNG *rng, Spake2Scalar &scalar) noexcept {
      if (rng == nullptr) {
        return false;
      }
      for (std::size_t attempt = 0; attempt < maximum_random_scalar_attempts; ++attempt) {
        if (wc_RNG_GenerateBlock(rng, scalar.data(), static_cast<word32>(scalar.size())) != 0) {
          secure_zero(scalar);
          return false;
        }
        if (valid_scalar(scalar)) {
          return true;
        }
      }
      secure_zero(scalar);
      return false;
    }

    /**
     * @brief Perform hardened scalar multiplication and map to affine form.
     *
     * @param curve Reviewed curve context.
     * @param scalar Valid private scalar.
     * @param input Valid group point.
     * @param output Destination point.
     * @param map Whether to map the result to affine form.
     * @return True for a valid non-infinity product.
     */
    [[nodiscard]] bool multiply_point(
      CurveContext &curve,
      const Spake2Scalar &scalar,
      ecc_point *input,
      ecc_point *output,
      const bool map
    ) noexcept {
      MpOwner scalar_integer;
      PointOwner input_copy;
      if (!curve.ready() || input == nullptr || output == nullptr || !input_copy.ready() ||
          !import_scalar(scalar, scalar_integer) || wc_ecc_copy_point(input, input_copy.get()) != MP_OKAY ||
          wc_ecc_mulmod_ex2(
            scalar_integer.get(),
            input_copy.get(),
            output,
            curve.curve_a(),
            curve.prime(),
            curve.order(),
            curve.rng(),
            map ? 1 : 0,
            nullptr
          ) != MP_OKAY) {
        return false;
      }
      return !map || (wc_ecc_point_is_at_infinity(output) == 0 &&
                      wc_ecc_point_is_on_curve(output, curve.index()) == MP_OKAY);
    }

    /**
     * @brief Add two affine P-256 points through the reviewed SP implementation.
     *
     * @param curve Reviewed curve context.
     * @param left First point.
     * @param right Second point.
     * @param output Destination point.
     * @return True for a valid non-infinity sum.
     */
    [[nodiscard]] bool add_points(
      CurveContext &curve,
      ecc_point *left,
      ecc_point *right,
      ecc_point *output
    ) noexcept {
      PointOwner left_copy;
      PointOwner right_copy;
      int infinity = 0;
      if (!curve.ready() || left == nullptr || right == nullptr || output == nullptr || !left_copy.ready() ||
          !right_copy.ready() || wc_ecc_copy_point(left, left_copy.get()) != MP_OKAY ||
          wc_ecc_copy_point(right, right_copy.get()) != MP_OKAY ||
          ecc_projective_add_point_safe(
            left_copy.get(),
            right_copy.get(),
            output,
            curve.curve_a(),
            curve.prime(),
            curve.montgomery(),
            &infinity
          ) != MP_OKAY ||
          infinity != 0 || ecc_map(output, curve.prime(), curve.montgomery()) != MP_OKAY) {
        return false;
      }
      return wc_ecc_point_is_at_infinity(output) == 0 &&
             wc_ecc_point_is_on_curve(output, curve.index()) == MP_OKAY;
    }

    /**
     * @brief Compute pA=xP+wM or pB=yP+wN.
     *
     * @param curve Reviewed curve context.
     * @param ephemeral x or y.
     * @param password_scalar w.
     * @param mask M for party A or N for party B.
     * @param output Encoded wire point.
     * @return True when every hardened group operation succeeds.
     */
    [[nodiscard]] bool derive_own_point(
      CurveContext &curve,
      const Spake2Scalar &ephemeral,
      const Spake2Scalar &password_scalar,
      ecc_point *mask,
      Spake2Point &output
    ) noexcept {
      PointOwner ephemeral_generator;
      PointOwner password_mask;
      PointOwner sum;
      return ephemeral_generator.ready() && password_mask.ready() && sum.ready() &&
             multiply_point(curve, ephemeral, curve.generator(), ephemeral_generator.get(), false) &&
             multiply_point(curve, password_scalar, mask, password_mask.get(), false) &&
             add_points(curve, ephemeral_generator.get(), password_mask.get(), sum.get()) &&
             export_point(sum.get(), output);
    }

    /**
     * @brief Compute x*(pB-wN) or y*(pA-wM) with cofactor one.
     *
     * @param curve Reviewed curve context.
     * @param peer_encoded Exact peer wire point.
     * @param ephemeral Local x or y.
     * @param password_scalar w.
     * @param mask N for A or M for B.
     * @param shared_encoded Encoded K output.
     * @return Invalid-point status for peer/group failures, otherwise exact crypto status.
     */
    [[nodiscard]] Spake2Status derive_shared_point(
      CurveContext &curve,
      const Spake2Point &peer_encoded,
      const Spake2Scalar &ephemeral,
      const Spake2Scalar &password_scalar,
      ecc_point *mask,
      Spake2Point &shared_encoded
    ) noexcept {
      PointOwner peer;
      PointOwner peer_projective;
      PointOwner negative_password_mask;
      PointOwner unmasked;
      PointOwner shared;
      Spake2Scalar negative_password_scalar;
      Spake2Scalar scalar_one {};
      scalar_one.back() = 1;
      std::uint16_t borrow = 0;
      if (!peer.ready() || !peer_projective.ready() || !negative_password_mask.ready() || !unmasked.ready() ||
          !shared.ready() ||
          !import_point(peer_encoded, curve.index(), peer.get())) {
        return Spake2Status::invalid_point;
      }
      for (std::size_t reverse_index = 0; reverse_index < p256_order.size(); ++reverse_index) {
        const auto index = p256_order.size() - 1 - reverse_index;
        const auto minuend = static_cast<std::uint16_t>(p256_order[index]);
        const auto subtrahend = static_cast<std::uint16_t>(password_scalar[index]) + borrow;
        negative_password_scalar[index] = static_cast<std::uint8_t>(minuend - subtrahend);
        borrow = static_cast<std::uint16_t>(minuend < subtrahend);
      }
      const auto success = borrow == 0 && valid_scalar(negative_password_scalar) &&
                           multiply_point(
                             curve,
                             negative_password_scalar,
                             mask,
                             negative_password_mask.get(),
                             false
                           ) &&
                           multiply_point(curve, scalar_one, peer.get(), peer_projective.get(), false) &&
                           add_points(curve, peer_projective.get(), negative_password_mask.get(), unmasked.get()) &&
                           multiply_point(curve, ephemeral, unmasked.get(), shared.get(), true) &&
                           export_point(shared.get(), shared_encoded);
      secure_zero(negative_password_scalar);
      return success ? Spake2Status::success : Spake2Status::invalid_point;
    }

    /**
     * @brief Append one LE64 length and byte string to TT.
     *
     * @param transcript Destination buffer.
     * @param offset In/out write offset.
     * @param value Byte string.
     * @return True when the bounded destination contains the complete field.
     */
    [[nodiscard]] bool append_transcript_field(
      std::array<std::uint8_t, transcript_capacity> &transcript,
      std::size_t &offset,
      const std::span<const std::uint8_t> value
    ) noexcept {
      constexpr std::size_t length_size = 8;
      if (value.size() > transcript.size() - offset || length_size > transcript.size() - offset - value.size()) {
        return false;
      }
      const auto value_size = static_cast<std::uint64_t>(value.size());
      for (std::size_t byte_index = 0; byte_index < length_size; ++byte_index) {
        transcript[offset++] = static_cast<std::uint8_t>(value_size >> (byte_index * 8U));
      }
      std::copy(value.begin(), value.end(), transcript.begin() + static_cast<std::ptrdiff_t>(offset));
      offset += value.size();
      return true;
    }

    /**
     * @brief Compute one full HMAC-SHA-256.
     *
     * @param key Confirmation key.
     * @param message Complete TT bytes.
     * @param output Full MAC output.
     * @return True when every wolfCrypt HMAC step succeeds.
     */
    [[nodiscard]] bool hmac_sha256(
      const std::span<const std::uint8_t> key,
      const std::span<const std::uint8_t> message,
      Spake2Confirmation &output
    ) noexcept {
      if (key.size() > std::numeric_limits<word32>::max() || message.size() > std::numeric_limits<word32>::max()) {
        return false;
      }
      Hmac hmac {};
      if (wc_HmacInit(&hmac, nullptr, INVALID_DEVID) != 0) {
        return false;
      }
      const auto success = wc_HmacSetKey(&hmac, WC_SHA256, key.data(), static_cast<word32>(key.size())) == 0 &&
                           wc_HmacUpdate(&hmac, message.data(), static_cast<word32>(message.size())) == 0 &&
                           wc_HmacFinal(&hmac, output.data()) == 0;
      wc_HmacFree(&hmac);
      return success;
    }

    /**
     * @brief Derive Ke, cA, and cB from exact TT and final AAD.
     *
     * @param identity_a Transcript identity A.
     * @param identity_b Transcript identity B.
     * @param point_a Exact pA.
     * @param point_b Exact pB.
     * @param shared_point Exact K.
     * @param password_scalar Fixed-width w.
     * @param aad Final challenge/exporter binding.
     * @param shared_key Derived Ke.
     * @param confirmation_a Derived cA.
     * @param confirmation_b Derived cB.
     * @return Exact derivation status.
     */
    [[nodiscard]] Spake2Status derive_keys(
      const std::span<const std::uint8_t> identity_a,
      const std::span<const std::uint8_t> identity_b,
      const Spake2Point &point_a,
      const Spake2Point &point_b,
      const Spake2Point &shared_point,
      const Spake2Scalar &password_scalar,
      const std::span<const std::uint8_t> aad,
      Spake2SharedKey &shared_key,
      Spake2Confirmation &confirmation_a,
      Spake2Confirmation &confirmation_b
    ) noexcept {
      if (aad.size() > spake2_maximum_aad_size) {
        return Spake2Status::invalid_argument;
      }
      std::array<std::uint8_t, transcript_capacity> transcript;
      std::array<std::uint8_t, WC_SHA256_DIGEST_SIZE> transcript_hash;
      std::array<std::uint8_t, spake2_shared_key_size> authentication_key;
      std::array<std::uint8_t, confirmation_key_material_size> confirmation_keys;
      std::array<std::uint8_t, confirmation_label_size + spake2_maximum_aad_size> hkdf_info;
      std::size_t transcript_size = 0;
      const auto transcript_ready = append_transcript_field(transcript, transcript_size, identity_a) &&
                                    append_transcript_field(transcript, transcript_size, identity_b) &&
                                    append_transcript_field(transcript, transcript_size, point_a) &&
                                    append_transcript_field(transcript, transcript_size, point_b) &&
                                    append_transcript_field(transcript, transcript_size, shared_point) &&
                                    append_transcript_field(transcript, transcript_size, password_scalar);
      if (!transcript_ready ||
          wc_Sha256Hash(
            transcript.data(),
            static_cast<word32>(transcript_size),
            transcript_hash.data()
          ) != 0) {
        secure_zero(transcript);
        return Spake2Status::crypto_failure;
      }
      std::copy_n(transcript_hash.begin(), shared_key.size(), shared_key.begin());
      std::copy_n(
        transcript_hash.begin() + static_cast<std::ptrdiff_t>(shared_key.size()),
        authentication_key.size(),
        authentication_key.begin()
      );
      std::copy(confirmation_label.begin(), confirmation_label.end(), hkdf_info.begin());
      std::copy(aad.begin(), aad.end(), hkdf_info.begin() + static_cast<std::ptrdiff_t>(confirmation_label.size()));
      const auto info_size = confirmation_label.size() + aad.size();
      const auto hkdf_ready = wc_HKDF(
                                WC_SHA256,
                                authentication_key.data(),
                                static_cast<word32>(authentication_key.size()),
                                nullptr,
                                0,
                                hkdf_info.data(),
                                static_cast<word32>(info_size),
                                confirmation_keys.data(),
                                static_cast<word32>(confirmation_keys.size())
                              ) == 0;
      const auto confirmations_ready = hkdf_ready &&
                                       hmac_sha256(
                                         std::span<const std::uint8_t> {
                                           confirmation_keys.data(),
                                           spake2_shared_key_size,
                                         },
                                         std::span<const std::uint8_t> {transcript.data(), transcript_size},
                                         confirmation_a
                                       ) &&
                                       hmac_sha256(
                                         std::span<const std::uint8_t> {
                                           confirmation_keys.data() + spake2_shared_key_size,
                                           spake2_shared_key_size,
                                         },
                                         std::span<const std::uint8_t> {transcript.data(), transcript_size},
                                         confirmation_b
                                       );
      secure_zero(transcript);
      secure_zero(transcript_hash);
      secure_zero(authentication_key);
      secure_zero(confirmation_keys);
      secure_zero(std::span<std::uint8_t> {hkdf_info.data(), info_size});
      if (!confirmations_ready) {
        secure_zero(shared_key);
        secure_zero(confirmation_a);
        secure_zero(confirmation_b);
        return Spake2Status::crypto_failure;
      }
      return Spake2Status::success;
    }

    /** @brief Fixed-size secret and identity state shared by both roles. */
    struct SessionData {
      std::array<std::uint8_t, spake2_maximum_identity_size> identity_a {};  ///< Copied identity A.
      std::array<std::uint8_t, spake2_maximum_identity_size> identity_b {};  ///< Copied identity B.
      std::size_t identity_a_size {};  ///< Active identity-A bytes.
      std::size_t identity_b_size {};  ///< Active identity-B bytes.
      Spake2Scalar password_scalar {};  ///< Secret w.
      Spake2Scalar ephemeral_scalar {};  ///< Secret x or y after generation.
      Spake2Point point_a {};  ///< Client wire point needed for TT.
      Spake2SharedKey shared_key {};  ///< Pending Ke.
      Spake2Confirmation local_confirmation {};  ///< Pending local cA or cB.
      Spake2Confirmation expected_confirmation {};  ///< Expected peer cB or cA.
      SessionState state {SessionState::ready};  ///< One-shot state.
      bool deterministic_ephemeral {};  ///< Whether vector scalar was injected.

      /** @brief Clear every secret and copied identity. */
      void clear() noexcept {
        secure_zero(identity_a);
        secure_zero(identity_b);
        secure_zero(password_scalar);
        secure_zero(ephemeral_scalar);
        secure_zero(point_a);
        secure_zero(shared_key);
        secure_zero(local_confirmation);
        secure_zero(expected_confirmation);
        identity_a_size = 0;
        identity_b_size = 0;
        deterministic_ephemeral = false;
        state = SessionState::terminal;
      }

      /** @brief Return active identity A. */
      [[nodiscard]] std::span<const std::uint8_t> active_identity_a() const noexcept {
        return {identity_a.data(), identity_a_size};
      }

      /** @brief Return active identity B. */
      [[nodiscard]] std::span<const std::uint8_t> active_identity_b() const noexcept {
        return {identity_b.data(), identity_b_size};
      }
    };

    /**
     * @brief Copy bounded identities into one fresh session.
     *
     * @param identity_a Candidate identity A.
     * @param identity_b Candidate identity B.
     * @param data Destination state.
     * @return Exact validation status.
     */
    [[nodiscard]] Spake2Status copy_identities(
      const std::span<const std::uint8_t> identity_a,
      const std::span<const std::uint8_t> identity_b,
      SessionData &data
    ) noexcept {
      if (identity_a.size() > data.identity_a.size() || identity_b.size() > data.identity_b.size()) {
        return Spake2Status::invalid_argument;
      }
      std::copy(identity_a.begin(), identity_a.end(), data.identity_a.begin());
      std::copy(identity_b.begin(), identity_b.end(), data.identity_b.begin());
      data.identity_a_size = identity_a.size();
      data.identity_b_size = identity_b.size();
      return Spake2Status::success;
    }

    /**
     * @brief Derive and reduce w from the exact PIN/scrypt profile.
     *
     * @param inputs Production inputs.
     * @param data Destination state.
     * @return Exact validation/derivation status.
     */
    [[nodiscard]] Spake2Status initialize_production_data(
      const Spake2Inputs &inputs,
      SessionData &data
    ) noexcept {
      if (!valid_pin(inputs.pin)) {
        return Spake2Status::invalid_pin;
      }
      if (inputs.salt.size() < spake2_minimum_salt_size || inputs.salt.size() > spake2_maximum_salt_size) {
        return Spake2Status::invalid_salt;
      }
      if (inputs.salt.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return Spake2Status::invalid_salt;
      }
      const auto identity_status = copy_identities(inputs.identity_a, inputs.identity_b, data);
      if (identity_status != Spake2Status::success) {
        return identity_status;
      }
      Spake2Scalar raw_password;
      const auto scrypt_result = wc_scrypt_ex(
        raw_password.data(),
        reinterpret_cast<const byte *>(inputs.pin.data()),
        static_cast<int>(inputs.pin.size()),
        inputs.salt.data(),
        static_cast<int>(inputs.salt.size()),
        32'768,
        8,
        1,
        static_cast<int>(raw_password.size())
      );
      const auto reduced = scrypt_result == 0 && reduce_password_scalar(raw_password, data.password_scalar);
      secure_zero(raw_password);
      if (!reduced) {
        data.clear();
        return scrypt_result == NOT_COMPILED_IN ? Spake2Status::unavailable : Spake2Status::crypto_failure;
      }
      return Spake2Status::success;
    }

  #ifdef LSP_SPAKE2_TESTING
    /**
     * @brief Install exact deterministic vector scalars.
     *
     * @param inputs Vector inputs.
     * @param data Destination state.
     * @return Exact scalar/identity status.
     */
    [[nodiscard]] Spake2Status initialize_test_data(
      const Spake2TestInputs &inputs,
      SessionData &data
    ) noexcept {
      const auto identity_status = copy_identities(inputs.identity_a, inputs.identity_b, data);
      if (identity_status != Spake2Status::success) {
        return identity_status;
      }
      if (!valid_scalar(inputs.w) || !valid_scalar(inputs.ephemeral_scalar)) {
        data.clear();
        return Spake2Status::invalid_scalar;
      }
      data.password_scalar = inputs.w;
      data.ephemeral_scalar = inputs.ephemeral_scalar;
      data.deterministic_ephemeral = true;
      return Spake2Status::success;
    }
  #endif
  }  // namespace

  class WolfsslSpake2ClientSession::Impl {
  public:
    /** @brief Clear client secrets on destruction. */
    ~Impl() {
      data.clear();
    }

    /** @brief Client secret and protocol state. */
    SessionData data;
  };

  class WolfsslSpake2HostSession::Impl {
  public:
    /** @brief Clear host secrets on destruction. */
    ~Impl() {
      data.clear();
    }

    /** @brief Host secret and protocol state. */
    SessionData data;
  };

  #ifdef LSP_SPAKE2_TESTING
  Spake2Status derive_spake2_password_scalar_for_test(
    const std::string_view pin,
    const std::span<const std::uint8_t> salt,
    Spake2Scalar &scalar
  ) noexcept {
    secure_zero(scalar);
    SessionData data;
    const auto status = initialize_production_data(Spake2Inputs {.pin = pin, .salt = salt}, data);
    if (status == Spake2Status::success) {
      scalar = data.password_scalar;
    }
    data.clear();
    return status;
  }
  #endif

  WolfsslSpake2ClientSession::WolfsslSpake2ClientSession(std::unique_ptr<Impl> implementation) noexcept:
      impl_ {std::move(implementation)} {
  }

  WolfsslSpake2ClientSession::~WolfsslSpake2ClientSession() = default;

  std::unique_ptr<WolfsslSpake2ClientSession> WolfsslSpake2ClientSession::create(
    const Spake2Inputs &inputs,
    Spake2Status &status
  ) noexcept {
    std::unique_ptr<Impl> implementation {new (std::nothrow) Impl};
    if (!implementation) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    status = initialize_production_data(inputs, implementation->data);
    if (status != Spake2Status::success) {
      return {};
    }
    std::unique_ptr<WolfsslSpake2ClientSession> session {
      new (std::nothrow) WolfsslSpake2ClientSession {std::move(implementation)},
    };
    if (!session) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    return session;
  }

  #ifdef LSP_SPAKE2_TESTING
  std::unique_ptr<WolfsslSpake2ClientSession> WolfsslSpake2ClientSession::create_for_test(
    const Spake2TestInputs &inputs,
    Spake2Status &status
  ) noexcept {
    std::unique_ptr<Impl> implementation {new (std::nothrow) Impl};
    if (!implementation) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    status = initialize_test_data(inputs, implementation->data);
    if (status != Spake2Status::success) {
      return {};
    }
    std::unique_ptr<WolfsslSpake2ClientSession> session {
      new (std::nothrow) WolfsslSpake2ClientSession {std::move(implementation)},
    };
    if (!session) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    return session;
  }
  #endif

  Spake2Status WolfsslSpake2ClientSession::start(Spake2Point &point_a) noexcept {
    secure_zero(point_a);
    if (!impl_ || impl_->data.state != SessionState::ready) {
      return Spake2Status::invalid_state;
    }
    CurveContext curve;
    if (!curve.ready()) {
      impl_->data.clear();
      return Spake2Status::unavailable;
    }
    if (!impl_->data.deterministic_ephemeral && !generate_scalar(curve.rng(), impl_->data.ephemeral_scalar)) {
      impl_->data.clear();
      return Spake2Status::crypto_failure;
    }
    if (!derive_own_point(
          curve,
          impl_->data.ephemeral_scalar,
          impl_->data.password_scalar,
          curve.point_m(),
          impl_->data.point_a
        )) {
      impl_->data.clear();
      return Spake2Status::crypto_failure;
    }
    point_a = impl_->data.point_a;
    impl_->data.state = SessionState::point_sent;
    return Spake2Status::success;
  }

  Spake2Status WolfsslSpake2ClientSession::receive_host_point(
    const Spake2Point &point_b,
    const std::span<const std::uint8_t> aad,
    Spake2Confirmation &confirmation_a
  ) noexcept {
    secure_zero(confirmation_a);
    if (!impl_ || impl_->data.state != SessionState::point_sent) {
      return Spake2Status::invalid_state;
    }
    CurveContext curve;
    Spake2Point shared_point;
    if (!curve.ready()) {
      impl_->data.clear();
      return Spake2Status::unavailable;
    }
    auto status = derive_shared_point(
      curve,
      point_b,
      impl_->data.ephemeral_scalar,
      impl_->data.password_scalar,
      curve.point_n(),
      shared_point
    );
    if (status == Spake2Status::success) {
      status = derive_keys(
        impl_->data.active_identity_a(),
        impl_->data.active_identity_b(),
        impl_->data.point_a,
        point_b,
        shared_point,
        impl_->data.password_scalar,
        aad,
        impl_->data.shared_key,
        impl_->data.local_confirmation,
        impl_->data.expected_confirmation
      );
    }
    secure_zero(shared_point);
    secure_zero(impl_->data.password_scalar);
    secure_zero(impl_->data.ephemeral_scalar);
    if (status != Spake2Status::success) {
      impl_->data.clear();
      return status;
    }
    confirmation_a = impl_->data.local_confirmation;
    impl_->data.state = SessionState::confirmation_pending;
    return Spake2Status::success;
  }

  Spake2Status WolfsslSpake2ClientSession::verify_host_confirmation(
    const Spake2Confirmation &confirmation_b,
    Spake2SharedKey &shared_key
  ) noexcept {
    secure_zero(shared_key);
    if (!impl_ || impl_->data.state != SessionState::confirmation_pending) {
      return Spake2Status::invalid_state;
    }
    if (!constant_equal(confirmation_b, impl_->data.expected_confirmation)) {
      impl_->data.clear();
      secure_zero(shared_key);
      return Spake2Status::confirmation_failed;
    }
    shared_key = impl_->data.shared_key;
    impl_->data.clear();
    return Spake2Status::success;
  }

  WolfsslSpake2HostSession::WolfsslSpake2HostSession(std::unique_ptr<Impl> implementation) noexcept:
      impl_ {std::move(implementation)} {
  }

  WolfsslSpake2HostSession::~WolfsslSpake2HostSession() = default;

  std::unique_ptr<WolfsslSpake2HostSession> WolfsslSpake2HostSession::create(
    const Spake2Inputs &inputs,
    Spake2Status &status
  ) noexcept {
    std::unique_ptr<Impl> implementation {new (std::nothrow) Impl};
    if (!implementation) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    status = initialize_production_data(inputs, implementation->data);
    if (status != Spake2Status::success) {
      return {};
    }
    std::unique_ptr<WolfsslSpake2HostSession> session {
      new (std::nothrow) WolfsslSpake2HostSession {std::move(implementation)},
    };
    if (!session) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    return session;
  }

  #ifdef LSP_SPAKE2_TESTING
  std::unique_ptr<WolfsslSpake2HostSession> WolfsslSpake2HostSession::create_for_test(
    const Spake2TestInputs &inputs,
    Spake2Status &status
  ) noexcept {
    std::unique_ptr<Impl> implementation {new (std::nothrow) Impl};
    if (!implementation) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    status = initialize_test_data(inputs, implementation->data);
    if (status != Spake2Status::success) {
      return {};
    }
    std::unique_ptr<WolfsslSpake2HostSession> session {
      new (std::nothrow) WolfsslSpake2HostSession {std::move(implementation)},
    };
    if (!session) {
      status = Spake2Status::crypto_failure;
      return {};
    }
    return session;
  }
  #endif

  Spake2Status WolfsslSpake2HostSession::receive_client_point(
    const Spake2Point &point_a,
    const std::span<const std::uint8_t> aad,
    Spake2Point &point_b
  ) noexcept {
    secure_zero(point_b);
    if (!impl_ || impl_->data.state != SessionState::ready) {
      return Spake2Status::invalid_state;
    }
    CurveContext curve;
    Spake2Point shared_point;
    if (!curve.ready()) {
      impl_->data.clear();
      return Spake2Status::unavailable;
    }
    if (!impl_->data.deterministic_ephemeral && !generate_scalar(curve.rng(), impl_->data.ephemeral_scalar)) {
      impl_->data.clear();
      return Spake2Status::crypto_failure;
    }
    if (!derive_own_point(
          curve,
          impl_->data.ephemeral_scalar,
          impl_->data.password_scalar,
          curve.point_n(),
          point_b
        )) {
      impl_->data.clear();
      return Spake2Status::crypto_failure;
    }
    auto status = derive_shared_point(
      curve,
      point_a,
      impl_->data.ephemeral_scalar,
      impl_->data.password_scalar,
      curve.point_m(),
      shared_point
    );
    if (status == Spake2Status::success) {
      status = derive_keys(
        impl_->data.active_identity_a(),
        impl_->data.active_identity_b(),
        point_a,
        point_b,
        shared_point,
        impl_->data.password_scalar,
        aad,
        impl_->data.shared_key,
        impl_->data.expected_confirmation,
        impl_->data.local_confirmation
      );
    }
    secure_zero(shared_point);
    secure_zero(impl_->data.password_scalar);
    secure_zero(impl_->data.ephemeral_scalar);
    if (status != Spake2Status::success) {
      impl_->data.clear();
      secure_zero(point_b);
      return status;
    }
    impl_->data.state = SessionState::confirmation_pending;
    return Spake2Status::success;
  }

  Spake2Status WolfsslSpake2HostSession::verify_client_confirmation(
    const Spake2Confirmation &confirmation_a,
    Spake2Confirmation &confirmation_b,
    Spake2SharedKey &shared_key
  ) noexcept {
    secure_zero(confirmation_b);
    secure_zero(shared_key);
    if (!impl_ || impl_->data.state != SessionState::confirmation_pending) {
      return Spake2Status::invalid_state;
    }
    if (!constant_equal(confirmation_a, impl_->data.expected_confirmation)) {
      impl_->data.clear();
      secure_zero(confirmation_b);
      secure_zero(shared_key);
      return Spake2Status::confirmation_failed;
    }
    confirmation_b = impl_->data.local_confirmation;
    shared_key = impl_->data.shared_key;
    impl_->data.clear();
    return Spake2Status::success;
  }
}  // namespace lumen::lsp

#else

namespace lumen::lsp {
  class WolfsslSpake2ClientSession::Impl {};

  class WolfsslSpake2HostSession::Impl {};

  WolfsslSpake2ClientSession::WolfsslSpake2ClientSession(std::unique_ptr<Impl> implementation) noexcept:
      impl_ {std::move(implementation)} {
  }

  WolfsslSpake2ClientSession::~WolfsslSpake2ClientSession() = default;

  std::unique_ptr<WolfsslSpake2ClientSession> WolfsslSpake2ClientSession::create(
    const Spake2Inputs &,
    Spake2Status &status
  ) noexcept {
    status = Spake2Status::unavailable;
    return {};
  }

  #ifdef LSP_SPAKE2_TESTING
  Spake2Status derive_spake2_password_scalar_for_test(
    std::string_view,
    std::span<const std::uint8_t>,
    Spake2Scalar &scalar
  ) noexcept {
    scalar.fill(0);
    return Spake2Status::unavailable;
  }

  std::unique_ptr<WolfsslSpake2ClientSession> WolfsslSpake2ClientSession::create_for_test(
    const Spake2TestInputs &,
    Spake2Status &status
  ) noexcept {
    status = Spake2Status::unavailable;
    return {};
  }
  #endif

  Spake2Status WolfsslSpake2ClientSession::start(Spake2Point &) noexcept {
    return Spake2Status::unavailable;
  }

  Spake2Status WolfsslSpake2ClientSession::receive_host_point(
    const Spake2Point &,
    std::span<const std::uint8_t>,
    Spake2Confirmation &
  ) noexcept {
    return Spake2Status::unavailable;
  }

  Spake2Status WolfsslSpake2ClientSession::verify_host_confirmation(
    const Spake2Confirmation &,
    Spake2SharedKey &
  ) noexcept {
    return Spake2Status::unavailable;
  }

  WolfsslSpake2HostSession::WolfsslSpake2HostSession(std::unique_ptr<Impl> implementation) noexcept:
      impl_ {std::move(implementation)} {
  }

  WolfsslSpake2HostSession::~WolfsslSpake2HostSession() = default;

  std::unique_ptr<WolfsslSpake2HostSession> WolfsslSpake2HostSession::create(
    const Spake2Inputs &,
    Spake2Status &status
  ) noexcept {
    status = Spake2Status::unavailable;
    return {};
  }

  #ifdef LSP_SPAKE2_TESTING
  std::unique_ptr<WolfsslSpake2HostSession> WolfsslSpake2HostSession::create_for_test(
    const Spake2TestInputs &,
    Spake2Status &status
  ) noexcept {
    status = Spake2Status::unavailable;
    return {};
  }
  #endif

  Spake2Status WolfsslSpake2HostSession::receive_client_point(
    const Spake2Point &,
    std::span<const std::uint8_t>,
    Spake2Point &
  ) noexcept {
    return Spake2Status::unavailable;
  }

  Spake2Status WolfsslSpake2HostSession::verify_client_confirmation(
    const Spake2Confirmation &,
    Spake2Confirmation &,
    Spake2SharedKey &
  ) noexcept {
    return Spake2Status::unavailable;
  }
}  // namespace lumen::lsp

#endif
