/**
 * @file src/protocol_common/crypto.cpp
 * @brief OpenSSL-backed protocol cryptographic primitives.
 */

#include "crypto.h"

#include <memory>
#include <openssl/evp.h>

namespace lumen::protocol_common::crypto {
  namespace {
    using digest_context_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    using key_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

    key_ptr raw_private_key(const std::span<const std::uint8_t> bytes) noexcept {
      return {EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, bytes.data(), bytes.size()), EVP_PKEY_free};
    }

    key_ptr raw_public_key(const std::span<const std::uint8_t> bytes) noexcept {
      return {EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, bytes.data(), bytes.size()), EVP_PKEY_free};
    }
  }  // namespace

  std::optional<Digest> sha256(const std::span<const std::uint8_t> input) noexcept {
    Digest digest {};
    std::size_t digest_size = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, input.data(), input.size(), digest.data(), &digest_size) != 1 ||
        digest_size != digest.size()) {
      return std::nullopt;
    }
    return digest;
  }

  std::optional<PublicKey> ed25519_public_key(const std::span<const std::uint8_t> private_seed) noexcept {
    if (private_seed.size() != ed25519_private_seed_bytes) {
      return std::nullopt;
    }
    const auto key = raw_private_key(private_seed);
    if (!key) {
      return std::nullopt;
    }

    PublicKey output {};
    std::size_t output_size = output.size();
    if (EVP_PKEY_get_raw_public_key(key.get(), output.data(), &output_size) != 1 || output_size != output.size()) {
      return std::nullopt;
    }
    return output;
  }

  std::optional<Signature> ed25519_sign(
    const std::span<const std::uint8_t> private_seed,
    const std::span<const std::uint8_t> message
  ) noexcept {
    if (private_seed.size() != ed25519_private_seed_bytes) {
      return std::nullopt;
    }
    const auto key = raw_private_key(private_seed);
    digest_context_ptr context {EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!key || !context || EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
      return std::nullopt;
    }

    Signature signature {};
    std::size_t signature_size = signature.size();
    if (EVP_DigestSign(context.get(), signature.data(), &signature_size, message.data(), message.size()) != 1 ||
        signature_size != signature.size()) {
      return std::nullopt;
    }
    return signature;
  }

  bool ed25519_verify(
    const std::span<const std::uint8_t> public_key,
    const std::span<const std::uint8_t> message,
    const std::span<const std::uint8_t> signature
  ) noexcept {
    if (public_key.size() != ed25519_public_key_bytes || signature.size() != ed25519_signature_bytes) {
      return false;
    }
    const auto key = raw_public_key(public_key);
    digest_context_ptr context {EVP_MD_CTX_new(), EVP_MD_CTX_free};
    return key && context && EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
           EVP_DigestVerify(context.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
  }
}  // namespace lumen::protocol_common::crypto
