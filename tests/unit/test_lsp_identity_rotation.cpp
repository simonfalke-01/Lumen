/**
 * @file tests/unit/test_lsp_identity_rotation.cpp
 * @brief Focused generation and atomic persistence coverage for LSP certificate rotation.
 */

#include "src/protocol_lsp/runtime/identity.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <ranges>
#include <type_traits>

TEST(LspIdentityRotation, IdentityIsMoveOnlyAndWipesMovedFromSecrets) {
  namespace runtime = lumen::lsp::runtime;
  static_assert(!std::is_copy_constructible_v<runtime::HostIdentity>);
  static_assert(!std::is_copy_assignable_v<runtime::HostIdentity>);
  static_assert(std::is_nothrow_move_constructible_v<runtime::HostIdentity>);
  static_assert(std::is_nothrow_move_assignable_v<runtime::HostIdentity>);

  runtime::HostIdentity source;
  source.host_id.fill(1);
  source.application_public_key.fill(2);
  source.application_private_key.fill(3);
  source.cookie_secret.fill(4);
  source.certificate_der = {5, 6, 7};
  source.private_key_der = {8, 9, 10};

  runtime::HostIdentity destination {std::move(source)};
  EXPECT_TRUE(lumen::lsp::is_zero(source.host_id));
  EXPECT_TRUE(lumen::lsp::is_zero(source.application_public_key));
  EXPECT_TRUE(lumen::lsp::is_zero(source.application_private_key));
  EXPECT_TRUE(lumen::lsp::is_zero(source.cookie_secret));
  EXPECT_TRUE(std::ranges::all_of(source.private_key_der, [](const std::uint8_t byte) {
    return byte == 0;
  }));
  EXPECT_EQ(destination.application_private_key.front(), 3U);
  EXPECT_EQ(destination.cookie_secret.front(), 4U);
  EXPECT_EQ(destination.private_key_der, (std::vector<std::uint8_t> {8, 9, 10}));
}

TEST(LspIdentityRotation, PreservesApplicationIdentityAndAtomicallyPersistsFreshDtlsCredentials) {
  namespace runtime = lumen::lsp::runtime;
  const auto current = runtime::generate_identity();
  if (!current && current.error() == runtime::IdentityError::provider_unavailable) {
    GTEST_SKIP() << "wolfSSL identity generation is disabled in this unit-test configuration";
  }
  ASSERT_TRUE(current);
  const auto rotated = runtime::generate_rotated_identity(*current);
  ASSERT_TRUE(rotated);
  EXPECT_EQ(rotated->host_id, current->host_id);
  EXPECT_EQ(rotated->application_public_key, current->application_public_key);
  EXPECT_EQ(rotated->application_private_key, current->application_private_key);
  EXPECT_EQ(rotated->cookie_secret, current->cookie_secret);
  EXPECT_NE(rotated->certificate_der, current->certificate_der);
  EXPECT_NE(rotated->private_key_der, current->private_key_der);

  const auto suffix = std::chrono::steady_clock::now().time_since_epoch().count();
  const auto directory = std::filesystem::temp_directory_path() /
                         ("lumen-lsp-identity-rotation-" + std::to_string(suffix));
  const auto path = directory / "lsp_identity_v1.bin";
  ASSERT_TRUE(runtime::persist_identity_atomic(path, *current));
  ASSERT_TRUE(runtime::persist_identity_atomic(path, *rotated));
  const auto loaded = runtime::load_or_create_identity(path);
  ASSERT_TRUE(loaded);
  EXPECT_EQ(loaded->certificate_der, rotated->certificate_der);
  EXPECT_EQ(loaded->private_key_der, rotated->private_key_der);
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  EXPECT_FALSE(error);
}
