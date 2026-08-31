/**
 * @file tests/unit/test_lsp_config.cpp
 * @brief Focused tests for LSP product configuration and retired-key handling.
 */

#include "../tests_common.h"

#include <src/config.h>

#include <cstdint>
#include <string>

namespace {
#if LUMEN_LSP_DEFAULT_ENABLED
  constexpr bool expected_default_enabled = true;  ///< Full-Windows build default.
#else
  constexpr bool expected_default_enabled = false;  ///< Legacy or unsupported-host build default.
#endif

  /**
   * @brief Restore global configuration state after each parser test.
   */
  class LspConfigTest: public BaseTest {
  protected:
    /**
     * @brief Save shared configuration before the test mutates it.
     */
    void SetUp() override {
      BaseTest::SetUp();
      original_lsp_ = config::lsp;
      original_modified_settings_ = config::modified_config_settings;
      reset_defaults();
      config::modified_config_settings.clear();
    }

    /**
     * @brief Restore shared configuration for subsequent tests.
     */
    void TearDown() override {
      config::lsp = original_lsp_;
      config::modified_config_settings = original_modified_settings_;
      BaseTest::TearDown();
    }

    /**
     * @brief Reset the LSP product settings to their compile-profile defaults.
     */
    static void reset_defaults() {
      config::lsp = {
        .enabled = expected_default_enabled,
        .port = 48'030,
        .profile = "adaptive-low-latency",
        .competition_capacity_mbps = 0,
        .pairing_permissions = 0x57U,
      };
    }

    config::lsp_t original_lsp_ {};  ///< LSP settings restored after each test.
    decltype(config::modified_config_settings) original_modified_settings_;  ///< Modified-setting map restored after each test.
  };
}  // namespace

TEST_F(LspConfigTest, UsesSafeCompileProfileDefaults) {
  EXPECT_EQ(config::lsp.enabled, expected_default_enabled);
  EXPECT_EQ(config::lsp.port, 48'030);
  EXPECT_EQ(config::lsp.profile, "adaptive-low-latency");
  EXPECT_EQ(config::lsp.competition_capacity_mbps, 0U);
  EXPECT_EQ(config::lsp.pairing_permissions, 0x57U);
}

TEST_F(LspConfigTest, ParsesEverySupportedLspSetting) {
  config::apply_config_for_test(
    "lsp_enabled = enabled\n"
    "lsp_port = 50000\n"
    "lsp_profile = competition\n"
    "lsp_competition_capacity_mbps = 2500\n"
    "lsp_pairing_permissions = 127\n"
  );

#if LUMEN_LSP_DEFAULT_ENABLED
  EXPECT_TRUE(config::lsp.enabled);
#else
  EXPECT_FALSE(config::lsp.enabled);
#endif
  EXPECT_EQ(config::lsp.port, 50'000);
  EXPECT_EQ(config::lsp.profile, "competition");
  EXPECT_EQ(config::lsp.competition_capacity_mbps, 2'500U);
  EXPECT_EQ(config::lsp.pairing_permissions, 0x7fU);
}

TEST_F(LspConfigTest, RejectsOutOfRangeAndUnknownValuesWithoutChangingSafeDefaults) {
  config::apply_config_for_test(
    "lsp_port = 0\n"
    "lsp_profile = fastest\n"
    "lsp_competition_capacity_mbps = -1\n"
    "lsp_pairing_permissions = 128\n"
  );

  EXPECT_EQ(config::lsp.port, 48'030);
  EXPECT_EQ(config::lsp.profile, "adaptive-low-latency");
  EXPECT_EQ(config::lsp.competition_capacity_mbps, 0U);
  EXPECT_EQ(config::lsp.pairing_permissions, 0x57U);
}

TEST_F(LspConfigTest, ReportsAndDropsRetiredKeysWithoutReinterpretingThemAsLsp) {
  config::apply_config_for_test(
    "protocol_v3_enabled = enabled\n"
    "protocol_v3_port = 49000\n"
    "legacy_compatibility = disabled\n"
  );

  EXPECT_FALSE(config::modified_config_settings.contains("protocol_v3_enabled"));
  EXPECT_FALSE(config::modified_config_settings.contains("protocol_v3_port"));
  EXPECT_FALSE(config::modified_config_settings.contains("legacy_compatibility"));
  EXPECT_EQ(config::lsp.port, 48'030);
  EXPECT_EQ(config::lsp.profile, "adaptive-low-latency");
  EXPECT_EQ(config::lsp.pairing_permissions, 0x57U);
}
