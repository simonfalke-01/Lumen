/**
 * @file tests/unit/test_input_config.cpp
 * @brief Test input configuration parsing.
 */
#include "../tests_common.h"

// local includes
#include <src/config.h>

// standard includes
#include <string_view>
#include <tuple>

using namespace std::literals;

/** @brief Parameterized coverage for the independent Windows gamepad backend selector. */
struct GamepadBackendConfigTest:
    BaseTest,
    testing::WithParamInterface<std::tuple<std::string_view, std::string_view>> {
  /** Restore global configuration mutated by apply_config_for_test(). */
  void TearDown() override {
    config::input = original_input;
    config::modified_config_settings = original_modified_config_settings;
    BaseTest::TearDown();
  }

  config::input_t original_input {config::input};  ///< Input configuration restored after each test.
  decltype(config::modified_config_settings) original_modified_config_settings {config::modified_config_settings};  ///< Modified settings restored after each test.
};

TEST_P(GamepadBackendConfigTest, AcceptsOnlyDeclaredBackends) {
  const auto &[setting, expected] = GetParam();
  config::input.gamepad_backend = "auto";

  config::apply_config_for_test(setting);

  EXPECT_EQ(expected, config::input.gamepad_backend);
}

INSTANTIATE_TEST_SUITE_P(
  GamepadBackendValues,
  GamepadBackendConfigTest,
  testing::Values(
    std::tuple {""sv, "auto"sv},
    std::tuple {"gamepad_backend = auto\n"sv, "auto"sv},
    std::tuple {"gamepad_backend = virtualhid\n"sv, "virtualhid"sv},
    std::tuple {"gamepad_backend = vigem\n"sv, "vigem"sv},
    std::tuple {"gamepad_backend = sendinput\n"sv, "auto"sv},
    std::tuple {"gamepad_backend = VirtualHid\n"sv, "auto"sv}
  )
);
