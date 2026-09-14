/**
 * @file tests/unit/test_lsp_input_rate_budget.cpp
 * @brief Regression coverage for constant-work host input-rate budget selection.
 */

#include "src/protocol_lsp/input_plane/rate.h"
#include "src/protocol_lsp/runtime/input_owner.h"

#include <cstdint>
#include <gtest/gtest.h>

namespace {
  namespace input = lumen::lsp::input_plane;
  namespace runtime = lumen::lsp::runtime;

  constexpr auto pointer_cost = input::wire_bits_per_second(
    input::ip_family::ipv4,
    input::pointer_payload_size,
    1
  );
  constexpr auto sensor_cost = input::wire_bits_per_second(input::ip_family::ipv4, 32, 1);
}  // namespace

TEST(LspInputRateBudget, ClampsSixteenKilohertzToOneKilohertz) {
  const auto result = runtime::clamp_input_rate_budget(
    pointer_cost * 16'000U,
    pointer_cost * 1'000U,
    pointer_cost,
    0,
    0,
    0,
    16'000,
    1'000,
    0,
    0
  );

  EXPECT_EQ(result.state_rate, 1'000U);
  EXPECT_EQ(result.sensor_rate, 0U);
  EXPECT_EQ(result.wire_bits, pointer_cost * 1'000U);
}

TEST(LspInputRateBudget, LeavesAnExactBudgetBoundaryUnchanged) {
  const auto aggregate = pointer_cost * 8'000U + sensor_cost * 250U;
  const auto result = runtime::clamp_input_rate_budget(
    aggregate,
    aggregate,
    pointer_cost,
    sensor_cost,
    0,
    0,
    8'000,
    1'000,
    250,
    125
  );

  EXPECT_EQ(result.state_rate, 8'000U);
  EXPECT_EQ(result.sensor_rate, 250U);
  EXPECT_EQ(result.wire_bits, aggregate);
}

TEST(LspInputRateBudget, UsesTheSelectedAddressFamilysCompleteWireCost) {
  const auto ipv6_cost = input::wire_bits_per_second(
    input::ip_family::ipv6,
    input::pointer_payload_size,
    1
  );
  ASSERT_GT(ipv6_cost, pointer_cost);
  const auto result = runtime::clamp_input_rate_budget(
    ipv6_cost * 16'000U,
    ipv6_cost * 1'000U,
    ipv6_cost,
    0,
    0,
    0,
    16'000,
    125,
    0,
    0
  );

  EXPECT_EQ(result.state_rate, 1'000U);
  EXPECT_EQ(result.wire_bits, ipv6_cost * 1'000U);
}

TEST(LspInputRateBudget, RoundsTheRequiredReductionUp) {
  const auto result = runtime::clamp_input_rate_budget(
    pointer_cost * 10U + 1U,
    pointer_cost * 8U,
    pointer_cost,
    0,
    0,
    0,
    10,
    1,
    0,
    0
  );

  EXPECT_EQ(result.state_rate, 7U);
  EXPECT_EQ(result.wire_bits, pointer_cost * 7U + 1U);
}

TEST(LspInputRateBudget, PreservesMinimumWhenTheBudgetCannotBeMet) {
  const auto result = runtime::clamp_input_rate_budget(
    pointer_cost * 16'000U,
    pointer_cost * 1'000U,
    pointer_cost,
    0,
    0,
    0,
    16'000,
    2'000,
    0,
    0
  );

  EXPECT_EQ(result.state_rate, 2'000U);
  EXPECT_GT(result.wire_bits, pointer_cost * 1'000U);
}

TEST(LspInputRateBudget, ReducesSensorsBeforeState) {
  const auto aggregate = pointer_cost * 1'000U + sensor_cost * 1'000U;
  const auto budget = pointer_cost * 1'000U + sensor_cost * 500U;
  const auto result = runtime::clamp_input_rate_budget(
    aggregate,
    budget,
    pointer_cost,
    sensor_cost,
    0,
    0,
    1'000,
    125,
    1'000,
    250
  );

  EXPECT_EQ(result.state_rate, 1'000U);
  EXPECT_EQ(result.sensor_rate, 500U);
  EXPECT_EQ(result.wire_bits, budget);
}

TEST(LspInputRateBudget, ExhaustsSensorHeadroomBeforeReducingState) {
  const auto aggregate = pointer_cost * 1'000U + sensor_cost * 1'000U;
  const auto budget = pointer_cost * 500U + sensor_cost * 250U;
  const auto result = runtime::clamp_input_rate_budget(
    aggregate,
    budget,
    pointer_cost,
    sensor_cost,
    0,
    0,
    1'000,
    125,
    1'000,
    250
  );

  EXPECT_EQ(result.sensor_rate, 250U);
  EXPECT_EQ(result.state_rate, 500U);
  EXPECT_EQ(result.wire_bits, budget);
}

TEST(LspInputRateBudget, LowersAZeroCostSensorBeforeClampingState) {
  const auto result = runtime::clamp_input_rate_budget(
    pointer_cost * 1'000U,
    pointer_cost * 500U,
    pointer_cost,
    0,
    0,
    0,
    1'000,
    125,
    1'000,
    250
  );

  EXPECT_EQ(result.sensor_rate, 250U);
  EXPECT_EQ(result.state_rate, 500U);
  EXPECT_EQ(result.wire_bits, pointer_cost * 500U);
}

TEST(LspInputRateBudget, PreservesExactSelectionAcrossSensorFallbackSaturation) {
  constexpr auto other_sensor_rate = 3'500U;
  constexpr auto maximum_sensor_rate = 1'000U;
  constexpr auto selected_sensor_rate = 250U;
  const auto aggregate = pointer_cost * 1'000U + sensor_cost * maximum_sensor_rate + sensor_cost * 4'000U;
  const auto budget = pointer_cost * 1'000U + sensor_cost * selected_sensor_rate +
                      sensor_cost * (other_sensor_rate + selected_sensor_rate);
  const auto result = runtime::clamp_input_rate_budget(
    aggregate,
    budget,
    pointer_cost,
    sensor_cost,
    sensor_cost,
    4'000U - other_sensor_rate,
    1'000,
    125,
    maximum_sensor_rate,
    125
  );

  EXPECT_EQ(result.state_rate, 1'000U);
  EXPECT_EQ(result.sensor_rate, selected_sensor_rate);
  EXPECT_EQ(result.wire_bits, budget);
}
