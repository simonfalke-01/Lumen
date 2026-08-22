/**
 * @file ring_tests.cpp
 * @brief Portable regression tests for the virtual-microphone PCM FIFO and ABI.
 */

#include "../LumenPcmRing.h"
#include "../../virtual_microphone_protocol.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>

/** Verify invalid initialization and operation arguments are rejected. */
static void TestInvalidArguments() {
  LUMEN_PCM_RING ring {};
  LUMEN_PCM_RING invalid_ring {};
  std::array<int16_t, 4> storage {};
  std::array<int16_t, 2> output {};

  assert(LumenPcmRingInitialize(nullptr, storage.data(), storage.size()) == 0);
  assert(LumenPcmRingInitialize(&ring, nullptr, storage.size()) == 0);
  assert(LumenPcmRingInitialize(&ring, storage.data(), 0u) == 0);
  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(nullptr, storage.data(), 1u) == 0u);
  assert(LumenPcmRingSubmit(&invalid_ring, storage.data(), 1u) == 0u);
  invalid_ring.storage = storage.data();
  assert(LumenPcmRingSubmit(&invalid_ring, storage.data(), 1u) == 0u);
  assert(LumenPcmRingSubmit(&ring, nullptr, 1u) == 0u);
  assert(LumenPcmRingSubmit(&ring, storage.data(), 0u) == 0u);
  invalid_ring = {};
  assert(LumenPcmRingRead(nullptr, output.data(), 1u) == 0u);
  assert(LumenPcmRingRead(&invalid_ring, output.data(), 1u) == 0u);
  invalid_ring.storage = storage.data();
  assert(LumenPcmRingRead(&invalid_ring, output.data(), 1u) == 0u);
  assert(LumenPcmRingRead(&ring, nullptr, 1u) == 0u);
  assert(LumenPcmRingRead(&ring, output.data(), 0u) == 0u);
  LumenPcmRingReset(nullptr);
  invalid_ring = {};
  LumenPcmRingReset(&invalid_ring);
  invalid_ring.storage = storage.data();
  LumenPcmRingReset(&invalid_ring);
  LumenPcmRingClear(nullptr);
  invalid_ring = {};
  LumenPcmRingClear(&invalid_ring);
  invalid_ring.storage = storage.data();
  LumenPcmRingClear(&invalid_ring);
}

/** Verify FIFO order across physical wraparound. */
static void TestWraparoundOrder() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 5> storage {};
  const std::array<int16_t, 4> first {1, 2, 3, 4};
  const std::array<int16_t, 3> second {5, 6, 7};
  std::array<int16_t, 2> prefix {};
  std::array<int16_t, 5> output {};

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(&ring, first.data(), first.size()) == first.size());
  assert(LumenPcmRingRead(&ring, prefix.data(), prefix.size()) == prefix.size());
  assert((prefix == std::array<int16_t, 2> {1, 2}));
  assert(LumenPcmRingSubmit(&ring, second.data(), second.size()) == second.size());
  assert(LumenPcmRingRead(&ring, output.data(), output.size()) == output.size());
  assert((output == std::array<int16_t, 5> {3, 4, 5, 6, 7}));
}

/** Verify reads always fill underflow with deterministic digital silence. */
static void TestUnderflowSilence() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 4> storage {};
  const std::array<int16_t, 2> input {11, -12};
  std::array<int16_t, 5> output {9, 9, 9, 9, 9};

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(&ring, input.data(), input.size()) == input.size());
  assert(LumenPcmRingRead(&ring, output.data(), output.size()) == input.size());
  assert((output == std::array<int16_t, 5> {11, -12, 0, 0, 0}));
  assert(ring.counters.consumed_frames == 2u);
  assert(ring.counters.silence_frames == 3u);
}

/** Verify overflow discards the oldest queued frames and keeps the newest. */
static void TestNewestDataWinsOverflow() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 4> storage {};
  const std::array<int16_t, 3> first {1, 2, 3};
  const std::array<int16_t, 3> second {4, 5, 6};
  std::array<int16_t, 4> output {};

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(&ring, first.data(), first.size()) == first.size());
  assert(LumenPcmRingSubmit(&ring, second.data(), second.size()) == second.size());
  assert(LumenPcmRingRead(&ring, output.data(), output.size()) == output.size());
  assert((output == std::array<int16_t, 4> {3, 4, 5, 6}));
  assert(ring.counters.dropped_frames == 2u);
}

/** Verify oversized submissions retain only their newest capacity frames. */
static void TestOversizedInput() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 4> storage {};
  const std::array<int16_t, 7> input {1, 2, 3, 4, 5, 6, 7};
  std::array<int16_t, 4> output {};

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(&ring, input.data(), input.size()) == storage.size());
  assert(LumenPcmRingRead(&ring, output.data(), output.size()) == output.size());
  assert((output == std::array<int16_t, 4> {4, 5, 6, 7}));
  assert(ring.counters.submitted_frames == 4u);
  assert(ring.counters.dropped_frames == 3u);
}

/** Verify reset empties audio while preserving and incrementing counters. */
static void TestResetAccounting() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 4> storage {};
  const std::array<int16_t, 2> input {1, 2};
  std::array<int16_t, 1> output {7};

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(&ring, input.data(), input.size()) == input.size());
  LumenPcmRingReset(&ring);
  assert(ring.queued_frames == 0u);
  assert(ring.counters.submitted_frames == 2u);
  assert(ring.counters.reset_count == 1u);
  assert(LumenPcmRingRead(&ring, output.data(), output.size()) == 0u);
  assert(output[0] == 0);
}

/** Verify opening a new stream can clear stale PCM without counting a reset. */
static void TestClearWithoutResetAccounting() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 4> storage {};
  const std::array<int16_t, 2> input {1, 2};

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  assert(LumenPcmRingSubmit(&ring, input.data(), input.size()) == input.size());
  LumenPcmRingClear(&ring);
  assert(ring.queued_frames == 0u);
  assert(ring.counters.submitted_frames == 2u);
  assert(ring.counters.reset_count == 0u);
}

/** Verify all lifetime counters saturate instead of wrapping to zero. */
static void TestSaturatingCounters() {
  LUMEN_PCM_RING ring {};
  std::array<int16_t, 2> storage {};
  const std::array<int16_t, 3> input {1, 2, 3};
  std::array<int16_t, 3> output {};
  constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();

  assert(LumenPcmRingInitialize(&ring, storage.data(), storage.size()) == 1);
  ring.counters.submitted_frames = maximum;
  ring.counters.consumed_frames = maximum;
  ring.counters.silence_frames = maximum;
  ring.counters.dropped_frames = maximum;
  ring.counters.reset_count = maximum;
  assert(LumenPcmRingSubmit(&ring, input.data(), input.size()) == storage.size());
  assert(LumenPcmRingRead(&ring, output.data(), output.size()) == storage.size());
  LumenPcmRingReset(&ring);
  assert(ring.counters.submitted_frames == maximum);
  assert(ring.counters.consumed_frames == maximum);
  assert(ring.counters.silence_frames == maximum);
  assert(ring.counters.dropped_frames == maximum);
  assert(ring.counters.reset_count == maximum);
}

/** Run all portable FIFO and ABI layout tests. */
int main() {
  TestInvalidArguments();
  TestWraparoundOrder();
  TestUnderflowSilence();
  TestNewestDataWinsOverflow();
  TestOversizedInput();
  TestResetAccounting();
  TestClearWithoutResetAccounting();
  TestSaturatingCounters();
  std::cout << "virtual microphone ring tests passed\n";
  return 0;
}
