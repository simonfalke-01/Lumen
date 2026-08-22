/**
 * @file LumenPcmRing.c
 * @brief Portable bounded PCM FIFO implementation.
 */

#include "LumenPcmRing.h"

#include <limits.h>
#include <string.h>

/**
 * Saturating addition for lifetime counters.
 *
 * @param current Existing counter value.
 * @param increment Value to add.
 * @return Saturated sum.
 */
static uint64_t LumenPcmSaturatingAdd(uint64_t current, size_t increment) {
  const uint64_t converted = (uint64_t) increment;

  if (converted > UINT64_MAX - current) {
    return UINT64_MAX;
  }
  return current + converted;
}

int LumenPcmRingInitialize(LUMEN_PCM_RING *ring, int16_t *storage, size_t capacity_frames) {
  if (ring == NULL || storage == NULL || capacity_frames == 0u) {
    return 0;
  }

  memset(ring, 0, sizeof(*ring));
  ring->storage = storage;
  ring->capacity_frames = capacity_frames;
  return 1;
}

size_t LumenPcmRingSubmit(LUMEN_PCM_RING *ring, const int16_t *frames, size_t frame_count) {
  size_t input_offset = 0u;
  size_t retained_frames = frame_count;
  size_t free_frames;
  size_t dropped_frames = 0u;
  size_t write_index;
  size_t first_copy;

  if (ring == NULL || ring->storage == NULL || ring->capacity_frames == 0u || frames == NULL || frame_count == 0u) {
    return 0u;
  }

  if (retained_frames > ring->capacity_frames) {
    input_offset = retained_frames - ring->capacity_frames;
    dropped_frames = input_offset;
    retained_frames = ring->capacity_frames;
  }

  free_frames = ring->capacity_frames - ring->queued_frames;
  if (retained_frames > free_frames) {
    const size_t queued_to_drop = retained_frames - free_frames;
    ring->read_index = (ring->read_index + queued_to_drop) % ring->capacity_frames;
    ring->queued_frames -= queued_to_drop;
    dropped_frames += queued_to_drop;
  }

  write_index = (ring->read_index + ring->queued_frames) % ring->capacity_frames;
  first_copy = retained_frames;
  if (first_copy > ring->capacity_frames - write_index) {
    first_copy = ring->capacity_frames - write_index;
  }

  memcpy(&ring->storage[write_index], &frames[input_offset], first_copy * sizeof(frames[0]));
  if (first_copy < retained_frames) {
    memcpy(ring->storage, &frames[input_offset + first_copy], (retained_frames - first_copy) * sizeof(frames[0]));
  }

  ring->queued_frames += retained_frames;
  ring->counters.submitted_frames = LumenPcmSaturatingAdd(ring->counters.submitted_frames, retained_frames);
  ring->counters.dropped_frames = LumenPcmSaturatingAdd(ring->counters.dropped_frames, dropped_frames);
  return retained_frames;
}

size_t LumenPcmRingRead(LUMEN_PCM_RING *ring, int16_t *output, size_t frame_count) {
  size_t available_frames;
  size_t first_copy;

  if (ring == NULL || ring->storage == NULL || ring->capacity_frames == 0u || output == NULL || frame_count == 0u) {
    return 0u;
  }

  available_frames = frame_count;
  if (available_frames > ring->queued_frames) {
    available_frames = ring->queued_frames;
  }
  first_copy = available_frames;
  if (first_copy > ring->capacity_frames - ring->read_index) {
    first_copy = ring->capacity_frames - ring->read_index;
  }

  memcpy(output, &ring->storage[ring->read_index], first_copy * sizeof(output[0]));
  if (first_copy < available_frames) {
    memcpy(&output[first_copy], ring->storage, (available_frames - first_copy) * sizeof(output[0]));
  }
  if (available_frames < frame_count) {
    memset(&output[available_frames], 0, (frame_count - available_frames) * sizeof(output[0]));
  }

  ring->read_index = (ring->read_index + available_frames) % ring->capacity_frames;
  ring->queued_frames -= available_frames;
  ring->counters.consumed_frames = LumenPcmSaturatingAdd(ring->counters.consumed_frames, available_frames);
  ring->counters.silence_frames = LumenPcmSaturatingAdd(ring->counters.silence_frames, frame_count - available_frames);
  return available_frames;
}

void LumenPcmRingReset(LUMEN_PCM_RING *ring) {
  if (ring == NULL || ring->storage == NULL || ring->capacity_frames == 0u) {
    return;
  }

  LumenPcmRingClear(ring);
  ring->counters.reset_count = LumenPcmSaturatingAdd(ring->counters.reset_count, 1u);
}

void LumenPcmRingClear(LUMEN_PCM_RING *ring) {
  if (ring == NULL || ring->storage == NULL || ring->capacity_frames == 0u) {
    return;
  }

  ring->read_index = 0u;
  ring->queued_frames = 0u;
}
