/**
 * @file LumenPcmRing.c
 * @brief Portable bounded PCM FIFO implementation.
 */

#include "LumenPcmRing.h"

#if defined(LUMEN_VMIC_KERNEL)
  #define LUMEN_PCM_UINT64_MAX MAXUINT64
  #define LumenPcmCopy(destination, source, bytes) RtlCopyMemory((destination), (source), (bytes))
  #define LumenPcmZero(destination, bytes) RtlZeroMemory((destination), (bytes))
#else
  #include <stdint.h>
  #include <string.h>
  #define LUMEN_PCM_UINT64_MAX UINT64_MAX
  #define LumenPcmCopy(destination, source, bytes) memcpy((destination), (source), (bytes))
  #define LumenPcmZero(destination, bytes) memset((destination), 0, (bytes))
#endif

/**
 * Saturating addition for lifetime counters.
 *
 * @param current Existing counter value.
 * @param increment Value to add.
 * @return Saturated sum.
 */
static lumen_pcm_uint64_t LumenPcmSaturatingAdd(lumen_pcm_uint64_t current, lumen_pcm_size_t increment) {
  const lumen_pcm_uint64_t converted = (lumen_pcm_uint64_t) increment;

  if (converted > LUMEN_PCM_UINT64_MAX - current) {
    return LUMEN_PCM_UINT64_MAX;
  }
  return current + converted;
}

int LumenPcmRingInitialize(LUMEN_PCM_RING *ring, lumen_pcm_int16_t *storage, lumen_pcm_size_t capacity_frames) {
  if (ring == NULL || storage == NULL || capacity_frames == 0u) {
    return 0;
  }

  LumenPcmZero(ring, sizeof(*ring));
  ring->storage = storage;
  ring->capacity_frames = capacity_frames;
  return 1;
}

lumen_pcm_size_t LumenPcmRingSubmit(
  LUMEN_PCM_RING *ring,
  const lumen_pcm_int16_t *frames,
  lumen_pcm_size_t frame_count
) {
  lumen_pcm_size_t input_offset = 0u;
  lumen_pcm_size_t retained_frames = frame_count;
  lumen_pcm_size_t free_frames;
  lumen_pcm_size_t dropped_frames = 0u;
  lumen_pcm_size_t write_index;
  lumen_pcm_size_t first_copy;

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
    const lumen_pcm_size_t queued_to_drop = retained_frames - free_frames;
    ring->read_index = (ring->read_index + queued_to_drop) % ring->capacity_frames;
    ring->queued_frames -= queued_to_drop;
    dropped_frames += queued_to_drop;
  }

  write_index = (ring->read_index + ring->queued_frames) % ring->capacity_frames;
  first_copy = retained_frames;
  if (first_copy > ring->capacity_frames - write_index) {
    first_copy = ring->capacity_frames - write_index;
  }

  LumenPcmCopy(&ring->storage[write_index], &frames[input_offset], first_copy * sizeof(frames[0]));
  if (first_copy < retained_frames) {
    LumenPcmCopy(
      ring->storage,
      &frames[input_offset + first_copy],
      (retained_frames - first_copy) * sizeof(frames[0])
    );
  }

  ring->queued_frames += retained_frames;
  ring->counters.submitted_frames = LumenPcmSaturatingAdd(ring->counters.submitted_frames, retained_frames);
  ring->counters.dropped_frames = LumenPcmSaturatingAdd(ring->counters.dropped_frames, dropped_frames);
  return retained_frames;
}

lumen_pcm_size_t LumenPcmRingRead(
  LUMEN_PCM_RING *ring,
  lumen_pcm_int16_t *output,
  lumen_pcm_size_t frame_count
) {
  lumen_pcm_size_t available_frames;
  lumen_pcm_size_t first_copy;

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

  LumenPcmCopy(output, &ring->storage[ring->read_index], first_copy * sizeof(output[0]));
  if (first_copy < available_frames) {
    LumenPcmCopy(&output[first_copy], ring->storage, (available_frames - first_copy) * sizeof(output[0]));
  }
  if (available_frames < frame_count) {
    LumenPcmZero(&output[available_frames], (frame_count - available_frames) * sizeof(output[0]));
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
