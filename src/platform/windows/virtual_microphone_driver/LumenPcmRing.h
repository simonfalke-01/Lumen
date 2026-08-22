/**
 * @file LumenPcmRing.h
 * @brief Portable bounded FIFO for mono signed 16-bit PCM frames.
 */

#ifndef LUMEN_PCM_RING_H
#define LUMEN_PCM_RING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Lifetime counters maintained by the PCM FIFO. */
typedef struct LUMEN_PCM_RING_COUNTERS {
  uint64_t submitted_frames;  ///< Frames retained from successful submissions.
  uint64_t consumed_frames;  ///< Queued frames returned to a consumer.
  uint64_t silence_frames;  ///< Zero frames synthesized on underflow.
  uint64_t dropped_frames;  ///< Oldest queued or oversized-input frames discarded.
  uint64_t reset_count;  ///< Number of FIFO resets.
} LUMEN_PCM_RING_COUNTERS;

/** Caller-owned FIFO state. All operations require external serialization. */
typedef struct LUMEN_PCM_RING {
  int16_t *storage;  ///< Caller-owned sample storage.
  size_t capacity_frames;  ///< Number of frames storage can retain.
  size_t read_index;  ///< Index of the oldest queued frame.
  size_t queued_frames;  ///< Number of queued frames.
  LUMEN_PCM_RING_COUNTERS counters;  ///< Saturating lifetime counters.
} LUMEN_PCM_RING;

/**
 * Initialize an empty PCM FIFO over caller-owned storage.
 *
 * @param ring State to initialize.
 * @param storage Storage for capacity_frames signed 16-bit mono samples.
 * @param capacity_frames Non-zero number of frames in storage.
 * @return 1 on success or 0 for invalid arguments.
 */
int LumenPcmRingInitialize(LUMEN_PCM_RING *ring, int16_t *storage, size_t capacity_frames);

/**
 * Append PCM while deterministically retaining the newest capacity frames.
 *
 * If insufficient space exists, the oldest queued frames are discarded. If
 * frame_count itself exceeds capacity, only the newest capacity input frames
 * are retained. Counters saturate instead of wrapping.
 *
 * @param ring Initialized FIFO.
 * @param frames Input signed 16-bit mono frames.
 * @param frame_count Number of input frames.
 * @return Number of input frames retained, or zero for invalid arguments.
 */
size_t LumenPcmRingSubmit(LUMEN_PCM_RING *ring, const int16_t *frames, size_t frame_count);

/**
 * Read exactly frame_count frames, filling any underflow with digital silence.
 *
 * @param ring Initialized FIFO.
 * @param output Destination for frame_count signed 16-bit mono frames.
 * @param frame_count Number of frames requested by the consumer.
 * @return Number of queued PCM frames copied before silence padding.
 */
size_t LumenPcmRingRead(LUMEN_PCM_RING *ring, int16_t *output, size_t frame_count);

/**
 * Empty queued audio while preserving lifetime counters.
 *
 * @param ring Initialized FIFO.
 */
void LumenPcmRingReset(LUMEN_PCM_RING *ring);

/**
 * Empty queued audio without changing lifetime counters.
 *
 * This is used when a newly opened stream must not inherit stale PCM.
 *
 * @param ring Initialized FIFO.
 */
void LumenPcmRingClear(LUMEN_PCM_RING *ring);

#ifdef __cplusplus
}
#endif

#endif /* LUMEN_PCM_RING_H */
