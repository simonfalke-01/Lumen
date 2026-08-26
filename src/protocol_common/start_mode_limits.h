/**
 * @file src/protocol_common/start_mode_limits.h
 * @brief Language-neutral numeric bounds shared by START admission and VDD.
 */
#ifndef LUMEN_PROTOCOL_COMMON_START_MODE_LIMITS_H
#define LUMEN_PROTOCOL_COMMON_START_MODE_LIMITS_H

#include <stdint.h>

/** Smallest client-visible even width. */
#define LUMEN_START_MODE_MIN_WIDTH 320u
/** Largest client-visible even width. */
#define LUMEN_START_MODE_MAX_WIDTH 7680u
/** Smallest client-visible even height. */
#define LUMEN_START_MODE_MIN_HEIGHT 200u
/** Largest client-visible even height. */
#define LUMEN_START_MODE_MAX_HEIGHT 4320u
/** Smallest exact refresh rate in hertz. */
#define LUMEN_START_MODE_MIN_REFRESH_HZ 10u
/** Largest exact refresh rate in hertz. */
#define LUMEN_START_MODE_MAX_REFRESH_HZ 480u
/** Largest exact rational component accepted by the uint32 wire contract. */
#define LUMEN_START_MODE_MAX_RATIONAL_COMPONENT UINT32_MAX

#endif  // LUMEN_PROTOCOL_COMMON_START_MODE_LIMITS_H
