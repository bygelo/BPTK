// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// One monotonic guest clock (BPTK-039). Every guest time source derives from
// a single monotonic base so the guest cannot observe divergent clock: a
// busy-wait, a vertical-blank spin, and a frame counter all see the same
// elapsed time. Real-monotonic mode clamps the delta between successive
// service read so a stalled reader neither jumps ahead nor runs at double
// speed. Virtual-monotonic mode advances by a declared deterministic amount
// per read so the bounded probe stays reproducible.

import { performance } from "node:perf_hooks";

export const guestClockDefault = Object.freeze({
  qpc_frequency_hz: 10000000,
  tsc_frequency_hz: 1000000,
  tick_frequency_hz: 1000,
  vblank_frequency_hz: 60,
  max_delta_ms: 100,
  rdtsc_cycle_per_read: 1000,
});

// The declared clamp: a service read advances guest time by at most this
// many millisecond regardless of how long the host actually stalled.
export function clampDelta(deltaMs, maxDeltaMs) {
  if (!Number.isFinite(deltaMs) || deltaMs < 0) return 0;
  return Math.min(deltaMs, maxDeltaMs);
}

export function createGuestClock(option = {}) {
  const declared = { ...guestClockDefault, ...option };
  const mode = declared.mode === "virtual_monotonic" ? "virtual_monotonic" : "real_monotonic";
  const originMs = performance.now();
  let lastReadMs = originMs;
  let guestMs = 0;

  function observe() {
    if (mode === "real_monotonic") {
      const now = performance.now();
      guestMs += clampDelta(now - lastReadMs, declared.max_delta_ms);
      lastReadMs = now;
    }
    // Virtual-monotonic observation is side-effect free: virtual time only
    // advances through the declared RDTSC progression or an explicit advance.
  }

  return {
    mode,
    elapsedGuestMs() {
      return guestMs;
    },
    advanceVirtualMs(deltaMs) {
      if (mode !== "virtual_monotonic") {
        const error = new Error("advanceVirtualMs is only available in virtual_monotonic mode");
        error.code = "invalid_clock_mode";
        throw error;
      }
      guestMs += clampDelta(deltaMs, Number.MAX_SAFE_INTEGER);
    },
    // QueryPerformanceCounter: 64-bit counter at the declared frequency.
    qpc() {
      observe();
      return Math.floor(guestMs * declared.qpc_frequency_hz / 1000);
    },
    // RDTSC: 64-bit cycle counter at the declared TSC frequency. The read
    // itself consumes the declared cycle amount of guest time.
    rdtsc() {
      observe();
      if (mode === "virtual_monotonic") {
        guestMs += clampDelta(declared.rdtsc_cycle_per_read / declared.tsc_frequency_hz * 1000, declared.max_delta_ms);
      }
      return Math.floor(guestMs * declared.tsc_frequency_hz / 1000);
    },
    // GetTickCount and timeGetTime share the one-millisecond period and wrap
    // at 32 bit.
    tickCount() {
      observe();
      return Math.floor(guestMs) >>> 0;
    },
    timeGetTime() {
      return this.tickCount();
    },
    // Vertical-blank frame counter at the declared refresh frequency.
    vblankFrameCount() {
      observe();
      return Math.floor(guestMs * declared.vblank_frequency_hz / 1000);
    },
    describe() {
      return {
        source: "one_monotonic_clock",
        mode,
        qpc_frequency_hz: declared.qpc_frequency_hz,
        tsc_frequency_hz: declared.tsc_frequency_hz,
        tick_frequency_hz: declared.tick_frequency_hz,
        vblank_frequency_hz: declared.vblank_frequency_hz,
        max_delta_ms: declared.max_delta_ms,
        rdtsc_cycle_per_read: declared.rdtsc_cycle_per_read,
      };
    },
  };
}
