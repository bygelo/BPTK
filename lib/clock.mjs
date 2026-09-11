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

// ---- frame pacing / vblank scheduler (BPTK-104) ---------------------------
// A deterministic present pacer over the one monotonic guest clock. A frame
// ready at guest time T presents on the next vertical-blank boundary at or
// after T; the pacer counts presented and dropped frames so a stall that
// misses one or more vblanks is reported rather than silently absorbed. Pure
// arithmetic over the declared refresh rate — no host display, no wall clock.
export function createFramePacer(option = {}) {
  const refreshHz = Number.isFinite(option.refresh_hz) && option.refresh_hz > 0
    ? option.refresh_hz
    : guestClockDefault.vblank_frequency_hz;
  const intervalMs = 1000 / refreshHz;
  let lastVblankIndex = null;
  let presentedCount = 0;
  let droppedCount = 0;

  // The guest time of the vblank a frame ready at nowMs syncs to: the next
  // boundary at or after now.
  function deadlineMs(nowMs) {
    const index = Math.ceil((Number.isFinite(nowMs) && nowMs > 0 ? nowMs : 0) / intervalMs - 1e-9);
    return index * intervalMs;
  }

  return {
    refresh_hz: refreshHz,
    interval_ms: intervalMs,
    deadlineMs,
    // Present the frame ready at nowMs. Returns the synced vblank, its index,
    // and how many vblanks were skipped since the previous present.
    present(nowMs) {
      const vblankTime = deadlineMs(nowMs);
      const vblankIndex = Math.round(vblankTime / intervalMs);
      const dropped = lastVblankIndex === null ? 0 : Math.max(vblankIndex - lastVblankIndex - 1, 0);
      lastVblankIndex = vblankIndex;
      const frameIndex = presentedCount;
      presentedCount += 1;
      droppedCount += dropped;
      return { frame_index: frameIndex, vblank_index: vblankIndex, present_time_ms: vblankTime, dropped, is_on_cadence: dropped === 0 };
    },
    presentFromClock(clock) {
      return this.present(clock.elapsedGuestMs());
    },
    stats() {
      return { presented_count: presentedCount, dropped_count: droppedCount, refresh_hz: refreshHz, interval_ms: intervalMs };
    },
  };
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
    tickCount64() {
      observe();
      return Math.floor(guestMs);
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
