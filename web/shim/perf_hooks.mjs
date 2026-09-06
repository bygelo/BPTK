// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Browser shim for node:perf_hooks. lib/clock.mjs imports { performance } and
// calls performance.now(); the browser provides an identical high-resolution
// performance global, so re-export it verbatim.

export const performance = globalThis.performance;
export const PerformanceObserver = globalThis.PerformanceObserver;
export default { performance, PerformanceObserver };
