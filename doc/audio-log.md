# Audio subsystem log (BPTK-014)

Legacy audio → WebAudio. New logic lives in `lib/audio.mjs`; `lib/hle.mjs` is
touched only to register exports once the guest export surface is wired.

## Honesty state

`implemented` here means real code plus an **active red** acceptance contract.
The portable DSP and state-machine core is exercised by a **green** node suite
(`test/audio.test.mjs`); the live half — a real `AudioWorklet`, the autoplay
gesture, and browser suspension — is **not** exercised in node, so the roadmap
benchmark **BENCH-014 stays `red` / `gate: excluded`** until FIX-007 renders
verified output after gesture activation. No binary stage moves this cycle: a
real `.exe` will not advance its stage until the thread → seh → cpu → user/gdi
block lands, exactly as the lane plan anticipates. `bptk corpus run` is
unavailable in this worktree (the DRM-free corpus stage is not mounted here);
coverage is measured by the acceptance suite below.

## Acceptance (offline, green)

| Property | How it is proven | State |
| --- | --- | --- |
| PCM decode (8/16-bit int, 32-bit float) | normalized to [-1, 1], unsupported tag refused by name | green |
| Constant-power pan + decibel volume/pan law | law checked at center/hard-left, −6 dB ≈ 0.501, floor = silence | green |
| Golden offline mix within tolerance | mixed block vs an independently computed pan/volume oracle, max error < 2e-4 | green |
| Resampling | half-rate source vs a linear-interpolation oracle, max error < 1e-5 | green |
| Zero underrun over a sustained run | 4000-block producer/consumer SAB ring run, `underrun_count === 0`; a starved read is still counted | green |
| A/V clock from one monotonic source | `createAudioClock` render position === guest clock elapsed, both derive from `lib/clock.mjs` | green |
| waveOut open/write/reset/callback | WOM_OPEN → WOM_DONE on drain, reset returns the queue early, WOM_CLOSE | green |
| DirectSound loop/volume/pan/position | looping buffer plays past its length, decibel gain applied, play cursor reported | green |
| DirectSound notification position | callback fires as the play cursor crosses the declared offset | green |
| DirectSound pause/resume | pause holds the cursor detached from the mix, resume continues from it | green |

## Live contract (red)

BENCH-014 (`bench/roadmap/spec/bptk-014.json`) remains `red` / `excluded`:
> The PCM fixture produces no verified WebAudio output.

Promotion trigger (unchanged): FIX-007 produces the expected audio hash,
callback trace, loop, volume, pan, and synchronization result after gesture
activation.

## Design notes

- **One mixer, many APIs.** waveOut, DirectSound, and (next slice) an XAudio2
  voice subset all lower a playing sound into one `mixSource`; a single
  deterministic summing pass renders interleaved stereo. Every gain resolves to
  an explicit left/right linear multiplier so the mixer stays one code path.
- **Thread seam.** Guest callbacks post through an injected
  `dispatch(callback, message, param)` — the seam onto the thread subsystem
  (BPTK-010) so a callback lands on the correct guest thread. The default runs
  synchronously, which keeps the mixer testable without the thread lane and lets
  that lane swap in real cross-thread posting on rebase. This lane therefore
  carries no hard import of `lib/thread.mjs`.
- **Ring.** Single-producer/single-consumer `Float32` interleaved ring over a
  `SharedArrayBuffer`, `Atomics` indices, underrun and overrun counted rather
  than papered over — the browser worklet's starvation signal.

## Cycle history

- **Cycle 1** — `lib/audio.mjs` core: format/decode, gain law, deterministic
  mixer + resampler, SAB ring, audio clock, waveOut and DirectSound state
  machines. `test/audio.test.mjs` (11 case, green). Registered
  `lib/audio.mjs` / `test/audio.test.mjs` in the npm content manifest and the
  validator surface. `npm run gate` exits 0 (175 test, 45 file).

- **Cycle 2** — XAudio2 voice subset: a mastering voice (master volume) and a
  source voice with a buffer queue, per-buffer loop count (0 / finite / 255
  infinite), source-amplitude volume, frequency ratio, `FlushSourceBuffers`,
  `GetState`, and the `OnBufferEnd` callback. Master and voice volume multiply
  into the mix-source gain. `test/audio.test.mjs` now 13 case, green. `npm run
  gate` exits 0.

- **Cycle 3** — audio conformance surface over the repo's generic apparatus
  (`lib/conformance.mjs`): `listAudioExport` declares twelve exports
  (`winmm!waveOut{Open,Write,Reset,Close}`, `dsound!IDirectSoundBuffer::{Play,
  Stop,SetVolume,SetPan,GetCurrentPosition}`, `xaudio2!IXAudio2SourceVoice::
  {SubmitSourceBuffer,Start,Stop}`), each with a deterministic mini-scenario
  oracle. The suite passes with `is_coverage_complete === true` — zero
  uncovered audio exports for this subsystem. `test/audio.test.mjs` now 14 case,
  green. `npm run gate` exits 0 (178 test).

## HLE registration is deferred (honest)

`lib/hle.mjs` does **not** import the peer subsystems (graphics, shader, clock)
— they are standalone, self-tested modules, and audio follows that pattern.
Registering the guest audio exports into `win32HleExportTable` requires
guest-memory marshalling of `WAVEFORMATEX`, PCM buffers at guest addresses, and
cross-thread callback posting; the HLE conformance test asserts
`is_coverage_complete === true`, so a bare registration without those
guest-memory-backed cases would either break the gate or fabricate a case (a
false green). That marshalling depends on the thread/runtime seam. This lane
therefore keeps the audio core self-contained and defers the `lib/hle.mjs`
export rows to the rebase-onto-thread step, exactly as the lane's dependency
note anticipates. The audio subsystem exposes an injected
`dispatch(callback, message, param)` so that seam is a one-function swap.

## Next

- On rebase onto thread: wire `dispatch` to the guest-thread poster and add the
  `winmm`/`dsound`/`xaudio2` export rows to `lib/hle.mjs` with guest-memory
  cases.
- Promote BPTK-014 `planned → implemented` via the 8-file contract, keeping the
  live BENCH-014 red and every count reconciled.
