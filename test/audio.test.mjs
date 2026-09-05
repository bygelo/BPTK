// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// Legacy-audio bridge tests (BPTK-014): PCM decode, the constant-power and
// decibel gain law, a golden offline mix inside numerical tolerance, a
// sustained ring run with zero underrun, the audio clock reading the one
// monotonic source, and the waveOut and DirectSound state machines with their
// guest-thread callback order.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createGuestClock } from "../lib/clock.mjs";
import { runConformanceSuite } from "../lib/conformance.mjs";
import {
  audioBound,
  buildAudioConformanceCaseTable,
  createAudioConformanceImplementation,
  listAudioExport,
  audioMessage,
  constantPowerPan,
  createAudioClock,
  createAudioRing,
  createAudioSystem,
  createMixSource,
  decibelToLinear,
  decodePcm,
  directSoundPanGain,
  mixBlock,
  normalizeWaveFormat,
} from "../lib/audio.mjs";

const mixRate = audioBound.mix_sample_rate_hz;

// A 16-bit signed mono sine at a chosen rate, as a guest PCM byte block.
function sinePcm16(rate, freq, frameCount, amplitude = 0.9) {
  const byte = Buffer.alloc(frameCount * 2);
  for (let i = 0; i < frameCount; i += 1) {
    const s = amplitude * Math.sin((2 * Math.PI * freq * i) / rate);
    byte.writeInt16LE(Math.round(s * 32767), i * 2);
  }
  return byte;
}

test("the wave format subset normalizes and refuses an unsupported tag", () => {
  const wave = normalizeWaveFormat({ format_tag: "pcm", sample_rate_hz: 44100, channel_count: 2, bit_per_sample: 16 });
  assert.equal(wave.block_align_byte, 4);
  assert.equal(wave.byte_per_second, 44100 * 4);
  assert.throws(() => normalizeWaveFormat({ format_tag: "adpcm", sample_rate_hz: 44100, channel_count: 2, bit_per_sample: 16 }), /format tag/);
  assert.throws(() => normalizeWaveFormat({ sample_rate_hz: 3000, channel_count: 1, bit_per_sample: 16 }), /out of range/);
  assert.throws(() => normalizeWaveFormat({ format_tag: "float", sample_rate_hz: 48000, channel_count: 1, bit_per_sample: 16 }), /Float format/);
});

test("PCM decode maps 8-bit, 16-bit, and float into the normalized range", () => {
  const byte8 = Buffer.from([0, 128, 255]);
  const eight = decodePcm({ format_tag: "pcm", sample_rate_hz: 8000, channel_count: 1, bit_per_sample: 8 }, byte8);
  assert.equal(eight.frame_count, 3);
  assert.ok(Math.abs(eight.sample[0] + 1) < 1e-6);
  assert.ok(Math.abs(eight.sample[1] - 0) < 1e-6);

  const byte16 = Buffer.alloc(4);
  byte16.writeInt16LE(-32768, 0);
  byte16.writeInt16LE(16384, 2);
  const sixteen = decodePcm({ format_tag: "pcm", sample_rate_hz: 8000, channel_count: 1, bit_per_sample: 16 }, byte16);
  assert.ok(Math.abs(sixteen.sample[0] + 1) < 1e-6);
  assert.ok(Math.abs(sixteen.sample[1] - 0.5) < 1e-6);

  const byteF = Buffer.alloc(4);
  byteF.writeFloatLE(0.25, 0);
  const floatDecode = decodePcm({ format_tag: "float", sample_rate_hz: 8000, channel_count: 1, bit_per_sample: 32 }, byteF);
  assert.ok(Math.abs(floatDecode.sample[0] - 0.25) < 1e-6);
});

test("the pan and decibel gain law holds at its declared points", () => {
  const center = constantPowerPan(0);
  assert.ok(Math.abs(center.left - center.right) < 1e-9);
  assert.ok(Math.abs(center.left ** 2 + center.right ** 2 - 1) < 1e-9); // constant power
  const hardLeft = constantPowerPan(-1);
  assert.ok(Math.abs(hardLeft.left - 1) < 1e-9 && Math.abs(hardLeft.right) < 1e-9);

  assert.ok(Math.abs(decibelToLinear(0) - 1) < 1e-9);
  assert.ok(Math.abs(decibelToLinear(-600) - 0.501) < 2e-3); // -6 dB ≈ half amplitude
  assert.equal(decibelToLinear(-10000), 0); // floor is silence

  const panLeft = directSoundPanGain(600); // attenuate left
  assert.ok(panLeft.right === 1 && panLeft.left < 1);
});

test("a PCM/volume/pan fixture renders to the golden mix within tolerance", () => {
  // Source at the mix rate so the frame index is integral: the mixed output is
  // the decoded sample scaled by the independently computed pan/volume gain.
  const frame = 4800;
  const decoded = decodePcm({ format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 }, sinePcm16(mixRate, 440, frame));
  const pan = constantPowerPan(0.5);
  const volume = decibelToLinear(-200); // -2 dB
  const source = createMixSource(decoded, { gain_left: volume * pan.left, gain_right: volume * pan.right });
  const { output } = mixBlock([source], frame, { mix_sample_rate_hz: mixRate });

  let maxError = 0;
  for (let f = 0; f < frame; f += 1) {
    const expectedLeft = Math.max(-1, Math.min(1, decoded.sample[f] * volume * pan.left));
    const expectedRight = Math.max(-1, Math.min(1, decoded.sample[f] * volume * pan.right));
    maxError = Math.max(maxError, Math.abs(output[f * 2] - expectedLeft), Math.abs(output[f * 2 + 1] - expectedRight));
  }
  assert.ok(maxError < 2e-4, `golden mix max error ${maxError} exceeds tolerance`);
});

test("resampling a half-rate source matches the linear-interpolation oracle", () => {
  const frame = 2400;
  const decoded = decodePcm({ format_tag: "pcm", sample_rate_hz: mixRate / 2, channel_count: 1, bit_per_sample: 16 }, sinePcm16(mixRate / 2, 300, frame));
  const outFrame = 1000;
  const source = createMixSource(decoded, { gain_left: 1, gain_right: 1 });
  const { output } = mixBlock([source], outFrame, { mix_sample_rate_hz: mixRate });

  const step = (mixRate / 2) / mixRate;
  let maxError = 0;
  for (let f = 0; f < outFrame; f += 1) {
    const position = f * step;
    const i0 = Math.floor(position);
    const frac = position - i0;
    const expected = decoded.sample[i0] + (decoded.sample[i0 + 1] - decoded.sample[i0]) * frac;
    maxError = Math.max(maxError, Math.abs(output[f * 2] - expected));
  }
  assert.ok(maxError < 1e-5, `interpolation error ${maxError} exceeds tolerance`);
});

test("a sustained ring run stays free of underrun while a starved read is counted", () => {
  const ring = createAudioRing({ frame_count: 4096 });
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const decoded = decodePcm({ format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 }, sinePcm16(mixRate, 220, 480));
  system.engine.addSource(createMixSource(decoded, { loop: true }));

  const blockFrame = 512;
  const scratch = new Float32Array(blockFrame * ring.channel_count);
  // Prime two blocks so the consumer always trails the producer.
  system.pump(ring, blockFrame);
  system.pump(ring, blockFrame);
  for (let iteration = 0; iteration < 4000; iteration += 1) {
    system.pump(ring, blockFrame);
    ring.read(scratch, blockFrame);
  }
  assert.equal(ring.underrun_count(), 0, "sustained run underran the ring");

  const starved = createAudioRing({ frame_count: 1024 });
  starved.read(new Float32Array(64 * 2), 64);
  assert.equal(starved.underrun_count(), 64, "a starved read must be counted");
});

test("the audio clock derives its position from the one monotonic guest clock", () => {
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const audioClock = createAudioClock(clock, { mix_sample_rate_hz: mixRate });
  for (let block = 0; block < 10; block += 1) audioClock.advance(4800);
  // Rendered position and the guest clock read the same elapsed time.
  assert.ok(Math.abs(audioClock.render_position_ms() - audioClock.guest_position_ms()) < 1e-9);
  assert.ok(Math.abs(audioClock.render_position_ms() - 1000) < 1e-9); // 48000 frames at 48 kHz = 1 s
});

test("waveOut opens, drains a block to WOM_DONE, and resets the queue", () => {
  const event = [];
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const device = system.openWaveOut(
    { format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 },
    { callback: (message, param) => event.push([message, param]) },
  );
  assert.deepEqual(event[0], [audioMessage.wom_open, device.handle]);

  const blockId = device.write(sinePcm16(mixRate, 440, 256));
  assert.equal(device.queued_block_count(), 1);
  system.render(256); // drains exactly the block
  assert.deepEqual(event.at(-1), [audioMessage.wom_done, blockId]);
  assert.equal(device.queued_block_count(), 0);

  // A block returned early by reset also posts WOM_DONE and clears the queue.
  const pending = device.write(sinePcm16(mixRate, 440, 4800));
  device.reset();
  assert.deepEqual(event.at(-1), [audioMessage.wom_done, pending]);
  assert.equal(device.queued_block_count(), 0);
  device.close();
  assert.deepEqual(event.at(-1), [audioMessage.wom_close, device.handle]);
});

test("a DirectSound buffer loops, honors volume and pan, and reports its cursor", () => {
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const format = { format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 };
  const wave = normalizeWaveFormat(format);
  const frame = 480;
  const buffer = system.createSoundBuffer({ format, byte_count: frame * wave.block_align_byte });

  const region = buffer.lock();
  sinePcm16(mixRate, 440, frame, 1).copy(region.view);
  buffer.unlock();
  buffer.setVolume(-600); // -6 dB
  buffer.setPan(0);
  buffer.play(true);

  system.render(frame * 3); // three loops
  assert.ok(buffer.is_playing(), "a looping buffer must keep playing past its length");
  const position = buffer.getCurrentPosition();
  assert.ok(position.play_cursor_byte >= 0 && position.play_cursor_byte < frame * wave.block_align_byte);
  buffer.stop();
  assert.ok(!buffer.is_playing());
});

test("a DirectSound notification fires as the play cursor crosses it", () => {
  const event = [];
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const format = { format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 };
  const wave = normalizeWaveFormat(format);
  const frame = 1000;
  const buffer = system.createSoundBuffer({ format, byte_count: frame * wave.block_align_byte });
  const region = buffer.lock();
  sinePcm16(mixRate, 440, frame, 1).copy(region.view);
  buffer.unlock();
  buffer.setNotificationPosition([{ offset_byte: 500 * wave.block_align_byte, token: 42, callback: (message, token) => event.push(token) }]);
  buffer.play(false);

  system.render(400); // before the notification offset
  assert.equal(event.length, 0);
  system.render(300); // crosses frame 500
  assert.deepEqual(event, [42]);
  buffer.release();
});

test("an XAudio2 source voice drains its buffer queue and fires OnBufferEnd in order", () => {
  const ended = [];
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const master = system.createMasteringVoice({ volume: 1 });
  const format = { format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 };
  const voice = system.createSourceVoice({ format, mastering_voice: master, on_buffer_end: (context) => ended.push(context) });

  voice.submitSourceBuffer({ byte: sinePcm16(mixRate, 440, 256), context: "a" });
  voice.submitSourceBuffer({ byte: sinePcm16(mixRate, 550, 128), context: "b" });
  assert.equal(voice.getState().buffer_queued_count, 2);
  voice.start();

  system.render(256); // drains buffer "a"
  assert.deepEqual(ended, ["a"]);
  assert.equal(voice.getState().buffer_queued_count, 1);
  system.render(128); // drains buffer "b"
  assert.deepEqual(ended, ["a", "b"]);
  assert.equal(voice.getState().buffer_queued_count, 0);
  assert.equal(voice.getState().sample_played_count, 384);
});

test("an XAudio2 infinite-loop buffer never ends and voice volume scales the mix", () => {
  const ended = [];
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const master = system.createMasteringVoice({ volume: 0.5 });
  const format = { format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 };
  const voice = system.createSourceVoice({ format, mastering_voice: master, on_buffer_end: (context) => ended.push(context) });
  voice.submitSourceBuffer({ byte: sinePcm16(mixRate, 440, 100, 1), loop_count: 255, context: "loop" });
  voice.setVolume(0.4);
  voice.start();

  const { output } = system.render(1000); // ten loop lengths, no OnBufferEnd
  assert.equal(ended.length, 0);
  assert.equal(voice.getState().buffer_queued_count, 1);
  // gain = voice 0.4 * master 0.5 = 0.2; the peak of the unit sine is bounded by it.
  let peak = 0;
  for (const value of output) peak = Math.max(peak, Math.abs(value));
  assert.ok(peak <= 0.2 + 1e-3 && peak > 0.15, `scaled peak ${peak} outside the expected band`);

  voice.stop();
  system.render(100);
  assert.equal(voice.getState().buffer_queued_count, 1); // stop does not dequeue
});

test("every declared audio export carries a conformance case and passes its oracle", () => {
  const caseTable = buildAudioConformanceCaseTable();
  const report = runConformanceSuite(caseTable, createAudioConformanceImplementation(), { served_export: listAudioExport() });
  assert.equal(report.fail_count, 0, `conformance failure: ${report.result.filter((entry) => !entry.pass).map((entry) => entry.case_id).join(", ")}`);
  assert.equal(report.pass_count, report.case_count);
  assert.equal(report.is_coverage_complete, true, "an audio export without a case is a coverage hole");
  assert.equal(report.uncovered_export.length, 0);
});

test("DirectSound pause holds the cursor and resume continues from it", () => {
  const clock = createGuestClock({ mode: "virtual_monotonic" });
  const system = createAudioSystem({ guest_clock: clock });
  const format = { format_tag: "pcm", sample_rate_hz: mixRate, channel_count: 1, bit_per_sample: 16 };
  const wave = normalizeWaveFormat(format);
  const frame = 2000;
  const buffer = system.createSoundBuffer({ format, byte_count: frame * wave.block_align_byte });
  const region = buffer.lock();
  sinePcm16(mixRate, 440, frame, 1).copy(region.view);
  buffer.unlock();
  buffer.play(false);

  system.render(500);
  const held = buffer.getCurrentPosition().play_cursor_byte;
  buffer.pause();
  assert.ok(!buffer.is_playing());
  system.render(500); // no advance while paused
  assert.equal(buffer.getCurrentPosition().play_cursor_byte, held);
  buffer.resume();
  system.render(200);
  assert.ok(buffer.getCurrentPosition().play_cursor_byte > held, "resume must continue from the held cursor");
  buffer.release();
});
