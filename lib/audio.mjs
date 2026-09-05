// Copyright 2026 Maphy Technologies
// SPDX-License-Identifier: Apache-2.0

// The legacy-audio bridge (BPTK-014). One portable mixer serves waveOut,
// DirectSound, and — in the next slice — an XAudio2 voice subset: every guest
// API lowers a playing sound into the same mix source, and one deterministic
// summing engine renders them into an interleaved stereo block. That block is
// handed to an AudioWorklet through a SharedArrayBuffer ring in the browser; in
// node the same ring is a plain SharedArrayBuffer, so the producer/consumer and
// underrun accounting are testable without a real audio device.
//
// The clock is the point of the exercise: audio position never runs on its own
// wall clock. The engine advances the one monotonic guest clock (lib/clock.mjs)
// by exactly the rendered duration each block, so a frame counter and the audio
// play cursor read the same elapsed time — the A/V clock derives from one
// source, which is the acceptance BENCH-014 measures offline.
//
// The live half stays red: a real AudioWorklet, the autoplay gesture, and
// browser suspension are not exercised here, so BENCH-014 remains excluded
// until FIX-007 renders verified output after gesture activation.

import { InputError } from "./input.mjs";

export const audioBound = Object.freeze({
  min_sample_rate_hz: 4000,
  max_sample_rate_hz: 192000,
  max_channel_count: 8,
  supported_bit_per_sample: Object.freeze([8, 16, 32]),
  mix_sample_rate_hz: 48000,
  mix_channel_count: 2,
  ring_frame_count: 8192,
  max_source_count: 64,
  max_frequency_ratio: 8,
  min_frequency_ratio: 1 / 8,
});

// DirectSound declares volume and pan in hundredths of a decibel; the floor is
// treated as silence rather than a finite attenuation.
export const directSoundBound = Object.freeze({
  volume_min_mb: -10000,
  volume_max_mb: 0,
  pan_min_mb: -10000,
  pan_max_mb: 10000,
});

// waveOut and DirectSound callback message identity the guest observes.
export const audioMessage = Object.freeze({
  wom_open: 0x03bb,
  wom_close: 0x03bc,
  wom_done: 0x03bd,
});

function audioError(code, message) {
  return new InputError(code, message);
}

function clamp(value, low, high) {
  if (value < low) return low;
  if (value > high) return high;
  return value;
}

// ---- format ---------------------------------------------------------------
// A WAVEFORMATEX subset: PCM 8/16-bit integer and 32-bit IEEE float. Every
// other tag is refused by name rather than mixed as noise.

export function normalizeWaveFormat(format) {
  if (format === null || typeof format !== "object") {
    throw audioError("wave_format_required", "A wave format object is required");
  }
  const tag = format.format_tag ?? "pcm";
  if (tag !== "pcm" && tag !== "float") {
    throw audioError("wave_format_tag", `Unsupported format tag: ${tag}`);
  }
  const sampleRateHz = format.sample_rate_hz;
  if (!Number.isInteger(sampleRateHz) || sampleRateHz < audioBound.min_sample_rate_hz || sampleRateHz > audioBound.max_sample_rate_hz) {
    throw audioError("wave_format_sample_rate", `Sample rate out of range: ${sampleRateHz}`);
  }
  const channelCount = format.channel_count;
  if (!Number.isInteger(channelCount) || channelCount < 1 || channelCount > audioBound.max_channel_count) {
    throw audioError("wave_format_channel", `Channel count out of range: ${channelCount}`);
  }
  const bitPerSample = format.bit_per_sample;
  if (!audioBound.supported_bit_per_sample.includes(bitPerSample)) {
    throw audioError("wave_format_bit", `Unsupported bit depth: ${bitPerSample}`);
  }
  if (tag === "float" && bitPerSample !== 32) {
    throw audioError("wave_format_float_bit", "Float format requires 32 bit per sample");
  }
  if (tag === "pcm" && bitPerSample === 32) {
    throw audioError("wave_format_pcm_bit", "32-bit samples must declare the float tag");
  }
  const blockAlignByte = channelCount * (bitPerSample / 8);
  return Object.freeze({
    format_tag: tag,
    sample_rate_hz: sampleRateHz,
    channel_count: channelCount,
    bit_per_sample: bitPerSample,
    block_align_byte: blockAlignByte,
    byte_per_second: blockAlignByte * sampleRateHz,
  });
}

// Decodes a guest PCM byte block into an interleaved Float32 buffer in the
// [-1, 1] range at the source's own rate and channel count.
export function decodePcm(format, byte) {
  const wave = normalizeWaveFormat(format);
  const view = ArrayBuffer.isView(byte) ? Buffer.from(byte.buffer, byte.byteOffset, byte.byteLength) : Buffer.from(byte);
  const frameCount = Math.floor(view.length / wave.block_align_byte);
  const sampleCount = frameCount * wave.channel_count;
  const out = new Float32Array(sampleCount);
  for (let i = 0; i < sampleCount; i += 1) {
    if (wave.bit_per_sample === 8) {
      out[i] = (view.readUInt8(i) - 128) / 128;
    } else if (wave.bit_per_sample === 16) {
      out[i] = view.readInt16LE(i * 2) / 32768;
    } else {
      out[i] = view.readFloatLE(i * 4);
    }
  }
  return { sample: out, frame_count: frameCount, channel_count: wave.channel_count, sample_rate_hz: wave.sample_rate_hz };
}

// ---- gain -----------------------------------------------------------------
// Constant-power pan keeps the summed power flat across the stereo field; the
// waveOut per-channel volume and the DirectSound decibel model both resolve to
// an explicit left/right linear gain so the mixer stays one code path.

export function constantPowerPan(pan) {
  const theta = (clamp(pan, -1, 1) + 1) * (Math.PI / 4);
  return { left: Math.cos(theta), right: Math.sin(theta) };
}

// DirectSound volume: hundredths of a decibel, floor is silence.
export function decibelToLinear(mb) {
  if (mb <= directSoundBound.volume_min_mb) return 0;
  return Math.pow(10, clamp(mb, directSoundBound.volume_min_mb, directSoundBound.volume_max_mb) / 2000);
}

// DirectSound pan: hundredths of a decibel of attenuation applied to the
// louder side's opposite channel. Positive pan attenuates the left channel.
export function directSoundPanGain(mb) {
  const value = clamp(mb, directSoundBound.pan_min_mb, directSoundBound.pan_max_mb);
  if (value === 0) return { left: 1, right: 1 };
  if (value > 0) return { left: decibelToLinear(-value), right: 1 };
  return { left: 1, right: decibelToLinear(value) };
}

// ---- mix source -----------------------------------------------------------
// One playing sound. Position is a fractional source-frame index; the engine
// advances it by the rate step each output frame and interpolates linearly.

export function createMixSource(decoded, option = {}) {
  if (!decoded || !(decoded.sample instanceof Float32Array)) {
    throw audioError("mix_source_sample", "A decoded Float32 sample buffer is required");
  }
  return {
    sample: decoded.sample,
    frame_count: decoded.frame_count,
    channel_count: decoded.channel_count,
    sample_rate_hz: decoded.sample_rate_hz,
    position: option.position ?? 0,
    rate_ratio: option.rate_ratio ?? 1,
    gain_left: option.gain_left ?? 1,
    gain_right: option.gain_right ?? 1,
    loop: option.loop ?? false,
    active: option.active ?? true,
    completed: false,
    token: option.token ?? null,
  };
}

function readSourceFrame(source, channel) {
  const total = source.frame_count;
  if (total === 0) return 0;
  const index0 = Math.floor(source.position);
  const frac = source.position - index0;
  let index1 = index0 + 1;
  if (index1 >= total) index1 = source.loop ? index1 - total : total - 1;
  const stride = source.channel_count;
  // Mono feeds both output channels; wider sources take their first two.
  const laneOffset = stride === 1 ? 0 : Math.min(channel, stride - 1);
  const s0 = source.sample[index0 * stride + laneOffset];
  const s1 = source.sample[index1 * stride + laneOffset];
  return s0 + (s1 - s0) * frac;
}

// ---- mixer ----------------------------------------------------------------
// Sums every active source into an interleaved stereo block, advancing each
// source's cursor and marking a non-looping source complete when it drains.
// Deterministic: identical sources and frame count yield identical output.

export function mixBlock(sourceList, frameCount, option = {}) {
  const mixRate = option.mix_sample_rate_hz ?? audioBound.mix_sample_rate_hz;
  const out = new Float32Array(frameCount * audioBound.mix_channel_count);
  const completion = [];
  for (const source of sourceList) {
    if (!source.active) continue;
    const step = (source.sample_rate_hz / mixRate) * source.rate_ratio;
    for (let f = 0; f < frameCount; f += 1) {
      if (!source.active) break;
      const left = readSourceFrame(source, 0) * source.gain_left;
      const right = readSourceFrame(source, 1) * source.gain_right;
      out[f * 2] += left;
      out[f * 2 + 1] += right;
      source.position += step;
      if (source.position >= source.frame_count) {
        if (source.loop && source.frame_count > 0) {
          source.position -= source.frame_count * Math.floor(source.position / source.frame_count);
        } else {
          source.active = false;
          source.completed = true;
          if (source.token !== null) completion.push(source.token);
        }
      }
    }
  }
  // Hard limiter: the summed field is clamped so a busy mix never wraps.
  for (let i = 0; i < out.length; i += 1) out[i] = clamp(out[i], -1, 1);
  return { output: out, completion };
}

// ---- ring -----------------------------------------------------------------
// A single-producer single-consumer ring of interleaved stereo frames over a
// SharedArrayBuffer. The producer is the mix engine, the consumer is the
// AudioWorklet; a read that outruns the writer is counted as an underrun rather
// than silently repeating stale audio.

const ringControl = Object.freeze({ write_frame: 0, read_frame: 1, underrun_count: 2, overrun_count: 3, field_count: 4 });

export function createAudioRing(option = {}) {
  const frameCount = option.frame_count ?? audioBound.ring_frame_count;
  const channelCount = audioBound.mix_channel_count;
  const headerByte = ringControl.field_count * 4;
  const dataByte = frameCount * channelCount * 4;
  const sab = option.buffer ?? new SharedArrayBuffer(headerByte + dataByte);
  const control = new Int32Array(sab, 0, ringControl.field_count);
  const data = new Float32Array(sab, headerByte, frameCount * channelCount);

  function available() {
    return Atomics.load(control, ringControl.write_frame) - Atomics.load(control, ringControl.read_frame);
  }

  return {
    buffer: sab,
    frame_count: frameCount,
    channel_count: channelCount,
    available_frame: available,
    free_frame() {
      return frameCount - available();
    },
    underrun_count() {
      return Atomics.load(control, ringControl.underrun_count);
    },
    overrun_count() {
      return Atomics.load(control, ringControl.overrun_count);
    },
    // Writes as many whole stereo frames as fit; a block that outruns the free
    // space is truncated and the dropped frames counted as an overrun.
    write(block) {
      const offered = Math.floor(block.length / channelCount);
      const free = frameCount - available();
      const accepted = Math.min(offered, free);
      let write = Atomics.load(control, ringControl.write_frame);
      for (let f = 0; f < accepted; f += 1) {
        const slot = ((write + f) % frameCount) * channelCount;
        data[slot] = block[f * channelCount];
        data[slot + 1] = block[f * channelCount + 1];
      }
      Atomics.store(control, ringControl.write_frame, write + accepted);
      if (accepted < offered) Atomics.add(control, ringControl.overrun_count, offered - accepted);
      return accepted;
    },
    // Fills the output with available frames; any shortfall is zero-filled and
    // counted as an underrun — the browser worklet's starvation signal.
    read(out, requestFrame) {
      const have = available();
      const served = Math.min(requestFrame, have);
      let read = Atomics.load(control, ringControl.read_frame);
      for (let f = 0; f < served; f += 1) {
        const slot = ((read + f) % frameCount) * channelCount;
        out[f * channelCount] = data[slot];
        out[f * channelCount + 1] = data[slot + 1];
      }
      for (let f = served; f < requestFrame; f += 1) {
        out[f * channelCount] = 0;
        out[f * channelCount + 1] = 0;
      }
      Atomics.store(control, ringControl.read_frame, read + served);
      if (served < requestFrame) Atomics.add(control, ringControl.underrun_count, requestFrame - served);
      return served;
    },
  };
}

// ---- audio clock ----------------------------------------------------------
// The audio position is a view of the one monotonic guest clock. In offline
// render the engine advances the clock by the rendered duration, so the audio
// play cursor and any frame counter reading the same clock never diverge.

export function createAudioClock(guestClock, option = {}) {
  const sampleRate = option.mix_sample_rate_hz ?? audioBound.mix_sample_rate_hz;
  let frameRendered = 0;
  return {
    frame_rendered() {
      return frameRendered;
    },
    render_position_ms() {
      return (frameRendered / sampleRate) * 1000;
    },
    guest_position_ms() {
      return guestClock.elapsedGuestMs();
    },
    advance(frameCount) {
      frameRendered += frameCount;
      if (guestClock.mode === "virtual_monotonic") {
        guestClock.advanceVirtualMs((frameCount / sampleRate) * 1000);
      }
    },
  };
}

// ---- engine ---------------------------------------------------------------
// Owns the live source set, renders blocks, drives the ring, and advances the
// audio clock. Completion tokens surface after each render so a device layer
// can dispatch its guest callback on the correct thread.

export function createAudioEngine(option = {}) {
  const mixRate = option.mix_sample_rate_hz ?? audioBound.mix_sample_rate_hz;
  const guestClock = option.guest_clock ?? null;
  const clock = guestClock ? createAudioClock(guestClock, { mix_sample_rate_hz: mixRate }) : null;
  const source = new Set();

  return {
    mix_sample_rate_hz: mixRate,
    clock,
    source_count() {
      return source.size;
    },
    addSource(mixSource) {
      if (source.size >= audioBound.max_source_count) {
        throw audioError("mix_source_limit", `Mix source count exceeds ${audioBound.max_source_count}`);
      }
      source.add(mixSource);
      return mixSource;
    },
    removeSource(mixSource) {
      source.delete(mixSource);
    },
    // Renders one stereo block, retires drained sources, and advances the
    // clock so audio time tracks the one monotonic source.
    render(frameCount) {
      const active = [...source];
      const { output, completion } = mixBlock(active, frameCount, { mix_sample_rate_hz: mixRate });
      for (const mixSource of active) {
        if (mixSource.completed) source.delete(mixSource);
      }
      if (clock) clock.advance(frameCount);
      return { output, completion };
    },
    // Produces one block into the ring; the return value carries the ring's
    // running underrun and overrun tally for a sustained-run assertion.
    pump(ring, frameCount) {
      const { output, completion } = this.render(frameCount);
      const accepted = ring.write(output);
      return { accepted, completion, underrun_count: ring.underrun_count(), overrun_count: ring.overrun_count() };
    },
  };
}

// ---- system ---------------------------------------------------------------
// The composition root: it owns one engine, routes completion tokens to their
// registered handler, and drives per-render buffer tick so DirectSound
// notification positions fire as the play cursor crosses them. Devices are
// created here so every guest API shares the one engine, ring, and clock.
//
// `dispatch` is the seam onto the thread subsystem (BPTK-010): a callback runs
// through `dispatch(callback, message, param)` so it lands on the correct guest
// thread. The default runs synchronously, which keeps the mixer testable
// without the thread lane and lets that lane swap in real cross-thread posting.

function synchronousDispatch(callback, message, param) {
  if (typeof callback === "function") callback(message, param);
}

export function createAudioSystem(option = {}) {
  const engine = createAudioEngine(option);
  const dispatch = option.dispatch ?? synchronousDispatch;
  const handler = new Map();
  const tick = new Set();
  let tokenSeq = 0;
  let handleSeq = 0;

  function allocToken(fn) {
    tokenSeq += 1;
    handler.set(tokenSeq, fn);
    return tokenSeq;
  }

  function route(completion) {
    for (const token of completion) {
      const fn = handler.get(token);
      if (fn) {
        handler.delete(token);
        fn();
      }
    }
  }

  function afterRender() {
    for (const fn of tick) fn();
  }

  const system = {
    engine,
    clock: engine.clock,
    render(frameCount) {
      const result = engine.render(frameCount);
      route(result.completion);
      afterRender();
      return result;
    },
    pump(ring, frameCount) {
      const result = engine.pump(ring, frameCount);
      route(result.completion);
      afterRender();
      return result;
    },
  };

  // ---- waveOut device -----------------------------------------------------
  // Open/write/reset/close. Each waveOutWrite becomes one non-looping mix
  // source; the WHDR completion posts WOM_DONE on the guest thread when the
  // source drains or when waveOutReset returns the queue early.

  system.openWaveOut = function openWaveOut(format, deviceOption = {}) {
    const wave = normalizeWaveFormat(format);
    const callback = deviceOption.callback ?? null;
    const post = deviceOption.dispatch ?? dispatch;
    handleSeq += 1;
    const handle = handleSeq;
    let block = [];
    let blockSeq = 0;
    let closed = false;
    let volumeLeft = deviceOption.volume_left ?? 1;
    let volumeRight = deviceOption.volume_right ?? 1;
    post(callback, audioMessage.wom_open, handle);
    return {
      handle,
      queued_block_count() {
        return block.filter((entry) => entry.source.active).length;
      },
      setVolume(left, right) {
        volumeLeft = clamp(left, 0, 1);
        volumeRight = clamp(right, 0, 1);
        for (const entry of block) {
          if (entry.source.active) {
            entry.source.gain_left = volumeLeft;
            entry.source.gain_right = volumeRight;
          }
        }
      },
      write(byte) {
        if (closed) throw audioError("waveout_closed", "waveOutWrite on a closed device");
        const decoded = decodePcm(wave, byte);
        blockSeq += 1;
        const blockId = blockSeq;
        const token = allocToken(() => post(callback, audioMessage.wom_done, blockId));
        const source = createMixSource(decoded, { token, gain_left: volumeLeft, gain_right: volumeRight });
        engine.addSource(source);
        block.push({ block_id: blockId, source, token });
        return blockId;
      },
      reset() {
        for (const entry of block) {
          if (entry.source.active) {
            engine.removeSource(entry.source);
            entry.source.active = false;
            if (handler.delete(entry.token)) post(callback, audioMessage.wom_done, entry.block_id);
          }
        }
        block = [];
      },
      close() {
        if (closed) return;
        this.reset();
        closed = true;
        post(callback, audioMessage.wom_close, handle);
      },
    };
  };

  // ---- DirectSound buffer -------------------------------------------------
  // A secondary buffer with a guest-writable backing store, lock/unlock, loop
  // playback, decibel volume, decibel pan, a play/write cursor, and position
  // notifications that fire as the play cursor crosses each declared offset.
  // Pause deactivates the source while holding the cursor; resume continues.

  system.createSoundBuffer = function createSoundBuffer(bufferOption = {}) {
    const wave = normalizeWaveFormat(bufferOption.format);
    const byteCount = bufferOption.byte_count;
    if (!Number.isInteger(byteCount) || byteCount <= 0 || byteCount % wave.block_align_byte !== 0) {
      throw audioError("sound_buffer_size", "Buffer byte count must be a positive whole frame count");
    }
    const backing = Buffer.alloc(byteCount);
    const totalFrame = byteCount / wave.block_align_byte;
    const post = bufferOption.dispatch ?? dispatch;
    let source = null;
    let playing = false;
    let loop = false;
    let volumeMb = directSoundBound.volume_max_mb;
    let panMb = 0;
    let frequencyHz = wave.sample_rate_hz;
    let cursorFrame = 0;
    let notification = [];
    let lastCursorFrame = 0;

    function applyGain() {
      if (!source) return;
      const volume = decibelToLinear(volumeMb);
      const pan = directSoundPanGain(panMb);
      source.gain_left = volume * pan.left;
      source.gain_right = volume * pan.right;
      source.rate_ratio = frequencyHz / wave.sample_rate_hz;
    }

    function checkNotification() {
      if (!source || !playing) return;
      const current = source.loop
        ? Math.floor(source.position)
        : (source.active ? Math.floor(source.position) : totalFrame);
      for (const entry of notification) {
        const target = entry.offset_byte === 0xffffffff ? totalFrame : Math.floor(entry.offset_byte / wave.block_align_byte);
        const crossed = lastCursorFrame < target && current >= target;
        if (crossed) post(entry.callback, audioMessage.wom_done, entry.token);
      }
      lastCursorFrame = current;
      cursorFrame = source.active ? Math.floor(source.position) % totalFrame : 0;
    }

    const bufferObject = {
      total_frame: totalFrame,
      // Lock returns a writable view of the backing store; unlock is the commit
      // point. The view aliases the backing buffer, matching the guest pointer.
      lock(offsetByte = 0, lengthByte = byteCount) {
        if (offsetByte < 0 || lengthByte < 0 || offsetByte + lengthByte > byteCount) {
          throw audioError("sound_buffer_lock", "Lock range escapes the buffer");
        }
        return { view: backing.subarray(offsetByte, offsetByte + lengthByte), offset_byte: offsetByte };
      },
      unlock() {
        if (source) {
          const decoded = decodePcm(wave, backing);
          source.sample = decoded.sample;
        }
      },
      play(loopFlag = false) {
        loop = Boolean(loopFlag);
        const decoded = decodePcm(wave, backing);
        source = createMixSource(decoded, { loop, position: cursorFrame });
        applyGain();
        engine.addSource(source);
        playing = true;
        lastCursorFrame = cursorFrame;
        return true;
      },
      stop() {
        if (source) {
          cursorFrame = source.active ? Math.floor(source.position) % totalFrame : 0;
          engine.removeSource(source);
        }
        playing = false;
      },
      // Pause holds the cursor and detaches from the mix; resume re-attaches at
      // the held position without re-decoding.
      pause() {
        if (source && playing) {
          cursorFrame = Math.floor(source.position) % totalFrame;
          engine.removeSource(source);
          playing = false;
        }
      },
      resume() {
        if (source && !playing) {
          source.position = cursorFrame;
          source.active = true;
          source.completed = false;
          engine.addSource(source);
          playing = true;
          lastCursorFrame = cursorFrame;
        }
      },
      setVolume(mb) {
        volumeMb = clamp(mb, directSoundBound.volume_min_mb, directSoundBound.volume_max_mb);
        applyGain();
      },
      setPan(mb) {
        panMb = clamp(mb, directSoundBound.pan_min_mb, directSoundBound.pan_max_mb);
        applyGain();
      },
      setFrequency(hz) {
        const ratio = clamp(hz / wave.sample_rate_hz, audioBound.min_frequency_ratio, audioBound.max_frequency_ratio);
        frequencyHz = ratio * wave.sample_rate_hz;
        applyGain();
      },
      getCurrentPosition() {
        const play = source && source.active ? Math.floor(source.position) % totalFrame : cursorFrame;
        return { play_cursor_byte: play * wave.block_align_byte, write_cursor_byte: ((play + 1) % totalFrame) * wave.block_align_byte };
      },
      setCurrentPosition(byteOffset) {
        cursorFrame = Math.floor(byteOffset / wave.block_align_byte) % totalFrame;
        if (source) source.position = cursorFrame;
        lastCursorFrame = cursorFrame;
      },
      setNotificationPosition(list) {
        notification = list.map((entry) => ({
          offset_byte: entry.offset_byte,
          token: entry.token,
          callback: entry.callback ?? null,
        }));
      },
      is_playing() {
        return playing && Boolean(source) && source.active;
      },
    };

    tick.add(checkNotification);
    bufferObject.release = function release() {
      tick.delete(checkNotification);
      if (source) engine.removeSource(source);
    };
    return bufferObject;
  };

  // ---- XAudio2 voice subset ----------------------------------------------
  // A mastering voice as the master-volume sink and a source voice with a
  // buffer queue, per-buffer loop count, source-amplitude volume, a frequency
  // ratio, and the OnBufferEnd callback. Every buffer lowers into the one
  // mixer; the master and voice volume multiply into the mix source gain.

  system.createMasteringVoice = function createMasteringVoice(voiceOption = {}) {
    let volume = voiceOption.volume ?? 1;
    return {
      is_mastering_voice: true,
      volume() {
        return volume;
      },
      setVolume(value) {
        volume = clamp(value, 0, audioBound.max_frequency_ratio);
      },
    };
  };

  system.createSourceVoice = function createSourceVoice(voiceOption = {}) {
    const wave = normalizeWaveFormat(voiceOption.format);
    const master = voiceOption.mastering_voice ?? null;
    const post = voiceOption.dispatch ?? dispatch;
    const onBufferEnd = voiceOption.on_buffer_end ?? null;
    let volume = 1;
    let frequencyRatio = 1;
    let queue = [];
    let playing = false;
    let current = null;
    let samplePlayed = 0;

    function voiceGain() {
      return volume * (master ? master.volume() : 1);
    }

    function startHead() {
      if (!playing || current || queue.length === 0) return;
      const entry = queue[0];
      const gain = voiceGain();
      const source = createMixSource(entry.decoded, {
        gain_left: gain,
        gain_right: gain,
        rate_ratio: frequencyRatio,
      });
      entry.token = allocToken(() => onBufferComplete(entry));
      source.token = entry.token;
      entry.source = source;
      current = entry;
      engine.addSource(source);
    }

    function onBufferComplete(entry) {
      if (entry.loop_remaining > 0) {
        if (entry.loop_remaining !== Infinity) entry.loop_remaining -= 1;
        entry.source.position = 0;
        entry.source.active = true;
        entry.source.completed = false;
        entry.token = allocToken(() => onBufferComplete(entry));
        entry.source.token = entry.token;
        engine.addSource(entry.source);
        return;
      }
      samplePlayed += entry.decoded.frame_count;
      queue.shift();
      current = null;
      if (onBufferEnd) post(onBufferEnd, entry.context, entry.decoded.frame_count);
      startHead();
    }

    return {
      is_source_voice: true,
      handle: (handleSeq += 1),
      submitSourceBuffer(bufferOption) {
        const decoded = decodePcm(wave, bufferOption.byte);
        const loopCount = bufferOption.loop_count ?? 0;
        queue.push({
          decoded,
          loop_remaining: loopCount === 255 ? Infinity : loopCount,
          context: bufferOption.context ?? null,
          source: null,
          token: null,
        });
        startHead();
      },
      start() {
        playing = true;
        startHead();
      },
      stop() {
        playing = false;
        if (current && current.source) engine.removeSource(current.source);
      },
      setVolume(value) {
        volume = clamp(value, 0, audioBound.max_frequency_ratio);
        if (current && current.source) {
          current.source.gain_left = voiceGain();
          current.source.gain_right = voiceGain();
        }
      },
      setFrequencyRatio(ratio) {
        frequencyRatio = clamp(ratio, audioBound.min_frequency_ratio, audioBound.max_frequency_ratio);
        if (current && current.source) current.source.rate_ratio = frequencyRatio;
      },
      flushSourceBuffers() {
        if (current && current.source) engine.removeSource(current.source);
        queue = [];
        current = null;
      },
      getState() {
        return { buffer_queued_count: queue.length, sample_played_count: samplePlayed };
      },
      destroy() {
        this.flushSourceBuffers();
        playing = false;
      },
    };
  };

  return system;
}

// ---- conformance ----------------------------------------------------------
// The audio surface serves the repo's generic conformance apparatus
// (lib/conformance.mjs): every declared export carries at least one case, so a
// zero-case export is the coverage hole the suite exists to expose. Each handler
// runs a self-contained deterministic mini-scenario over one fresh system and
// reports one salient observable through the public API, so the case table is
// an oracle for the portable behavior — not the live browser bridge, which
// stays the red half of BENCH-014.

// The audio export surface this subsystem is accountable for.
export function listAudioExport() {
  return [
    "winmm.dll!waveOutOpen",
    "winmm.dll!waveOutWrite",
    "winmm.dll!waveOutReset",
    "winmm.dll!waveOutClose",
    "dsound.dll!IDirectSoundBuffer::Play",
    "dsound.dll!IDirectSoundBuffer::Stop",
    "dsound.dll!IDirectSoundBuffer::SetVolume",
    "dsound.dll!IDirectSoundBuffer::SetPan",
    "dsound.dll!IDirectSoundBuffer::GetCurrentPosition",
    "xaudio2.dll!IXAudio2SourceVoice::SubmitSourceBuffer",
    "xaudio2.dll!IXAudio2SourceVoice::Start",
    "xaudio2.dll!IXAudio2SourceVoice::Stop",
  ];
}

const conformanceFormat = Object.freeze({ format_tag: "pcm", sample_rate_hz: 48000, channel_count: 1, bit_per_sample: 16 });

function constantPcm16(frameCount, value) {
  const byte = Buffer.alloc(frameCount * 2);
  const sample = Math.round(clamp(value, -1, 1) * 32767);
  for (let i = 0; i < frameCount; i += 1) byte.writeInt16LE(sample, i * 2);
  return byte;
}

function fillSoundBuffer(buffer, frameCount, value) {
  const region = buffer.lock();
  constantPcm16(frameCount, value).copy(region.view);
  buffer.unlock();
}

function peakOf(output, stride, offset) {
  let peak = 0;
  for (let i = offset; i < output.length; i += stride) peak = Math.max(peak, Math.abs(output[i]));
  return peak;
}

// One dispatcher over the audio surface; each case is independent so the
// generic engine's fresh-per-case model needs no scenario replay.
export function createAudioConformanceImplementation() {
  const frame = 480;

  const handler = {
    "winmm.dll!waveOutOpen"() {
      const system = createAudioSystem();
      const device = system.openWaveOut(conformanceFormat);
      return { return_value: device.handle, last_error: 0 };
    },
    "winmm.dll!waveOutWrite"() {
      const system = createAudioSystem();
      const device = system.openWaveOut(conformanceFormat);
      device.write(constantPcm16(256, 0.5));
      return { return_value: device.queued_block_count(), last_error: 0 };
    },
    "winmm.dll!waveOutReset"() {
      let done = 0;
      const system = createAudioSystem();
      const device = system.openWaveOut(conformanceFormat, { callback: (message) => { if (message === audioMessage.wom_done) done += 1; } });
      device.write(constantPcm16(4800, 0.5));
      device.reset();
      // Reset returns the queue: one WOM_DONE fired and the queue is empty.
      return { return_value: done, last_error: device.queued_block_count() };
    },
    "winmm.dll!waveOutClose"() {
      let closed = 0;
      const system = createAudioSystem();
      const device = system.openWaveOut(conformanceFormat, { callback: (message) => { if (message === audioMessage.wom_close) closed += 1; } });
      device.close();
      return { return_value: closed, last_error: 0 };
    },
    "dsound.dll!IDirectSoundBuffer::Play"() {
      const system = createAudioSystem();
      const buffer = system.createSoundBuffer({ format: conformanceFormat, byte_count: frame * 2 });
      fillSoundBuffer(buffer, frame, 0.5);
      buffer.play(false);
      system.render(1);
      return { return_value: buffer.is_playing() ? 1 : 0, last_error: 0 };
    },
    "dsound.dll!IDirectSoundBuffer::Stop"() {
      const system = createAudioSystem();
      const buffer = system.createSoundBuffer({ format: conformanceFormat, byte_count: frame * 2 });
      fillSoundBuffer(buffer, frame, 0.5);
      buffer.play(false);
      system.render(1);
      buffer.stop();
      return { return_value: buffer.is_playing() ? 1 : 0, last_error: 0 };
    },
    "dsound.dll!IDirectSoundBuffer::SetVolume"() {
      const system = createAudioSystem();
      const buffer = system.createSoundBuffer({ format: conformanceFormat, byte_count: frame * 2 });
      fillSoundBuffer(buffer, frame, 0.5);
      buffer.setVolume(directSoundBound.volume_min_mb); // silence
      buffer.play(false);
      const { output } = system.render(64);
      return { return_value: peakOf(output, 1, 0) > 1e-6 ? 1 : 0, last_error: 0 };
    },
    "dsound.dll!IDirectSoundBuffer::SetPan"() {
      const system = createAudioSystem();
      const buffer = system.createSoundBuffer({ format: conformanceFormat, byte_count: frame * 2 });
      fillSoundBuffer(buffer, frame, 0.5);
      buffer.setPan(directSoundBound.pan_max_mb); // attenuate the left channel to silence
      buffer.play(false);
      const { output } = system.render(64);
      return { return_value: peakOf(output, 2, 0) > 1e-6 ? 1 : 0, last_error: 0 };
    },
    "dsound.dll!IDirectSoundBuffer::GetCurrentPosition"() {
      const system = createAudioSystem();
      const buffer = system.createSoundBuffer({ format: conformanceFormat, byte_count: frame * 2 });
      fillSoundBuffer(buffer, frame, 0.5);
      buffer.play(false);
      system.render(100);
      return { return_value: buffer.getCurrentPosition().play_cursor_byte, last_error: 0 };
    },
    "xaudio2.dll!IXAudio2SourceVoice::SubmitSourceBuffer"() {
      const system = createAudioSystem();
      const voice = system.createSourceVoice({ format: conformanceFormat, mastering_voice: system.createMasteringVoice() });
      voice.submitSourceBuffer({ byte: constantPcm16(256, 0.5) });
      return { return_value: voice.getState().buffer_queued_count, last_error: 0 };
    },
    "xaudio2.dll!IXAudio2SourceVoice::Start"() {
      const system = createAudioSystem();
      const voice = system.createSourceVoice({ format: conformanceFormat, mastering_voice: system.createMasteringVoice() });
      voice.submitSourceBuffer({ byte: constantPcm16(256, 0.5) });
      voice.start();
      system.render(256); // drains the queue
      return { return_value: voice.getState().buffer_queued_count, last_error: 0 };
    },
    "xaudio2.dll!IXAudio2SourceVoice::Stop"() {
      const system = createAudioSystem();
      const voice = system.createSourceVoice({ format: conformanceFormat, mastering_voice: system.createMasteringVoice() });
      voice.submitSourceBuffer({ byte: constantPcm16(256, 0.5) });
      voice.start();
      system.render(64); // partial, then stop must not dequeue
      voice.stop();
      return { return_value: voice.getState().buffer_queued_count, last_error: 0 };
    },
  };

  return function audioConformanceImplementation(library, symbol) {
    const key = `${library}!${symbol}`;
    const run = handler[key];
    if (!run) throw audioError("audio_export_unknown", `No audio export handler for ${key}`);
    return run();
  };
}

// The oracle: one case per audio export, expected values pinned to the
// deterministic mini-scenario above.
export function buildAudioConformanceCaseTable() {
  const parse = (key) => ({ library: key.slice(0, key.indexOf("!")), symbol: key.slice(key.indexOf("!") + 1) });
  const expected = {
    "winmm.dll!waveOutOpen": { return_value: 1, last_error: 0 },
    "winmm.dll!waveOutWrite": { return_value: 1, last_error: 0 },
    "winmm.dll!waveOutReset": { return_value: 1, last_error: 0 },
    "winmm.dll!waveOutClose": { return_value: 1, last_error: 0 },
    "dsound.dll!IDirectSoundBuffer::Play": { return_value: 1, last_error: 0 },
    "dsound.dll!IDirectSoundBuffer::Stop": { return_value: 0, last_error: 0 },
    "dsound.dll!IDirectSoundBuffer::SetVolume": { return_value: 0, last_error: 0 },
    "dsound.dll!IDirectSoundBuffer::SetPan": { return_value: 0, last_error: 0 },
    "dsound.dll!IDirectSoundBuffer::GetCurrentPosition": { return_value: 200, last_error: 0 },
    "xaudio2.dll!IXAudio2SourceVoice::SubmitSourceBuffer": { return_value: 1, last_error: 0 },
    "xaudio2.dll!IXAudio2SourceVoice::Start": { return_value: 0, last_error: 0 },
    "xaudio2.dll!IXAudio2SourceVoice::Stop": { return_value: 1, last_error: 0 },
  };
  return listAudioExport().map((key, index) => {
    const { library, symbol } = parse(key);
    return { case_id: `AUDIO-${String(index + 1).padStart(3, "0")}`, library, symbol, input: [], expected: expected[key] };
  });
}
