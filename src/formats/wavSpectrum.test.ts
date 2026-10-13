import { describe, expect, it, vi } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectWav, spectrogramWav, spectrumWav } from "./wavSpectrum";
import { decodeWavDtmf } from "./dtmf";
import { decodeWavMorse } from "./morse";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";

vi.mock("../runtimes/ffmpeg", () => ({
  loadFFmpeg: async () => ({
    ffmpeg: {
      writeFile: async (_name: string, data: Uint8Array<ArrayBuffer>) => { structuredClone(data, { transfer: [data.buffer] }); },
      exec: async () => 0,
      readFile: async () => Uint8Array.of(82, 73, 70, 70),
    },
    dispose: () => undefined,
  }),
}));

const HEADER = Uint8Array.from(atob("UklGRiQQAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAQAAA="), (character) => character.charCodeAt(0));

function tone(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(44 + 2_048 * 2);
  bytes.set(HEADER);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < 2_048; index++) view.setInt16(44 + index * 2, Math.round(0.6 * 32767 * Math.sin(2 * Math.PI * 1_000 * index / 8_000)), true);
  return bytes;
}

function dtmfFixture(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(44 + 6_000 * 2);
  bytes.set(HEADER);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, bytes.length - 8, true);
  view.setUint32(40, 6_000 * 2, true);
  for (const [index, [low, high]] of [[697, 1209], [697, 1336], [941, 1477]].entries()) {
    const offset = index * 2_000;
    for (let frame = 0; frame < 1_600; frame++) {
      const time = frame / 8_000;
      view.setInt16(44 + (offset + frame) * 2, Math.round(32767 * 0.38 * (Math.sin(2 * Math.PI * low * time) + Math.sin(2 * Math.PI * high * time))), true);
    }
  }
  return bytes;
}

function morseFixture(words: readonly (readonly string[])[] = [["...", "---", "..."]]): Uint8Array<ArrayBuffer> {
  const units = words.flatMap((word, wordIndex) => [
    ...(wordIndex ? [[7, false] as const] : []),
    ...word.flatMap((letter, index) => [
      ...(index ? [[3, false] as const] : []),
      ...[...letter].flatMap((mark, markIndex) => [
        ...(markIndex ? [[1, false] as const] : []), [mark === "." ? 1 : 3, true] as const,
      ]),
    ]),
  ]);
  const frames = units.reduce((sum, [length]) => sum + length * 960, 0);
  const bytes = new Uint8Array(44 + frames * 2);
  bytes.set(HEADER);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, bytes.length - 8, true);
  view.setUint32(40, frames * 2, true);
  let offset = 0;
  for (const [length, active] of units) {
    for (let frame = 0; frame < length * 960; frame++) {
      const sample = active ? Math.round(32767 * 0.45 * Math.sin(2 * Math.PI * 700 * frame / 8_000)) : 0;
      view.setInt16(44 + (offset + frame) * 2, sample, true);
    }
    offset += length * 960;
  }
  return bytes;
}

describe("PCM WAV spectrum", () => {
  it("decodes Morse SOS from 120 ms keyed audio without mistaking letter gaps for words", async () => {
    const report = await decodeWavMorse(new MemorySource(morseFixture()), 0, 120, -32);
    expect(report).toMatchObject({ text: "SOS", truncated: false, dotMilliseconds: 120 });
    expect(report.symbols.map(({ code }) => code)).toEqual(["...", "---", "..."]);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "hardware.audio.morse", inputs: { data: bytesFrom(morseFixture()) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.text).toMatchObject({ type: "text", text: "SOS" });
  });

  it("keeps Morse word gaps and does not decode digital silence", async () => {
    expect((await decodeWavMorse(new MemorySource(morseFixture([["...", "---", "..."], ["...", "---", "..."]])), 0, 120, -32)).text).toBe("SOS SOS");
    const silence = morseFixture();
    silence.fill(0, 44);
    expect((await decodeWavMorse(new MemorySource(silence), 0, 120, -32)).text).toBe("");
    await expect(decodeWavMorse(new MemorySource(silence), 1, 120, -32)).rejects.toThrow(/Morse channel/);
  });
  it("reports the input byte count before FFmpeg transfers its buffer", async () => {
    const input = tone();
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "audio.ffmpeg.wav", inputs: { data: bytesFrom(input) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { inputBytes: input.length, outputBytes: 4, sampleRate: 8_000, channels: 1 } });
  });
  it("decodes independently specified dual-tone DTMF 12# windows", async () => {
    const report = await decodeWavDtmf(new MemorySource(dtmfFixture()), 0, 256, 1_024, 2_000, 8, -35);
    expect(report).toMatchObject({ digits: "12#", windows: 3, ignoredWindows: 0, truncated: false });
    expect(report.decoded.map((item) => item.symbol)).toEqual(["1", "2", "#"]);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "hardware.audio.dtmf", inputs: { data: bytesFrom(dtmfFixture()) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.text).toMatchObject({ type: "text", text: "12#" });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { windows: 3, ignoredWindows: 0 } });
  });

  it("collapses adjacent tone windows and allows the same key after silence", async () => {
    const repeated = dtmfFixture();
    const view = new DataView(repeated.buffer);
    for (let frame = 2_000; frame < 4_000; frame++) view.setInt16(44 + frame * 2, view.getInt16(44 + (frame - 2_000) * 2, true), true);
    const report = await decodeWavDtmf(new MemorySource(repeated), 0, 0, 512, 512, 12, -35);
    expect(report).toMatchObject({ digits: "11#", windows: 11, truncated: false });
    expect(report.ignoredWindows).toBeGreaterThan(0);
    expect(await decodeWavDtmf(new MemorySource(repeated), 0, 0, 512, 512, 2, -35)).toMatchObject({ digits: "1", windows: 2, truncated: true });
    await expect(decodeWavDtmf(new MemorySource(repeated), 2, 0, 512, 512, 12, -35)).rejects.toThrow(/DTMF channel/);
  });

  it("rejects FFT resolution too coarse to identify distinct DTMF rows", async () => {
    const wav = dtmfFixture();
    const view = new DataView(wav.buffer);
    view.setUint32(24, 48_000, true);
    view.setUint32(28, 96_000, true);
    await expect(decodeWavDtmf(new MemorySource(wav), 0, 0, 1_024, 1_024, 3, -35)).rejects.toThrow(/resolution/);
  });
  it("finds the 1 kHz peak of an independently produced 8 kHz PCM16 wave", async () => {
    const source = new MemorySource(tone());
    expect(await inspectWav(source)).toMatchObject({ channels: 1, sampleRate: 8_000, frames: 2_048, dataOffset: 44 });
    const result = await spectrumWav(source, 0, 0, 1_024, "hann", 5);
    expect(result).toMatchObject({ fftSize: 1_024, binWidthHz: 7.8125 });
    expect(result.peaks[0]).toMatchObject({ bin: 128, frequencyHz: 1_000 });
    expect(result.peaks[0].levelDbfs).toBeGreaterThan(-6);
    expect(result.peaks[0].levelDbfs).toBeLessThan(-2);
  });

  it("rejects a malformed block alignment and truncated RIFF extent", async () => {
    const invalid = tone();
    new DataView(invalid.buffer).setUint16(32, 4, true);
    await expect(inspectWav(new MemorySource(invalid))).rejects.toThrow(/mono\/stereo PCM16/);
    await expect(inspectWav(new MemorySource(tone().slice(0, -1)))).rejects.toThrow(/extent is invalid or truncated/);
  });

  it("selects a stereo channel and skips padded non-audio chunks", async () => {
    const stereo = tone();
    const view = new DataView(stereo.buffer);
    view.setUint16(22, 2, true);
    view.setUint32(28, 32_000, true);
    view.setUint16(32, 4, true);
    for (let frame = 0; frame < 1_024; frame++) {
      view.setInt16(44 + frame * 4, Math.round(0.6 * 32767 * Math.sin(2 * Math.PI * 437.5 * frame / 8_000)), true);
      view.setInt16(46 + frame * 4, Math.round(0.6 * 32767 * Math.sin(2 * Math.PI * 1_000 * frame / 8_000)), true);
    }
    const padded = new Uint8Array(stereo.length + 10);
    padded.set(stereo.subarray(0, 36));
    padded.set(new TextEncoder().encode("JUNK"), 36);
    new DataView(padded.buffer).setUint32(40, 1, true);
    padded[44] = 0xaa;
    padded.set(stereo.subarray(36), 46);
    new DataView(padded.buffer).setUint32(4, padded.length - 8, true);
    const source = new MemorySource(padded);
    expect(await inspectWav(source)).toMatchObject({ channels: 2, frames: 1_024, dataOffset: 54 });
    expect((await spectrumWav(source, 0, 0, 1_024, "hann", 1)).peaks[0].frequencyHz).toBe(437.5);
    expect((await spectrumWav(source, 1, 0, 1_024, "hann", 1)).peaks[0].frequencyHz).toBe(1_000);
  });

  it("places 500 Hz then 1500 Hz in separate time columns of a spectrogram", async () => {
    const wav = tone();
    const view = new DataView(wav.buffer);
    for (let frame = 0; frame < 2_048; frame++) {
      const frequency = frame < 1_024 ? 500 : 1_500;
      view.setInt16(44 + frame * 2, Math.round(0.6 * 32767 * Math.sin(2 * Math.PI * frequency * frame / 8_000)), true);
    }
    const result = await spectrogramWav(new MemorySource(wav), 0, 0, 1_024, 1_024, 2, "rectangular", 80);
    expect(result.report).toMatchObject({ windows: 2, truncated: false, width: 2, height: 513, binWidthHz: 7.8125 });
    const png = new MemorySource(result.png);
    const decoded = await decodePng(png, await parsePng(png));
    const pixel = (row: number, column: number) => decoded.image.samples[(row * 2 + column) * 4];
    expect(pixel(513 - 1 - 64, 0)).toBeGreaterThan(200);
    expect(pixel(513 - 1 - 192, 1)).toBeGreaterThan(200);
    expect(pixel(513 - 1 - 64, 1)).toBeLessThan(20);
    expect(pixel(513 - 1 - 192, 0)).toBeLessThan(20);
  });

  it("exposes sample metadata and FFT peaks through the operation registry", async () => {
    const registry = createDefaultRegistry();
    const input = { data: bytesFrom(tone()) };
    const inspection = await executeOperation(registry, { operationId: "audio.wav.inspect", inputs: input, params: {} });
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toMatchObject({ sampleRate: 8_000, frames: 2_048 });
    const result = await executeOperation(registry, {
      operationId: "audio.wav.spectrum", inputs: input,
      params: { channel: 0, startFrame: 0, fftSize: 1_024, window: "hann", peakCount: 3 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: { peaks: { frequencyHz: number }[] } }).data.peaks[0].frequencyHz).toBe(1_000);
    expect(result.run.diagnostics).toEqual(["Dominant WAV frequency 1000.00 Hz in 1024 samples."]);
  });

  it("exports a spectrogram PNG and window-bound report through the registry", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "audio.wav.spectrogram", inputs: { data: bytesFrom(tone()) },
      params: { channel: 0, startFrame: 0, fftSize: 1_024, hopFrames: 256, maxWindows: 3, window: "hann", levelFloorDbfs: 80 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({ windows: 3, truncated: true, width: 3, height: 513, levelFloorDbfs: -80 });
    const png = (result.outputs.image as { source: Parameters<typeof parsePng>[0] }).source;
    expect((await parsePng(png)).ihdr).toMatchObject({ width: 3, height: 513 });
    expect(result.run.diagnostics).toEqual(["Rendered 3 WAV time window(s) at 7.81 Hz per bin. Window limit reached."]);
  });
});