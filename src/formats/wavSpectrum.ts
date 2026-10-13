import type { ByteSource } from "../core/bytes/ByteSource";
import type { Bytes } from "../core/bytes/ByteSource";
import { encodeRgbaPng } from "./png/encode";

export const MAX_WAV_BYTES = 512 * 1024 * 1024;

export interface WavInfo {
  channels: 1 | 2;
  sampleRate: number;
  frames: number;
  durationSeconds: number;
  dataOffset: number;
  dataBytes: number;
  trailingBytes: number;
}

export interface SpectrumReport {
  wav: WavInfo;
  channel: number;
  startFrame: number;
  fftSize: number;
  window: "hann" | "rectangular";
  binWidthHz: number;
  peaks: { bin: number; frequencyHz: number; levelDbfs: number }[];
}

export interface SpectrogramReport {
  wav: WavInfo;
  channel: number;
  startFrame: number;
  fftSize: number;
  hopFrames: number;
  windows: number;
  truncated: boolean;
  binWidthHz: number;
  levelFloorDbfs: number;
  width: number;
  height: number;
}

function ascii(bytes: Uint8Array, offset: number): string {
  return String.fromCharCode(...bytes.subarray(offset, offset + 4));
}

export async function inspectWav(source: ByteSource, signal?: AbortSignal): Promise<WavInfo> {
  if (source.size > MAX_WAV_BYTES) throw new Error("WAV input exceeds the 512 MiB limit");
  const header = await source.read(0, 12);
  if (header.length !== 12 || ascii(header, 0) !== "RIFF" || ascii(header, 8) !== "WAVE") throw new Error("Input is not a RIFF/WAVE file");
  const declaredEnd = new DataView(header.buffer).getUint32(4, true) + 8;
  if (declaredEnd < 44 || declaredEnd > source.size) throw new Error("WAV RIFF extent is invalid or truncated");
  let offset = 12;
  let format: { channels: 1 | 2; sampleRate: number; blockAlign: number } | null = null;
  let dataOffset = -1;
  let dataBytes = 0;
  for (let chunks = 0; offset < declaredEnd && chunks < 4_096; chunks++) {
    if (signal?.aborted) throw signal.reason;
    const chunk = await source.read(offset, 8);
    if (chunk.length !== 8) throw new Error("WAV chunk header is truncated");
    const size = new DataView(chunk.buffer).getUint32(4, true);
    if (size > declaredEnd - offset - 8 || size % 2 > declaredEnd - offset - 8 - size) throw new Error("WAV chunk extent or padding is invalid");
    const name = ascii(chunk, 0);
    if (name === "fmt ") {
      if (format || size < 16 || size > 40) throw new Error("WAV format chunk is duplicated or unsupported");
      const contents = await source.read(offset + 8, 16);
      const view = new DataView(contents.buffer, contents.byteOffset, contents.byteLength);
      const channels = view.getUint16(2, true);
      const sampleRate = view.getUint32(4, true);
      const blockAlign = view.getUint16(12, true);
      if (view.getUint16(0, true) !== 1 || (channels !== 1 && channels !== 2) || sampleRate < 8_000 || sampleRate > 192_000 ||
        view.getUint32(8, true) !== sampleRate * channels * 2 || blockAlign !== channels * 2 || view.getUint16(14, true) !== 16) throw new Error("WAV spectrum supports only mono/stereo PCM16 from 8 to 192 kHz");
      format = { channels, sampleRate, blockAlign };
    } else if (name === "data") {
      if (!format || dataOffset >= 0 || size % format.blockAlign !== 0) throw new Error("WAV data chunk is duplicate, misaligned, or precedes fmt");
      dataOffset = offset + 8;
      dataBytes = size;
    }
    offset += 8 + size + (size % 2);
  }
  if (offset !== declaredEnd || !format || dataOffset < 0 || dataBytes === 0) throw new Error("WAV chunks, fmt, or sample data are incomplete");
  const frames = dataBytes / format.blockAlign;
  return { channels: format.channels, sampleRate: format.sampleRate, frames, durationSeconds: frames / format.sampleRate, dataOffset, dataBytes, trailingBytes: source.size - declaredEnd };
}

export async function spectrumWav(source: ByteSource, channel: number, startFrame: number, fftSize: number, window: "hann" | "rectangular", peakCount: number, signal?: AbortSignal): Promise<SpectrumReport> {
  const wav = await inspectWav(source, signal);
  if (!Number.isSafeInteger(channel) || channel < 0 || channel >= wav.channels || !Number.isSafeInteger(startFrame) || startFrame < 0 ||
    !Number.isSafeInteger(fftSize) || fftSize < 256 || fftSize > 8_192 || (fftSize & (fftSize - 1)) !== 0 ||
    !Number.isSafeInteger(peakCount) || peakCount < 1 || peakCount > 32 || startFrame + fftSize > wav.frames) throw new Error("WAV channel, sample window, or FFT parameters are invalid");
  const levels = await spectrumBins(source, wav, channel, startFrame, fftSize, window, signal);
  const peaks = levels.map((levelDbfs, bin) => ({ bin, frequencyHz: bin * wav.sampleRate / fftSize, levelDbfs: Math.round(levelDbfs * 100) / 100 }))
    .sort((first, second) => second.levelDbfs - first.levelDbfs || first.bin - second.bin).slice(0, peakCount);
  return { wav, channel, startFrame, fftSize, window, binWidthHz: wav.sampleRate / fftSize, peaks };
}

async function spectrumBins(source: ByteSource, wav: WavInfo, channel: number, startFrame: number, fftSize: number, window: "hann" | "rectangular", signal?: AbortSignal): Promise<number[]> {
  const blockAlign = wav.channels * 2;
  const pcm = await source.read(wav.dataOffset + startFrame * blockAlign, fftSize * blockAlign);
  if (pcm.length !== fftSize * blockAlign) throw new Error("WAV sample window is truncated");
  const view = new DataView(pcm.buffer, pcm.byteOffset, pcm.byteLength);
  const samples = new Array<number>(fftSize);
  let windowSum = 0;
  for (let index = 0; index < fftSize; index++) {
    const weight = window === "hann" ? 0.5 - 0.5 * Math.cos(2 * Math.PI * index / (fftSize - 1)) : 1;
    samples[index] = view.getInt16(index * blockAlign + channel * 2, true) / 32768 * weight;
    windowSum += weight;
  }
  if (signal?.aborted) throw signal.reason;
  const { default: FFT } = await import("fft.js");
  const fft = new FFT(fftSize);
  const spectrum = fft.createComplexArray();
  fft.realTransform(spectrum, samples);
  fft.completeSpectrum(spectrum);
  return Array.from({ length: fftSize / 2 + 1 }, (_, bin) => {
    const magnitude = Math.hypot(spectrum[bin * 2], spectrum[bin * 2 + 1]) * (bin === 0 || bin === fftSize / 2 ? 1 : 2) / windowSum;
    return 20 * Math.log10(Math.max(magnitude, 1e-6));
  });
}

export async function spectrogramWav(source: ByteSource, channel: number, startFrame: number, fftSize: number, hopFrames: number, maxWindows: number, window: "hann" | "rectangular", levelFloorDbfs: number, signal?: AbortSignal): Promise<{ png: Bytes; report: SpectrogramReport }> {
  const wav = await inspectWav(source, signal);
  if (!Number.isSafeInteger(channel) || channel < 0 || channel >= wav.channels || !Number.isSafeInteger(startFrame) || startFrame < 0 ||
    !Number.isSafeInteger(fftSize) || fftSize < 256 || fftSize > 8_192 || (fftSize & (fftSize - 1)) !== 0 ||
    !Number.isSafeInteger(hopFrames) || hopFrames < 1 || hopFrames > 8_192 || !Number.isSafeInteger(maxWindows) || maxWindows < 1 || maxWindows > 128 ||
    !Number.isSafeInteger(levelFloorDbfs) || levelFloorDbfs < 20 || levelFloorDbfs > 120 || startFrame + fftSize > wav.frames) throw new Error("WAV spectrogram selection or budget is invalid");
  const available = Math.floor((wav.frames - startFrame - fftSize) / hopFrames) + 1;
  const windows = Math.min(available, maxWindows);
  const height = fftSize / 2 + 1;
  const rgba = new Uint8Array(windows * height * 4);
  for (let column = 0; column < windows; column++) {
    if (signal?.aborted) throw signal.reason;
    const levels = await spectrumBins(source, wav, channel, startFrame + column * hopFrames, fftSize, window, signal);
    for (let bin = 0; bin < height; bin++) {
      const intensity = Math.round(255 * Math.max(0, Math.min(1, (levels[bin] + levelFloorDbfs) / levelFloorDbfs)));
      const offset = ((height - 1 - bin) * windows + column) * 4;
      rgba[offset] = rgba[offset + 1] = rgba[offset + 2] = intensity;
      rgba[offset + 3] = 255;
    }
  }
  const png = await encodeRgbaPng(windows, height, rgba, signal);
  return {
    png,
    report: { wav, channel, startFrame, fftSize, hopFrames, windows, truncated: available > windows, binWidthHz: wav.sampleRate / fftSize, levelFloorDbfs: -levelFloorDbfs, width: windows, height },
  };
}