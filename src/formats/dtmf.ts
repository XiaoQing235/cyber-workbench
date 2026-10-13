import type { ByteSource } from "../core/bytes/ByteSource";
import { inspectWav, spectrumWav, type SpectrumReport } from "./wavSpectrum";

const LOW = [697, 770, 852, 941];
const HIGH = [1209, 1336, 1477, 1633];
const KEYPAD = ["123A", "456B", "789C", "*0#D"];

export interface DtmfReport {
  digits: string;
  windows: number;
  ignoredWindows: number;
  truncated: boolean;
  decoded: { startFrame: number; symbol: string; lowHz: number; highHz: number; lowDbfs: number; highDbfs: number }[];
}

function strongest(peaks: SpectrumReport["peaks"], targets: number[], toleranceHz: number) {
  return targets.map((target, index) => ({ index, peak: peaks.filter((item) => Math.abs(item.frequencyHz - target) <= toleranceHz)
    .sort((first, second) => second.levelDbfs - first.levelDbfs)[0] })).filter((item) => item.peak)
    .sort((first, second) => second.peak.levelDbfs - first.peak.levelDbfs)[0];
}

export async function decodeWavDtmf(source: ByteSource, channel: number, startFrame: number, fftSize: number, hopFrames: number, maxWindows: number, minDbfs: number, signal?: AbortSignal): Promise<DtmfReport> {
  const wav = await inspectWav(source, signal);
  if (!Number.isSafeInteger(channel) || channel < 0 || channel >= wav.channels || !Number.isSafeInteger(startFrame) || startFrame < 0 ||
    !Number.isSafeInteger(fftSize) || fftSize < 512 || fftSize > 4_096 || (fftSize & (fftSize - 1)) !== 0 ||
    !Number.isSafeInteger(hopFrames) || hopFrames < 1 || hopFrames > 32_768 || !Number.isSafeInteger(maxWindows) || maxWindows < 1 || maxWindows > 128 ||
    !Number.isFinite(minDbfs) || minDbfs < -80 || minDbfs > -5 || startFrame + fftSize > wav.frames) throw new Error("DTMF channel, FFT window or scan budget is invalid");
  if (wav.sampleRate / fftSize > 20) throw new Error("DTMF FFT resolution must be at most 20 Hz per bin; increase FFT size or use a lower-rate WAV");
  const available = Math.floor((wav.frames - startFrame - fftSize) / hopFrames) + 1;
  const windows = Math.min(available, maxWindows);
  const decoded: DtmfReport["decoded"] = [];
  let ignoredWindows = 0;
  let previousSymbol = "";
  for (let index = 0; index < windows; index++) {
    if (signal?.aborted) throw signal.reason;
    const frame = startFrame + index * hopFrames;
    const spectrum = await spectrumWav(source, channel, frame, fftSize, "hann", 32, signal);
    const tolerance = Math.max(15, spectrum.binWidthHz * 1.5);
    const low = strongest(spectrum.peaks, LOW, tolerance);
    const high = strongest(spectrum.peaks, HIGH, tolerance);
    if (!low || !high || low.peak.levelDbfs < minDbfs || high.peak.levelDbfs < minDbfs) { ignoredWindows++; previousSymbol = ""; continue; }
    const symbol = KEYPAD[low.index][high.index];
    if (symbol !== previousSymbol) decoded.push({ startFrame: frame, symbol, lowHz: low.peak.frequencyHz, highHz: high.peak.frequencyHz,
      lowDbfs: low.peak.levelDbfs, highDbfs: high.peak.levelDbfs });
    previousSymbol = symbol;
  }
  return { digits: decoded.map((item) => item.symbol).join(""), windows, ignoredWindows, truncated: available > windows, decoded };
}