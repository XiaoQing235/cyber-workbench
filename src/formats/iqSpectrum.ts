import type { ByteSource } from "../core/bytes/ByteSource";

export const MAX_IQ_BYTES = 16 * 1024 * 1024;

export interface IqSpectrumReport {
  sampleFormat: "interleaved-u8-iq";
  sampleRate: number;
  totalFrames: number;
  startFrame: number;
  fftSize: number;
  window: "hann" | "rectangular";
  binWidthHz: number;
  peaks: { bin: number; frequencyHz: number; levelDbfs: number }[];
}

export async function spectrumIqU8(source: ByteSource, sampleRate: number, startFrame: number, fftSize: number,
  window: "hann" | "rectangular", peakCount: number, signal?: AbortSignal): Promise<IqSpectrumReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 512 || source.size > MAX_IQ_BYTES || source.size % 2 !== 0) {
    throw new Error("Unsigned-8-bit IQ input requires bounded interleaved I/Q pairs");
  }
  const totalFrames = source.size / 2;
  if (!Number.isSafeInteger(sampleRate) || sampleRate < 8_000 || sampleRate > 192_000 ||
    !Number.isSafeInteger(startFrame) || startFrame < 0 || !Number.isSafeInteger(fftSize) || fftSize < 256 || fftSize > 8_192 ||
    (fftSize & (fftSize - 1)) !== 0 || !Number.isSafeInteger(peakCount) || peakCount < 1 || peakCount > 32 ||
    (window !== "hann" && window !== "rectangular") || startFrame + fftSize > totalFrames) {
    throw new Error("IQ sample rate, FFT window or peak budget is invalid");
  }
  const bytes = await source.read(startFrame * 2, fftSize * 2);
  if (bytes.length !== fftSize * 2) throw new Error("IQ sample window is truncated");
  const { default: FFT } = await import("fft.js");
  const fft = new FFT(fftSize);
  const input = fft.createComplexArray();
  const output = fft.createComplexArray();
  let windowSum = 0;
  for (let frame = 0; frame < fftSize; frame++) {
    const weight = window === "hann" ? 0.5 - 0.5 * Math.cos(2 * Math.PI * frame / (fftSize - 1)) : 1;
    input[frame * 2] = (bytes[frame * 2] - 127.5) / 127.5 * weight;
    input[frame * 2 + 1] = (bytes[frame * 2 + 1] - 127.5) / 127.5 * weight;
    windowSum += weight;
  }
  if (signal?.aborted) throw signal.reason;
  fft.transform(output, input);
  const peaks = Array.from({ length: fftSize }, (_, bin) => ({ bin,
    frequencyHz: (bin < fftSize / 2 ? bin : bin - fftSize) * sampleRate / fftSize,
    levelDbfs: Math.round(20 * Math.log10(Math.max(1e-8, Math.hypot(output[bin * 2], output[bin * 2 + 1]) / windowSum)) * 100) / 100,
  })).sort((left, right) => right.levelDbfs - left.levelDbfs || left.bin - right.bin).slice(0, peakCount);
  return { sampleFormat: "interleaved-u8-iq", sampleRate, totalFrames, startFrame, fftSize, window, binWidthHz: sampleRate / fftSize, peaks };
}