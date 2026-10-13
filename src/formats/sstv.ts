import type { ByteSource } from "../core/bytes/ByteSource";
import { inspectWav, type WavInfo } from "./wavSpectrum";

const VIS_DURATION_MS = 910;
const VIS_MODES: Record<number, string> = { 8: "Robot 36", 44: "Martin M1" };

export interface SstvVisReport {
  wav: WavInfo;
  channel: number;
  startFrame: number;
  mode: number;
  modeName: string | null;
  bits: number[];
  parityBit: number;
  verified: true;
  tones: { segment: string; classifiedHz: number; levelDbfs: number }[];
}

export async function decodeSstvVis(source: ByteSource, channel: number, startFrame: number, minLevelDbfs: number, signal?: AbortSignal): Promise<SstvVisReport> {
  const wav = await inspectWav(source, signal);
  if (!Number.isSafeInteger(channel) || channel < 0 || channel >= wav.channels || !Number.isSafeInteger(startFrame) || startFrame < 0 ||
    !Number.isFinite(minLevelDbfs) || minLevelDbfs < -80 || minLevelDbfs > -5 ||
    startFrame + Math.ceil(wav.sampleRate * VIS_DURATION_MS / 1000) > wav.frames) throw new Error("SSTV VIS channel, start frame, level or 910 ms header extent is invalid");
  const tones: SstvVisReport["tones"] = [];
  let elapsedMs = 0;
  const classify = async (segment: string, durationMs: number, frequencies: readonly number[]): Promise<number> => {
    if (signal?.aborted) throw signal.reason;
    const frames = Math.floor(wav.sampleRate * Math.min(18, durationMs * 0.6) / 1000);
    const center = startFrame + Math.round(wav.sampleRate * (elapsedMs + durationMs / 2) / 1000);
    const first = center - Math.floor(frames / 2);
    elapsedMs += durationMs;
    const pcm = await source.read(wav.dataOffset + first * wav.channels * 2, frames * wav.channels * 2);
    if (pcm.length !== frames * wav.channels * 2) throw new Error(`SSTV ${segment} tone window is truncated`);
    const view = new DataView(pcm.buffer, pcm.byteOffset, pcm.byteLength);
    const samples = new Float64Array(frames);
    let windowSum = 0;
    for (let index = 0; index < frames; index++) {
      const weight = 0.5 - 0.5 * Math.cos(2 * Math.PI * index / (frames - 1));
      samples[index] = view.getInt16(index * wav.channels * 2 + channel * 2, true) / 32768 * weight;
      windowSum += weight;
    }
    const levels = frequencies.map((frequencyHz) => {
      const coefficient = 2 * Math.cos(2 * Math.PI * frequencyHz / wav.sampleRate);
      let previous = 0;
      let beforePrevious = 0;
      for (const sample of samples) {
        const current = sample + coefficient * previous - beforePrevious;
        beforePrevious = previous;
        previous = current;
      }
      const power = Math.max(0, previous ** 2 + beforePrevious ** 2 - coefficient * previous * beforePrevious);
      return { frequencyHz, levelDbfs: 20 * Math.log10(Math.max(1e-9, 2 * Math.sqrt(power) / windowSum)) };
    }).sort((left, right) => right.levelDbfs - left.levelDbfs);
    if (levels[0].levelDbfs < minLevelDbfs || levels[0].levelDbfs - levels[1].levelDbfs < 3) {
      throw new Error(`SSTV ${segment} tone is too quiet or ambiguous`);
    }
    tones.push({ segment, classifiedHz: levels[0].frequencyHz, levelDbfs: Math.round(levels[0].levelDbfs * 100) / 100 });
    return levels[0].frequencyHz;
  };
  for (const [segment, duration, expected] of [["leader", 300, 1900], ["break", 10, 1200], ["leader", 300, 1900], ["start", 30, 1200]] as const) {
    if (await classify(segment, duration, [expected, expected === 1900 ? 1200 : 1900]) !== expected) throw new Error(`SSTV VIS ${segment} tone is invalid`);
  }
  const bits: number[] = [];
  for (let index = 0; index < 7; index++) bits.push(await classify(`bit ${index}`, 30, [1100, 1300]) === 1100 ? 1 : 0);
  const parityBit = await classify("parity", 30, [1100, 1300]) === 1100 ? 1 : 0;
  if (parityBit !== bits.reduce((sum, bit) => sum + bit, 0) % 2) throw new Error("SSTV VIS parity check failed");
  if (await classify("stop", 30, [1200, 1900]) !== 1200) throw new Error("SSTV VIS stop tone is invalid");
  const mode = bits.reduce((value, bit, index) => value | (bit << index), 0);
  return { wav, channel, startFrame, mode, modeName: VIS_MODES[mode] ?? null, bits, parityBit, verified: true, tones };
}