import type { ByteSource } from "../core/bytes/ByteSource";
import { inspectWav } from "./wavSpectrum";

const LETTERS: Record<string, string> = {
  ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
  "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
  "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", ".----": "1", "..---": "2", "...--": "3",
  "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-----": "0",
};

export interface MorseReport {
  text: string;
  symbols: { code: string; character: string; startSeconds: number }[];
  dotMilliseconds: number;
  minLevelDbfs: number;
  windowFrames: number;
  processedSeconds: number;
  truncated: boolean;
}

export async function decodeWavMorse(source: ByteSource, channel: number, dotMilliseconds: number, minLevelDbfs: number, signal?: AbortSignal): Promise<MorseReport> {
  const wav = await inspectWav(source, signal);
  if (!Number.isSafeInteger(channel) || channel < 0 || channel >= wav.channels ||
    !Number.isSafeInteger(dotMilliseconds) || dotMilliseconds < 40 || dotMilliseconds > 500 ||
    !Number.isFinite(minLevelDbfs) || minLevelDbfs < -80 || minLevelDbfs > -5) throw new Error("Morse channel, dot duration or level threshold is invalid");
  const frames = Math.min(wav.frames, wav.sampleRate * 30);
  const blockAlign = wav.channels * 2;
  const pcm = await source.read(wav.dataOffset, frames * blockAlign);
  if (pcm.length !== frames * blockAlign) throw new Error("Morse WAV sample data is truncated");
  const view = new DataView(pcm.buffer, pcm.byteOffset, pcm.byteLength);
  const windowFrames = Math.max(1, Math.round(wav.sampleRate * dotMilliseconds / 6_000));
  const runs: { active: boolean; start: number; end: number }[] = [];
  for (let start = 0; start < frames; start += windowFrames) {
    if (signal?.aborted) throw signal.reason;
    const end = Math.min(frames, start + windowFrames);
    let energy = 0;
    for (let frame = start; frame < end; frame++) {
      const sample = view.getInt16(frame * blockAlign + channel * 2, true) / 32768;
      energy += sample * sample;
    }
    const active = 20 * Math.log10(Math.max(Math.sqrt(energy / (end - start)), 1e-6)) >= minLevelDbfs;
    const previous = runs.at(-1);
    if (previous?.active === active) previous.end = end;
    else runs.push({ active, start, end });
  }
  const symbols: MorseReport["symbols"] = [];
  let text = "";
  let code = "";
  let firstFrame = 0;
  const flush = () => {
    if (!code) return;
    const character = LETTERS[code] ?? "?";
    symbols.push({ code, character, startSeconds: firstFrame / wav.sampleRate });
    text += character;
    code = "";
  };
  for (const run of runs) {
    if (signal?.aborted) throw signal.reason;
    const units = (run.end - run.start) * 1_000 / wav.sampleRate / dotMilliseconds;
    if (run.active) {
      if (units < 0.5) continue;
      if (!code) firstFrame = run.start;
      code += units >= 2 ? "-" : ".";
    } else if (units >= 5) {
      flush();
      if (text && !text.endsWith(" ")) text += " ";
    } else if (units >= 2) flush();
    if (symbols.length >= 256) break;
  }
  flush();
  return { text: text.trimEnd(), symbols, dotMilliseconds, minLevelDbfs, windowFrames,
    processedSeconds: frames / wav.sampleRate, truncated: frames < wav.frames || symbols.length >= 256 };
}
