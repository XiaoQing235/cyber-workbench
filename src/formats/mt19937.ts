import type { Bytes } from "../core/bytes/ByteSource";

const STATE_WORDS = 624;
const MAX_OBSERVED = STATE_WORDS + 32;

export interface MtRecovery {
  observed: number;
  verified: boolean;
  state: Bytes;
  next: number[];
}

function undoRight(value: number, shift: number): number {
  let result = value;
  for (let attempt = 0; attempt < 6; attempt++) result = value ^ (result >>> shift);
  return result >>> 0;
}

function undoLeft(value: number, shift: number, mask: number): number {
  let result = value;
  for (let attempt = 0; attempt < 6; attempt++) result = value ^ ((result << shift) & mask);
  return result >>> 0;
}

function untemper(value: number): number {
  let result = undoRight(value, 18);
  result = undoLeft(result, 15, 0xefc60000);
  result = undoLeft(result, 7, 0x9d2c5680);
  return undoRight(result, 11);
}

function temper(value: number): number {
  let result = value ^ (value >>> 11);
  result ^= (result << 7) & 0x9d2c5680;
  result ^= (result << 15) & 0xefc60000;
  return (result ^ (result >>> 18)) >>> 0;
}

function twist(state: Uint32Array): void {
  for (let index = 0; index < STATE_WORDS; index++) {
    const combined = (state[index] & 0x80000000) | (state[(index + 1) % STATE_WORDS] & 0x7fffffff);
    state[index] = (state[(index + 397) % STATE_WORDS] ^ (combined >>> 1) ^ ((combined & 1) ? 0x9908b0df : 0)) >>> 0;
  }
}

function parseOutput(value: unknown, index: number): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff) return value;
  if (typeof value === "string" && /^(?:0|[1-9][0-9]{0,9})$/.test(value)) {
    const parsed = Number(value);
    if (parsed <= 0xffffffff) return parsed;
  }
  throw new Error(`MT19937 output ${index} must be an unsigned 32-bit integer`);
}

export function recoverMt19937(text: string, predictCount: number): MtRecovery {
  if (!Number.isSafeInteger(predictCount) || predictCount < 1 || predictCount > 32) throw new Error("MT19937 prediction count must be between 1 and 32");
  let values: unknown;
  if (text.trimStart().startsWith("[")) {
    try { values = JSON.parse(text); }
    catch { throw new Error("MT19937 observations are not valid JSON"); }
  } else values = text.replace(/\r/g, "").split("\n").filter(Boolean);
  if (!Array.isArray(values) || values.length < STATE_WORDS || values.length > MAX_OBSERVED) throw new Error("MT19937 recovery requires 624 to 656 consecutive outputs");
  const observations = values.map(parseOutput);
  const recovered = Uint32Array.from(observations.slice(0, STATE_WORDS), untemper);
  const state = new Uint8Array(STATE_WORDS * 4);
  const view = new DataView(state.buffer);
  for (let index = 0; index < STATE_WORDS; index++) view.setUint32(index * 4, recovered[index], true);
  const predictedState = recovered.slice();
  twist(predictedState);
  let position = 0;
  const nextOutput = () => {
    if (position === STATE_WORDS) { twist(predictedState); position = 0; }
    return temper(predictedState[position++]);
  };
  for (let index = STATE_WORDS; index < observations.length; index++) {
    if (nextOutput() !== observations[index]) throw new Error(`MT19937 state does not reproduce observed output ${index}`);
  }
  const next = Array.from({ length: predictCount }, nextOutput);
  return { observed: observations.length, verified: observations.length > STATE_WORDS, state, next };
}