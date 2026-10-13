import type { ByteSource } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

const MAX_VCD_BYTES = 2 * 1024 * 1024;
const MAX_CHANGES = 100_000;

interface Change { tick: number; value: "0" | "1" | "x" | "z" }
interface Signal { id: string; name: string; width: number; changes: Change[] }

export interface VcdReport {
  timescale: string;
  signals: { id: string; name: string; width: number; changes: number }[];
  lastTick: number;
  scalarTransitions: number;
}

export interface UartReport {
  signal: string;
  bitTicks: number;
  bytes: number[];
  startTicks: number[];
  framingErrors: number;
  sampledBeyondLastTick: boolean;
}

export interface SpiReport {
  mode: 0;
  bitOrder: "msb";
  selectActiveLow: true;
  clock: string;
  data: string;
  select: string;
  sampledEdges: number;
  bytes: number[];
  incompleteBits: number;
}

export interface I2cReport {
  clock: string;
  data: string;
  sampledEdges: number;
  messages: {
    startTick: number;
    stopTick: number | null;
    address: number | null;
    read: boolean | null;
    addressAck: boolean | null;
    data: number[];
    dataAcks: boolean[];
    incompleteBits: number;
  }[];
}

export interface ManchesterReport {
  signal: string;
  startTick: number;
  bitTicks: number;
  convention: "ieee" | "inverted";
  sampledBits: number;
  bytes: number[];
  incompleteBits: number;
  truncated: boolean;
}

export interface NrzReport {
  signal: string;
  startTick: number;
  bitTicks: number;
  inverted: boolean;
  sampledBits: number;
  bytes: number[];
  incompleteBits: number;
  truncated: boolean;
}

export interface CanReport {
  signal: string;
  bitTicks: number;
  frames: { startTick: number; identifier: number; data: number[]; crc15: string; crcValid: true; acknowledged: boolean; stuffedBits: number }[];
  limitReached: boolean;
}

async function parseVcd(source: ByteSource, signal?: AbortSignal): Promise<{ report: VcdReport; signals: Signal[] }> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 20 || source.size > MAX_VCD_BYTES) throw new Error("VCD input exceeds the 2 MiB budget");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(source, MAX_VCD_BYTES));
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines.length > 200_000) throw new Error("VCD exceeds the line budget");
  const scopes: string[] = [];
  const signals: Signal[] = [];
  const byId = new Map<string, Signal>();
  let timescale = "";
  let definitionsEnded = false;
  let tick = 0;
  let scalarTransitions = 0;
  for (const [index, line] of lines.entries()) {
    if ((index & 0x3fff) === 0 && signal?.aborted) throw signal.reason;
    const value = line.trim();
    if (!value) continue;
    if (!definitionsEnded) {
      if (value.startsWith("$timescale")) {
        const match = /^\$timescale\s+(1|10|100)\s*(s|ms|us|ns|ps|fs)\s+\$end$/.exec(value);
        if (!match) throw new Error("VCD timescale must be a single supported directive");
        timescale = `${match[1]} ${match[2]}`;
      } else if (value.startsWith("$scope")) {
        const match = /^\$scope\s+\S+\s+(\S{1,128})\s+\$end$/.exec(value);
        if (!match || scopes.length >= 32) throw new Error("VCD scope header is malformed");
        scopes.push(match[1]);
      } else if (value === "$upscope $end") {
        if (!scopes.pop()) throw new Error("VCD scope nesting is invalid");
      } else if (value.startsWith("$var")) {
        const match = /^\$var\s+\S+\s+(\d+)\s+(\S{1,32})\s+(\S{1,128})\s+\$end$/.exec(value);
        if (!match || signals.length >= 128) throw new Error("VCD variable header exceeds the signal budget");
        const width = Number(match[1]);
        if (!Number.isSafeInteger(width) || width < 1 || width > 4096 || byId.has(match[2])) throw new Error("VCD variable width or identifier is invalid");
        const entry = { id: match[2], name: [...scopes, match[3]].join("."), width, changes: [] };
        signals.push(entry);
        byId.set(entry.id, entry);
      } else if (value === "$enddefinitions $end") definitionsEnded = true;
      continue;
    }
    if (value.startsWith("#")) {
      if (!/^#\d+$/.test(value)) throw new Error("VCD timestamp is malformed");
      const next = Number(value.slice(1));
      if (!Number.isSafeInteger(next) || next < tick) throw new Error("VCD timestamps must be monotonically increasing safe integers");
      tick = next;
      continue;
    }
    if (value.startsWith("$")) continue;
    const change = /^([01xXzZ])(\S+)$/.exec(value);
    if (!change) continue;
    const entry = byId.get(change[2]);
    if (!entry || entry.width !== 1) continue;
    if (++scalarTransitions > MAX_CHANGES) throw new Error("VCD exceeds the scalar-transition budget");
    entry.changes.push({ tick, value: change[1].toLowerCase() as Change["value"] });
  }
  if (!definitionsEnded || !timescale || signals.length === 0 || scopes.length !== 0) throw new Error("VCD header is incomplete");
  return { report: { timescale, signals: signals.map((entry) => ({ id: entry.id, name: entry.name, width: entry.width, changes: entry.changes.length })), lastTick: tick, scalarTransitions }, signals };
}

export async function inspectVcd(source: ByteSource, signal?: AbortSignal): Promise<VcdReport> {
  return (await parseVcd(source, signal)).report;
}

function valueAt(changes: Change[], sampleTick: number): Change["value"] | null {
  let low = 0;
  let high = changes.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (changes[mid].tick <= sampleTick) low = mid + 1;
    else high = mid;
  }
  return low === 0 ? null : changes[low - 1].value;
}

/** Explicitly sampled NRZ bitstream. Requires recorded coverage for every bit centre. */
export async function decodeVcdNrz(source: ByteSource, signalName: string, startTick: number, bitTicks: number,
  maxBytes: number, inverted: boolean, signal?: AbortSignal): Promise<NrzReport> {
  if (!Number.isSafeInteger(startTick) || startTick < 0 || !Number.isSafeInteger(bitTicks) || bitTicks < 2 || bitTicks > 1_000_000 ||
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4096 || typeof inverted !== "boolean") {
    throw new Error("NRZ sampling parameters exceed their bounds");
  }
  const { report, signals } = await parseVcd(source, signal);
  const selected = signals.find((entry) => entry.width === 1 && (entry.id === signalName || entry.name === signalName));
  if (!selected) throw new Error("NRZ needs a valid scalar signal ID or name");
  const bytes: number[] = [];
  let current = 0;
  let sampledBits = 0;
  const available = Math.max(0, Math.floor((report.lastTick - startTick + bitTicks / 2) / bitTicks));
  const count = Math.min(available, maxBytes * 8);
  for (let index = 0; index < count; index++) {
    if ((index & 0x3fff) === 0 && signal?.aborted) throw signal.reason;
    const sample = valueAt(selected.changes, startTick + (index + 0.5) * bitTicks);
    if (sample !== "0" && sample !== "1") throw new Error("NRZ signal is unknown at a sampled bit centre");
    current = (current << 1) | ((sample === "1" ? 1 : 0) ^ Number(inverted));
    sampledBits++;
    if (sampledBits % 8 === 0) { bytes.push(current); current = 0; }
  }
  return { signal: selected.name, startTick, bitTicks, inverted, sampledBits, bytes,
    incompleteBits: sampledBits % 8, truncated: available > maxBytes * 8 };
}

export async function decodeVcdUart(source: ByteSource, signalName: string, bitTicks: number, maxBytes: number, signal?: AbortSignal): Promise<UartReport> {
  if (!Number.isSafeInteger(bitTicks) || bitTicks < 2 || bitTicks > 1_000_000 || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4_096) throw new Error("UART bit width or output budget is invalid");
  const { report, signals } = await parseVcd(source, signal);
  const options = signals.filter((entry) => entry.width === 1);
  const selected = signalName ? options.find((entry) => entry.id === signalName || entry.name === signalName) : options.length === 1 ? options[0] : undefined;
  if (!selected) throw new Error("UART needs a valid scalar signal ID or name");
  const changes = selected.changes;
  const at = (sampleTick: number) => valueAt(changes, sampleTick);
  const bytes: number[] = [];
  const startTicks: number[] = [];
  let framingErrors = 0;
  let nextStart = 0;
  let sampledBeyondLastTick = false;
  for (let index = 1; index < changes.length; index++) {
    if (signal?.aborted) throw signal.reason;
    const start = changes[index].tick;
    if (start < nextStart || changes[index - 1].value !== "1" || changes[index].value !== "0") continue;
    if (at(start + bitTicks / 2) !== "0") continue;
    let byte = 0;
    let valid = true;
    for (let bit = 0; bit < 8; bit++) {
      const sample = at(start + (bit + 1.5) * bitTicks);
      if (sample !== "0" && sample !== "1") { valid = false; break; }
      if (sample === "1") byte |= 1 << bit;
    }
    const stop = at(start + 9.5 * bitTicks);
    if (stop !== "1") { valid = false; framingErrors++; }
    sampledBeyondLastTick ||= start + 9.5 * bitTicks > report.lastTick;
    nextStart = start + 10 * bitTicks;
    if (valid) {
      bytes.push(byte);
      startTicks.push(start);
      if (bytes.length >= maxBytes) break;
    }
  }
  return { signal: selected.name, bitTicks, bytes, startTicks, framingErrors, sampledBeyondLastTick };
}

export async function decodeVcdCan(source: ByteSource, signalName: string, bitTicks: number, maxFrames: number, startTick: number, signal?: AbortSignal): Promise<CanReport> {
  if (signalName.length > 256 || !Number.isSafeInteger(bitTicks) || bitTicks < 2 || bitTicks > 1_000_000 ||
    !Number.isSafeInteger(maxFrames) || maxFrames < 1 || maxFrames > 64 || !Number.isSafeInteger(startTick) || startTick < 0) {
    throw new Error("CAN signal, bit width or frame budget is invalid");
  }
  const { report, signals } = await parseVcd(source, signal);
  const options = signals.filter((entry) => entry.width === 1);
  const selected = signalName ? options.find((entry) => entry.id === signalName || entry.name === signalName) : options.length === 1 ? options[0] : undefined;
  if (!selected) throw new Error("CAN needs a valid scalar signal ID or name");
  const frames: CanReport["frames"] = [];
  let nextStart = startTick;
  for (let index = 1; index < selected.changes.length; index++) {
    if (signal?.aborted) throw signal.reason;
    const start = selected.changes[index].tick;
    if (start < nextStart || selected.changes[index - 1].value !== "1" || selected.changes[index].value !== "0") continue;
    if (frames.length >= maxFrames) return { signal: selected.name, bitTicks, frames, limitReached: true };
    let rawBits = 0;
    let stuffedBits = 0;
    let lastBit = -1;
    let runLength = 0;
    let crc = 0;
    const rawBit = (): number => {
      const sampleTick = start + (rawBits + 0.5) * bitTicks;
      if (sampleTick > report.lastTick) throw new Error(`CAN frame at tick ${start} extends beyond the recorded waveform`);
      const bit = valueAt(selected.changes, sampleTick);
      if (bit !== "0" && bit !== "1") throw new Error(`CAN signal is unknown at tick ${sampleTick}`);
      rawBits++;
      return bit === "1" ? 1 : 0;
    };
    const consumeStuffBit = (): void => {
      if (runLength !== 5) return;
      const bit = rawBit();
      if (bit === lastBit) throw new Error(`CAN bit stuffing is invalid in the frame at tick ${start}`);
      stuffedBits++;
      lastBit = bit;
      runLength = 1;
    };
    const unstuffedBit = (): number => {
      consumeStuffBit();
      const bit = rawBit();
      runLength = bit === lastBit ? runLength + 1 : 1;
      lastBit = bit;
      return bit;
    };
    const dataBit = (): number => {
      const bit = unstuffedBit();
      crc = ((crc << 1) & 0x7fff) ^ (((crc >>> 14) ^ bit) ? 0x4599 : 0);
      return bit;
    };
    const readBits = (count: number, next: () => number): number => {
      let value = 0;
      for (let bit = 0; bit < count; bit++) value = (value << 1) | next();
      return value;
    };
    if (dataBit() !== 0) throw new Error(`CAN start-of-frame is not dominant at tick ${start}`);
    const identifier = readBits(11, dataBit);
    const remote = dataBit();
    const extended = dataBit();
    const reserved = dataBit();
    if (remote || extended || reserved) throw new Error("Only classical 11-bit CAN data frames are supported");
    const length = readBits(4, dataBit);
    if (length > 8) throw new Error("CAN FD or reserved data lengths are unsupported");
    const data = Array.from({ length }, () => readBits(8, dataBit));
    const receivedCrc = readBits(15, unstuffedBit);
    consumeStuffBit();
    if (receivedCrc !== crc) throw new Error(`CAN frame at tick ${start} has an invalid CRC-15`);
    const crcDelimiter = rawBit();
    const acknowledgement = rawBit();
    const ackDelimiter = rawBit();
    const eof = readBits(7, rawBit);
    if (crcDelimiter !== 1 || ackDelimiter !== 1 || eof !== 0x7f) throw new Error(`CAN frame at tick ${start} has invalid delimiters or EOF`);
    frames.push({ startTick: start, identifier, data, crc15: `0x${receivedCrc.toString(16).padStart(4, "0")}`,
      crcValid: true, acknowledged: acknowledgement === 0, stuffedBits });
    nextStart = start + (rawBits + 3) * bitTicks;
  }
  return { signal: selected.name, bitTicks, frames, limitReached: false };
}

export async function decodeVcdSpi(source: ByteSource, clockName: string, dataName: string, selectName: string, maxBytes: number, signal?: AbortSignal): Promise<SpiReport> {
  if (![clockName, dataName, selectName].every((name) => name.length > 0 && name.length <= 256) || new Set([clockName, dataName, selectName]).size !== 3 ||
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4_096) throw new Error("SPI signal selection or output budget is invalid");
  const parsed = await parseVcd(source, signal);
  const find = (name: string): Signal => {
    const matched = parsed.signals.find((item) => item.width === 1 && (item.id === name || item.name === name));
    if (!matched) throw new Error(`SPI needs scalar VCD signal ${name}`);
    return matched;
  };
  const clock = find(clockName);
  const data = find(dataName);
  const select = find(selectName);
  if (new Set([clock.id, data.id, select.id]).size !== 3) throw new Error("SPI clock, data and select must be distinct signals");
  const bytes: number[] = [];
  let sampledEdges = 0;
  let accumulator = 0;
  let bits = 0;
  let selectCursor = 0;
  let selectValue: Change["value"] | null = null;
  for (let index = 1; index < clock.changes.length; index++) {
    if (signal?.aborted) throw signal.reason;
    const edge = clock.changes[index];
    if (clock.changes[index - 1].value !== "0" || edge.value !== "1") continue;
    while (selectCursor < select.changes.length && select.changes[selectCursor].tick <= edge.tick) {
      selectValue = select.changes[selectCursor++].value;
      if (selectValue === "1") {
        bits = 0;
        accumulator = 0;
      }
    }
    if (selectValue !== "0") continue;
    const value = valueAt(data.changes, edge.tick);
    if (value !== "0" && value !== "1") throw new Error("SPI data is unknown at a selected clock edge");
    accumulator = (accumulator << 1) | (value === "1" ? 1 : 0);
    sampledEdges++;
    if (++bits === 8) {
      bytes.push(accumulator);
      bits = 0;
      accumulator = 0;
      if (bytes.length >= maxBytes) break;
    }
  }
  return { mode: 0, bitOrder: "msb", selectActiveLow: true,
    clock: clock.name, data: data.name, select: select.name, sampledEdges, bytes, incompleteBits: bits };
}

export async function decodeVcdI2c(source: ByteSource, clockName: string, dataName: string, maxMessages: number, maxBytes: number, signal?: AbortSignal): Promise<I2cReport> {
  if (![clockName, dataName].every((name) => name.length > 0 && name.length <= 256) || clockName === dataName ||
    !Number.isSafeInteger(maxMessages) || maxMessages < 1 || maxMessages > 64 ||
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4_096) throw new Error("I2C signal selection or output budget is invalid");
  const parsed = await parseVcd(source, signal);
  const find = (name: string): Signal => {
    const matched = parsed.signals.find((item) => item.width === 1 && (item.id === name || item.name === name));
    if (!matched) throw new Error(`I2C needs scalar VCD signal ${name}`);
    return matched;
  };
  const clock = find(clockName);
  const data = find(dataName);
  if (clock.id === data.id) throw new Error("I2C SCL and SDA must be distinct signals");

  const events = [
    ...clock.changes.slice(1).map((change, index) => ({ kind: "clock" as const, ...change, previous: clock.changes[index].value })),
    ...data.changes.slice(1).map((change, index) => ({ kind: "data" as const, ...change, previous: data.changes[index].value })),
  ].sort((first, second) => first.tick - second.tick);
  const messages: I2cReport["messages"] = [];
  let current: I2cReport["messages"][number] | null = null;
  let sampledEdges = 0;
  let decodedBytes = 0;
  let accumulator = 0;
  let bits = 0;
  for (const [index, event] of events.entries()) {
    if ((index & 0x3fff) === 0 && signal?.aborted) throw signal.reason;
    if (index > 0 && event.tick === events[index - 1].tick) throw new Error("I2C simultaneous SCL/SDA transitions are ambiguous");
    if (event.kind === "data") {
      if (current && event.value !== "0" && event.value !== "1") throw new Error("I2C SDA is unknown during a transaction");
      if (valueAt(clock.changes, event.tick) !== "1" || event.previous === event.value) continue;
      if (event.previous === "1" && event.value === "0") {
        if (messages.length >= maxMessages) throw new Error("I2C message budget exceeded");
        if (current) current.incompleteBits = bits;
        current = { startTick: event.tick, stopTick: null, address: null, read: null, addressAck: null, data: [], dataAcks: [], incompleteBits: 0 };
        messages.push(current);
        bits = 0;
        accumulator = 0;
      } else if (event.previous === "0" && event.value === "1" && current) {
        current.incompleteBits = bits;
        current.stopTick = event.tick;
        current = null;
        bits = 0;
        accumulator = 0;
      }
      continue;
    }
    if (!current) continue;
    if (event.value !== "0" && event.value !== "1") throw new Error("I2C SCL is unknown during a transaction");
    if (event.previous !== "0" || event.value !== "1") continue;
    const next = events[index + 1];
    if (next?.kind === "data" && valueAt(clock.changes, next.tick) === "1" &&
      ((next.previous === "1" && next.value === "0") || (next.previous === "0" && next.value === "1"))) continue;
    const bit = valueAt(data.changes, event.tick);
    if (bit !== "0" && bit !== "1") throw new Error("I2C SDA is unknown at a clock edge");
    sampledEdges++;
    if (bits < 8) accumulator = (accumulator << 1) | (bit === "1" ? 1 : 0);
    if (++bits !== 9) continue;
    if (current.address === null) {
      if ((accumulator & 0xf8) === 0xf0) throw new Error("I2C 10-bit addresses are unsupported");
      current.address = accumulator >> 1;
      current.read = (accumulator & 1) === 1;
      current.addressAck = bit === "0";
    } else {
      if (++decodedBytes > maxBytes) throw new Error("I2C decoded-byte budget exceeded");
      current.data.push(accumulator);
      current.dataAcks.push(bit === "0");
    }
    bits = 0;
    accumulator = 0;
  }
  if (current) current.incompleteBits = bits;
  return { clock: clock.name, data: data.name, sampledEdges, messages };
}

export async function decodeVcdManchester(source: ByteSource, signalName: string, startTick: number, bitTicks: number, maxBytes: number, convention: "ieee" | "inverted", signal?: AbortSignal): Promise<ManchesterReport> {
  if (signalName.length < 1 || signalName.length > 256 || !Number.isSafeInteger(startTick) || startTick < 0 ||
    !Number.isSafeInteger(bitTicks) || bitTicks < 4 || bitTicks > 1_000_000 ||
    !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4_096 ||
    (convention !== "ieee" && convention !== "inverted")) throw new Error("Manchester signal selection or bit budget is invalid");
  const parsed = await parseVcd(source, signal);
  const selected = parsed.signals.find((entry) => entry.width === 1 && (entry.id === signalName || entry.name === signalName));
  if (!selected) throw new Error("Manchester needs a valid scalar signal ID or name");
  const availableBits = Math.max(0, Math.floor((parsed.report.lastTick - startTick) / bitTicks));
  const sampledBits = Math.min(availableBits, maxBytes * 8);
  const bytes: number[] = [];
  let accumulator = 0;
  for (let index = 0; index < sampledBits; index++) {
    if (signal?.aborted) throw signal.reason;
    const first = valueAt(selected.changes, startTick + (index + 0.25) * bitTicks);
    const second = valueAt(selected.changes, startTick + (index + 0.75) * bitTicks);
    if ((first !== "0" && first !== "1") || (second !== "0" && second !== "1") || first === second) {
      throw new Error(`Manchester bit ${index} lacks a known midpoint transition`);
    }
    const bit = (first === "0") !== (convention === "inverted") ? 1 : 0;
    accumulator = (accumulator << 1) | bit;
    if (index % 8 === 7) {
      bytes.push(accumulator);
      accumulator = 0;
    }
  }
  return { signal: selected.name, startTick, bitTicks, convention, sampledBits, bytes,
    incompleteBits: sampledBits % 8, truncated: availableBits > sampledBits };
}
