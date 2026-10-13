import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { MemorySource, readAll } from "../core/bytes/sources";

const MAX_CSV_BYTES = 2 * 1024 * 1024;
const MAX_ROWS = 50_000;
const MAX_TRANSITIONS = 100_000;
const encoder = new TextEncoder();

export interface SaleaeVcdReport {
  timescale: "1 ns";
  rows: number;
  transitions: number;
  lastTick: number;
  channels: { original: string; signal: string }[];
}

export async function saleaeDigitalCsvToVcd(source: ByteSource, signal?: AbortSignal): Promise<{ vcd: Bytes; report: SaleaeVcdReport }> {
  if (signal?.aborted) throw signal.reason;
  const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(source, MAX_CSV_BYTES));
  const { default: Papa } = await import("papaparse");
  const parsed = Papa.parse<string[]>(text, { delimiter: ",", skipEmptyLines: "greedy", dynamicTyping: false });
  if (parsed.errors.length || parsed.data.length < 2 || parsed.data.length > MAX_ROWS + 1) throw new Error("Saleae digital CSV is malformed or exceeds the row budget");
  const [header, ...rows] = parsed.data;
  if (header[0] !== "Time [s]" || header.length < 2 || header.length > 17 || header.slice(1).some((name) => !name.trim() || name.length > 128)) {
    throw new Error("Saleae digital CSV needs Time [s] and 1 to 16 named channels");
  }
  const used = new Set<string>();
  const channels = header.slice(1).map((original, index) => {
    const base = original.trim().replace(/[^A-Za-z0-9_$]/g, "_");
    let signalName = base;
    for (let suffix = 1; used.has(signalName); suffix++) signalName = `${base}_${suffix}`;
    used.add(signalName);
    return { original, signal: `saleae.${signalName}`, id: String.fromCharCode(33 + index), name: signalName };
  });
  const lines = ["$timescale 1 ns $end", "$scope module saleae $end",
    ...channels.map((channel) => `$var wire 1 ${channel.id} ${channel.name} $end`),
    "$upscope $end", "$enddefinitions $end"];
  let lastTick = -1;
  let transitions = 0;
  let values: string[] = [];
  for (const [index, row] of rows.entries()) {
    if ((index & 0x3fff) === 0 && signal?.aborted) throw signal.reason;
    if (row.length !== header.length || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(row[0])) throw new Error(`Saleae CSV row ${index + 2} has invalid columns or timestamp`);
    const seconds = Number(row[0]);
    const nanoseconds = seconds * 1e9;
    const tick = Math.round(nanoseconds);
    if (!Number.isSafeInteger(tick) || tick <= lastTick || Math.abs(nanoseconds - tick) > 1e-4) {
      throw new Error(`Saleae CSV row ${index + 2} loses timing at 1 ns resolution or is out of order`);
    }
    const next = row.slice(1).map((state) => state.trim().toLowerCase());
    if (next.some((state) => state !== "0" && state !== "1" && state !== "x")) throw new Error(`Saleae CSV row ${index + 2} has an invalid digital value`);
    lines.push(`#${tick}`);
    for (let channel = 0; channel < next.length; channel++) {
      if (next[channel] !== values[channel]) {
        if (++transitions > MAX_TRANSITIONS) throw new Error("Saleae CSV exceeds the VCD transition budget");
        lines.push(`${next[channel]}${channels[channel].id}`);
      }
    }
    values = next;
    lastTick = tick;
  }
  const vcd = encoder.encode(`${lines.join("\n")}\n`);
  if (vcd.length > MAX_CSV_BYTES) throw new Error("Converted VCD exceeds the 2 MiB budget");
  return { vcd, report: { timescale: "1 ns", rows: rows.length, transitions, lastTick,
    channels: channels.map(({ original, signal: name }) => ({ original, signal: name })) } };
}

/** Strict subset of sigrok-cli CSV digital exports (time in seconds plus 1–16 logic probes). */
export async function sigrokDigitalCsvToVcd(source: ByteSource, signal?: AbortSignal): Promise<{ vcd: Bytes; report: SaleaeVcdReport }> {
  if (signal?.aborted) throw signal.reason;
  const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(source, MAX_CSV_BYTES));
  const { default: Papa } = await import("papaparse");
  const parsed = Papa.parse<string[]>(text, { delimiter: ",", skipEmptyLines: "greedy", dynamicTyping: false });
  if (parsed.errors.length || parsed.data.length < 2 || parsed.data.length > MAX_ROWS + 1) throw new Error("sigrok digital CSV is malformed or exceeds the row budget");
  const [header, ...rows] = parsed.data;
  if (!/^(?:Time|time|Time \[s\])$/.test(header[0]) || header.length < 2 || header.length > 17 ||
    header.slice(1).some((name) => !/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(name))) {
    throw new Error("sigrok digital CSV needs a seconds time column and 1–16 named probes");
  }
  const normalized = Papa.unparse([["Time [s]", ...header.slice(1)], ...rows]);
  const result = await saleaeDigitalCsvToVcd(new MemorySource(encoder.encode(normalized)), signal);
  const vcd = encoder.encode(new TextDecoder().decode(result.vcd).replace("$scope module saleae $end", "$scope module sigrok $end"));
  return { vcd, report: { ...result.report, channels: result.report.channels.map((channel) => ({
    ...channel, signal: channel.signal.replace(/^saleae\./, "sigrok."),
  })) } };
}
