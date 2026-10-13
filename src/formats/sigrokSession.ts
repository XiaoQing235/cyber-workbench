import type { ByteSource } from "../core/bytes/ByteSource";
import { toBlob } from "../core/bytes/sources";
import { readZip, zipEntryData } from "../core/archive/zip";

const MAX_SESSION = 8 * 1024 * 1024;
const MAX_SAMPLES = 100_000;
const MAX_VCD = 2 * 1024 * 1024;

export interface SigrokSessionReport {
  sampleRateHz: number;
  samples: number;
  probes: number;
  transitions: number;
  lastTick: number;
  timescale: "1 ns";
}

/** Read a single-device, one-byte-per-sample sigrok session with a 1ns-compatible sample rate. */
export async function sigrokSessionToVcd(source: ByteSource, signal?: AbortSignal): Promise<{ vcd: Uint8Array<ArrayBuffer>; report: SigrokSessionReport }> {
  if (!Number.isSafeInteger(source.size) || source.size < 22 || source.size > MAX_SESSION) throw new Error("sigrok session exceeds its 8 MiB budget");
  if (signal?.aborted) throw signal.reason;
  const entries = await readZip(await toBlob(source));
  if (entries.length < 2 || entries.length > 8 || new Set(entries.map((entry) => entry.name)).size !== entries.length) {
    throw new Error("sigrok session needs a bounded unique entry set");
  }
  const metadata = entries.find((entry) => entry.name === "metadata");
  const logic = entries.find((entry) => entry.name === "logic-1");
  const version = entries.find((entry) => entry.name === "version");
  if (!metadata || !logic || !version || entries.some((entry) => !["metadata", "logic-1", "version"].includes(entry.name))) {
    throw new Error("sigrok session supports only metadata, version and a single logic-1 stream");
  }
  if (version.size < 1 || version.size > 16 || new TextDecoder("ascii").decode(await (await zipEntryData(version, 16)).arrayBuffer()).trim() !== "2") {
    throw new Error("sigrok session version 2 is required");
  }
  if (metadata.size > 64 * 1024 || logic.size < 1 || logic.size > MAX_SAMPLES ||
    ![0, 8].includes(logic.method) || logic.compressedSize > MAX_SAMPLES) {
    throw new Error("sigrok session metadata or stored/deflated logic samples exceed their budget");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(await (await zipEntryData(metadata, 64 * 1024)).arrayBuffer());
  const sections = new Map<string, Map<string, string>>();
  let current: Map<string, string> | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#") || line.startsWith(";")) continue;
    const heading = /^\[([a-z0-9 -]+)\]$/i.exec(line.trim());
    if (heading) {
      if (sections.has(heading[1].toLowerCase())) throw new Error("sigrok metadata repeats an INI section");
      current = new Map();
      sections.set(heading[1].toLowerCase(), current);
      continue;
    }
    const match = /^([a-z0-9 -]+)=(.*)$/i.exec(line);
    if (!match || !current || current.has(match[1].trim().toLowerCase())) throw new Error("sigrok metadata contains malformed or duplicate keys");
    current.set(match[1].trim().toLowerCase(), match[2].trim());
  }
  if (sections.has("device 2") || sections.size > 2) throw new Error("sigrok session supports one digital device");
  const device = sections.get("device 1");
  if (!device) throw new Error("sigrok session has no device 1 metadata");
  if (device.get("capturefile") !== "logic-1" || (device.has("total analog") && device.get("total analog") !== "0")) {
    throw new Error("sigrok session needs a single digital capturefile named logic-1");
  }
  const rate = /^(\d+(?:\.\d+)?)\s*(hz|khz|mhz|ghz)$/i.exec(device.get("samplerate") ?? "");
  if (!rate) throw new Error("sigrok sample rate must have Hz, kHz, MHz or GHz units");
  const sampleRateHz = Number(rate[1]) * ({ hz: 1, khz: 1e3, mhz: 1e6, ghz: 1e9 } as Record<string, number>)[rate[2].toLowerCase()];
  const period = 1e9 / sampleRateHz;
  if (!Number.isSafeInteger(period) || period < 1 || period * (logic.size - 1) > Number.MAX_SAFE_INTEGER) {
    throw new Error("sigrok sample rate cannot be represented at 1 ns resolution");
  }
  const probes: { name: string; id: string }[] = [];
  for (let i = 1; i <= 8; i++) {
    const name = device.get(`probe${i}`);
    if (!name) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/.test(name)) throw new Error("sigrok probe name is invalid");
    probes.push({ name, id: String.fromCharCode(32 + i) });
  }
  if (!probes.length || probes.some((probe, i) => i > 0 && probes.slice(0, i).some((prior) => prior.name === probe.name))) {
    throw new Error("sigrok session needs unique digital probes");
  }
  if (device.get("unitsize") !== "1" || device.get("total probes") !== String(probes.length) ||
    probes.some((_, i) => !device.has(`probe${i + 1}`))) throw new Error("sigrok session supports contiguous 1-byte digital probes only");
  const raw = new Uint8Array(await (await zipEntryData(logic, MAX_SAMPLES)).arrayBuffer());
  if (signal?.aborted) throw signal.reason;
  const lines = ["$timescale 1 ns $end", "$scope module sigrok $end", ...probes.map(({ name, id }) => `$var wire 1 ${id} ${name} $end`),
    "$upscope $end", "$enddefinitions $end"];
  let previous = -1;
  let transitions = 0;
  for (let index = 0; index < raw.length; index++) {
    if ((index & 0x3fff) === 0 && signal?.aborted) throw signal.reason;
    if ((raw[index] >> probes.length) !== 0) throw new Error("sigrok logic sample contains bits outside declared probes");
    if (raw[index] === previous) continue;
    lines.push(`#${index * period}`);
    for (let probe = 0; probe < probes.length; probe++) {
      const bit = 1 << probe;
      if (previous < 0 || (raw[index] & bit) !== (previous & bit)) {
        if (++transitions > MAX_SAMPLES) throw new Error("sigrok session exceeds its transition budget");
        lines.push(`${raw[index] & bit ? 1 : 0}${probes[probe].id}`);
      }
    }
    previous = raw[index];
  }
  const vcd = new TextEncoder().encode(`${lines.join("\n")}\n`);
  if (vcd.length > MAX_VCD) throw new Error("sigrok VCD output exceeds 2 MiB");
  return { vcd, report: { sampleRateHz, samples: raw.length, probes: probes.length, transitions,
    lastTick: (raw.length - 1) * period, timescale: "1 ns" } };
}
