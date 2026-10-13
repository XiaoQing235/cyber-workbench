import type { ByteSource } from "../core/bytes/ByteSource";

export const MAX_PREFETCH_BYTES = 8 * 1024 * 1024;
const FILETIME_UNIX_OFFSET = 116444736000000000n;

export interface PrefetchReport {
  version: 17 | 23 | 26 | 30;
  variant: 1 | 2 | null;
  executable: string;
  hash: string;
  declaredBytes: number;
  runCount: number;
  lastRun: { filetime: string; utc: string } | null;
  olderRuns: { filetime: string; utc: string }[];
}

function fileTime(value: bigint): PrefetchReport["lastRun"] {
  if (value === 0n) return null;
  const since = value - FILETIME_UNIX_OFFSET;
  let milliseconds = since / 10_000n;
  let remainder = since % 10_000n;
  if (remainder < 0n) { milliseconds--; remainder += 10_000n; }
  const date = new Date(Number(milliseconds));
  if (!Number.isFinite(date.getTime())) throw new Error("Prefetch FILETIME exceeds the supported date range");
  return { filetime: value.toString(), utc: date.toISOString().replace(/Z$/, `${String(remainder / 10n).padStart(3, "0")}Z`) };
}

export async function inspectPrefetch(source: ByteSource, signal?: AbortSignal): Promise<PrefetchReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 152 || source.size > MAX_PREFETCH_BYTES) throw new Error("Prefetch file exceeds the header or 8 MiB budget");
  const header = await source.read(0, 84);
  if (header.length !== 84) throw new Error("Prefetch header is truncated");
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (String.fromCharCode(...header.subarray(0, 3)) === "MAM") throw new Error("Compressed MAM Prefetch is unsupported");
  if (String.fromCharCode(...header.subarray(4, 8)) !== "SCCA") throw new Error("Not an uncompressed SCCA Prefetch file");
  const version = view.getUint32(0, true);
  if (version !== 17 && version !== 23 && version !== 26 && version !== 30) throw new Error(`Prefetch version ${version} is unsupported`);
  const metricsField = version === 30 ? await source.read(84, 4) : null;
  if (metricsField && metricsField.length !== 4) throw new Error("Prefetch v30 information header is truncated");
  const metricsOffset = metricsField ? new DataView(metricsField.buffer, metricsField.byteOffset, 4).getUint32(0, true) : 0;
  const variant = version === 30 ? metricsOffset === 304 ? 1 : metricsOffset === 296 ? 2 : null : null;
  if (version === 30 && variant === null) throw new Error("Prefetch v30 file information variant is unsupported");
  const minimum = version === 30 ? variant === 1 ? 304 : 296 : ({ 17: 152, 23: 240, 26: 304 } as const)[version];
  if (source.size < minimum || view.getUint32(12, true) !== source.size) throw new Error("Prefetch file information is truncated or the declared extent differs");
  const name = header.subarray(16, 76);
  let terminated = 0;
  while (terminated + 1 < name.length && (name[terminated] !== 0 || name[terminated + 1] !== 0)) terminated += 2;
  if (terminated === 0 || terminated + 1 >= name.length) throw new Error("Prefetch executable name is empty or unterminated");
  const executable = new TextDecoder("utf-16le", { fatal: true }).decode(name.subarray(0, terminated));
  if (/[\x00-\x1f\x7f]/.test(executable)) throw new Error("Prefetch executable name contains control characters");
  const info = await source.read(84, minimum - 84);
  if (info.length !== minimum - 84) throw new Error("Prefetch versioned file information is truncated");
  const details = new DataView(info.buffer, info.byteOffset, info.byteLength);
  const getTime = (absolute: number): PrefetchReport["lastRun"] => fileTime(details.getBigUint64(absolute - 84, true));
  const lastRun = getTime(version === 17 ? 0x78 : 0x80);
  const olderRuns: PrefetchReport["olderRuns"] = [];
  if (version === 26 || version === 30) {
    for (let index = 0; index < 7; index++) {
      const time = getTime(0x88 + index * 8);
      if (time) olderRuns.push(time);
    }
  }
  if (signal?.aborted) throw signal.reason;
  return {
    version, variant, executable, hash: `0x${view.getUint32(76, true).toString(16).padStart(8, "0")}`,
    declaredBytes: source.size, runCount: details.getUint32((version === 17 ? 0x90 : version === 23 ? 0x98 : version === 30 && variant === 2 ? 0xc8 : 0xd0) - 84, true),
    lastRun, olderRuns,
  };
}
