import type { ByteSource } from "../core/bytes/ByteSource";

export const MAX_ESE_BYTES = 512 * 1024 * 1024;
const MIN_HEADER = 668;
const MAGIC = 0x89abcdef;

export interface EseHeaderReport {
  format: "ESE/ESENT";
  pageBytes: number;
  fileBytes: number;
  version: string;
  revision: number;
  state: "created" | "dirty" | "clean" | "converting" | "force-detach";
  fileType: "database";
  primaryChecksumValid: boolean;
  shadowMatchesPrimary: boolean;
  tablesDecoded: false;
  pagesDecoded: false;
}

/** Inspect the ESE/ESENT database header only. This does not decode SRUM tables or ESE pages. */
export async function inspectEseHeader(source: ByteSource, signal?: AbortSignal): Promise<EseHeaderReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 2 * 2048 || source.size > MAX_ESE_BYTES) {
    throw new Error("ESE database is outside its size budget");
  }
  if (signal?.aborted) throw signal.reason;
  const prefix = await source.read(0, MIN_HEADER);
  if (prefix.length !== MIN_HEADER) throw new Error("ESE file header is truncated");
  const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
  if (view.getUint32(4, true) !== MAGIC || view.getUint32(12, true) !== 0) throw new Error("Not an ESE database file header");
  const pageBytes = view.getUint32(236, true);
  if (![2048, 4096, 8192, 16384, 32768].includes(pageBytes) || source.size < 2 * pageBytes || source.size % pageBytes !== 0) {
    throw new Error("ESE page size or file extent is invalid");
  }
  const stateId = view.getUint32(52, true);
  const states: Record<number, EseHeaderReport["state"]> = { 1: "created", 2: "dirty", 3: "clean", 4: "converting", 5: "force-detach" };
  if (!states[stateId]) throw new Error("ESE database state is unsupported");
  const first = await source.read(0, pageBytes);
  if (first.length !== pageBytes) throw new Error("ESE header page is truncated");
  const words = new DataView(first.buffer, first.byteOffset, first.byteLength);
  let checksum = MAGIC;
  for (let offset = 4; offset + 4 <= pageBytes; offset += 4) checksum ^= words.getUint32(offset, true);
  const shadow = await source.read(pageBytes, pageBytes);
  if (signal?.aborted) throw signal.reason;
  if (shadow.length !== pageBytes) throw new Error("ESE shadow header page is truncated");
  const shadowMatchesPrimary = first.every((byte, index) => byte === shadow[index]);
  return { format: "ESE/ESENT", pageBytes, fileBytes: source.size,
    version: `0x${view.getUint32(8, true).toString(16)}`, revision: view.getUint32(232, true),
    state: states[stateId], fileType: "database", primaryChecksumValid: (checksum >>> 0) === view.getUint32(0, true),
    shadowMatchesPrimary, tablesDecoded: false, pagesDecoded: false };
}
