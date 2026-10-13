import type { ByteSource } from "../core/bytes/ByteSource";
import { inspectEvtx } from "./evtx";

/** Inventory candidate inline name records anchored by plausible BinXML element/attribute tokens. */
export async function evtxInlineNames(source: ByteSource, chunkIndex: number, recordIndex: number,
  signal?: AbortSignal): Promise<{ names: { offset: number; name: string; kind: "element" | "attribute" }[];
    fieldsMapped: false; candidateNames: true }> {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= 256 ||
    !Number.isSafeInteger(recordIndex) || recordIndex < 0 || recordIndex >= 4096) throw new Error("EVTX record index exceeds its budget");
  const chunk = (await inspectEvtx(source, chunkIndex + 1, signal, recordIndex + 1)).chunks[chunkIndex];
  const record = chunk?.records[recordIndex];
  if (!record) throw new Error("EVTX selected record is missing");
  if (!chunk.headerChecksumValid || !chunk.dataChecksumValid) throw new Error("EVTX selected chunk checksum is invalid");
  if (record.bytes < 28 || record.bytes > 65536 - 512) throw new Error("EVTX selected BinXML extent is invalid");
  const bytes = await source.read(record.offset + 24, record.bytes - 28);
  if (signal?.aborted) throw signal.reason;
  if (bytes.length !== record.bytes - 28 || bytes.length < 42) throw new Error("EVTX BinXML is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const base = record.offset - (4096 + chunkIndex * 65536) + 24;
  if (bytes[0] !== 0x0f || bytes[1] !== 1 || bytes[2] !== 1 || bytes[3] !== 0 || bytes[4] !== 0x0c ||
    bytes[5] !== 1 || view.getUint32(10, true) !== base + 14) throw new Error("EVTX has no supported inline template");
  const templateBytes = view.getUint32(34, true);
  const end = 38 + templateBytes;
  if (templateBytes > 32768 || end + 4 > bytes.length || bytes[38] !== 0x0f || bytes[end - 1] !== 0) {
    throw new Error("EVTX inline template exceeds its bounds");
  }
  const names: { offset: number; name: string; kind: "element" | "attribute" }[] = [];
  const decoder = new TextDecoder("utf-16le", { fatal: true });
  for (let at = 38; at + 12 < end && names.length < 128; at++) {
    if (signal?.aborted) throw signal.reason;
    const token = bytes[at];
    const kind = token === 1 || token === 0x41 ? "element" : token === 6 ? "attribute" : null;
    if (!kind) continue;
    const pointer = view.getUint32(at + (kind === "element" ? 7 : 1), true);
    const local = pointer - base;
    if (local <= at || local + 10 > end || view.getUint32(local, true) >= 65536) continue;
    const length = view.getUint16(local + 6, true);
    if (!length || length > 128 || local + 10 + length * 2 > end || view.getUint16(local + 8 + length * 2, true) !== 0) continue;
    const name = decoder.decode(bytes.subarray(local + 8, local + 8 + length * 2));
    if (!/^[A-Za-z_][A-Za-z0-9_:-]*$/.test(name)) continue;
    if (!names.some((item) => item.offset === pointer)) names.push({ offset: pointer, name, kind });
  }
  return { names, fieldsMapped: false, candidateNames: true };
}
