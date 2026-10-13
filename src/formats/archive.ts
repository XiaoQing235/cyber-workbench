import { readZip, zipEntryData } from "../core/archive/zip";

/** One file from an uploaded archive, read lazily. */
export interface ArchiveFile {
  path: string;
  size: number;
  read: () => Promise<Blob>;
}

const MAX_INFLATED = 512 * 1024 * 1024;

export class ArchiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArchiveError";
  }
}

function octal(field: Uint8Array): number {
  const text = new TextDecoder().decode(field).replace(/\0.*$/s, "").trim();
  if (text && !/^[0-7]+$/.test(text)) throw new ArchiveError("Tar header has an invalid octal field");
  const value = text ? parseInt(text, 8) : 0;
  if (!Number.isSafeInteger(value)) throw new ArchiveError("Tar header has an unsafe numeric field");
  return value;
}

function paxRecords(data: Uint8Array): Map<string, string> {
  const records = new Map<string, string>();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (let offset = 0; offset < data.length; ) {
    const space = data.indexOf(0x20, offset);
    if (space < offset + 1 || space > offset + 10) throw new ArchiveError("Tar PAX record has an invalid length prefix");
    const digits = decoder.decode(data.subarray(offset, space));
    if (!/^[1-9]\d*$/.test(digits)) throw new ArchiveError("Tar PAX record has an invalid length prefix");
    const length = Number(digits);
    if (!Number.isSafeInteger(length) || space + 2 >= offset + length || offset + length > data.length || data[offset + length - 1] !== 0x0a) throw new ArchiveError("Tar PAX record exceeds its header");
    const record = decoder.decode(data.subarray(space + 1, offset + length - 1));
    const separator = record.indexOf("=");
    if (separator < 1) throw new ArchiveError("Tar PAX record has no key and value");
    records.set(record.slice(0, separator), record.slice(separator + 1));
    if (records.size > 128) throw new ArchiveError("Tar PAX header exceeds the key budget");
    offset += length;
  }
  return records;
}

/** POSIX ustar / GNU / PAX tar: regular files only. */
async function readTar(archive: Blob): Promise<ArchiveFile[]> {
  const files: ArchiveFile[] = [];
  let longName: string | null = null;
  let localPax = new Map<string, string>();
  const globalPax = new Map<string, string>();
  for (let offset = 0; offset + 512 <= archive.size; ) {
    const header = new Uint8Array(await archive.slice(offset, offset + 512).arrayBuffer());
    if (header.every((byte) => byte === 0)) break;
    const expectedChecksum = octal(header.subarray(148, 156));
    const actualChecksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 0x20 : byte), 0);
    if (actualChecksum !== expectedChecksum) throw new ArchiveError("Tar header checksum is invalid");
    const size = octal(header.subarray(124, 136));
    const type = String.fromCharCode(header[156]);
    const dataStart = offset + 512;
    const next = dataStart + Math.ceil(size / 512) * 512;
    if (size > MAX_INFLATED || next > archive.size || !Number.isSafeInteger(next)) throw new ArchiveError("Tar member exceeds the archive or read budget");
    const name = new TextDecoder().decode(header.subarray(0, 100)).replace(/\0.*$/s, "");
    const prefix = new TextDecoder().decode(header.subarray(345, 500)).replace(/\0.*$/s, "");
    if (type === "x" || type === "g") {
      if (size > 4_096) throw new ArchiveError("Tar PAX header exceeds 4,096 bytes");
      const records = paxRecords(new Uint8Array(await archive.slice(dataStart, dataStart + size).arrayBuffer()));
      for (const [key, value] of records) (type === "x" ? localPax : globalPax).set(key, value);
    } else if (type === "L") {
      if (size > 4_096) throw new ArchiveError("Tar long path exceeds 4,096 bytes");
      longName = (await archive.slice(dataStart, dataStart + size).text()).replace(/\0.*$/s, "");
    } else {
      const paxSize = localPax.get("size") ?? globalPax.get("size");
      if (paxSize !== undefined && (!/^\d+$/.test(paxSize) || Number(paxSize) !== size)) throw new ArchiveError("Tar PAX size disagrees with the member header");
      const path = localPax.get("path") ?? globalPax.get("path") ?? longName ?? (prefix ? `${prefix}/${name}` : name);
      longName = null;
      localPax = new Map();
      if (type === "0" || type === "\0" || type === "7") {
        const data = archive.slice(dataStart, dataStart + size);
        files.push({ path, size, read: async () => data });
        if (files.length > 10_000) throw new ArchiveError("Tar archive exceeds the 10,000-file budget");
      }
    }
    offset = next;
  }
  return files;
}

/** Files from a ZIP or tar upload. */
export async function readArchive(archive: Blob): Promise<ArchiveFile[]> {
  const head = new Uint8Array(await archive.slice(0, 512).arrayBuffer());
  if (head[0] === 0x50 && head[1] === 0x4b) {
    return (await readZip(archive))
      .filter((entry) => !entry.name.endsWith("/"))
      .map((entry) => ({ path: entry.name, size: entry.size, read: () => zipEntryData(entry, MAX_INFLATED) }));
  }
  if (head.length >= 262 && new TextDecoder().decode(head.subarray(257, 262)) === "ustar") return readTar(archive);
  throw new ArchiveError("Upload the repository as a .zip or .tar (decompress a .tar.gz first)");
}
