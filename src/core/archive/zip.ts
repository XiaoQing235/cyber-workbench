import { BlobSource } from "../bytes/sources";
import { CRC32_INITIAL, crc32Finish, crc32Update } from "../checksum/crc32";
import { inflate } from "../compression/inflate";

/** Minimal ZIP support: writes stored (uncompressed) entries, reads stored and deflated ones. No ZIP64. */

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const UTF8_NAMES = 0x0800;
// 1980-01-01 00:00, the earliest DOS date, so identical inputs give identical archives.
const DOS_DATE = (0 << 9) | (1 << 5) | 1;
const MAX_32 = 0xffffffff;
const READ_CHUNK = 4 * 1024 * 1024;

export class ZipError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ZipError";
  }
}

export interface ZipInput {
  name: string;
  data: Blob;
}

export interface ZipEntry {
  name: string;
  method: number;
  crc32: number;
  compressedSize: number;
  size: number;
  /** The stored (possibly compressed) bytes, as a lazy slice of the archive. */
  raw: Blob;
}

async function crcOfBlob(blob: Blob): Promise<number> {
  let register = CRC32_INITIAL;
  for (let offset = 0; offset < blob.size; offset += READ_CHUNK) {
    register = crc32Update(register, new Uint8Array(await blob.slice(offset, offset + READ_CHUNK).arrayBuffer()));
  }
  return crc32Finish(register);
}

function header(size: number, fill: (view: DataView) => void): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(size);
  fill(new DataView(bytes.buffer));
  return bytes;
}

/** Builds the archive as a Blob composed of the inputs, so large entries are never copied into memory. */
export async function writeZip(inputs: readonly ZipInput[]): Promise<Blob> {
  if (inputs.length > 0xffff) throw new ZipError("Too many entries for a ZIP without ZIP64");
  const encoder = new TextEncoder();
  const parts: BlobPart[] = [];
  const central: Uint8Array<ArrayBuffer>[] = [];
  let offset = 0;
  for (const input of inputs) {
    const name = encoder.encode(input.name);
    const size = input.data.size;
    if (size >= MAX_32 || offset >= MAX_32) throw new ZipError("Archive too large for a ZIP without ZIP64");
    const crc = await crcOfBlob(input.data);
    const common = (view: DataView, at: number) => {
      view.setUint16(at, 20, true);
      view.setUint16(at + 2, UTF8_NAMES, true);
      view.setUint16(at + 4, 0, true);
      view.setUint16(at + 6, 0, true);
      view.setUint16(at + 8, DOS_DATE, true);
      view.setUint32(at + 10, crc, true);
      view.setUint32(at + 14, size, true);
      view.setUint32(at + 18, size, true);
      view.setUint16(at + 22, name.length, true);
    };
    const local = header(30 + name.length, (view) => {
      view.setUint32(0, LOCAL_HEADER, true);
      common(view, 4);
    });
    local.set(name, 30);
    central.push(
      header(46 + name.length, (view) => {
        view.setUint32(0, CENTRAL_HEADER, true);
        view.setUint16(4, 20, true);
        common(view, 6);
        view.setUint32(42, offset, true);
      }),
    );
    central[central.length - 1].set(name, 46);
    parts.push(local, input.data);
    offset += local.length + size;
  }
  const centralSize = central.reduce((sum, entry) => sum + entry.length, 0);
  if (offset + centralSize >= MAX_32) throw new ZipError("Archive too large for a ZIP without ZIP64");
  const end = header(22, (view) => {
    view.setUint32(0, END_OF_CENTRAL_DIRECTORY, true);
    view.setUint16(8, inputs.length, true);
    view.setUint16(10, inputs.length, true);
    view.setUint32(12, centralSize, true);
    view.setUint32(16, offset, true);
  });
  return new Blob([...parts, ...central, end], { type: "application/zip" });
}

async function readBytes(blob: Blob, start: number, length: number): Promise<DataView> {
  if (start < 0 || start + length > blob.size) throw new ZipError("Truncated ZIP archive");
  return new DataView(await blob.slice(start, start + length).arrayBuffer());
}

/** Lists entries from the central directory. Entry data stays in the archive Blob until read. */
export async function readZip(archive: Blob): Promise<ZipEntry[]> {
  const tailLength = Math.min(archive.size, 22 + 0xffff);
  const tail = await readBytes(archive, archive.size - tailLength, tailLength);
  let end = -1;
  for (let i = tailLength - 22; i >= 0; i--) {
    if (tail.getUint32(i, true) === END_OF_CENTRAL_DIRECTORY) {
      end = i;
      break;
    }
  }
  if (end < 0) throw new ZipError("Not a ZIP archive (no end of central directory)");
  const count = tail.getUint16(end + 10, true);
  const centralSize = tail.getUint32(end + 12, true);
  const centralOffset = tail.getUint32(end + 16, true);
  if (centralOffset === MAX_32 || count === 0xffff) throw new ZipError("ZIP64 archives are not supported");

  const directory = await readBytes(archive, centralOffset, centralSize);
  const decoder = new TextDecoder();
  const entries: ZipEntry[] = [];
  let at = 0;
  for (let index = 0; index < count; index++) {
    if (at + 46 > directory.byteLength || directory.getUint32(at, true) !== CENTRAL_HEADER) {
      throw new ZipError(`Corrupt central directory at entry ${index}`);
    }
    const flags = directory.getUint16(at + 8, true);
    const method = directory.getUint16(at + 10, true);
    const crc = directory.getUint32(at + 16, true);
    const compressedSize = directory.getUint32(at + 20, true);
    const size = directory.getUint32(at + 24, true);
    const nameLength = directory.getUint16(at + 28, true);
    const extraLength = directory.getUint16(at + 30, true);
    const commentLength = directory.getUint16(at + 32, true);
    const localOffset = directory.getUint32(at + 42, true);
    const name = decoder.decode(new Uint8Array(directory.buffer, directory.byteOffset + at + 46, nameLength));
    at += 46 + nameLength + extraLength + commentLength;

    if (flags & 1) throw new ZipError(`Entry ${name} is encrypted`);
    if (method !== 0 && method !== 8) throw new ZipError(`Entry ${name} uses unsupported compression method ${method}`);
    const local = await readBytes(archive, localOffset, 30);
    if (local.getUint32(0, true) !== LOCAL_HEADER) throw new ZipError(`Corrupt local header for ${name}`);
    const dataStart = localOffset + 30 + local.getUint16(26, true) + local.getUint16(28, true);
    if (dataStart + compressedSize > archive.size) throw new ZipError(`Entry ${name} extends past the end of the archive`);
    entries.push({ name, method, crc32: crc, compressedSize, size, raw: archive.slice(dataStart, dataStart + compressedSize) });
  }
  return entries;
}

/** Entry contents with the CRC verified. Stored entries stay a lazy slice of the archive. */
export async function zipEntryData(entry: ZipEntry, maxInflatedBytes: number): Promise<Blob> {
  let data = entry.raw;
  if (entry.method === 8) {
    const result = await inflate(new BlobSource(entry.raw), "deflate-raw", { maxOutputBytes: maxInflatedBytes });
    if (result.error) throw new ZipError(`Entry ${entry.name} is corrupt: ${result.error}`);
    data = new Blob([result.bytes]);
  }
  if (data.size !== entry.size) throw new ZipError(`Entry ${entry.name} has the wrong size`);
  if ((await crcOfBlob(data)) !== entry.crc32) throw new ZipError(`Entry ${entry.name} fails its CRC check`);
  return data;
}
