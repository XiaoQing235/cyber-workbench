import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

export const MAX_LNK_BYTES = 2 * 1024 * 1024;
const HEADER_ID = [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
const WINDOWS_TO_UNIX_TICKS = 116444736000000000n;

export interface LnkTime {
  filetime: string;
  utc: string;
}

export interface LnkReport {
  targetPath: string | null;
  targetSource: "environment" | "relative-path" | "link-info" | "unresolved";
  networkShare: string | null;
  relativePath: string | null;
  workingDirectory: string | null;
  description: string | null;
  arguments: string | null;
  iconLocation: string | null;
  idListBytes: number;
  hasLinkInfo: boolean;
  flags: number;
  fileAttributes: number;
  fileSize: number;
  created: LnkTime | null;
  accessed: LnkTime | null;
  modified: LnkTime | null;
}

function fileTime(view: DataView, offset: number): LnkTime | null {
  const ticks = view.getBigUint64(offset, true);
  if (ticks === 0n) return null;
  const since = ticks - WINDOWS_TO_UNIX_TICKS;
  let milliseconds = since / 10_000n;
  let remainder = since % 10_000n;
  if (remainder < 0n) { milliseconds--; remainder += 10_000n; }
  const date = new Date(Number(milliseconds));
  if (!Number.isFinite(date.getTime())) throw new Error("LNK FILETIME is outside the supported date range");
  return { filetime: ticks.toString(), utc: date.toISOString().replace(/Z$/, `${String(remainder / 10n).padStart(3, "0")}Z`) };
}

function linkInfoString(bytes: Bytes, start: number, size: number, offset: number, unicode: boolean): string | null {
  if (offset === 0) return null;
  if (offset >= size) throw new Error("LNK LinkInfo path offset exceeds its section");
  const data = bytes.subarray(start + offset, start + size);
  let end = 0;
  if (unicode) {
    while (end + 1 < data.length && (data[end] !== 0 || data[end + 1] !== 0)) end += 2;
    if (end + 1 >= data.length) throw new Error("LNK Unicode LinkInfo path is unterminated");
  } else {
    end = data.indexOf(0);
    if (end < 0) throw new Error("LNK LinkInfo path is unterminated");
  }
  if (end > 2_048) throw new Error("LNK LinkInfo path exceeds 2,048 bytes");
  return new TextDecoder(unicode ? "utf-16le" : "windows-1252", { fatal: true }).decode(data.subarray(0, end));
}

export async function inspectLnk(source: ByteSource, signal?: AbortSignal): Promise<LnkReport> {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_LNK_BYTES);
  if (bytes.length < 80) throw new Error("LNK header is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== 0x4c || !HEADER_ID.every((byte, index) => bytes[4 + index] === byte)) throw new Error("Input is not a ShellLink file");
  const flags = view.getUint32(20, true);
  const unicode = (flags & 0x80) !== 0;
  let offset = 76;
  let idListBytes = 0;
  if (flags & 0x01) {
    if (offset + 2 > bytes.length) throw new Error("LNK ID list is truncated");
    idListBytes = view.getUint16(offset, true);
    offset += 2 + idListBytes;
    if (offset > bytes.length) throw new Error("LNK ID list exceeds the file");
  }
  let localBasePath: string | null = null;
  let pathSuffix: string | null = null;
  let networkShare: string | null = null;
  if (flags & 0x02) {
    if (offset + 28 > bytes.length) throw new Error("LNK LinkInfo is truncated");
    const size = view.getUint32(offset, true);
    const headerSize = view.getUint32(offset + 4, true);
    if (size < 28 || headerSize < 28 || headerSize > size || size > bytes.length - offset) throw new Error("LNK LinkInfo has invalid bounds");
    const localOffset = view.getUint32(offset + 16, true);
    const networkOffset = view.getUint32(offset + 20, true);
    const suffixOffset = view.getUint32(offset + 24, true);
    const localUnicode = headerSize >= 36 ? view.getUint32(offset + 28, true) : 0;
    const suffixUnicode = headerSize >= 36 ? view.getUint32(offset + 32, true) : 0;
    if ([localOffset, suffixOffset, localUnicode, suffixUnicode].some((entry) => entry !== 0 && entry < headerSize)) throw new Error("LNK LinkInfo path points into its header");
    localBasePath = linkInfoString(bytes, offset, size, localUnicode || localOffset, !!localUnicode);
    pathSuffix = linkInfoString(bytes, offset, size, suffixUnicode || suffixOffset, !!suffixUnicode);
    if (networkOffset !== 0) {
      if (networkOffset < headerSize || networkOffset + 20 > size) throw new Error("LNK network LinkInfo offset is invalid");
      const networkStart = offset + networkOffset;
      const networkSize = view.getUint32(networkStart, true);
      if (networkSize < 20 || networkSize > size - networkOffset) throw new Error("LNK network LinkInfo extent is invalid");
      const nameOffset = view.getUint32(networkStart + 8, true);
      const nameUnicode = nameOffset > 20 && networkSize >= 28 ? view.getUint32(networkStart + 20, true) : 0;
      if (nameOffset < 20 || (nameUnicode !== 0 && nameUnicode < 28)) throw new Error("LNK network name points into its header");
      networkShare = linkInfoString(bytes, networkStart, networkSize, nameUnicode || nameOffset, !!nameUnicode);
    }
    offset += size;
  }
  const strings: (string | null)[] = [];
  for (const flag of [0x04, 0x08, 0x10, 0x20, 0x40]) {
    if (!(flags & flag)) { strings.push(null); continue; }
    if (offset + 2 > bytes.length) throw new Error("LNK StringData length is truncated");
    const count = view.getUint16(offset, true);
    const length = count * (unicode ? 2 : 1);
    offset += 2;
    if (length > 32_768 || length > bytes.length - offset) throw new Error("LNK StringData exceeds its bounded extent");
    const value = new TextDecoder(unicode ? "utf-16le" : "windows-1252", { fatal: true }).decode(bytes.subarray(offset, offset + length));
    if (value.includes("\0")) throw new Error("LNK StringData contains an embedded NUL");
    strings.push(value);
    offset += length;
  }
  let environmentTarget: string | null = null;
  while (offset + 4 <= bytes.length) {
    const size = view.getUint32(offset, true);
    if (size === 0) { offset += 4; break; }
    if (size < 8 || size > bytes.length - offset) throw new Error("LNK ExtraData block exceeds the file");
    if (view.getUint32(offset + 4, true) === 0xa0000001) {
      if (size !== 788 || environmentTarget !== null) throw new Error("LNK environment target block is invalid or duplicated");
      environmentTarget = linkInfoString(bytes, offset, size, 268, true) || linkInfoString(bytes, offset, size, 8, false);
    }
    offset += size;
  }
  if (offset !== bytes.length) throw new Error("LNK has incomplete or trailing ExtraData");
  const [description, relativePath, workingDirectory, args, iconLocation] = strings;
  const absolute = (value: string | null): value is string => !!value && /^(?:[a-zA-Z]:[\\/]|\\\\)/.test(value);
  const linkInfoPath = absolute(localBasePath) ? localBasePath + (pathSuffix ?? "")
    : absolute(networkShare) && pathSuffix ? `${networkShare}${networkShare.endsWith("\\") ? "" : "\\"}${pathSuffix}` : null;
  const targetPath = absolute(environmentTarget) ? environmentTarget : absolute(relativePath) ? relativePath : linkInfoPath;
  const targetSource = absolute(environmentTarget) ? "environment" : absolute(relativePath) ? "relative-path" : linkInfoPath ? "link-info" : "unresolved";
  if (signal?.aborted) throw signal.reason;
  return {
    targetPath, targetSource, networkShare, relativePath, workingDirectory, description, arguments: args, iconLocation,
    idListBytes, hasLinkInfo: (flags & 0x02) !== 0, flags, fileAttributes: view.getUint32(24, true), fileSize: view.getUint32(52, true),
    created: fileTime(view, 28), accessed: fileTime(view, 36), modified: fileTime(view, 44),
  };
}