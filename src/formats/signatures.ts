import type { ByteSource } from "../core/bytes/ByteSource";

export interface Signature {
  type: string;
  description: string;
  /** Bytes to match; null matches any byte. */
  magic: readonly (number | null)[];
  offset?: number;
  /** Long enough to be meaningful when found inside other data. */
  embeddable?: boolean;
  /** Extra check for short magics, so a match inside other data is not just chance. */
  validate?: (bytes: Uint8Array, at: number) => boolean;
}

const ascii = (text: string): number[] => [...text].map((c) => c.charCodeAt(0));
const any = (count: number): null[] => Array<null>(count).fill(null);

export const SIGNATURES: readonly Signature[] = [
  { type: "png", description: "PNG image", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], embeddable: true },
  {
    type: "jpeg",
    description: "JPEG image",
    magic: [0xff, 0xd8, 0xff],
    embeddable: true,
    // The next byte must be a marker that can follow SOI (APPn, DQT, DHT, SOF…).
    validate: (bytes, at) => bytes[at + 3] >= 0xc0 && bytes[at + 3] <= 0xfe,
  },
  { type: "gif", description: "GIF image", magic: ascii("GIF8"), embeddable: true },
  { type: "bmp", description: "BMP image (weak: 2-byte signature)", magic: ascii("BM") },
  { type: "webp", description: "WebP image", magic: [...ascii("RIFF"), ...any(4), ...ascii("WEBP")] },
  { type: "wav", description: "WAV audio", magic: [...ascii("RIFF"), ...any(4), ...ascii("WAVE")] },
  { type: "avi", description: "AVI video", magic: [...ascii("RIFF"), ...any(4), ...ascii("AVI ")] },
  { type: "tiff", description: "TIFF image (little-endian)", magic: [0x49, 0x49, 0x2a, 0x00] },
  { type: "tiff", description: "TIFF image (big-endian)", magic: [0x4d, 0x4d, 0x00, 0x2a] },
  { type: "psd", description: "Photoshop document", magic: ascii("8BPS") },
  { type: "ico", description: "Windows icon (weak)", magic: [0x00, 0x00, 0x01, 0x00] },
  { type: "zip", description: "ZIP archive (local file header)", magic: [0x50, 0x4b, 0x03, 0x04], embeddable: true },
  { type: "zip", description: "ZIP archive (empty)", magic: [0x50, 0x4b, 0x05, 0x06] },
  { type: "gzip", description: "gzip stream", magic: [0x1f, 0x8b, 0x08], embeddable: true },
  { type: "bzip2", description: "bzip2 stream", magic: [...ascii("BZh"), null, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59], embeddable: true },
  { type: "xz", description: "xz stream", magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], embeddable: true },
  { type: "7z", description: "7-Zip archive", magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], embeddable: true },
  { type: "rar", description: "RAR archive", magic: [...ascii("Rar!"), 0x1a, 0x07], embeddable: true },
  { type: "tar", description: "tar archive", magic: ascii("ustar"), offset: 257 },
  { type: "pdf", description: "PDF document", magic: ascii("%PDF-"), embeddable: true },
  { type: "rtf", description: "RTF document", magic: ascii("{\\rtf") },
  { type: "elf", description: "ELF executable", magic: [0x7f, 0x45, 0x4c, 0x46], embeddable: true },
  { type: "pe", description: "DOS/Windows executable (MZ, weak)", magic: ascii("MZ") },
  { type: "macho", description: "Mach-O executable (64-bit)", magic: [0xcf, 0xfa, 0xed, 0xfe] },
  { type: "macho", description: "Mach-O executable (32-bit)", magic: [0xce, 0xfa, 0xed, 0xfe] },
  {
    type: "macho",
    description: "Mach-O universal binary",
    magic: [0xca, 0xfe, 0xba, 0xbe],
    // Shares its magic with Java classes: a fat header's slice count is small, a class file's version is not.
    validate: (bytes, at) => bytes[at + 4] === 0 && bytes[at + 5] === 0 && bytes[at + 6] === 0 && bytes[at + 7] > 0 && bytes[at + 7] <= 32,
  },
  {
    type: "class",
    description: "Java class file",
    magic: [0xca, 0xfe, 0xba, 0xbe],
    validate: (bytes, at) => ((bytes[at + 6] << 8) | bytes[at + 7]) >= 45,
  },
  { type: "dex", description: "Android DEX", magic: ascii("dex\n") },
  { type: "wasm", description: "WebAssembly module", magic: [0x00, 0x61, 0x73, 0x6d] },
  { type: "lua", description: "Lua bytecode", magic: [0x1b, 0x4c, 0x75, 0x61] },
  { type: "pcap", description: "pcap capture (little-endian)", magic: [0xd4, 0xc3, 0xb2, 0xa1] },
  { type: "pcap", description: "pcap capture (big-endian)", magic: [0xa1, 0xb2, 0xc3, 0xd4] },
  { type: "pcap", description: "pcap capture (nanosecond)", magic: [0x4d, 0x3c, 0xb2, 0xa1] },
  { type: "pcapng", description: "pcapng capture", magic: [0x0a, 0x0d, 0x0d, 0x0a] },
  { type: "sqlite", description: "SQLite database", magic: [...ascii("SQLite format 3"), 0x00], embeddable: true },
  { type: "ogg", description: "Ogg container", magic: ascii("OggS") },
  { type: "flac", description: "FLAC audio", magic: ascii("fLaC") },
  { type: "mp3", description: "MP3 with ID3 tag", magic: ascii("ID3") },
  { type: "midi", description: "MIDI audio", magic: ascii("MThd") },
  { type: "xml", description: "XML document", magic: ascii("<?xml") },
  { type: "bom-utf8", description: "UTF-8 text with BOM", magic: [0xef, 0xbb, 0xbf] },
  { type: "bom-utf16le", description: "UTF-16LE text with BOM", magic: [0xff, 0xfe] },
  { type: "bom-utf16be", description: "UTF-16BE text with BOM", magic: [0xfe, 0xff] },
];

export function matchesAt(bytes: Uint8Array, at: number, magic: readonly (number | null)[]): boolean {
  if (at + magic.length > bytes.length) return false;
  for (let i = 0; i < magic.length; i++) {
    const expected = magic[i];
    if (expected !== null && bytes[at + i] !== expected) return false;
  }
  return true;
}

/** zlib header check from RFC 1950: CM = 8 and the 16-bit header is a multiple of 31. */
export function looksLikeZlib(bytes: Uint8Array, at = 0): boolean {
  if (at + 2 > bytes.length) return false;
  const cmf = bytes[at];
  const flg = bytes[at + 1];
  return (cmf & 0x0f) === 8 && cmf >> 4 <= 7 && ((cmf << 8) | flg) % 31 === 0;
}

const EMBEDDABLE = SIGNATURES.filter((signature) => signature.embeddable && (signature.offset ?? 0) === 0);
const BY_FIRST_BYTE = new Map<number, Signature[]>();
for (const signature of EMBEDDABLE) {
  const first = signature.magic[0];
  if (first !== null) BY_FIRST_BYTE.set(first, [...(BY_FIRST_BYTE.get(first) ?? []), signature]);
}
const LONGEST_MAGIC = Math.max(...EMBEDDABLE.map((signature) => signature.magic.length));

export interface SignatureHit {
  signature: Signature;
  offset: number;
}

/** Embeddable signatures starting anywhere in [start, end), read in chunks. */
export async function scanSignatures(
  source: ByteSource,
  options: { start: number; end: number; maxHits: number; chunkSize?: number; signal?: AbortSignal },
): Promise<SignatureHit[]> {
  const chunkSize = options.chunkSize ?? 4 * 1024 * 1024;
  const hits: SignatureHit[] = [];
  for (let base = options.start; base < options.end && hits.length < options.maxHits; base += chunkSize) {
    options.signal?.throwIfAborted();
    const window = await source.read(base, Math.min(chunkSize + LONGEST_MAGIC, source.size - base));
    const limit = Math.min(chunkSize, options.end - base, window.length);
    for (let i = 0; i < limit && hits.length < options.maxHits; i++) {
      for (const signature of BY_FIRST_BYTE.get(window[i]) ?? []) {
        if (matchesAt(window, i, signature.magic) && (signature.validate?.(window, i) ?? true)) hits.push({ signature, offset: base + i });
      }
    }
  }
  return hits;
}
