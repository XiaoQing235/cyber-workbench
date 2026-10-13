import type { ByteSource } from "../core/bytes/ByteSource";

/** Where an embedded file ends; `end` is null when its format gives no reliable way to tell. */
export interface Extent {
  end: number | null;
  how: string;
}

const WINDOW = 1024 * 1024;

const u16be = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];
const u32be = (b: Uint8Array, o: number) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const u16le = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8);
const u32le = (b: Uint8Array, o: number) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

async function exact(source: ByteSource, offset: number, length: number): Promise<Uint8Array | null> {
  if (offset < 0 || offset + length > source.size) return null;
  return source.read(offset, length);
}

/** First offset ≥ `from` where `match(window, i)` holds, scanning in windows that overlap by `overlap` bytes. */
async function scan(source: ByteSource, from: number, overlap: number, match: (window: Uint8Array, i: number) => boolean): Promise<number | null> {
  for (let base = from; base < source.size; base += WINDOW) {
    const window = await source.read(base, WINDOW + overlap);
    const limit = Math.min(WINDOW, window.length - overlap);
    for (let i = 0; i < Math.max(limit, 0); i++) if (match(window, i)) return base + i;
    if (window.length <= overlap) break;
  }
  return null;
}

async function png(source: ByteSource, start: number): Promise<Extent> {
  let pos = start + 8;
  for (let chunks = 0; chunks < 1_000_000; chunks++) {
    const head = await exact(source, pos, 8);
    if (!head) return { end: null, how: "PNG chunks run past the end of the data" };
    const type = String.fromCharCode(...head.subarray(4, 8));
    if (!/^[A-Za-z]{4}$/.test(type)) return { end: null, how: `Invalid PNG chunk type at offset ${pos + 4}` };
    pos += 12 + u32be(head, 0);
    if (pos > source.size) return { end: null, how: `The ${type} chunk runs past the end of the data` };
    if (type === "IEND") return { end: pos, how: "Walked the chunks to IEND" };
  }
  return { end: null, how: "Too many PNG chunks" };
}

async function jpeg(source: ByteSource, start: number): Promise<Extent> {
  let pos = start + 2;
  while (pos + 2 <= source.size) {
    const marker = await source.read(pos, 4);
    if (marker[0] !== 0xff) return { end: null, how: `Expected a JPEG marker at offset ${pos}` };
    const code = marker[1];
    if (code === 0xd9) return { end: pos + 2, how: "Walked the markers to EOI" };
    if (code === 0xff) {
      pos++;
      continue;
    }
    if ((code >= 0xd0 && code <= 0xd7) || code === 0x01) {
      pos += 2;
      continue;
    }
    if (marker.length < 4) break;
    pos += 2 + u16be(marker, 2);
    if (code === 0xda) {
      // Entropy-coded data ends at the first 0xFF that is not stuffing (FF 00), a restart marker or fill.
      const next = await scan(source, pos, 1, (w, i) => w[i] === 0xff && w[i + 1] !== 0x00 && w[i + 1] !== 0xff && !(w[i + 1] >= 0xd0 && w[i + 1] <= 0xd7));
      if (next === null) break;
      pos = next;
    }
  }
  return { end: null, how: "No EOI marker before the end of the data" };
}

async function skipSubBlocks(source: ByteSource, pos: number): Promise<number | null> {
  for (;;) {
    const size = await exact(source, pos, 1);
    if (!size) return null;
    pos += 1 + size[0];
    if (size[0] === 0) return pos;
  }
}

async function gif(source: ByteSource, start: number): Promise<Extent> {
  const header = await exact(source, start, 13);
  if (!header) return { end: null, how: "Truncated GIF header" };
  let pos: number | null = start + 13 + (header[10] & 0x80 ? 3 * (1 << ((header[10] & 7) + 1)) : 0);
  while (pos !== null && pos < source.size) {
    const [block] = await source.read(pos, 1);
    if (block === 0x3b) return { end: pos + 1, how: "Walked the blocks to the GIF trailer" };
    if (block === 0x21) {
      pos = await skipSubBlocks(source, pos + 2);
    } else if (block === 0x2c) {
      const descriptor = await exact(source, pos, 10);
      if (!descriptor) break;
      pos = await skipSubBlocks(source, pos + 10 + (descriptor[9] & 0x80 ? 3 * (1 << ((descriptor[9] & 7) + 1)) : 0) + 1);
    } else {
      return { end: null, how: `Unexpected GIF block 0x${block.toString(16)} at offset ${pos}` };
    }
  }
  return { end: null, how: "No GIF trailer before the end of the data" };
}

async function zip(source: ByteSource, start: number): Promise<Extent> {
  // The end-of-central-directory record whose directory sits right before it, counted from this archive's start.
  let from = start;
  for (;;) {
    const at = await scan(source, from, 3, (w, i) => w[i] === 0x50 && w[i + 1] === 0x4b && w[i + 2] === 0x05 && w[i + 3] === 0x06);
    if (at === null) return { end: null, how: "No end-of-central-directory record" };
    const record = await exact(source, at, 22);
    if (record && start + u32le(record, 16) + u32le(record, 12) === at) {
      const end = at + 22 + u16le(record, 20);
      if (end <= source.size) return { end, how: "End-of-central-directory record points back to this archive" };
    }
    from = at + 1;
  }
}

async function pdf(source: ByteSource, start: number): Promise<Extent> {
  let last: number | null = null;
  for (let from = start; ; ) {
    const at = await scan(source, from, 4, (w, i) => w[i] === 0x25 && w[i + 1] === 0x25 && w[i + 2] === 0x45 && w[i + 3] === 0x4f && w[i + 4] === 0x46);
    if (at === null) break;
    last = at;
    from = at + 5;
  }
  if (last === null) return { end: null, how: "No %%EOF marker" };
  const tail = await source.read(last + 5, 2);
  const eol = tail[0] === 0x0d ? (tail[1] === 0x0a ? 2 : 1) : tail[0] === 0x0a ? 1 : 0;
  return { end: last + 5 + eol, how: "Last %%EOF marker (incremental updates included)" };
}

async function declaredSize(source: ByteSource, start: number, read: (head: Uint8Array) => number, min: number, label: string): Promise<Extent> {
  const head = await exact(source, start, 32);
  if (!head) return { end: null, how: "Truncated header" };
  const size = read(head);
  return size >= min && start + size <= source.size ? { end: start + size, how: label } : { end: null, how: `${label} is not plausible (${size})` };
}

async function elf(source: ByteSource, start: number): Promise<Extent> {
  const head = await exact(source, start, 64);
  if (!head) return { end: null, how: "Truncated ELF header" };
  const wide = head[4] === 2;
  const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const le = head[5] === 1;
  const word = (o: number) => (wide ? Number(view.getBigUint64(o, le)) : view.getUint32(o, le));
  const [phoff, shoff] = wide ? [word(0x20), word(0x28)] : [word(0x1c), word(0x20)];
  const [phentsize, phnum, shentsize, shnum] = wide
    ? [view.getUint16(0x36, le), view.getUint16(0x38, le), view.getUint16(0x3a, le), view.getUint16(0x3c, le)]
    : [view.getUint16(0x2a, le), view.getUint16(0x2c, le), view.getUint16(0x2e, le), view.getUint16(0x30, le)];
  let end = Math.max(wide ? 64 : 52, phoff + phentsize * phnum, shoff + shentsize * shnum);
  const table = async (offset: number, count: number, size: number, field: (entry: DataView) => number) => {
    const bytes = await exact(source, start + offset, count * size);
    if (!bytes) return;
    const entries = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < count; i++) end = Math.max(end, field(new DataView(entries.buffer, entries.byteOffset + i * size, size)));
  };
  const big = (v: DataView, o: number) => (wide ? Number(v.getBigUint64(o, le)) : v.getUint32(o, le));
  await table(phoff, phnum, phentsize, (v) => big(v, wide ? 8 : 4) + big(v, wide ? 32 : 16));
  await table(shoff, shnum, shentsize, (v) => (v.getUint32(4, le) === 8 ? 0 : big(v, wide ? 24 : 16) + big(v, wide ? 32 : 20)));
  return start + end <= source.size
    ? { end: start + end, how: "Furthest program header, section or header table" }
    : { end: null, how: "ELF headers point past the end of the data" };
}

/** Extent of the file of `type` starting at `start`, from its own structure. */
export async function fileExtent(source: ByteSource, type: string, start: number): Promise<Extent> {
  switch (type) {
    case "png":
      return png(source, start);
    case "jpeg":
      return jpeg(source, start);
    case "gif":
      return gif(source, start);
    case "zip":
      return zip(source, start);
    case "pdf":
      return pdf(source, start);
    case "elf":
      return elf(source, start);
    case "bmp":
      return declaredSize(source, start, (h) => u32le(h, 2), 26, "BMP file-size field");
    case "webp":
    case "wav":
    case "avi":
      return declaredSize(source, start, (h) => u32le(h, 4) + 8, 12, "RIFF size field");
    case "sqlite":
      return declaredSize(source, start, (h) => (u16be(h, 16) === 1 ? 65536 : u16be(h, 16)) * u32be(h, 28), 512, "SQLite page size × page count");
    case "7z":
      return declaredSize(source, start, (h) => 32 + Number(new DataView(h.buffer, h.byteOffset).getBigUint64(12, true) + new DataView(h.buffer, h.byteOffset).getBigUint64(20, true)), 32, "7-Zip next-header offset and size");
    default:
      return { end: null, how: "This format does not record its length; carving to the end of the data" };
  }
}
