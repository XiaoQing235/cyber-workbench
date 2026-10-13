import { crc32 } from "../core/checksum/crc32";

const LOCAL = 0x04034b50;
const CENTRAL = 0x02014b50;
const EOCD = 0x06054b50;
const MAX_INPUT_BYTES = 128 * 1024;

interface LocalRecord {
  header: Uint8Array<ArrayBuffer>;
  name: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
  offset: number;
}

interface CentralRecord {
  header: Uint8Array<ArrayBuffer>;
  name: Uint8Array<ArrayBuffer>;
  extra: Uint8Array<ArrayBuffer>;
}

interface ZipParts {
  locals: LocalRecord[];
  central: CentralRecord[];
  end: Uint8Array<ArrayBuffer>;
}

function combine(...parts: readonly Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let position = 0;
  for (const part of parts) { result.set(part, position); position += part.length; }
  return result;
}

function view(bytes: Uint8Array): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function splitStoredZip(bytes: Uint8Array): ZipParts {
  if (bytes.length < 22 || bytes.length > MAX_INPUT_BYTES) throw new Error("Polyglot input ZIP exceeds 128 KiB or is truncated");
  const data = view(bytes);
  const locals: LocalRecord[] = [];
  const central: CentralRecord[] = [];
  let offset = 0;
  for (let index = 0; index < 3; index++) {
    if (offset + 30 > bytes.length || data.getUint32(offset, true) !== LOCAL) throw new Error("Polyglot input needs three contiguous local ZIP entries");
    const nameLength = data.getUint16(offset + 26, true);
    const extraLength = data.getUint16(offset + 28, true);
    const storedLength = data.getUint32(offset + 18, true);
    const end = offset + 30 + nameLength + extraLength + storedLength;
    if (nameLength < 1 || nameLength > 64 || extraLength > 256 || storedLength > 64 * 1024 || end > bytes.length ||
      data.getUint16(offset + 6, true) !== 0 || data.getUint16(offset + 8, true) !== 0 ||
      storedLength !== data.getUint32(offset + 22, true)) throw new Error("Polyglot input must contain bounded unencrypted stored entries");
    const name = bytes.slice(offset + 30, offset + 30 + nameLength);
    if (name.some((byte) => byte < 0x21 || byte > 0x7e)) throw new Error("Polyglot input name is not safe ASCII");
    const content = bytes.slice(offset + 30 + nameLength + extraLength, end);
    if (crc32(content) !== data.getUint32(offset + 14, true)) throw new Error("Polyglot input entry CRC is invalid");
    locals.push({ header: bytes.slice(offset, offset + 30), name, data: content, offset });
    offset = end;
  }
  const centralStart = offset;
  for (let index = 0; index < 3; index++) {
    if (offset + 46 > bytes.length || data.getUint32(offset, true) !== CENTRAL) throw new Error("Polyglot input central directory is missing an entry");
    const nameLength = data.getUint16(offset + 28, true);
    const extraLength = data.getUint16(offset + 30, true);
    const commentLength = data.getUint16(offset + 32, true);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    const local = locals[index];
    if (nameLength !== local.name.length || extraLength > 256 || commentLength !== 0 || end > bytes.length ||
      data.getUint16(offset + 8, true) !== 0 || data.getUint16(offset + 10, true) !== 0 ||
      data.getUint32(offset + 16, true) !== crc32(local.data) ||
      data.getUint32(offset + 20, true) !== local.data.length || data.getUint32(offset + 24, true) !== local.data.length ||
      data.getUint32(offset + 42, true) !== local.offset ||
      bytes.subarray(offset + 46, offset + 46 + nameLength).some((byte, at) => byte !== local.name[at])) {
      throw new Error("Polyglot input local and central entries disagree");
    }
    central.push({ header: bytes.slice(offset, offset + 46), name: local.name, extra: bytes.slice(offset + 46 + nameLength, end) });
    offset = end;
  }
  if (offset + 22 !== bytes.length || data.getUint32(offset, true) !== EOCD ||
    data.getUint16(offset + 4, true) !== 0 || data.getUint16(offset + 6, true) !== 0 ||
    data.getUint16(offset + 8, true) !== 3 || data.getUint16(offset + 10, true) !== 3 ||
    data.getUint32(offset + 12, true) !== offset - centralStart || data.getUint32(offset + 16, true) !== centralStart ||
    data.getUint16(offset + 20, true) !== 0) throw new Error("Polyglot input ZIP end record is inconsistent");
  return { locals, central, end: bytes.slice(offset) };
}

function localHeader(record: LocalRecord, extraLength: number): Uint8Array<ArrayBuffer> {
  const header = record.header.slice();
  view(header).setUint16(28, extraLength, true);
  return header;
}

function localRecord(record: LocalRecord, extra: Uint8Array): Uint8Array<ArrayBuffer> {
  return combine(localHeader(record, extra.length), record.name, extra, record.data);
}

function centralRecord(record: CentralRecord, localOffset: number, commentLength = 0): Uint8Array<ArrayBuffer> {
  const header = record.header.slice();
  view(header).setUint32(42, localOffset, true);
  view(header).setUint16(32, commentLength, true);
  return combine(header, record.name, record.extra);
}

function commentHeader(length = 0, checksum = 0): Uint8Array<ArrayBuffer> {
  if (length > 0xffff) throw new Error("Polyglot Unicode comment exceeds ZIP length limit");
  const header = new Uint8Array(9);
  const fields = view(header);
  fields.setUint16(0, 0x6375, true);
  fields.setUint16(2, length, true);
  header[4] = 1;
  fields.setUint32(5, checksum, true);
  return header;
}

function unicodeComment(content: Uint8Array): Uint8Array<ArrayBuffer> {
  return combine(commentHeader(content.length, crc32(content)), content);
}

function endRecord(template: Uint8Array, directory: number, size: number, comment: Uint8Array,
  count = 3, centralDisk = 0): Uint8Array<ArrayBuffer> {
  if (comment.length > 0xffff) throw new Error("Polyglot end comment exceeds ZIP length limit");
  const header = template.slice();
  const fields = view(header);
  fields.setUint16(6, centralDisk, true);
  fields.setUint16(8, count, true);
  fields.setUint16(10, count, true);
  fields.setUint32(12, size, true);
  fields.setUint32(16, directory, true);
  fields.setUint16(20, comment.length, true);
  return combine(header, comment);
}

export function buildPolyglotZip(first: Uint8Array, second: Uint8Array): Uint8Array<ArrayBuffer> {
  const left = splitStoredZip(first);
  const right = splitStoredZip(second);
  if (left.locals[0].name.toString() !== right.locals[2].name.toString() ||
    !left.locals[0].data.every((byte, index) => byte === right.locals[2].data[index]) ||
    left.locals[0].data.length !== right.locals[2].data.length) {
    throw new Error("Polyglot inputs must share identical first/last entry content and name");
  }

  const firstFakeLength = left.locals[0].data.length + 30 + left.locals[1].name.length + 9;
  const firstRightHeader = localHeader(right.locals[0], firstFakeLength + 9);
  const firstExtra = unicodeComment(combine(firstRightHeader, right.locals[0].name, commentHeader()));
  const firstLocal = localRecord(left.locals[0], firstExtra);

  const secondFakeLength = left.locals[1].data.length + 30 + left.locals[2].name.length + 9;
  const secondRightHeader = localHeader(right.locals[1], secondFakeLength + 9);
  const secondExtra = unicodeComment(combine(right.locals[0].data, secondRightHeader, right.locals[1].name, commentHeader()));
  const secondLocal = localRecord(left.locals[1], secondExtra);

  const rightOffsets = [0, 30 + left.locals[0].name.length + 9,
    firstLocal.length + 30 + left.locals[1].name.length + 9 + right.locals[0].data.length];
  const leftCentral = [centralRecord(left.central[0], 0), centralRecord(left.central[1], firstLocal.length),
    centralRecord(left.central[2], firstLocal.length + secondLocal.length)];

  const rightFirst = centralRecord(right.central[0], rightOffsets[1]);
  const fake = leftCentral[0].slice();
  view(fake).setUint32(22, 0, true);
  const fakeCommentLength = left.locals[2].data.length + leftCentral.reduce((length, record) => length + record.length, 0) + 22;
  const rightSecond = centralRecord(right.central[1], rightOffsets[2], fakeCommentLength);
  const thirdExtra = unicodeComment(combine(right.locals[1].data, rightFirst, fake, rightSecond));
  const thirdLocal = localRecord(left.locals[2], thirdExtra);
  const leftDirectoryOffset = firstLocal.length + secondLocal.length + thirdLocal.length;
  const leftDirectory = combine(...leftCentral);

  const innerDirectoryOffset = firstLocal.length + secondLocal.length + 30 + left.locals[2].name.length +
    left.locals[1].data.length + 9;
  const innerDirectorySize = fake.length + rightFirst.length + rightSecond.length +
    centralRecord(right.central[2], right.locals[2].offset).length + fakeCommentLength;
  const hiddenEnd = endRecord(right.end, innerDirectoryOffset, innerDirectorySize, new Uint8Array(0), 4, 1);
  return combine(firstLocal, secondLocal, thirdLocal, leftDirectory,
    endRecord(left.end, leftDirectoryOffset, leftDirectory.length, hiddenEnd));
}