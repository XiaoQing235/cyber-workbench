import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { Sha256 } from "../core/hash/sha256";

const MAX_HEADER_BYTES = 16 * 1024;
const AES_CIPHER_ID = "31c1f2e6bf714350be5805216afc5aff";
const ARGON2D_ID = "ef636ddf8c29444b91f7a9a403e30a0c";
const ARGON2ID_ID = "9e298b1956db4773b23dfc3ec6f0a1e6";
const decoder = new TextDecoder("utf-8", { fatal: true });

export interface KeePassReport {
  format: "KDBX3" | "KDBX4";
  version: string;
  cipher: "AES-256";
  kdf: "AES-KDF" | "Argon2d" | "Argon2id";
  iterations: number;
  memoryKiB?: number;
  parallelism?: number;
  headerBytes: number;
  hash: string;
}

class Cursor {
  offset = 0;
  private readonly view: DataView;

  constructor(readonly bytes: Bytes, offset = 0) {
    this.offset = offset;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  take(length: number): Bytes {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) throw new Error("KeePass header is truncated or exceeds the 16 KiB limit");
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  uint8(): number { return this.take(1)[0]; }
  uint16(): number { const offset = this.offset; this.take(2); return this.view.getUint16(offset, true); }
  uint32(): number { const offset = this.offset; this.take(4); return this.view.getUint32(offset, true); }
}

function hex(bytes: Bytes): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function field(fields: Map<number, Bytes>, id: number, length?: number): Bytes {
  const bytes = fields.get(id);
  if (!bytes || (length !== undefined && bytes.length !== length)) throw new Error(`KeePass header field ${id} is missing or has an invalid length`);
  return bytes;
}

function parameter(parameters: Map<string, { type: number; value: Bytes }>, name: string, type: number, length?: number): Bytes {
  const item = parameters.get(name);
  if (!item || item.type !== type || (length !== undefined && item.value.length !== length)) throw new Error(`KeePass KDF parameter ${name} is missing or has an invalid type or length`);
  return item.value;
}

function uint32(bytes: Bytes): number { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, true); }
function uint64(bytes: Bytes): number {
  const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("KeePass KDF parameter exceeds JavaScript's safe integer range");
  return Number(value);
}

function kdfParameters(bytes: Bytes): Map<string, { type: number; value: Bytes }> {
  const cursor = new Cursor(bytes);
  if (cursor.uint16() !== 0x0100) throw new Error("KeePass uses an unsupported KDF dictionary version");
  const parameters = new Map<string, { type: number; value: Bytes }>();
  let terminated = false;
  while (cursor.offset < bytes.length) {
    const type = cursor.uint8();
    if (type === 0) { terminated = true; break; }
    const nameLength = cursor.uint32();
    if (nameLength > 256) throw new Error("KeePass KDF parameter name exceeds 256 bytes");
    const name = decoder.decode(cursor.take(nameLength));
    const value = cursor.take(cursor.uint32());
    if (parameters.has(name)) throw new Error(`KeePass KDF parameter ${name} is duplicated`);
    parameters.set(name, { type, value });
  }
  if (!terminated || cursor.offset !== bytes.length) throw new Error("KeePass KDF dictionary is unterminated or has trailing data");
  return parameters;
}

export async function inspectKeePass(source: ByteSource, signal?: AbortSignal): Promise<KeePassReport> {
  if (signal?.aborted) throw signal.reason;
  const bytes = await source.read(0, Math.min(source.size, MAX_HEADER_BYTES + 64));
  const cursor = new Cursor(bytes);
  if (cursor.uint32() !== 0x9aa2d903 || cursor.uint32() !== 0xb54bfb67) throw new Error("Input is not a KeePass KDBX database");
  const minor = cursor.uint16();
  const major = cursor.uint16();
  if ((major !== 3 && major !== 4) || minor > 1) throw new Error(`KeePass KDBX version ${major}.${minor} is unsupported`);

  const fields = new Map<number, Bytes>();
  let terminated = false;
  for (let index = 0; index < 64 && cursor.offset <= MAX_HEADER_BYTES; index++) {
    const id = cursor.uint8();
    const length = major === 3 ? cursor.uint16() : cursor.uint32();
    const value = cursor.take(length);
    if (id === 0) {
      if (hex(value) !== "0d0a0d0a") throw new Error("KeePass header has an invalid end marker");
      terminated = true;
      break;
    }
    if (fields.has(id)) throw new Error(`KeePass header field ${id} is duplicated`);
    fields.set(id, value);
  }
  if (!terminated || cursor.offset > MAX_HEADER_BYTES) throw new Error("KeePass header exceeds the field count or 16 KiB limit");
  if (hex(field(fields, 2, 16)) !== AES_CIPHER_ID || field(fields, 7).length !== 16) throw new Error("KeePass export supports only AES-256 databases");
  const masterSeed = field(fields, 4, 32);
  const headerLength = cursor.offset;
  if (major === 3) {
    const transformSeed = field(fields, 5, 32);
    const iterations = uint64(field(fields, 6, 8));
    const startBytes = field(fields, 9, 32);
    if (iterations < 1 || iterations > 0xffffffff) throw new Error("KeePass AES-KDF rounds exceed the supported 32-bit range");
    const encryptedPrefix = await source.read(headerLength, 32);
    if (encryptedPrefix.length !== 32) throw new Error("KeePass KDBX3 encrypted prefix is truncated");
    if (signal?.aborted) throw signal.reason;
    return {
      format: "KDBX3", version: `${major}.${minor}`, cipher: "AES-256", kdf: "AES-KDF", iterations, headerBytes: headerLength,
      hash: `$keepass$*2*${iterations}*0*${hex(masterSeed)}*${hex(transformSeed)}*${hex(field(fields, 7))}*${hex(startBytes)}*${hex(encryptedPrefix)}`,
    };
  }
  const parameters = kdfParameters(field(fields, 11));
  const uuid = hex(parameter(parameters, "$UUID", 0x42, 16));
  if (uuid !== ARGON2D_ID && uuid !== ARGON2ID_ID) throw new Error("KeePass export supports only Argon2d and Argon2id KDFs");
  const iterations = uint64(parameter(parameters, "I", 0x05, 8));
  const memoryBytes = uint64(parameter(parameters, "M", 0x05, 8));
  const parallelism = uint32(parameter(parameters, "P", 0x04, 4));
  const argonVersion = uint32(parameter(parameters, "V", 0x04, 4));
  const salt = parameter(parameters, "S", 0x42, 32);
  if (iterations < 1 || iterations > 0xffffffff || parallelism < 1 || parallelism > 1024 || memoryBytes < parallelism * 8192 || memoryBytes > 16 * 1024 ** 3 || memoryBytes % 1024 !== 0 || argonVersion !== 19) throw new Error("KeePass Argon2 KDF parameters are unsupported");

  if (source.size < headerLength + 64 + 36 || bytes.length < headerLength + 64) throw new Error("KeePass KDBX4 header or encrypted body is truncated");
  const header = bytes.subarray(0, headerLength);
  const expectedDigest = bytes.subarray(headerLength, headerLength + 32);
  const actualDigest = new Sha256().update(header).digest();
  if (hex(expectedDigest) !== hex(actualDigest)) throw new Error("KeePass KDBX4 header SHA-256 is invalid");
  const headerHmac = bytes.subarray(headerLength + 32, headerLength + 64);
  const firstBlock = await source.read(headerLength + 64, 36);
  if (firstBlock.length !== 36 || uint32(firstBlock.subarray(32)) > source.size - headerLength - 100) throw new Error("KeePass first encrypted block is truncated");
  if (signal?.aborted) throw signal.reason;
  return {
    format: "KDBX4", version: `${major}.${minor}`, cipher: "AES-256",
    kdf: uuid === ARGON2D_ID ? "Argon2d" : "Argon2id", iterations,
    memoryKiB: memoryBytes / 1024, parallelism, headerBytes: headerLength,
    hash: `$keepass$*4*${iterations}*${uuid.slice(0, 8)}*${memoryBytes}*${argonVersion}*${parallelism}*${hex(masterSeed)}*${hex(salt)}*${hex(header)}*${hex(headerHmac)}`,
  };
}