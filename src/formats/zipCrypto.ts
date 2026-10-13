import { MemorySource } from "../core/bytes/sources";
import { CRC32_TABLE, crc32 } from "../core/checksum/crc32";
import { inflate } from "../core/compression/inflate";

interface Keys {
  first: number;
  second: number;
  third: number;
}

function updateCrc(register: number, byte: number): number {
  return (CRC32_TABLE[(register ^ byte) & 0xff] ^ (register >>> 8)) >>> 0;
}

function update(keys: Keys, byte: number): void {
  keys.first = updateCrc(keys.first, byte);
  keys.second = (Math.imul((keys.second + (keys.first & 0xff)) >>> 0, 134775813) + 1) >>> 0;
  keys.third = updateCrc(keys.third, keys.second >>> 24);
}

function initialize(password: Uint8Array): Keys {
  const keys: Keys = { first: 0x12345678, second: 0x23456789, third: 0x34567890 };
  for (const byte of password) update(keys, byte);
  return keys;
}

function decryptByte(keys: Keys, cipher: number): number {
  const temporary = (keys.third | 2) >>> 0;
  const plain = cipher ^ ((Math.imul(temporary, temporary ^ 1) >>> 8) & 0xff);
  update(keys, plain);
  return plain;
}

export type ZipCryptoTestResult =
  | { status: "rejected" }
  | { status: "header-match"; reason: string }
  | { status: "verified"; plaintext?: Uint8Array<ArrayBuffer> };

type VerificationOptions = { checkByte: number; method: number; crc32: number; uncompressedSize: number; maxOutputBytes: number; exposePlaintext?: boolean; signal?: AbortSignal };

async function decryptAndVerify(
  encrypted: Uint8Array<ArrayBuffer>,
  keys: Keys,
  options: VerificationOptions,
): Promise<ZipCryptoTestResult> {
  if (encrypted.length < 12) return { status: "rejected" };
  for (let index = 0; index < 11; index++) decryptByte(keys, encrypted[index]);
  if (decryptByte(keys, encrypted[11]) !== options.checkByte) return { status: "rejected" };

  const compressed = new Uint8Array(encrypted.length - 12);
  for (let index = 12; index < encrypted.length; index++) compressed[index - 12] = decryptByte(keys, encrypted[index]);
  let plain: Uint8Array<ArrayBuffer>;
  if (options.method === 0) {
    plain = compressed;
  } else if (options.method === 8) {
    const result = await inflate(new MemorySource(compressed), "deflate-raw", { maxOutputBytes: options.maxOutputBytes, signal: options.signal });
    if (result.error) return { status: "rejected" };
    plain = result.bytes;
  } else {
    return { status: "header-match", reason: `compression method ${options.method} is not available for full verification` };
  }
  return plain.length === options.uncompressedSize && crc32(plain) === options.crc32
    ? { status: "verified", ...(options.exposePlaintext ? { plaintext: plain } : {}) } : { status: "rejected" };
}

/** Tests one password against a complete traditional ZipCrypto stream, including its 12-byte header. */
export async function testZipCryptoPassword(encrypted: Uint8Array<ArrayBuffer>, password: Uint8Array, options: VerificationOptions): Promise<ZipCryptoTestResult> {
  return decryptAndVerify(encrypted, initialize(password), options);
}

/** Validates a complete entry with internal keys recovered independently, not a password. */
export async function testZipCryptoKeys(encrypted: Uint8Array<ArrayBuffer>, keys: Keys, options: VerificationOptions): Promise<ZipCryptoTestResult> {
  if (![keys.first, keys.second, keys.third].every((key) => Number.isInteger(key) && key >= 0 && key <= 0xffffffff)) return { status: "rejected" };
  return decryptAndVerify(encrypted, { ...keys }, options);
}

/** Test helper for producing standards-conformant traditional ZipCrypto bytes. */
export function encryptZipCryptoForTest(plain: Uint8Array, password: Uint8Array, checkByte: number): Uint8Array<ArrayBuffer> {
  const keys = initialize(password);
  const input = new Uint8Array(12 + plain.length);
  for (let index = 0; index < 11; index++) input[index] = (index * 29 + 7) & 0xff;
  input[11] = checkByte;
  input.set(plain, 12);
  const encrypted = new Uint8Array(input.length);
  for (let index = 0; index < input.length; index++) {
    const temporary = (keys.third | 2) >>> 0;
    encrypted[index] = input[index] ^ ((Math.imul(temporary, temporary ^ 1) >>> 8) & 0xff);
    update(keys, input[index]);
  }
  return encrypted;
}