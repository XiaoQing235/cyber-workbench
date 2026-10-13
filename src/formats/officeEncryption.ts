import type { CFB$Container, CFB$Entry } from "cfb";
import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

export const MAX_OFFICE_BYTES = 16 * 1024 * 1024;
const MAX_INFO_BYTES = 64 * 1024;
const OLE_SIGNATURE = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const PASSWORD_URI = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";

export interface OfficeEncryptionReport {
  format: "Office Standard (2007)" | "Office Agile (2013)";
  container: "OLE Compound File";
  cipher: "AES-128-CBC" | "AES-256-CBC";
  hashAlgorithm: "SHA1" | "SHA512";
  spinCount: number;
  saltBytes: number;
  encryptedPackageBytes: number;
  hash: string;
}

function stream(container: CFB$Container, name: string): CFB$Entry {
  const root = container.FullPaths[0];
  if (container.FileIndex[0]?.type !== 5 || !root?.endsWith("/")) throw new Error("Office compound-file root directory is invalid");
  const entries = container.FullPaths.flatMap((path, index) => path.toLowerCase() === `${root}${name}`.toLowerCase() ? [container.FileIndex[index]] : []);
  if (entries.length !== 1 || entries[0].type !== 2 || !Number.isSafeInteger(entries[0].size) || entries[0].size < 0 || entries[0].content.length !== entries[0].size) throw new Error(`Office ${name} stream is missing, duplicated, or truncated`);
  return entries[0];
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Office ${name} XML element is missing or ambiguous`);
  return value as Record<string, unknown>;
}

function attribute(node: Record<string, unknown>, name: string): string {
  const value = node[`@${name}`];
  if (typeof value !== "string") throw new Error(`Office password key ${name} attribute is missing or invalid`);
  return value;
}

function numberAttribute(node: Record<string, unknown>, name: string, max: number): number {
  const text = attribute(node, name);
  if (!/^(?:0|[1-9][0-9]*)$/.test(text)) throw new Error(`Office password key ${name} must be a decimal integer`);
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw new Error(`Office password key ${name} is outside the supported range`);
  return value;
}

function binaryAttribute(node: Record<string, unknown>, name: string, length: number): Bytes {
  const encoded = attribute(node, name);
  if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) throw new Error(`Office password key ${name} has invalid base64`);
  const value = Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
  if (value.length !== length) throw new Error(`Office password key ${name} must be ${length} bytes`);
  return value;
}

function hex(bytes: Bytes): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function standardEncryption(data: Bytes, encryptedPackageBytes: number): OfficeEncryptionReport {
  if (data.length < 12 + 32 + 72) throw new Error("Office Standard EncryptionInfo is truncated");
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint16(0, true) !== 3 || view.getUint16(2, true) !== 2 || view.getUint32(4, true) !== 0x24) throw new Error("Office export supports only Standard 3.2 AES encryption");
  const headerSize = view.getUint32(8, true);
  const verifierAt = 12 + headerSize;
  if (headerSize < 34 || headerSize % 2 !== 0 || verifierAt + 72 !== data.length) throw new Error("Office Standard header or verifier has invalid bounds");
  if (view.getUint32(12, true) !== 0x24 || view.getUint32(16, true) !== 0 || view.getUint32(20, true) !== 0x660e || view.getUint32(24, true) !== 0x8004 || view.getUint32(28, true) !== 128 || view.getUint32(32, true) !== 24 || view.getUint32(36, true) !== 0 || view.getUint32(40, true) !== 0) throw new Error("Office Standard cipher or hash parameters are unsupported");
  if (view.getUint16(verifierAt - 2, true) !== 0 || view.getUint32(verifierAt, true) !== 16 || view.getUint32(verifierAt + 36, true) !== 20) throw new Error("Office Standard provider or verifier fields are invalid");
  const salt = data.subarray(verifierAt + 4, verifierAt + 20);
  const verifier = data.subarray(verifierAt + 20, verifierAt + 36);
  const verifierHash = data.subarray(verifierAt + 40, verifierAt + 72);
  return {
    format: "Office Standard (2007)", container: "OLE Compound File", cipher: "AES-128-CBC", hashAlgorithm: "SHA1",
    spinCount: 50_000, saltBytes: 16, encryptedPackageBytes,
    hash: `$office$*2007*20*128*16*${hex(salt)}*${hex(verifier)}*${hex(verifierHash.slice(0, 20))}`,
  };
}

export async function inspectOfficeEncryption(source: ByteSource, signal?: AbortSignal): Promise<OfficeEncryptionReport> {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_OFFICE_BYTES);
  if (!OLE_SIGNATURE.every((byte, index) => bytes[index] === byte)) throw new Error("Input is not an encrypted Office compound file");
  const { read } = await import("cfb");
  const compound = read(bytes, { type: "array", WTF: true });
  const info = stream(compound, "EncryptionInfo");
  const encrypted = stream(compound, "EncryptedPackage");
  if (info.size < 8 || info.size > MAX_INFO_BYTES || encrypted.size < 8) throw new Error("Office encryption streams have invalid bounds");
  const data = Uint8Array.from(info.content);
  const view = new DataView(data.buffer);
  if (view.getUint16(0, true) === 3 && view.getUint16(2, true) === 2) return standardEncryption(data, encrypted.size);
  if (view.getUint16(0, true) !== 4 || view.getUint16(2, true) !== 4 || view.getUint32(4, true) !== 0x40) throw new Error("Office export supports only Agile 4.4 password encryption");
  const { XMLParser, XMLValidator } = await import("fast-xml-parser");
  const xml = new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(8));
  if (/<!DOCTYPE|<!ENTITY/i.test(xml) || XMLValidator.validate(xml) !== true) throw new Error("Office EncryptionInfo XML is unsafe or malformed");
  const document = record(new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", removeNSPrefix: true, processEntities: false, parseAttributeValue: false, maxNestedTags: 32 }).parse(xml), "document");
  const encryption = record(document.encryption, "encryption");
  const keyData = record(encryption.keyData, "keyData");
  const encryptors = record(encryption.keyEncryptors, "keyEncryptors").keyEncryptor;
  const passwordKeys = (Array.isArray(encryptors) ? encryptors : [encryptors])
    .filter((value) => value && typeof value === "object" && !Array.isArray(value) && value["@uri"] === PASSWORD_URI);
  if (passwordKeys.length !== 1) throw new Error("Office document must contain exactly one password key encryptor");
  const key = record(record(passwordKeys[0], "password key").encryptedKey, "encryptedKey");
  for (const name of ["saltSize", "blockSize", "keyBits", "hashSize", "cipherAlgorithm", "cipherChaining", "hashAlgorithm"]) {
    if (attribute(key, name) !== attribute(keyData, name)) throw new Error(`Office password key ${name} disagrees with keyData`);
  }
  const spinCount = numberAttribute(key, "spinCount", 1_000_000);
  const saltSize = numberAttribute(key, "saltSize", 16);
  const blockSize = numberAttribute(key, "blockSize", 16);
  const keyBits = numberAttribute(key, "keyBits", 256);
  const hashSize = numberAttribute(key, "hashSize", 64);
  if (saltSize !== 16 || blockSize !== 16 || keyBits !== 256 || hashSize !== 64 || attribute(key, "cipherAlgorithm") !== "AES" || attribute(key, "cipherChaining") !== "ChainingModeCBC" || attribute(key, "hashAlgorithm") !== "SHA512") throw new Error("Office export supports only SHA512/AES-256-CBC Agile password keys");
  binaryAttribute(keyData, "saltValue", 16);
  const salt = binaryAttribute(key, "saltValue", 16);
  const verifier = binaryAttribute(key, "encryptedVerifierHashInput", 16);
  const verifierHash = binaryAttribute(key, "encryptedVerifierHashValue", 64);
  if (signal?.aborted) throw signal.reason;
  return {
    format: "Office Agile (2013)", container: "OLE Compound File", cipher: "AES-256-CBC", hashAlgorithm: "SHA512",
    spinCount, saltBytes: saltSize, encryptedPackageBytes: encrypted.size,
    hash: `$office$*2013*${spinCount}*${keyBits}*${saltSize}*${hex(salt)}*${hex(verifier)}*${hex(verifierHash.subarray(0, 32))}`,
  };
}