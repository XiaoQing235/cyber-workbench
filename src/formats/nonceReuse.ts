import type { Bytes } from "../core/bytes/ByteSource";

const MAX_RECORDS = 64;
const MAX_CIPHERTEXT_BYTES = 64 * 1024;
const MAX_TOTAL_BYTES = 512 * 1024;

export interface NonceRecord {
  algorithm: "AES-CTR" | "AES-GCM";
  keyId: string | null;
  nonce: Bytes;
  ciphertext: Bytes;
  tag: Bytes | null;
  knownPlaintext: { offset: number; bytes: Bytes } | null;
}

export interface NonceReuseGroup {
  algorithm: NonceRecord["algorithm"];
  keyId: string | null;
  nonce: string;
  indexes: number[];
  risk: "confirmed" | "possible";
  overlapBytes: number;
  xorPreview: string;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function hex(value: Bytes): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeHex(value: unknown, name: string, maxLength: number): Bytes {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || value.length > maxLength * 2 || !/^[0-9a-f]+$/i.test(value)) {
    throw new Error(`${name} must be nonempty even-length hex, at most ${maxLength} bytes`);
  }
  return Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function allowedKeys(value: Record<string, unknown>, keys: string[], label: string): void {
  for (const key of Object.keys(value)) if (!keys.includes(key)) throw new Error(`${label} has unsupported field ${key}`);
}

export function parseNonceRecords(text: string): NonceRecord[] {
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Nonce records must be valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length < 2 || parsed.length > MAX_RECORDS) throw new Error("Nonce input requires 2 to 64 records");
  const records: NonceRecord[] = [];
  let total = 0;
  for (const [index, value] of parsed.entries()) {
    const source = record(value, `Record ${index}`);
    allowedKeys(source, ["algorithm", "keyId", "nonce", "ciphertext", "tag", "knownPlaintext"], `Record ${index}`);
    if (source.algorithm !== "AES-CTR" && source.algorithm !== "AES-GCM") throw new Error(`Record ${index} has an unsupported algorithm`);
    if (source.keyId !== undefined && (typeof source.keyId !== "string" || source.keyId.length < 1 || source.keyId.length > 128)) throw new Error(`Record ${index} has an invalid key ID`);
    const nonce = decodeHex(source.nonce, `Record ${index} nonce`, 16);
    if (nonce.length !== (source.algorithm === "AES-GCM" ? 12 : 16)) throw new Error(`Record ${index} nonce has an invalid size for ${source.algorithm}`);
    const ciphertext = decodeHex(source.ciphertext, `Record ${index} ciphertext`, MAX_CIPHERTEXT_BYTES);
    total += ciphertext.length;
    if (total > MAX_TOTAL_BYTES) throw new Error("Nonce ciphertexts exceed the 512 KiB total limit");
    const tag = source.tag === undefined ? null : decodeHex(source.tag, `Record ${index} tag`, 16);
    if (tag && (source.algorithm !== "AES-GCM" || tag.length !== 16)) throw new Error(`Record ${index} tag must be 16-byte AES-GCM data`);
    let knownPlaintext: NonceRecord["knownPlaintext"] = null;
    if (source.knownPlaintext !== undefined) {
      const crib = record(source.knownPlaintext, `Record ${index} knownPlaintext`);
      allowedKeys(crib, ["offset", "hex"], `Record ${index} knownPlaintext`);
      if (!Number.isSafeInteger(crib.offset) || (crib.offset as number) < 0) throw new Error(`Record ${index} knownPlaintext offset is invalid`);
      const knownBytes = decodeHex(crib.hex, `Record ${index} knownPlaintext`, ciphertext.length);
      if ((crib.offset as number) + knownBytes.length > ciphertext.length) throw new Error(`Record ${index} knownPlaintext exceeds the ciphertext`);
      knownPlaintext = { offset: crib.offset as number, bytes: knownBytes };
    }
    records.push({ algorithm: source.algorithm, keyId: source.keyId as string | undefined ?? null, nonce, ciphertext, tag, knownPlaintext });
  }
  return records;
}

export async function parseNonceCsv(text: string): Promise<NonceRecord[]> {
  const { default: Papa } = await import("papaparse");
  const parsed = Papa.parse<Record<string, string>>(text, { header: true, delimiter: ",", skipEmptyLines: "greedy", dynamicTyping: false });
  if (parsed.errors.length > 0) throw new Error(`Nonce CSV is malformed: ${parsed.errors[0].message}`);
  const fields = parsed.meta.fields ?? [];
  const allowed = ["algorithm", "keyId", "nonce", "ciphertext", "tag", "knownPlaintextOffset", "knownPlaintextHex"];
  if (!fields.includes("algorithm") || !fields.includes("nonce") || !fields.includes("ciphertext")) throw new Error("Nonce CSV requires algorithm, nonce, and ciphertext columns");
  for (const name of fields) if (!allowed.includes(name)) throw new Error(`Nonce CSV has an unsupported or duplicate column ${name}`);
  if (parsed.data.length < 2 || parsed.data.length > MAX_RECORDS) throw new Error("Nonce input requires 2 to 64 records");
  const records = parsed.data.map((row, index) => {
    const result: Record<string, unknown> = {};
    for (const name of ["algorithm", "keyId", "nonce", "ciphertext", "tag"]) {
      const value = row[name];
      if (value !== undefined && value !== "") result[name] = value;
    }
    const offset = row.knownPlaintextOffset;
    const crib = row.knownPlaintextHex;
    if ((offset && !crib) || (crib && !offset)) throw new Error(`Nonce CSV record ${index} needs both crib offset and hex`);
    if (offset && crib) {
      if (!/^(?:0|[1-9][0-9]*)$/.test(offset) || !Number.isSafeInteger(Number(offset))) throw new Error(`Nonce CSV record ${index} has an invalid crib offset`);
      result.knownPlaintext = { offset: Number(offset), hex: crib };
    }
    return result;
  });
  return parseNonceRecords(JSON.stringify(records));
}

export function xorCiphertexts(first: NonceRecord, second: NonceRecord): Bytes {
  const count = Math.min(first.ciphertext.length, second.ciphertext.length);
  return Uint8Array.from({ length: count }, (_, index) => first.ciphertext[index] ^ second.ciphertext[index]);
}

export function analyzeNonceReuse(records: NonceRecord[]): NonceReuseGroup[] {
  const candidates = new Map<string, number[]>();
  for (const [index, entry] of records.entries()) {
    const key = JSON.stringify([entry.algorithm, entry.keyId, hex(entry.nonce)]);
    const indexes = candidates.get(key) ?? [];
    indexes.push(index);
    candidates.set(key, indexes);
  }
  return [...candidates.values()].filter((indexes) => indexes.length > 1).map((indexes) => {
    const first = records[indexes[0]];
    const second = records[indexes[1]];
    const difference = xorCiphertexts(first, second);
    return {
      algorithm: first.algorithm, keyId: first.keyId, nonce: hex(first.nonce), indexes,
      risk: first.keyId === null ? "possible" as const : "confirmed" as const,
      overlapBytes: difference.length, xorPreview: hex(difference.subarray(0, 64)),
    };
  });
}

export function recoverWithCrib(records: NonceRecord[], firstIndex: number, secondIndex: number): { xor: Bytes; recovered: Bytes | null; offset: number | null; risk: "confirmed" | "possible" } {
  const first = records[firstIndex];
  const second = records[secondIndex];
  if (!first || !second || firstIndex === secondIndex) throw new Error("Nonce analysis needs two different record indexes");
  if (first.algorithm !== second.algorithm || hex(first.nonce) !== hex(second.nonce) || (first.keyId && second.keyId && first.keyId !== second.keyId)) throw new Error("Selected ciphertexts do not share a compatible algorithm, nonce, and key ID");
  const xor = xorCiphertexts(first, second);
  const crib = first.knownPlaintext ?? second.knownPlaintext;
  const offset = crib?.offset ?? null;
  const knownFirst = first.knownPlaintext !== null;
  let recovered: Bytes | null = null;
  if (crib && offset !== null) {
    const other = knownFirst ? second : first;
    const known = knownFirst ? first : second;
    const count = Math.min(crib.bytes.length, Math.max(0, other.ciphertext.length - offset));
    recovered = Uint8Array.from({ length: count }, (_, index) => known.ciphertext[offset + index] ^ other.ciphertext[offset + index] ^ crib.bytes[index]);
  }
  return { xor, recovered, offset, risk: first.keyId && first.keyId === second.keyId ? "confirmed" : "possible" };
}