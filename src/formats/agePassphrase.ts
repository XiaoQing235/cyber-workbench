import type { ByteSource } from "../core/bytes/ByteSource";

export const MAX_AGE_CIPHERTEXT_BYTES = 64 * 1024;
const MAX_AGE_HEADER_BYTES = 1024;
const MAX_SCRYPT_WORK_FACTOR = 19;

export interface AgePassphraseResult {
  plaintext: Uint8Array<ArrayBuffer>;
  workFactor: number;
}

export async function decryptAgePassphrase(source: ByteSource, passphrase: string, signal?: AbortSignal): Promise<AgePassphraseResult> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 100 || source.size > MAX_AGE_CIPHERTEXT_BYTES) {
    throw new Error("Age ciphertext is truncated or exceeds 64 KiB");
  }
  if (passphrase.length < 1 || passphrase.length > 128) throw new Error("Age passphrase must contain 1-128 characters");
  const bytes = await source.read(0, source.size);
  if (signal?.aborted) throw signal.reason;
  if (bytes.length !== source.size) throw new Error("Age ciphertext read is truncated");
  const marker = new TextEncoder().encode("\n--- ");
  let markerOffset = -1;
  for (let index = 0; index + marker.length < Math.min(bytes.length, MAX_AGE_HEADER_BYTES); index++) {
    if (marker.every((byte, at) => bytes[index + at] === byte)) { markerOffset = index; break; }
  }
  const headerEnd = markerOffset < 0 ? -1 : bytes.indexOf(0x0a, markerOffset + marker.length);
  if (headerEnd < 0 || headerEnd >= MAX_AGE_HEADER_BYTES) throw new Error("Age passphrase header is missing or too large");
  const header = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, headerEnd + 1));
  const stanza = /^age-encryption\.org\/v1\n-> scrypt [A-Za-z0-9+/]{22} ([1-9][0-9]?)\n[A-Za-z0-9+/]{43}\n--- [A-Za-z0-9+/]{43}\n$/.exec(header);
  if (!stanza) throw new Error("Expected a single binary age scrypt passphrase stanza");
  const workFactor = Number(stanza[1]);
  if (workFactor > MAX_SCRYPT_WORK_FACTOR) throw new Error(`Age scrypt work factor exceeds ${MAX_SCRYPT_WORK_FACTOR}`);
  const { Decrypter } = await import("age-encryption");
  if (signal?.aborted) throw signal.reason;
  const decrypter = new Decrypter();
  decrypter.addPassphrase(passphrase);
  const plaintext = new Uint8Array(await decrypter.decrypt(bytes));
  if (signal?.aborted) throw signal.reason;
  if (plaintext.length > MAX_AGE_CIPHERTEXT_BYTES) throw new Error("Age plaintext exceeds 64 KiB");
  return { plaintext, workFactor };
}