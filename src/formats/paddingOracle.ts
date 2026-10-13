import type { Bytes } from "../core/bytes/ByteSource";

export interface PaddingOracleInput {
  key: Bytes;
  iv: Bytes;
  ciphertexts: Bytes[];
}

export interface PaddingOracleReport {
  probed: number;
  available: number;
  valid: number;
  truncated: boolean;
  outcomes: { index: number; status: "valid" | "invalid"; plaintextBytes?: number }[];
}

function hex(value: unknown, name: string, maxBytes: number): Bytes {
  if (typeof value !== "string" || value.length === 0 || value.length % 2 !== 0 || value.length > maxBytes * 2 || !/^[0-9a-f]+$/i.test(value)) {
    throw new Error(`Oracle ${name} must be even-length hex within ${maxBytes} bytes`);
  }
  return Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

export function parsePaddingOracleInput(text: string): PaddingOracleInput {
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Oracle input must be valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Oracle input must be an object");
  const source = parsed as Record<string, unknown>;
  for (const name of Object.keys(source)) if (!["key", "iv", "ciphertexts"].includes(name)) throw new Error(`Oracle input has unsupported field ${name}`);
  const key = hex(source.key, "key", 32);
  if (![16, 24, 32].includes(key.length)) throw new Error("Oracle AES key must contain 16, 24, or 32 bytes");
  const iv = hex(source.iv, "IV", 16);
  if (iv.length !== 16) throw new Error("Oracle AES-CBC IV must contain 16 bytes");
  if (!Array.isArray(source.ciphertexts) || source.ciphertexts.length < 1 || source.ciphertexts.length > 256) throw new Error("Oracle input needs 1 to 256 ciphertext probes");
  const ciphertexts = source.ciphertexts.map((value, index) => {
    const bytes = hex(value, `ciphertext ${index}`, 64);
    if (bytes.length % 16 !== 0) throw new Error(`Oracle ciphertext ${index} must contain complete 16-byte blocks`);
    return bytes;
  });
  return { key, iv, ciphertexts };
}

export async function simulatePaddingOracle(input: PaddingOracleInput, maxProbes: number, yieldControl?: () => Promise<void>): Promise<PaddingOracleReport> {
  if (!Number.isSafeInteger(maxProbes) || maxProbes < 1 || maxProbes > 256) throw new Error("Oracle probe budget must be between 1 and 256");
  const key = await crypto.subtle.importKey("raw", input.key, "AES-CBC", false, ["decrypt"]);
  const outcomes: PaddingOracleReport["outcomes"] = [];
  let valid = 0;
  for (let index = 0; index < Math.min(maxProbes, input.ciphertexts.length); index++) {
    try {
      const plaintext = await crypto.subtle.decrypt({ name: "AES-CBC", iv: input.iv }, key, input.ciphertexts[index]);
      valid++;
      outcomes.push({ index, status: "valid", plaintextBytes: plaintext.byteLength });
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "OperationError")) throw error;
      outcomes.push({ index, status: "invalid" });
    }
    if ((index + 1) % 16 === 0) await yieldControl?.();
  }
  return { probed: outcomes.length, available: input.ciphertexts.length, valid, truncated: outcomes.length < input.ciphertexts.length, outcomes };
}