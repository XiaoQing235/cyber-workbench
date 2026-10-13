export interface LcgXorTranscriptReport {
  observations: string[];
  decimalText: string;
  skippedRsa: number;
  blockBytes: 32;
}

export function recoverLcgXorTranscript(text: string): LcgXorTranscriptReport {
  if (text.length > 8_000) throw new Error("LCG-XOR transcript exceeds 8,000 characters");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("LCG-XOR transcript is not valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length < 6 || parsed.length > 80) throw new Error("LCG-XOR transcript needs 6 to 80 message rows");
  const observations: string[] = [];
  let skippedRsa = 0;
  for (const [index, raw] of parsed.entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`LCG-XOR row ${index} is not an object`);
    const row = raw as Record<string, unknown>;
    if (Object.keys(row).some((key) => !["conversation_time", "mode", "plaintext", "ciphertext"].includes(key))) throw new Error(`LCG-XOR row ${index} has unsupported fields`);
    if (row.mode === "RSA") { skippedRsa++; continue; }
    if (row.mode !== "LCG-XOR" || !Number.isSafeInteger(row.conversation_time) || (row.conversation_time as number) < 0 ||
      typeof row.plaintext !== "string" || typeof row.ciphertext !== "string" || !/^[0-9a-f]{64}$/i.test(row.ciphertext)) {
      throw new Error(`LCG-XOR row ${index} has invalid mode, time, plaintext or 32-byte ciphertext`);
    }
    const plaintext = new TextEncoder().encode(row.plaintext);
    if (plaintext.length > 32 || observations.length >= 64) throw new Error("LCG-XOR plaintext or observation budget is exceeded");
    const recovered = new Uint8Array(32);
    let time = BigInt(row.conversation_time as number);
    for (let at = 31; at >= 0; at--) {
      recovered[at] = Number(time & 0xffn);
      time >>= 8n;
    }
    for (let at = 0; at < 32; at++) {
      recovered[at] ^= Number.parseInt(row.ciphertext.slice(at * 2, at * 2 + 2), 16) ^ (plaintext[at] ?? 0);
    }
    let state = 0n;
    for (const byte of recovered) state = (state << 8n) | BigInt(byte);
    observations.push(state.toString());
  }
  if (observations.length < 6) throw new Error("LCG-XOR transcript needs at least six known-plaintext outputs");
  return { observations, decimalText: observations.join("\n"), skippedRsa, blockBytes: 32 };
}
