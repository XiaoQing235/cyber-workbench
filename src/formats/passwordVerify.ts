import { sha256 } from "@noble/hashes/sha256";

export interface PasswordVerifyReport {
  algorithm: "md5" | "sha256";
  tried: number;
  truncated: boolean;
  matches: { line: number; candidate: string }[];
  digestVerified: boolean;
}

/** Compare UTF-8 candidates to a specifically identified raw digest, never guessing the hash type. */
export async function verifyPasswordCandidates(words: string, digest: string, algorithm: "md5" | "sha256", maxAttempts: number,
  yieldControl?: () => Promise<void>): Promise<PasswordVerifyReport> {
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10_000 ||
    !["md5", "sha256"].includes(algorithm) || !new RegExp(`^[0-9a-f]{${algorithm === "md5" ? 32 : 64}}$`, "i").test(digest) ||
    new TextEncoder().encode(words).length > 1_000_000) throw new Error("Candidate verifier parameters exceed the bounded raw-digest format");
  const encoder = new TextEncoder();
  const md5 = algorithm === "md5" ? (await import("@noble/hashes/legacy")).md5 : null;
  const matches: PasswordVerifyReport["matches"] = [];
  const lines = words.replace(/\r/g, "").split("\n");
  let tried = 0;
  let truncated = false;
  for (const [index, candidate] of lines.entries()) {
    if (!candidate) continue;
    if (tried >= maxAttempts) { truncated = true; break; }
    const bytes = encoder.encode(candidate);
    if (bytes.length > 1024) throw new Error("Password candidate exceeds the 1 KiB budget");
    const hash = md5 ? md5(bytes) : sha256(bytes);
    const actual = Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
    tried++;
    if (actual === digest.toLowerCase()) matches.push({ line: index + 1, candidate });
    if (tried % 250 === 0) await yieldControl?.();
    if (matches.length >= 16) { truncated = true; break; }
  }
  return { algorithm, tried, truncated, matches, digestVerified: matches.length > 0 };
}
