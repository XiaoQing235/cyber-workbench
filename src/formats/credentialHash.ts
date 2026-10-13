export interface CredentialHashMatch {
  line: number;
  format: string;
  confidence: "exact" | "likely" | "ambiguous";
  hashcatModes: number[];
  johnFormats: string[];
  notes: string[];
}

export interface CredentialHashReport {
  matches: CredentialHashMatch[];
  unrecognised: { line: number; length: number }[];
  truncated: boolean;
}

const HEX_32 = /^[0-9a-f]{32}$/i;
const HEX_48 = /^[0-9a-f]{48}$/i;
const HEX_16 = /^[0-9a-f]{16}$/i;

function splitIdentity(line: string): { hash: string } {
  const marker = line.indexOf("$");
  if (marker > 0 && line[marker - 1] === ":") {
    const hash = line.slice(marker).split(":", 1)[0];
    const metadata = line.slice(marker + hash.length);
    if (metadata === "" || /^(?::[0-9]*){4,7}$/.test(metadata)) return { hash };
  }
  return { hash: line };
}

function matchUnixCrypt(line: string, lineNumber: number): CredentialHashMatch | null {
  const { hash } = splitIdentity(line);
  const formats = [
    { pattern: /^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$/, format: "Unix md5crypt", mode: 500, john: "md5crypt", confidence: "exact" as const },
    { pattern: /^\$2[abxy]\$(?:0[4-9]|[12][0-9]|3[01])\$[./0-9A-Za-z]{53}$/, format: "bcrypt", mode: 3200, john: "bcrypt", confidence: "exact" as const },
    { pattern: /^\$5\$(?:rounds=[1-9][0-9]{3,8}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}$/, format: "Unix sha256crypt", mode: 7400, john: "sha256crypt", confidence: "exact" as const },
    { pattern: /^\$6\$(?:rounds=[1-9][0-9]{3,8}\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$/, format: "Unix sha512crypt", mode: 1800, john: "sha512crypt", confidence: "exact" as const },
  ];
  const found = formats.find(({ pattern }) => pattern.test(hash));
  if (!found) return null;
  return {
    line: lineNumber,
    format: found.format,
    confidence: found.confidence,
    hashcatModes: found.mode === null ? [] : [found.mode],
    johnFormats: [found.john],
    notes: [],
  };
}

function validNtlmV2Blob(blob: string): boolean {
  if (!/^[0-9a-f]{64,}$/i.test(blob) || blob.length % 2 !== 0) return false;
  const lower = blob.toLowerCase();
  if (!lower.startsWith("01010000") || lower.slice(8, 16) !== "00000000" || lower.slice(48, 56) !== "00000000") return false;
  let cursor = 56;
  while (cursor + 8 <= lower.length) {
    const id = lower.slice(cursor, cursor + 4);
    const length = Number.parseInt(lower.slice(cursor + 6, cursor + 8) + lower.slice(cursor + 4, cursor + 6), 16);
    cursor += 8;
    if (id === "0000") return length === 0 && cursor === lower.length;
    cursor += length * 2;
    if (cursor > lower.length) return false;
  }
  return false;
}

function matchNetNtlm(line: string, lineNumber: number): CredentialHashMatch | null {
  const parts = line.split(":");
  if (parts.length !== 6 || parts[1] !== "") return null;
  if (HEX_48.test(parts[3]) && HEX_48.test(parts[4]) && HEX_16.test(parts[5])) {
    return { line: lineNumber, format: "NetNTLMv1", confidence: "exact", hashcatModes: [5500], johnFormats: ["netntlm"], notes: [] };
  }
  const blob = parts[5];
  if (HEX_16.test(parts[3]) && HEX_32.test(parts[4]) && validNtlmV2Blob(blob)) {
    return { line: lineNumber, format: "NetNTLMv2", confidence: "exact", hashcatModes: [5600], johnFormats: ["netntlmv2"], notes: [] };
  }
  return null;
}

function matchPwdump(line: string, lineNumber: number): CredentialHashMatch | null {
  const parts = line.split(":");
  if (parts.length < 4 || !/^\d+$/.test(parts[1]) || !HEX_32.test(parts[2]) || !HEX_32.test(parts[3])) return null;
  return {
    line: lineNumber,
    format: "Windows pwdump (LM + NTLM)",
    confidence: "exact",
    hashcatModes: [3000, 1000],
    johnFormats: ["LM", "NT"],
    notes: ["The record contains separate LM and NT hashes; all-zero or standard empty-hash values may be placeholders."],
  };
}

function matchRawHex(line: string, lineNumber: number): CredentialHashMatch | null {
  if (!HEX_32.test(line)) return null;
  return {
    line: lineNumber,
    format: "Raw 128-bit hexadecimal digest",
    confidence: "ambiguous",
    hashcatModes: [0, 1000],
    johnFormats: ["Raw-MD5", "NT"],
    notes: ["Shape alone cannot distinguish MD5 from NTLM or other 128-bit digests; confirm the source context."],
  };
}

function matchKerberos(line: string, lineNumber: number): CredentialHashMatch | null {
  const asrep = /^\$krb5asrep\$23\$[^:$\s]+:([0-9a-f]{32})\$([0-9a-f]{64,})$/i.exec(line);
  if (asrep && asrep[2].length % 2 === 0) {
    return { line: lineNumber, format: "Kerberos 5 AS-REP (etype 23)", confidence: "exact", hashcatModes: [18200], johnFormats: ["krb5asrep"], notes: [] };
  }
  const tgs = /^\$krb5tgs\$23\$\*[^$*\s]+\$[^$*\s]+\$[^$*\s]+\*\$([0-9a-f]{32})\$([0-9a-f]{64,})$/i.exec(line);
  if (tgs && tgs[2].length % 2 === 0) {
    return { line: lineNumber, format: "Kerberos 5 TGS-REP (etype 23)", confidence: "exact", hashcatModes: [13100], johnFormats: ["krb5tgs"], notes: [] };
  }
  return null;
}

function classify(line: string, lineNumber: number): CredentialHashMatch | null {
  return matchUnixCrypt(line, lineNumber) ?? matchNetNtlm(line, lineNumber) ?? matchPwdump(line, lineNumber) ?? matchKerberos(line, lineNumber) ?? matchRawHex(line, lineNumber);
}

export async function identifyCredentialHashes(text: string, maxLines: number, yieldControl?: () => Promise<void>): Promise<CredentialHashReport> {
  const matches: CredentialHashMatch[] = [];
  const unrecognised: CredentialHashReport["unrecognised"] = [];
  let nonEmpty = 0;
  let lineNumber = 1;
  let start = 0;
  let truncated = false;
  for (let cursor = 0; cursor <= text.length; cursor++) {
    if (cursor > 0 && cursor % 16_384 === 0) await yieldControl?.();
    if (cursor < text.length && text.charCodeAt(cursor) !== 10) continue;
    const line = text.slice(start, cursor).replace(/\r$/, "").trim();
    start = cursor + 1;
    if (line.length > 0) {
      nonEmpty++;
      if (nonEmpty > maxLines) { truncated = true; break; }
      const match = line.length <= 16_384 ? classify(line, lineNumber) : null;
      if (match) matches.push(match);
      else unrecognised.push({ line: lineNumber, length: line.length });
    }
    lineNumber++;
  }
  return { matches, unrecognised, truncated };
}