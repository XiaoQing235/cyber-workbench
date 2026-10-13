import type { Finding } from "../../core/analysis/finding";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { SIGNATURES, looksLikeZlib, matchesAt, scanSignatures } from "../../formats/signatures";
import { bytesInput, MiB } from "../util";

const SAMPLE_BYTES = 8 * MiB;
const EMBEDDED_SCAN_BYTES = 64 * MiB;
const EMBEDDED_SCAN_CHUNK = 4 * MiB;
const MAX_EMBEDDED_HITS = 50;

export interface EmbeddedHit {
  type: string;
  description: string;
  offset: number;
}

export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]++;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function printableRatio(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 0x20 && byte < 0x7f) || byte === 0x09 || byte === 0x0a || byte === 0x0d) printable++;
  }
  return printable / bytes.length;
}

const charTable = (chars: string) => {
  const table = new Uint8Array(256);
  for (const c of chars) table[c.charCodeAt(0)] = 1;
  return table;
};
const BASE64_CHARS = charTable("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-");
const HEX_CHARS = charTable("0123456789abcdefABCDEF");
const BINARY_CHARS = charTable("01");
const WHITESPACE = charTable(" \t\r\n");

/** The inspector to suggest for a detected type. */
const INSPECTORS: Record<string, string> = {
  png: "png.inspect",
  bmp: "bmp.inspect",
  pcap: "pcap.inspect",
  pcapng: "pcap.inspect",
  sqlite: "sqlite.inspect",
  elf: "code.disasm",
  pe: "code.disasm",
  macho: "code.disasm",
};

function textShape(bytes: Uint8Array): "base64" | "hex" | "binary-digits" | null {
  let base64 = true;
  let hex = true;
  let binary = true;
  let significant = 0;
  for (const byte of bytes) {
    if (WHITESPACE[byte]) continue;
    significant++;
    base64 &&= BASE64_CHARS[byte] === 1;
    hex &&= HEX_CHARS[byte] === 1;
    binary &&= BINARY_CHARS[byte] === 1;
    if (!base64 && !hex && !binary) return null;
  }
  if (significant < 8) return null;
  if (binary) return "binary-digits";
  if (hex) return "hex";
  return base64 ? "base64" : null;
}

export const fileDetect = defineOperation<Record<string, never>>({
  spec: {
    id: "file.detect",
    version: "1.0.0",
    title: "Detect file type",
    category: "Analysis",
    description:
      "Identify the format from magic bytes, measure entropy and printable ratio, and find embedded file signatures worth carving.",
    keywords: ["magic", "identify", "type", "entropy", "carve", "binwalk", "file"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    const head = await source.read(0, 4096);
    const findings: Finding[] = [];

    const candidates = SIGNATURES.filter((signature) => {
      const at = signature.offset ?? 0;
      return matchesAt(head, at, signature.magic) && (signature.validate?.(head, at) ?? true);
    }).map((signature) => ({ type: signature.type, description: signature.description }));
    if (candidates.length === 0 && looksLikeZlib(head)) {
      candidates.push({ type: "zlib", description: "zlib stream (weak: 2-byte header check)" });
    }

    const sample = await source.read(0, SAMPLE_BYTES);
    const entropy = Math.round(shannonEntropy(sample) * 1000) / 1000;
    const printable = Math.round(printableRatio(sample) * 1000) / 1000;

    const scanEnd = Math.min(source.size, EMBEDDED_SCAN_BYTES);
    const embedded: EmbeddedHit[] = (
      await scanSignatures(source, { start: 1, end: scanEnd, maxHits: MAX_EMBEDDED_HITS, chunkSize: EMBEDDED_SCAN_CHUNK, signal: ctx.signal })
    ).map(({ signature, offset }) => ({ type: signature.type, description: signature.description, offset }));

    if (candidates.length > 0) {
      const inspector = INSPECTORS[candidates[0].type];
      findings.push({
        id: "detect.type",
        ruleId: "detect.signature",
        severity: candidates[0].description.includes("weak") ? "weak" : "strong",
        message: `Signature matches ${candidates.map((c) => c.description).join(", ")}`,
        span: { offset: 0, length: Math.min(16, source.size) },
        evidence: candidates.map((c) => ({
          kind: "signature" as const,
          tier: c.description.includes("weak") ? ("weak" as const) : ("strong" as const),
          detail: `Magic bytes of ${c.description}. A signature identifies a format, not that the rest of the file is valid`,
        })),
        ...(inspector ? { suggestion: { operationId: inspector, label: "Inspect", then: [] } } : {}),
      });
    }
    if (candidates.length === 0 && printable > 0.95 && sample.length > 0) {
      const shape = textShape(sample);
      findings.push({
        id: "detect.text",
        ruleId: "detect.text-shape",
        severity: "medium",
        message:
          shape === "base64"
            ? "Printable text using only the Base64 alphabet"
            : shape === "hex"
              ? "Printable text containing only hex digits"
              : shape === "binary-digits"
                ? "Printable text containing only 0 and 1"
                : `Mostly printable text (${Math.round(printable * 100)}%)`,
        evidence: [
          {
            kind: "plausibility",
            tier: "medium",
            detail: `${Math.round(printable * 100)}% of the first ${sample.length} bytes are printable${shape ? `; every non-space character is in the ${shape} alphabet` : ""}`,
          },
        ],
        suggestion:
          shape === "base64" || shape === "hex"
            ? { operationId: "decode.auto", label: "Search for encodings", then: [] }
            : { operationId: "text.decode", label: "Decode as text" },
      });
    }
    if (entropy > 7.5) {
      findings.push({
        id: "detect.entropy",
        severity: "weak",
        message: `High entropy (${entropy} bits/byte): compressed or encrypted data. High entropy alone does not prove encryption.`,
      });
    }
    for (const hit of embedded.slice(0, 10)) {
      findings.push({
        id: `detect.embedded.${hit.offset}`,
        ruleId: "detect.embedded",
        severity: "weak",
        message: `${hit.description} signature at offset ${hit.offset} (0x${hit.offset.toString(16)})`,
        span: { offset: hit.offset, length: 8 },
        evidence: [
          {
            kind: "signature",
            tier: "weak",
            detail: `${hit.description} magic bytes inside other data. They can occur by chance; carve and check the structure`,
            span: { offset: hit.offset, length: 8 },
          },
        ],
        suggestion: { operationId: "bytes.slice", params: { offset: hit.offset, length: -1 }, label: "Carve from here" },
      });
    }

    return {
      report: structuredValue({
        size: source.size,
        candidates,
        entropyBitsPerByte: entropy,
        printableRatio: printable,
        sampledBytes: sample.length,
        embedded,
        embeddedScanLimited: source.size > EMBEDDED_SCAN_BYTES || embedded.length >= MAX_EMBEDDED_HITS,
        findings,
      }),
    };
  },
});
