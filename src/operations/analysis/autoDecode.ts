import type { Evidence, Finding, SuggestedStep, Suggestion } from "../../core/analysis/finding";
import type { Bytes } from "../../core/bytes/ByteSource";
import { MemorySource, readAll } from "../../core/bytes/sources";
import { crc32 } from "../../core/checksum/crc32";
import { InflateLimitError, inflate, type InflateFormat } from "../../core/compression/inflate";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { formatSize, structuredValue } from "../../core/value";
import { SIGNATURES, looksLikeZlib, matchesAt } from "../../formats/signatures";
import { decodeBase64 } from "../encoding/base64";
import { bytesInput, MiB, parseHex, yieldToEventLoop } from "../util";

export const DEFAULT_FLAG_PATTERN = "[A-Za-z0-9_]{2,24}\\{[^{}\\n]{1,256}\\}";

const INFLATE_LIMIT = 32 * MiB;
const MATCH_WINDOW = 16 * MiB;
const MIN_ENCODED_CHARS = 8;
const MIN_PRINTABLE_PREFIX = 16;
const MAX_FLAGS_PER_NODE = 5;
const MAX_CANDIDATES = 10;
const PREVIEW_CHARS = 120;

const TEXT_STEP: SuggestedStep = { operationId: "text.decode", params: { charset: "utf-8", onInvalid: "error" } };
const BASE64_STANDARD = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64_URL = /^[A-Za-z0-9_-]+={0,2}$/;
const HEX_DIGITS_ONLY = /^[0-9a-fA-F]+$/;
const HEX_TEXT = /^[\s0-9a-fA-Fx\\:,;._-]+$/;
const REVERSED_BASE64 = /^={1,2}[A-Za-z0-9+/_-]{6,}$/;
// Two-byte magics (BM, MZ, UTF-16 BOMs) match decoded noise too often to be evidence; gzip is decoded as a layer.
const FILE_SIGNATURES = SIGNATURES.filter((s) => s.magic.length >= 3 && s.type !== "gzip" && !s.type.startsWith("bom-"));

/** One decoding applied to a node, with the operation steps that reproduce it exactly. */
interface Layer {
  label: string;
  steps: SuggestedStep[];
  bytes: Bytes;
  evidence: Evidence[];
}

interface SearchNode {
  bytes: Bytes;
  layers: string[];
  steps: SuggestedStep[];
  evidence: Evidence[];
}

interface FlagMatch {
  text: string;
  offset: number;
}

export interface EvidenceScore {
  targetMatch: boolean;
  strong: number;
  medium: number;
  weak: number;
}

export interface DecodeCandidate {
  kind: "flag" | "file" | "text";
  layers: string[];
  steps: SuggestedStep[];
  size: number;
  flags: FlagMatch[];
  fileType?: string;
  preview?: string;
  /** Every observation along the path and about the result, in order. */
  evidence: Evidence[];
  score: EvidenceScore;
}

const isTextByte = (byte: number) => (byte >= 0x20 && byte < 0x7f) || byte === 0x09 || byte === 0x0a || byte === 0x0d;

function printablePrefix(bytes: Bytes): number {
  let end = 0;
  while (end < bytes.length && isTextByte(bytes[end])) end++;
  return end;
}

/** One character per byte, so match positions are byte offsets. */
function binaryString(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return out;
}

function base64Layer(text: string, compact: string): Layer | null {
  if (compact.length < MIN_ENCODED_CHARS || HEX_DIGITS_ONLY.test(compact)) return null;
  const alphabet = BASE64_STANDARD.test(compact) ? "standard" : BASE64_URL.test(compact) ? "url" : null;
  if (!alphabet) return null;
  try {
    const label = alphabet === "url" ? "Base64 (URL-safe)" : "Base64";
    const aligned = compact.length % 4 === 0;
    return {
      label,
      steps: [TEXT_STEP, { operationId: "base64.decode", params: { alphabet, requirePadding: false } }],
      bytes: decodeBase64(text, alphabet, false).bytes,
      evidence: [
        {
          kind: "decode",
          tier: aligned ? "medium" : "weak",
          detail: `${label}: ${compact.length} characters, all in the alphabet${aligned ? ", length a multiple of 4" : ""}${compact.endsWith("=") ? ", with padding" : ""}; decodes without error`,
        },
      ],
    };
  } catch {
    return null;
  }
}

function hexLayer(text: string): Layer | null {
  if (!HEX_TEXT.test(text)) return null;
  try {
    const bytes = parseHex(text, true);
    if (bytes.length * 2 < MIN_ENCODED_CHARS) return null;
    return {
      label: "Hex",
      steps: [TEXT_STEP, { operationId: "hex.decode", params: { ignoreSeparators: true } }],
      bytes,
      evidence: [{ kind: "decode", tier: "medium", detail: `Hex: ${bytes.length * 2} hex digits decode to ${bytes.length} bytes` }],
    };
  } catch {
    return null;
  }
}

function reverseLayer(bytes: Bytes, compact: string): Layer | null {
  if (!REVERSED_BASE64.test(compact)) return null;
  return {
    label: "Reverse",
    steps: [{ operationId: "bytes.reverse", params: { groupSize: 0, remainder: "keep" } }],
    bytes: bytes.slice().reverse(),
    evidence: [{ kind: "structure", tier: "medium", detail: 'Reverse: starts with "=" padding, as reversed Base64 does' }],
  };
}

/** Text followed by junk, typical of LSB output: keep the text. */
function prefixLayer(bytes: Bytes): Layer | null {
  const end = printablePrefix(bytes);
  if (end < MIN_PRINTABLE_PREFIX || end === bytes.length) return null;
  return {
    label: `Text prefix (${end} bytes)`,
    steps: [{ operationId: "bytes.slice", params: { offset: 0, length: end } }],
    bytes: bytes.subarray(0, end),
    evidence: [
      {
        kind: "structure",
        tier: end >= 32 ? "medium" : "weak",
        detail: `Text prefix: ${end} printable bytes, then ${bytes.length - end} bytes that are not text`,
      },
    ],
  };
}

async function inflateLayer(bytes: Bytes, format: InflateFormat, signal: AbortSignal): Promise<Layer | null> {
  try {
    // Partial output is kept: data after a valid stream is common and the decoded part still counts.
    const result = await inflate(new MemorySource(bytes), format, { maxOutputBytes: INFLATE_LIMIT, signal });
    if (result.bytes.length === 0) return null;
    const header: Evidence =
      format === "gzip"
        ? { kind: "signature", tier: "medium", detail: "gzip: magic bytes 1f 8b 08" }
        : { kind: "structure", tier: "weak", detail: "zlib: header check bits valid (only a 2-byte check)" };
    const integrity: Evidence = result.error
      ? { kind: "integrity", tier: "weak", detail: `${format}: stream broke off after ${result.bytes.length} bytes; partial output kept` }
      : { kind: "integrity", tier: "strong", detail: `${format}: ${result.bytes.length} bytes decompressed, end-of-stream checksum verified` };
    return {
      label: format,
      steps: [{ operationId: "zlib.inflate", params: { format, maxOutputBytes: INFLATE_LIMIT, allowPartial: true } }],
      bytes: result.bytes,
      evidence: [header, integrity],
    };
  } catch (error) {
    if (error instanceof InflateLimitError) return null;
    throw error;
  }
}

async function expand(bytes: Bytes, signal: AbortSignal): Promise<Layer[]> {
  const layers: (Layer | null)[] = [];
  if (printablePrefix(bytes) === bytes.length) {
    const text = new TextDecoder().decode(bytes);
    const compact = text.replace(/\s+/g, "");
    layers.push(base64Layer(text, compact), hexLayer(text), reverseLayer(bytes, compact));
  } else {
    layers.push(prefixLayer(bytes));
  }
  if (looksLikeZlib(bytes)) layers.push(await inflateLayer(bytes, "zlib", signal));
  if (bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 0x08) layers.push(await inflateLayer(bytes, "gzip", signal));
  return layers.filter((layer): layer is Layer => layer !== null);
}

function findFlags(bytes: Bytes, pattern: RegExp): FlagMatch[] {
  const subject = binaryString(bytes.subarray(0, MATCH_WINDOW));
  const flags: FlagMatch[] = [];
  pattern.lastIndex = 0;
  for (let match = pattern.exec(subject); match && flags.length < MAX_FLAGS_PER_NODE; match = pattern.exec(subject)) {
    if (match[0] === "") {
      pattern.lastIndex++;
      continue;
    }
    flags.push({ text: match[0], offset: match.index });
  }
  return flags;
}

function readablePreview(bytes: Bytes): string | undefined {
  if (bytes.length < 4) return undefined;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, 64 * 1024), { stream: true });
  } catch {
    return undefined;
  }
  let control = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) || code === 0x7f) control++;
  }
  return control <= text.length * 0.02 ? text.slice(0, PREVIEW_CHARS) : undefined;
}

function score(evidence: readonly Evidence[], targetMatch: boolean): EvidenceScore {
  const count = (tier: Evidence["tier"]) => evidence.filter((item) => item.tier === tier).length;
  return { targetMatch, strong: count("strong"), medium: count("medium"), weak: count("weak") };
}

/** Orders by evidence, never by an invented probability: strong before medium before weak. */
const rank = (s: EvidenceScore) => Number(s.targetMatch) * 1e6 + s.strong * 1e4 + s.medium * 1e2 + s.weak;

function assess(node: SearchNode, pattern: RegExp, isLeaf: boolean): DecodeCandidate | null {
  const make = (kind: DecodeCandidate["kind"], extra: Evidence, fields: Partial<DecodeCandidate>): DecodeCandidate => {
    const evidence = [...node.evidence, extra];
    return {
      kind,
      layers: node.layers,
      steps: node.steps,
      size: node.bytes.length,
      flags: [],
      ...fields,
      evidence,
      score: score(evidence, kind === "flag"),
    };
  };
  const flags = findFlags(node.bytes, pattern);
  if (flags.length > 0) {
    const where = node.layers.length === 0 ? `at offset ${flags[0].offset} of the input` : "in the decoded result";
    return make(
      "flag",
      {
        kind: "targetMatch",
        tier: "strong",
        detail: `Flag pattern matches ${JSON.stringify(flags[0].text)} ${where}. A pattern match is not proof the flag is correct.`,
        ...(node.layers.length === 0 ? { span: { offset: flags[0].offset, length: flags[0].text.length } } : {}),
      },
      { flags },
    );
  }
  if (node.layers.length === 0) return null;
  const signature = FILE_SIGNATURES.find((s) => matchesAt(node.bytes, s.offset ?? 0, s.magic));
  if (signature) {
    return make(
      "file",
      { kind: "signature", tier: signature.magic.length >= 4 ? "medium" : "weak", detail: `Result starts with the ${signature.description} signature` },
      { fileType: signature.description },
    );
  }
  const preview = isLeaf ? readablePreview(node.bytes) : undefined;
  if (preview === undefined) return null;
  return make("text", { kind: "plausibility", tier: "medium", detail: "Result is valid UTF-8 with almost no control characters" }, { preview });
}

function describe(candidate: DecodeCandidate): string {
  const via = candidate.layers.join(" → ");
  switch (candidate.kind) {
    case "flag": {
      const flags = candidate.flags.map((flag) => flag.text).join(", ");
      return via ? `Possible flag after ${via} (unverified): ${flags}` : `Possible flag in the input (unverified): ${flags}`;
    }
    case "file":
      return `${via} produces ${candidate.fileType} (${candidate.size} bytes)`;
    case "text":
      return `${via} produces readable text: ${JSON.stringify(candidate.preview)}`;
  }
}

function toFinding(candidate: DecodeCandidate, index: number): Finding {
  const [first, ...rest] = candidate.steps;
  const suggestion: Suggestion | undefined =
    candidate.steps.length > 0
      ? {
          ...first,
          label: candidate.steps.length === 1 ? "Run this step" : `Run these ${candidate.steps.length} steps`,
          then: rest,
        }
      : undefined;
  const flag = candidate.flags[0];
  return {
    id: `decode.candidate.${index}`,
    ruleId: "decode.search",
    severity: candidate.kind === "flag" ? "strong" : "medium",
    message: describe(candidate),
    evidence: candidate.evidence,
    ...(candidate.layers.length === 0 && flag ? { span: { offset: flag.offset, length: flag.text.length } } : {}),
    ...(suggestion ? { suggestion } : {}),
  };
}

const KIND_RANK: Record<DecodeCandidate["kind"], number> = { flag: 0, file: 1, text: 2 };
const nodeKey = (bytes: Bytes) => `${bytes.length}:${crc32(bytes)}`;

type SearchParams = {
  flagPattern: string;
  maxDepth: number;
  maxNodes: number;
  maxActive: number;
  keptPerBranch: number;
  maxBytes: number;
  maxRoundMs: number;
};

export const autoDecode = defineOperation<SearchParams>({
  spec: {
    id: "decode.auto",
    version: "1.1.0",
    title: "Auto-decode (search encodings)",
    category: "Analysis",
    description:
      "Beam search over layered decodings (text prefix, Base64, hex, reversed text, zlib, gzip) within explicit budgets. Reports results containing a flag-like match, a known file type or readable text, each with its evidence. Matches are candidates, not verified flags.",
    keywords: ["magic", "auto", "decode", "flag", "layers", "nested", "cyberchef", "explore"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        flagPattern: {
          type: "string",
          title: "Flag pattern (regular expression)",
          minLength: 1,
          default: DEFAULT_FLAG_PATTERN,
        },
        maxDepth: { type: "integer", title: "Maximum layers", minimum: 1, maximum: 12, default: 6 },
        maxNodes: { type: "integer", title: "Maximum attempts", minimum: 1, maximum: 1000, default: 100 },
        maxActive: { type: "integer", title: "Active candidates per round", minimum: 1, maximum: 1000, default: 100 },
        keptPerBranch: { type: "integer", title: "Kept per branch", minimum: 1, maximum: 100, default: 20 },
        maxBytes: { type: "integer", title: "Bytes examined (total)", minimum: 1024, maximum: 1024 * MiB, default: 128 * MiB },
        maxRoundMs: { type: "integer", title: "Time per round (ms)", minimum: 100, maximum: 60_000, default: 5000 },
      },
      required: ["flagPattern", "maxDepth", "maxNodes", "maxActive", "keptPerBranch", "maxBytes", "maxRoundMs"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
    limits: { maxInputBytes: 32 * MiB },
  },
  async run(ctx, inputs, params) {
    let pattern: RegExp;
    try {
      pattern = new RegExp(params.flagPattern, "g");
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new OperationError("INVALID_PARAMS", `Flag pattern is not a valid regular expression: ${reason}`);
    }

    const root = await readAll(bytesInput(inputs));
    let frontier: SearchNode[] = [{ bytes: root, layers: [], steps: [], evidence: [] }];
    const seen = new Set([nodeKey(root)]);
    const reportedFlags = new Set<string>();
    const candidates: DecodeCandidate[] = [];
    const stoppedBy = new Set<string>();
    const narrowedBy = new Set<string>();
    let explored = 0;
    let bytesExamined = 0;
    let pruned = 0;
    let depth = 0;

    // One round per depth: expand every active node, keep the best children, then cap the frontier.
    search: for (; frontier.length > 0; depth++) {
      const roundStart = performance.now();
      const next: SearchNode[] = [];
      for (const node of frontier) {
        ctx.throwIfAborted();
        if (explored >= params.maxNodes) stoppedBy.add(`maximum attempts (${params.maxNodes})`);
        else if (bytesExamined + node.bytes.length > params.maxBytes) stoppedBy.add(`bytes examined (${formatSize(params.maxBytes)})`);
        else if (performance.now() - roundStart > params.maxRoundMs) stoppedBy.add(`time per round (${params.maxRoundMs} ms)`);
        if (stoppedBy.size > 0) break search;
        explored++;
        bytesExamined += node.bytes.length;

        const layers = depth < params.maxDepth ? await expand(node.bytes, ctx.signal) : [];
        const children = layers
          .filter((layer) => {
            const key = nodeKey(layer.bytes);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
          })
          .map((layer) => ({
            bytes: layer.bytes,
            layers: [...node.layers, layer.label],
            steps: [...node.steps, ...layer.steps],
            evidence: [...node.evidence, ...layer.evidence],
          }))
          .sort((a, b) => rank(score(b.evidence, false)) - rank(score(a.evidence, false)));
        if (children.length > params.keptPerBranch) {
          pruned += children.length - params.keptPerBranch;
          narrowedBy.add(`kept per branch (${params.keptPerBranch})`);
        }
        next.push(...children.slice(0, params.keptPerBranch));

        const candidate = assess(node, pattern, layers.length === 0);
        // Rounds go by depth, so the first chain reaching a flag is the shortest one.
        if (candidate && !(candidate.kind === "flag" && candidate.flags.every((f) => reportedFlags.has(f.text)))) {
          for (const flag of candidate.flags) reportedFlags.add(flag.text);
          candidates.push(candidate);
        }
        if (explored % 8 === 0) await yieldToEventLoop();
      }
      next.sort((a, b) => rank(score(b.evidence, false)) - rank(score(a.evidence, false)));
      if (next.length > params.maxActive) {
        pruned += next.length - params.maxActive;
        narrowedBy.add(`active candidates (${params.maxActive})`);
      }
      frontier = next.slice(0, params.maxActive);
    }

    candidates.sort(
      (a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind] || rank(b.score) - rank(a.score) || a.layers.length - b.layers.length,
    );
    const kept = candidates.slice(0, MAX_CANDIDATES);
    const findings = kept.map(toFinding);
    const limits = [...stoppedBy, ...narrowedBy];
    const searchComplete = limits.length === 0;
    const budget = { attempts: explored, bytesExamined, depthReached: Math.max(0, depth - 1), pruned, stoppedBy: [...stoppedBy], narrowedBy: [...narrowedBy] };
    if (!searchComplete) {
      findings.push({
        id: "decode.budget",
        ruleId: "decode.search",
        severity: "weak",
        message: `Search limited by ${limits.join(", ")} after ${explored} attempts and ${formatSize(bytesExamined)} examined; raise the budget to search further.`,
      });
    } else if (kept.length === 0) {
      findings.push({
        id: "decode.none",
        ruleId: "decode.search",
        severity: "weak",
        message: `No flag-like match, known file type or readable text in ${explored} decoding attempt(s).`,
      });
    }
    return { report: structuredValue({ explored, searchComplete, budget, candidates: kept, findings }) };
  },
});
