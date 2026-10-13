import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { analyzeNonceReuse, parseNonceCsv, parseNonceRecords, recoverWithCrib } from "../../formats/nonceReuse";
import { textInput } from "../util";

const INPUT = [{ name: "records", type: "text" }] as const;
const FORMAT = { type: "string" as const, title: "Record format", enum: ["json", "csv"], default: "json" };
const PAIR_PARAMETERS = {
  type: "object" as const,
  properties: {
    format: FORMAT,
    firstIndex: { type: "integer" as const, title: "First record index", minimum: 0, maximum: 63, default: 0 },
    secondIndex: { type: "integer" as const, title: "Second record index", minimum: 0, maximum: 63, default: 1 },
  },
  required: ["firstIndex", "secondIndex"],
  additionalProperties: false as const,
};

async function recordsInput(text: string, format: "json" | "csv" = "json") {
  if (text.length > 1_200_000 || new TextEncoder().encode(text).length > 1_200_000) throw new OperationError("INPUT_TOO_LARGE", "Nonce input is limited to 1.2 MB of JSON or CSV");
  try { return format === "csv" ? await parseNonceCsv(text) : parseNonceRecords(text); }
  catch (error) { throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
}

export const nonceReuseInspect = defineOperation<{ format?: "json" | "csv" }>({
  spec: {
    id: "crypto.nonce-reuse.inspect", version: "1.1.0", title: "Inspect reused nonces", category: "Crypto",
    description: "Group bounded JSON/CSV AES-CTR/GCM ciphertext records by algorithm, key ID, and nonce. Unknown key IDs are only possible reuse; GCM tags are not authenticated.",
    keywords: ["nonce", "iv", "ctr", "gcm", "keystream", "reuse", "json", "csv"],
    inputs: INPUT, outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: { format: FORMAT }, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const records = await recordsInput(textInput(inputs, "records"), params.format);
    const groups = analyzeNonceReuse(records);
    ctx.diagnostic(`Found ${groups.length} reused-nonce group(s) among ${records.length} ciphertexts.`);
    return { report: structuredValue({ recordCount: records.length, groups }) };
  },
});

export const nonceReuseXor = defineOperation<{ firstIndex: number; secondIndex: number; format?: "json" | "csv" }>({
  spec: {
    id: "crypto.nonce-reuse.xor", version: "1.1.0", title: "XOR reused-nonce ciphertexts", category: "Crypto",
    description: "XOR the overlapping bytes of two AES-CTR/GCM ciphertexts sharing a nonce and compatible key ID. This is not plaintext or GCM tag verification.",
    keywords: ["nonce", "iv", "ctr", "gcm", "xor", "crib", "keystream"],
    inputs: INPUT, outputs: [{ name: "xor", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: PAIR_PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const records = await recordsInput(textInput(inputs, "records"), params.format);
    try {
      const { xor, risk } = recoverWithCrib(records, params.firstIndex, params.secondIndex);
      if (risk === "possible") ctx.diagnostic("Key identity is unconfirmed; ciphertext XOR does not prove keystream reuse.");
      return { xor: bytesFrom(xor), report: structuredValue({ firstIndex: params.firstIndex, secondIndex: params.secondIndex, overlapBytes: xor.length, risk }) };
    } catch (error) {
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const nonceReuseCrib = defineOperation<{ firstIndex: number; secondIndex: number; format?: "json" | "csv" }>({
  spec: {
    id: "crypto.nonce-reuse.crib", version: "1.1.0", title: "Apply reused-nonce crib", category: "Crypto",
    description: "Use one record's knownPlaintext hex and offset to derive candidate bytes in a second AES-CTR/GCM ciphertext sharing its nonce. Bytes are not authenticated.",
    keywords: ["nonce", "crib", "known plaintext", "ctr", "gcm", "recover"],
    inputs: INPUT, outputs: [{ name: "candidate", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: PAIR_PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const records = await recordsInput(textInput(inputs, "records"), params.format);
    try {
      const { recovered, offset, risk } = recoverWithCrib(records, params.firstIndex, params.secondIndex);
      if (!recovered?.length || offset === null) throw new Error("Selected pair has no overlapping knownPlaintext crib");
      ctx.diagnostic(`Recovered ${recovered.length} candidate byte(s) at offset ${offset}; plaintext and GCM tags are not verified.`);
      return { candidate: bytesFrom(recovered), report: structuredValue({ firstIndex: params.firstIndex, secondIndex: params.secondIndex, offset, candidateBytes: recovered.length, risk, verified: false }) };
    } catch (error) {
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});