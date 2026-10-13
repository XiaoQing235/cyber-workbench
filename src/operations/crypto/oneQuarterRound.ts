import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { recoverOneQuarterRound } from "../../formats/oneQuarterRound";
import { bytesInput, parseHex } from "../util";

const MAX_PACKAGE_BYTES = 600_000;

export const quarterRoundPrefixRecover = defineOperation<{ knownPrefixHex: string }>({
  spec: {
    id: "crypto.chacha.qr1-prefix-recover", version: "1.0.0", title: "Recover one-quarter-round stream", category: "Crypto",
    description: "Recover 4-48 candidate plaintext bytes and the counter from a known 32-byte key and assumed four-byte prefix in a zero-constant, one-quarter-round ChaCha variant. Accepts Numerology-compatible JSON. Not standard ChaCha20; the nonce is irrelevant only over this limited range.",
    keywords: ["chacha", "quarter round", "known plaintext", "counter", "nonce", "numerology"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "candidate", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      knownPrefixHex: { type: "string", title: "Assumed four-byte prefix (hex)", pattern: "^[0-9a-fA-F]{8}$", default: "4354467b" },
    }, required: ["knownPrefixHex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_PACKAGE_BYTES },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const source = bytesInput(inputs);
    if (source.size < 2 || source.size > MAX_PACKAGE_BYTES) throw new OperationError("INPUT_TOO_LARGE", "One-quarter-round JSON package must be within 600,000 bytes");
    try {
      const bytes = await source.read(0, source.size);
      ctx.throwIfAborted();
      if (bytes.length !== source.size) throw new Error("Package read is truncated");
      const document: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      if (!document || typeof document !== "object" || Array.isArray(document)) throw new Error("Expected an object containing cipher_parameters and flag_ciphertext");
      const packageFields = document as Record<string, unknown>;
      const cipherParameters = packageFields.cipher_parameters;
      if (!cipherParameters || typeof cipherParameters !== "object" || Array.isArray(cipherParameters)) throw new Error("Package cipher_parameters are missing");
      const keyHex = (cipherParameters as Record<string, unknown>).key;
      const ciphertextHex = packageFields.flag_ciphertext;
      if (typeof keyHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(keyHex) ||
        typeof ciphertextHex !== "string" || !/^[0-9a-fA-F]{8,96}$/.test(ciphertextHex) || ciphertextHex.length % 2 !== 0) {
        throw new Error("Package key or 4-48 byte flag ciphertext is invalid");
      }
      const result = recoverOneQuarterRound(parseHex(keyHex, false), parseHex(ciphertextHex, false), parseHex(params.knownPrefixHex, false));
      let utf8Candidate: string | null = null;
      try { utf8Candidate = new TextDecoder("utf-8", { fatal: true }).decode(result.plaintext); }
      catch { utf8Candidate = null; }
      ctx.diagnostic(`Derived 32-bit counter ${result.counter} from the assumed prefix; ${result.nonceIndependentBytes} byte(s) are a candidate, not verified plaintext.`);
      return { candidate: bytesFrom(result.plaintext), report: structuredValue({
        counter: result.counter, assumedPrefixHex: params.knownPrefixHex.toLowerCase(),
        nonceIndependentBytes: result.nonceIndependentBytes, utf8Candidate, verified: false,
      }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});