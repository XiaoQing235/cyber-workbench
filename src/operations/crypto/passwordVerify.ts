import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { verifyPasswordCandidates } from "../../formats/passwordVerify";
import { textInput, yieldToEventLoop } from "../util";

export const passwordCandidatesVerify = defineOperation<{ algorithm: "md5" | "sha256"; digest: string; maxAttempts: number }>({
  spec: {
    id: "credential.candidates.verify", version: "1.0.0", title: "Verify password candidates", category: "Crypto",
    description: "Check a bounded UTF-8 wordlist against an explicitly chosen raw MD5 or SHA-256 digest. A match verifies only the chosen digest, not any ambiguous hash classification.",
    keywords: ["password", "dictionary", "hash", "md5", "sha256", "verify"],
    inputs: [{ name: "words", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      algorithm: { type: "string", title: "Digest algorithm", enum: ["md5", "sha256"], default: "sha256" },
      digest: { type: "string", title: "Expected hexadecimal digest", maxLength: 64, default: "" },
      maxAttempts: { type: "integer", title: "Maximum candidates to test", minimum: 1, maximum: 10_000, default: 1000 },
    }, required: ["algorithm", "digest", "maxAttempts"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 1_000_000 },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await verifyPasswordCandidates(textInput(inputs, "words"), params.digest, params.algorithm, params.maxAttempts, async () => {
        ctx.throwIfAborted(); await yieldToEventLoop();
      });
      ctx.throwIfAborted();
      return { report: structuredValue(report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
