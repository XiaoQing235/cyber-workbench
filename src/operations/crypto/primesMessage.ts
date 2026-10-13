import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { recoverPrimeMessage } from "../../formats/primesMessage";
import { textInput } from "../util";

export const primesMessageRecover = defineOperation<{ maxTerms: number }>({
  spec: {
    id: "crypto.primes.message-recover", version: "1.0.0", title: "Recover indexed-prime message", category: "Crypto",
    description: "Recover a bounded 7-bit ASCII message from hex q and x and a supplied approximate message using exact continued fractions and square-free indexed prime factors. Candidates are verified by re-encoding; a match does not prove the message is uniquely determined.",
    keywords: ["primes", "continued fraction", "indexed prime", "modular", "message"],
    inputs: [{ name: "data", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      maxTerms: { type: "integer", title: "Maximum convergents", minimum: 1, maximum: 2048, default: 2048 },
    }, required: ["maxTerms"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 5_000 },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const report = recoverPrimeMessage(textInput(inputs, "data"), params.maxTerms);
      ctx.diagnostic(`Tested ${report.testedConvergents} convergent(s); ${report.candidate === null ? "no re-encoded message recovered" : `${report.correctedBits} bit(s) corrected and encoding verified`}.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
