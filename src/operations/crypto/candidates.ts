import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { generatePasswordCandidates, type CandidateOptions } from "../../formats/passwordCandidates";
import { textInput, yieldToEventLoop } from "../util";

export const passwordCandidatesGenerate = defineOperation<Omit<CandidateOptions, "words">>({
  spec: {
    id: "credential.candidates.generate",
    version: "1.0.0",
    title: "Generate password candidates",
    category: "Crypto",
    description: "Generate bounded password candidates from dictionary rules, Hashcat-style masks, or ordered word pairs. Outputs a UTF-8 wordlist and a count report.",
    keywords: ["password", "dictionary", "rules", "mask", "charset", "combine", "wordlist"],
    inputs: [{ name: "words", type: "text" }],
    outputs: [{ name: "candidates", type: "text" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        source: { type: "string", title: "Source", enum: ["dictionary", "mask", "combine"], default: "dictionary" },
        rules: { type: "string", title: "Rules (: l u c r d $x ^x), one per line", multiline: true, maxLength: 1_024, default: ":\nu\n$!" },
        mask: { type: "string", title: "Mask (?l ?u ?d ?s ?a ?1 ??)", maxLength: 128, default: "pass?d?d" },
        customCharset: { type: "string", title: "Custom ?1 characters", maxLength: 1_024, default: "" },
        combineWith: { type: "string", title: "Second word list for ordered pairs", multiline: true, maxLength: 100_000, default: "2024\n2025" },
        maxCandidates: { type: "integer", title: "Maximum candidates", minimum: 1, maximum: 10_000, default: 1_000 },
        maxWork: { type: "integer", title: "Maximum attempted combinations", minimum: 1, maximum: 100_000, default: 10_000 },
        maxOutputBytes: { type: "integer", title: "Maximum output bytes", minimum: 1, maximum: 1_000_000, default: 100_000 },
        unique: { type: "boolean", title: "Remove duplicate candidates", default: true },
      },
      required: ["source", "rules", "mask", "customCharset", "combineWith", "maxCandidates", "maxWork", "maxOutputBytes", "unique"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
    limits: { maxInputBytes: 1_000_000 },
  },
  async run(ctx, inputs, params) {
    const words = textInput(inputs, "words");
    if (words.length > 1_000_000 || new TextEncoder().encode(words).length > 1_000_000) throw new OperationError("INPUT_TOO_LARGE", "Input word list is limited to 1 MB of UTF-8");
    ctx.throwIfAborted();
    const { text, ...report } = await generatePasswordCandidates({ ...params, words }, async () => {
      ctx.throwIfAborted();
      await yieldToEventLoop();
    });
    ctx.throwIfAborted();
    ctx.diagnostic(`Generated ${report.generated} candidate(s) from ${report.work} attempt(s).${report.truncated ? " A configured limit was reached." : ""}`);
    return { candidates: textValue(text), report: structuredValue(report) };
  },
});