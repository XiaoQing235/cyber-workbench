import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { analyzeOracleTranscript, type OracleCondition } from "../../formats/oracleTranscript";
import { parsePaddingOracleInput, simulatePaddingOracle } from "../../formats/paddingOracle";
import { textInput, yieldToEventLoop } from "../util";

export const paddingOracleSimulate = defineOperation<{ maxProbes: number }>({
  spec: {
    id: "crypto.oracle.padding-simulate",
    version: "1.0.0",
    title: "Simulate AES-CBC padding oracle",
    category: "Crypto",
    description: "Test up to 256 local AES-CBC ciphertext probes against a supplied key and IV using WebCrypto PKCS#7 validation. No network access or plaintext export.",
    keywords: ["oracle", "padding", "aes", "cbc", "pkcs7", "local", "probes"],
    inputs: [{ name: "probes", type: "text" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: { maxProbes: { type: "integer", title: "Maximum local probes", minimum: 1, maximum: 256, default: 32 } },
      required: ["maxProbes"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 65_536 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs, "probes");
    if (text.length > 65_536) throw new OperationError("INPUT_TOO_LARGE", "Oracle input is limited to 65,536 characters");
    try {
      const input = parsePaddingOracleInput(text);
      const report = await simulatePaddingOracle(input, params.maxProbes, async () => {
        ctx.throwIfAborted();
        await yieldToEventLoop();
      });
      ctx.throwIfAborted();
      ctx.diagnostic(`Tested ${report.probed} local probe(s); ${report.valid} had valid PKCS#7 padding.${report.truncated ? " Probe budget reached." : ""}`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const oracleTranscriptAnalyze = defineOperation<OracleCondition>({
  spec: {
    id: "crypto.oracle.transcript-analyze",
    version: "1.0.0",
    title: "Analyze oracle transcript",
    category: "Crypto",
    description: "Classify imported JSON response records by HTTP status, UTF-8 body length, literal content, or duration, and measure inconsistent repeated requests. Never sends probes.",
    keywords: ["oracle", "transcript", "status", "length", "content", "timing", "noise", "offline"],
    inputs: [{ name: "transcript", type: "text" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        mode: { type: "string", title: "Response condition", enum: ["status", "length", "contains", "timing"], default: "status" },
        statusValue: { type: "integer", title: "HTTP status", minimum: 100, maximum: 599, default: 200 },
        minimumBytes: { type: "integer", title: "Minimum body bytes", minimum: 0, maximum: 16_384, default: 3 },
        contains: { type: "string", title: "Literal body text", maxLength: 256, default: "ok" },
        minimumMs: { type: "number", title: "Minimum duration (ms)", minimum: 0, maximum: 60_000, default: 20 },
      },
      required: ["mode", "statusValue", "minimumBytes", "contains", "minimumMs"],
      additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 1_200_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs, "transcript");
    if (text.length > 1_200_000 || new TextEncoder().encode(text).length > 1_200_000) throw new OperationError("INPUT_TOO_LARGE", "Oracle transcript is limited to 1.2 MB of UTF-8 data");
    try {
      const report = analyzeOracleTranscript(text, params);
      ctx.diagnostic(`Classified ${report.total} stored response(s); ${report.noisyRequests} repeated request(s) had inconsistent outcomes.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});