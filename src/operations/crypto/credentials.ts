import { defineOperation } from "../../core/operation/types";
import { OperationError } from "../../core/operation/errors";
import { structuredValue } from "../../core/value";
import { identifyCredentialHashes } from "../../formats/credentialHash";
import { textInput, yieldToEventLoop } from "../util";

export const credentialHashIdentify = defineOperation<{ maxLines: number }>({
  spec: {
    id: "credential.hash-identify",
    version: "1.1.0",
    title: "Identify password hash material",
    category: "Crypto",
    description: "Classify common password-recovery hash lines, including Kerberos etype 23 and Unix shadow, and recommend John and Hashcat formats. Raw digests remain ambiguous.",
    keywords: ["hashcat", "john", "ntlm", "netntlm", "kerberos", "shadow", "password", "bcrypt", "crypt"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: { maxLines: { type: "integer", title: "Maximum non-empty lines", minimum: 1, maximum: 10_000, default: 1_000 } },
      required: ["maxLines"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: 4 * 1024 * 1024 },
  },
  async run(ctx, inputs, params) {
    const text = textInput(inputs);
    if (text.length > 1024 * 1024 || new TextEncoder().encode(text).length > 4 * 1024 * 1024) {
      throw new OperationError("INPUT_TOO_LARGE", "Credential text is limited to 1,048,576 characters and 4 MiB of UTF-8 data");
    }
    const report = await identifyCredentialHashes(text, params.maxLines, async () => {
      ctx.throwIfAborted();
      await yieldToEventLoop();
    });
    ctx.diagnostic(`Identified ${report.matches.length} of ${report.matches.length + report.unrecognised.length} hash line(s).`);
    if (report.truncated) ctx.diagnostic(`Stopped after the configured ${params.maxLines} non-empty lines.`);
    return { report: structuredValue(report) };
  },
});