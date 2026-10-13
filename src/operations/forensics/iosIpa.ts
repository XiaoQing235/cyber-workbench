import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractIpaEntry, inspectIpa, MAX_IPA_BYTES } from "../../formats/iosIpa";
import { bytesInput } from "../util";

export const ipaInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.ios.ipa.inspect", version: "1.0.0", title: "Inspect iOS IPA", category: "Forensics",
    description: "Inspect a bounded IPA ZIP and binary top-level Info.plist for bundle ID, versions, capabilities and permission-key names. Other plist values and signing claims are not returned or verified.",
    keywords: ["ios", "ipa", "plist", "bundle", "mobile", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_IPA_BYTES },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectIpa(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Inspected IPA ${report.bundleId}: ${report.archivedFiles} file(s), ${report.usageDescriptionKeys.length} permission key(s); signature is not verified.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const ipaExtract = defineOperation<{ path: string }>({
  spec: {
    id: "forensics.ios.ipa.extract", version: "1.0.0", title: "Extract IPA file", category: "Forensics",
    description: "Extract an explicit IPA ZIP member with CRC validation. Paths outside the archive, links and unsafe traversal are not followed.",
    keywords: ["ios", "ipa", "plist", "archive", "extract", "mobile", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object", properties: { path: { type: "string", title: "IPA file path", minLength: 1, maxLength: 1_024, default: "" } },
      required: ["path"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_IPA_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const data = await extractIpaEntry(bytesInput(inputs), params.path, ctx.signal);
      ctx.diagnostic(`Extracted ${params.path} (${data.size} bytes), ZIP CRC verified.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});