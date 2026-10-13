import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractGodotPckFile, inspectGodotPck } from "../../formats/godotPck";
import { bytesInput, MiB } from "../util";

export const godotPckInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.godot-pck.inspect", version: "1.0.0", title: "Inspect Godot PCK", category: "Reverse",
    description: "Inspect a bounded standalone Godot V4 PCK: engine version, encrypted-directory state, safe file paths, sizes, offsets and declared MD5 values. Checksums are not verified until extraction.",
    keywords: ["godot", "pck", "game", "archive", "resource", "encrypted"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectGodotPck(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Godot ${report.engineVersion} PCK: ${report.encryptedDirectory ? "directory encrypted" : `${report.files.length} listed file(s); MD5 declarations not yet checked`}.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const godotPckExtract = defineOperation<{ path: string }>({
  spec: {
    id: "reverse.godot-pck.extract", version: "1.0.0", title: "Extract Godot PCK file", category: "Reverse",
    description: "Extract an unencrypted Godot V4 PCK member by path, comparing its declared MD5. MD5 detects accidental corruption but does not prove authenticity; encrypted or delta members are not decrypted.",
    keywords: ["godot", "pck", "game", "extract", "md5", "resource"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      path: { type: "string", title: "PCK member path", minLength: 1, maxLength: 1_024, default: "" },
    }, required: ["path"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { data } = await extractGodotPckFile(bytesInput(inputs), params.path, ctx.signal);
      ctx.diagnostic(`Extracted ${params.path} (${data.size} bytes); its declared MD5 matched (not an authenticity proof).`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
