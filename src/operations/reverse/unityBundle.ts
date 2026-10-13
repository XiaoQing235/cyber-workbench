import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { extractUnityTextAsset, inspectUnityBundle } from "../../formats/unityBundle";
import { bytesInput, MiB } from "../util";

export const unityBundleInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.unity.bundle.inspect", version: "1.0.0", title: "Inspect Unity AssetBundle", category: "Reverse",
    description: "Inspect bounded UnityFS v7/v8 bundles, their decompressed file extents and serialized object names. Rejects other containers and oversized compressed block claims.",
    keywords: ["unity", "assetbundle", "unityfs", "textasset", "game", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectUnityBundle(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Unity ${report.unityRevision}: ${report.files.length} bundle file(s), ${report.assets.length} named object(s).`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const unityTextAssetExtract = defineOperation<{ path: string }>({
  spec: {
    id: "reverse.unity.textasset.extract", version: "1.0.0", title: "Extract Unity TextAsset", category: "Reverse",
    description: "Extract one unencrypted TextAsset by its exact project path from a bounded UnityFS v7/v8 bundle. Other asset types and large embedded resources are not extracted.",
    keywords: ["unity", "assetbundle", "textasset", "extract", "game", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      path: { type: "string", title: "TextAsset project path", minLength: 1, maxLength: 512, default: "" },
    }, required: ["path"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { data, name } = await extractUnityTextAsset(bytesInput(inputs), params.path, ctx.signal);
      ctx.diagnostic(`Extracted Unity TextAsset ${name} (${data.length} bytes) from ${params.path}.`);
      return { data: bytesFrom(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});