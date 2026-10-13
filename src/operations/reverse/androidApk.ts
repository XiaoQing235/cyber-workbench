import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractApkDex, inspectApk, MAX_APK_BYTES } from "../../formats/androidManifest";
import { bytesInput } from "../util";

export const apkInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.android.apk.inspect", version: "1.0.0", title: "Inspect Android APK", category: "Reverse",
    description: "Inspect an offline APK ZIP and CRC-validated binary manifest for package, SDK, permissions, security flags and exported components. List DEX and native-library counts; signature artifacts are not verified.",
    keywords: ["android", "apk", "manifest", "permissions", "dex", "mobile", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_APK_BYTES },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const report = await inspectApk(bytesInput(inputs), ctx.signal);
      ctx.throwIfAborted();
      ctx.diagnostic(`APK ${report.manifest.packageName}: ${report.dexFiles.length} DEX file(s), ${report.manifest.permissions.length} permission(s), ${report.manifest.exportedComponents.length} explicitly exported component(s); signatures not verified.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const apkDexExtract = defineOperation<{ dexIndex: number }>({
  spec: {
    id: "reverse.android.apk.dex-extract", version: "1.0.0", title: "Extract APK DEX", category: "Reverse",
    description: "Extract a CRC-checked classes.dex member by zero-based index from a bounded APK. Feed its bytes to Inspect Android DEX; no code executes.",
    keywords: ["android", "apk", "dex", "extract", "bytecode", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { dexIndex: { type: "integer", title: "DEX index (zero-based)", minimum: 0, maximum: 255, default: 0 } },
      required: ["dexIndex"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_APK_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const data = await extractApkDex(bytesInput(inputs), params.dexIndex, ctx.signal);
      ctx.throwIfAborted();
      ctx.diagnostic(`Extracted APK DEX ${params.dexIndex} (${data.size} bytes) with ZIP CRC verified.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});