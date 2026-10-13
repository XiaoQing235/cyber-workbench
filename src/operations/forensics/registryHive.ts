import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue, textValue } from "../../core/value";
import { decodeRegistryValue, extractRegistryValue, inspectRegistryHive, MAX_HIVE_BYTES } from "../../formats/registryHive";
import { bytesInput } from "../util";

const parameters = { type: "object" as const, properties: {
  keyPath: { type: "string" as const, title: "Key path (blank = root)", maxLength: 2048, default: "" },
}, required: ["keyPath"], additionalProperties: false as const };

export const registryHiveInspect = defineOperation<{ keyPath: string }>({
  spec: {
    id: "forensics.windows.registry.inspect", version: "1.0.0", title: "Inspect registry hive keys", category: "Forensics",
    description: "Inspect a selected key, its immediate subkeys and value names/types/sizes in an offline regf hive using bounded multi-bin reads. Value contents are not returned. Last-write timestamps are metadata, not proof of a specific value change; deleted cells and transaction logs are not recovered.",
    keywords: ["registry", "regf", "hbin", "nk", "windows", "last write"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: parameters, runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_HIVE_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectRegistryHive(bytesInput(inputs), params.keyPath, ctx.signal);
      if (!report.synchronized) ctx.diagnostic("Registry header sequence numbers disagree; transaction logs may be needed for current state.");
      return { report: structuredValue(report) };
    }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const registryHiveTimelineExport = defineOperation<{ keyPath: string; hostname: string }>({
  spec: {
    id: "forensics.windows.registry.timeline-export", version: "1.0.0", title: "Export registry key timeline", category: "Forensics",
    description: "Export last-write timestamps of a selected registry key and immediate subkeys as Plaso-style JSONL for offline timeline correlation.",
    keywords: ["registry", "last write", "timeline", "plaso", "windows"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { ...parameters, properties: { ...parameters.properties,
      hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" },
    }, required: [...parameters.required, "hostname"] },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_HIVE_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectRegistryHive(bytesInput(inputs), params.keyPath, ctx.signal);
      const lines = [report.selected, ...report.children].filter((entry) => entry.lastWrite !== null).map((entry) =>
        JSON.stringify({ timestamp: entry.lastWrite!.utc, parser: "registry_hive", hostname: params.hostname,
          filename: entry.path, message: "Registry key last write (value changed is not established)" }));
      if (!lines.length) throw new Error("Selected registry key and its subkeys have no last-write timestamps");
      ctx.diagnostic(`Exported ${lines.length} registry key last-write event(s).`);
      return { text: textValue(lines.join("\n")) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const registryHiveValueExtract = defineOperation<{ keyPath: string; valueName: string }>({
  spec: {
    id: "forensics.windows.registry.value-extract", version: "1.0.0", title: "Extract registry value bytes", category: "Forensics",
    description: "Extract one selected registry value as raw bytes after validating its allocated cell. Does not interpret the value's type or return other hive content. Big-data values are unsupported.",
    keywords: ["registry", "value", "vk", "bytes", "extract", "windows"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { ...parameters, properties: { ...parameters.properties,
      valueName: { type: "string", title: "Value name (blank = default)", maxLength: 2048, default: "" },
    }, required: [...parameters.required, "valueName"] },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_HIVE_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractRegistryValue(bytesInput(inputs), params.keyPath, params.valueName, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const registryHiveValueDecode = defineOperation<{ keyPath: string; valueName: string }>({
  spec: {
    id: "forensics.windows.registry.value-decode", version: "1.0.0", title: "Decode registry value", category: "Forensics",
    description: "Decode one selected REG_SZ UTF-16LE or REG_DWORD little-endian value from a validated offline hive. Unsupported types and large values remain raw-byte artifacts.",
    keywords: ["registry", "reg_sz", "reg_dword", "windows", "decode", "hive"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { ...parameters, properties: { ...parameters.properties,
      valueName: { type: "string", title: "Value name (blank = default)", maxLength: 2048, default: "" },
    }, required: [...parameters.required, "valueName"] },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_HIVE_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { report: structuredValue(await decodeRegistryValue(bytesInput(inputs), params.keyPath, params.valueName, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
