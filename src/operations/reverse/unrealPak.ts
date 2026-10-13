import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractUnrealPakEntry, inspectUnrealPak, listUnrealPak } from "../../formats/unrealPak";
import { bytesInput, MiB } from "../util";

export const unrealPakInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.unreal-pak.inspect", version: "1.0.0", title: "Inspect Unreal PAK footer", category: "Reverse",
    description: "Inspect the legacy v1–v3 Unreal PAK footer and verify the bounded index SHA-1. The index and assets are not decoded; newer footer layouts and encrypted indices are unsupported.",
    keywords: ["unreal", "pak", "game", "footer", "index", "sha1"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectUnrealPak(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const unrealPakList = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.unreal-pak.list", version: "1.0.0", title: "List legacy Unreal PAK entries", category: "Reverse",
    description: "List bounded, uncompressed entries from a legacy v3 Unreal PAK index after verifying its SHA-1. Encrypted and compressed entries are rejected.",
    keywords: ["unreal", "pak", "game", "index", "entries"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await listUnrealPak(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const unrealPakExtract = defineOperation<{ path: string }>({
  spec: {
    id: "reverse.unreal-pak.extract", version: "1.0.0", title: "Extract legacy Unreal PAK entry", category: "Reverse",
    description: "Extract an uncompressed legacy v3 Unreal PAK entry after validating its index and SHA-1. No asset code executes.",
    keywords: ["unreal", "pak", "game", "extract", "sha1"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      path: { type: "string", title: "Member path", minLength: 1, maxLength: 1024, default: "" },
    }, required: ["path"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractUnrealPakEntry(bytesInput(inputs), params.path, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
