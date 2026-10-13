import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractIl2CppLiteral, inspectIl2Cpp, readIl2CppStringLiterals, MAX_IL2CPP_BYTES } from "../../formats/il2cpp";
import { bytesInput } from "../util";

export const il2cppInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.il2cpp.inspect", version: "1.0.0", title: "Inspect IL2CPP metadata", category: "Reverse",
    description: "Inspect bounded Unity global-metadata.dat v24–v31 section offsets/sizes without loading the file or executing game code. Metadata tables and string values are not decoded; modified or encrypted headers are unsupported.",
    keywords: ["unity", "il2cpp", "global-metadata.dat", "game", "metadata", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_IL2CPP_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectIl2Cpp(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const il2cppLiterals = defineOperation<{ maxLiterals: number }>({
  spec: {
    id: "reverse.il2cpp.literals", version: "1.0.0", title: "Read IL2CPP string literals", category: "Reverse",
    description: "Read bounded UTF-8 string literals from an unmodified Unity global-metadata.dat file. Invalid offsets and non-UTF-8 data are rejected; no game code runs.",
    keywords: ["unity", "il2cpp", "string literals", "global-metadata.dat", "game", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      maxLiterals: { type: "integer", title: "Maximum literals", minimum: 1, maximum: 1024, default: 128 },
    }, required: ["maxLiterals"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_IL2CPP_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { report: structuredValue(await readIl2CppStringLiterals(bytesInput(inputs), params.maxLiterals, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const il2cppLiteralExtract = defineOperation<{ index: number }>({
  spec: {
    id: "reverse.il2cpp.literal-extract", version: "1.0.0", title: "Extract IL2CPP literal bytes", category: "Reverse",
    description: "Extract one selected global-metadata.dat string-literal entry as original bytes, including non-UTF-8 entries. No game code executes.",
    keywords: ["unity", "il2cpp", "string literal", "bytes", "extract", "game"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      index: { type: "integer", title: "Literal index (zero-based)", minimum: 0, maximum: 99_999, default: 0 },
    }, required: ["index"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_IL2CPP_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractIl2CppLiteral(bytesInput(inputs), params.index, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
