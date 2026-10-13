import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { extractDotNetString, inspectDotNet, MAX_DOTNET_BYTES } from "../../formats/dotnet";
import { bytesInput } from "../util";

export const dotnetInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.dotnet.inspect", version: "1.2.0", title: "Inspect .NET assembly", category: "Reverse",
    description: "Inspect a bounded PE/CLR header, entry-point token, BSJB streams, metadata table row counts and optional Module name offline. Assembly code is not executed or decompiled.",
    keywords: ["dotnet", ".net", "clr", "c#", "pe", "bsjb", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_DOTNET_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectDotNet(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const dotnetString = defineOperation<{ offset: number }>({
  spec: {
    id: "reverse.dotnet.string", version: "1.0.0", title: "Extract .NET metadata string", category: "Reverse",
    description: "Read one bounded, null-terminated UTF-8 entry at an explicit offset in a validated CLR #Strings heap. Does not execute the assembly or infer which metadata row references the entry.",
    keywords: ["dotnet", "clr", "metadata", "strings", "heap", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: {
      offset: { type: "integer", title: "#Strings heap offset (zero is reserved)", minimum: 1, maximum: 8 * 1024 * 1024, default: 1 },
    }, required: ["offset"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_DOTNET_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { text: textValue(await extractDotNetString(bytesInput(inputs), params.offset, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
