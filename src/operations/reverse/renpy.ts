import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractRenPyIndex, extractRenPyMember, inspectRenPy, listRenPyMembers, MAX_RPA_BYTES } from "../../formats/renpy";
import { bytesInput } from "../util";

export const renpyInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.renpy.inspect", version: "1.0.0", title: "Inspect Ren'Py RPA header", category: "Reverse",
    description: "Inspect the RPA-3.0 index offset and obfuscation key with bounded reads. The compressed pickle index is not unpickled or executed.",
    keywords: ["renpy", "rpa", "game", "archive", "index", "pickle"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_RPA_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectRenPy(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const renpyIndexExtract = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.renpy.index-extract", version: "1.0.0", title: "Extract Ren'Py index bytes", category: "Reverse",
    description: "Extract the compressed RPA-3.0 pickle index as a lazy byte slice for static inspection. No pickle is unpickled or executed.",
    keywords: ["renpy", "rpa", "game", "archive", "index", "pickle", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_RPA_BYTES },
  },
  async run(ctx, inputs) {
    try { return { data: bytesValue(await extractRenPyIndex(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const renpyMembersInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.renpy.members", version: "1.0.0", title: "List Ren'Py RPA members", category: "Reverse",
    description: "List members from a bounded RPA-3.0 zlib index only when its pickle uses a restricted literal dictionary layout. Unsupported pickle opcodes are rejected; no unpickling or code execution occurs.",
    keywords: ["renpy", "rpa", "game", "archive", "members", "pickle"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_RPA_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue({ members: (await listRenPyMembers(bytesInput(inputs), ctx.signal)).map(({ prefix: _prefix, ...member }) => member), indexExecuted: false }) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const renpyMemberExtract = defineOperation<{ path: string }>({
  spec: {
    id: "reverse.renpy.member-extract", version: "1.0.0", title: "Extract Ren'Py RPA member", category: "Reverse",
    description: "Extract a selected member from the restricted RPA-3.0 literal index as a lazy byte artifact. Prefix bytes are restored; pickle code is never executed.",
    keywords: ["renpy", "rpa", "game", "archive", "member", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      path: { type: "string", title: "Member path", minLength: 1, maxLength: 1024, default: "" },
    }, required: ["path"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_RPA_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractRenPyMember(bytesInput(inputs), params.path, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
