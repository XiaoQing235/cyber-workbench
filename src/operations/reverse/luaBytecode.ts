import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectLuaBytecode, MAX_LUA_CHUNK_BYTES } from "../../formats/luaBytecode";
import { bytesInput } from "../util";

export const luaBytecodeInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.lua.bytecode.inspect", version: "1.0.0", title: "Inspect Lua 5.4 bytecode", category: "Reverse",
    description: "Inspect bounded 64-bit Lua 5.4 chunks: functions, instruction offsets, raw opcode previews, constants, and upvalues. Does not execute or decompile bytecode.",
    keywords: ["lua", "luac", "bytecode", "opcodes", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_LUA_CHUNK_BYTES },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectLuaBytecode(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Lua 5.4: ${report.prototypes.length} function(s), ${report.totalInstructions} instruction(s). No bytecode executed.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});