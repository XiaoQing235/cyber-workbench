import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectSeccomp, MAX_SECCOMP_BYTES } from "../../formats/seccomp";
import { bytesInput } from "../util";

export const seccompInspect = defineOperation<{ arch: number; syscall: number; args: string }>({
  spec: {
    id: "reverse.seccomp.inspect", version: "1.0.0", title: "Inspect seccomp filter", category: "Reverse",
    description: "Inspect raw little-endian sock_filter cBPF and simulate one syscall locally. Supports absolute seccomp_data loads, constant jumps and returns only; reports reachable actions without claiming a complete syscall allowlist.",
    keywords: ["seccomp", "bpf", "syscall", "constraint", "sandbox"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      arch: { type: "integer", title: "Audit architecture (x86-64 = 3221225534)", minimum: 0, maximum: 0xffffffff, default: 0xc000003e },
      syscall: { type: "integer", title: "Syscall number to simulate", minimum: 0, maximum: 0xffffffff, default: 0 },
      args: { type: "string", title: "Six arguments (unsigned decimal or hex, comma-separated)", maxLength: 150, default: "0,0,0,0,0,0" },
    }, required: ["arch", "syscall", "args"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_SECCOMP_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { report: structuredValue(await inspectSeccomp(bytesInput(inputs), params.arch, params.syscall, params.args, ctx.signal)) }; }
    catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
