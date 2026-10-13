import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { verifyNpcHint } from "../../formats/npcHint";
import { textInput } from "../util";

export const npcHintVerify = defineOperation<{ candidate: string; maxStates: number }>({
  spec: {
    id: "crypto.graph.npc-hint-verify", version: "1.0.0", title: "Verify labeled NPC hint path", category: "Crypto",
    description: "Check whether a supplied lowercase candidate spells a distinct-node Hamiltonian path through a bounded undirected DOT graph. A graph-valid candidate is not a verified age password; encrypted data is not decrypted.",
    keywords: ["hamiltonian", "graph", "dot", "password", "npc", "hint"],
    inputs: [{ name: "hint", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      candidate: { type: "string", title: "Candidate password", pattern: "^[a-z]{2,64}$", maxLength: 64, default: "standardwatersigngivenchosen" },
      maxStates: { type: "integer", title: "Maximum search states", minimum: 1, maximum: 1_000_000, default: 100_000 },
    }, required: ["candidate", "maxStates"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 16_384 },
  },
  async run(ctx, inputs, params) {
    try {
      const report = verifyNpcHint(textInput(inputs, "hint"), params.candidate, params.maxStates, ctx.signal);
      ctx.diagnostic(`Explored ${report.statesExplored} graph state(s); ${report.graphValid ? "candidate path exists" : "no path established"}. Password is not verified by decryption.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
