import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { verifyNpcHint } from "./npcHint";

describe("Google CTF 2023 NPC hint graph", () => {
  it("verifies the published password as a labeled Hamiltonian path without decrypting age", async () => {
    const bytes = readFileSync(new URL("./testing/google-ctf-2023-npc-hint.dot", import.meta.url));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("dfa0002d37492e277a82f4b4fd1ebe85f8b2ef3f");
    const hint = bytes.toString("utf8");
    const result = verifyNpcHint(hint, "standardwatersigngivenchosen", 100_000);
    expect(result).toMatchObject({ nodes: 28, edges: 103, statesExplored: 53,
      candidate: "standardwatersigngivenchosen", graphValid: true, truncated: false, passwordVerified: false });
    expect(result.path).toHaveLength(28);
    expect(new Set(result.path).size).toBe(28);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "crypto.graph.npc-hint-verify",
      inputs: { hint: textValue(hint) }, params: { candidate: "standardwatersigngivenchosen", maxStates: 100_000 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: result });
    expect(verifyNpcHint(hint, "standardwatersigngivenchosea", 100_000)).toMatchObject({ graphValid: false, path: null, passwordVerified: false });
    expect(verifyNpcHint(hint, "standardwatersigngivenchosen", 1)).toMatchObject({ truncated: true, graphValid: false });
  });
});
