import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { discoverNpcPasswords } from "./npcDiscovery";
import { verifyNpcHint } from "./npcHint";

const hint = readFileSync(new URL("./testing/google-ctf-2023-npc-hint.dot", import.meta.url), "utf8");
const original = readFileSync(new URL("./testing/google-ctf-2023-npc-USACONST.TXT", import.meta.url));
const dictionary = original.toString("latin1");

describe("NPC graph dictionary discovery", () => {
  it("finds the archived passphrase from only the original graph and full dictionary", async () => {
    expect(createHash("sha256").update(original).digest("hex")).toBe("f450b57276f4c4a5f52f918062ffb710aa7a29add67b38014be2ea01c08ef95b");
    const result = discoverNpcPasswords(hint, dictionary, 1_000_000, 64);
    expect(result).toMatchObject({ nodes: 28, dictionaryWords: 1_087, compatibleWords: 259 });
    expect(result.statesExplored).toBeLessThanOrEqual(1_000_000);
    expect(result.candidates).toContain("standardwatersigngivenchosen");
    expect(verifyNpcHint(hint, "standardwatersigngivenchosen", 100_000).graphValid).toBe(true);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "crypto.graph.npc-discover",
      inputs: { data: textValue(JSON.stringify({ hint, dictionary })) },
      params: { maxStates: 1_000_000, maxCandidates: 64 } });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: result });
  });

  it("authenticates a discovered password against the original age ciphertext", async () => {
    const ciphertext = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-npc-secret.age", import.meta.url)));
    const result = await executeOperation(createDefaultRegistry(), { operationId: "crypto.graph.npc-discover",
      inputs: { data: textValue(JSON.stringify({ hint, dictionary, ageCiphertextHex: Buffer.from(ciphertext).toString("hex") })) },
      params: { maxStates: 1_000_000, maxCandidates: 64 } });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { age: { authenticated: true,
      passphrase: "standardwatersigngivenchosen", utf8Candidate: "CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}", truncated: false }, flagVerified: false } });
  }, 90_000);

  it("enforces graph, dictionary, search and cancellation limits", () => {
    expect(discoverNpcPasswords(hint, dictionary, 1, 64)).toMatchObject({ statesExplored: 1, candidates: [], truncated: true });
    expect(() => discoverNpcPasswords("digraph {}", dictionary, 100, 64)).toThrow(/undirected DOT graph/);
    expect(() => discoverNpcPasswords(hint, "a".repeat(64 * 1024 + 1), 100, 64)).toThrow(/word list or search budget/);
    const controller = new AbortController();
    controller.abort(new Error("NPC search cancelled"));
    expect(() => discoverNpcPasswords(hint, dictionary, 100, 64, controller.signal)).toThrow(/NPC search cancelled/);
  });

  it("rejects malformed optional age bytes before attempting decryption", async () => {
    const result = await executeOperation(createDefaultRegistry(), { operationId: "crypto.graph.npc-discover",
      inputs: { data: textValue(JSON.stringify({ hint, dictionary, ageCiphertextHex: "123" })) },
      params: { maxStates: 1, maxCandidates: 1 } });
    expect(result.run.error?.code).toBe("INVALID_INPUT");
    expect(result.outputs.report).toBeUndefined();
  });
});