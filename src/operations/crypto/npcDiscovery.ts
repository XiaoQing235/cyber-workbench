import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { MemorySource } from "../../core/bytes/sources";
import { structuredValue } from "../../core/value";
import { decryptAgePassphrase, MAX_AGE_CIPHERTEXT_BYTES } from "../../formats/agePassphrase";
import { discoverNpcPasswords } from "../../formats/npcDiscovery";
import { parseHex, textInput } from "../util";

const MAX_AGE_ATTEMPTS = 16;

export const npcPasswordsDiscover = defineOperation<{ maxStates: number; maxCandidates: number }>({
  spec: {
    id: "crypto.graph.npc-discover", version: "1.1.0", title: "Search NPC graph dictionary", category: "Crypto",
    description: "Search bounded dictionary-word paths over a labeled DOT graph using JSON hint and dictionary strings. Optional ageCiphertextHex authenticates up to 16 discovered candidates. Search may be truncated.",
    keywords: ["npc", "hamiltonian", "graph", "word list", "dictionary", "password"],
    inputs: [{ name: "data", type: "text" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      maxStates: { type: "integer", title: "Maximum graph states", minimum: 1, maximum: 1_000_000, default: 1_000_000 },
      maxCandidates: { type: "integer", title: "Maximum candidates", minimum: 1, maximum: 64, default: 64 },
    }, required: ["maxStates", "maxCandidates"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: 256 * 1024 },
  },
  async run(ctx, inputs, params) {
    try {
      const text = textInput(inputs, "data");
      if (text.length > 256 * 1024) throw new Error("NPC input exceeds 256 KiB");
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("NPC input must be a JSON object");
      const document = parsed as Record<string, unknown>;
      if (Object.keys(document).some((key) => key !== "hint" && key !== "dictionary" && key !== "ageCiphertextHex") ||
        typeof document.hint !== "string" || typeof document.dictionary !== "string") {
        throw new Error("NPC input needs hint and dictionary strings, with optional ageCiphertextHex");
      }
      const report = discoverNpcPasswords(document.hint, document.dictionary, params.maxStates, params.maxCandidates, ctx.signal);
      if (document.ageCiphertextHex === undefined) {
        ctx.diagnostic(`Found ${report.candidates.length} graph-valid password candidate(s) after ${report.statesExplored} states${report.truncated ? "; search truncated" : ""}. No age password was verified.`);
        return { report: structuredValue(report) };
      }
      if (typeof document.ageCiphertextHex !== "string" || document.ageCiphertextHex.length < 200 ||
        document.ageCiphertextHex.length > MAX_AGE_CIPHERTEXT_BYTES * 2 || !/^(?:[0-9a-fA-F]{2})+$/.test(document.ageCiphertextHex)) {
        throw new Error("ageCiphertextHex must be a bounded binary age file encoded as complete hex bytes");
      }
      const source = new MemorySource(parseHex(document.ageCiphertextHex, false));
      let authenticated: { passphrase: string; plaintextBytes: number; utf8Candidate: string | null } | null = null;
      let attempts = 0;
      for (const passphrase of report.candidates.slice(0, MAX_AGE_ATTEMPTS)) {
        ctx.throwIfAborted();
        attempts++;
        try {
          const result = await decryptAgePassphrase(source, passphrase, ctx.signal);
          let utf8Candidate: string | null = null;
          try { utf8Candidate = new TextDecoder("utf-8", { fatal: true }).decode(result.plaintext); }
          catch { utf8Candidate = null; }
          authenticated = { passphrase, plaintextBytes: result.plaintext.length, utf8Candidate };
          break;
        } catch (error) {
          ctx.throwIfAborted();
          if (!(error instanceof Error) || error.message !== "no identity matched any of the file's recipients") throw error;
        }
      }
      ctx.diagnostic(`Found ${report.candidates.length} graph-valid candidate(s); authenticated ${authenticated ? "one" : "none"} within ${attempts} bounded age attempt(s).`);
      return { report: structuredValue({ ...report, age: { authenticated: authenticated !== null,
        attempts, truncated: authenticated === null && attempts < report.candidates.length,
        ...authenticated }, flagVerified: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});