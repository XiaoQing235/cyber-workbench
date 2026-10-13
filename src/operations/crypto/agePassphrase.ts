import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { decryptAgePassphrase, MAX_AGE_CIPHERTEXT_BYTES } from "../../formats/agePassphrase";
import { bytesInput } from "../util";

export const agePassphraseDecrypt = defineOperation<{ passphrase: string }>({
  spec: {
    id: "crypto.age.passphrase-decrypt", version: "1.0.0", title: "Decrypt age passphrase file", category: "Crypto",
    description: "Decrypt a bounded binary age file with one scrypt stanza at work factor 19 or less. Authentication verifies the passphrase and bytes, not the origin of any embedded flag. No passphrase guessing.",
    keywords: ["age", "scrypt", "passphrase", "decrypt", "file", "npc"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "plaintext", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      passphrase: { type: "string", title: "Age passphrase", minLength: 1, maxLength: 128, default: "" },
    }, required: ["passphrase"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: MAX_AGE_CIPHERTEXT_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const result = await decryptAgePassphrase(bytesInput(inputs), params.passphrase, ctx.signal);
      let utf8Candidate: string | null = null;
      try { utf8Candidate = new TextDecoder("utf-8", { fatal: true }).decode(result.plaintext); }
      catch { utf8Candidate = null; }
      ctx.diagnostic(`Authenticated ${result.plaintext.length} age plaintext byte(s) with scrypt work factor ${result.workFactor}.`);
      return { plaintext: bytesFrom(result.plaintext), report: structuredValue({ plaintextBytes: result.plaintext.length,
        workFactor: result.workFactor, authenticated: true, utf8Candidate, flagVerified: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});