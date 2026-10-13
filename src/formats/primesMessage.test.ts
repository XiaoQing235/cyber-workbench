import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { recoverPrimeMessage } from "./primesMessage";
import challenge from "./testing/google-ctf-2023-primes-chal.sage?raw";

describe("Google CTF Primes indexed-prime recovery", () => {
  it("recovers the released flag from the licensed challenge script and verifies its published encoding", async () => {
    const match = challenge.match(/^m = b"([^"]+)"$/m);
    const attachment = readFileSync(new URL("./testing/google-ctf-2023-primes-chal.sage", import.meta.url));
    expect(createHash("sha1").update(`blob ${attachment.length}\0`).update(attachment).digest("hex"))
      .toBe("563203438d030693e7cdd502a2633a33eb13f0b9");
    const q = challenge.match(/^# q = (0x[0-9a-f]+)$/im)?.[1];
    const x = challenge.match(/^# x = (0x[0-9a-f]+)$/im)?.[1];
    if (!match || !q || !x) throw new Error("Original Primes attachment is incomplete");
    const original = match[1];
    const input = JSON.stringify({ message: original, q, x });
    const report = recoverPrimeMessage(input, 2048);
    expect(report).toEqual({ candidate: "I have a sweet flag for you: CTF{w0W_c0Nt1nUed_fr4Ct10ns_suR3_Ar3_fUn_Huh}",
      correctedBits: 135, convergentIndex: 380, testedConvergents: 381, verifiedEncoding: true });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "crypto.primes.message-recover",
      inputs: { data: textValue(input) }, params: { maxTerms: 2048 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
    expect(recoverPrimeMessage(JSON.stringify({ message: report.candidate, q, x }), 1)).toMatchObject({
      candidate: report.candidate, correctedBits: 0, convergentIndex: null, testedConvergents: 0, verifiedEncoding: true,
    });
    expect(recoverPrimeMessage(input, 380)).toMatchObject({ candidate: null, testedConvergents: 380, verifiedEncoding: false });
    expect(() => recoverPrimeMessage(JSON.stringify({ message: original, q, x: "0x0" }), 2048)).toThrow(/modular bounds/);
    const modified = Array.from(original);
    modified[31] = String.fromCharCode(modified[31].charCodeAt(0) ^ 1);
    expect(recoverPrimeMessage(JSON.stringify({ message: modified.join(""), q, x }), 2048)).toMatchObject({ candidate: null, verifiedEncoding: false });
  });
});
