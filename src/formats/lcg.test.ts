import { describe, expect, it } from "vitest";
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { recoverLcg, recoverUnknownModulusLcg } from "./lcg";
import { recoverLcgXorTranscript } from "./lcgXorTranscript";
import { reconstructLcgRsa } from "./lcgRsa";
import { inspectRsaPublicKey, MAX_RSA_PUBLIC_PEM_BYTES } from "./rsaPublicKey";
import googleCtf2023Dump from "./testing/google-ctf-2023-lcg-dump.txt?raw";

describe("known-modulus LCG recovery", () => {
  it("recovers standard 32-bit parameters from an independently generated sequence", () => {
    const observed = [42, 1083814273, 378494188, 2479403867, 955863294, 1613448261];
    expect(recoverLcg(observed.map(String).join("\n"), "4294967296", 2)).toEqual({
      modulus: "4294967296", multiplier: "1664525", increment: "1013904223", observed: 6,
      next: ["110225632", "1921058495"], verified: true,
    });
  });

  it("refuses non-invertible or inconsistent observations", () => {
    expect(() => recoverLcg("0\n2\n6", "256", 1)).toThrow(/multiple generators fit/);
    expect(() => recoverLcg("42\n1083814273\n378494188\n9", "4294967296", 1)).toThrow(/do not reproduce observed output 3/);
  });

  it("recovers 64-bit values without JavaScript number rounding", () => {
    const observed = ["123456789", "18192599831048943872", "16626069846921725519", "14460625333602356786", "295651901058895385", "5451256728882455220"];
    expect(recoverLcg(observed.join("\n"), "18446744073709551616", 1)).toMatchObject({
      multiplier: "6364136223846793005", increment: "1442695040888963407", next: ["18112491282767800051"], verified: true,
    });
  });

  it("requires lossless decimal input rather than rounded JSON numbers", () => {
    expect(recoverLcg('["42","1083814273","378494188"]', "4294967296", 1)).toMatchObject({ multiplier: "1664525", verified: false });
    expect(() => recoverLcg("[42,1083814273,378494188]", "4294967296", 1)).toThrow(/unsigned decimal integer/);
    expect(() => recoverLcg("42\n1083814273\n378494188", "0", 1)).toThrow(/modulus must be/);
  });

  it("exposes verified parameters and predictions through the operation registry", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.prng.lcg-recover", inputs: { observed: textValue("42\n1083814273\n378494188\n2479403867") },
      params: { modulus: "4294967296", predictCount: 2 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({
      multiplier: "1664525", increment: "1013904223", next: ["955863294", "1613448261"], verified: true,
    });
    expect(result.run.diagnostics).toEqual(["Verified an LCG across 4 outputs and predicted 2 next value(s)."]);
  });
});

describe("unknown modulus LCG recovery", () => {
  const modulus = (1n << 255n) - 19n;
  const multiplier = (1n << 200n) + 1234567890123456789n;
  const increment = (1n << 128n) + 987654321n;
  let value = (1n << 160n) + 12345n;
  const observations = Array.from({ length: 10 }, () => {
    value = (multiplier * value + increment) % modulus;
    return value;
  });

  it("recovers the exact candidate and predicts held-out outputs from eight observations", () => {
    const report = recoverUnknownModulusLcg(observations.slice(0, 8).map(String).join("\n"), 2);
    expect(report).toMatchObject({ modulus: modulus.toString(), multiplier: multiplier.toString(), increment: increment.toString(),
      observed: 8, determinantsUsed: 5, next: observations.slice(8).map(String), verified: true, modulusCandidate: true });
  });

  it("reproduces the published Google CTF 2023 512-bit LCG intermediates from the original dump", async () => {
    const expectedModulus = "83112712730169462651691200922402278820138931316818820786"
      + "55426814178920681968884651437107918874328518499850252591"
      + "810409558783335118823692585959490215446923";
    const expectedMultiplier = "99470802153294399618017402366955844921383026244330401927"
      + "15338178840908786409091547637641754209244428298011420568"
      + "4938728578475547514901286372129860608477";
    const expectedIncrement = "39105397941934099798868700498694568156850408683128785373"
      + "93070815966881265118275755165613835833103526090552456472"
      + "867019296386475520134783987251699999776365";
    const expectedNext = "34001199730010417455407542484071251854490296230719127538"
      + "73001449542356327585002633704234264852161096609585456610"
      + "992840702166213287637317298700504577713818";
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.prng.lcg-unknown", inputs: { observed: textValue(googleCtf2023Dump) }, params: { predictCount: 1 },
    });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: {
      modulus: expectedModulus, multiplier: expectedMultiplier, increment: expectedIncrement,
      next: [expectedNext], observed: 6, determinantsUsed: 3, verified: true, modulusCandidate: true,
    } });
    expect(() => recoverUnknownModulusLcg(Array(6).fill((1n << 512n).toString()).join("\n"), 1)).toThrow(/under 2\^512/);
  });

  it("rejects insufficient, linear and lossy observations", () => {
    expect(() => recoverUnknownModulusLcg(observations.slice(0, 5).map(String).join("\n"), 1)).toThrow(/6 to 64/);
    expect(() => recoverUnknownModulusLcg("1\n2\n3\n4\n5\n6", 1)).toThrow(/modulus candidate/);
    expect(() => recoverUnknownModulusLcg(JSON.stringify(observations.slice(0, 8).map(Number)), 1)).toThrow(/unsigned decimal integer/);
  });

  it("exposes bounded candidate recovery through a separate operation", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.prng.lcg-unknown", inputs: { observed: textValue(observations.slice(0, 8).map(String).join("\n")) },
      params: { predictCount: 2 },
    });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { modulus: modulus.toString(),
      next: observations.slice(8).map(String), modulusCandidate: true } });
    expect(result.run.diagnostics[0]).toMatch(/cannot prove.*unique/);
  });

  it("recovers exact states from known-plaintext LCG-XOR rows and skips RSA ciphertexts", async () => {
    const rows = observations.slice(0, 8).map((state, index) => {
      const plaintext = index === 0 ? "Hello" : "message";
      const time = index * 3;
      const padded = new TextEncoder().encode(plaintext);
      let plainState = 0n;
      for (let at = 0; at < 32; at++) plainState = (plainState << 8n) | BigInt(padded[at] ?? 0);
      return { conversation_time: time, mode: "LCG-XOR", plaintext, ciphertext: (state ^ plainState ^ BigInt(time)).toString(16).padStart(64, "0") };
    });
    const text = JSON.stringify([...rows, { conversation_time: 99, mode: "RSA", plaintext: "[ENCRYPTED]", ciphertext: "00" }]);
    const report = recoverLcgXorTranscript(text);
    expect(report).toMatchObject({ observations: observations.slice(0, 8).map(String), skippedRsa: 1, blockBytes: 32 });
    expect(report.observations[0]).toBe("1824160642967967581736247101273935863615247628611999855750595745374");
    expect(recoverUnknownModulusLcg(report.decimalText, 2).modulus).toBe(modulus.toString());
    expect(() => recoverLcgXorTranscript(JSON.stringify([{ ...rows[0], ciphertext: "ff" }, ...rows.slice(1)]))).toThrow(/invalid mode, time/);
    expect(() => recoverLcgXorTranscript(JSON.stringify([{ ...rows[0], plaintext: "X".repeat(33) }, ...rows.slice(1)]))).toThrow(/plaintext or observation budget/);
    const recovered = await executeOperation(createDefaultRegistry(), { operationId: "crypto.prng.lcg-xor-transcript",
      inputs: { transcript: textValue(text) }, params: {} });
    expect(recovered.run.error).toBeUndefined();
    expect(recovered.outputs.observed).toMatchObject({ type: "text", text: report.decimalText });
    const inferred = await executeOperation(createDefaultRegistry(), { operationId: "crypto.prng.lcg-unknown",
      inputs: { observed: recovered.outputs.observed }, params: { predictCount: 2 } });
    expect(inferred.outputs.report).toMatchObject({ type: "structured", data: { modulus: modulus.toString(), modulusCandidate: true } });
  });
});

describe("LCG-derived RSA reconstruction", () => {
  const sample = JSON.stringify({ modulus: "65521", multiplier: "17", increment: "43", firstObserved: "1352", ciphertexts: ["9773e462"] });

  it("matches SymPy's two prime states and decrypts the native little-endian ciphertext", async () => {
    expect(await reconstructLcgRsa(sample, 16, 2, 100)).toMatchObject({ seed: "77", primes: ["51407", "46381"], primeConfidence: "probable",
      iterations: 66, rsaModulus: "2384308067", publicExponent: "65537", decrypted: [{ hex: "4f4b", utf8: "OK" }] });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "crypto.prng.lcg-rsa-reconstruct",
      inputs: { parameters: textValue(sample) }, params: { primeBits: 16, primeCount: 2, maxIterations: 100 } });
    expect(result.run.status).toBe("success");
    expect(result.outputs.plaintext).toMatchObject({ type: "text", text: "OK" });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { primeConfidence: "probable", iterations: 66 } });
  });

  it("reconstructs the published Google CTF 2023 RSA key and flag from original attachments", async () => {
    const recovered = recoverUnknownModulusLcg(googleCtf2023Dump, 1);
    const pem = readFileSync(new URL("./testing/google-ctf-2023-lcg-public.pem", import.meta.url), "utf8");
    const key = createPublicKey(pem).export({ format: "jwk" });
    const publicModulus = BigInt(`0x${Buffer.from(key.n!, "base64url").toString("hex")}`).toString();
    expect(await inspectRsaPublicKey(pem)).toEqual({ format: "SPKI", modulus: publicModulus, modulusBits: 4090, publicExponent: "65537" });
    const inspected = await executeOperation(createDefaultRegistry(), { operationId: "crypto.rsa.public-key.inspect", inputs: { data: textValue(pem) }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { modulus: publicModulus, modulusBits: 4090, publicExponent: "65537" } });
    const encrypted = readFileSync(new URL("./testing/google-ctf-2023-lcg-flag.bin", import.meta.url));
    const result = await executeOperation(createDefaultRegistry(), { operationId: "crypto.prng.lcg-rsa-reconstruct",
      inputs: { parameters: textValue(JSON.stringify({ modulus: recovered.modulus, multiplier: recovered.multiplier,
        increment: recovered.increment, firstObserved: googleCtf2023Dump.trim().split("\n")[0], ciphertexts: [encrypted.toString("hex")] })) },
      params: { primeBits: 512, primeCount: 8, maxIterations: 20_000 },
    });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: {
      iterations: 13_047, primeConfidence: "probable", publicExponent: "65537", rsaModulus: publicModulus,
    } });
    expect(result.outputs.plaintext).toMatchObject({ type: "text", text: "CTF{C0nGr@tz_RiV35t_5h4MiR_nD_Ad13MaN_W0ulD_b_h@pPy}" });
  });

  it("enforces search limits and exact decimal or ciphertext input", async () => {
    await expect(reconstructLcgRsa(sample, 16, 2, 10)).rejects.toThrow(/found .* probable primes within 10/);
    await expect(reconstructLcgRsa(sample.replace('"65521"', "65521"), 16, 2, 100)).rejects.toThrow(/exact unsigned decimal/);
    await expect(reconstructLcgRsa(sample.replace("9773e462", "zz"), 16, 2, 100)).rejects.toThrow(/little-endian hex/);
  });
});

describe("RSA public SPKI inspection", () => {
  const pem = readFileSync(new URL("./testing/google-ctf-2023-lcg-public.pem", import.meta.url), "utf8");

  it("accepts CRLF PEM and rejects private labels, malformed base64, and oversized input", async () => {
    expect(await inspectRsaPublicKey(pem.replace(/\n/g, "\r\n"))).toMatchObject({ modulusBits: 4090, publicExponent: "65537" });
    await expect(inspectRsaPublicKey(pem.replace(/PUBLIC KEY/g, "PRIVATE KEY"))).rejects.toThrow(/PUBLIC KEY/);
    await expect(inspectRsaPublicKey(pem.replace("MIICITAN", "!IICITAN"))).rejects.toThrow(/PUBLIC KEY|base64/);
    await expect(inspectRsaPublicKey("A".repeat(MAX_RSA_PUBLIC_PEM_BYTES + 1))).rejects.toThrow(/12,000/);
  });
});