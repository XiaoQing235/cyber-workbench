import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue, textValue } from "../../core/value";
import { recoverLcg, recoverUnknownModulusLcg } from "../../formats/lcg";
import { recoverLcgXorTranscript } from "../../formats/lcgXorTranscript";
import { reconstructLcgRsa } from "../../formats/lcgRsa";
import { recoverMt19937 } from "../../formats/mt19937";
import { textInput } from "../util";

export const lcgRecover = defineOperation<{ modulus: string; predictCount: number }>({
  spec: {
    id: "crypto.prng.lcg-recover",
    version: "1.0.0",
    title: "Recover LCG generator",
    category: "Crypto",
    description: "Infer a known-modulus LCG from three decimal outputs and verify against further observations before bounded prediction. Ambiguous inverses are rejected.",
    keywords: ["prng", "lcg", "linear congruential", "recover", "predict", "modulus"],
    inputs: [{ name: "observed", type: "text" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        modulus: { type: "string", title: "Modulus (decimal)", maxLength: 20, default: "4294967296" },
        predictCount: { type: "integer", title: "Next outputs", minimum: 1, maximum: 64, default: 3 },
      },
      required: ["modulus", "predictCount"],
      additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 32_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs, "observed");
    if (text.length > 32_000) throw new OperationError("INPUT_TOO_LARGE", "LCG observations are limited to 32,000 characters");
    try {
      const report = recoverLcg(text, params.modulus, params.predictCount);
      ctx.diagnostic(report.verified
        ? `Verified an LCG across ${report.observed} outputs and predicted ${report.next.length} next value(s).`
        : "LCG parameters fit three outputs; no independent continuation was supplied.");
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const lcgUnknownRecover = defineOperation<{ predictCount: number }>({
  spec: {
    id: "crypto.prng.lcg-unknown", version: "1.0.0", title: "Infer unknown LCG modulus", category: "Crypto",
    description: "Derive a candidate modulus up to 512 bits from 6-64 exact decimal outputs, infer generator parameters and verify all observations before bounded prediction. Other compatible generators may exist.",
    keywords: ["prng", "lcg", "unknown modulus", "bigint", "recover", "predict"],
    inputs: [{ name: "observed", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      predictCount: { type: "integer", title: "Next outputs", minimum: 1, maximum: 16, default: 3 },
    }, required: ["predictCount"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 12_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs, "observed");
    if (text.length > 12_000) throw new OperationError("INPUT_TOO_LARGE", "Unknown-modulus LCG observations are limited to 12,000 characters");
    try {
      const report = recoverUnknownModulusLcg(text, params.predictCount);
      ctx.diagnostic(`A modulus candidate reproduces ${report.observed} outputs; finite observations cannot prove this generator is unique.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const lcgXorTranscript = defineOperation<Record<string, never>>({
  spec: {
    id: "crypto.prng.lcg-xor-transcript", version: "1.0.0", title: "Recover LCG-XOR transcript", category: "Crypto",
    description: "Recover exact 256-bit LCG outputs from up to 64 known-plaintext 32-byte XOR transcript rows. Time is XORed as a big-endian integer; RSA-mode messages are skipped and not decrypted.",
    keywords: ["prng", "lcg", "xor", "known plaintext", "transcript", "chat"],
    inputs: [{ name: "transcript", type: "text" }], outputs: [{ name: "observed", type: "text" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8_000 },
  },
  async run(ctx, inputs) {
    ctx.throwIfAborted();
    try {
      const report = recoverLcgXorTranscript(textInput(inputs, "transcript"));
      ctx.diagnostic(`Recovered ${report.observations.length} exact LCG-XOR output(s); skipped ${report.skippedRsa} RSA row(s) without decrypting them.`);
      return { observed: textValue(report.decimalText), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const lcgRsaReconstruct = defineOperation<{ primeBits: number; primeCount: number; maxIterations: number }>({
  spec: {
    id: "crypto.prng.lcg-rsa-reconstruct", version: "1.0.0", title: "Decrypt LCG-derived RSA", category: "Crypto",
    description: "Rewind an invertible LCG, select bounded probable-prime states up to 512 bits and decrypt 1-4 little-endian RSA ciphertexts offline. Requires known generator parameters and first output; probable primes are not mathematical proofs.",
    keywords: ["lcg", "rsa", "prng", "probable primes", "modular arithmetic", "offline"],
    inputs: [{ name: "parameters", type: "text" }], outputs: [{ name: "plaintext", type: "text" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      primeBits: { type: "integer", title: "Prime candidate bits", minimum: 8, maximum: 512, default: 256 },
      primeCount: { type: "integer", title: "Probable primes", minimum: 2, maximum: 8, default: 8 },
      maxIterations: { type: "integer", title: "Maximum LCG iterations", minimum: 1, maximum: 20_000, default: 10_000 },
    }, required: ["primeBits", "primeCount", "maxIterations"], additionalProperties: false },
    runtime: "ts", deterministic: false, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: 16_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    try {
      const report = await reconstructLcgRsa(textInput(inputs, "parameters"), params.primeBits, params.primeCount, params.maxIterations, ctx.signal);
      ctx.diagnostic(`Selected ${report.primes.length} probable RSA prime(s) in ${report.iterations} bounded LCG iteration(s); decrypted ${report.decrypted.length} ciphertext(s) offline.`);
      return { plaintext: textValue(report.decrypted.map((item) => item.utf8 ?? `[non-UTF-8: ${item.hex}]`).join("\n")), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const mt19937Recover = defineOperation<{ predictCount: number }>({
  spec: {
    id: "crypto.prng.mt19937-recover",
    version: "1.0.0",
    title: "Recover MT19937 state",
    category: "Crypto",
    description: "Recover MT19937 state from 624 to 656 consecutive unsigned 32-bit outputs. Extra observations verify the predicted continuation; 624 alone cannot.",
    keywords: ["prng", "mt19937", "mersenne twister", "state", "untemper", "predict"],
    inputs: [{ name: "observed", type: "text" }],
    outputs: [{ name: "report", type: "structured" }, { name: "state", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { predictCount: { type: "integer", title: "Next outputs", minimum: 1, maximum: 32, default: 3 } },
      required: ["predictCount"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 16_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs, "observed");
    if (text.length > 16_000) throw new OperationError("INPUT_TOO_LARGE", "MT19937 observations are limited to 16,000 characters");
    try {
      const { state, ...report } = recoverMt19937(text, params.predictCount);
      ctx.throwIfAborted();
      ctx.diagnostic(report.verified
        ? `Verified MT19937 continuation against ${report.observed - 624} additional output(s).`
        : "State inferred from exactly 624 outputs; the next value is not independently verified.");
      return { report: structuredValue(report), state: bytesFrom(state) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});