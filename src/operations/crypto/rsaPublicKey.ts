import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectRsaPublicKey, MAX_RSA_PUBLIC_PEM_BYTES } from "../../formats/rsaPublicKey";
import { textInput } from "../util";

export const rsaPublicKeyInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "crypto.rsa.public-key.inspect", version: "1.0.0", title: "Inspect RSA public key", category: "Crypto",
    description: "Import an unencrypted SPKI PUBLIC KEY PEM with browser WebCrypto and report exact decimal modulus, bit length and public exponent. Does not import private keys or perform decryption.",
    keywords: ["rsa", "pem", "spki", "public key", "modulus", "exponent"],
    inputs: [{ name: "data", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_RSA_PUBLIC_PEM_BYTES },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectRsaPublicKey(textInput(inputs, "data"), ctx.signal);
      ctx.diagnostic(`RSA SPKI public key: ${report.modulusBits} bits, exponent ${report.publicExponent}.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});