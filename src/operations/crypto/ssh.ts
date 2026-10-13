import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { exportOpenSshJohn, inspectSshPrivateKey } from "../../formats/sshPrivateKey";
import { bytesInput, MiB } from "../util";

const MAX_INPUT_BYTES = 2 * MiB;

export const sshPrivateKeyInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "credential.ssh-private-key.inspect",
    version: "1.0.0",
    title: "Inspect SSH private key",
    category: "Crypto",
    description: "Inspect OpenSSH v1 private-key encryption metadata without decrypting or retaining key bytes. Legacy PEM and PKCS#8 are not yet supported.",
    keywords: ["ssh", "private key", "openssh", "pem", "bcrypt", "cipher", "kdf"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: MAX_INPUT_BYTES },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      return { report: structuredValue(inspectSshPrivateKey(await readAll(bytesInput(inputs), MAX_INPUT_BYTES))) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const sshPrivateKeyJohnExport = defineOperation<Record<string, never>>({
  spec: {
    id: "credential.ssh-private-key.john-export",
    version: "1.0.0",
    title: "Export OpenSSH hash for John",
    category: "Crypto",
    description: "Export a bcrypt-protected OpenSSH v1 key using AES-256-CBC or AES-256-CTR in John the Ripper's $sshng$ format.",
    keywords: ["ssh2john", "sshng", "john", "openssh", "password", "bcrypt"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "hash", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: MAX_INPUT_BYTES },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const hash = exportOpenSshJohn(await readAll(bytesInput(inputs), MAX_INPUT_BYTES));
      ctx.diagnostic("Exported password-recovery material for John the Ripper's SSH format.");
      return { hash: textValue(hash) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});