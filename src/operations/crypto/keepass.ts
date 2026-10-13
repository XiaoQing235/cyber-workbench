import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { inspectKeePass } from "../../formats/keepass";
import { bytesInput } from "../util";

export const keepassInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "credential.keepass.inspect",
    version: "1.0.0",
    title: "Inspect KeePass database",
    category: "Crypto",
    description: "Inspect KDBX3 AES-KDF or KDBX4 Argon2d/Argon2id AES-256 headers. Keyfiles, older versions, and other ciphers are not supported.",
    keywords: ["keepass", "kdbx", "database", "password", "argon2", "aes-kdf"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const { hash: _hash, ...report } = await inspectKeePass(bytesInput(inputs), ctx.signal);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const keepassHashExport = defineOperation<Record<string, never>>({
  spec: {
    id: "credential.keepass.hash-export",
    version: "1.0.0",
    title: "Export KeePass password hash",
    category: "Crypto",
    description: "Export password-only KDBX3 AES-KDF or KDBX4 Argon2 AES-256 material in $keepass$ form for Hashcat and John the Ripper.",
    keywords: ["keepass2john", "kdbx", "hashcat", "john", "argon2", "aes-kdf", "password", "hash export"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "hash", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectKeePass(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Exported ${report.format} ${report.kdf} password material for Hashcat mode ${report.format === "KDBX3" ? 13400 : 34300} and John the Ripper.`);
      return { hash: textValue(report.hash) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});