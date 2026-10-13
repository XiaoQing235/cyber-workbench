import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { inspectOfficeEncryption, MAX_OFFICE_BYTES } from "../../formats/officeEncryption";
import { bytesInput } from "../util";

export const officeEncryptionInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "document.office.encryption-inspect",
    version: "1.1.0",
    title: "Inspect Office encryption",
    category: "Forensics",
    description: "Inspect Office 2007 Standard AES-128/SHA1 or 2013 Agile AES-256/SHA512 password encryption (16 MiB limit). Other schemes are not supported.",
    keywords: ["office", "xlsx", "docx", "pptx", "agile", "standard", "encryption", "password"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
    limits: { maxInputBytes: MAX_OFFICE_BYTES },
  },
  async run(ctx, inputs) {
    try {
      const { hash: _hash, ...report } = await inspectOfficeEncryption(bytesInput(inputs), ctx.signal);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const officeHashExport = defineOperation<Record<string, never>>({
  spec: {
    id: "document.office.hash-export",
    version: "1.1.0",
    title: "Export Office password hash",
    category: "Forensics",
    description: "Export Office 2007 Standard or 2013 Agile password material in $office$ form for Hashcat modes 9400/9600 and John the Ripper (16 MiB limit).",
    keywords: ["office2john", "xlsx", "docx", "pptx", "hashcat", "john", "password", "hash export"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "hash", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
    limits: { maxInputBytes: MAX_OFFICE_BYTES },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectOfficeEncryption(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Exported ${report.format} password material for Hashcat mode ${report.format === "Office Standard (2007)" ? 9400 : 9600} and John the Ripper.`);
      return { hash: textValue(report.hash) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});