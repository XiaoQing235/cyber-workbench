import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { inspectPdfEncryption } from "../../formats/pdfEncryption";
import { bytesInput } from "../util";

export const pdfEncryptionInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "document.pdf.encryption-inspect",
    version: "1.0.0",
    title: "Inspect PDF encryption",
    category: "Forensics",
    description: "Inspect direct hex-string PDF Standard security parameters through one classic xref table and one direct indirect encryption dictionary; incremental and hybrid xrefs are unsupported.",
    keywords: ["pdf", "encryption", "password", "standard security", "forensics"],
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
      const report = await inspectPdfEncryption(bytesInput(inputs), ctx.signal);
      const { hash: _hash, ...inspection } = report;
      return { report: structuredValue(inspection) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const pdfHashExport = defineOperation<Record<string, never>>({
  spec: {
    id: "document.pdf.hash-export",
    version: "1.0.0",
    title: "Export PDF password hash",
    category: "Forensics",
    description: "Export direct hex-string PDF Standard security material from one classic xref table and direct indirect encryption dictionary; incremental and hybrid xrefs are unsupported.",
    keywords: ["pdf", "pdf2john", "hashcat", "john", "password", "hash export"],
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
      const report = await inspectPdfEncryption(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Exported a PDF Standard security revision ${report.revision} hash for Hashcat and John the Ripper.`);
      return { hash: textValue(report.hash) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});