import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractJavaEntry, inspectJavaArchive } from "../../formats/javaArchive";
import { bytesInput, MiB } from "../util";

export const jarInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.java.jar.inspect", version: "1.0.0", title: "Inspect Java JAR", category: "Reverse",
    description: "Inspect bounded JAR central-directory entries, selected manifest fields, first class-file major version and signature artefact names. Signatures are not cryptographically verified.",
    keywords: ["java", "jar", "class", "manifest", "zip", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 128 * MiB },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const report = await inspectJavaArchive(bytesInput(inputs), ctx.signal);
      ctx.throwIfAborted();
      ctx.diagnostic(`Listed ${report.entries.length} JAR file(s), including ${report.classes} class(es). Signature artifacts are not verified.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const jarExtract = defineOperation<{ path: string }>({
  spec: {
    id: "reverse.java.jar.extract", version: "1.0.0", title: "Extract JAR entry", category: "Reverse",
    description: "Extract a named JAR file using bounded inflate and ZIP CRC validation. No class is loaded or executed.",
    keywords: ["java", "jar", "class", "extract", "zip", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { path: { type: "string", title: "JAR entry path", minLength: 1, maxLength: 1_024, default: "" } },
      required: ["path"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 128 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const data = await extractJavaEntry(bytesInput(inputs), params.path, ctx.signal);
      ctx.throwIfAborted();
      ctx.diagnostic(`Extracted ${params.path} (${data.size} bytes) with ZIP CRC verified.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});