import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation, type StringParam } from "../../core/operation/types";
import { bytesFrom, structuredValue, textValue } from "../../core/value";
import { bytesInput, MiB, textInput } from "../util";

// The interpreter and YAML parser are loaded on first use, in the worker, keeping them out of the main bundle.
const loadLab = () => import("../../formats/ksy/lab");

const COMMON = { runtime: "ts", deterministic: true, sideEffects: "none", streaming: false } as const;
const FORMAT: StringParam = {
  type: "string",
  title: "Format",
  description: "auto picks a built-in schema from the file signature; custom uses the .ksy below.",
  enum: ["auto", "custom", "png", "bmp", "gif", "wav", "zip"],
  default: "auto",
};
const KSY: StringParam = {
  type: "string",
  title: ".ksy schema (custom format)",
  description: "Kaitai Struct YAML: meta, seq, types, enums, instances; expressions, repeat, if, switch-on, process (xor, zlib, rol, ror), valid and -checksum.",
  default: "",
  maxLength: 1_000_000,
  multiline: true,
};

async function withLabErrors<T>(work: (lab: Awaited<ReturnType<typeof loadLab>>) => Promise<T>): Promise<T> {
  const lab = await loadLab();
  try {
    return await work(lab);
  } catch (error) {
    if (error instanceof lab.StructLabError) throw new OperationError("INVALID_PARAMS", error.message);
    throw error;
  }
}

export const structParse = defineOperation<{ format: string; ksy: string }>({
  spec: {
    ...COMMON,
    id: "struct.parse",
    version: "1.0.0",
    title: "Parse binary structure (.ksy)",
    category: "Binary",
    description:
      "Parse bytes with a Kaitai Struct (.ksy) schema or a built-in one into a field tree linked to the hex view. On a mismatch it keeps the fields read so far and reports the offset.",
    keywords: ["kaitai", "ksy", "struct", "structure", "template", "fields", "parse", "010", "header", "checksum"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: { format: FORMAT, ksy: KSY }, required: ["format", "ksy"], additionalProperties: false },
    cost: "medium",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const bytes = await readAll(bytesInput(inputs));
    const { report, notes } = await withLabErrors((lab) => lab.analyse(bytes, params.format, params.ksy, ctx.signal));
    notes.forEach((note) => ctx.diagnostic(note));
    return { report: structuredValue(report) };
  },
});

export const structSetField = defineOperation<{ format: string; ksy: string; path: string; value: string; recompute: boolean }>({
  spec: {
    ...COMMON,
    id: "struct.set-field",
    version: "1.0.0",
    title: "Set structure field",
    category: "Binary",
    description:
      "Write a new value into one field of a parsed structure (in place, same size), then recompute the checksums the schema declares. With no path it only recomputes checksums.",
    keywords: ["kaitai", "ksy", "patch", "edit", "field", "repair", "fix", "checksum", "crc", "header"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        format: FORMAT,
        ksy: KSY,
        path: { type: "string", title: "Field path (e.g. chunks[0].body.width)", default: "", maxLength: 1000 },
        value: { type: "string", title: "New value (number, enum label, hex bytes or text)", default: "", maxLength: 100_000 },
        recompute: { type: "boolean", title: "Recompute checksums", default: true },
      },
      required: ["format", "ksy", "path", "value", "recompute"],
      additionalProperties: false,
    },
    cost: "medium",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const bytes = await readAll(bytesInput(inputs));
    const result = await withLabErrors((lab) =>
      lab.setField(bytes, params.format, params.ksy, params.path, params.value, params.recompute, ctx.signal),
    );
    result.notes.forEach((note) => ctx.diagnostic(note));
    return { data: bytesFrom(result.bytes) };
  },
});

export const structCodegen = defineOperation<{ language: "python" | "javascript" }>({
  spec: {
    ...COMMON,
    id: "struct.codegen",
    version: "1.0.0",
    title: "Generate parser code from .ksy",
    category: "Binary",
    description:
      "Compile a .ksy schema into a standalone parser: a Python 3 script (prints the tree when run on a file) or a dependency-free ES module, for solve scripts.",
    keywords: ["kaitai", "ksy", "export", "python", "javascript", "code", "generate", "compile", "solve script"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "code", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { language: { type: "string", title: "Language", enum: ["python", "javascript"], default: "python" } },
      required: ["language"],
      additionalProperties: false,
    },
    cost: "low",
  },
  async run(ctx, inputs, params) {
    const [{ exportParser }, { KsySchemaError }] = await Promise.all([import("../../formats/ksy/codegen"), import("../../formats/ksy/schema")]);
    try {
      const { code, fileName } = exportParser(textInput(inputs), params.language);
      ctx.diagnostic(`Save as ${fileName}.`);
      return { code: textValue(code) };
    } catch (error) {
      if (error instanceof KsySchemaError) throw new OperationError("INVALID_INPUT", `Schema error at ${error.message}`);
      throw error;
    }
  },
});
