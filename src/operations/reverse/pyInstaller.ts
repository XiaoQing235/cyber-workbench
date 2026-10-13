import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractPyInstallerEntry, extractPyInstallerPyc, inspectPyInstaller } from "../../formats/pyInstaller";
import { bytesInput, MiB } from "../util";

export const pyInstallerInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.pyinstaller.inspect", version: "1.0.0", title: "Inspect PyInstaller archive", category: "Reverse",
    description: "Locate a bounded PyInstaller CArchive cookie, list entry types, packed sizes and Python version in a .pkg or bundled executable without executing bytecode.",
    keywords: ["pyinstaller", "carchive", "pkg", "pyz", "python", "executable", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectPyInstaller(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Found ${report.entries.length} PyInstaller entry(s) for Python ${report.pythonVersion}; no Python bytecode was executed.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const pyInstallerExtract = defineOperation<{ name: string }>({
  spec: {
    id: "reverse.pyinstaller.extract", version: "1.0.0", title: "Extract PyInstaller entry", category: "Reverse",
    description: "Extract a named PyInstaller CArchive member with a 64 MiB decompression limit. Python scripts are returned as raw marshal bytes, not executed or decompiled.",
    keywords: ["pyinstaller", "carchive", "pkg", "pyz", "extract", "marshal", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      name: { type: "string", title: "Archive entry name", minLength: 1, maxLength: 1_024, default: "" },
    }, required: ["name"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { data, entry } = await extractPyInstallerEntry(bytesInput(inputs), params.name, ctx.signal);
      ctx.diagnostic(`Extracted ${entry.name} (${data.size} bytes, type ${entry.typecode}); contents were not executed.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const pyInstallerPycRebuild = defineOperation<{ name: string }>({
  spec: {
    id: "reverse.pyinstaller.pyc-rebuild", version: "1.0.0", title: "Rebuild PyInstaller script PYC", category: "Reverse",
    description: "Prefix a marshaled PyInstaller Python 3.11-3.13 script or module with a synthetic .pyc header. Its timestamp and source size are unknown and set to zero; no bytecode is executed.",
    keywords: ["pyinstaller", "pyc", "python", "marshal", "rebuild", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      name: { type: "string", title: "Marshaled script entry name", minLength: 1, maxLength: 1_024, default: "" },
    }, required: ["name"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const result = await extractPyInstallerPyc(bytesInput(inputs), params.name, ctx.signal);
      ctx.diagnostic(`Reconstructed Python ${result.pythonVersion} .pyc with ${result.marshalBytes} marshal byte(s); header timestamp and source size are synthetic, and code was not executed.`);
      return { data: bytesValue(result.data), report: structuredValue({ name: params.name, pythonVersion: result.pythonVersion,
        marshalBytes: result.marshalBytes, syntheticHeader: true, executed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
