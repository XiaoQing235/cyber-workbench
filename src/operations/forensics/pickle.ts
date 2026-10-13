import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB } from "../util";

const SCRIPT = `import json
import pickletools

operations = []
findings = []
protocol = None
truncated = False
risky = {"GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST", "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID"}
for opcode, argument, offset in pickletools.genops(data):
    if len(operations) >= 5000:
        truncated = True
        break
    name = opcode.name
    operations.append({"name": name, "offset": offset})
    if name == "PROTO":
        protocol = argument
    if name in risky:
        finding = {"name": name, "offset": offset}
        if name == "GLOBAL" and isinstance(argument, str):
            finding["reference"] = argument[:256]
        findings.append(finding)
result = json.dumps({"protocol": protocol, "operations": operations, "findings": findings, "truncated": truncated, "unpickled": False}, separators=(",", ":")).encode("utf-8")
`;

export const pickleOpcodesInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.model.pickle.opcodes", version: "1.0.0", title: "Inspect pickle opcodes", category: "Forensics",
    description: "List up to 5,000 pickle opcode names/offsets with risky global/reduction leads using Python's pickletools in an isolated worker. No pickle is loaded or executed; arbitrary string payloads are omitted.",
    keywords: ["model", "pickle", "pkl", "opcode", "global", "reduce", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "pyodide", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: MiB },
  },
  async run(ctx, inputs) {
    ctx.throwIfAborted();
    const input = await readAll(bytesInput(inputs), MiB);
    const { runPython } = await importPack("Python", () => import("../../runtimes/python"));
    const outcome = await runPython(SCRIPT, input, 15_000, ctx.signal);
    if (outcome.note) ctx.diagnostic(outcome.note);
    if (outcome.error) throw new OperationError("INVALID_INPUT", outcome.error.trim().split("\n").at(-1) ?? "Invalid pickle opcode stream");
    if (!outcome.result) throw new OperationError("INTERNAL", "Pickle opcode scanner returned no result");
    const report = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(outcome.result));
    ctx.diagnostic(`Listed ${report.operations.length} pickle opcode(s), ${report.findings.length} global/reduction lead(s). No pickle was loaded.`);
    return { report: structuredValue(report) };
  },
});