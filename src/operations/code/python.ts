import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom } from "../../core/value";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB } from "../util";

const TEMPLATE = `# \`data\` holds the input bytes. Set \`result\` (bytes or str) for the output,
# or just print(): without a result, the output is what the script printed.
# Python 3.14 with the standard library; no network, no files outside this run.
import hashlib

print(len(data), "bytes, sha256", hashlib.sha256(data).hexdigest())
result = data[::-1]
`;

const SHOWN_LINES = 30;

export const pythonRun = defineOperation<{ script: string; timeLimit: number }>({
  spec: {
    id: "python.run",
    version: "1.0.0",
    title: "Run Python script",
    category: "Code",
    description:
      "Run your own Python 3 script (standard library) on the input. It runs in an isolated worker with no network, storage or page access, and is never run automatically.",
    keywords: ["python", "pyodide", "script", "solve", "code", "custom", "program"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "result", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        script: { type: "string", title: "Python script", default: TEMPLATE, multiline: true, maxLength: 1_000_000 },
        timeLimit: { type: "integer", title: "Time limit (seconds)", minimum: 1, maximum: 600, default: 60 },
      },
      required: ["script", "timeLimit"],
      additionalProperties: false,
    },
    runtime: "pyodide",
    deterministic: false,
    sideEffects: "codeExecution",
    streaming: false,
    cost: "high",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const input = await readAll(bytesInput(inputs));
    const { runPython } = await importPack("Python", () => import("../../runtimes/python"));
    const outcome = await runPython(params.script, input, params.timeLimit * 1000, ctx.signal);
    if (outcome.note) ctx.diagnostic(outcome.note);
    const shown = outcome.result || outcome.error ? outcome.stdout : [];
    shown.slice(0, SHOWN_LINES).forEach((line) => ctx.diagnostic(`› ${line}`));
    if (shown.length > SHOWN_LINES) ctx.diagnostic(`… ${shown.length - SHOWN_LINES} more line(s) of output`);
    if (outcome.error) {
      const traceback = outcome.error.trim().split("\n");
      throw new OperationError("INVALID_PARAMS", traceback.slice(-12).join("\n"));
    }
    if (outcome.result) return { result: bytesFrom(new Uint8Array(outcome.result)) };
    ctx.diagnostic("No result was set: the output is what the script printed.");
    return { result: bytesFrom(new TextEncoder().encode(outcome.stdout.join("\n") + (outcome.stdout.length ? "\n" : ""))) };
  },
});
