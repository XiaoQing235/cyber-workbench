import { loadPyodide } from "pyodide";
import { beforeAll, describe, expect, it } from "vitest";
import type { Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom, type Value } from "../core/value";
import { createEngine } from "../runtimes/python/engine";
import { setPythonRunner } from "../runtimes/python";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();

beforeAll(async () => {
  const engine = await createEngine(loadPyodide, new URL("../../node_modules/pyodide/", import.meta.url).pathname);
  setPythonRunner(async (script, input) => engine.run(script, input));
}, 60_000);

async function python(script: string, input: Bytes = new TextEncoder().encode("flag{py}")) {
  const result = await executeOperation(registry, { operationId: "python.run", inputs: { data: bytesFrom(input) }, params: { script } });
  const value = Object.values(result.outputs)[0] as Extract<Value, { type: "bytes" }> | undefined;
  return {
    text: value ? new TextDecoder().decode(await readAll(value.source)) : "",
    error: result.run.error,
    diagnostics: result.run.diagnostics,
  };
}

describe("Python pack", () => {
  it("runs a script on the input with the standard library", async () => {
    const { text, diagnostics } = await python("import base64, hashlib\nprint('sha1', hashlib.sha1(data).hexdigest()[:8])\nresult = base64.b64encode(data[::-1])");
    expect(text).toBe("fXlwe2dhbGY=");
    expect(diagnostics).toEqual(["› sha1 cca7879b"]);
  });

  it("outputs what was printed when no result is set, and converts other result types", async () => {
    expect((await python("for i in range(3): print(i)")).text).toBe("0\n1\n2\n");
    expect((await python("result = 'naïve'")).text).toBe("naïve");
    expect((await python("result = [1, 2]")).text).toBe("[1, 2]");
    expect((await python("result = bytearray(b'ab')")).text).toBe("ab");
  });

  it("reports the traceback, keeping the output printed before it", async () => {
    const { error, diagnostics } = await python("print('before')\nx = 1 / 0");
    expect(error?.code).toBe("INVALID_PARAMS");
    expect(error?.message).toMatch(/File "<script>", line 2[\s\S]*ZeroDivisionError: division by zero$/);
    expect(diagnostics).toEqual(["› before"]);
  });

  it("starts every run with fresh variables", async () => {
    await python("leftover = 1");
    expect((await python("result = str('leftover' in globals())")).text).toBe("False");
  });

  it("gives Python no JavaScript modules", async () => {
    for (const module of ["js", "pyodide_js"]) {
      const { error } = await python(`import ${module}`);
      expect(error?.message).toMatch(new RegExp(`ModuleNotFoundError: No module named '${module}'`));
    }
    // pyodide.code needs the js module; pyodide.ffi stays (the worker removes eval and the network before scripts run).
    expect((await python("from pyodide.code import run_js\nrun_js('1')")).error?.message).toMatch(/ModuleNotFoundError: No module named 'js'/);
  });

  it("lists risky pickle opcodes without unpickling or revealing string contents", async () => {
    const fixture = Uint8Array.from(atob("gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwDc3RylJOUjAZiZW5pZ26UhZRSlC4="), (character) => character.charCodeAt(0));
    const result = await executeOperation(registry, { operationId: "forensics.model.pickle.opcodes", inputs: { data: bytesFrom(fixture) }, params: {} });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { protocol: 4, unpickled: false, truncated: false,
      findings: [{ name: "STACK_GLOBAL", offset: 28 }, { name: "REDUCE", offset: 41 }] } });
    expect(JSON.stringify(result.outputs)).not.toContain("benign");
    const invalid = await executeOperation(registry, { operationId: "forensics.model.pickle.opcodes", inputs: { data: bytesFrom(Uint8Array.of(0x80, 0x04)) }, params: {} });
    expect(invalid.run.error?.code).toBe("INVALID_INPUT");
  });
});
