import type { PyodideAPI } from "pyodide";

export interface PythonOutcome {
  stdout: string[];
  /** Bytes the script left in `result`; null when it did not set one. */
  result: Uint8Array | null;
  /** Python traceback when the script raised. */
  error?: string;
}

const MAX_OUTPUT_LINES = 10_000;

const PROLOGUE = "data = open('/input', 'rb').read()\nresult = None\n";
const EPILOGUE = `
_r = result
if isinstance(_r, str):
    _r = _r.encode()
elif isinstance(_r, (bytearray, memoryview)):
    _r = bytes(_r)
elif _r is not None and not isinstance(_r, bytes):
    _r = repr(_r).encode()
if _r is not None:
    with open('/output', 'wb') as _f:
        _f.write(_r)
`;

/**
 * Pyodide with no JavaScript reachable from Python: the `js` module is an object without a prototype,
 * and `js` and `pyodide_js` are unregistered.
 */
export async function createEngine(load: (options: Parameters<typeof import("pyodide").loadPyodide>[0]) => Promise<PyodideAPI>, indexURL: string) {
  let lines: string[] = [];
  const collect = (line: string) => {
    if (lines.length < MAX_OUTPUT_LINES) lines.push(line);
  };
  const py = await load({
    indexURL,
    jsglobals: Object.create(null) as object,
    stdout: collect,
    stderr: collect,
    env: { HOME: "/home/user" },
  });
  py.unregisterJsModule("js");
  py.unregisterJsModule("pyodide_js");
  py.runPython("import sys\nfor _m in ('js', 'pyodide_js'): sys.modules.pop(_m, None)\ndel _m");

  return {
    version: py.version,
    run(script: string, input: Uint8Array): PythonOutcome {
      lines = [];
      py.FS.writeFile("/input", input);
      const namespace = py.toPy({});
      try {
        py.runPython(PROLOGUE, { globals: namespace });
        py.runPython(script, { globals: namespace, filename: "<script>" });
        py.runPython(EPILOGUE, { globals: namespace });
        const result = py.FS.analyzePath("/output").exists ? py.FS.readFile("/output") : null;
        return { stdout: lines, result };
      } catch (error) {
        return { stdout: lines, result: null, error: error instanceof Error ? error.message : String(error) };
      } finally {
        namespace.destroy();
        for (const path of ["/input", "/output"]) if (py.FS.analyzePath(path).exists) py.FS.unlink(path);
      }
    },
  };
}

export type PythonEngine = Awaited<ReturnType<typeof createEngine>>;
