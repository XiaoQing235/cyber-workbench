import { describe, expect, it } from "vitest";
import { bytesFrom, textValue } from "../value";
import { OperationError } from "./errors";
import { executeOperation } from "./execute";
import { OperationRegistry } from "./registry";
import { defineOperation, type OperationSpec } from "./types";

function spec(overrides: Partial<OperationSpec> = {}): OperationSpec {
  return {
    id: "test.echo",
    version: "1.0.0",
    title: "Echo",
    category: "Test",
    description: "Returns its input",
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { times: { type: "integer", minimum: 1, maximum: 3, default: 1 } },
      required: ["times"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
    ...overrides,
  };
}

const echo = defineOperation<{ times: number }>({
  spec: spec(),
  async run(_ctx, inputs, params) {
    const value = inputs.text;
    if (value.type !== "text") throw new Error("unreachable");
    return { text: textValue(value.text.repeat(params.times)) };
  },
});

function registryWith(...definitions: Parameters<OperationRegistry["register"]>[0][]): OperationRegistry {
  const registry = new OperationRegistry();
  for (const definition of definitions) registry.register(definition);
  return registry;
}

describe("OperationRegistry", () => {
  it("resolves the latest version unless one is pinned", () => {
    const v2 = { ...echo, spec: { ...echo.spec, version: "1.10.0" } };
    const v1b = { ...echo, spec: { ...echo.spec, version: "1.2.0" } };
    const registry = registryWith(echo, v2, v1b);
    expect(registry.get("test.echo").spec.version).toBe("1.10.0");
    expect(registry.get("test.echo", "1.0.0").spec.version).toBe("1.0.0");
  });

  it("rejects duplicates and malformed specs", () => {
    const registry = registryWith(echo);
    expect(() => registry.register(echo)).toThrow(/already registered/);
    expect(() => registry.register({ ...echo, spec: spec({ id: "NoDots" }) })).toThrow(/Invalid operation id/);
    expect(() => registry.register({ ...echo, spec: spec({ id: "test.v", version: "1.0" }) })).toThrow(/version/);
  });

  it("reports unknown operations with a typed error", () => {
    expect(() => new OperationRegistry().get("nope.nope")).toThrow(OperationError);
  });

  it("searches ids, titles and keywords", () => {
    const registry = registryWith(echo, { ...echo, spec: spec({ id: "test.other", title: "Other", keywords: ["needle"] }) });
    expect(registry.search("needle").map((s) => s.id)).toEqual(["test.other"]);
    expect(registry.search("echo").map((s) => s.id)).toEqual(["test.echo"]);
  });
});

describe("executeOperation", () => {
  const registry = registryWith(echo);

  it("applies parameter defaults and records a successful run", async () => {
    const result = await executeOperation(registry, { operationId: "test.echo", inputs: { text: textValue("ab") } });
    expect(result.run.status).toBe("success");
    expect(result.run.parameters).toEqual({ times: 1 });
    expect(result.run.operationVersion).toBe("1.0.0");
    expect(result.outputs.text).toEqual(textValue("ab"));
  });

  it("fails on invalid parameters without running", async () => {
    const result = await executeOperation(registry, {
      operationId: "test.echo",
      inputs: { text: textValue("ab") },
      params: { times: 9 },
    });
    expect(result.run.status).toBe("failed");
    expect(result.run.error?.code).toBe("INVALID_PARAMS");
    expect(result.outputs).toEqual({});
  });

  it("rejects unknown parameters", async () => {
    const result = await executeOperation(registry, {
      operationId: "test.echo",
      inputs: { text: textValue("ab") },
      params: { times: 1, extra: true },
    });
    expect(result.run.error?.code).toBe("INVALID_PARAMS");
  });

  it("checks input presence and type", async () => {
    const missing = await executeOperation(registry, { operationId: "test.echo", inputs: {} });
    expect(missing.run.error?.code).toBe("INPUT_MISSING");
    const wrongType = await executeOperation(registry, {
      operationId: "test.echo",
      inputs: { text: bytesFrom(new Uint8Array(1)) },
    });
    expect(wrongType.run.error?.code).toBe("INPUT_TYPE");
  });

  it("reports cancellation as its own status", async () => {
    const slow = defineOperation({
      spec: spec({ id: "test.slow", parametersSchema: { type: "object", properties: {}, additionalProperties: false } }),
      run: (ctx) =>
        new Promise((_resolve, reject) => ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason))),
    });
    const controller = new AbortController();
    const pending = executeOperation(
      registryWith(slow),
      { operationId: "test.slow", inputs: { text: textValue("") } },
      { signal: controller.signal },
    );
    controller.abort();
    const result = await pending;
    expect(result.run.status).toBe("cancelled");
    expect(result.run.error?.code).toBe("CANCELLED");
  });

  it("turns broken output contracts and crashes into failures", async () => {
    const wrongOutput = defineOperation({
      spec: spec({ id: "test.wrong", parametersSchema: { type: "object", properties: {}, additionalProperties: false } }),
      run: async () => ({ text: bytesFrom(new Uint8Array(0)) }),
    });
    const crash = defineOperation({
      spec: spec({ id: "test.crash", parametersSchema: { type: "object", properties: {}, additionalProperties: false } }),
      run: async () => {
        throw new Error("boom");
      },
    });
    const registry = registryWith(wrongOutput, crash);
    const inputs = { text: textValue("") };
    expect((await executeOperation(registry, { operationId: "test.wrong", inputs })).run.error?.code).toBe(
      "OUTPUT_CONTRACT",
    );
    const crashed = await executeOperation(registry, { operationId: "test.crash", inputs });
    expect(crashed.run.error).toEqual({ code: "INTERNAL", message: "boom" });
  });
});
