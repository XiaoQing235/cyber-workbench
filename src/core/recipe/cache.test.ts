import { describe, expect, it } from "vitest";
import { createDefaultRegistry } from "../../operations";
import { ArtifactStore } from "../artifact/store";
import { MemorySource } from "../bytes/sources";
import { applyDefaults, executeOperation } from "../operation/execute";
import { bytesValue } from "../value";
import { canonicalJson, findReusableRun } from "./cache";

const registry = createDefaultRegistry();

describe("result reuse", () => {
  it("finds an identical earlier run regardless of parameter order, and nothing else", async () => {
    const store = new ArtifactStore();
    const input = store.add({ name: "in", value: bytesValue(new MemorySource(Uint8Array.of(1, 2, 3))) });
    const spec = registry.get("bytes.xor").spec;
    const result = await executeOperation(registry, { operationId: "bytes.xor", inputs: { data: input.value }, params: { key: "ff" } });
    store.recordRun(result.run);
    const output = store.add({ name: "out", value: result.outputs.data, producedBy: result.run.id, parents: [input.id] });

    const reordered = { keyFormat: "hex", key: "ff" };
    expect(canonicalJson(reordered)).toBe(canonicalJson(applyDefaults(spec, { key: "ff" })));
    expect(findReusableRun(store, input, spec, reordered)).toEqual({ run: result.run, outputs: [output] });
    expect(findReusableRun(store, input, spec, applyDefaults(spec, { key: "fe" }))).toBeNull();
    expect(findReusableRun(store, output, spec, reordered)).toBeNull();
    expect(findReusableRun(store, input, { ...spec, deterministic: false }, reordered)).toBeNull();
  });
});
