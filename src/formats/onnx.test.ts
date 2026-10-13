import fixtureUrl from "./testing/onnx-1.19-tiny.onnx?inline";
import externalUrl from "./testing/onnx-1.19-external.onnx?inline";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractOnnxTensor, extractOnnxTensorBits, inspectOnnx } from "./onnx";

const fixture = Uint8Array.from(atob(fixtureUrl.slice(fixtureUrl.indexOf(",") + 1)), (character) => character.charCodeAt(0));
const externalFixture = Uint8Array.from(atob(externalUrl.slice(externalUrl.indexOf(",") + 1)), (character) => character.charCodeAt(0));
const source = (bytes: Uint8Array = fixture) => new MemorySource(bytes.slice());

describe("ONNX protobuf metadata", () => {
  it("inventories a model checked by official ONNX 1.19 without executing nodes or revealing tensor values", async () => {
    const report = await inspectOnnx(source());
    expect(report).toMatchObject({ irVersion: "12", producer: "cyberhelper-fixture", externalTensorDataRead: false,
      modelExecuted: false, modelValidated: false, opsets: [{ domain: "", version: "18" }], graph: { name: "tiny-add",
        nodes: [{ name: "sum", opType: "Add", inputs: ["x", "weight"], outputs: ["y"] }],
        inputs: [{ name: "x", dataType: 1, shape: ["1", "2"] }], outputs: [{ name: "y", dataType: 1, shape: ["1", "2"] }],
        initializers: [{ name: "weight", dataType: 1, dimensions: ["2"], elements: "2", rawDataBytes: 8, externalData: false }] } });
      expect(await readAll(await extractOnnxTensor(source(), "weight"))).toEqual(Uint8Array.of(0, 0, 0, 63, 0, 0, 192, 63));
  });

  it("rejects malformed wire metadata and a forged graph message", async () => {
    const broken = fixture.slice();
    broken[0] = 0xff;
    await expect(inspectOnnx(source(broken))).rejects.toThrow();
    const invalid = fixture.slice(0, 8);
    await expect(inspectOnnx(source(invalid))).rejects.toThrow(/index out of range/);
  });

  it("reports an ONNX external tensor without reading its absent sidecar", async () => {
    expect(await inspectOnnx(source(externalFixture))).toMatchObject({ externalTensorDataRead: false, modelExecuted: false,
      graph: { initializers: [{ name: "weight", dimensions: ["2"], rawDataBytes: 0, externalData: true }] } });
    await expect(extractOnnxTensor(source(externalFixture), "weight")).rejects.toThrow(/external data is not fetched/);
  });

  it("exposes bounded graph inventory through the Forensics registry without claiming model validation", async () => {
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.model.onnx.inspect",
      inputs: { data: bytesValue(source()) }, params: {} });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { modelExecuted: false, modelValidated: false,
      graph: { nodes: [{ opType: "Add" }], initializers: [{ name: "weight", rawDataBytes: 8 }] } } });
    const extracted = await executeOperation(createDefaultRegistry(), { operationId: "forensics.model.onnx.extract",
      inputs: { data: bytesValue(source()) }, params: { name: "weight" } });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected raw ONNX tensor bytes");
    expect(await readAll(extracted.outputs.data.source)).toEqual(Uint8Array.of(0, 0, 0, 63, 0, 0, 192, 63));
  });

  it("samples embedded float representation bits without fetching an external tensor", async () => {
    expect(await extractOnnxTensorBits(source(), "weight", 22, 1)).toEqual({ data: Uint8Array.of(0x40), samples: 2, dataType: 1 });
    await expect(extractOnnxTensorBits(source(externalFixture), "weight", 22, 1)).rejects.toThrow(/embedded raw_data/);
    await expect(extractOnnxTensorBits(source(), "weight", 32, 1)).rejects.toThrow(/bit index/);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.model.onnx.bits",
      inputs: { data: bytesValue(source()) }, params: { name: "weight", bit: 22, maxOutputBytes: 1 } });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { samples: 2, verifiedPayload: false } });
  });
});
