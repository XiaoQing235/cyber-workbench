import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { writeZip } from "../core/archive/zip";
import { BlobSource, MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { sigrokSessionToVcd } from "./sigrokSession";
import { inspectVcd } from "./vcd";

const meta = (rate = "1 MHz") => `[global]\nsigrok version=0.5.2\n[device 1]\ncapturefile=logic-1\nsamplerate=${rate}\nunitsize=1\ntotal probes=2\nprobe1=tx\nprobe2=clk\n`;
async function session(metadata = meta(), logic = Uint8Array.of(0, 1, 3, 2)): Promise<BlobSource> {
  return new BlobSource(await writeZip([
    { name: "version", data: new Blob(["2"]) },
    { name: "metadata", data: new Blob([metadata]) },
    { name: "logic-1", data: new Blob([logic]) },
  ]));
}

describe("native sigrok digital session import", () => {
  it("converts stored logic samples into a VCD artifact with exact transitions", async () => {
    const source = await session();
    const { vcd, report } = await sigrokSessionToVcd(source);
    expect(report).toEqual({ sampleRateHz: 1_000_000, samples: 4, probes: 2, transitions: 5, lastTick: 3000, timescale: "1 ns" });
    expect((await inspectVcd(new MemorySource(vcd))).signals.map((signal) => signal.name)).toEqual(["sigrok.tx", "sigrok.clk"]);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "hardware.sigrok.session-import",
      inputs: { data: bytesValue(source) }, params: {} });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected VCD bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(vcd);
  });

  it("converts a separately produced ZIP-deflated digital session without exceeding sample bounds", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/sigrok-deflated-logic.sr", import.meta.url)));
    const { vcd, report } = await sigrokSessionToVcd(new MemorySource(bytes));
    expect(report).toMatchObject({ sampleRateHz: 1_000_000, samples: 32, probes: 2, lastTick: 31_000 });
    expect((await inspectVcd(new MemorySource(vcd))).signals.map((signal) => signal.name)).toEqual(["sigrok.tx", "sigrok.clk"]);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "hardware.sigrok.session-import",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
  });

  it("rejects unsupported sample periods, undeclared bits and malformed probe layouts", async () => {
    await expect(sigrokSessionToVcd(await session(meta("3 MHz")))).rejects.toThrow(/1 ns resolution/);
    await expect(sigrokSessionToVcd(await session(meta(), Uint8Array.of(0, 4)))).rejects.toThrow(/outside declared probes/);
    await expect(sigrokSessionToVcd(await session(meta().replace("unitsize=1", "unitsize=2")))).rejects.toThrow(/1-byte/);
    await expect(sigrokSessionToVcd(await session(meta().replace("capturefile=logic-1", "capturefile=other")))).rejects.toThrow(/capturefile/);
  });
});
