import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { sigrokDigitalCsvToVcd } from "./saleaeCsv";
import { inspectVcd } from "./vcd";

const source = (text: string) => new MemorySource(new TextEncoder().encode(text));

describe("offline sigrok digital CSV import", () => {
  it("keeps timestamps, X gaps and probe names in inspectable VCD", async () => {
    const input = source("Time,D0,CLK\n0,0,1\n0.000000001,1,1\n0.000000002,x,0\n");
    const { vcd, report } = await sigrokDigitalCsvToVcd(input);
    expect(report).toMatchObject({ rows: 3, transitions: 5, lastTick: 2,
      channels: [{ signal: "sigrok.D0" }, { signal: "sigrok.CLK" }] });
    expect(new TextDecoder().decode(vcd)).toContain("#2\nx!\n0\"");
    expect((await inspectVcd(new MemorySource(vcd))).signals.map((signal) => signal.name)).toEqual(["sigrok.D0", "sigrok.CLK"]);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "hardware.sigrok.digital-import", inputs: { data: bytesValue(input) }, params: {} });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected VCD bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(vcd);
  });

  it("rejects analog probes, invalid timing and non-digital states", async () => {
    await expect(sigrokDigitalCsvToVcd(source("Time,Analog 0\n0,0.5\n"))).rejects.toThrow(/named probes/);
    await expect(sigrokDigitalCsvToVcd(source("Time,D0\n0,1\n0.0000000001,0\n"))).rejects.toThrow(/timing/);
    await expect(sigrokDigitalCsvToVcd(source("Time,D0\n0,2\n"))).rejects.toThrow(/digital value/);
  });
});
