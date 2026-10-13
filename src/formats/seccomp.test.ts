import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectSeccomp } from "./seccomp";

// Classic seccomp filter: reject wrong arch, allow write(1), otherwise EPERM.
function filter(...instructions: [number, number, number, number][]): MemorySource {
  const bytes = new Uint8Array(instructions.length * 8);
  const view = new DataView(bytes.buffer);
  instructions.forEach(([code, jt, jf, k], index) => {
    view.setUint16(index * 8, code, true);
    view.setUint8(index * 8 + 2, jt);
    view.setUint8(index * 8 + 3, jf);
    view.setUint32(index * 8 + 4, k, true);
  });
  return new MemorySource(bytes);
}

const sample = () => filter(
  [0x20, 0, 0, 4],            // arch
  [0x15, 1, 0, 0xc000003e], // x86-64 -> 3, otherwise 2
  [0x06, 0, 0, 0x80000000], // KILL_PROCESS
  [0x20, 0, 0, 0],            // syscall
  [0x15, 0, 3, 1],            // write -> 5, otherwise 8
  [0x20, 0, 0, 16],           // arg0 low
  [0x15, 0, 1, 1],            // fd == 1 -> 7, else 8
  [0x06, 0, 0, 0x7fff0000], // ALLOW
  [0x06, 0, 0, 0x00050001], // ERRNO(EPERM)
);

describe("offline seccomp classic-BPF inspection", () => {
  it("follows both branches and simulates arch, syscall, and argument decisions", async () => {
    const source = sample();
    const allowed = await inspectSeccomp(source, 0xc000003e, 1, "1,0,0,0,0,0");
    expect(allowed.sample).toMatchObject({ action: "ALLOW", value: "0x7fff0000", trace: [0, 1, 3, 4, 5, 6, 7] });
    expect(allowed.reachableReturns).toEqual([
      { index: 2, action: "KILL_PROCESS", value: "0x80000000" },
      { index: 7, action: "ALLOW", value: "0x7fff0000" },
      { index: 8, action: "ERRNO", value: "0x00050001" },
    ]);
    expect((await inspectSeccomp(source, 0xc000003e, 1, "2,0,0,0,0,0")).sample.action).toBe("ERRNO");
    expect((await inspectSeccomp(source, 0xc000003e, 0, "1,0,0,0,0,0")).sample.action).toBe("ERRNO");
    expect((await inspectSeccomp(source, 0, 1, "1,0,0,0,0,0")).sample.action).toBe("KILL_PROCESS");
  });

  it("reads high 32 bits of 64-bit arguments and uses unsigned 32-bit comparisons", async () => {
    const source = filter([0x20, 0, 0, 20], [0x35, 0, 1, 0x80000000],
      [0x06, 0, 0, 0x7fff0000], [0x06, 0, 0, 0x00050001]);
    expect((await inspectSeccomp(source, 0xc000003e, 0, "0x8000000000000000,0,0,0,0,0")).sample.action).toBe("ALLOW");
    expect((await inspectSeccomp(source, 0xc000003e, 0, "0x7fffffffffffffff,0,0,0,0,0")).sample.action).toBe("ERRNO");
  });

  it("rejects invalid instructions and paths rather than inventing a decision", async () => {
    await expect(inspectSeccomp(filter([0x20, 0, 0, 8], [0x06, 0, 0, 0x7fff0000]), 0, 0, "0,0,0,0,0,0")).rejects.toThrow(/offset/);
    await expect(inspectSeccomp(filter([0x15, 0, 2, 0], [0x06, 0, 0, 0]), 0, 0, "0,0,0,0,0,0")).rejects.toThrow(/leaves/);
    await expect(inspectSeccomp(filter([0x20, 0, 0, 0]), 0, 0, "0,0,0,0,0,0")).rejects.toThrow(/falls off/);
    await expect(inspectSeccomp(filter([0x04, 0, 0, 1]), 0, 0, "0,0,0,0,0,0")).rejects.toThrow(/unsupported/);
    await expect(inspectSeccomp(filter([0x05, 1, 0, 0], [0x06, 0, 0, 0]), 0, 0, "0,0,0,0,0,0")).rejects.toThrow(/unused jump fields/);
    await expect(inspectSeccomp(filter([0x06, 0, 0, 0x12340000]), 0, 0, "0,0,0,0,0,0")).rejects.toThrow(/unknown/);
    await expect(inspectSeccomp(sample(), 0, 0, "0x10000000000000000,0,0,0,0,0")).rejects.toThrow(/64 bits/);
    await expect(inspectSeccomp(sample(), 0, 0, "0,0,0,0,0")).rejects.toThrow(/six/);
  });

  it("is available via the operation registry and returns an unverified report", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "reverse.seccomp.inspect", inputs: { data: bytesValue(sample()) },
      params: { arch: 0xc000003e, syscall: 1, args: "1,0,0,0,0,0" },
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { sample: { action: "ALLOW" } } });
  });
});
