import { describe, expect, it } from "vitest";
import { MersenneTwister19937 } from "random-js";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { recoverMt19937 } from "./mt19937";

describe("MT19937 state recovery", () => {
  it("predicts canonical outputs from 624 observed values without claiming verification", () => {
    const engine = MersenneTwister19937.seed(5489);
    const observed = Array.from({ length: 624 }, () => engine.next() >>> 0);
    expect(observed.slice(0, 4)).toEqual([3499211612, 581869302, 3890346734, 3586334585]);
    const expected = Array.from({ length: 8 }, () => engine.next() >>> 0);
    const result = recoverMt19937(observed.join("\n"), 8);
    expect(result).toMatchObject({ observed: 624, verified: false, next: expected });
    expect(result.state.length).toBe(624 * 4);
  });

  it("verifies observed continuation and predicts subsequent values", () => {
    const engine = MersenneTwister19937.seed(1234);
    const observed = Array.from({ length: 630 }, () => engine.next() >>> 0);
    const expected = Array.from({ length: 6 }, () => engine.next() >>> 0);
    expect(recoverMt19937(JSON.stringify(observed), 6)).toMatchObject({ observed: 630, verified: true, next: expected });
    observed[626] ^= 1;
    expect(() => recoverMt19937(JSON.stringify(observed), 1)).toThrow(/does not reproduce observed output 626/);
  });

  it("predicts from shifted consecutive windows without requiring cycle alignment", () => {
    for (const offset of [1, 100, 397, 623]) {
      const engine = MersenneTwister19937.seed(7);
      for (let index = 0; index < offset; index++) engine.next();
      const observed = Array.from({ length: 625 }, () => engine.next() >>> 0);
      const expected = Array.from({ length: 16 }, () => engine.next() >>> 0);
      expect(recoverMt19937(JSON.stringify(observed), 16)).toMatchObject({ verified: true, next: expected });
    }
  });

  it("requires consecutive 32-bit values and a bounded prediction", () => {
    expect(() => recoverMt19937("1\n2\n3", 1)).toThrow(/requires 624/);
    expect(() => recoverMt19937(Array(624).fill("4294967296").join("\n"), 1)).toThrow(/unsigned 32-bit/);
    expect(() => recoverMt19937(Array(624).fill("0").join("\n"), 33)).toThrow(/between 1 and 32/);
  });

  it("exports a recovered state artifact and verified next outputs through the registry", async () => {
    const engine = MersenneTwister19937.seed(2026);
    const observed = Array.from({ length: 625 }, () => engine.next() >>> 0);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.prng.mt19937-recover", inputs: { observed: textValue(observed.join("\n")) }, params: { predictCount: 2 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({ verified: true, observed: 625, next: [engine.next() >>> 0, engine.next() >>> 0] });
    expect((await readAll((result.outputs.state as { source: Parameters<typeof readAll>[0] }).source)).length).toBe(624 * 4);
    expect(result.run.diagnostics).toEqual(["Verified MT19937 continuation against 1 additional output(s)."]);
  });
});