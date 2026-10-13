import { describe, expect, it } from "vitest";
import type { Finding } from "./core/analysis/finding";
import { executeOperation } from "./core/operation/execute";
import { bytesFrom } from "./core/value";
import { compress, makeBmp24, makePng, tamperDimensions } from "./formats/testing/fixtures";
import { createDefaultRegistry } from "./operations";

const registry = createDefaultRegistry();

async function findingsOf(operationId: string, bytes: Uint8Array<ArrayBuffer>, params = {}): Promise<Finding[]> {
  const result = await executeOperation(registry, { operationId, inputs: { data: bytesFrom(bytes) }, params });
  const report = Object.values(result.outputs)[0];
  if (report?.type !== "structured") throw new Error(result.run.error?.message ?? "no report");
  return (report.data as { findings: Finding[] }).findings;
}

// M4 exit criterion: every suggestion shows its evidence and source.
describe("every suggestion explains itself", () => {
  it("attaches a rule and evidence to each finding that proposes an action", async () => {
    const png = await makePng({ width: 4, height: 4, colorType: 2, bitDepth: 8, pixels: new Uint8Array(48), trailing: Uint8Array.of(0x50, 0x4b, 3, 4, 0, 0) });
    const tampered = tamperDimensions(png, 4, 2);
    const fixedCrcShrunk = Object.values(
      (await executeOperation(registry, { operationId: "png.set-ihdr", inputs: { data: bytesFrom(png) }, params: { height: 2 } })).outputs,
    )[0];
    const shrunkBytes = new Uint8Array(await (fixedCrcShrunk.type === "bytes" ? fixedCrcShrunk.source.read(0, fixedCrcShrunk.source.size) : new Uint8Array()));
    const all = [
      ...(await findingsOf("png.inspect", tampered)),
      ...(await findingsOf("png.inspect", shrunkBytes)),
      ...(await findingsOf("png.find-dimensions", tampered, { maxDimension: 16 })),
      ...(await findingsOf("bmp.inspect", makeBmp24(4, 2, new Uint8Array(48), 2))),
      ...(await findingsOf("file.detect", png)),
      ...(await findingsOf("file.detect", new TextEncoder().encode("SGVsbG8gd29ybGQ="))),
      ...(await findingsOf("decode.auto", await compress(new TextEncoder().encode("flag{evidence}"), "gzip"))),
    ];
    const withSuggestions = all.filter((finding) => finding.suggestion);
    expect(withSuggestions.length).toBeGreaterThanOrEqual(7);
    for (const finding of withSuggestions) {
      expect(finding.ruleId, finding.id).toMatch(/^[a-z]+\.[a-z-]+$/);
      expect(finding.evidence?.length, finding.id).toBeGreaterThan(0);
    }
  });
});
