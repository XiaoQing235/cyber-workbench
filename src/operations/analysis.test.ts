import { describe, expect, it } from "vitest";
import type { Finding, SuggestedStep } from "../core/analysis/finding";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { OperationResult } from "../core/operation/run";
import type { Params } from "../core/operation/types";
import { bytesFrom, type Value } from "../core/value";
import { compress, concat, makePng } from "../formats/testing/fixtures";
import type { DecodeCandidate } from "./analysis/autoDecode";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const ascii = (text: string) => new TextEncoder().encode(text);
const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

function run(operationId: string, input: Value, params: Params = {}): Promise<OperationResult> {
  const port = registry.get(operationId).spec.inputs[0].name;
  return executeOperation(registry, { operationId, inputs: { [port]: input }, params });
}

function single(result: OperationResult): Value {
  expect(result.run.error).toBeUndefined();
  return Object.values(result.outputs)[0];
}

function textOf(result: OperationResult): string {
  const value = single(result);
  if (value.type !== "text") throw new Error(`expected text, got ${value.type}`);
  return value.text;
}

interface DecodeReport {
  explored: number;
  searchComplete: boolean;
  candidates: DecodeCandidate[];
  findings: Finding[];
}

async function autoDecode(bytes: Uint8Array<ArrayBuffer>, params: Params = {}): Promise<DecodeReport> {
  const value = single(await run("decode.auto", bytesFrom(bytes), params));
  if (value.type !== "structured") throw new Error(`expected a report, got ${value.type}`);
  return value.data as DecodeReport;
}

/** Runs a candidate's steps through the real operations, as the UI does. */
async function replay(steps: readonly SuggestedStep[], bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  let value: Value = bytesFrom(bytes);
  for (const step of steps) value = single(await run(step.operationId, value, step.params));
  if (value.type !== "bytes") throw new Error(`expected bytes, got ${value.type}`);
  return new TextDecoder().decode(await readAll(value.source));
}

describe("strings.extract", () => {
  it("lists printable runs with hex offsets", async () => {
    const data = concat(Uint8Array.of(0, 1), ascii("hello"), Uint8Array.of(0), ascii("ab"), Uint8Array.of(0), ascii("world!"), Uint8Array.of(0));
    expect(textOf(await run("strings.extract", bytesFrom(data)))).toBe("00000002  hello\n0000000b  world!");
    expect(textOf(await run("strings.extract", bytesFrom(data), { offsets: false, minLength: 2 }))).toBe("hello\nab\nworld!");
  });

  it("joins a string split across read chunks", async () => {
    const data = new Uint8Array(2 * 1024 * 1024);
    const at = 1024 * 1024 - 5;
    data.set(ascii("boundary-string"), at);
    expect(textOf(await run("strings.extract", bytesFrom(data)))).toBe(`${at.toString(16).padStart(8, "0")}  boundary-string`);
  });

  it("finds UTF-16LE strings at odd offsets alongside ASCII ones", async () => {
    const wide = Uint8Array.from([..."wide"].flatMap((c) => [c.charCodeAt(0), 0]));
    const data = concat(Uint8Array.of(0xff, 0xff, 0xff), wide, Uint8Array.of(0xff), ascii("plain"), Uint8Array.of(0xff));
    expect(textOf(await run("strings.extract", bytesFrom(data), { encoding: "both" }))).toBe(
      "00000003  [UTF-16LE] wide\n0000000c  plain",
    );
  });

  it("stops at the string limit and says so", async () => {
    const result = await run("strings.extract", bytesFrom(ascii("aaaa\0bbbb\0cccc\0dddd")), { maxStrings: 2, offsets: false });
    expect(textOf(result)).toBe("aaaa\nbbbb");
    expect(result.run.diagnostics[0]).toMatch(/Stopped after 2 strings/);
  });
});

describe("decode.auto", () => {
  const flag = ascii("CTF{layered_encodings}");

  it("points at a flag that is already in the input", async () => {
    const report = await autoDecode(concat(Uint8Array.of(0, 1, 2), ascii("flag{plain_sight}"), new Uint8Array(8)));
    expect(report.findings[0]).toMatchObject({ severity: "strong", span: { offset: 3, length: 17 } });
    expect(report.findings[0].message).toMatch(/unverified/);
    expect(report.findings[0].suggestion).toBeUndefined();
  });

  it("unwraps hex around Base64 and the steps replay to the flag", async () => {
    const data = ascii(Array.from(ascii(base64(flag)), (b) => b.toString(16).padStart(2, "0")).join(" "));
    const [best] = (await autoDecode(data)).candidates;
    expect(best).toMatchObject({ kind: "flag", layers: ["Hex", "Base64"], flags: [{ text: "CTF{layered_encodings}", offset: 0 }] });
    expect(await replay(best.steps, data)).toBe("CTF{layered_encodings}");
  });

  it("keeps the text prefix of LSB-style output, then decodes Base64 and zlib", async () => {
    const encoded = ascii(base64(await compress(flag)));
    const data = concat(encoded, new Uint8Array(64));
    const report = await autoDecode(data);
    const [best] = report.candidates;
    expect(best.layers).toEqual([`Text prefix (${encoded.length} bytes)`, "Base64", "zlib"]);
    expect(await replay(best.steps, data)).toBe("CTF{layered_encodings}");
    const suggestion = report.findings[0].suggestion;
    expect([suggestion?.operationId, ...(suggestion?.then ?? []).map((s) => s.operationId)]).toEqual([
      "bytes.slice",
      "text.decode",
      "base64.decode",
      "zlib.inflate",
    ]);
  });

  it("handles gzip around reversed Base64", async () => {
    const data = await compress(ascii([...base64(ascii("flag{gz_reverse}"))].reverse().join("")), "gzip");
    const [best] = (await autoDecode(data)).candidates;
    expect(best.layers).toEqual(["gzip", "Reverse", "Base64"]);
    expect(await replay(best.steps, data)).toBe("flag{gz_reverse}");
  });

  it("reports decoded file types and readable text as weaker candidates", async () => {
    const png = await makePng({ width: 1, height: 1, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(0) });
    expect((await autoDecode(ascii(base64(png)))).candidates[0]).toMatchObject({ kind: "file", fileType: "PNG image", layers: ["Base64"] });
    const text = (await autoDecode(ascii(base64(ascii("nothing to see here, move along"))))).candidates[0];
    expect(text).toMatchObject({ kind: "text", preview: "nothing to see here, move along" });
  });

  it("uses a custom flag pattern", async () => {
    const data = ascii(base64(ascii("key: FLAG-1234-5678")));
    const report = await autoDecode(data, { flagPattern: "FLAG-\\d{4}-\\d{4}" });
    expect(report.candidates[0].flags[0].text).toBe("FLAG-1234-5678");
  });

  it("rejects an invalid pattern and reports an exhausted budget or an empty result", async () => {
    expect((await run("decode.auto", bytesFrom(ascii("x")), { flagPattern: "(" })).run.error?.code).toBe("INVALID_PARAMS");
    const nested = ascii(base64(ascii(base64(ascii(base64(flag))))));
    const limited = await autoDecode(nested, { maxNodes: 2 });
    expect(limited.searchComplete).toBe(false);
    expect(limited.findings.at(-1)?.id).toBe("decode.budget");
    expect((await autoDecode(nested)).candidates[0].layers).toEqual(["Base64", "Base64", "Base64"]);
    expect((await autoDecode(Uint8Array.of(1, 2, 3, 250))).findings.map((f) => f.id)).toEqual(["decode.none"]);
  });

  it("explains every candidate with evidence and ranks by it", async () => {
    const data = concat(ascii(base64(await compress(flag))), new Uint8Array(64));
    const report = await autoDecode(data);
    const [best] = report.candidates;
    expect(best.evidence.map((item) => `${item.kind}:${item.tier}`)).toEqual([
      "structure:medium",
      "decode:medium",
      "structure:weak",
      "integrity:strong",
      "targetMatch:strong",
    ]);
    expect(best.score).toEqual({ targetMatch: true, strong: 2, medium: 2, weak: 1 });
    expect(report.findings[0]).toMatchObject({ ruleId: "decode.search", evidence: best.evidence });
    expect(report.findings[0].evidence?.at(-1)?.detail).toMatch(/not proof/);
  });

  it("enforces each budget and says which one stopped the search", async () => {
    const nested = ascii(base64(ascii(base64(ascii(base64(flag))))));
    const bytesLimited = await autoDecode(nested, { maxBytes: 1024 + 1 });
    expect(bytesLimited).toMatchObject({ searchComplete: true });
    const tight = await autoDecode(concat(nested, new Uint8Array(2000)), { maxBytes: 1024 });
    expect(tight.searchComplete).toBe(false);
    expect(tight.findings.at(-1)?.message).toMatch(/bytes examined/);
    const shallow = await autoDecode(nested, { maxDepth: 2 });
    expect(shallow.candidates.some((candidate) => candidate.kind === "flag")).toBe(false);
    const narrow = await autoDecode(ascii("deadbeefdeadbeef"), { keptPerBranch: 1, maxActive: 1 });
    expect(narrow).toMatchObject({ searchComplete: true });
  });

  it("resolves recipes pinned to version 1.0.0 to the compatible 1.1.0", () => {
    expect(registry.get("decode.auto", "1.0.0").spec.version).toBe("1.1.0");
  });
});
