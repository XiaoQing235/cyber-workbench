import { describe, expect, it } from "vitest";
import { writeZip } from "../core/archive/zip";
import type { Finding } from "../core/analysis/finding";
import type { Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { Params } from "../core/operation/types";
import { bytesFrom, type Value } from "../core/value";
import { joinPath, type FieldNode, type StructReport } from "../formats/ksy/tree";
import { compress, concat, makeBmp24, makePng, tamperDimensions } from "../formats/testing/fixtures";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const ascii = (text: string) => Uint8Array.from(text, (c) => c.charCodeAt(0));

async function run(operationId: string, input: Value, params: Params = {}) {
  const result = await executeOperation(registry, { operationId, inputs: { data: input }, params });
  return { value: Object.values(result.outputs)[0], error: result.run.error, diagnostics: result.run.diagnostics };
}

async function parse(bytes: Bytes, params: Params = {}): Promise<StructReport> {
  const { value, error } = await run("struct.parse", bytesFrom(bytes), params);
  if (error) throw new Error(error.message);
  return (value as { data: StructReport }).data;
}

async function patch(bytes: Bytes, params: Params): Promise<Bytes> {
  const { value, error } = await run("struct.set-field", bytesFrom(bytes), params);
  if (error) throw new Error(error.message);
  return readAll((value as Extract<Value, { type: "bytes" }>).source);
}

const custom = (ksy: string, bytes: Bytes) => parse(bytes, { format: "custom", ksy });

function node(report: StructReport, path: string): FieldNode {
  const found = (current: FieldNode, prefix: string): FieldNode | undefined => {
    for (const child of current.children ?? []) {
      const childPath = joinPath(prefix, child.name);
      if (childPath === path) return child;
      if (path.startsWith(childPath)) {
        const deeper = found(child, childPath);
        if (deeper) return deeper;
      }
    }
    return undefined;
  };
  const result = found(report.root, "");
  if (!result) throw new Error(`No node at ${path}`);
  return result;
}

const value = (report: StructReport, path: string) => node(report, path).value;
const rules = (findings: Finding[]) => findings.map((finding) => finding.ruleId);

describe("Binary structure lab: built-in schemas", () => {
  it("parses a PNG, links fields to bytes, decompresses zTXt, and repairs a tampered IHDR with its CRC", async () => {
    const pixels = new Uint8Array(32 * 8 * 3).map((_, i) => i);
    const ztxt = concat(ascii("Comment"), Uint8Array.of(0, 0), await compress(ascii("flag{ztxt}")));
    const png = await makePng({ width: 32, height: 8, colorType: 2, bitDepth: 8, pixels, extraChunks: [["zTXt", ztxt]] });

    const report = await parse(png);
    expect(report.params).toEqual({ format: "png", ksy: "" });
    expect(report.findings).toEqual([]);
    expect(value(report, "chunks[0].type")).toBe("IHDR");
    expect(node(report, "chunks[0].body.width")).toMatchObject({ offset: 16, length: 4, value: 32, type: "u4be" });
    expect(node(report, "chunks[0].body.color_type")).toMatchObject({ value: 2, label: "truecolor" });
    expect(node(report, "chunks[0].crc").checksum).toMatchObject({ algorithm: "crc32", ok: true, range: { offset: 12, length: 17 } });
    // zTXt text is inflated: the decoded field lives in processed data, so it has no offset in the file.
    expect(node(report, "chunks[1].body.text.value")).toMatchObject({ value: "flag{ztxt}", offset: null });
    expect(report.root.children?.find((child) => child.name === "chunks")?.count).toBe(4);
    expect(report.parsedBytes).toBe(png.length);

    const tampered = tamperDimensions(png, 32, 9);
    const broken = await parse(tampered);
    expect(rules(broken.findings)).toEqual(["struct.checksum"]);
    expect(broken.findings[0].span).toEqual({ offset: 29, length: 4 });
    expect(broken.findings[0].suggestion).toMatchObject({ operationId: "struct.set-field", params: { format: "png", path: "" }, then: [{ operationId: "struct.parse" }] });

    // Setting the field back reproduces the original file, whose CRC already matches.
    const { diagnostics } = await run("struct.set-field", bytesFrom(tampered), { format: "png", path: "chunks[0].body.height", value: "8" });
    expect(diagnostics).toEqual([expect.stringMatching(/^Set chunks\[0\]\.body\.height at 0x14: 00 00 00 09 → 00 00 00 08/)]);
    expect(await patch(tampered, { format: "png", path: "chunks[0].body.height", value: "8" })).toEqual(png);

    // A new value gets a recomputed CRC.
    const taller = await run("struct.set-field", bytesFrom(png), { format: "png", path: "chunks[0].body.height", value: "16" });
    expect(taller.diagnostics[1]).toMatch(/^Recomputed chunks\[0\]\.crc: 0x[0-9a-f]+ → 0x[0-9a-f]+\.$/);
    expect((await parse(await patch(png, { format: "png", path: "chunks[0].body.height", value: "16" }))).findings).toEqual([]);

    // "Recompute all checksums" keeps the edit and makes the file consistent.
    const consistent = await patch(tampered, { format: "png" });
    expect((await parse(consistent)).findings).toEqual([]);
    expect(value(await parse(consistent), "chunks[0].body.height")).toBe(9);

    // Enum labels are accepted for enum fields.
    expect(value(await parse(await patch(png, { format: "png", path: "chunks[0].body.color_type", value: "truecolor_alpha" })), "chunks[0].body.color_type")).toBe(6);
  });

  it("reports trailing data after the structure", async () => {
    const png = await makePng({ width: 1, height: 1, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(0), trailing: ascii("PK\x03\x04hidden") });
    const report = await parse(png, { format: "auto" });
    expect(rules(report.findings)).toEqual(["struct.trailing"]);
    expect(report.findings[0]).toMatchObject({ span: { offset: png.length - 10, length: 10 }, suggestion: { operationId: "bytes.slice", params: { offset: png.length - 10 } } });
  });

  it("parses a BMP whose height hides rows, and restores the height", async () => {
    const bmp = makeBmp24(4, 2, new Uint8Array(4 * 4 * 3).fill(0x80), 2);
    const report = await parse(bmp);
    expect(report.title).toBe("BMP image");
    expect(value(report, "dib_header.height")).toBe(2);
    expect(value(report, "dib_header.row_size")).toBe(12);
    expect(value(report, "expected_pixel_bytes")).toBe(24);
    expect(node(report, "pixels")).toMatchObject({ offset: 54, length: 48, instance: true });
    expect(node(report, "color_table").count).toBe(0);
    const restored = await parse(await patch(bmp, { format: "bmp", path: "dib_header.height", value: "4" }));
    expect(value(restored, "expected_pixel_bytes")).toBe(48);
  });

  it("walks a ZIP and edits the encryption flag", async () => {
    const zip = new Uint8Array(await (await writeZip([
      { name: "flag.txt", data: new Blob(["flag{zip}"]) },
      { name: "b.txt", data: new Blob(["bb"]) },
    ])).arrayBuffer());
    const report = await parse(zip);
    expect(node(report, "sections").count).toBe(5);
    expect(value(report, "sections[0].body.name")).toBe("flag.txt");
    expect(value(report, "sections[0].body.data")).toBe("66 6c 61 67 7b 7a 69 70 7d");
    expect(node(report, "sections[2].section_type").label).toBe("central_dir_entry");
    expect(value(report, "sections[4].body.entries_total")).toBe(2);
    expect(report.findings).toEqual([]);
    const flagged = await parse(await patch(zip, { format: "zip", path: "sections[0].body.flags", value: "0x0801" }));
    expect(value(flagged, "sections[0].body.flags")).toBe(0x801);
  });

  it("parses GIF blocks, including comment text, and stops at an invalid block with its offset", async () => {
    const gif = concat(
      ascii("GIF89a"),
      Uint8Array.of(1, 0, 1, 0, 0x80, 0, 0),
      Uint8Array.of(0, 0, 0, 255, 255, 255),
      Uint8Array.of(0x21, 0xfe, 5), ascii("hello"), Uint8Array.of(0),
      Uint8Array.of(0x21, 0xf9, 4, 0, 10, 0, 0, 0),
      Uint8Array.of(0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 0x44, 0x01, 0),
      Uint8Array.of(0x3b),
    );
    const report = await parse(gif);
    expect(node(report, "global_color_table").count).toBe(2);
    expect(value(report, "blocks[0].body.body.blocks[0].text")).toBe("hello");
    expect(value(report, "blocks[1].body.body.delay_time")).toBe(10);
    expect(value(report, "blocks[2].body.width")).toBe(1);
    expect(node(report, "blocks[3].block_type").label).toBe("trailer");
    expect(report.findings).toEqual([]);

    const corrupt = new Uint8Array(gif);
    corrupt[28] = 0x99; // the graphic-control block's introducer
    const broken = await parse(corrupt, { format: "gif" });
    expect(broken.error).toMatchObject({ offset: 28, path: "blocks[1].block_type" });
    expect(broken.findings[0].message).toMatch(/^Parsing stopped at 0x1c in blocks\[1\]\.block_type: Validation failed/);
    expect(node(broken, "blocks[1].block_type").error).toMatch(/Validation failed/);
    expect(value(broken, "blocks[0].body.body.blocks[0].text")).toBe("hello");
  });

  it("parses WAV chunks with LIST/INFO text and odd-size padding", async () => {
    const u32 = (n: number) => Uint8Array.of(n & 255, (n >> 8) & 255, (n >> 16) & 255, n >>> 24);
    const u16 = (n: number) => Uint8Array.of(n & 255, n >> 8);
    const fmt = concat(u16(1), u16(1), u32(8000), u32(8000), u16(1), u16(8));
    const info = concat(ascii("INFO"), ascii("INAM"), u32(8), ascii("flag{w}\0"));
    const body = concat(ascii("WAVE"), ascii("fmt "), u32(16), fmt, ascii("LIST"), u32(info.length), info, ascii("data"), u32(3), Uint8Array.of(1, 2, 3, 0));
    const wav = concat(ascii("RIFF"), u32(body.length), body);
    const report = await parse(wav);
    expect(node(report, "chunks[0].body.format").label).toBe("pcm");
    expect(value(report, "chunks[1].body.items[0].value")).toBe("flag{w}");
    expect(node(report, "chunks[2].pad").length).toBe(1);
    expect(report.findings).toEqual([]);
  });

  it("explains when no built-in format matches", async () => {
    const { error } = await run("struct.parse", bytesFrom(ascii("hello")), { format: "auto" });
    expect(error).toMatchObject({ code: "INVALID_PARAMS", message: expect.stringMatching(/Not a built-in format/) });
  });
});

describe("Binary structure lab: .ksy interpreter", () => {
  it("evaluates expressions like Kaitai: precedence, floor division, 64-bit values and methods", async () => {
    const ksy = `
meta:
  id: calc
  endian: le
seq:
  - id: a
    type: u1
  - id: big
    type: u8
instances:
  precedence:
    value: a & 0x80 != 0
  floor_div:
    value: -7 / 2
  py_mod:
    value: -7 % 3
  ternary:
    value: 'a > 100 ? "big" : "small"'
  big_plus:
    value: big + 1
  shifted:
    value: 1 << 40
  strings:
    value: '"abc".reverse + "42".to_i.to_s'
  radix:
    value: '"ff".to_i(16)'
  float:
    value: a / 2.0
`;
    const report = await custom(ksy, Uint8Array.of(0x85, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
    expect(value(report, "big")).toBe("18446744073709551615");
    expect(value(report, "precedence")).toBe(true);
    expect(value(report, "floor_div")).toBe(-4);
    expect(value(report, "py_mod")).toBe(2);
    expect(value(report, "ternary")).toBe("big");
    expect(value(report, "big_plus")).toBe("18446744073709551616");
    expect(value(report, "shifted")).toBe(2 ** 40);
    expect(value(report, "strings")).toBe("cba42");
    expect(value(report, "radix")).toBe(255);
    expect(value(report, "float")).toBe(66.5);
  });

  it("reads bit fields in both bit orders and realigns for byte fields", async () => {
    const ksy = `
meta:
  id: bits
seq:
  - id: flag
    type: b1
  - id: kind
    type: b3
  - id: nibble
    type: b4
  - id: after
    type: u1
  - id: low
    type: b4le
  - id: high
    type: b4le
`;
    const report = await custom(ksy, Uint8Array.of(0b1_011_0110, 0x7f, 0xa5));
    expect([value(report, "flag"), value(report, "kind"), value(report, "nibble"), value(report, "after"), value(report, "low"), value(report, "high")]).toEqual([true, 3, 6, 0x7f, 5, 10]);
    expect(node(report, "nibble")).toMatchObject({ offset: 0, length: 1 });
  });

  it("supports process, substreams, repeat modes, _parent/_root/_index, terminators, pos instances and switch without a match", async () => {
    const ksy = `
meta:
  id: proc
  endian: be
  encoding: ASCII
seq:
  - id: key
    type: u1
  - id: len
    type: u1
  - id: secret
    size: len
    process: xor(key)
    type: message
  - id: rotated
    size: 2
    process: rol(1)
  - id: sizes
    type: u1
    repeat: expr
    repeat-expr: 2
  - id: parts
    size: sizes[_index]
    type: str
    repeat: expr
    repeat-expr: 2
  - id: names
    type: strz
    repeat: until
    repeat-until: _ == "end"
  - id: tag
    type: u1
  - id: tagged
    type:
      switch-on: tag
      cases:
        1: message
  - id: rest
    type: u1
    repeat: eos
instances:
  second_byte:
    pos: 1
    type: u1
  from_root_io:
    io: _root._io
    pos: 0
    size: 2
types:
  message:
    seq:
      - id: text
        type: str
        size-eos: true
    instances:
      parent_key:
        value: _parent.key
      root_len:
        value: _root.len
`;
    const secret = ascii("flag").map((b) => b ^ 0x2a);
    const bytes = concat(
      Uint8Array.of(0x2a, 4), secret,
      Uint8Array.of(0b1000_0001, 0b0100_0000),
      Uint8Array.of(2, 3), ascii("hiyou"),
      ascii("a\0b\0end\0"),
      Uint8Array.of(9),
      Uint8Array.of(7, 8),
    );
    const report = await custom(ksy, bytes);
    expect(report.findings).toEqual([]);
    expect(node(report, "secret")).toMatchObject({ offset: 2, length: 4, type: "message (xor)" });
    expect(node(report, "secret.text")).toMatchObject({ value: "flag", offset: null });
    expect(value(report, "secret.parent_key")).toBe(0x2a);
    expect(value(report, "secret.root_len")).toBe(4);
    expect(value(report, "rotated")).toBe("03 80");
    expect([value(report, "parts[0]"), value(report, "parts[1]")]).toEqual(["hi", "you"]);
    expect(node(report, "names").count).toBe(3);
    expect(node(report, "tagged").display).toBe("(no matching case)");
    expect(node(report, "rest").count).toBe(2);
    expect(node(report, "second_byte")).toMatchObject({ value: 4, offset: 1, instance: true });
    expect(value(report, "from_root_io")).toBe("2a 04");
  });

  it("keeps the fields read so far and reports where and why parsing stopped", async () => {
    const ksy = `
meta:
  id: rec
  endian: le
seq:
  - id: magic
    contents: CTF1
  - id: count
    type: u4
  - id: items
    type: u4
    repeat: expr
    repeat-expr: count
`;
    const short = concat(ascii("CTF1"), Uint8Array.of(100, 0, 0, 0), Uint8Array.of(1, 0, 0, 0, 2, 0, 0, 0, 3, 0));
    const report = await custom(ksy, short);
    expect(report.error).toMatchObject({ path: "items[2]", offset: 16, message: "Needed 4 byte(s) at offset 0x10, but only 2 remain" });
    expect(node(report, "items").count).toBe(2);
    expect(node(report, "items[2]").error).toMatch(/Needed 4 byte/);
    expect(report.parsedBytes).toBe(16);

    // A wrong magic is reported with a one-click repair that writes the expected bytes.
    const wrong = concat(ascii("CTF0"), Uint8Array.of(1, 0, 0, 0, 7, 0, 0, 0));
    const broken = await custom(ksy, wrong);
    expect(broken.findings[0]).toMatchObject({
      span: { offset: 0, length: 4 },
      suggestion: { operationId: "struct.set-field", params: { format: "custom", ksy, path: "magic", value: "43 54 46 31" } },
    });
    const fixed = await patch(wrong, broken.findings[0].suggestion!.params!);
    expect(new TextDecoder().decode(fixed.subarray(0, 4))).toBe("CTF1");
    expect((await custom(ksy, fixed)).error).toBeUndefined();
  });

  it("verifies -checksum fields with other algorithms", async () => {
    const ksy = `
meta:
  id: summed
seq:
  - id: body
    size: 3
  - id: sum
    type: u1
    -checksum:
      algorithm: sum8
      start: 0
      end: 3
  - id: parity
    type: u1
    -checksum:
      algorithm: xor8
      start: 0
      end: 3
`;
    const data = Uint8Array.of(0x10, 0x20, 0xf0, 0x20, 0xc1);
    const report = await custom(ksy, data);
    expect(node(report, "sum").checksum).toMatchObject({ ok: true, computed: 0x20 });
    expect(node(report, "parity").checksum).toMatchObject({ ok: false, computed: 0xc0, range: { offset: 0, length: 3 } });
    expect(rules(report.findings)).toEqual(["struct.checksum"]);
    const fixed = await patch(data, { format: "custom", ksy });
    expect(fixed[4]).toBe(0xc0);
  });

  it("rejects schema mistakes with their location before reading any bytes", async () => {
    const attempt = async (ksy: string) => (await run("struct.parse", bytesFrom(Uint8Array.of(1, 2, 3, 4)), { format: "custom", ksy })).error?.message;
    expect(await attempt("meta: {id: x}\nseq:\n  - id: a\n    typo: 1\n")).toBe('Schema error at seq[0]: Unknown key "typo"');
    expect(await attempt("meta: {id: x}\nseq:\n  - id: a\n    type: missing\n")).toBe('Schema error at seq[0]: Unknown type "missing"');
    expect(await attempt("meta: {id: x}\nseq:\n  - id: a\n    type: u4\n")).toMatch(/seq\[0\]: u4 has no endianness/);
    expect(await attempt("meta: {id: x}\nseq:\n  - id: a\n    size: (1 +\n")).toMatch(/^Schema error at seq\[0\]\.size: Unexpected end of expression/);
    expect(await attempt("meta: {id: x}\nseq:\n  - id: a\n    type: u1\n    valid: e::nope\nenums:\n  e:\n    1: yes_\n")).toMatch(/Enum e has no label "nope"/);
    expect(await attempt("seq: [")).toMatch(/^Schema error at Not valid YAML/);
    expect(await attempt("")).toMatch(/Paste a \.ksy schema/);
  });

  it("caps runaway repeats", async () => {
    const report = await custom("meta: {id: x}\nseq:\n  - id: a\n    type: u1\n    repeat: expr\n    repeat-expr: 100000000\n", Uint8Array.of(1));
    expect(report.error?.message).toBe("repeat-expr is 100000000; the limit is 10,000,000");
  });
});

describe("Binary structure lab: code export", () => {
  const PROC = `
meta:
  id: proc
  endian: be
  encoding: ASCII
seq:
  - id: key
    type: u1
  - id: len
    type: u1
  - id: secret
    size: len
    process: xor(key)
    type: message
  - id: names
    type: strz
    repeat: until
    repeat-until: _ == "end"
  - id: kind
    type: u1
    enum: kind
    valid:
      any-of: [kind::a, kind::b]
  - id: flags
    type: b3
  - id: rest_bits
    type: b5
  - id: rest
    type: u2
    repeat: eos
instances:
  calc:
    value: '(-7 / 2) * 100 + (-7 % 3) * 10 + (key > 1 ? 1 : 0)'
  ratio:
    value: len / 8.0
  second_byte:
    pos: 1
    type: u1
types:
  message:
    seq:
      - id: text
        type: str
        size-eos: true
    instances:
      parent_key:
        value: _parent.key
enums:
  kind:
    1: a
    2: b
`;
  const bytes = concat(
    Uint8Array.of(0x2a, 4), ascii("flag").map((b) => b ^ 0x2a),
    ascii("x\0end\0"),
    Uint8Array.of(2, 0b101_10011, 0x12, 0x34),
  );

  /** Loads a generated ES module in-process (tests only; the app's CSP forbids this). */
  function load(code: string) {
    const body = code.replace(/^export (?=class|function|const)/gm, "");
    return new Function(`${body}\nreturn { parse, dump, ParseError };`)() as {
      parse(data: Uint8Array): Record<string, unknown> & { checksum_errors: string[] };
      dump(value: unknown): string;
      ParseError: ErrorConstructor;
    };
  }

  async function generate(ksy: string, language: "python" | "javascript") {
    const { value, error, diagnostics } = await executeOperation(registry, { operationId: "struct.codegen", inputs: { text: { type: "text", text: ksy } }, params: { language } }).then((result) => ({
      value: Object.values(result.outputs)[0],
      error: result.run.error,
      diagnostics: result.run.diagnostics,
    }));
    return { code: value?.type === "text" ? value.text : "", error, diagnostics };
  }

  it("generates a JavaScript parser that agrees with the interpreter", async () => {
    const { code, diagnostics } = await generate(PROC, "javascript");
    expect(diagnostics).toEqual(["Save as proc.mjs."]);
    const parser = load(code);
    const root = parser.parse(bytes);
    const report = await custom(PROC, bytes);
    expect((root.secret as { text: string }).text).toBe(value(report, "secret.text"));
    expect((root.secret as { parent_key: number }).parent_key).toBe(0x2a);
    expect(root.names).toEqual(["x", "end"]);
    expect([root.kind, root.flags, root.rest_bits, root.rest]).toEqual([2, 5, 19, [0x1234]]);
    expect([root.calc, root.ratio, root.second_byte]).toEqual([value(report, "calc"), value(report, "ratio"), 4]);
    expect(root.calc).toBe(-379);
    expect(parser.dump(root)).toContain("kind: b (0x2)");

    const invalid = new Uint8Array(bytes);
    invalid[12] = 3;
    expect(() => parser.parse(invalid)).toThrow("validation failed: kind is 3");
  });

  it("generates parsers for the built-in schemas, with checksum checks", async () => {
    const png = await makePng({ width: 2, height: 2, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(1, 2, 3, 4) });
    const parser = load((await generate((await parse(png)).schema, "javascript")).code);
    const root = parser.parse(png);
    const chunks = root.chunks as { type: string; body: { height?: number } }[];
    expect(chunks.map((chunk) => chunk.type)).toEqual(["IHDR", "IDAT", "IEND"]);
    expect(chunks[0].body.height).toBe(2);
    expect(root.checksum_errors).toEqual([]);
    expect(parser.parse(tamperDimensions(png, 2, 3)).checksum_errors).toEqual([expect.stringMatching(/^Chunk\.crc: stored 0x[0-9a-f]+, crc32 is 0x[0-9a-f]+$/)]);

    const { code: python } = await generate((await parse(png)).schema, "python");
    expect(python).toMatch(/^#!\/usr\/bin\/env python3/);
    expect(python).toContain("class Chunk(Struct):");
    expect(python).toContain("class ColorType(IntEnum):");
    expect(python).toContain('_check(self, "crc", self.crc, "crc32", self._io.data[_c[0]:_c[1]])');
    expect(python).toContain("def parse(data):");
  });

  it("reports schema errors on export", async () => {
    const { error } = await generate("meta: {id: x}\nseq:\n  - id: a\n    type: nope\n", "python");
    expect(error).toMatchObject({ code: "INVALID_INPUT", message: 'Schema error at seq[0]: Unknown type "nope"' });
  });
});
