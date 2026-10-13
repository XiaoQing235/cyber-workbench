import type { Finding } from "../../core/analysis/finding";
import { parseIntLiteral } from "./expr";
import { hexBytes, normaliseEncoding, CP437_HIGH, parseKsy } from "./interpreter";
import { PRESETS, sniffFormat } from "./presets";
import { KsySchemaError, loadKsy, type EnumDef, type KsySchema } from "./schema";
import type { FieldNode, StructReport } from "./tree";

/** A problem the user can fix: unknown format, schema error, bad path or value. */
export class StructLabError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StructLabError";
  }
}

const hex = (value: number) => `0x${value.toString(16)}`;

interface Chosen {
  schema: KsySchema;
  text: string;
  params: { format: string; ksy: string };
}

export function chooseSchema(format: string, ksy: string, head: Uint8Array): Chosen {
  let name = format;
  if (format === "auto") {
    const sniffed = sniffFormat(head);
    if (!sniffed) throw new StructLabError('Not a built-in format (PNG, BMP, GIF, WAV, ZIP). Choose "custom" and paste a .ksy schema.');
    name = sniffed;
  }
  const text = name === "custom" ? ksy : PRESETS[name];
  if (name === "custom" && !ksy.trim()) throw new StructLabError("Paste a .ksy schema into the schema box, or choose a built-in format.");
  if (text === undefined) throw new StructLabError(`Unknown format "${name}"`);
  try {
    return { schema: loadKsy(text), text, params: { format: name, ksy: name === "custom" ? ksy : "" } };
  } catch (error) {
    if (error instanceof KsySchemaError) throw new StructLabError(`Schema error at ${error.message}`);
    throw error;
  }
}

function walk(node: FieldNode, visit: (node: FieldNode) => void): void {
  visit(node);
  for (const child of node.children ?? []) walk(child, visit);
}

const reparse = (params: Chosen["params"]) => ({ operationId: "struct.parse", params });

export async function analyse(bytes: Uint8Array, format: string, ksy: string, signal?: AbortSignal): Promise<{ report: StructReport; notes: string[] }> {
  const chosen = chooseSchema(format, ksy, bytes.subarray(0, 16));
  const { schema, params } = chosen;
  const mismatches: { path: string; node: FieldNode }[] = [];
  const result = await parseKsy(schema, bytes, {
    signal,
    onField: (path, node) => {
      if (node.checksum && !node.checksum.ok) mismatches.push({ path, node });
    },
  });
  const findings: Finding[] = [];
  const notes = [`Parsed ${result.parsedBytes.toLocaleString()} of ${bytes.length.toLocaleString()} bytes as ${schema.title ?? schema.id}.`];
  const { error } = result;

  if (error) {
    const where = error.offset === null ? "" : ` at ${hex(error.offset)}`;
    notes.push(`Stopped${where} in ${error.path || schema.id}: ${error.message}`);
    const node = error.node;
    const repairable = error.expected !== undefined && node?.encoding && node.offset !== null;
    findings.push({
      id: "struct-error",
      ruleId: "struct.parse",
      severity: "strong",
      message: `Parsing stopped${where} in ${error.path || schema.id}: ${error.message}`,
      ...(error.offset !== null ? { span: { offset: error.offset, length: Math.max(1, Math.min(node?.length || 1, bytes.length - error.offset)) } } : {}),
      evidence: [{ kind: "structure", tier: "strong", detail: `Everything before this offset matches the ${schema.id} schema; the tree shows the fields read so far.` }],
      ...(repairable
        ? {
            suggestion: {
              operationId: "struct.set-field",
              params: { ...params, path: error.path, value: error.expected, recompute: true },
              label: `Write the expected value into ${error.path}`,
              then: [reparse(params)],
            },
          }
        : {}),
    });
  }

  for (const { path, node } of mismatches.slice(0, 50)) {
    const sum = node.checksum!;
    findings.push({
      id: `checksum:${path}`,
      ruleId: "struct.checksum",
      severity: "strong",
      message: `${path} stores ${hex(Number(node.value))}, but the ${sum.algorithm} of its data is ${hex(sum.computed)}`,
      ...(node.offset !== null ? { span: { offset: node.offset, length: node.length } } : {}),
      evidence: [
        {
          kind: "integrity",
          tier: "strong",
          detail: `${sum.algorithm} over ${sum.range ? `${hex(sum.range.offset)}–${hex(sum.range.offset + sum.range.length)}` : "processed data"}. A mismatch means the covered bytes (or the checksum) were changed.`,
          ...(sum.range ? { span: sum.range } : {}),
        },
      ],
      suggestion: { operationId: "struct.set-field", params: { ...params, path: "", value: "", recompute: true }, label: "Recompute all checksums", then: [reparse(params)] },
    });
  }
  if (mismatches.length > 0) notes.push(`${mismatches.length} checksum mismatch(es).`);

  let covered = result.parsedBytes;
  walk(result.root, (node) => {
    if (node.offset !== null) covered = Math.max(covered, node.offset + node.length);
  });
  if (!error && !result.truncated && covered < bytes.length) {
    findings.push({
      id: "struct-trailing",
      ruleId: "struct.trailing",
      severity: "medium",
      message: `${(bytes.length - covered).toLocaleString()} byte(s) after the parsed structure, from ${hex(covered)}`,
      span: { offset: covered, length: bytes.length - covered },
      evidence: [{ kind: "structure", tier: "medium", detail: "The schema ends here but the data continues: often an appended file or hidden payload." }],
      suggestion: { operationId: "bytes.slice", params: { offset: covered, length: -1 }, label: "Extract the trailing bytes" },
    });
  }
  if (!error) {
    for (const failure of result.instanceErrors.slice(0, 20)) {
      findings.push({ id: `instance:${failure.path}`, ruleId: "struct.instance", severity: "weak", message: `${failure.path}: ${failure.message}` });
    }
  }
  if (result.truncated) notes.push("The tree keeps the first 20,000 fields (500 per array); parsing continued past them.");

  const report: StructReport = {
    kind: "struct",
    title: schema.title ?? schema.id,
    params,
    schema: chosen.text,
    root: result.root,
    parsedBytes: result.parsedBytes,
    totalBytes: bytes.length,
    ...(error ? { error: { message: error.message, offset: error.offset, path: error.path } } : {}),
    truncated: result.truncated,
    findings,
  };
  return { report, notes };
}

function encodeText(text: string, encoding: string): Uint8Array {
  const label = normaliseEncoding(encoding);
  if (label === "utf-8") return new TextEncoder().encode(text);
  if (label === "latin1" || label === "cp437") {
    return Uint8Array.from([...text], (char) => {
      const code = char.charCodeAt(0);
      if (code < 0x80 || (label === "latin1" && code < 0x100)) return code;
      const index = label === "cp437" ? CP437_HIGH.indexOf(char) : -1;
      if (index < 0) throw new StructLabError(`"${char}" cannot be written in ${encoding}`);
      return 0x80 + index;
    });
  }
  if (label === "utf-16le" || label === "utf-16be") {
    const out = new Uint8Array(text.length * 2);
    const view = new DataView(out.buffer);
    for (let i = 0; i < text.length; i++) view.setUint16(i * 2, text.charCodeAt(i), label === "utf-16le");
    return out;
  }
  throw new StructLabError(`Editing ${encoding} strings is not supported`);
}

function encodeValue(path: string, node: FieldNode, enumDef: EnumDef | null, text: string): Uint8Array {
  const encoding = node.encoding;
  if (!encoding || node.offset === null) {
    throw new StructLabError(`${path} cannot be edited in place: it is ${node.offset === null ? "computed or inside processed data" : `a ${node.type}`}. Choose one of its fields.`);
  }
  switch (encoding.kind) {
    case "int": {
      const value = parseIntLiteral(text) ?? enumDef?.values.get(text.trim()) ?? null;
      if (value === null) {
        const labels = enumDef ? ` or one of ${[...enumDef.values.keys()].join(", ")}` : "";
        throw new StructLabError(`${path} needs an integer (123, 0x7b)${labels}`);
      }
      const bits = BigInt(encoding.width * 8);
      const min = encoding.signed ? -(1n << (bits - 1n)) : 0n;
      const max = encoding.signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n;
      const big = BigInt(value);
      if (big < min || big > max) throw new StructLabError(`${value} does not fit in ${node.type} (${min}–${max})`);
      const out = new Uint8Array(encoding.width);
      const unsigned = BigInt.asUintN(Number(bits), big);
      for (let i = 0; i < encoding.width; i++) {
        const byte = Number((unsigned >> BigInt(8 * i)) & 0xffn);
        out[encoding.le ? i : encoding.width - 1 - i] = byte;
      }
      return out;
    }
    case "float": {
      const value = Number(text.trim());
      if (text.trim() === "" || Number.isNaN(value)) throw new StructLabError(`${path} needs a number`);
      const out = new Uint8Array(encoding.width);
      const view = new DataView(out.buffer);
      if (encoding.width === 4) view.setFloat32(0, value, encoding.le);
      else view.setFloat64(0, value, encoding.le);
      return out;
    }
    case "bytes": {
      const digits = text.replace(/0x|\\x|[\s,:]/gi, "");
      if (!/^([0-9a-f]{2})*$/i.test(digits)) throw new StructLabError(`${path} needs hex bytes, like 89 50 4e 47`);
      const out = Uint8Array.from(digits.match(/../g) ?? [], (pair) => parseInt(pair, 16));
      if (out.length !== node.length) throw new StructLabError(`${path} is ${node.length} byte(s); the value has ${out.length}`);
      return out;
    }
    case "str": {
      const encoded = encodeText(text, encoding.encoding);
      const room = encoding.terminated ? node.length - 1 : node.length;
      if (encoded.length > room || (encoding.pad === null && encoded.length !== room)) {
        throw new StructLabError(`${path} holds ${encoding.pad === null ? "exactly" : "at most"} ${room} byte(s) in ${encoding.encoding}; the value needs ${encoded.length}`);
      }
      const out = new Uint8Array(node.length).fill(encoding.pad ?? 0);
      out.set(encoded);
      return out;
    }
  }
}

export async function setField(
  bytes: Uint8Array,
  format: string,
  ksy: string,
  path: string,
  value: string,
  recompute: boolean,
  signal?: AbortSignal,
): Promise<{ bytes: Uint8Array<ArrayBuffer>; notes: string[] }> {
  const { schema } = chooseSchema(format, ksy, bytes.subarray(0, 16));
  const out = new Uint8Array(bytes);
  const notes: string[] = [];
  const target = path.trim();
  if (target) {
    let found: { node: FieldNode; enumDef: EnumDef | null } | null = null;
    const result = await parseKsy(schema, out, {
      signal,
      maxNodes: 0,
      onField: (fieldPath, node, enumDef) => {
        if (fieldPath === target) found = { node, enumDef };
      },
    });
    // The field that stopped the parse (bad magic, failed validation) can be edited too.
    if (!found && result.error?.path === target && result.error.node) found = { node: result.error.node, enumDef: null };
    if (!found) {
      const stopped = result.error ? ` Parsing stopped at ${result.error.path || "the start"} (${result.error.message}).` : "";
      throw new StructLabError(`No field at "${target}". Paths look like chunks[0].body.width.${stopped}`);
    }
    const { node, enumDef } = found as { node: FieldNode; enumDef: EnumDef | null };
    const encoded = encodeValue(target, node, enumDef, value);
    const before = hexBytes(out.subarray(node.offset!, node.offset! + encoded.length), 16);
    out.set(encoded, node.offset!);
    notes.push(`Set ${target} at ${hex(node.offset!)}: ${before} → ${hexBytes(encoded, 16)}.`);
  }
  if (recompute) {
    for (let pass = 0; ; pass++) {
      const stale: { path: string; node: FieldNode }[] = [];
      await parseKsy(schema, out, {
        signal,
        maxNodes: 0,
        onField: (fieldPath, node) => {
          if (node.checksum && !node.checksum.ok && node.encoding?.kind === "int" && node.offset !== null) stale.push({ path: fieldPath, node });
        },
      });
      if (stale.length === 0) break;
      if (pass === 8) {
        notes.push("Checksums still changed after 8 passes; stopped.");
        break;
      }
      for (const { path: fieldPath, node } of stale) {
        out.set(encodeValue(fieldPath, node, null, String(node.checksum!.computed)), node.offset!);
        notes.push(`Recomputed ${fieldPath}: ${hex(Number(node.value))} → ${hex(node.checksum!.computed)}.`);
      }
    }
  }
  if (notes.length === 0) notes.push("Nothing to change: no field given and all checksums match.");
  return { bytes: out, notes };
}
