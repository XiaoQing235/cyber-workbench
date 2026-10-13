import { parse as parseYaml } from "yaml";
import { enumRefs, KsyExprError, parseExpr, parseIntLiteral, type Expr } from "./expr";

/** A problem in the schema itself, reported with where it is (e.g. `types.chunk.seq[2]`). */
export class KsySchemaError extends Error {
  constructor(
    message: string,
    readonly where: string,
  ) {
    super(where ? `${where}: ${message}` : message);
    this.name = "KsySchemaError";
  }
}

export type Endian = "le" | "be";

export interface Meta {
  endian?: Endian;
  bitEndian?: Endian;
  encoding?: string;
}

export interface EnumDef {
  name: string;
  labels: Map<string, string>; // value.toString() → label
  values: Map<string, number | bigint>; // label → value
}

export type TypeRef =
  | { kind: "name"; name: string }
  | { kind: "switch"; on: Expr; cases: { key: Expr | null; type: string }[] };

export type ChecksumAlgorithm = "crc32" | "adler32" | "sum8" | "xor8";

/** `-checksum` extension: the field stores a checksum of bytes [start, end) of its stream. */
export interface ChecksumDef {
  algorithm: ChecksumAlgorithm;
  start: Expr;
  end: Expr;
}

export interface ValidDef {
  eq?: Expr;
  min?: Expr;
  max?: Expr;
  anyOf?: Expr[];
  expr?: Expr;
}

export interface AttrDef {
  id: string;
  where: string;
  doc?: string;
  type?: TypeRef;
  size?: Expr;
  sizeEos: boolean;
  terminator?: number;
  consume: boolean;
  include: boolean;
  eosError: boolean;
  padRight?: number;
  contents?: Uint8Array;
  repeat?: "expr" | "eos" | "until";
  repeatExpr?: Expr;
  repeatUntil?: Expr;
  if?: Expr;
  enumName?: string;
  encoding?: string;
  process?: { name: "xor" | "zlib" | "rol" | "ror"; args: Expr[] };
  valid?: ValidDef;
  checksum?: ChecksumDef;
  // Instances only.
  pos?: Expr;
  io?: Expr;
  value?: Expr;
}

export interface TypeDef {
  name: string;
  where: string;
  parent: TypeDef | null;
  meta: Meta;
  doc?: string;
  seq: AttrDef[];
  instances: Map<string, AttrDef>;
  types: Map<string, TypeDef>;
  enums: Map<string, EnumDef>;
}

export interface KsySchema {
  id: string;
  title?: string;
  root: TypeDef;
}

export type Primitive =
  | { kind: "int"; width: 1 | 2 | 4 | 8; signed: boolean; endian?: Endian }
  | { kind: "float"; width: 4 | 8; endian?: Endian }
  | { kind: "bits"; width: number; endian?: Endian }
  | { kind: "str"; zero: boolean };

export function primitive(name: string): Primitive | null {
  let match = /^([us])([1248])(le|be)?$/.exec(name);
  if (match) return { kind: "int", width: Number(match[2]) as 1 | 2 | 4 | 8, signed: match[1] === "s", endian: match[3] as Endian | undefined };
  match = /^f([48])(le|be)?$/.exec(name);
  if (match) return { kind: "float", width: Number(match[1]) as 4 | 8, endian: match[2] as Endian | undefined };
  match = /^b([1-9][0-9]?)(le|be)?$/.exec(name);
  if (match && Number(match[1]) <= 64) return { kind: "bits", width: Number(match[1]), endian: match[2] as Endian | undefined };
  if (name === "str" || name === "strz") return { kind: "str", zero: name === "strz" };
  return null;
}

type Map_ = Record<string, unknown>;
const isMap = (value: unknown): value is Map_ => typeof value === "object" && value !== null && !Array.isArray(value);
const NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

const ATTR_KEYS = new Set([
  "id", "doc", "doc-ref", "type", "size", "size-eos", "terminator", "consume", "include", "eos-error", "pad-right",
  "contents", "repeat", "repeat-expr", "repeat-until", "if", "enum", "encoding", "process", "valid",
]);
const INSTANCE_KEYS = new Set([...ATTR_KEYS, "pos", "io", "value"]);
const TYPE_KEYS = new Set(["meta", "doc", "doc-ref", "seq", "types", "enums", "instances", "params"]);
const META_KEYS = new Set([
  "id", "title", "application", "file-extension", "xref", "license", "ks-version", "ks-debug", "ks-opaque-types",
  "endian", "bit-endian", "encoding", "imports", "tags",
]);

function own(map: Map_): [string, unknown][] {
  return Object.keys(map).map((key) => [key, map[key]]);
}

function checkKeys(map: Map_, allowed: Set<string>, where: string): void {
  for (const key of Object.keys(map)) {
    // Keys starting with "-" are extensions (e.g. -webide-representation); only -checksum is interpreted.
    if (!allowed.has(key) && !key.startsWith("-")) throw new KsySchemaError(`Unknown key "${key}"`, where);
  }
}

function expr(value: unknown, where: string): Expr {
  if (typeof value === "number") return Number.isInteger(value) ? { kind: "int", value } : { kind: "float", value };
  if (typeof value === "boolean") return { kind: "bool", value };
  if (typeof value === "string") {
    try {
      return parseExpr(value);
    } catch (error) {
      if (error instanceof KsyExprError) throw new KsySchemaError(error.message, where);
      throw error;
    }
  }
  throw new KsySchemaError(`Expected an expression, got ${JSON.stringify(value)}`, where);
}

function bool(value: unknown, where: string): boolean {
  if (typeof value !== "boolean") throw new KsySchemaError("Expected true or false", where);
  return value;
}

function byte(value: unknown, where: string): number {
  const number = typeof value === "string" ? parseIntLiteral(value) : value;
  if (typeof number !== "number" || !Number.isInteger(number) || number < 0 || number > 255) {
    throw new KsySchemaError("Expected a byte value (0–255)", where);
  }
  return number;
}

function bytesOf(value: unknown, where: string): Uint8Array {
  const parts = Array.isArray(value) ? value : [value];
  const out: number[] = [];
  for (const part of parts) {
    if (typeof part === "string") out.push(...new TextEncoder().encode(part));
    else out.push(byte(part, where));
  }
  return Uint8Array.from(out);
}

function meta(spec: unknown, inherited: Meta, where: string): Meta {
  if (spec === undefined) return inherited;
  if (!isMap(spec)) throw new KsySchemaError("meta must be a mapping", where);
  checkKeys(spec, META_KEYS, where);
  const imports = spec.imports;
  if (Array.isArray(imports) && imports.length > 0) {
    throw new KsySchemaError("imports are not supported: paste the imported types into this schema", where);
  }
  const endian = (key: string): Endian | undefined => {
    const value = spec[key];
    if (value === undefined) return undefined;
    if (value !== "le" && value !== "be") throw new KsySchemaError(`${key} must be le or be (switchable endianness is not supported)`, where);
    return value;
  };
  if (spec.encoding !== undefined && typeof spec.encoding !== "string") throw new KsySchemaError("encoding must be a string", where);
  return {
    endian: endian("endian") ?? inherited.endian,
    bitEndian: endian("bit-endian") ?? inherited.bitEndian,
    encoding: (spec.encoding as string | undefined) ?? inherited.encoding,
  };
}

function enumDef(name: string, spec: unknown, where: string): EnumDef {
  if (!isMap(spec)) throw new KsySchemaError("An enum is a mapping of values to labels", where);
  const def: EnumDef = { name, labels: new Map(), values: new Map() };
  for (const [key, entry] of own(spec)) {
    const value = parseIntLiteral(key);
    if (value === null) throw new KsySchemaError(`Enum key "${key}" is not an integer`, where);
    const label = isMap(entry) ? entry.id : entry;
    if (typeof label !== "string" || !NAME.test(label)) throw new KsySchemaError(`Enum label for ${key} must be a name`, where);
    def.labels.set(value.toString(), label);
    def.values.set(label, value);
  }
  return def;
}

function typeRef(spec: unknown, where: string): TypeRef {
  if (typeof spec === "string") {
    if (spec.includes("(")) throw new KsySchemaError(`Parameterised types (${spec}) are not supported`, where);
    if (!/^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$/.test(spec)) throw new KsySchemaError(`Invalid type name "${spec}"`, where);
    return { kind: "name", name: spec };
  }
  if (!isMap(spec) || spec["switch-on"] === undefined || !isMap(spec.cases)) {
    throw new KsySchemaError("type must be a name or a mapping with switch-on and cases", where);
  }
  checkKeys(spec, new Set(["switch-on", "cases"]), where);
  const cases = own(spec.cases).map(([key, type]) => {
    const name = typeRef(type, `${where}.cases`);
    if (name.kind !== "name") throw new KsySchemaError("Nested switch types are not supported", where);
    return { key: key === "_" ? null : expr(key, `${where}.cases`), type: name.name };
  });
  return { kind: "switch", on: expr(spec["switch-on"], `${where}.switch-on`), cases };
}

function processDef(spec: unknown, where: string): AttrDef["process"] {
  const match = typeof spec === "string" ? /^([a-z0-9_]+)(?:\((.*)\))?$/.exec(spec.trim()) : null;
  if (!match) throw new KsySchemaError("process must look like xor(key), zlib, rol(n) or ror(n)", where);
  const name = match[1];
  if (name !== "xor" && name !== "zlib" && name !== "rol" && name !== "ror") {
    throw new KsySchemaError(`process ${name} is not supported (xor, zlib, rol and ror are)`, where);
  }
  const args = match[2] === undefined ? [] : (expr(`[${match[2]}]`, where) as Extract<Expr, { kind: "array" }>).items;
  if ((name === "zlib") !== (args.length === 0)) throw new KsySchemaError(`process ${name} takes ${name === "zlib" ? "no" : "one"} argument`, where);
  return { name, args };
}

function validDef(spec: unknown, where: string): ValidDef {
  if (!isMap(spec)) return { eq: expr(spec, where) };
  checkKeys(spec, new Set(["eq", "min", "max", "any-of", "expr"]), where);
  const anyOf = spec["any-of"];
  if (anyOf !== undefined && !Array.isArray(anyOf)) throw new KsySchemaError("any-of must be a list", where);
  return {
    ...(spec.eq !== undefined ? { eq: expr(spec.eq, where) } : {}),
    ...(spec.min !== undefined ? { min: expr(spec.min, where) } : {}),
    ...(spec.max !== undefined ? { max: expr(spec.max, where) } : {}),
    ...(anyOf ? { anyOf: (anyOf as unknown[]).map((item) => expr(item, where)) } : {}),
    ...(spec.expr !== undefined ? { expr: expr(spec.expr, where) } : {}),
  };
}

function checksumDef(spec: unknown, where: string): ChecksumDef {
  if (!isMap(spec)) throw new KsySchemaError("-checksum must be a mapping with algorithm, start and end", where);
  checkKeys(spec, new Set(["algorithm", "start", "end"]), where);
  const algorithm = spec.algorithm;
  if (algorithm !== "crc32" && algorithm !== "adler32" && algorithm !== "sum8" && algorithm !== "xor8") {
    throw new KsySchemaError("-checksum algorithm must be crc32, adler32, sum8 or xor8", where);
  }
  if (spec.start === undefined || spec.end === undefined) throw new KsySchemaError("-checksum needs start and end", where);
  return { algorithm, start: expr(spec.start, `${where}.start`), end: expr(spec.end, `${where}.end`) };
}

function attrDef(spec: unknown, where: string, fallbackId: string, instance: boolean): AttrDef {
  if (!isMap(spec)) throw new KsySchemaError("An attribute must be a mapping", where);
  checkKeys(spec, instance ? INSTANCE_KEYS : ATTR_KEYS, where);
  const id = instance ? fallbackId : (spec.id ?? fallbackId);
  if (typeof id !== "string" || !NAME.test(id)) throw new KsySchemaError("id must be a name (letters, digits, _)", where);
  const at = (key: string) => `${where}.${key}`;
  const attr: AttrDef = {
    id,
    where,
    sizeEos: spec["size-eos"] !== undefined ? bool(spec["size-eos"], at("size-eos")) : false,
    consume: spec.consume !== undefined ? bool(spec.consume, at("consume")) : true,
    include: spec.include !== undefined ? bool(spec.include, at("include")) : false,
    eosError: spec["eos-error"] !== undefined ? bool(spec["eos-error"], at("eos-error")) : true,
  };
  if (typeof spec.doc === "string") attr.doc = spec.doc;
  if (spec.type !== undefined) attr.type = typeRef(spec.type, at("type"));
  if (spec.size !== undefined) attr.size = expr(spec.size, at("size"));
  if (spec.terminator !== undefined) attr.terminator = byte(spec.terminator, at("terminator"));
  if (spec["pad-right"] !== undefined) attr.padRight = byte(spec["pad-right"], at("pad-right"));
  if (spec.contents !== undefined) attr.contents = bytesOf(spec.contents, at("contents"));
  if (spec.if !== undefined) attr.if = expr(spec.if, at("if"));
  if (spec.enum !== undefined) {
    if (typeof spec.enum !== "string") throw new KsySchemaError("enum must be a name", at("enum"));
    attr.enumName = spec.enum;
  }
  if (spec.encoding !== undefined) {
    if (typeof spec.encoding !== "string") throw new KsySchemaError("encoding must be a string", at("encoding"));
    attr.encoding = spec.encoding;
  }
  if (spec.process !== undefined) attr.process = processDef(spec.process, at("process"));
  if (spec.valid !== undefined) attr.valid = validDef(spec.valid, at("valid"));
  if (spec["-checksum"] !== undefined) attr.checksum = checksumDef(spec["-checksum"], at("-checksum"));
  if (spec.repeat !== undefined) {
    const repeat = spec.repeat;
    if (repeat !== "expr" && repeat !== "eos" && repeat !== "until") throw new KsySchemaError("repeat must be expr, eos or until", at("repeat"));
    attr.repeat = repeat;
    if (repeat === "expr") {
      if (spec["repeat-expr"] === undefined) throw new KsySchemaError("repeat: expr needs repeat-expr", where);
      attr.repeatExpr = expr(spec["repeat-expr"], at("repeat-expr"));
    }
    if (repeat === "until") {
      if (spec["repeat-until"] === undefined) throw new KsySchemaError("repeat: until needs repeat-until", where);
      attr.repeatUntil = expr(spec["repeat-until"], at("repeat-until"));
    }
  }
  if (instance) {
    if (spec.pos !== undefined) attr.pos = expr(spec.pos, at("pos"));
    if (spec.io !== undefined) attr.io = expr(spec.io, at("io"));
    if (spec.value !== undefined) attr.value = expr(spec.value, at("value"));
  }
  const sized = attr.size !== undefined || attr.sizeEos;
  if (attr.size !== undefined && attr.sizeEos) throw new KsySchemaError("Use either size or size-eos, not both", where);
  if (attr.contents && (attr.type || sized)) throw new KsySchemaError("contents cannot be combined with type or size", where);
  const prim = attr.type?.kind === "name" ? primitive(attr.type.name) : null;
  if (attr.value === undefined && !attr.contents && !sized && attr.terminator === undefined) {
    if (!attr.type) throw new KsySchemaError("Raw bytes need size, size-eos, terminator or contents", where);
    if (prim?.kind === "str" && !prim.zero) throw new KsySchemaError("str needs size, size-eos or terminator (or use strz)", where);
  }
  if (attr.process && attr.type && prim) throw new KsySchemaError("process applies to raw bytes or user types", where);
  if (attr.process && !sized && attr.terminator === undefined) throw new KsySchemaError("process needs size, size-eos or terminator", where);
  return attr;
}

function typeDef(name: string, spec: unknown, parent: TypeDef | null, inherited: Meta, where: string): TypeDef {
  if (!isMap(spec)) throw new KsySchemaError("A type must be a mapping", where);
  checkKeys(spec, TYPE_KEYS, where);
  if (spec.params !== undefined) throw new KsySchemaError("Parameterised types (params) are not supported", where);
  const prefix = where ? `${where}.` : "";
  const type: TypeDef = {
    name,
    where,
    parent,
    meta: meta(spec.meta, inherited, `${prefix}meta`),
    seq: [],
    instances: new Map(),
    types: new Map(),
    enums: new Map(),
  };
  if (typeof spec.doc === "string") type.doc = spec.doc;
  if (spec.enums !== undefined) {
    if (!isMap(spec.enums)) throw new KsySchemaError("enums must be a mapping", `${prefix}enums`);
    for (const [enumName, entries] of own(spec.enums)) type.enums.set(enumName, enumDef(enumName, entries, `${prefix}enums.${enumName}`));
  }
  if (spec.types !== undefined) {
    if (!isMap(spec.types)) throw new KsySchemaError("types must be a mapping", `${prefix}types`);
    for (const [typeName, child] of own(spec.types)) {
      if (!NAME.test(typeName)) throw new KsySchemaError(`Invalid type name "${typeName}"`, `${prefix}types`);
      type.types.set(typeName, typeDef(typeName, child, type, type.meta, `${prefix}types.${typeName}`));
    }
  }
  if (spec.seq !== undefined) {
    if (!Array.isArray(spec.seq)) throw new KsySchemaError("seq must be a list", `${prefix}seq`);
    const seen = new Set<string>();
    type.seq = spec.seq.map((item, index) => {
      const attr = attrDef(item, `${prefix}seq[${index}]`, `_unnamed${index}`, false);
      if (seen.has(attr.id)) throw new KsySchemaError(`Duplicate id "${attr.id}"`, attr.where);
      seen.add(attr.id);
      return attr;
    });
  }
  if (spec.instances !== undefined) {
    if (!isMap(spec.instances)) throw new KsySchemaError("instances must be a mapping", `${prefix}instances`);
    for (const [instanceName, item] of own(spec.instances)) {
      if (!NAME.test(instanceName)) throw new KsySchemaError(`Invalid instance name "${instanceName}"`, `${prefix}instances`);
      type.instances.set(instanceName, attrDef(item, `${prefix}instances.${instanceName}`, instanceName, true));
    }
  }
  return type;
}

/** Finds a user type by (possibly `::`-qualified) name, searching enclosing types outwards like Kaitai. */
export function resolveType(name: string, from: TypeDef): TypeDef | null {
  const [first, ...rest] = name.split("::");
  for (let scope: TypeDef | null = from; scope; scope = scope.parent) {
    let found = scope.types.get(first) ?? (scope.parent === null && scope.name === first ? scope : undefined);
    if (!found) continue;
    for (const part of rest) {
      found = found.types.get(part);
      if (!found) return null;
    }
    return found;
  }
  return null;
}

export function resolveEnum(name: string, from: TypeDef): EnumDef | null {
  const parts = name.split("::");
  const enumName = parts.pop()!;
  if (parts.length === 0) {
    for (let scope: TypeDef | null = from; scope; scope = scope.parent) {
      const found = scope.enums.get(enumName);
      if (found) return found;
    }
    return null;
  }
  return resolveType(parts.join("::"), from)?.enums.get(enumName) ?? null;
}

function exprsOf(attr: AttrDef): Expr[] {
  const list: (Expr | null | undefined)[] = [attr.size, attr.repeatExpr, attr.repeatUntil, attr.if, attr.pos, attr.io, attr.value];
  if (attr.type?.kind === "switch") list.push(attr.type.on, ...attr.type.cases.map((item) => item.key));
  if (attr.valid) list.push(attr.valid.eq, attr.valid.min, attr.valid.max, attr.valid.expr, ...(attr.valid.anyOf ?? []));
  if (attr.checksum) list.push(attr.checksum.start, attr.checksum.end);
  if (attr.process) list.push(...attr.process.args);
  return list.filter((item): item is Expr => item !== undefined && item !== null);
}

/** Checks every type and enum reference up front, so mistakes are reported before any bytes are read. */
function checkReferences(type: TypeDef): void {
  for (const attr of [...type.seq, ...type.instances.values()]) {
    const names = attr.type?.kind === "name" ? [attr.type.name] : attr.type?.kind === "switch" ? attr.type.cases.map((item) => item.type) : [];
    for (const name of names) {
      const prim = primitive(name);
      if (prim) {
        if ((prim.kind === "int" && prim.width > 1) || prim.kind === "float") {
          if (!prim.endian && !type.meta.endian) throw new KsySchemaError(`${name} has no endianness: use ${name}le / ${name}be or set meta.endian`, attr.where);
        }
        if (prim.kind === "str" && !attr.encoding && !type.meta.encoding) throw new KsySchemaError("Strings need an encoding (attribute encoding or meta.encoding)", attr.where);
        continue;
      }
      if (!resolveType(name, type)) throw new KsySchemaError(`Unknown type "${name}"`, attr.where);
    }
    if (attr.enumName && !resolveEnum(attr.enumName, type)) throw new KsySchemaError(`Unknown enum "${attr.enumName}"`, attr.where);
    for (const expression of exprsOf(attr)) {
      for (const ref of enumRefs(expression)) {
        const def = resolveEnum(ref.enumPath, type);
        if (!def) throw new KsySchemaError(`Unknown enum "${ref.enumPath}"`, attr.where);
        if (!def.values.has(ref.label)) throw new KsySchemaError(`Enum ${ref.enumPath} has no label "${ref.label}"`, attr.where);
      }
    }
  }
  for (const child of type.types.values()) checkReferences(child);
}

export function loadKsy(text: string): KsySchema {
  let doc: unknown;
  try {
    doc = parseYaml(text, { maxAliasCount: 100, uniqueKeys: true, prettyErrors: false });
  } catch (error) {
    throw new KsySchemaError(`Not valid YAML: ${error instanceof Error ? error.message : String(error)}`, "");
  }
  if (!isMap(doc)) throw new KsySchemaError("A .ksy schema is a YAML mapping with meta and seq", "");
  const metaSpec = isMap(doc.meta) ? doc.meta : {};
  const id = metaSpec.id ?? "root";
  if (typeof id !== "string" || !NAME.test(id)) throw new KsySchemaError("meta.id must be a name", "meta");
  const root = typeDef(id, doc, null, { bitEndian: "be" }, "");
  checkReferences(root);
  return { id, root, ...(typeof metaSpec.title === "string" ? { title: metaSpec.title } : {}) };
}
