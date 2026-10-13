import { MemorySource } from "../../core/bytes/sources";
import { crc32 } from "../../core/checksum/crc32";
import { inflate } from "../../core/compression/inflate";
import { toSafe, type Expr } from "./expr";
import {
  primitive,
  resolveEnum,
  resolveType,
  type AttrDef,
  type ChecksumAlgorithm,
  type EnumDef,
  type KsySchema,
  type Meta,
  type TypeDef,
} from "./schema";
import { joinPath, type FieldNode } from "./tree";

const MAX_DEPTH = 64;
const MAX_REPEAT = 10_000_000;
const MAX_STEPS = 20_000_000;
const MAX_INFLATE = 64 * 1024 * 1024;

const hex = (value: number | bigint) => (value < 0 ? `-0x${(-value).toString(16)}` : `0x${value.toString(16)}`);
export const hexBytes = (bytes: Uint8Array, max = Infinity) =>
  Array.from(bytes.subarray(0, Math.min(bytes.length, max)), (b) => b.toString(16).padStart(2, "0")).join(" ") + (bytes.length > max ? " …" : "");

export class KsyParseError extends Error {
  path = "";
  /** The field being read when parsing failed (its span and encoding, for repairs). */
  node: FieldNode | null = null;
  constructor(
    message: string,
    public offset: number | null,
    /** What the field should contain, when known (hex for contents, a value for valid: eq). */
    readonly expected?: string,
  ) {
    super(message);
    this.name = "KsyParseError";
  }
}

export class EnumValue {
  constructor(
    readonly def: EnumDef,
    readonly value: number | bigint,
  ) {}

  get label(): string | undefined {
    return this.def.labels.get(this.value.toString());
  }
}

/**
 * Floats are boxed so that `7 / 2.0` and `7 / 2` stay distinguishable at run time (2.0 === 2 in JS).
 * Plain numbers and bigints are always integers.
 */
export class KFloat {
  constructor(readonly value: number) {}
}

export class KStream {
  pos = 0;
  private bits = 0n;
  private bitsLeft = 0;
  private readonly view: DataView;

  constructor(
    readonly bytes: Uint8Array,
    /** Absolute offset of position 0 in the parsed artifact; null for processed data. */
    readonly base: number | null,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get size(): number {
    return this.bytes.length;
  }

  get eof(): boolean {
    return this.bitsLeft === 0 && this.pos >= this.bytes.length;
  }

  get bitPos(): number {
    return this.pos * 8 - this.bitsLeft;
  }

  abs(pos = this.pos): number | null {
    return this.base === null ? null : this.base + pos;
  }

  where(pos = this.pos): string {
    const absolute = this.abs(pos);
    return absolute === null ? `position ${hex(pos)} of processed data` : `offset ${hex(absolute)}`;
  }

  private need(count: number): void {
    if (this.pos + count > this.bytes.length) {
      throw new KsyParseError(`Needed ${count} byte(s) at ${this.where()}, but only ${this.bytes.length - this.pos} remain`, this.abs());
    }
  }

  save() {
    return { pos: this.pos, bits: this.bits, bitsLeft: this.bitsLeft };
  }

  restore(state: ReturnType<KStream["save"]>): void {
    this.pos = state.pos;
    this.bits = state.bits;
    this.bitsLeft = state.bitsLeft;
  }

  alignToByte(): void {
    this.bits = 0n;
    this.bitsLeft = 0;
  }

  seek(pos: number): void {
    if (pos < 0 || pos > this.bytes.length) throw new KsyParseError(`Position ${pos} is outside the stream (size ${this.bytes.length})`, this.abs());
    this.pos = pos;
    this.alignToByte();
  }

  read(count: number): Uint8Array {
    this.need(count);
    const out = this.bytes.subarray(this.pos, this.pos + count);
    this.pos += count;
    return out;
  }

  readInt(width: 1 | 2 | 4 | 8, signed: boolean, le: boolean): number | bigint {
    this.need(width);
    const at = this.pos;
    this.pos += width;
    switch (width) {
      case 1:
        return signed ? this.view.getInt8(at) : this.view.getUint8(at);
      case 2:
        return signed ? this.view.getInt16(at, le) : this.view.getUint16(at, le);
      case 4:
        return signed ? this.view.getInt32(at, le) : this.view.getUint32(at, le);
      case 8:
        return toSafe(signed ? this.view.getBigInt64(at, le) : this.view.getBigUint64(at, le));
    }
  }

  readFloat(width: 4 | 8, le: boolean): KFloat {
    this.need(width);
    const at = this.pos;
    this.pos += width;
    return new KFloat(width === 4 ? this.view.getFloat32(at, le) : this.view.getFloat64(at, le));
  }

  /** Kaitai's bit reader: big-endian takes bits from the most significant end of each byte. */
  readBits(count: number, le: boolean): bigint {
    const needed = count - this.bitsLeft;
    let result = 0n;
    if (le) {
      if (needed > 0) {
        const buffer = this.read(Math.ceil(needed / 8));
        buffer.forEach((byte, i) => (result |= BigInt(byte) << BigInt(i * 8)));
        const fresh = result >> BigInt(needed);
        result = (result << BigInt(this.bitsLeft)) | this.bits;
        this.bits = fresh;
      } else {
        result = this.bits;
        this.bits >>= BigInt(count);
      }
      this.bitsLeft = -needed & 7;
      return result & ((1n << BigInt(count)) - 1n);
    }
    this.bitsLeft = -needed & 7;
    if (needed > 0) {
      const buffer = this.read(Math.ceil(needed / 8));
      for (const byte of buffer) result = (result << 8n) | BigInt(byte);
      const fresh = result;
      result = (result >> BigInt(this.bitsLeft)) | (this.bits << BigInt(needed));
      this.bits = fresh;
    } else {
      result = this.bits >> BigInt(-needed);
    }
    this.bits &= (1n << BigInt(this.bitsLeft)) - 1n;
    return result;
  }

  readTerminated(terminator: number, include: boolean, consume: boolean, eosError: boolean): Uint8Array {
    const start = this.pos;
    const end = this.bytes.indexOf(terminator, start);
    if (end < 0) {
      if (eosError) throw new KsyParseError(`No terminator ${hex(terminator)} after ${this.where(start)}`, this.abs(start));
      this.pos = this.bytes.length;
      return this.bytes.subarray(start);
    }
    this.pos = consume ? end + 1 : end;
    return this.bytes.subarray(start, include ? end + 1 : end);
  }
}

export class KStruct {
  readonly values = new Map<string, KValue>();
  readonly raw = new Map<string, Uint8Array>();
  readonly instanceState = new Map<string, { failed?: unknown; pending?: true }>();
  readonly seqNodes: FieldNode[] = [];
  readonly instanceNodes = new Map<string, FieldNode>();
  readonly root: KStruct;

  constructor(
    readonly type: TypeDef,
    readonly io: KStream,
    readonly parent: KStruct | null,
    readonly node: FieldNode,
    readonly path: string,
    readonly depth: number,
  ) {
    this.root = parent?.root ?? this;
  }
}

export type KValue = number | bigint | KFloat | string | boolean | Uint8Array | EnumValue | KStruct | KStream | KValue[] | null;

interface Scope {
  struct: KStruct;
  index?: number;
  /** `_` in repeat-until (last element) and valid (the value). */
  last?: { value: KValue };
}

export interface ParseOptions {
  signal?: AbortSignal;
  /** Fields kept in the returned tree (default 20,000). Parsing continues past it. */
  maxNodes?: number;
  /** Array elements kept per array (default 500). */
  maxArrayChildren?: number;
  /** Called for every primitive field read, whether or not it is kept in the tree. */
  onField?: (path: string, node: FieldNode, enumDef: EnumDef | null) => void;
}

export interface ParseResult {
  root: FieldNode;
  error?: KsyParseError;
  /** Bytes consumed by the root sequence. */
  parsedBytes: number;
  truncated: boolean;
  /** Instance failures (the main parse may still have succeeded). */
  instanceErrors: KsyParseError[];
}

class Context {
  nodes = 0;
  steps = 0;
  truncated = false;
  readonly structs: KStruct[] = [];
  readonly instanceErrors: KsyParseError[] = [];
  readonly maxNodes: number;
  readonly maxArrayChildren: number;

  constructor(readonly options: ParseOptions) {
    this.maxNodes = options.maxNodes ?? 20_000;
    this.maxArrayChildren = options.maxArrayChildren ?? 500;
  }

  keep(): boolean {
    if (this.nodes >= this.maxNodes) {
      this.truncated = true;
      return false;
    }
    this.nodes++;
    return true;
  }

  async tick(): Promise<void> {
    this.steps++;
    if (this.steps > MAX_STEPS) throw new KsyParseError(`Stopped after ${MAX_STEPS.toLocaleString()} fields`, null);
    if ((this.steps & 0xfff) === 0) {
      this.options.signal?.throwIfAborted();
      // Let a queued cancel request run during long parses.
      if ((this.steps & 0xffff) === 0) await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}

const newNode = (name: string, attr: AttrDef | null): FieldNode => ({
  name,
  type: "",
  offset: null,
  length: 0,
  ...(attr?.doc ? { doc: attr.doc } : {}),
});

const fail = (message: string): never => {
  throw new KsyParseError(message, null);
};

function annotate(error: unknown, path: string, node: FieldNode | null, offset: number | null): void {
  if (!(error instanceof KsyParseError) || error.path) return;
  error.path = path;
  error.offset ??= offset;
  error.node = node;
  if (node) node.error = error.message;
}

// ---------------------------------------------------------------------------------------------
// Values and expressions

function kind(value: KValue): string {
  if (value === null) return "null (an absent field)";
  if (value instanceof Uint8Array) return "bytes";
  if (value instanceof EnumValue) return `enum ${value.def.name}`;
  if (value instanceof KFloat) return "float";
  if (value instanceof KStruct) return value.type.name;
  if (value instanceof KStream) return "stream";
  if (Array.isArray(value)) return "array";
  if (typeof value === "bigint" || typeof value === "number") return "integer";
  return typeof value === "string" ? "string" : "boolean";
}

function show(value: KValue): string {
  if (typeof value === "number" || typeof value === "bigint") return value >= 0 ? `${value} (${hex(value)})` : String(value);
  if (value instanceof KFloat) return String(value.value);
  if (typeof value === "string") return JSON.stringify(value.length > 60 ? `${value.slice(0, 60)}…` : value);
  if (value instanceof Uint8Array) return `[${hexBytes(value, 16)}]`;
  if (value instanceof EnumValue) return value.label ? `${value.def.name}::${value.label}` : `${value.value} (not in ${value.def.name})`;
  return kind(value);
}

type Num = number | bigint | KFloat;

function numeric(value: KValue, what: string): Num {
  if (typeof value === "number" || typeof value === "bigint" || value instanceof KFloat) return value;
  if (value instanceof EnumValue) return value.value;
  return fail(`${what} needs a number, got ${kind(value)}`);
}

const plain = (value: Num): number | bigint => (value instanceof KFloat ? value.value : value);

function asBool(value: KValue, what: string): boolean {
  if (typeof value !== "boolean") fail(`${what} must be true or false, got ${show(value)}`);
  return value as boolean;
}

function toInt(value: KValue, what: string): number {
  const number = numeric(value, what);
  if (typeof number !== "number") fail(`${what} must be an integer below 2^53, got ${show(value)}`);
  return number as number;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export function equals(a: KValue, b: KValue): boolean {
  const x = a instanceof EnumValue ? a.value : a instanceof KFloat ? a.value : a;
  const y = b instanceof EnumValue ? b.value : b instanceof KFloat ? b.value : b;
  if ((typeof x === "number" || typeof x === "bigint") && (typeof y === "number" || typeof y === "bigint")) {
    if (typeof x === typeof y) return x === y;
    return Number.isInteger(Number(x)) && Number.isInteger(Number(y)) ? BigInt(x) === BigInt(y) : Number(x) === Number(y);
  }
  if (x instanceof Uint8Array && y instanceof Uint8Array) return bytesEqual(x, y);
  return x === y;
}

function compare(op: "<" | "<=" | ">" | ">=", a: KValue, b: KValue): boolean {
  let x: number | bigint | string;
  let y: number | bigint | string;
  if (typeof a === "string" && typeof b === "string") {
    x = a;
    y = b;
  } else {
    x = plain(numeric(a, op));
    y = plain(numeric(b, op));
  }
  switch (op) {
    case "<":
      return x < y;
    case "<=":
      return x <= y;
    case ">":
      return x > y;
    case ">=":
      return x >= y;
  }
}

function arithmetic(op: string, a: KValue, b: KValue): KValue {
  if (op === "+" && typeof a === "string" && typeof b === "string") return a + b;
  const x = numeric(a, op);
  const y = numeric(b, op);
  if (x instanceof KFloat || y instanceof KFloat) {
    const [p, q] = [Number(plain(x)), Number(plain(y))];
    switch (op) {
      case "+":
        return new KFloat(p + q);
      case "-":
        return new KFloat(p - q);
      case "*":
        return new KFloat(p * q);
      case "/":
        return new KFloat(p / q);
      case "%":
        return new KFloat(p - q * Math.floor(p / q));
      default:
        return fail(`${op} needs integers, got ${show(a)} and ${show(b)}`);
    }
  }
  if (typeof x === "number" && typeof y === "number") {
    const fast = op === "+" ? x + y : op === "-" ? x - y : op === "*" ? x * y : NaN;
    if (Number.isSafeInteger(fast)) return fast;
  }
  const X = BigInt(x);
  const Y = BigInt(y);
  switch (op) {
    case "+":
      return toSafe(X + Y);
    case "-":
      return toSafe(X - Y);
    case "*":
      return toSafe(X * Y);
    case "/": {
      if (Y === 0n) fail("Division by zero");
      const quotient = X / Y;
      // Integer division floors, as in Kaitai (and Python).
      return toSafe(X % Y !== 0n && X < 0n !== Y < 0n ? quotient - 1n : quotient);
    }
    case "%": {
      if (Y === 0n) fail("Modulo by zero");
      const remainder = X % Y;
      return toSafe(remainder !== 0n && remainder < 0n !== Y < 0n ? remainder + Y : remainder);
    }
    case "&":
      return toSafe(X & Y);
    case "|":
      return toSafe(X | Y);
    case "^":
      return toSafe(X ^ Y);
    case "<<":
      if (Y < 0n || Y > 1024n) fail(`Shift by ${Y} is out of range`);
      return toSafe(X << Y);
    case ">>":
      if (Y < 0n || Y > 1024n) fail(`Shift by ${Y} is out of range`);
      return toSafe(X >> Y);
  }
  return fail(`Unknown operator ${op}`);
}

function latin1(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return out;
}

export const CP437_HIGH =
  "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0";

export const normaliseEncoding = (encoding: string) => {
  const label = encoding.trim().toLowerCase().replace(/_/g, "-");
  if (["ascii", "us-ascii", "iso-8859-1", "iso8859-1", "latin1", "latin-1"].includes(label)) return "latin1";
  if (label === "cp437" || label === "ibm437") return "cp437";
  if (label === "sjis" || label === "shift-jis") return "shift_jis";
  if (label === "utf8") return "utf-8";
  return label;
};

export function decodeString(bytes: Uint8Array, encoding: string): string {
  const label = normaliseEncoding(encoding);
  if (label === "latin1") return latin1(bytes);
  if (label === "cp437") return Array.from(bytes, (b) => (b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80])).join("");
  let decoder: TextDecoder;
  try {
    decoder = new TextDecoder(label);
  } catch {
    return fail(`Unknown encoding "${encoding}"`);
  }
  return decoder.decode(bytes);
}

function member(ctx: Context, object: KValue, name: string): Promise<KValue> | KValue {
  if (object instanceof KStruct) {
    if (name === "_parent") return object.parent ?? fail("The root type has no _parent");
    if (name === "_root") return object.root;
    if (name === "_io") return object.io;
    return field(ctx, object, name);
  }
  if (object instanceof KStream) {
    if (name === "size") return object.size;
    if (name === "pos") return object.pos;
    if (name === "eof") return object.eof;
  } else if (object instanceof Uint8Array || Array.isArray(object)) {
    const items: ArrayLike<KValue> = object;
    if (name === "size" || name === "length") return items.length;
    if (name === "first" || name === "last") {
      if (items.length === 0) fail(`.${name} of an empty ${kind(object)}`);
      return items[name === "first" ? 0 : items.length - 1];
    }
    if (name === "min" || name === "max") {
      if (items.length === 0) fail(`.${name} of an empty ${kind(object)}`);
      let best = items[0];
      for (let i = 1; i < items.length; i++) if (compare(name === "min" ? "<" : ">", items[i], best)) best = items[i];
      return best;
    }
  } else if (typeof object === "string") {
    if (name === "length") return [...object].length;
    if (name === "reverse") return [...object].reverse().join("");
    if (name === "to_i") return stringToInt(object, 10);
  } else if (typeof object === "number" || typeof object === "bigint") {
    if (name === "to_s") return object.toString();
    if (name === "to_i") return object;
  } else if (object instanceof KFloat) {
    if (name === "to_i") return Number.isFinite(object.value) ? toSafe(BigInt(Math.trunc(object.value))) : fail(`${object.value} has no integer value`);
  } else if (typeof object === "boolean") {
    if (name === "to_i") return object ? 1 : 0;
  } else if (object instanceof EnumValue) {
    if (name === "to_i") return object.value;
  }
  return fail(`${kind(object)} has no property .${name}`);
}

function stringToInt(text: string, radix: number): number | bigint {
  const digits = "0123456789abcdefghijklmnopqrstuvwxyz".slice(0, radix);
  const match = new RegExp(`^([+-]?)([${digits}]+)$`, "i").exec(text.trim());
  if (!match) return fail(`"${text}" is not a base-${radix} integer`);
  let value = 0n;
  for (const digit of match[2].toLowerCase()) value = value * BigInt(radix) + BigInt(digits.indexOf(digit));
  return toSafe(match[1] === "-" ? -value : value);
}

function call(object: KValue, name: string, args: KValue[]): KValue {
  if (object instanceof Uint8Array && name === "to_s" && args.length === 1 && typeof args[0] === "string") return decodeString(object, args[0]);
  if (typeof object === "string" && name === "to_i" && args.length <= 1) {
    const radix = args.length ? toInt(args[0], "to_i radix") : 10;
    if (radix < 2 || radix > 36) fail(`Radix ${radix} is out of range`);
    return stringToInt(object, radix);
  }
  if (typeof object === "string" && name === "substring" && args.length === 2) {
    const chars = [...object];
    return chars.slice(toInt(args[0], "substring start"), toInt(args[1], "substring end")).join("");
  }
  return fail(`${kind(object)} has no method .${name}(${args.length} argument(s))`);
}

async function evaluate(ctx: Context, expr: Expr, scope: Scope): Promise<KValue> {
  switch (expr.kind) {
    case "int":
    case "str":
    case "bool":
      return expr.value;
    case "float":
      return new KFloat(expr.value);
    case "name":
      switch (expr.name) {
        case "_root":
          return scope.struct.root;
        case "_parent":
          return scope.struct.parent ?? fail("The root type has no _parent");
        case "_io":
          return scope.struct.io;
        case "_index":
          return scope.index ?? fail("_index is only available inside a repeated field");
        case "_":
          return scope.last ? scope.last.value : fail("_ is only available in repeat-until and valid");
      }
      return field(ctx, scope.struct, expr.name);
    case "enum": {
      const def = resolveEnum(expr.enumPath, scope.struct.type) ?? fail(`Unknown enum ${expr.enumPath}`);
      return new EnumValue(def, def.values.get(expr.label) ?? fail(`Enum ${expr.enumPath} has no label ${expr.label}`));
    }
    case "unary": {
      const operand = await evaluate(ctx, expr.operand, scope);
      if (expr.op === "not") return !asBool(operand, "not");
      const value = numeric(operand, expr.op);
      if (value instanceof KFloat) {
        if (expr.op === "-") return new KFloat(-value.value);
        return fail(`~ needs an integer, got ${show(operand)}`);
      }
      if (expr.op === "-") return typeof value === "bigint" ? toSafe(-value) : -value;
      return toSafe(~BigInt(value));
    }
    case "binary": {
      const left = await evaluate(ctx, expr.left, scope);
      if (expr.op === "and" || expr.op === "or") {
        const first = asBool(left, expr.op);
        if (expr.op === "and" ? !first : first) return first;
        return asBool(await evaluate(ctx, expr.right, scope), expr.op);
      }
      const right = await evaluate(ctx, expr.right, scope);
      switch (expr.op) {
        case "==":
          return equals(left, right);
        case "!=":
          return !equals(left, right);
        case "<":
        case "<=":
        case ">":
        case ">=":
          return compare(expr.op, left, right);
        default:
          return arithmetic(expr.op, left, right);
      }
    }
    case "ternary":
      return asBool(await evaluate(ctx, expr.condition, scope), "The ?: condition")
        ? evaluate(ctx, expr.then, scope)
        : evaluate(ctx, expr.otherwise, scope);
    case "member":
      return member(ctx, await evaluate(ctx, expr.object, scope), expr.name);
    case "call": {
      const object = await evaluate(ctx, expr.object, scope);
      const args: KValue[] = [];
      for (const arg of expr.args) args.push(await evaluate(ctx, arg, scope));
      if (args.length === 0) return member(ctx, object, expr.name);
      return call(object, expr.name, args);
    }
    case "index": {
      const object = await evaluate(ctx, expr.object, scope);
      const index = toInt(await evaluate(ctx, expr.index, scope), "Index");
      if (!(object instanceof Uint8Array) && !Array.isArray(object)) return fail(`Cannot index ${kind(object)}`);
      if (index < 0 || index >= object.length) fail(`Index ${index} is out of range (length ${object.length})`);
      return object[index];
    }
    case "array": {
      const items: KValue[] = [];
      for (const item of expr.items) items.push(await evaluate(ctx, item, scope));
      return items;
    }
  }
}

/** A field, raw substream or instance of a struct, by name. */
async function field(ctx: Context, struct: KStruct, name: string): Promise<KValue> {
  if (struct.values.has(name)) return struct.values.get(name)!;
  if (name.startsWith("_raw_") && struct.raw.has(name.slice(5))) return struct.raw.get(name.slice(5))!;
  const instance = struct.type.instances.get(name);
  if (instance) return evaluateInstance(ctx, struct, name, instance);
  if (struct.type.seq.some((attr) => attr.id === name)) return fail(`"${name}" is used before it is parsed`);
  return fail(`${struct.type.name} has no field "${name}"`);
}

// ---------------------------------------------------------------------------------------------
// Reading

function describe(node: FieldNode, value: KValue): void {
  if (typeof value === "number" || typeof value === "bigint") {
    node.value = typeof value === "bigint" ? value.toString() : value;
    node.display = show(value);
  } else if (value instanceof KFloat) {
    node.value = Number.isFinite(value.value) ? value.value : String(value.value);
    node.display = String(value.value);
  } else if (value instanceof EnumValue) {
    node.value = typeof value.value === "bigint" ? value.value.toString() : value.value;
    if (value.label) node.label = value.label;
    node.display = value.label ? `${value.label} (${hex(value.value)})` : `${hex(value.value)} (not in ${value.def.name})`;
  } else if (typeof value === "string") {
    node.value = value.length > 2000 ? `${value.slice(0, 2000)}…` : value;
    node.display = JSON.stringify(value.length > 200 ? `${value.slice(0, 200)}…` : value);
  } else if (typeof value === "boolean") {
    node.value = value;
    node.display = String(value);
  } else if (value instanceof Uint8Array) {
    node.value = hexBytes(value, 256);
    node.display = value.length === 0 ? "(empty)" : `${hexBytes(value, 16)}${value.length > 16 ? ` (${value.length.toLocaleString()} bytes)` : ""}`;
  } else if (Array.isArray(value)) {
    node.display = `${value.length.toLocaleString()} item(s)`;
  } else if (value instanceof KStruct) {
    node.display = value.type.name;
  } else if (value === null) {
    node.display = "(absent)";
  }
}

function checksum(algorithm: ChecksumAlgorithm, bytes: Uint8Array): number {
  switch (algorithm) {
    case "crc32":
      return crc32(bytes);
    case "adler32": {
      let a = 1;
      let b = 0;
      for (let i = 0; i < bytes.length; i += 4096) {
        for (const byte of bytes.subarray(i, i + 4096)) {
          a += byte;
          b += a;
        }
        a %= 65521;
        b %= 65521;
      }
      return ((b << 16) | a) >>> 0;
    }
    case "sum8":
      return bytes.reduce((sum, byte) => (sum + byte) & 0xff, 0);
    case "xor8":
      return bytes.reduce((sum, byte) => sum ^ byte, 0);
  }
}

async function validate(ctx: Context, attr: AttrDef, value: KValue, scope: Scope, offset: number | null): Promise<void> {
  const valid = attr.valid!;
  const check = (ok: boolean, expected: string, exact?: KValue) => {
    if (!ok) {
      const plain = exact instanceof EnumValue ? exact.value : exact;
      const fix = typeof plain === "number" || typeof plain === "bigint" ? plain.toString() : undefined;
      throw new KsyParseError(`Validation failed: ${attr.id} is ${show(value)}, expected ${expected}`, offset, fix);
    }
  };
  if (valid.eq) {
    const expected = await evaluate(ctx, valid.eq, scope);
    check(equals(value, expected), show(expected), expected);
  }
  if (valid.min) {
    const min = await evaluate(ctx, valid.min, scope);
    check(compare(">=", value, min), `at least ${show(min)}`);
  }
  if (valid.max) {
    const max = await evaluate(ctx, valid.max, scope);
    check(compare("<=", value, max), `at most ${show(max)}`);
  }
  if (valid.anyOf) {
    const options: KValue[] = [];
    for (const option of valid.anyOf) options.push(await evaluate(ctx, option, scope));
    check(options.some((option) => equals(value, option)), `one of ${options.map(show).join(", ")}`);
  }
  if (valid.expr) {
    check(asBool(await evaluate(ctx, valid.expr, { ...scope, last: { value } }), "valid expr"), "to satisfy its valid expression");
  }
}

/** Common tail for primitive fields: enum, validation, checksum check, reporting. */
async function finish(
  ctx: Context,
  struct: KStruct,
  attr: AttrDef,
  io: KStream,
  node: FieldNode,
  path: string,
  scope: Scope,
  raw: KValue,
  checksumRange: [number, number] | null,
): Promise<KValue> {
  let value = raw;
  const enumDef = attr.enumName && (typeof raw === "number" || typeof raw === "bigint") ? resolveEnum(attr.enumName, struct.type) : null;
  if (enumDef) value = new EnumValue(enumDef, raw as number | bigint);
  describe(node, value);
  if (attr.valid) await validate(ctx, attr, value, scope, node.offset);
  if (checksumRange && attr.checksum) {
    const [from, to] = checksumRange;
    if (from < 0 || to > io.size || from > to) fail(`-checksum range ${from}..${to} is outside the stream (size ${io.size})`);
    const computed = checksum(attr.checksum.algorithm, io.bytes.subarray(from, to));
    node.checksum = {
      algorithm: attr.checksum.algorithm,
      computed,
      ok: equals(raw, computed),
      range: io.base === null ? null : { offset: io.base + from, length: to - from },
    };
  }
  ctx.options.onField?.(path, node, enumDef);
  return value;
}

async function chooseType(ctx: Context, attr: AttrDef, scope: Scope): Promise<string | null> {
  const type = attr.type;
  if (!type) return null;
  if (type.kind === "name") return type.name;
  const on = await evaluate(ctx, type.on, scope);
  let fallback: string | null = null;
  for (const item of type.cases) {
    if (item.key === null) fallback = item.type;
    else if (equals(on, await evaluate(ctx, item.key, scope))) return item.type;
  }
  return fallback;
}

async function processBytes(ctx: Context, attr: AttrDef, data: Uint8Array, scope: Scope): Promise<Uint8Array> {
  const process = attr.process!;
  if (process.name === "zlib") {
    try {
      const result = await inflate(new MemorySource(new Uint8Array(data)), "zlib", { maxOutputBytes: MAX_INFLATE, signal: ctx.options.signal });
      if (result.error) fail(`zlib: ${result.error}`);
      return result.bytes;
    } catch (error) {
      if (error instanceof KsyParseError || ctx.options.signal?.aborted) throw error;
      return fail(`zlib: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const arg = await evaluate(ctx, process.args[0], scope);
  if (process.name === "xor") {
    const key = arg instanceof Uint8Array ? arg : Uint8Array.of(toInt(arg, "xor key") & 0xff);
    if (key.length === 0) fail("xor key is empty");
    return data.map((byte, i) => byte ^ key[i % key.length]);
  }
  const amount = toInt(arg, `${process.name} amount`) & 7;
  const left = process.name === "rol" ? amount : (8 - amount) & 7;
  return data.map((byte) => ((byte << left) | (byte >> (8 - left))) & 0xff);
}

function endianOf(endian: "le" | "be" | undefined, meta: Meta): boolean {
  return (endian ?? meta.endian) === "le";
}

/** Reads one value of an attribute (one element, for repeated attributes). */
async function readOne(ctx: Context, struct: KStruct, attr: AttrDef, io: KStream, node: FieldNode, path: string, scope: Scope): Promise<KValue> {
  const typeName = await chooseType(ctx, attr, scope);
  const prim = typeName ? primitive(typeName) : null;
  const meta = struct.type.meta;
  // Evaluated before reading, so `_io.pos` refers to where the checksum field starts.
  const checksumRange: [number, number] | null = attr.checksum
    ? [toInt(await evaluate(ctx, attr.checksum.start, scope), "-checksum start"), toInt(await evaluate(ctx, attr.checksum.end, scope), "-checksum end")]
    : null;

  if (prim?.kind === "bits") {
    const startByte = Math.floor(io.bitPos / 8);
    const le = (prim.endian ?? meta.bitEndian) === "le";
    const bits = io.readBits(prim.width, le);
    node.type = `b${prim.width}${prim.endian ?? ""}`;
    node.offset = io.abs(startByte);
    node.length = Math.max(1, io.pos - startByte);
    return finish(ctx, struct, attr, io, node, path, scope, prim.width === 1 ? bits === 1n : toSafe(bits), checksumRange);
  }

  io.alignToByte();
  const start = io.pos;
  node.offset = io.abs(start);

  if (attr.contents) {
    node.type = "contents";
    node.length = attr.contents.length;
    if (io.base !== null) node.encoding = { kind: "bytes" };
    const actual = io.read(Math.min(attr.contents.length, io.size - io.pos));
    describe(node, actual);
    if (!bytesEqual(actual, attr.contents)) {
      throw new KsyParseError(`Expected ${hexBytes(attr.contents, 32)}, found ${actual.length ? hexBytes(actual, 32) : "end of data"}`, io.abs(start), hexBytes(attr.contents));
    }
    return finish(ctx, struct, attr, io, node, path, scope, actual, checksumRange);
  }

  if (prim?.kind === "int") {
    const le = endianOf(prim.endian, meta);
    node.type = prim.width === 1 ? typeName! : `${prim.signed ? "s" : "u"}${prim.width}${le ? "le" : "be"}`;
    node.length = prim.width;
    if (io.base !== null) node.encoding = { kind: "int", width: prim.width, signed: prim.signed, le };
    return finish(ctx, struct, attr, io, node, path, scope, io.readInt(prim.width, prim.signed, le), checksumRange);
  }
  if (prim?.kind === "float") {
    const le = endianOf(prim.endian, meta);
    node.type = `f${prim.width}${le ? "le" : "be"}`;
    node.length = prim.width;
    if (io.base !== null) node.encoding = { kind: "float", width: prim.width, le };
    return finish(ctx, struct, attr, io, node, path, scope, io.readFloat(prim.width, le), checksumRange);
  }

  const sized = attr.size !== undefined || attr.sizeEos;
  const terminator = attr.terminator ?? (prim?.kind === "str" && prim.zero ? 0 : undefined);
  let data: Uint8Array | null = null;
  if (sized) {
    const size = attr.sizeEos ? io.size - io.pos : toInt(await evaluate(ctx, attr.size!, scope), "size");
    if (size < 0) fail(`size is negative (${size})`);
    data = io.read(size);
    if (attr.padRight !== undefined) {
      let end = data.length;
      while (end > 0 && data[end - 1] === attr.padRight) end--;
      data = data.subarray(0, end);
    }
    if (terminator !== undefined) {
      const end = data.indexOf(terminator);
      if (end >= 0) data = data.subarray(0, attr.include ? end + 1 : end);
    }
  } else if (terminator !== undefined) {
    data = io.readTerminated(terminator, attr.include, attr.consume, attr.eosError);
  }

  const userType = typeName && !prim ? resolveType(typeName, struct.type) : null;
  if (data === null) {
    if (!userType) {
      // A switch with no matching case and no size reads nothing, as in Kaitai.
      node.type = "none";
      node.display = "(no matching case)";
      return null;
    }
    node.type = typeName!;
    try {
      return await parseStruct(ctx, userType, io, struct, path, node);
    } finally {
      node.length = io.pos - start;
    }
  }

  node.length = io.pos - start;
  let base = io.abs(start);
  if (attr.process) {
    struct.raw.set(attr.id, data);
    data = await processBytes(ctx, attr, data, scope);
    base = null;
  }
  if (userType) {
    if (!attr.process) struct.raw.set(attr.id, data);
    node.type = attr.process ? `${typeName} (${attr.process.name})` : typeName!;
    return parseStruct(ctx, userType, new KStream(data, base), struct, path, node);
  }
  if (prim?.kind === "str") {
    const encoding = attr.encoding ?? meta.encoding!;
    node.type = prim.zero ? "strz" : "str";
    if (base !== null) node.encoding = { kind: "str", encoding, pad: attr.padRight ?? terminator ?? null, terminated: terminator !== undefined && !sized };
    return finish(ctx, struct, attr, io, node, path, scope, decodeString(data, encoding), checksumRange);
  }
  node.type = attr.process ? `bytes (${attr.process.name})` : "bytes";
  if (base !== null) node.encoding = { kind: "bytes" };
  return finish(ctx, struct, attr, io, node, path, scope, data, checksumRange);
}

/** Reads an attribute, repeated or not, into `node`. */
async function readAttr(ctx: Context, struct: KStruct, attr: AttrDef, io: KStream, node: FieldNode, path: string, scope: Scope): Promise<KValue> {
  if (!attr.repeat) {
    try {
      return await readOne(ctx, struct, attr, io, node, path, scope);
    } catch (error) {
      annotate(error, path, node, io.abs());
      throw error;
    }
  }
  const start = Math.floor(io.bitPos / 8);
  const items: KValue[] = [];
  node.offset = io.abs(start);
  node.children = [];
  node.count = 0;
  let elementType = "";
  const readItem = async (index: number): Promise<KValue> => {
    await ctx.tick();
    const itemPath = `${path}[${index}]`;
    const item = newNode(`[${index}]`, null);
    if (index < ctx.maxArrayChildren && ctx.keep()) node.children!.push(item);
    try {
      const value = await readOne(ctx, struct, attr, io, item, itemPath, { struct, index });
      items.push(value);
      elementType ||= item.type;
      return value;
    } catch (error) {
      annotate(error, itemPath, item, io.abs());
      throw error;
    }
  };
  try {
    if (attr.repeat === "expr") {
      const count = toInt(await evaluate(ctx, attr.repeatExpr!, scope), "repeat-expr");
      if (count < 0 || count > MAX_REPEAT) fail(`repeat-expr is ${count}; the limit is ${MAX_REPEAT.toLocaleString()}`);
      for (let index = 0; index < count; index++) await readItem(index);
    } else if (attr.repeat === "eos") {
      for (let index = 0; !io.eof; index++) {
        const before = io.bitPos;
        await readItem(index);
        if (io.bitPos === before) fail(`repeat: eos stopped making progress at ${io.where()}`);
      }
    } else {
      for (let index = 0; ; index++) {
        const value = await readItem(index);
        if (asBool(await evaluate(ctx, attr.repeatUntil!, { struct, index, last: { value } }), "repeat-until")) break;
      }
    }
  } catch (error) {
    annotate(error, path, node, io.abs());
    throw error;
  } finally {
    node.count = items.length;
    node.length = io.pos - start;
    node.type = `${elementType || (attr.type?.kind === "name" ? attr.type.name : "bytes")}[]`;
    node.display = `${items.length.toLocaleString()} item(s)`;
  }
  return items;
}

async function parseStruct(ctx: Context, type: TypeDef, io: KStream, parent: KStruct | null, path: string, node: FieldNode): Promise<KStruct> {
  const depth = (parent?.depth ?? -1) + 1;
  if (depth > MAX_DEPTH) fail(`Types nest more than ${MAX_DEPTH} levels deep (a recursive structure?)`);
  const struct = new KStruct(type, io, parent, node, path, depth);
  ctx.structs.push(struct);
  node.display ??= type.name;
  for (const attr of type.seq) {
    const attrPath = joinPath(path, attr.id);
    const scope: Scope = { struct };
    try {
      if (attr.if && !asBool(await evaluate(ctx, attr.if, scope), "if")) {
        struct.values.set(attr.id, null);
        continue;
      }
    } catch (error) {
      annotate(error, attrPath, null, io.abs());
      throw error;
    }
    const child = newNode(attr.id, attr);
    if (ctx.keep()) struct.seqNodes.push(child);
    struct.values.set(attr.id, await readAttr(ctx, struct, attr, io, child, attrPath, scope));
  }
  return struct;
}

async function evaluateInstance(ctx: Context, struct: KStruct, name: string, attr: AttrDef): Promise<KValue> {
  const state = struct.instanceState.get(name);
  if (state?.pending) fail(`Instance "${name}" depends on itself`);
  if (state?.failed) throw state.failed;
  if (state) return struct.values.get(name) ?? null;
  struct.instanceState.set(name, { pending: true });
  const path = joinPath(struct.path, name);
  const node: FieldNode = { ...newNode(name, attr), instance: true };
  if (ctx.keep()) struct.instanceNodes.set(name, node);
  const scope: Scope = { struct };
  try {
    let value: KValue = null;
    if (attr.if && !asBool(await evaluate(ctx, attr.if, scope), "if")) {
      node.type = "absent";
      node.display = "(if is false)";
    } else if (attr.value) {
      value = await evaluate(ctx, attr.value, scope);
      const enumDef = attr.enumName && (typeof value === "number" || typeof value === "bigint") ? resolveEnum(attr.enumName, struct.type) : null;
      if (enumDef) value = new EnumValue(enumDef, value as number | bigint);
      node.type = "value";
      describe(node, value);
    } else {
      const io = attr.io ? await evaluate(ctx, attr.io, scope) : struct.io;
      if (!(io instanceof KStream)) fail(`io must be a stream (like _root._io), got ${kind(io)}`);
      const stream = io as KStream;
      const saved = stream.save();
      try {
        if (attr.pos) stream.seek(toInt(await evaluate(ctx, attr.pos, scope), "pos"));
        value = await readAttr(ctx, struct, attr, stream, node, path, scope);
      } finally {
        stream.restore(saved);
      }
    }
    struct.values.set(name, value);
    struct.instanceState.set(name, {});
    return value;
  } catch (error) {
    annotate(error, path, node, null);
    struct.instanceState.set(name, { failed: error });
    throw error;
  }
}

export async function parseKsy(schema: KsySchema, bytes: Uint8Array, options: ParseOptions = {}): Promise<ParseResult> {
  const ctx = new Context(options);
  const io = new KStream(bytes, 0);
  const root: FieldNode = { name: schema.id, type: schema.id, offset: 0, length: 0 };
  let error: KsyParseError | undefined;
  try {
    await parseStruct(ctx, schema.root, io, null, "", root);
  } catch (caught) {
    if (!(caught instanceof KsyParseError)) throw caught;
    error = caught;
  }
  const parsedBytes = io.pos;
  // Instances not needed during the main parse are evaluated now, as a lazy reader would on access.
  for (let i = 0; i < ctx.structs.length; i++) {
    const struct = ctx.structs[i];
    for (const [name, attr] of struct.type.instances) {
      if (struct.instanceState.has(name)) continue;
      try {
        await ctx.tick();
        await evaluateInstance(ctx, struct, name, attr);
      } catch (caught) {
        if (!(caught instanceof KsyParseError)) throw caught;
        ctx.instanceErrors.push(caught);
      }
    }
  }
  for (const struct of ctx.structs) {
    const instances = [...struct.type.instances.keys()].flatMap((name) => struct.instanceNodes.get(name) ?? []);
    struct.node.children = [...struct.seqNodes, ...instances];
  }
  root.length = parsedBytes;
  return { root, error, parsedBytes, truncated: ctx.truncated, instanceErrors: ctx.instanceErrors };
}
