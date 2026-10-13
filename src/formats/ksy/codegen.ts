import type { Expr } from "./expr";
import { loadKsy, primitive, resolveEnum, resolveType, type AttrDef, type EnumDef, type KsySchema, type TypeDef } from "./schema";

/** Compiles a schema to a standalone parser (Python 3 or an ES module), the export counterpart of the interpreter. */

export type Language = "python" | "javascript";

const PY_KEYWORDS = new Set(
  "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield".split(" "),
);

const camel = (name: string) => name.replace(/(^|_)([a-z0-9])/g, (_m, _sep, c: string) => c.toUpperCase()).replace(/^[0-9]/, "_$&");

const PY_RUNTIME = String.raw`import struct
import sys
import zlib
from enum import IntEnum


class ParseError(Exception):
    pass


class Stream:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)
        self.pos = 0
        self.bits = 0
        self.bits_left = 0

    @property
    def eof(self):
        return self.bits_left == 0 and self.pos >= self.size

    def save(self):
        return (self.pos, self.bits, self.bits_left)

    def restore(self, state):
        self.pos, self.bits, self.bits_left = state

    def align(self):
        self.bits = 0
        self.bits_left = 0

    def seek(self, pos):
        if pos < 0 or pos > self.size:
            raise ParseError(f"position {pos} is outside the stream ({self.size} bytes)")
        self.pos = pos
        self.align()

    def take(self, n):
        if n < 0 or self.pos + n > self.size:
            raise ParseError(f"needed {n} byte(s) at {self.pos:#x}, but only {self.size - self.pos} remain")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def read_bytes(self, n):
        self.align()
        return self.take(n)

    def read_full(self):
        return self.read_bytes(self.size - self.pos)

    def read_term(self, term, include, consume, eos_error):
        self.align()
        end = self.data.find(bytes([term]), self.pos)
        if end < 0:
            if eos_error:
                raise ParseError(f"no terminator {term:#x} after {self.pos:#x}")
            out = self.data[self.pos:]
            self.pos = self.size
            return out
        out = self.data[self.pos:end + 1 if include else end]
        self.pos = end + 1 if consume else end
        return out

    def ensure(self, expected):
        self.align()
        start = self.pos
        actual = self.take(min(len(expected), self.size - self.pos))
        if actual != expected:
            raise ParseError(f"expected {expected.hex(' ')} at {start:#x}, found {actual.hex(' ') or 'end of data'}")
        return actual

    def read_int(self, n, signed, le):
        return int.from_bytes(self.read_bytes(n), "little" if le else "big", signed=signed)

    def read_float(self, n, le):
        return struct.unpack(("<" if le else ">") + ("f" if n == 4 else "d"), self.read_bytes(n))[0]

    def read_bits(self, n, le):
        needed = n - self.bits_left
        if le:
            if needed > 0:
                result = int.from_bytes(self.take((needed + 7) // 8), "little")
                fresh = result >> needed
                result = (result << self.bits_left) | self.bits
                self.bits = fresh
            else:
                result = self.bits
                self.bits >>= n
            self.bits_left = -needed & 7
            return result & ((1 << n) - 1)
        self.bits_left = -needed & 7
        if needed > 0:
            result = int.from_bytes(self.take((needed + 7) // 8), "big")
            fresh = result
            result = (result >> self.bits_left) | (self.bits << needed)
            self.bits = fresh
        else:
            result = self.bits >> -needed
        self.bits &= (1 << self.bits_left) - 1
        return result


class Struct:
    SEQ = ()
    INSTANCES = ()

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root is not None else self
        if _root is None:
            self.checksum_errors = []
        self._read()

    def _read(self):
        pass


def _fail(message):
    raise ParseError(message)


def _div(a, b):
    return a // b if isinstance(a, int) and isinstance(b, int) else a / b


def _decode(data, encoding):
    label = encoding.strip().lower().replace("_", "-")
    if label in ("ascii", "us-ascii", "iso-8859-1", "iso8859-1", "latin1", "latin-1"):
        return data.decode("latin-1")
    if label in ("sjis", "shift-jis"):
        label = "shift_jis"
    return data.decode(label, errors="replace")


def _strip(data, pad):
    end = len(data)
    while end > 0 and data[end - 1] == pad:
        end -= 1
    return data[:end]


def _terminate(data, term, include):
    end = data.find(bytes([term]))
    return data if end < 0 else data[:end + 1 if include else end]


def _enum(cls, value):
    try:
        return cls(value)
    except ValueError:
        return value


def _p(obj, name):
    if isinstance(obj, (Struct, Stream)):
        return getattr(obj, name)
    if isinstance(obj, (bytes, list, str)):
        if name in ("size", "length"):
            return len(obj)
        if name == "first":
            return obj[0]
        if name == "last":
            return obj[-1]
        if name == "min":
            return min(obj)
        if name == "max":
            return max(obj)
        if name == "reverse" and isinstance(obj, str):
            return obj[::-1]
        if name == "to_i" and isinstance(obj, str):
            return int(obj, 10)
    if name == "to_i":
        return int(obj)
    if name == "to_s":
        return str(obj)
    raise ParseError(f"{type(obj).__name__} has no property .{name}")


def _call(obj, name, args):
    if name == "to_s" and isinstance(obj, bytes):
        return _decode(obj, args[0])
    if name == "to_i" and isinstance(obj, str):
        return int(obj, args[0])
    if name == "substring" and isinstance(obj, str):
        return obj[args[0]:args[1]]
    raise ParseError(f"{type(obj).__name__} has no method .{name}()")


def _process(name, data, arg=None):
    if name == "zlib":
        return zlib.decompress(data)
    if name == "xor":
        key = bytes([arg & 0xFF]) if isinstance(arg, int) else arg
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    amount = (arg if name == "rol" else 8 - arg) & 7
    return bytes(((b << amount) | (b >> (8 - amount))) & 0xFF for b in data)


def _checksum(algorithm, data):
    if algorithm == "crc32":
        return zlib.crc32(data) & 0xFFFFFFFF
    if algorithm == "adler32":
        return zlib.adler32(data) & 0xFFFFFFFF
    if algorithm == "sum8":
        return sum(data) & 0xFF
    result = 0
    for b in data:
        result ^= b
    return result


def _check(obj, name, stored, algorithm, data):
    computed = _checksum(algorithm, data)
    if stored != computed:
        obj._root.checksum_errors.append(f"{type(obj).__name__}.{name}: stored {stored:#x}, {algorithm} is {computed:#x}")


def dump(obj, name=None, indent=0, out=print):
    """Prints a parsed structure as an indented tree."""
    pad = "  " * indent
    label = f"{name}: " if name is not None else ""
    if isinstance(obj, Struct):
        out(f"{pad}{label}{type(obj).__name__}")
        for field in type(obj).SEQ + type(obj).INSTANCES:
            try:
                value = getattr(obj, field)
            except ParseError as error:
                out(f"{pad}  {field}: <{error}>")
                continue
            dump(value, field, indent + 1, out)
    elif isinstance(obj, list):
        out(f"{pad}{label}{len(obj)} item(s)")
        for index, item in enumerate(obj[:200]):
            dump(item, f"[{index}]", indent + 1, out)
        if len(obj) > 200:
            out(f"{pad}  ...")
    elif isinstance(obj, bytes):
        out(f"{pad}{label}{obj[:32].hex(' ')}{' ...' if len(obj) > 32 else ''} ({len(obj)} bytes)")
    elif isinstance(obj, IntEnum):
        out(f"{pad}{label}{obj.name} ({int(obj):#x})")
    elif isinstance(obj, bool) or obj is None:
        out(f"{pad}{label}{obj}")
    elif isinstance(obj, int):
        out(f"{pad}{label}{obj} ({obj:#x})")
    else:
        out(f"{pad}{label}{obj!r}")
`;

const JS_RUNTIME = String.raw`export class ParseError extends Error {}

const CP437 = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0";
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(" ");
let inflate = null;

/** zlib-processed fields need an inflater, e.g. under Node: setInflate((b) => zlib.inflateSync(b)). */
export function setInflate(fn) {
  inflate = fn;
}

export class Stream {
  constructor(bytes) {
    this.bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    this.size = this.bytes.length;
    this.pos = 0;
    this.bits = 0n;
    this.bitsLeft = 0;
  }
  get eof() {
    return this.bitsLeft === 0 && this.pos >= this.size;
  }
  save() {
    return [this.pos, this.bits, this.bitsLeft];
  }
  restore(state) {
    [this.pos, this.bits, this.bitsLeft] = state;
  }
  align() {
    this.bits = 0n;
    this.bitsLeft = 0;
  }
  seek(pos) {
    if (pos < 0 || pos > this.size) throw new ParseError("position " + pos + " is outside the stream (" + this.size + " bytes)");
    this.pos = pos;
    this.align();
  }
  take(n) {
    if (n < 0 || this.pos + n > this.size) throw new ParseError("needed " + n + " byte(s) at 0x" + this.pos.toString(16) + ", but only " + (this.size - this.pos) + " remain");
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  read_bytes(n) {
    this.align();
    return this.take(n);
  }
  read_full() {
    return this.read_bytes(this.size - this.pos);
  }
  read_term(term, include, consume, eosError) {
    this.align();
    const end = this.bytes.indexOf(term, this.pos);
    if (end < 0) {
      if (eosError) throw new ParseError("no terminator 0x" + term.toString(16) + " after 0x" + this.pos.toString(16));
      const out = this.bytes.subarray(this.pos);
      this.pos = this.size;
      return out;
    }
    const out = this.bytes.subarray(this.pos, include ? end + 1 : end);
    this.pos = consume ? end + 1 : end;
    return out;
  }
  ensure(expected) {
    this.align();
    const start = this.pos;
    const actual = this.take(Math.min(expected.length, this.size - this.pos));
    if (!_eq(actual, expected)) throw new ParseError("expected " + hex(expected) + " at 0x" + start.toString(16) + ", found " + (hex(actual) || "end of data"));
    return actual;
  }
  read_int(n, signed, le) {
    this.align();
    const at = this.pos;
    this.take(n);
    const v = this.view;
    if (n === 1) return signed ? v.getInt8(at) : v.getUint8(at);
    if (n === 2) return signed ? v.getInt16(at, le) : v.getUint16(at, le);
    if (n === 4) return signed ? v.getInt32(at, le) : v.getUint32(at, le);
    // Numbers above 2^53 lose precision, as in Kaitai's JavaScript runtime.
    return Number(signed ? v.getBigInt64(at, le) : v.getBigUint64(at, le));
  }
  read_float(n, le) {
    this.align();
    const at = this.pos;
    this.take(n);
    return n === 4 ? this.view.getFloat32(at, le) : this.view.getFloat64(at, le);
  }
  read_bits(n, le) {
    const needed = n - this.bitsLeft;
    let result = 0n;
    if (le) {
      if (needed > 0) {
        this.take(Math.ceil(needed / 8)).forEach((b, i) => (result |= BigInt(b) << BigInt(i * 8)));
        const fresh = result >> BigInt(needed);
        result = (result << BigInt(this.bitsLeft)) | this.bits;
        this.bits = fresh;
      } else {
        result = this.bits;
        this.bits >>= BigInt(n);
      }
      this.bitsLeft = -needed & 7;
      return Number(result & ((1n << BigInt(n)) - 1n));
    }
    this.bitsLeft = -needed & 7;
    if (needed > 0) {
      for (const b of this.take(Math.ceil(needed / 8))) result = (result << 8n) | BigInt(b);
      const fresh = result;
      result = (result >> BigInt(this.bitsLeft)) | (this.bits << BigInt(needed));
      this.bits = fresh;
    } else {
      result = this.bits >> BigInt(-needed);
    }
    this.bits &= (1n << BigInt(this.bitsLeft)) - 1n;
    return Number(result);
  }
}

export class Struct {
  constructor(_io, _parent = null, _root = null) {
    this._io = _io;
    this._parent = _parent;
    this._root = _root ?? this;
    if (_root === null) this.checksum_errors = [];
    this._read();
  }
  _read() {}
}

function _fail(message) {
  throw new ParseError(message);
}
function _hex(text) {
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}
function _eq(a, b) {
  if (a instanceof Uint8Array && b instanceof Uint8Array) return a.length === b.length && a.every((x, i) => x === b[i]);
  return a === b;
}
function _div(a, b) {
  return Number.isInteger(a) && Number.isInteger(b) ? Math.floor(a / b) : a / b;
}
function _mod(a, b) {
  const r = a % b;
  return r !== 0 && (r < 0) !== (b < 0) ? r + b : r;
}
function _bit(op, a, b) {
  const x = BigInt(a);
  const y = BigInt(b);
  return Number(op === "&" ? x & y : op === "|" ? x | y : op === "^" ? x ^ y : op === "<<" ? x << y : x >> y);
}
function _inv(a) {
  return Number(~BigInt(a));
}
function _decode(bytes, encoding) {
  const label = encoding.trim().toLowerCase().replace(/_/g, "-");
  if (["ascii", "us-ascii", "iso-8859-1", "iso8859-1", "latin1", "latin-1"].includes(label)) return Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  if (label === "cp437" || label === "ibm437") return Array.from(bytes, (b) => (b < 0x80 ? String.fromCharCode(b) : CP437[b - 0x80])).join("");
  return new TextDecoder(label === "sjis" ? "shift_jis" : label).decode(bytes);
}
function _strip(bytes, pad) {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === pad) end--;
  return bytes.subarray(0, end);
}
function _terminate(bytes, term, include) {
  const end = bytes.indexOf(term);
  return end < 0 ? bytes : bytes.subarray(0, include ? end + 1 : end);
}
function _p(obj, name) {
  if (obj instanceof Struct || obj instanceof Stream) return obj[name];
  if (obj instanceof Uint8Array || Array.isArray(obj) || typeof obj === "string") {
    if (name === "size" || name === "length") return typeof obj === "string" ? [...obj].length : obj.length;
    if (name === "first") return obj[0];
    if (name === "last") return obj[obj.length - 1];
    if (name === "min") return Math.min(...obj);
    if (name === "max") return Math.max(...obj);
    if (name === "reverse" && typeof obj === "string") return [...obj].reverse().join("");
    if (name === "to_i" && typeof obj === "string") return parseInt(obj, 10);
  }
  if (name === "to_i") return typeof obj === "boolean" ? Number(obj) : Math.trunc(obj);
  if (name === "to_s") return String(obj);
  throw new ParseError(typeof obj + " has no property ." + name);
}
function _call(obj, name, args) {
  if (name === "to_s" && obj instanceof Uint8Array) return _decode(obj, args[0]);
  if (name === "to_i" && typeof obj === "string") return parseInt(obj, args[0]);
  if (name === "substring" && typeof obj === "string") return [...obj].slice(args[0], args[1]).join("");
  throw new ParseError(typeof obj + " has no method ." + name + "()");
}
function _process(name, bytes, arg) {
  if (name === "zlib") {
    if (!inflate) throw new ParseError("zlib field: call setInflate() first");
    return new Uint8Array(inflate(bytes));
  }
  if (name === "xor") {
    const key = arg instanceof Uint8Array ? arg : Uint8Array.of(arg & 0xff);
    return bytes.map((b, i) => b ^ key[i % key.length]);
  }
  const amount = (name === "rol" ? arg : 8 - arg) & 7;
  return bytes.map((b) => ((b << amount) | (b >> (8 - amount))) & 0xff);
}
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function _checksum(algorithm, bytes) {
  if (algorithm === "crc32") {
    let crc = 0xffffffff;
    for (const b of bytes) crc = CRC_TABLE[(crc ^ b) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }
  if (algorithm === "adler32") {
    let a = 1;
    let b = 0;
    for (const x of bytes) {
      a = (a + x) % 65521;
      b = (b + a) % 65521;
    }
    return ((b << 16) | a) >>> 0;
  }
  if (algorithm === "sum8") return bytes.reduce((s, x) => (s + x) & 0xff, 0);
  return bytes.reduce((s, x) => s ^ x, 0);
}
function _check(obj, name, stored, algorithm, bytes) {
  const computed = _checksum(algorithm, bytes);
  if (stored !== computed) obj._root.checksum_errors.push(obj.constructor.name + "." + name + ": stored 0x" + stored.toString(16) + ", " + algorithm + " is 0x" + computed.toString(16));
}

/** Renders a parsed structure as an indented tree. */
export function dump(obj, name = null, indent = 0, labels = null) {
  const pad = "  ".repeat(indent);
  const label = name === null ? "" : name + ": ";
  if (obj instanceof Struct) {
    const type = obj.constructor;
    const lines = [pad + label + type.name];
    for (const field of [...type.SEQ, ...type.INSTANCES]) {
      let value;
      try {
        value = obj[field];
      } catch (error) {
        lines.push(pad + "  " + field + ": <" + error.message + ">");
        continue;
      }
      lines.push(dump(value, field, indent + 1, type.ENUMS[field] ?? null));
    }
    return lines.join("\n");
  }
  if (Array.isArray(obj)) {
    const lines = [pad + label + obj.length + " item(s)"];
    obj.slice(0, 200).forEach((item, index) => lines.push(dump(item, "[" + index + "]", indent + 1, labels)));
    if (obj.length > 200) lines.push(pad + "  ...");
    return lines.join("\n");
  }
  if (obj instanceof Uint8Array) return pad + label + hex(obj.subarray(0, 32)) + (obj.length > 32 ? " ..." : "") + " (" + obj.length + " bytes)";
  if (typeof obj === "number" && Number.isInteger(obj)) {
    const tag = labels ? Object.keys(labels).find((key) => labels[key] === obj) : undefined;
    return pad + label + (tag ? tag + " (0x" + obj.toString(16) + ")" : obj + (obj >= 0 ? " (0x" + obj.toString(16) + ")" : ""));
  }
  return pad + label + (typeof obj === "string" ? JSON.stringify(obj) : String(obj));
}
`;

interface Dialect {
  self: string;
  none: string;
  bool(value: boolean): string;
  float(value: number): string;
  bytes(value: Uint8Array): string;
  field(id: string): string;
  and(a: string, b: string): string;
  or(a: string, b: string): string;
  not(a: string): string;
  eq(a: string, b: string): string;
  mod(a: string, b: string): string;
  bit(op: string, a: string, b: string): string;
  inv(a: string): string;
  ternary(condition: string, then: string, otherwise: string): string;
  stmt(text: string): string;
  local(name: string, value: string): string;
  newObject(cls: string, args: string): string;
  push(list: string, item: string): string;
  ifHead(condition: string): string;
  elifHead(condition: string): string;
  forHead(variable: string, count: string): string;
  whileHead(condition: string): string;
  loopHead(): string;
  increment(variable: string): string;
  /** Python blocks end by dedenting; JavaScript blocks need a closing brace. */
  braces: boolean;
}

const hexOf = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const PYTHON: Dialect = {
  self: "self",
  none: "None",
  bool: (value) => (value ? "True" : "False"),
  float: (value) => (Number.isInteger(value) ? `${value}.0` : String(value)),
  bytes: (value) => `bytes.fromhex("${hexOf(value)}")`,
  field: (id) => (PY_KEYWORDS.has(id) ? `${id}_` : id),
  and: (a, b) => `(${a} and ${b})`,
  or: (a, b) => `(${a} or ${b})`,
  not: (a) => `(not ${a})`,
  eq: (a, b) => `(${a} == ${b})`,
  mod: (a, b) => `(${a} % ${b})`,
  bit: (op, a, b) => `(${a} ${op} ${b})`,
  inv: (a) => `(~${a})`,
  ternary: (condition, then, otherwise) => `(${then} if ${condition} else ${otherwise})`,
  stmt: (text) => text,
  local: (name, value) => `${name} = ${value}`,
  newObject: (cls, args) => `${cls}(${args})`,
  push: (list, item) => `${list}.append(${item})`,
  ifHead: (condition) => `if ${condition}`,
  elifHead: (condition) => `elif ${condition}`,
  forHead: (variable, count) => `for ${variable} in range(${count})`,
  whileHead: (condition) => `while ${condition}`,
  loopHead: () => "while True",
  increment: (variable) => `${variable} += 1`,
  braces: false,
};

const JAVASCRIPT: Dialect = {
  self: "this",
  none: "null",
  bool: (value) => String(value),
  float: (value) => String(value),
  bytes: (value) => `_hex("${hexOf(value)}")`,
  field: (id) => id,
  and: (a, b) => `(${a} && ${b})`,
  or: (a, b) => `(${a} || ${b})`,
  not: (a) => `(!${a})`,
  eq: (a, b) => `_eq(${a}, ${b})`,
  mod: (a, b) => `_mod(${a}, ${b})`,
  bit: (op, a, b) => `_bit("${op}", ${a}, ${b})`,
  inv: (a) => `_inv(${a})`,
  ternary: (condition, then, otherwise) => `(${condition} ? ${then} : ${otherwise})`,
  stmt: (text) => `${text};`,
  local: (name, value) => `${name} = ${value};`,
  newObject: (cls, args) => `new ${cls}(${args})`,
  push: (list, item) => `${list}.push(${item});`,
  ifHead: (condition) => `if (${condition})`,
  elifHead: (condition) => `else if (${condition})`,
  forHead: (variable, count) => `for (${variable} = 0; ${variable} < ${count}; ${variable}++)`,
  whileHead: (condition) => `while (${condition})`,
  loopHead: () => "for (;;)",
  increment: (variable) => `${variable}++;`,
  braces: true,
};

class Writer {
  private readonly lines: string[] = [];
  private depth = 0;

  constructor(private readonly dialect: Dialect) {}

  line(text: string): void {
    this.lines.push(text ? `${"    ".slice(0, this.dialect.braces ? 2 : 4).repeat(this.depth)}${text}` : "");
  }

  block(head: string, body: () => void): void {
    this.line(this.dialect.braces ? `${head} {` : `${head}:`);
    this.depth++;
    const before = this.lines.length;
    body();
    if (!this.dialect.braces && this.lines.length === before) this.line("pass");
    this.depth--;
    if (this.dialect.braces) this.line("}");
  }

  toString(): string {
    return this.lines.join("\n");
  }
}

interface Scope {
  type: TypeDef;
  index?: string;
  last?: string;
}

class Generator {
  private readonly classNames = new Map<TypeDef, string>();
  private readonly enumNames = new Map<EnumDef, string>();

  constructor(
    private readonly schema: KsySchema,
    private readonly d: Dialect,
  ) {
    const taken = new Set<string>(["Stream", "Struct", "ParseError", "IntEnum"]);
    const unique = (base: string, qualified: string) => {
      const name = taken.has(base) ? qualified : base;
      taken.add(name);
      return name;
    };
    const visit = (type: TypeDef, prefix: string) => {
      this.classNames.set(type, unique(camel(type.name), prefix + camel(type.name)));
      for (const def of type.enums.values()) this.enumNames.set(def, unique(camel(def.name), prefix + camel(type.name) + camel(def.name)));
      for (const child of type.types.values()) visit(child, prefix + camel(type.name));
    };
    visit(schema.root, "");
  }

  private className(name: string, from: TypeDef): string {
    return this.classNames.get(resolveType(name, from)!)!;
  }

  private enumName(name: string, from: TypeDef): string {
    return this.enumNames.get(resolveEnum(name, from)!)!;
  }

  private isFloat(expr: Expr, scope: Scope): boolean {
    switch (expr.kind) {
      case "float":
        return true;
      case "unary":
        return expr.op === "-" && this.isFloat(expr.operand, scope);
      case "binary":
        return ["+", "-", "*", "/", "%"].includes(expr.op) && (this.isFloat(expr.left, scope) || this.isFloat(expr.right, scope));
      case "name": {
        const attr = scope.type.seq.find((item) => item.id === expr.name) ?? scope.type.instances.get(expr.name);
        if (attr?.type?.kind === "name" && primitive(attr.type.name)?.kind === "float") return true;
        return attr?.value !== undefined && this.isFloat(attr.value, scope);
      }
      default:
        return false;
    }
  }

  expr(expr: Expr, scope: Scope): string {
    const d = this.d;
    const sub = (inner: Expr) => this.expr(inner, scope);
    switch (expr.kind) {
      case "int":
        return expr.value.toString();
      case "float":
        return d.float(expr.value);
      case "str":
        return JSON.stringify(expr.value);
      case "bool":
        return d.bool(expr.value);
      case "name":
        switch (expr.name) {
          case "_root":
          case "_parent":
          case "_io":
            return `${d.self}.${expr.name}`;
          case "_index":
            return scope.index ?? "i";
          case "_":
            return scope.last ?? "_";
        }
        return `${d.self}.${d.field(expr.name)}`;
      case "enum":
        return `${this.enumName(expr.enumPath, scope.type)}.${d.field(expr.label)}`;
      case "unary":
        return expr.op === "not" ? d.not(sub(expr.operand)) : expr.op === "~" ? d.inv(sub(expr.operand)) : `(-${sub(expr.operand)})`;
      case "binary": {
        const [a, b] = [sub(expr.left), sub(expr.right)];
        switch (expr.op) {
          case "and":
            return d.and(a, b);
          case "or":
            return d.or(a, b);
          case "==":
            return d.eq(a, b);
          case "!=":
            return d.not(d.eq(a, b));
          case "/":
            return this.isFloat(expr.left, scope) || this.isFloat(expr.right, scope) ? `(${a} / ${b})` : `_div(${a}, ${b})`;
          case "%":
            return d.mod(a, b);
          case "&":
          case "|":
          case "^":
          case "<<":
          case ">>":
            return d.bit(expr.op, a, b);
          default:
            return `(${a} ${expr.op} ${b})`;
        }
      }
      case "ternary":
        return d.ternary(sub(expr.condition), sub(expr.then), sub(expr.otherwise));
      case "member":
        return `_p(${sub(expr.object)}, "${d.field(expr.name)}")`;
      case "call":
        return expr.args.length === 0
          ? `_p(${sub(expr.object)}, "${expr.name}")`
          : `_call(${sub(expr.object)}, "${expr.name}", [${expr.args.map(sub).join(", ")}])`;
      case "index":
        return `${sub(expr.object)}[${sub(expr.index)}]`;
      case "array":
        return `[${expr.items.map(sub).join(", ")}]`;
    }
  }

  /** Reads one value of `attr` from `io` into `target`. */
  private readOne(w: Writer, attr: AttrDef, owner: TypeDef, target: string, io: string, scope: Scope): void {
    const d = this.d;
    const self = d.self;
    if (attr.checksum) {
      w.line(d.local("_c", `[${this.expr(attr.checksum.start, scope)}, ${this.expr(attr.checksum.end, scope)}]`));
    }
    const finish = (value: string, primitiveValue: boolean) => {
      const enumName = attr.enumName ? this.enumName(attr.enumName, owner) : null;
      w.line(d.local(target, enumName && primitiveValue && !this.dialectIsJs() ? `_enum(${enumName}, ${value})` : value));
      if (attr.valid) this.validate(w, attr, target, scope);
      if (attr.checksum) w.line(d.stmt(`_check(${self}, "${attr.id}", ${target}, "${attr.checksum.algorithm}", ${io}.${this.dialectIsJs() ? "bytes.subarray(_c[0], _c[1])" : "data[_c[0]:_c[1]]"})`));
    };
    if (attr.contents) {
      finish(`${io}.ensure(${d.bytes(attr.contents)})`, false);
      return;
    }
    const typed = (typeName: string | null) => {
      const prim = typeName ? primitive(typeName) : null;
      const meta = owner.meta;
      if (prim?.kind === "bits") {
        const le = (prim.endian ?? meta.bitEndian) === "le";
        const read = `${io}.read_bits(${prim.width}, ${d.bool(le)})`;
        finish(prim.width === 1 ? (this.dialectIsJs() ? `(${read} === 1)` : `(${read} == 1)`) : read, true);
        return;
      }
      if (prim?.kind === "int") {
        finish(`${io}.read_int(${prim.width}, ${d.bool(prim.signed)}, ${d.bool((prim.endian ?? meta.endian) === "le")})`, true);
        return;
      }
      if (prim?.kind === "float") {
        finish(`${io}.read_float(${prim.width}, ${d.bool((prim.endian ?? meta.endian) === "le")})`, true);
        return;
      }
      const sized = attr.size !== undefined || attr.sizeEos;
      const terminator = attr.terminator ?? (prim?.kind === "str" && prim.zero ? 0 : undefined);
      let data: string | null = null;
      if (sized) {
        data = attr.sizeEos ? `${io}.read_full()` : `${io}.read_bytes(${this.expr(attr.size!, scope)})`;
        if (attr.padRight !== undefined) data = `_strip(${data}, ${attr.padRight})`;
        if (terminator !== undefined) data = `_terminate(${data}, ${terminator}, ${d.bool(attr.include)})`;
      } else if (terminator !== undefined) {
        data = `${io}.read_term(${terminator}, ${d.bool(attr.include)}, ${d.bool(attr.consume)}, ${d.bool(attr.eosError)})`;
      }
      const user = typeName && !prim ? this.className(typeName, owner) : null;
      if (data === null) {
        w.line(d.local(target, user ? d.newObject(user, `${io}, ${self}, ${self}._root`) : d.none));
        return;
      }
      if (attr.process) {
        const arg = attr.process.args[0] ? `, ${this.expr(attr.process.args[0], scope)}` : "";
        w.line(d.local(`${self}._raw_${d.field(attr.id)}`, data));
        data = `_process("${attr.process.name}", ${self}._raw_${d.field(attr.id)}${arg})`;
      }
      if (user) {
        w.line(d.local(target, d.newObject(user, `${d.newObject("Stream", data)}, ${self}, ${self}._root`)));
        return;
      }
      if (prim?.kind === "str") {
        finish(`_decode(${data}, ${JSON.stringify(attr.encoding ?? meta.encoding)})`, false);
        return;
      }
      finish(data, false);
    };
    const type = attr.type;
    if (type?.kind !== "switch") {
      typed(type?.name ?? null);
      return;
    }
    w.line(d.local("_on", this.expr(type.on, scope)));
    const cases = type.cases.filter((item) => item.key !== null);
    const fallback = type.cases.find((item) => item.key === null);
    cases.forEach((item, index) => {
      const condition = d.eq("_on", this.expr(item.key!, scope));
      w.block(index === 0 ? d.ifHead(condition) : d.elifHead(condition), () => typed(item.type));
    });
    const otherwise = () => (fallback ? typed(fallback.type) : typed(null));
    if (cases.length === 0) otherwise();
    else w.block("else", otherwise);
  }

  private dialectIsJs(): boolean {
    return this.d.braces;
  }

  private validate(w: Writer, attr: AttrDef, target: string, scope: Scope): void {
    const d = this.d;
    const valid = attr.valid!;
    const checks: string[] = [];
    if (valid.eq) checks.push(d.eq(target, this.expr(valid.eq, scope)));
    if (valid.min) checks.push(`(${target} >= ${this.expr(valid.min, scope)})`);
    if (valid.max) checks.push(`(${target} <= ${this.expr(valid.max, scope)})`);
    if (valid.anyOf) checks.push(`(${valid.anyOf.map((option) => d.eq(target, this.expr(option, scope))).reduce((a, b) => d.or(a, b))})`);
    if (valid.expr) checks.push(this.expr(valid.expr, { ...scope, last: target }));
    const condition = checks.reduce((a, b) => d.and(a, b));
    w.block(d.ifHead(d.not(condition)), () => w.line(d.stmt(`_fail("validation failed: ${attr.id} is " + ${this.dialectIsJs() ? "String" : "str"}(${target}))`)));
  }

  private readAttr(w: Writer, attr: AttrDef, owner: TypeDef, target: string, io: string): void {
    const d = this.d;
    const scope: Scope = { type: owner };
    if (!attr.repeat) {
      this.readOne(w, attr, owner, target, io, scope);
      return;
    }
    w.line(d.local(target, "[]"));
    const element = (inner: Scope) => {
      this.readOne(w, attr, owner, "_", io, inner);
      w.line(d.stmt(d.push(target, "_").replace(/;$/, "")));
    };
    if (attr.repeat === "expr") {
      w.block(d.forHead("i", this.expr(attr.repeatExpr!, scope)), () => element({ type: owner, index: "i" }));
    } else if (attr.repeat === "eos") {
      w.line(d.local("i", "0"));
      w.block(d.whileHead(d.not(`${io}.eof`)), () => {
        element({ type: owner, index: "i" });
        w.line(d.increment("i"));
      });
    } else {
      w.line(d.local("i", "0"));
      w.block(d.loopHead(), () => {
        element({ type: owner, index: "i" });
        w.block(d.ifHead(this.expr(attr.repeatUntil!, { type: owner, index: "i", last: "_" })), () => w.line(d.stmt("break")));
        w.line(d.increment("i"));
      });
    }
  }

  private emitType(w: Writer, type: TypeDef): void {
    const d = this.d;
    const name = this.classNames.get(type)!;
    const seq = type.seq.map((attr) => JSON.stringify(d.field(attr.id)));
    const instances = [...type.instances.keys()].map((key) => JSON.stringify(d.field(key)));
    const python = !this.dialectIsJs();
    const self = d.self;
    w.block(python ? `class ${name}(Struct)` : `export class ${name} extends Struct`, () => {
      if (python) {
        w.line(`SEQ = (${seq.join(", ")}${seq.length === 1 ? "," : ""})`);
        w.line(`INSTANCES = (${instances.join(", ")}${instances.length === 1 ? "," : ""})`);
        w.line("");
      }
      w.block(python ? "def _read(self)" : "_read()", () => {
        if (!python && type.seq.length > 0) w.line("let _, _on, _c, i;");
        for (const attr of type.seq) {
          const target = `${self}.${d.field(attr.id)}`;
          if (attr.if) {
            w.block(d.ifHead(this.expr(attr.if, { type })), () => this.readAttr(w, attr, type, target, `${self}._io`));
            w.block("else", () => w.line(d.local(target, d.none)));
          } else {
            this.readAttr(w, attr, type, target, `${self}._io`);
          }
        }
      });
      for (const [key, attr] of type.instances) {
        const cache = `${self}._m_${d.field(key)}`;
        if (python) {
          w.line("");
          w.line("@property");
        }
        w.block(python ? `def ${d.field(key)}(self)` : `get ${key}()`, () => {
          if (!python) w.line("let _, _on, _c, i, io, saved;");
          w.block(python ? `if not hasattr(self, "_m_${d.field(key)}")` : `if (${cache} === undefined)`, () => {
            const body = () => {
              if (attr.value) {
                const enumName = attr.enumName ? this.enumName(attr.enumName, type) : null;
                const value = this.expr(attr.value, { type });
                w.line(d.local(cache, enumName && python ? `_enum(${enumName}, ${value})` : value));
                return;
              }
              w.line(d.local("io", attr.io ? this.expr(attr.io, { type }) : `${self}._io`));
              w.line(d.local("saved", "io.save()"));
              if (attr.pos) w.line(d.stmt(`io.seek(${this.expr(attr.pos, { type })})`));
              this.readAttr(w, attr, type, cache, "io");
              w.line(d.stmt("io.restore(saved)"));
            };
            if (attr.if) {
              w.block(d.ifHead(this.expr(attr.if, { type })), body);
              w.block("else", () => w.line(d.local(cache, d.none)));
            } else {
              body();
            }
          });
          w.line(d.stmt(`return ${cache}`));
        });
      }
    });
    if (!python) {
      const enums = [...type.seq, ...type.instances.values()]
        .filter((attr) => attr.enumName)
        .map((attr) => `${attr.id}: ${this.enumName(attr.enumName!, type)}`);
      w.line(`${name}.SEQ = [${seq.join(", ")}];`);
      w.line(`${name}.INSTANCES = [${instances.join(", ")}];`);
      w.line(`${name}.ENUMS = { ${enums.join(", ")} };`);
    }
    w.line("");
    if (python) w.line("");
    for (const child of type.types.values()) this.emitType(w, child);
  }

  private emitEnums(w: Writer, type: TypeDef): void {
    const d = this.d;
    for (const def of type.enums.values()) {
      const name = this.enumNames.get(def)!;
      const entries = [...def.values].map(([label, value]) => [d.field(label), value.toString()] as const);
      if (this.dialectIsJs()) {
        w.line(`export const ${name} = Object.freeze({ ${entries.map(([label, value]) => `${label}: ${value}`).join(", ")} });`);
      } else {
        w.block(`class ${name}(IntEnum)`, () => entries.forEach(([label, value]) => w.line(`${label} = ${value}`)));
        w.line("");
        w.line("");
      }
    }
    for (const child of type.types.values()) this.emitEnums(w, child);
  }

  generate(source: string): string {
    const python = !this.dialectIsJs();
    const w = new Writer(this.d);
    const root = this.classNames.get(this.schema.root)!;
    const title = this.schema.title ?? this.schema.id;
    const schemaComment = source.trimEnd().split("\n").map((line) => (python ? `#   ${line}` : ` *   ${line}`));
    const header = python
      ? [
          "#!/usr/bin/env python3",
          `"""Parser for ${title}, generated by CTF Workbench from a .ksy schema.`,
          "",
          `Usage: python3 ${this.schema.id}.py FILE   (prints the parsed tree)`,
          `   or: from ${this.schema.id} import parse; root = parse(data)`,
          '"""',
          "",
          "# Schema:",
          ...schemaComment,
          "",
        ]
      : [
          `/**`,
          ` * Parser for ${title}, generated by CTF Workbench from a .ksy schema. ES module, no dependencies.`,
          ` *`,
          ` * import { parse, dump } from "./${this.schema.id}.mjs";`,
          ` * console.log(dump(parse(new Uint8Array(bytes))));`,
          ` *`,
          ` * Schema:`,
          ...schemaComment,
          ` */`,
          "",
        ];
    this.emitEnums(w, this.schema.root);
    this.emitType(w, this.schema.root);
    const footer = python
      ? [
          "def parse(data):",
          `    return ${root}(Stream(data))`,
          "",
          "",
          'if __name__ == "__main__":',
          "    if len(sys.argv) != 2:",
          '        sys.exit(f"usage: {sys.argv[0]} FILE")',
          '    with open(sys.argv[1], "rb") as file:',
          "        root = parse(file.read())",
          "    dump(root)",
          "    for problem in root.checksum_errors:",
          '        print("checksum mismatch:", problem)',
          "",
        ]
      : ["export function parse(bytes) {", `  return new ${root}(new Stream(bytes));`, "}", ""];
    return [...header, python ? PY_RUNTIME : JS_RUNTIME, python ? "\n" : "", w.toString(), ...footer].join("\n");
  }
}

export function generateParser(schema: KsySchema, source: string, language: Language): string {
  return new Generator(schema, language === "python" ? PYTHON : JAVASCRIPT).generate(source);
}

/** Schema text in, parser source out; throws KsySchemaError for invalid schemas. */
export function exportParser(source: string, language: Language): { code: string; fileName: string } {
  const schema = loadKsy(source);
  return { code: generateParser(schema, source, language), fileName: `${schema.id}.${language === "python" ? "py" : "mjs"}` };
}
