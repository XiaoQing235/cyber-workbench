/** Kaitai Struct expression language: lexer and Pratt parser. Evaluation lives in the interpreter. */

export type BinaryOp =
  | "+" | "-" | "*" | "/" | "%"
  | "<<" | ">>" | "&" | "|" | "^"
  | "==" | "!=" | "<" | "<=" | ">" | ">="
  | "and" | "or";

export type Expr =
  | { kind: "int"; value: number | bigint }
  | { kind: "float"; value: number }
  | { kind: "str"; value: string }
  | { kind: "bool"; value: boolean }
  | { kind: "name"; name: string }
  | { kind: "enum"; enumPath: string; label: string }
  | { kind: "unary"; op: "-" | "~" | "not"; operand: Expr }
  | { kind: "binary"; op: BinaryOp; left: Expr; right: Expr }
  | { kind: "ternary"; condition: Expr; then: Expr; otherwise: Expr }
  | { kind: "member"; object: Expr; name: string }
  | { kind: "call"; object: Expr; name: string; args: Expr[] }
  | { kind: "index"; object: Expr; index: Expr }
  | { kind: "array"; items: Expr[] };

export class KsyExprError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KsyExprError";
  }
}

/** Integers stay plain numbers while exact; u8/s8 values beyond 2^53 become bigints. */
export function toSafe(value: bigint): number | bigint {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
}

/** 123, -5, 0x1f, 0b101, 0o17 (underscores allowed); null if the text is not an integer literal. */
export function parseIntLiteral(text: string): number | bigint | null {
  const match = /^([+-]?)(0x[0-9a-f_]+|0b[01_]+|0o[0-7_]+|[0-9][0-9_]*)$/i.exec(text.trim());
  if (!match) return null;
  const magnitude = BigInt(match[2].replace(/_/g, "").toLowerCase());
  return toSafe(match[1] === "-" ? -magnitude : magnitude);
}

type Token =
  | { kind: "int"; value: number | bigint; at: number }
  | { kind: "float"; value: number; at: number }
  | { kind: "str"; value: string; at: number }
  | { kind: "id"; value: string; at: number }
  | { kind: "op"; value: string; at: number }
  | { kind: "end"; at: number };

const OPERATORS = ["::", "<<", ">>", "<=", ">=", "==", "!=", "+", "-", "*", "/", "%", "&", "|", "^", "~", "<", ">", "?", ":", "(", ")", "[", "]", ".", ","];
const ESCAPES: Record<string, string> = { a: "\x07", b: "\b", t: "\t", n: "\n", v: "\v", f: "\f", r: "\r", e: "\x1b", '"': '"', "'": "'", "\\": "\\" };

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const fail = (message: string): never => {
    throw new KsyExprError(`${message} at column ${i + 1} of "${source}"`);
  };
  while (i < source.length) {
    const c = source[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") {
      i++;
      continue;
    }
    const at = i;
    const rest = source.slice(i);
    if (c >= "0" && c <= "9") {
      const radix = /^0[xX][0-9a-fA-F_]+|^0[bB][01_]+|^0[oO][0-7_]+/.exec(rest);
      if (radix) {
        tokens.push({ kind: "int", value: toSafe(BigInt(radix[0].replace(/_/g, "").toLowerCase())), at });
        i += radix[0].length;
        continue;
      }
      const decimal = /^[0-9][0-9_]*(\.[0-9][0-9_]*)?([eE][+-]?[0-9]+)?/.exec(rest)!;
      const text = decimal[0].replace(/_/g, "");
      tokens.push(
        decimal[1] || decimal[2] ? { kind: "float", value: Number(text), at } : { kind: "int", value: toSafe(BigInt(text)), at },
      );
      i += decimal[0].length;
      continue;
    }
    const word = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest);
    if (word) {
      tokens.push({ kind: "id", value: word[0], at });
      i += word[0].length;
      continue;
    }
    if (c === "'") {
      const end = source.indexOf("'", i + 1);
      if (end < 0) fail("Unterminated string");
      tokens.push({ kind: "str", value: source.slice(i + 1, end), at });
      i = end + 1;
      continue;
    }
    if (c === '"') {
      let value = "";
      i++;
      for (;;) {
        if (i >= source.length) fail("Unterminated string");
        const ch = source[i];
        if (ch === '"') break;
        if (ch !== "\\") {
          value += ch;
          i++;
          continue;
        }
        const next = source[i + 1] ?? "";
        const hexEscape = /^x([0-9a-fA-F]{2})|^u([0-9a-fA-F]{4})|^([0-7]{1,3})/.exec(source.slice(i + 1));
        if (ESCAPES[next] !== undefined) {
          value += ESCAPES[next];
          i += 2;
        } else if (hexEscape) {
          value += String.fromCharCode(parseInt(hexEscape[1] ?? hexEscape[2] ?? hexEscape[3], hexEscape[3] ? 8 : 16));
          i += 1 + hexEscape[0].length;
        } else {
          fail(`Unknown escape \\${next}`);
        }
      }
      tokens.push({ kind: "str", value, at });
      i++;
      continue;
    }
    const op = OPERATORS.find((candidate) => source.startsWith(candidate, i));
    if (!op) fail(`Unexpected "${c}"`);
    tokens.push({ kind: "op", value: op!, at });
    i += op!.length;
  }
  tokens.push({ kind: "end", at: source.length });
  return tokens;
}

// Binding powers: Python-like, so bitwise operators bind tighter than comparisons (`flags & 0x80 != 0` works).
const TERNARY = 10;
const NOT = 40;
const UNARY = 120;
const BINARY: Record<string, number> = {
  or: 20,
  and: 30,
  "==": 50, "!=": 50, "<": 50, "<=": 50, ">": 50, ">=": 50,
  "|": 60,
  "^": 70,
  "&": 80,
  "<<": 90, ">>": 90,
  "+": 100, "-": 100,
  "*": 110, "/": 110, "%": 110,
};

class Parser {
  private index = 0;

  constructor(
    private readonly tokens: Token[],
    private readonly source: string,
  ) {}

  parse(): Expr {
    const expr = this.expression(0);
    if (this.peek().kind !== "end") this.fail("Unexpected input");
    return expr;
  }

  private peek(): Token {
    return this.tokens[this.index];
  }

  private isOp(value: string): boolean {
    const token = this.peek();
    return token.kind === "op" && token.value === value;
  }

  private expect(value: string): void {
    if (!this.isOp(value)) this.fail(`Expected "${value}"`);
    this.index++;
  }

  private identifier(): string {
    const token = this.peek();
    if (token.kind !== "id") this.fail("Expected a name");
    this.index++;
    return (token as { value: string }).value;
  }

  private fail(message: string): never {
    throw new KsyExprError(`${message} at column ${this.peek().at + 1} of "${this.source}"`);
  }

  private list(close: string): Expr[] {
    const items: Expr[] = [];
    if (this.isOp(close)) {
      this.index++;
      return items;
    }
    for (;;) {
      items.push(this.expression(0));
      if (this.isOp(close)) {
        this.index++;
        return items;
      }
      this.expect(",");
    }
  }

  private expression(minPower: number): Expr {
    let left = this.prefix();
    for (;;) {
      const token = this.peek();
      const op = token.kind === "op" ? token.value : token.kind === "id" && (token.value === "and" || token.value === "or") ? token.value : null;
      if (op === null) return left;
      if (op === ".") {
        this.index++;
        const name = this.identifier();
        if (name === "as" && this.isOp("<")) this.fail("Type casts (.as<…>) are not supported");
        if (this.isOp("(")) {
          this.index++;
          left = { kind: "call", object: left, name, args: this.list(")") };
        } else {
          left = { kind: "member", object: left, name };
        }
        continue;
      }
      if (op === "[") {
        this.index++;
        const index = this.expression(0);
        this.expect("]");
        left = { kind: "index", object: left, index };
        continue;
      }
      if (op === "?") {
        if (TERNARY <= minPower) return left;
        this.index++;
        const then = this.expression(0);
        this.expect(":");
        left = { kind: "ternary", condition: left, then, otherwise: this.expression(TERNARY - 1) };
        continue;
      }
      const power = BINARY[op];
      if (power === undefined || power <= minPower) return left;
      this.index++;
      left = { kind: "binary", op: op as BinaryOp, left, right: this.expression(power) };
    }
  }

  private prefix(): Expr {
    const token = this.peek();
    this.index++;
    switch (token.kind) {
      case "int":
        return { kind: "int", value: token.value };
      case "float":
        return { kind: "float", value: token.value };
      case "str":
        return { kind: "str", value: token.value };
      case "id": {
        if (token.value === "true" || token.value === "false") return { kind: "bool", value: token.value === "true" };
        if (token.value === "not") return { kind: "unary", op: "not", operand: this.expression(NOT) };
        if (token.value === "sizeof" || token.value === "bitsizeof") this.fail(`${token.value}<…> is not supported`);
        if (!this.isOp("::")) return { kind: "name", name: token.value };
        const parts = [token.value];
        while (this.isOp("::")) {
          this.index++;
          parts.push(this.identifier());
        }
        return { kind: "enum", enumPath: parts.slice(0, -1).join("::"), label: parts[parts.length - 1] };
      }
      case "op":
        if (token.value === "-" || token.value === "~") return { kind: "unary", op: token.value, operand: this.expression(UNARY) };
        if (token.value === "(") {
          const inner = this.expression(0);
          this.expect(")");
          return inner;
        }
        if (token.value === "[") return { kind: "array", items: this.list("]") };
        break;
      case "end":
        this.index--;
        this.fail("Unexpected end of expression");
    }
    this.index--;
    return this.fail(`Unexpected "${(token as { value: string }).value}"`);
  }
}

export function parseExpr(source: string): Expr {
  return new Parser(tokenize(source), source).parse();
}

/** Every enum reference in an expression, for validating schemas before parsing. */
export function enumRefs(expr: Expr, out: { enumPath: string; label: string }[] = []): { enumPath: string; label: string }[] {
  switch (expr.kind) {
    case "enum":
      out.push(expr);
      break;
    case "unary":
      enumRefs(expr.operand, out);
      break;
    case "binary":
      enumRefs(expr.left, out);
      enumRefs(expr.right, out);
      break;
    case "ternary":
      enumRefs(expr.condition, out);
      enumRefs(expr.then, out);
      enumRefs(expr.otherwise, out);
      break;
    case "member":
      enumRefs(expr.object, out);
      break;
    case "call":
      enumRefs(expr.object, out);
      expr.args.forEach((arg) => enumRefs(arg, out));
      break;
    case "index":
      enumRefs(expr.object, out);
      enumRefs(expr.index, out);
      break;
    case "array":
      expr.items.forEach((item) => enumRefs(item, out));
      break;
  }
  return out;
}
