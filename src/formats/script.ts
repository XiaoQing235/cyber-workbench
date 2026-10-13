/**
 * Static unpacking of obfuscated scripts. Nothing is ever executed: every rule rewrites a
 * recognised pattern whose arguments are literals, and passes repeat until nothing changes.
 */

export type ScriptLanguage = "javascript" | "powershell";

export interface UnpackResult {
  text: string;
  language: ScriptLanguage;
  applied: { rule: string; count: number }[];
  passes: number;
}

type Rule = { name: string; apply: (text: string) => { text: string; count: number } };

const PRINTABLE = /^[\t\n\r\x20-\x7e\u00a0-\uffff]*$/;

function base64Bytes(value: string): Uint8Array | null {
  const clean = value.replace(/\s+/g, "");
  if (clean.length < 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return null;
  try {
    return Uint8Array.from(atob(clean), (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function decodeText(bytes: Uint8Array, encoding: "utf-8" | "utf-16le"): string | null {
  try {
    const text = new TextDecoder(encoding, { fatal: true }).decode(bytes);
    return PRINTABLE.test(text) ? text : null;
  } catch {
    return null;
  }
}

/** JS string-literal escapes, without evaluating anything. */
export function unescapeJs(body: string): string {
  return body.replace(/\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|[0-7]{1,3}|[\s\S])/g, (_match, escape: string) => {
    if (escape[0] === "x") return String.fromCharCode(parseInt(escape.slice(1), 16));
    if (escape.startsWith("u{")) return String.fromCodePoint(parseInt(escape.slice(2, -1), 16));
    if (escape[0] === "u") return String.fromCharCode(parseInt(escape.slice(1), 16));
    if (/^[0-7]+$/.test(escape)) return String.fromCharCode(parseInt(escape, 8));
    return { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", "0": "\0", "\n": "" }[escape] ?? escape;
  });
}

const JS_STRING = String.raw`(["'])((?:\\[\s\S]|(?!\1)[^\\\n])*)\1`;
const jsLiteral = (value: string) => JSON.stringify(value);
const psLiteral = (value: string) => `'${value.replace(/'/g, "''")}'`;

function replaceAll(text: string, pattern: RegExp, replace: (...groups: string[]) => string | null): { text: string; count: number } {
  let count = 0;
  const out = text.replace(pattern, (...args: unknown[]) => {
    const groups = args.slice(0, -2).filter((value): value is string => typeof value === "string" || value === undefined) as string[];
    const result = replace(...groups);
    if (result === null) return groups[0];
    count++;
    return result;
  });
  return { text: out, count };
}

/** Dean Edwards' packer: eval(function(p,a,c,k,e,d){…}('payload',radix,count,'w0|w1|…'.split('|'),…)). */
const PACKER =
  /eval\(function\(p,a,c,k,e,[dr]\)[\s\S]*?\}\(\s*(["'])((?:\\[\s\S]|(?!\1)[^\\])*)\1\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(["'])((?:\\[\s\S]|(?!\5)[^\\])*)\5\.split\(\s*(["'])\|\7\s*\)[\s\S]*?\)\)/g;

function unpackDeanEdwards(text: string): { text: string; count: number } {
  return replaceAll(text, PACKER, (_all, _q, payload, radix, _count, _q2, words) => {
    const base = Number(radix);
    const keywords = unescapeJs(words).split("|");
    const value = (word: string) => {
      let n = 0;
      for (const char of word) {
        const code = char.charCodeAt(0);
        const digit = code >= 48 && code <= 57 ? code - 48 : code >= 97 && code <= 122 ? code - 87 : code >= 65 && code <= 90 && base > 36 ? code - 29 : -1;
        if (digit < 0 || digit >= base) return -1;
        n = n * base + digit;
      }
      return n;
    };
    return unescapeJs(payload).replace(/\b\w+\b/g, (word) => {
      const index = value(word);
      return index >= 0 && keywords[index] ? keywords[index] : word;
    });
  });
}

const JS_RULES: Rule[] = [
  { name: "Dean Edwards packer", apply: unpackDeanEdwards },
  {
    name: "String.fromCharCode",
    apply: (text) =>
      replaceAll(text, /String\.fromCharCode\(\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+))*)\s*\)/g, (_all, codes) =>
        jsLiteral(String.fromCharCode(...codes.split(",").map((code) => Number(code.trim())))),
      ),
  },
  {
    name: "atob",
    apply: (text) =>
      replaceAll(text, new RegExp(String.raw`\batob\(\s*${JS_STRING}\s*\)`, "g"), (_all, _q, body) => {
        const bytes = base64Bytes(unescapeJs(body));
        const decoded = bytes && decodeText(bytes, "utf-8");
        return decoded === null ? null : jsLiteral(decoded);
      }),
  },
  {
    name: "unescape / decodeURIComponent",
    apply: (text) =>
      replaceAll(text, new RegExp(String.raw`\b(?:unescape|decodeURIComponent|decodeURI)\(\s*${JS_STRING}\s*\)`, "g"), (all, _q, body) => {
        try {
          const value = unescapeJs(body);
          return jsLiteral(all.startsWith("unescape") ? unescape(value) : decodeURIComponent(value));
        } catch {
          return null;
        }
      }),
  },
  {
    name: "escaped string literals",
    apply: (text) =>
      replaceAll(text, new RegExp(JS_STRING, "g"), (_all, _q, body) =>
        /\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F{])/.test(body) ? jsLiteral(unescapeJs(body)) : null,
      ),
  },
  {
    name: "string concatenation",
    apply: (text) =>
      replaceAll(
        text,
        /(["'])((?:\\[\s\S]|(?!\1)[^\\\n])*)\1\s*\+\s*(["'])((?:\\[\s\S]|(?!\3)[^\\\n])*)\3/g,
        (_all, _q, left, _q2, right) => jsLiteral(unescapeJs(left) + unescapeJs(right)),
      ),
  },
  {
    name: "reversed strings",
    apply: (text) =>
      replaceAll(
        text,
        /(["'])((?:\\[\s\S]|(?!\1)[^\\\n])*)\1\.split\(\s*(["'])\3\s*\)\.reverse\(\)\.join\(\s*(["'])\4\s*\)/g,
        (_all, _q, body) => jsLiteral([...unescapeJs(body)].reverse().join("")),
      ),
  },
];

const ENCODINGS: Record<string, "utf-8" | "utf-16le"> = { unicode: "utf-16le", utf8: "utf-8", ascii: "utf-8", default: "utf-8" };

const PS_RULES: Rule[] = [
  {
    name: "-EncodedCommand",
    apply: (text) =>
      replaceAll(text, /-(ec|e[a-z]*)\s+["']?([A-Za-z0-9+/]{16,}={0,2})["']?/gi, (_all, flag, payload) => {
        // Any unambiguous prefix of -EncodedCommand works, as does the -ec alias.
        if (flag.toLowerCase() !== "ec" && !"encodedcommand".startsWith(flag.toLowerCase())) return null;
        const bytes = base64Bytes(payload);
        const script = bytes && decodeText(bytes, "utf-16le");
        return script === null ? null : `\n# --- decoded -EncodedCommand ---\n${script}\n# --- end ---\n`;
      }),
  },
  {
    name: "FromBase64String",
    apply: (text) =>
      replaceAll(
        text,
        /\[(?:System\.)?Text\.Encoding\]::(Unicode|UTF8|ASCII|Default)\.GetString\(\s*\[(?:System\.)?Convert\]::FromBase64String\(\s*(['"])([A-Za-z0-9+/=\s]+)\2\s*\)\s*\)/gi,
        (_all, encoding, _q, payload) => {
          const bytes = base64Bytes(payload);
          const decoded = bytes && decodeText(bytes, ENCODINGS[encoding.toLowerCase()]);
          return decoded === null ? null : psLiteral(decoded);
        },
      ),
  },
  {
    name: "[char] codes",
    apply: (text) =>
      replaceAll(text, /\[char\]\s*(?:0x[0-9a-f]+|\d+)(?:\s*\+\s*\[char\]\s*(?:0x[0-9a-f]+|\d+))*/gi, (all) =>
        psLiteral(String.fromCharCode(...[...all.matchAll(/(0x[0-9a-f]+|\d+)/gi)].map((match) => Number(match[1])))),
      ),
  },
  {
    name: "[char[]] -join",
    apply: (text) =>
      replaceAll(text, /\(?\s*\[char\[\]\]\s*\(\s*((?:\d+\s*,\s*)*\d+)\s*\)\s*\)?\s*-join\s*(['"])\2/gi, (_all, codes) =>
        psLiteral(String.fromCharCode(...codes.split(",").map((code) => Number(code.trim())))),
      ),
  },
  {
    name: "-f format reordering",
    apply: (text) =>
      replaceAll(
        text,
        /\(\s*(?:"((?:[^"{}]|\{\d+\})*)"|'((?:[^'{}]|''|\{\d+\})*)')\s*-f\s*((?:(?:'(?:[^']|'')*'|"[^"]*")\s*,\s*)*(?:'(?:[^']|'')*'|"[^"]*"))\s*\)/gi,
        (_all, doubleQuoted, singleQuoted, args) => {
          const format = doubleQuoted ?? singleQuoted.replace(/''/g, "'");
          const values = [...args.matchAll(/'((?:[^']|'')*)'|"([^"]*)"/g)].map((match) => match[2] ?? match[1].replace(/''/g, "'"));
          return psLiteral(format.replace(/\{(\d+)\}/g, (_m: string, index: string) => values[Number(index)] ?? ""));
        },
      ),
  },
  {
    name: "string concatenation",
    apply: (text) =>
      replaceAll(text, /'((?:[^'\n]|'')*)'\s*\+\s*'((?:[^'\n]|'')*)'/g, (_all, left, right) => psLiteral((left + right).replace(/''/g, "'"))),
  },
  {
    name: "backtick noise",
    // Backtick escapes are `0 `a `b `e `f `n `r `t `u `v; before any other letter it only breaks up a word: In`vo`ke.
    apply: (text) => replaceAll(text, /`(?=[cdg-mo-qswxyzA-Z])/g, () => ""),
  },
];

export function detectLanguage(text: string): ScriptLanguage {
  return /\b(iex|invoke-expression|frombase64string|write-host|new-object|powershell)\b|\[char\]|\$env:|\s-e(c|nc\w*)\s/i.test(text) ? "powershell" : "javascript";
}

export function unpackScript(source: string, language: ScriptLanguage | "auto", maxPasses = 10): UnpackResult {
  let text = source;
  let detected = language === "auto" ? detectLanguage(text) : language;
  const totals = new Map<string, number>();
  let passes = 0;
  for (; passes < maxPasses; passes++) {
    let changed = false;
    for (const rule of detected === "powershell" ? PS_RULES : JS_RULES) {
      const result = rule.apply(text);
      if (result.count > 0 && result.text !== text) {
        text = result.text;
        totals.set(rule.name, (totals.get(rule.name) ?? 0) + result.count);
        changed = true;
      }
    }
    // A decoded -EncodedCommand is PowerShell even if the wrapper looked like something else.
    if (language === "auto") detected = detectLanguage(text);
    if (!changed) break;
  }
  return { text, language: detected, applied: [...totals].map(([rule, count]) => ({ rule, count })), passes };
}
