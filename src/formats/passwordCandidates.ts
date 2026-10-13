import { OperationError } from "../core/operation/errors";

const MASK_CHARSETS: Record<string, string> = {
  l: "abcdefghijklmnopqrstuvwxyz",
  u: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  d: "0123456789",
  s: " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
};
MASK_CHARSETS.a = MASK_CHARSETS.l + MASK_CHARSETS.u + MASK_CHARSETS.d + MASK_CHARSETS.s;

export function generateMaskCandidates(mask: string, customCharset: string, limit: number): { values: string[]; truncated: boolean } {
  const positions: string[][] = [];
  for (let index = 0; index < mask.length; index++) {
    if (mask[index] !== "?") {
      positions.push([mask[index]]);
      continue;
    }
    const token = mask[++index];
    if (token === undefined) throw new OperationError("INVALID_PARAMS", "Mask ends with an incomplete ? token");
    if (token === "?") positions.push(["?"]);
    else if (token === "1") {
      const chars = [...new Set(Array.from(customCharset))];
      if (chars.length === 0) throw new OperationError("INVALID_PARAMS", "Mask uses ?1 but the custom character set is empty");
      positions.push(chars);
    } else {
      const charset = MASK_CHARSETS[token];
      if (!charset) throw new OperationError("INVALID_PARAMS", `Unsupported mask token ?${token}`);
      positions.push(Array.from(charset));
    }
  }
  if (positions.length === 0) return { values: [""], truncated: false };
  let total = 1;
  for (const position of positions) total = Math.min(limit + 1, total * position.length);
  const count = Math.min(limit, total);
  const values: string[] = [];
  const indices = new Array<number>(positions.length).fill(0);
  for (let attempt = 0; attempt < count; attempt++) {
    values.push(positions.map((position, index) => position[indices[index]]).join(""));
    for (let index = indices.length - 1; index >= 0; index--) {
      indices[index]++;
      if (indices[index] < positions[index].length) break;
      indices[index] = 0;
    }
  }
  return { values, truncated: total > limit };
}

export interface CandidateOptions {
  source: "dictionary" | "mask" | "combine";
  words: string;
  rules: string;
  mask: string;
  customCharset: string;
  combineWith: string;
  maxCandidates: number;
  maxWork: number;
  maxOutputBytes: number;
  unique: boolean;
}

export interface CandidateResult {
  text: string;
  generated: number;
  work: number;
  truncated: boolean;
  source: CandidateOptions["source"];
}

function applyRule(word: string, rule: string): string {
  switch (rule) {
    case ":": return word;
    case "l": return word.toLowerCase();
    case "u": return word.toUpperCase();
    case "c": return word.slice(0, 1).toUpperCase() + word.slice(1).toLowerCase();
    case "r": return Array.from(word).reverse().join("");
    case "d": return word + word;
    default:
      if (rule.length === 2 && rule[0] === "$") return word + rule[1];
      if (rule.length === 2 && rule[0] === "^") return rule[1] + word;
      throw new OperationError("INVALID_PARAMS", `Unsupported password rule ${JSON.stringify(rule)}`);
  }
}

export async function generatePasswordCandidates(options: CandidateOptions, yieldControl?: () => Promise<void>): Promise<CandidateResult> {
  if (![options.maxCandidates, options.maxWork, options.maxOutputBytes].every((value) => Number.isSafeInteger(value) && value > 0)) {
    throw new OperationError("INVALID_PARAMS", "Candidate, work, and output limits must be positive safe integers");
  }
  const values: string[] = [];
  const seen = options.unique ? new Set<string>() : null;
  const encoder = new TextEncoder();
  let work = 0;
  let outputBytes = 0;
  let truncated = false;
  const append = async (candidate: string): Promise<boolean> => {
    if (work >= options.maxWork) { truncated = true; return false; }
    work++;
    if (work % 250 === 0) await yieldControl?.();
    if (seen?.has(candidate)) return true;
    const size = encoder.encode(candidate).length + (values.length > 0 ? 1 : 0);
    if (values.length >= options.maxCandidates || size > options.maxOutputBytes - outputBytes) { truncated = true; return false; }
    values.push(candidate);
    outputBytes += size;
    seen?.add(candidate);
    return true;
  };

  if (options.source === "mask") {
    const generated = generateMaskCandidates(options.mask, options.customCharset, Math.min(options.maxCandidates, options.maxWork));
    truncated = generated.truncated;
    for (const candidate of generated.values) if (!await append(candidate)) break;
  } else {
    const words = options.words.replace(/\r/g, "").split("\n").filter(Boolean);
    if (options.source === "dictionary") {
      const rules = options.rules.replace(/\r/g, "").split("\n").filter(Boolean);
      const selectedRules = rules.length > 0 ? rules : [":"];
      if (selectedRules.length > 128) throw new OperationError("INVALID_PARAMS", "Dictionary is limited to 128 rules");
      for (const rule of selectedRules) applyRule("", rule);
      for (const word of words) {
        for (const rule of selectedRules) if (!await append(applyRule(word, rule))) return { text: values.join("\n"), generated: values.length, work, truncated, source: options.source };
      }
    } else if (options.source === "combine") {
      const otherWords = options.combineWith.replace(/\r/g, "").split("\n").filter(Boolean);
      if (otherWords.length === 0) throw new OperationError("INVALID_PARAMS", "Combination source needs a second word list");
      for (const word of words) {
        for (const otherWord of otherWords) if (!await append(word + otherWord)) return { text: values.join("\n"), generated: values.length, work, truncated, source: options.source };
      }
    } else throw new OperationError("INVALID_PARAMS", `Unknown candidate source ${String(options.source)}`);
  }
  return { text: values.join("\n"), generated: values.length, work, truncated, source: options.source };
}