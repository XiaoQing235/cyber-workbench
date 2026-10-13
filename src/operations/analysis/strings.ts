import { defineOperation } from "../../core/operation/types";
import { textValue } from "../../core/value";
import { bytesInput, CHUNK_SIZE } from "../util";

type StringsEncoding = "ascii" | "utf-16le" | "both";

interface FoundString {
  offset: number;
  text: string;
  wide: boolean;
}

interface Scanner {
  scan(chunk: Uint8Array, base: number): void;
  end(): void;
}

const MAX_OUTPUT_CHARS = 64 * 1024 * 1024;

const isPrintable = (byte: number) => (byte >= 0x20 && byte < 0x7f) || byte === 0x09;

/** Runs of printable ASCII; runs may cross chunk boundaries. */
function asciiScanner(minLength: number, emit: (found: FoundString) => void): Scanner {
  const decoder = new TextDecoder();
  let start = -1;
  let pending = "";
  const finish = (text: string) => {
    if (text.length >= minLength) emit({ offset: start, text, wide: false });
    start = -1;
    pending = "";
  };
  return {
    scan(chunk, base) {
      let segment = 0;
      for (let i = 0; i < chunk.length; i++) {
        if (isPrintable(chunk[i])) {
          if (start < 0) {
            start = base + i;
            segment = i;
          }
        } else if (start >= 0) {
          finish(pending + decoder.decode(chunk.subarray(segment, i)));
        }
      }
      if (start >= 0) pending += decoder.decode(chunk.subarray(segment));
    },
    end() {
      if (start >= 0) finish(pending);
    },
  };
}

/** Runs of printable characters encoded as UTF-16LE (char, 0x00), tracked separately for even and odd offsets. */
function wideScanner(minLength: number, emit: (found: FoundString) => void): Scanner {
  const start = [-1, -1];
  const text = ["", ""];
  let previous = -1;
  const finish = (parity: number) => {
    if (start[parity] >= 0 && text[parity].length >= minLength) {
      emit({ offset: start[parity], text: text[parity], wide: true });
    }
    start[parity] = -1;
    text[parity] = "";
  };
  return {
    scan(chunk, base) {
      for (let i = 0; i < chunk.length; i++) {
        const first = i > 0 ? chunk[i - 1] : previous;
        if (first < 0) continue;
        const parity = (base + i - 1) & 1;
        if (isPrintable(first) && chunk[i] === 0) {
          if (start[parity] < 0) start[parity] = base + i - 1;
          text[parity] += String.fromCharCode(first);
        } else if (start[parity] >= 0) {
          finish(parity);
        }
      }
      if (chunk.length > 0) previous = chunk[chunk.length - 1];
    },
    end() {
      finish(0);
      finish(1);
    },
  };
}

export const stringsExtract = defineOperation<{
  minLength: number;
  encoding: StringsEncoding;
  offsets: boolean;
  maxStrings: number;
}>({
  spec: {
    id: "strings.extract",
    version: "1.0.0",
    title: "Strings",
    category: "Analysis",
    description: "List runs of printable characters, like the Unix strings tool. Optionally also UTF-16LE strings.",
    keywords: ["strings", "printable", "ascii", "utf16", "wide", "text"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        minLength: { type: "integer", title: "Minimum length", minimum: 1, maximum: 1024, default: 4 },
        encoding: { type: "string", title: "Encoding", enum: ["ascii", "utf-16le", "both"], default: "ascii" },
        offsets: { type: "boolean", title: "Show offsets (hex)", default: true },
        maxStrings: { type: "integer", title: "Stop after (strings)", minimum: 1, maximum: 10_000_000, default: 100_000 },
      },
      required: ["minLength", "encoding", "offsets", "maxStrings"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    const found: FoundString[] = [];
    const emit = (item: FoundString) => found.push(item);
    const scanners: Scanner[] = [];
    if (params.encoding !== "utf-16le") scanners.push(asciiScanner(params.minLength, emit));
    if (params.encoding !== "ascii") scanners.push(wideScanner(params.minLength, emit));

    let stoppedAt: number | null = null;
    for (let offset = 0; offset < source.size; offset += CHUNK_SIZE) {
      ctx.throwIfAborted();
      const chunk = await source.read(offset, CHUNK_SIZE);
      for (const scanner of scanners) scanner.scan(chunk, offset);
      if (found.length >= params.maxStrings) {
        stoppedAt = offset + chunk.length;
        break;
      }
    }
    if (stoppedAt === null) for (const scanner of scanners) scanner.end();

    found.sort((a, b) => a.offset - b.offset || Number(a.wide) - Number(b.wide));
    const lines: string[] = [];
    let chars = 0;
    for (const item of found.slice(0, params.maxStrings)) {
      const tag = params.encoding === "both" && item.wide ? "[UTF-16LE] " : "";
      const line = params.offsets ? `${item.offset.toString(16).padStart(8, "0")}  ${tag}${item.text}` : tag + item.text;
      chars += line.length + 1;
      if (chars > MAX_OUTPUT_CHARS) {
        ctx.diagnostic(`Output truncated at ${lines.length} strings (${MAX_OUTPUT_CHARS} characters).`);
        break;
      }
      lines.push(line);
    }
    if (stoppedAt !== null) {
      ctx.diagnostic(`Stopped after ${params.maxStrings} strings at offset ${stoppedAt} of ${source.size}.`);
    }
    return { text: textValue(lines.join("\n")) };
  },
});
