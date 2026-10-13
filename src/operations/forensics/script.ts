import { defineOperation } from "../../core/operation/types";
import { textValue } from "../../core/value";
import { unpackScript, type ScriptLanguage } from "../../formats/script";
import { textInput } from "../util";

export const scriptUnpack = defineOperation<{ language: ScriptLanguage | "auto"; maxPasses: number }>({
  spec: {
    id: "script.unpack",
    version: "1.0.0",
    title: "Unpack obfuscated script",
    category: "Forensics",
    description:
      "Statically peel common obfuscation layers from JavaScript and PowerShell (packer, fromCharCode, atob, escapes, concatenation, -EncodedCommand, Base64, [char] codes, -f reordering, backticks). The script is never run.",
    keywords: ["deobfuscate", "unpack", "javascript", "powershell", "packer", "eval", "encodedcommand", "malware", "dropper"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        language: { type: "string", title: "Language", enum: ["auto", "javascript", "powershell"], default: "auto" },
        maxPasses: { type: "integer", title: "Maximum passes", minimum: 1, maximum: 50, default: 10 },
      },
      required: ["language", "maxPasses"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
  },
  async run(ctx, inputs, params) {
    const result = unpackScript(textInput(inputs), params.language, params.maxPasses);
    ctx.diagnostic(
      result.applied.length === 0
        ? `No known ${result.language} obfuscation found.`
        : `${result.language}: ${result.applied.map((item) => `${item.rule} ×${item.count}`).join(", ")} in ${result.passes} pass(es).`,
    );
    return { text: textValue(result.text) };
  },
});
