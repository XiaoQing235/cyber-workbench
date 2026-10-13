import type { Evidence, Finding } from "../../core/analysis/finding";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { fileExtent } from "../../formats/carve";
import { SIGNATURES, matchesAt, scanSignatures } from "../../formats/signatures";
import { bytesInput, MiB } from "../util";

const SCAN_LIMIT = 1024 * MiB;
const MAX_ITEMS = 200;

export interface CarvedItem {
  offset: number;
  type: string;
  description: string;
  length: number | null;
  how: string;
  /** Offset of an earlier item that already contains this one. */
  inside?: number;
}

export const carveScan = defineOperation<Record<string, never>>({
  spec: {
    id: "carve.scan",
    version: "1.0.0",
    title: "Find embedded files",
    category: "Analysis",
    description:
      "Find files hidden inside other data (binwalk-style) and work out where each one ends from its own structure: PNG chunks, JPEG markers, GIF blocks, ZIP directory, ELF headers and more.",
    keywords: ["carve", "binwalk", "foremost", "embedded", "extract", "polyglot", "appended"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    const head = await source.read(0, 512);
    const top = SIGNATURES.find((signature) => (signature.offset ?? 0) === 0 && signature.magic.length >= 3 && matchesAt(head, 0, signature.magic));
    const hits = await scanSignatures(source, { start: 1, end: Math.min(source.size, SCAN_LIMIT), maxHits: MAX_ITEMS, signal: ctx.signal });
    const candidates = [...(top ? [{ signature: top, offset: 0 }] : []), ...hits];

    const items: CarvedItem[] = [];
    for (const { signature, offset } of candidates) {
      ctx.throwIfAborted();
      const extent = await fileExtent(source, signature.type, offset);
      const container = items.find((item) => item.length !== null && offset > item.offset && offset < item.offset + item.length);
      items.push({
        offset,
        type: signature.type,
        description: signature.description,
        length: extent.end === null ? null : extent.end - offset,
        how: extent.how,
        ...(container ? { inside: container.offset } : {}),
      });
    }

    const findings: Finding[] = [];
    for (const item of items) {
      const end = item.length === null ? null : item.offset + item.length;
      const evidence: Evidence[] = [
        { kind: "signature", tier: item.offset === 0 ? "strong" : "weak", detail: `${item.description} magic bytes at offset ${item.offset}`, span: { offset: item.offset, length: 8 } },
        end === null
          ? { kind: "structure", tier: "weak", detail: `${item.how}` }
          : { kind: "structure", tier: "strong", detail: `${item.how}: ${item.length} bytes, ending at offset ${end}` },
      ];
      if (item.offset === 0) {
        if (end !== null && end < source.size) {
          findings.push({
            id: "carve.trailing",
            ruleId: "carve.extent",
            severity: "strong",
            message: `${source.size - end} byte(s) follow the end of the ${item.description} at offset ${end}`,
            span: { offset: end, length: source.size - end },
            evidence,
            suggestion: { operationId: "bytes.slice", params: { offset: end, length: -1 }, label: "Extract what follows" },
          });
        }
        continue;
      }
      findings.push({
        id: `carve.item.${item.offset}`,
        ruleId: "carve.extent",
        severity: item.inside !== undefined ? "weak" : end === null ? "medium" : "strong",
        message:
          `${item.description} at offset ${item.offset} (0x${item.offset.toString(16)}), ` +
          (item.length === null ? "length unknown" : `${item.length} bytes`) +
          (item.inside !== undefined ? `, inside the file at offset ${item.inside}` : ""),
        span: { offset: item.offset, length: item.length ?? Math.min(16, source.size - item.offset) },
        evidence,
        suggestion: { operationId: "bytes.slice", params: { offset: item.offset, length: item.length ?? -1 }, label: `Carve the ${item.type.toUpperCase()}` },
      });
    }
    if (findings.length === 0) {
      findings.push({ id: "carve.none", ruleId: "carve.extent", severity: "weak", message: "No embedded file signatures found" });
    }
    return {
      report: structuredValue({ size: source.size, items, scanLimited: source.size > SCAN_LIMIT || hits.length >= MAX_ITEMS, findings }),
    };
  },
});
