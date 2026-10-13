import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectTerraformState } from "../../formats/terraformState";
import { bytesInput, MiB } from "../util";

export const terraformStateInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.terraform.state.inspect", version: "1.0.0", title: "Inspect Terraform state metadata", category: "Forensics",
    description: "Inspect a raw Terraform v4 .tfstate offline (8 MiB max). Report resource addresses, providers, dependencies and output sensitivity. Attribute and output values are never returned.",
    keywords: ["terraform", "tfstate", "iac", "cloud", "dependencies", "secrets", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(bytesInput(inputs), 8 * MiB));
      const report = inspectTerraformState(text);
      ctx.throwIfAborted();
      ctx.diagnostic(`Inspected ${report.resources.length} Terraform resource(s), ${report.dependencyEdges.length} dependency edge(s), and ${report.outputKeys.filter((output) => output.sensitive).length} sensitive output key(s). No state values were returned.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});