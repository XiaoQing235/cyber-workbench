import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectKubernetesManifests } from "../../formats/kubernetesManifests";
import { bytesInput, MiB } from "../util";

export const kubernetesManifestsInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.kubernetes.manifests.inspect", version: "1.0.0", title: "Inspect Kubernetes manifests", category: "Forensics",
    description: "Inspect offline multi-document Kubernetes YAML for workloads, images, service accounts, RBAC and concrete privilege leads. Secret payloads and container env values are never returned; no cluster is contacted.",
    keywords: ["kubernetes", "k8s", "yaml", "rbac", "secret", "container", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(bytesInput(inputs), 2 * MiB));
      const report = await inspectKubernetesManifests(text);
      ctx.throwIfAborted();
      ctx.diagnostic(`Inspected ${report.total} Kubernetes resource(s); found ${report.findings.length} concrete privilege lead(s). Secret and env values were not returned.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});