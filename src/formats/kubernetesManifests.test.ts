import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectKubernetesManifests } from "./kubernetesManifests";

const SENTINEL = "FAKE-NOT-A-SECRET";
const YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: fixture-web
  namespace: fixture
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:1.27
        securityContext:
          privileged: true
        env:
        - name: TOKEN
          value: ${SENTINEL}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: fixture-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: Group
  name: system:masters
---
apiVersion: v1
kind: Secret
metadata:
  name: fixture-secret
  namespace: fixture
data:
  password: RkFLRS1OT1QtQS1TRUNSRVQ=
`;

describe("Kubernetes offline manifest inventory", () => {
  it("finds workload and RBAC leads without leaking Secret or env payloads", async () => {
    const report = await inspectKubernetesManifests(YAML);
    expect(report.total).toBe(3);
    expect(report.resources[0]).toMatchObject({ kind: "Deployment", name: "fixture-web", namespace: "fixture", containers: [{ name: "nginx", image: "nginx:1.27" }] });
    expect(report.resources[2]).toMatchObject({ kind: "Secret", secretKeys: 1, containers: [] });
    expect(report.findings).toEqual(expect.arrayContaining([
      { resource: "fixture/Deployment/fixture-web", level: "high", reason: "Privileged container nginx" },
      { resource: "ClusterRoleBinding/fixture-admin", level: "high", reason: "Binding includes system:masters group" },
    ]));
    expect(JSON.stringify(report)).not.toContain(SENTINEL);
    expect(JSON.stringify(report)).not.toContain("RkFLRS1OT1QtQS1TRUNSRVQ=");
  });

  it("rejects duplicate keys, cyclic aliases and unbounded documents", async () => {
    await expect(inspectKubernetesManifests("kind: Pod\nkind: Secret\n")).rejects.toThrow(/document 1 is invalid/);
    await expect(inspectKubernetesManifests("kind: Pod\nmetadata: &cyclic { name: *cyclic }\napiVersion: v1\n")).rejects.toThrow(/metadata.name must be bounded text/);
    await expect(inspectKubernetesManifests("---\napiVersion: v1\nkind: ConfigMap\nmetadata: { name: sample }\n".repeat(1_001))).rejects.toThrow(/1,000 documents/);
  });

  it("registers a file-based operation that omits Secret/env values and rejects invalid UTF-8", async () => {
    const registry = createDefaultRegistry();
    const result = await executeOperation(registry, {
      operationId: "forensics.kubernetes.manifests.inspect", inputs: { data: bytesFrom(new TextEncoder().encode(YAML)) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { total: 3 } });
    expect(JSON.stringify(result.outputs)).not.toContain(SENTINEL);
    expect(JSON.stringify(result.outputs)).not.toContain("RkFLRS1OT1QtQS1TRUNSRVQ=");
    const invalid = await executeOperation(registry, {
      operationId: "forensics.kubernetes.manifests.inspect", inputs: { data: bytesFrom(Uint8Array.of(0xff)) }, params: {},
    });
    expect(invalid.run.error?.code).toBe("INVALID_INPUT");
  });
});