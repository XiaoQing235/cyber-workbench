import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectTerraformState } from "./terraformState";

const SENTINEL = "FAKE-DO-NOT-LEAK-123";
const fixture = {
  version: 4, terraform_version: "1.11.3", serial: 3, lineage: "local-fixture",
  resources: [
    { mode: "managed", type: "terraform_data", name: "linked", provider: "provider[\"terraform.io/builtin/terraform\"]",
      instances: [{ schema_version: 0, attributes: { input: { value: SENTINEL } }, dependencies: ["terraform_data.seed"], sensitive_attributes: [] }] },
    { mode: "managed", type: "terraform_data", name: "seed", provider: "provider[\"terraform.io/builtin/terraform\"]",
      instances: [{ schema_version: 0, attributes: { input: { token: SENTINEL }, output: SENTINEL }, sensitive_attributes: [["input", "token"]] }] },
  ],
  outputs: { private_token: { value: SENTINEL, type: "string", sensitive: true }, public_name: { value: "seed", type: "string" } },
};

describe("raw Terraform state metadata", () => {
  it("shows dependencies and sensitivity without exposing raw values", () => {
    const report = inspectTerraformState(JSON.stringify(fixture));
    expect(report).toMatchObject({
      format: "terraform-state-v4", terraformVersion: "1.11.3", serial: 3,
      resources: [{ address: "terraform_data.linked", instances: 1, dependsOn: ["terraform_data.seed"] },
        { address: "terraform_data.seed", sensitiveAttributePaths: 1 }],
      outputKeys: [{ name: "private_token", sensitive: true }, { name: "public_name", sensitive: false }],
      dependencyEdges: [{ from: "terraform_data.linked", to: "terraform_data.seed" }],
    });
    expect(JSON.stringify(report)).not.toContain(SENTINEL);
    expect(report.resources[0]).not.toHaveProperty("attributes");
    expect(report.outputKeys[0]).not.toHaveProperty("value");
  });

  it("rejects unsupported state formats and invalid dependency arrays", () => {
    expect(() => inspectTerraformState(JSON.stringify({ ...fixture, version: 3 }))).toThrow(/raw v4/);
    expect(() => inspectTerraformState(JSON.stringify({ ...fixture, resources: [{ ...fixture.resources[0], instances: [{ dependencies: "oops" }] }] }))).toThrow(/dependencies exceed/);
  });

  it("keeps sensitive state values out of the registered Forensics operation", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.terraform.state.inspect", inputs: { data: bytesFrom(new TextEncoder().encode(JSON.stringify(fixture))) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { resources: [{ address: "terraform_data.linked" }, { address: "terraform_data.seed" }] } });
    expect(JSON.stringify(result.outputs)).not.toContain(SENTINEL);
  });
});