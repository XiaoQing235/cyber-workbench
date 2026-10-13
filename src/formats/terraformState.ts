const MAX_STATE_BYTES = 8 * 1024 * 1024;
const MAX_RESOURCES = 2_000;
const MAX_INSTANCES = 5_000;

export interface TerraformStateResource {
  address: string;
  mode: "managed" | "data";
  type: string;
  provider: string;
  instances: number;
  taintedInstances: number;
  deposedInstances: number;
  sensitiveAttributePaths: number;
  dependsOn: string[];
}

export interface TerraformStateReport {
  format: "terraform-state-v4";
  terraformVersion: string;
  serial: number;
  resources: TerraformStateResource[];
  outputKeys: { name: string; sensitive: boolean }[];
  dependencyEdges: { from: string; to: string }[];
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Terraform ${label} must be an object`);
  return value as Record<string, unknown>;
}

function label(value: unknown, field: string, maximum = 512): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\0-\x1f\x7f]/.test(value)) throw new Error(`Terraform ${field} must be bounded text`);
  return value;
}

export function inspectTerraformState(text: string): TerraformStateReport {
  if (new TextEncoder().encode(text).length > MAX_STATE_BYTES) throw new Error("Terraform state exceeds the 8 MiB input budget");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Terraform state is not valid JSON"); }
  const state = object(parsed, "state");
  if (state.version !== 4 || !Number.isSafeInteger(state.serial) || (state.serial as number) < 0) throw new Error("Terraform state must be raw v4 state with a valid serial");
  const terraformVersion = label(state.terraform_version, "terraform_version", 64);
  if (!Array.isArray(state.resources) || state.resources.length > MAX_RESOURCES) throw new Error("Terraform resources exceed the 2,000-resource budget");
  const resources: TerraformStateResource[] = [];
  const dependencyEdges: TerraformStateReport["dependencyEdges"] = [];
  let totalInstances = 0;
  for (const [index, entry] of state.resources.entries()) {
    const resource = object(entry, `resource ${index}`);
    if (resource.mode !== "managed" && resource.mode !== "data") throw new Error("Terraform resource mode is unsupported");
    const type = label(resource.type, "resource type", 256);
    const name = label(resource.name, "resource name", 256);
    const module = resource.module === undefined ? "" : `${label(resource.module, "module address", 512)}.`;
    const address = `${module}${resource.mode === "data" ? "data." : ""}${type}.${name}`;
    const provider = label(resource.provider, "provider", 512);
    if (!Array.isArray(resource.instances) || resource.instances.length > MAX_INSTANCES - totalInstances) throw new Error("Terraform state exceeds the 5,000-instance budget");
    totalInstances += resource.instances.length;
    const dependencies = new Set<string>();
    let taintedInstances = 0;
    let deposedInstances = 0;
    let sensitiveAttributePaths = 0;
    for (const value of resource.instances) {
      const instance = object(value, "instance");
      if (instance.status === "tainted") taintedInstances++;
      if (instance.deposed !== undefined && instance.deposed !== null) deposedInstances++;
      if (instance.sensitive_attributes !== undefined && !Array.isArray(instance.sensitive_attributes)) throw new Error("Terraform sensitive_attributes must be a list");
      sensitiveAttributePaths += Array.isArray(instance.sensitive_attributes) ? instance.sensitive_attributes.length : 0;
      if (instance.dependencies !== undefined && instance.dependencies !== null) {
        if (!Array.isArray(instance.dependencies) || instance.dependencies.length > 512) throw new Error("Terraform instance dependencies exceed the budget");
        for (const dependency of instance.dependencies) dependencies.add(label(dependency, "dependency address"));
      }
    }
    const dependsOn = [...dependencies].sort();
    for (const to of dependsOn) dependencyEdges.push({ from: address, to });
    resources.push({ address, mode: resource.mode, type, provider, instances: resource.instances.length,
      taintedInstances, deposedInstances, sensitiveAttributePaths, dependsOn });
  }
  const outputs = state.outputs === undefined ? {} : object(state.outputs, "outputs");
  if (Object.keys(outputs).length > 1_000) throw new Error("Terraform state exceeds the 1,000-output budget");
  const outputKeys = Object.entries(outputs).map(([name, value]) => {
    label(name, "output name", 256);
    const metadata = object(value, "output metadata");
    if (metadata.sensitive !== undefined && typeof metadata.sensitive !== "boolean") throw new Error("Terraform output sensitive flag must be boolean");
    return { name, sensitive: metadata.sensitive === true };
  }).sort((first, second) => first.name.localeCompare(second.name));
  resources.sort((first, second) => first.address.localeCompare(second.address));
  return { format: "terraform-state-v4", terraformVersion, serial: state.serial as number, resources, outputKeys, dependencyEdges };
}