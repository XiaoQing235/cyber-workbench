const MAX_YAML_BYTES = 2 * 1024 * 1024;
const MAX_RESOURCES = 1_000;

export interface KubernetesResource {
  apiVersion: string;
  kind: string;
  name: string;
  namespace: string | null;
  containers: { name: string; image: string }[];
  serviceAccount: string | null;
  secretKeys: number | null;
}

export interface KubernetesFinding {
  resource: string;
  level: "high" | "review";
  reason: string;
}

export interface KubernetesManifestReport {
  total: number;
  resources: KubernetesResource[];
  findings: KubernetesFinding[];
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Kubernetes ${label} must be an object`);
  return value as Record<string, unknown>;
}

function name(value: unknown, label: string, maximum = 253): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\0-\x1f\x7f]/.test(value)) throw new Error(`Kubernetes ${label} must be bounded text`);
  return value;
}

function nested(root: Record<string, unknown>, ...keys: string[]): Record<string, unknown> | null {
  let value: unknown = root;
  for (const key of keys) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    value = (value as Record<string, unknown>)[key];
  }
  return value === undefined || value === null ? null : object(value, keys.join("."));
}

function podSpec(resource: Record<string, unknown>, kind: string): Record<string, unknown> | null {
  if (kind === "Pod") return nested(resource, "spec");
  if (kind === "CronJob") return nested(resource, "spec", "jobTemplate", "spec", "template", "spec");
  if (["Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet", "ReplicationController"].includes(kind)) return nested(resource, "spec", "template", "spec");
  return null;
}

function collect(resource: Record<string, unknown>, resources: KubernetesResource[], findings: KubernetesFinding[]): void {
  const kind = name(resource.kind, "kind", 128);
  if (kind === "List") {
    if (!Array.isArray(resource.items)) throw new Error("Kubernetes List items must be an array");
    for (const item of resource.items) collect(object(item, "List item"), resources, findings);
    return;
  }
  if (resources.length >= MAX_RESOURCES) throw new Error("Kubernetes manifest exceeds 1,000 resources");
  const apiVersion = name(resource.apiVersion, "apiVersion", 128);
  const metadata = object(resource.metadata, "metadata");
  const resourceName = name(metadata.name, "metadata.name");
  const namespace = metadata.namespace === undefined || metadata.namespace === null ? null : name(metadata.namespace, "metadata.namespace");
  const address = `${namespace ? `${namespace}/` : ""}${kind}/${resourceName}`;
  const finding = (level: KubernetesFinding["level"], reason: string) => findings.push({ resource: address, level, reason });
  const pod = podSpec(resource, kind);
  const containers: KubernetesResource["containers"] = [];
  if (pod) {
    for (const field of ["initContainers", "containers", "ephemeralContainers"]) {
      if (pod[field] === undefined) continue;
      if (!Array.isArray(pod[field]) || (pod[field] as unknown[]).length > 256) throw new Error(`Kubernetes ${field} exceeds the container budget`);
      for (const item of pod[field] as unknown[]) {
        const container = object(item, "container");
        containers.push({ name: name(container.name, "container name"), image: name(container.image, "container image", 512) });
        if (nested(container, "securityContext")?.privileged === true) finding("high", `Privileged container ${container.name}`);
      }
    }
    for (const field of ["hostNetwork", "hostPID", "hostIPC"]) if (pod[field] === true) finding("review", `${field} is enabled`);
    if (pod.volumes !== undefined) {
      if (!Array.isArray(pod.volumes) || pod.volumes.length > 256) throw new Error("Kubernetes volumes exceed the budget");
      for (const volume of pod.volumes) if (object(volume, "volume").hostPath !== undefined) finding("review", "hostPath volume is mounted");
    }
  }
  if (kind === "ClusterRoleBinding" || kind === "RoleBinding") {
    const roleRef = nested(resource, "roleRef");
    if (roleRef?.name === "cluster-admin" && roleRef.kind === "ClusterRole") finding("high", "Binding grants cluster-admin");
    if (resource.subjects !== undefined) {
      if (!Array.isArray(resource.subjects) || resource.subjects.length > 256) throw new Error("Kubernetes binding subjects exceed the budget");
      for (const subject of resource.subjects) {
        const item = object(subject, "subject");
        if (item.kind === "Group" && item.name === "system:masters") finding("high", "Binding includes system:masters group");
      }
    }
  }
  if (kind === "Role" || kind === "ClusterRole") {
    if (resource.rules !== undefined) {
      if (!Array.isArray(resource.rules) || resource.rules.length > 256) throw new Error("Kubernetes RBAC rules exceed the budget");
      for (const rule of resource.rules) {
        const item = object(rule, "RBAC rule");
        if (Array.isArray(item.verbs) && item.verbs.includes("*") && Array.isArray(item.resources) && item.resources.includes("*")) finding("high", "RBAC rule has wildcard verbs and resources");
      }
    }
  }
  const secretKeys = kind === "Secret" ? new Set([
    ...Object.keys(resource.data === undefined ? {} : object(resource.data, "Secret data")),
    ...Object.keys(resource.stringData === undefined ? {} : object(resource.stringData, "Secret stringData")),
  ]).size : null;
  resources.push({ apiVersion, kind, name: resourceName, namespace, containers,
    serviceAccount: pod?.serviceAccountName === undefined ? null : name(pod.serviceAccountName, "serviceAccountName"), secretKeys });
}

export async function inspectKubernetesManifests(text: string): Promise<KubernetesManifestReport> {
  if (new TextEncoder().encode(text).length > MAX_YAML_BYTES) throw new Error("Kubernetes YAML exceeds the 2 MiB input budget");
  const { parseAllDocuments } = await import("yaml");
  const documents = parseAllDocuments(text, { uniqueKeys: true });
  if (documents.length < 1 || documents.length > 1_000) throw new Error("Kubernetes YAML requires 1 to 1,000 documents");
  const resources: KubernetesResource[] = [];
  const findings: KubernetesFinding[] = [];
  for (const [index, document] of documents.entries()) {
    if (document.errors.length > 0) throw new Error(`Kubernetes YAML document ${index + 1} is invalid`);
    if (document.contents === null) continue;
    let parsed: unknown;
    try { parsed = document.toJS({ maxAliasCount: 50 }); }
    catch { throw new Error(`Kubernetes YAML document ${index + 1} has invalid aliases`); }
    collect(object(parsed, `document ${index + 1}`), resources, findings);
  }
  if (resources.length === 0) throw new Error("Kubernetes YAML contains no resources");
  return { total: resources.length, resources, findings };
}