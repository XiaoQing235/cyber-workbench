import { Validator, type Schema } from "@cfworker/json-schema";
import { OperationError } from "./errors";
import type { OperationDefinition, OperationSpec, Params } from "./types";
import type { ValueType } from "../value";

const ID_PATTERN = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9-]*)+$/;
const VERSION_PATTERN = /^(\d+)\.(\d+)\.(\d+)$/;
const MAX_REPORTED_ERRORS = 5;

interface Entry {
  definition: OperationDefinition;
  validator: Validator;
}

function compareVersions(a: string, b: string): number {
  const pa = VERSION_PATTERN.exec(a)!.slice(1).map(Number);
  const pb = VERSION_PATTERN.exec(b)!.slice(1).map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
}

function assertValidSpec(spec: OperationSpec): void {
  if (!ID_PATTERN.test(spec.id)) throw new Error(`Invalid operation id "${spec.id}"`);
  if (!VERSION_PATTERN.test(spec.version)) {
    throw new Error(`Operation ${spec.id} has invalid version "${spec.version}"`);
  }
  for (const ports of [spec.inputs, spec.outputs]) {
    const names = ports.map((port) => port.name);
    if (new Set(names).size !== names.length) {
      throw new Error(`Operation ${spec.id} has duplicate port names`);
    }
  }
  const properties = Object.keys(spec.parametersSchema.properties);
  for (const name of spec.parametersSchema.required ?? []) {
    if (!properties.includes(name)) {
      throw new Error(`Operation ${spec.id} requires undeclared parameter "${name}"`);
    }
  }
}

export class OperationRegistry {
  private readonly entries = new Map<string, Entry>();
  private readonly latest = new Map<string, string>();

  register(definition: OperationDefinition): void {
    const { spec } = definition;
    assertValidSpec(spec);
    const key = `${spec.id}@${spec.version}`;
    if (this.entries.has(key)) throw new Error(`Operation ${key} is already registered`);
    const validator = new Validator(spec.parametersSchema as unknown as Schema, "2020-12", false);
    this.entries.set(key, { definition, validator });
    const current = this.latest.get(spec.id);
    if (current === undefined || compareVersions(spec.version, current) > 0) {
      this.latest.set(spec.id, spec.version);
    }
  }

  /** Resolves `id` at `version`, or at its latest version when none is given. */
  get(id: string, version?: string): OperationDefinition {
    return this.entry(id, version).definition;
  }

  has(id: string): boolean {
    return this.latest.has(id);
  }

  validateParams(spec: OperationSpec, params: Params): void {
    const result = this.entry(spec.id, spec.version).validator.validate(params);
    if (result.valid) return;
    const messages = result.errors
      .filter((error) => error.keyword !== "properties")
      .slice(0, MAX_REPORTED_ERRORS)
      .map((error) => `${error.instanceLocation.replace(/^#\/?/, "") || "params"}: ${error.error}`);
    throw new OperationError("INVALID_PARAMS", messages.join("; ") || "Invalid parameters");
  }

  /** Latest version of every operation, sorted by category then title. */
  list(): OperationSpec[] {
    return [...this.latest]
      .map(([id, version]) => this.entry(id, version).definition.spec)
      .sort((a, b) => a.category.localeCompare(b.category) || a.title.localeCompare(b.title));
  }

  search(query: string, options: { inputType?: ValueType } = {}): OperationSpec[] {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    return this.list().filter((spec) => {
      if (options.inputType && !spec.inputs.some((port) => port.type === options.inputType)) {
        return false;
      }
      const haystack = [spec.id, spec.title, spec.category, spec.description, ...(spec.keywords ?? [])]
        .join(" ")
        .toLowerCase();
      return terms.every((term) => haystack.includes(term));
    });
  }

  private entry(id: string, version?: string): Entry {
    const resolved = version === undefined ? this.latest.get(id) : this.compatible(id, version);
    const entry = resolved === undefined ? undefined : this.entries.get(`${id}@${resolved}`);
    if (!entry) {
      throw new OperationError(
        "UNKNOWN_OPERATION",
        `Unknown operation ${version ? `${id}@${version}` : id}`,
      );
    }
    return entry;
  }

  /** The exact version, else the newest registered one with the same major version and no older. */
  private compatible(id: string, version: string): string | undefined {
    if (this.entries.has(`${id}@${version}`)) return version;
    const wanted = VERSION_PATTERN.exec(version);
    if (!wanted) return undefined;
    let best: string | undefined;
    for (const key of this.entries.keys()) {
      if (!key.startsWith(`${id}@`)) continue;
      const candidate = key.slice(id.length + 1);
      if (VERSION_PATTERN.exec(candidate)?.[1] !== wanted[1] || compareVersions(candidate, version) < 0) continue;
      if (best === undefined || compareVersions(candidate, best) > 0) best = candidate;
    }
    return best;
  }
}
