import type { Value, ValueType } from "../value";

interface ParamBase {
  title?: string;
  description?: string;
}

export interface StringParam extends ParamBase {
  type: "string";
  default?: string;
  enum?: readonly string[];
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  /** UI hint: edit in a multi-line text area (e.g. a QR grid or a .ksy spec). */
  multiline?: boolean;
}

export interface NumberParam extends ParamBase {
  type: "integer" | "number";
  default?: number;
  minimum?: number;
  maximum?: number;
}

export interface BooleanParam extends ParamBase {
  type: "boolean";
  default?: boolean;
}

export type ParamProperty = StringParam | NumberParam | BooleanParam;

/** A JSON Schema subset: enough to validate parameters and generate forms automatically. */
export interface ParamsSchema {
  type: "object";
  properties: Readonly<Record<string, ParamProperty>>;
  required?: readonly string[];
  additionalProperties: false;
}

export interface PortSpec {
  name: string;
  type: ValueType;
}

export interface OperationSpec {
  /** Stable dotted id, e.g. "base64.decode". Recipes reference `id@version`. */
  id: string;
  /** Semantic version. Any change to outputs for the same input requires a new version. */
  version: string;
  title: string;
  category: string;
  description: string;
  keywords?: readonly string[];
  inputs: readonly PortSpec[];
  outputs: readonly PortSpec[];
  parametersSchema: ParamsSchema;
  /** "wasm" and "pyodide" operations load a Runtime Pack on first use. */
  runtime: "ts" | "wasm" | "pyodide";
  /** Same inputs and parameters always give the same outputs. */
  deterministic: boolean;
  /** Processes input in chunks rather than loading it whole. */
  streaming: boolean;
  /** Anything other than "none" is never run by automated analysis. */
  sideEffects: "none" | "network" | "codeExecution";
  cost: "low" | "medium" | "high";
  limits?: { maxInputBytes?: number };
}

export interface OperationContext {
  readonly signal: AbortSignal;
  throwIfAborted(): void;
  /** Records a note for the user that does not make the run fail. */
  diagnostic(message: string): void;
}

export type Params = Record<string, unknown>;

export interface OperationDefinition<P extends Params = Params> {
  spec: OperationSpec;
  run(
    ctx: OperationContext,
    inputs: Readonly<Record<string, Value>>,
    params: P,
  ): Promise<Record<string, Value>>;
}

/** Lets each operation type its own parameters while the registry stores them uniformly. */
export function defineOperation<P extends Params>(definition: OperationDefinition<P>): OperationDefinition {
  return definition as unknown as OperationDefinition;
}
