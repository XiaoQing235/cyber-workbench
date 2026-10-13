import type { Value } from "../value";
import { OperationError } from "./errors";
import type { OperationRegistry } from "./registry";
import type { OperationResult, OperationRun, RunStatus } from "./run";
import type { OperationContext, OperationSpec, Params } from "./types";

export interface ExecuteRequest {
  operationId: string;
  operationVersion?: string;
  inputs: Readonly<Record<string, Value>>;
  params?: Params;
}

export interface ExecuteOptions {
  signal?: AbortSignal;
  runId?: string;
}

/** Fills in schema defaults for parameters the caller left undefined. */
export function applyDefaults(spec: OperationSpec, params: Params): Params {
  const result: Params = { ...params };
  for (const [name, property] of Object.entries(spec.parametersSchema.properties)) {
    if (result[name] === undefined && property.default !== undefined) {
      result[name] = property.default;
    }
  }
  return result;
}

function checkInputs(spec: OperationSpec, inputs: Readonly<Record<string, Value>>): void {
  for (const port of spec.inputs) {
    const value = inputs[port.name];
    if (value === undefined) {
      throw new OperationError("INPUT_MISSING", `Missing input "${port.name}"`);
    }
    if (value.type !== port.type) {
      throw new OperationError(
        "INPUT_TYPE",
        `Input "${port.name}" must be ${port.type}, got ${value.type}`,
      );
    }
    const max = spec.limits?.maxInputBytes;
    if (max !== undefined && value.type === "bytes" && value.source.size > max) {
      throw new OperationError(
        "INPUT_TOO_LARGE",
        `Input "${port.name}" is ${value.source.size} bytes; ${spec.id} accepts at most ${max}`,
      );
    }
  }
}

function checkOutputs(spec: OperationSpec, outputs: Record<string, Value>): void {
  const declared = new Set(spec.outputs.map((port) => port.name));
  for (const name of Object.keys(outputs)) {
    if (!declared.has(name)) {
      throw new OperationError("OUTPUT_CONTRACT", `${spec.id} returned undeclared output "${name}"`);
    }
  }
  for (const port of spec.outputs) {
    const value = outputs[port.name];
    if (value === undefined || value.type !== port.type) {
      throw new OperationError(
        "OUTPUT_CONTRACT",
        `${spec.id} must return ${port.type} output "${port.name}"`,
      );
    }
  }
}

function isAbort(error: unknown, signal: AbortSignal | undefined): boolean {
  if (signal?.aborted) return true;
  if (error instanceof OperationError) return error.code === "CANCELLED";
  return error instanceof DOMException && error.name === "AbortError";
}

/**
 * Runs one operation and always resolves with a run record. Errors never escape as exceptions,
 * and a failed run never carries outputs.
 */
export async function executeOperation(
  registry: OperationRegistry,
  request: ExecuteRequest,
  options: ExecuteOptions = {},
): Promise<OperationResult> {
  const { signal } = options;
  const startedAt = new Date();
  const start = performance.now();
  const diagnostics: string[] = [];
  let version: string | null = request.operationVersion ?? null;
  let params: Params = request.params ?? {};

  const finish = (
    status: RunStatus,
    outputs: Record<string, Value>,
    error?: OperationRun["error"],
  ): OperationResult => ({
    run: {
      id: options.runId ?? crypto.randomUUID(),
      operationId: request.operationId,
      operationVersion: version,
      parameters: params,
      status,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
      durationMs: Math.round((performance.now() - start) * 100) / 100,
      diagnostics,
      ...(error ? { error } : {}),
    },
    outputs,
  });

  try {
    const definition = registry.get(request.operationId, request.operationVersion);
    const { spec } = definition;
    version = spec.version;
    params = applyDefaults(spec, params);
    registry.validateParams(spec, params);
    checkInputs(spec, request.inputs);
    signal?.throwIfAborted();

    const neverAborted = new AbortController().signal;
    const ctx: OperationContext = {
      signal: signal ?? neverAborted,
      throwIfAborted: () => signal?.throwIfAborted(),
      diagnostic: (message) => {
        diagnostics.push(message);
      },
    };
    const outputs = await definition.run(ctx, request.inputs, params);
    signal?.throwIfAborted();
    checkOutputs(spec, outputs);
    return finish("success", outputs);
  } catch (error) {
    if (isAbort(error, signal)) {
      return finish("cancelled", {}, { code: "CANCELLED", message: "The operation was cancelled" });
    }
    if (error instanceof OperationError) {
      return finish("failed", {}, { code: error.code, message: error.message });
    }
    const message = error instanceof Error ? error.message : String(error);
    return finish("failed", {}, { code: "INTERNAL", message });
  }
}
