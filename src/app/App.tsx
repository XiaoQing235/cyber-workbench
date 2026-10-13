import { lazy, Suspense, useMemo, useState, useSyncExternalStore, type DragEvent } from "react";
import type { SuggestedStep, Suggestion } from "../core/analysis/finding";
import type { Artifact } from "../core/artifact/store";
import type { SourceSpan } from "../core/bytes/span";
import { BlobSource } from "../core/bytes/sources";
import { applyDefaults, executeOperation } from "../core/operation/execute";
import type { OperationRun } from "../core/operation/run";
import type { Params } from "../core/operation/types";
import { linearPipeline } from "../core/pipeline/pipeline";
import { findReusableRun } from "../core/recipe/cache";
import type { Recipe } from "../core/recipe/recipe";
import { bytesValue, describeValue, textValue } from "../core/value";
import { ArtifactView } from "./components/ArtifactView";
import { ParamsForm, defaultParams } from "./components/ParamsForm";
import { PacksPanel } from "./components/PacksPanel";
import { RecipesPanel } from "./components/Recipes";
import { WorkspaceBar } from "./components/WorkspaceBar";
import { getPool, registry, store } from "./services";

// React Flow is only downloaded when the pipeline view is first opened.
const PipelineEditor = lazy(() => import("./components/PipelineEditor").then((module) => ({ default: module.PipelineEditor })));

type InputMode = "text" | "hex" | "artifact";

const BUTTON = "rounded border border-slate-300 bg-white px-3 py-1 text-sm hover:bg-slate-100 disabled:opacity-50";
const PRIMARY = "rounded bg-sky-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50";

/** Runs a conversion on the main thread (inputs typed by hand are small) and records its provenance. */
async function convert(source: Artifact, operationId: string, params: Params): Promise<Artifact> {
  const spec = registry.get(operationId).spec;
  const result = await executeOperation(registry, {
    operationId,
    inputs: { [spec.inputs[0].name]: source.value },
    params,
  });
  store.recordRun(result.run);
  if (result.run.status !== "success") {
    throw new Error(`${spec.title} failed: ${result.run.error?.message ?? result.run.status}`);
  }
  const [, value] = Object.entries(result.outputs)[0];
  return store.add({ name: `${spec.title} of ${source.name}`, value, producedBy: result.run.id, parents: [source.id] });
}

const withDefaults = (step: SuggestedStep): Params => ({
  ...defaultParams(registry.get(step.operationId, step.operationVersion).spec),
  ...step.params,
});

/** Runs one operation in the worker pool and records the run and its outputs. */
async function execute(step: SuggestedStep, input: Artifact, params: Params, signal: AbortSignal) {
  const spec = registry.get(step.operationId, step.operationVersion).spec;
  const reusable = findReusableRun(store, input, spec, applyDefaults(spec, params));
  if (reusable && reusable.outputs.length > 0) return { ...reusable, reused: true };
  const result = await getPool().run(spec.id, { [spec.inputs[0].name]: input.value }, params, {
    operationVersion: spec.version,
    signal,
  });
  store.recordRun(result.run);
  const outputs = Object.entries(result.outputs).map(([name, value]) =>
    store.add({ name: `${spec.title} → ${name}`, value, producedBy: result.run.id, parents: [input.id] }),
  );
  return { run: result.run, outputs, reused: false };
}

export function App() {
  useSyncExternalStore(store.subscribe, store.getVersion);

  const [query, setQuery] = useState("");
  const operations = useMemo(() => registry.search(query), [query]);
  const [operationId, setOperationId] = useState("base64.decode");
  const spec = registry.get(operationId).spec;
  const port = spec.inputs[0];

  const [params, setParams] = useState<Params>(() => defaultParams(spec));
  const [mode, setMode] = useState<InputMode>("text");
  const [text, setText] = useState("");
  const [inputArtifactId, setInputArtifactId] = useState<string | null>(null);
  const [running, setRunning] = useState<AbortController | null>(null);
  const [lastRun, setLastRun] = useState<OperationRun | null>(null);
  const [outputIds, setOutputIds] = useState<string[]>([]);
  const [reused, setReused] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [inputOpen, setInputOpen] = useState(true);
  const [focus, setFocus] = useState<{ artifactId: string; span: SourceSpan } | null>(null);
  const [view, setView] = useState<"tools" | "pipeline">("tools");
  const [pipelineId, setPipelineId] = useState<string | null>(null);

  const inputArtifact = inputArtifactId ? store.get(inputArtifactId) : undefined;
  const artifacts = store.list().reverse();

  const selectOperation = (id: string) => {
    setView("tools");
    setOperationId(id);
    setParams(defaultParams(registry.get(id).spec));
    setInputOpen(!["forensics.terraform.state.inspect", "forensics.kubernetes.manifests.inspect", "forensics.mail.inspect", "forensics.mail.attachment-extract", "forensics.model.safetensors.inspect", "forensics.model.safetensors.extract", "forensics.model.pickle.opcodes", "forensics.ios.ipa.inspect", "forensics.ios.ipa.extract", "network.har.diff", "network.burp.diff"].includes(id));
    setLastRun(null);
    setOutputIds([]);
    setProblem(null);
  };

  const chooseInput = (id: string) => {
    setMode("artifact");
    setInputArtifactId(id);
  };

  const applySuggestion = (suggestion: Suggestion, inputId: string) => {
    const steps = [suggestion, ...(suggestion.then ?? [])];
    const unknown = steps.find((step) => !registry.has(step.operationId));
    if (unknown) {
      setProblem(`Unknown operation ${unknown.operationId}`);
      return;
    }
    if (suggestion.then) {
      void runSteps(steps, inputId);
      return;
    }
    selectOperation(suggestion.operationId);
    setParams(withDefaults(suggestion));
    chooseInput(inputId);
  };

  /** Runs steps in order, each on the previous output; every intermediate result stays an artifact. */
  const runSteps = async (steps: readonly SuggestedStep[], inputId: string) => {
    let current = store.get(inputId);
    if (!current) return;
    const controller = new AbortController();
    setRunning(controller);
    try {
      for (const [index, step] of steps.entries()) {
        let params: Params;
        try {
          params = withDefaults(step);
        } catch (error) {
          setProblem(`Step ${index + 1}: ${error instanceof Error ? error.message : String(error)}`);
          return;
        }
        const result = await execute(step, current, params, controller.signal);
        if (index === steps.length - 1 || result.run.status !== "success") {
          // Show the last step that ran, with its input and parameters, like a manual run.
          selectOperation(step.operationId);
          setParams(params);
          chooseInput(current.id);
          setLastRun(result.run);
          setReused(result.reused);
          setOutputIds(result.outputs.map((artifact) => artifact.id));
          return;
        }
        current = result.outputs[0];
      }
    } finally {
      setRunning(null);
    }
  };

  const showSpan = (span: SourceSpan, artifactId: string) => {
    setView("tools");
    chooseInput(artifactId);
    setInputOpen(true);
    setFocus({ artifactId, span: { ...span } });
  };

  const recipeSteps = (recipe: Recipe): SuggestedStep[] =>
    recipe.steps.map(({ operationId, operationVersion, params }) => ({
      operationId,
      params,
      ...(operationVersion !== null ? { operationVersion } : {}),
    }));

  const runRecipe = (recipe: Recipe) => {
    if (mode !== "artifact" || !inputArtifact) {
      setProblem("Choose an input artifact first.");
      return;
    }
    void runSteps(recipeSteps(recipe), inputArtifact.id);
  };

  /** Turns steps into an editable pipeline: input node (bound when known) followed by one node per step. */
  const openPipeline = (steps: readonly SuggestedStep[], inputId: string | undefined, name?: string) => {
    try {
      const title = steps.map((step) => registry.get(step.operationId, step.operationVersion).spec.title).join(" → ");
      const pipeline = linearPipeline(name ?? (title.length > 60 ? `${title.slice(0, 59)}…` : title), steps, registry, inputId);
      store.savePipeline(pipeline);
      setPipelineId(pipeline.id);
      setView("pipeline");
    } catch (error) {
      setProblem(error instanceof Error ? error.message : String(error));
    }
  };

  const openSuggestionInPipeline = (suggestion: Suggestion, inputId: string) =>
    openPipeline([suggestion, ...(suggestion.then ?? [])], inputId);

  const openRecipeInPipeline = (recipe: Recipe) =>
    openPipeline(recipeSteps(recipe), mode === "artifact" ? inputArtifact?.id : undefined, recipe.name);

  const importFiles = (files: FileList | null) => {
    if (!files || files.length === 0) return;
    let last: Artifact | undefined;
    for (const file of files) last = store.add({ name: file.name, value: bytesValue(new BlobSource(file)) });
    if (last) chooseInput(last.id);
  };

  const onDrop = (event: DragEvent<HTMLElement>) => {
    event.preventDefault();
    importFiles(event.dataTransfer.files);
  };

  /** Builds the input artifact, converting only where the conversion is explicit and lossless. */
  const prepareInput = async (): Promise<Artifact> => {
    let artifact: Artifact;
    if (mode === "artifact") {
      if (!inputArtifact) throw new Error("Choose a file or an artifact first.");
      artifact = inputArtifact;
    } else if (mode === "hex") {
      artifact = await convert(store.add({ name: "Hex input", value: textValue(text) }), "hex.decode", {
        ignoreSeparators: true,
      });
    } else {
      artifact = store.add({ name: "Text input", value: textValue(text) });
    }
    if (artifact.value.type === port.type) return artifact;
    if (port.type === "bytes" && artifact.value.type === "text") {
      return convert(artifact, "text.encode", { charset: "utf-8", onUnmappable: "error" });
    }
    throw new Error(
      `${spec.title} needs ${port.type} input, but "${artifact.name}" is ${artifact.value.type}.` +
        (port.type === "text" ? ' Run "Decode text" first and choose the charset explicitly.' : ""),
    );
  };

  const run = async () => {
    setProblem(null);
    let input: Artifact;
    try {
      input = await prepareInput();
    } catch (error) {
      setProblem(error instanceof Error ? error.message : String(error));
      return;
    }
    const controller = new AbortController();
    setRunning(controller);
    const result = await execute({ operationId: spec.id, operationVersion: spec.version }, input, params, controller.signal);
    setRunning(null);
    setLastRun(result.run);
    setReused(result.reused);
    setOutputIds(result.outputs.map((artifact) => artifact.id));
  };

  const isolated = typeof crossOriginIsolated !== "undefined" && crossOriginIsolated;

  return (
    <div className="flex h-full flex-col">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 bg-white px-4 py-2">
        <h1 className="text-lg font-semibold">CTF Workbench</h1>
        <WorkspaceBar />
      </header>

      <div className="flex min-h-0 flex-1">
        <nav className="flex w-64 shrink-0 flex-col gap-2 border-r border-slate-200 bg-white p-3">
          <input
            className="rounded border border-slate-300 px-2 py-1 text-sm"
            placeholder="Search operations…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <ul className="min-h-0 flex-1 overflow-y-auto text-sm">
            {operations.map((operation, index) => (
              <li key={operation.id}>
                {(index === 0 || operations[index - 1].category !== operation.category) && (
                  <p className="mt-2 px-2 text-xs font-semibold tracking-wide text-slate-400 uppercase">
                    {operation.category}
                  </p>
                )}
                <button
                  className={`w-full rounded px-2 py-1 text-left ${operation.id === operationId ? "bg-sky-100 text-sky-900" : "hover:bg-slate-100"}`}
                  onClick={() => selectOperation(operation.id)}
                  title={operation.description}
                >
                  {operation.title}
                </button>
              </li>
            ))}
            {operations.length === 0 && <li className="px-2 text-slate-500">No match.</li>}
          </ul>
        </nav>

        <main className="flex min-w-0 flex-1 flex-col gap-4 overflow-y-auto p-4" onDragOver={(e) => e.preventDefault()} onDrop={onDrop}>
          <div className="flex gap-1 text-sm">
            {(["tools", "pipeline"] as const).map((name) => (
              <button
                key={name}
                className={`rounded px-3 py-1 ${view === name ? "bg-slate-800 text-white" : "bg-slate-200 hover:bg-slate-300"}`}
                onClick={() => setView(name)}
              >
                {name === "tools" ? "Quick tools" : "Pipeline"}
              </button>
            ))}
          </div>
          {view === "pipeline" ? (
            <Suspense fallback={<p className="text-sm text-slate-500">Loading the pipeline editor…</p>}>
              <PipelineEditor pipelineId={pipelineId} onSelectPipeline={setPipelineId} />
            </Suspense>
          ) : (
          <>
          <section className="flex flex-col gap-1">
            <h2 className="text-base font-semibold">{spec.title}</h2>
            <p className="text-sm text-slate-600">{spec.description}</p>
            <p className="font-mono text-xs text-slate-400">
              {spec.id}@{spec.version} · {spec.inputs.map((p) => p.type).join(", ")} →{" "}
              {spec.outputs.map((p) => p.type).join(", ")}
            </p>
          </section>

          <section className="flex flex-col gap-2 rounded-lg border border-slate-200 bg-white p-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="font-medium">Input</span>
              {(["text", "hex", "artifact"] as const).map((name) => (
                <button
                  key={name}
                  className={`rounded px-2 py-0.5 ${mode === name ? "bg-slate-800 text-white" : "bg-slate-200"}`}
                  onClick={() => setMode(name)}
                >
                  {name === "text" ? "Text" : name === "hex" ? "Hex" : "File / artifact"}
                </button>
              ))}
            </div>
            {mode === "artifact" ? (
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <label className={BUTTON}>
                  Choose file…
                  <input type="file" multiple className="hidden" onChange={(event) => importFiles(event.target.files)} />
                </label>
                <span className="text-slate-600">
                  {inputArtifact
                    ? `${inputArtifact.name} · ${describeValue(inputArtifact.value)}`
                    : "Drop a file anywhere here, or pick an artifact on the right."}
                </span>
                {inputArtifact && (
                  <details
                    open={inputOpen}
                    onToggle={(event) => setInputOpen(event.currentTarget.open)}
                    className="w-full"
                  >
                    <summary className="cursor-pointer text-xs text-slate-600">View input</summary>
                    <ArtifactView
                      key={inputArtifact.id}
                      artifact={inputArtifact}
                      onSuggest={applySuggestion}
                      onShowSpan={showSpan}
                      onOpenInPipeline={openSuggestionInPipeline}
                      focus={focus?.artifactId === inputArtifact.id ? focus.span : undefined}
                    />
                  </details>
                )}
              </div>
            ) : (
              <>
                <textarea
                  className="h-32 w-full resize-y rounded border border-slate-300 p-2 font-mono text-sm"
                  placeholder={mode === "hex" ? "48 65 6c 6c 6f  (0x / \\x prefixes and : , ; - separators are ignored)" : "Type or paste text…"}
                  value={text}
                  onChange={(event) => setText(event.target.value)}
                />
                {mode === "text" && port.type === "bytes" && (
                  <p className="text-xs text-slate-500">This operation needs bytes: the text is encoded as UTF-8 first.</p>
                )}
              </>
            )}
          </section>

          <section className="flex flex-col gap-3 rounded-lg border border-slate-200 bg-white p-3">
            <span className="text-sm font-medium">Parameters</span>
            <ParamsForm spec={spec} value={params} onChange={setParams} />
            <div className="flex items-center gap-2">
              <button className={PRIMARY} disabled={running !== null} onClick={() => void run()}>
                {running ? "Running…" : "Run"}
              </button>
              {running && (
                <button className={BUTTON} onClick={() => running.abort()}>
                  Cancel
                </button>
              )}
            </div>
            {problem && <p className="text-sm text-red-700">{problem}</p>}
          </section>

          {lastRun && (
            <section className="flex flex-col gap-3">
              <p className="text-sm">
                <span
                  className={
                    lastRun.status === "success"
                      ? "text-emerald-700"
                      : lastRun.status === "cancelled"
                        ? "text-amber-700"
                        : "text-red-700"
                  }
                >
                  {lastRun.status}
                </span>{" "}
                <span className="text-slate-500">
                  in {lastRun.durationMs} ms{reused && " · reused the identical earlier result (same input, operation version and parameters)"}
                </span>
                {lastRun.error && <span className="text-red-700"> · {lastRun.error.message}</span>}
              </p>
              {lastRun.diagnostics.map((message) => (
                <p key={message} className="text-sm text-amber-700">
                  {message}
                </p>
              ))}
              {outputIds.map((id) => {
                const artifact = store.get(id);
                return artifact ? (
                  <ArtifactView
                    key={id}
                    artifact={artifact}
                    onUseAsInput={chooseInput}
                    onSuggest={applySuggestion}
                    onShowSpan={showSpan}
                    onOpenInPipeline={openSuggestionInPipeline}
                  />
                ) : null;
              })}
            </section>
          )}
          </>
          )}
        </main>

        <aside className="flex w-72 shrink-0 flex-col gap-3 border-l border-slate-200 bg-white p-3">
          <h2 className="text-sm font-semibold">Artifacts</h2>
          <ul className="min-h-0 flex-1 overflow-y-auto text-sm">
            {artifacts.map((artifact) => {
              const producer = artifact.producedBy ? store.getRun(artifact.producedBy) : undefined;
              const deletable = store.childrenOf(artifact.id).length === 0;
              return (
                <li key={artifact.id} className="group flex items-start">
                  <button
                    className={`min-w-0 flex-1 rounded px-2 py-1 text-left ${artifact.id === inputArtifactId && mode === "artifact" ? "bg-sky-100" : "hover:bg-slate-100"}`}
                    onClick={() => chooseInput(artifact.id)}
                    title="Use as input"
                  >
                    <span className="block truncate">{artifact.name}</span>
                    <span className="block text-xs text-slate-500">
                      {describeValue(artifact.value)}
                      {producer ? ` · ${producer.operationId}` : " · imported"}
                    </span>
                  </button>
                  {deletable && (
                    <button
                      className="invisible px-1 text-slate-400 group-hover:visible hover:text-red-700"
                      aria-label={`Delete ${artifact.name}`}
                      title="Delete (nothing was derived from it)"
                      onClick={() => store.remove(artifact.id)}
                    >
                      ×
                    </button>
                  )}
                </li>
              );
            })}
            {artifacts.length === 0 && <li className="px-2 text-slate-500">Nothing yet.</li>}
          </ul>
          <RecipesPanel
            canRun={mode === "artifact" && inputArtifact !== undefined && running === null}
            onRun={runRecipe}
            onOpen={openRecipeInPipeline}
          />
          <PacksPanel />
        </aside>
      </div>

      <footer className="border-t border-slate-200 bg-white px-4 py-1 text-xs text-slate-500">
        Everything runs in your browser; nothing is uploaded. · Cross-origin isolated: {isolated ? "yes" : "no"} ·{" "}
        {registry.list().length} operations
      </footer>
    </div>
  );
}
