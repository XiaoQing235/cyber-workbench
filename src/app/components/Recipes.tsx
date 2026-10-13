import { useState } from "react";
import { applyDefaults } from "../../core/operation/execute";
import { lineage, recipeFromLineage, type Recipe, type RecipeStep } from "../../core/recipe/recipe";
import { registry, store } from "../services";

const BUTTON = "rounded border border-slate-300 bg-white px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50";

const title = (operationId: string) => (registry.has(operationId) ? registry.get(operationId).spec.title : operationId);

function summarise(params: Record<string, unknown>): string {
  const text = Object.entries(params)
    .map(([key, value]) => `${key}=${typeof value === "string" ? JSON.stringify(value) : String(value)}`)
    .join(" ");
  return text.length > 90 ? `${text.slice(0, 90)}…` : text;
}

/** The chain of runs that produced an artifact, with a way to keep it as a recipe. */
export function LineageView({ artifactId }: { artifactId: string }) {
  const [saved, setSaved] = useState(false);
  const chain = lineage(store, artifactId);
  if (!chain || chain.steps.length === 0) return null;

  const save = () => {
    const name = chain.steps.map(({ run }) => title(run.operationId)).join(" → ");
    store.saveRecipe(recipeFromLineage(name.length > 80 ? `${name.slice(0, 79)}…` : name, chain.steps));
    setSaved(true);
  };

  return (
    <details className="text-xs text-slate-600">
      <summary className="cursor-pointer">
        How this was made: {chain.steps.length} step{chain.steps.length === 1 ? "" : "s"} from {chain.root.name}
      </summary>
      <ol className="mt-1 flex flex-col gap-0.5 border-l-2 border-slate-200 pl-2">
        <li className="font-medium">{chain.root.name}</li>
        {chain.steps.map(({ run }) => (
          <li key={run.id}>
            → {title(run.operationId)}{" "}
            <span className="font-mono text-slate-500">
              {run.operationId}@{run.operationVersion} {summarise(run.parameters)}
            </span>
          </li>
        ))}
      </ol>
      <button className={`${BUTTON} mt-1`} disabled={saved} onClick={save}>
        {saved ? "Saved as a recipe" : "Save as recipe"}
      </button>
    </details>
  );
}

/** Parses edited steps and checks each against the registry, so a broken recipe cannot be saved. */
function parseSteps(text: string): RecipeStep[] {
  const parsed: unknown = JSON.parse(text);
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error("Steps must be a non-empty list");
  return parsed.map((item: unknown, index) => {
    const step = item as Partial<RecipeStep> | null;
    if (typeof step?.operationId !== "string") throw new Error(`Step ${index + 1}: operationId is missing`);
    const version = typeof step.operationVersion === "string" ? step.operationVersion : undefined;
    const spec = registry.get(step.operationId, version).spec;
    const params = typeof step.params === "object" && step.params !== null ? step.params : {};
    try {
      registry.validateParams(spec, applyDefaults(spec, params));
    } catch (error) {
      throw new Error(`Step ${index + 1} (${spec.title}): ${error instanceof Error ? error.message : String(error)}`);
    }
    return { operationId: spec.id, operationVersion: spec.version, params };
  });
}

function RecipeItem({
  recipe,
  canRun,
  onRun,
  onOpen,
}: {
  recipe: Recipe;
  canRun: boolean;
  onRun: (recipe: Recipe) => void;
  onOpen: (recipe: Recipe) => void;
}) {
  const [editing, setEditing] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const apply = () => {
    try {
      store.saveRecipe({ ...recipe, steps: parseSteps(editing ?? "") });
      setEditing(null);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  return (
    <li className="flex flex-col gap-1 rounded border border-slate-200 p-2">
      <input
        className="rounded border border-transparent px-1 text-sm font-medium hover:border-slate-300"
        defaultValue={recipe.name}
        aria-label="Recipe name"
        onBlur={(event) => {
          const name = event.target.value.trim();
          if (name && name !== recipe.name) store.saveRecipe({ ...recipe, name });
        }}
      />
      <ol className="list-inside list-decimal text-xs text-slate-600">
        {recipe.steps.map((step, index) => (
          <li key={index}>{title(step.operationId)}</li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-1">
        <button
          className={BUTTON}
          disabled={!canRun}
          title={canRun ? "Run every step on the current input" : "Choose an input artifact first"}
          onClick={() => onRun(recipe)}
        >
          Run on input
        </button>
        <button className={BUTTON} title="Edit as pipeline nodes (bound to the current input, if any)" onClick={() => onOpen(recipe)}>
          Open in pipeline
        </button>
        <button className={BUTTON} onClick={() => setEditing(editing === null ? JSON.stringify(recipe.steps, null, 2) : null)}>
          {editing === null ? "Edit" : "Cancel"}
        </button>
        <button className={BUTTON} onClick={() => confirm(`Delete the recipe "${recipe.name}"?`) && store.removeRecipe(recipe.id)}>
          Delete
        </button>
      </div>
      {editing !== null && (
        <div className="flex flex-col gap-1">
          <textarea
            className="h-48 w-full rounded border border-slate-300 p-1 font-mono text-xs"
            value={editing}
            aria-label="Recipe steps (JSON)"
            onChange={(event) => setEditing(event.target.value)}
          />
          {error && <p className="text-xs text-red-700">{error}</p>}
          <button className={BUTTON} onClick={apply}>
            Apply changes
          </button>
        </div>
      )}
    </li>
  );
}

export function RecipesPanel({
  canRun,
  onRun,
  onOpen,
}: {
  canRun: boolean;
  onRun: (recipe: Recipe) => void;
  onOpen: (recipe: Recipe) => void;
}) {
  const recipes = store.listRecipes();
  return (
    <section className="flex max-h-[45%] min-h-0 flex-col gap-2">
      <h2 className="text-sm font-semibold">Recipes</h2>
      <ul className="flex min-h-0 flex-col gap-2 overflow-y-auto">
        {recipes.map((recipe) => (
          <RecipeItem key={recipe.id} recipe={recipe} canRun={canRun} onRun={onRun} onOpen={onOpen} />
        ))}
        {recipes.length === 0 && (
          <li className="px-2 text-xs text-slate-500">Open "How this was made" on a result and save it as a recipe.</li>
        )}
      </ul>
    </section>
  );
}
